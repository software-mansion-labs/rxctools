//! NSKeyedArchiver encoding and decoding for the DTX payloads instruments and XCTest exchange.

use crate::util::{Error, Result, bail};
use plist::{Dictionary, Uid, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum NS {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Real(f64),
    Str(String),
    Data(Vec<u8>),
    Array(Vec<NS>),
    Set(Vec<NS>),
    Dict(Vec<(NS, NS)>),
    Uuid([u8; 16]),
    Url {
        base: Option<Box<NS>>,
        relative: String,
    },
    Date(f64),
    Error {
        code: i64,
        domain: String,
        user_info: Box<NS>,
    },
    /// Any other class: name and its archived fields.
    Object {
        class: String,
        fields: BTreeMap<String, NS>,
    },
}

impl NS {
    pub fn str(s: &str) -> NS {
        NS::Str(s.into())
    }
    pub fn dict(pairs: Vec<(&str, NS)>) -> NS {
        NS::Dict(pairs.into_iter().map(|(k, v)| (NS::str(k), v)).collect())
    }
    pub fn obj(class: &str, fields: Vec<(&str, NS)>) -> NS {
        NS::Object {
            class: class.into(),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }
    pub fn get(&self, key: &str) -> Option<&NS> {
        match self {
            NS::Dict(d) => d
                .iter()
                .find(|(k, _)| matches!(k, NS::Str(s) if s == key))
                .map(|(_, v)| v),
            NS::Object { fields, .. } => fields.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            NS::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            NS::UInt(u) => Some(*u),
            NS::Int(i) if *i >= 0 => Some(*i as u64),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            NS::Bool(b) => Some(*b),
            NS::Int(i) => Some(*i != 0),
            NS::UInt(i) => Some(*i != 0),
            _ => None,
        }
    }
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::{Value as J, json};
        match self {
            NS::Null => J::Null,
            NS::Bool(b) => json!(b),
            NS::Int(i) => json!(i),
            NS::UInt(u) => json!(u),
            // whole floats print without a fraction
            NS::Real(r) if r.fract() == 0.0 && r.abs() < 1e15 => json!(*r as i64),
            NS::Real(r) => json!(r),
            NS::Str(s) => json!(s),
            NS::Data(d) => json!(crate::util::base64(d)),
            NS::Array(a) | NS::Set(a) => J::Array(a.iter().map(|v| v.to_json()).collect()),
            NS::Dict(d) => J::Object(
                d.iter()
                    .map(|(k, v)| {
                        (
                            k.as_str()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| k.to_json().to_string()),
                            v.to_json(),
                        )
                    })
                    .collect(),
            ),
            NS::Uuid(u) => json!(uuid::Uuid::from_bytes(*u).to_string()),
            NS::Url { relative, .. } => json!(relative),
            NS::Date(d) => json!(d),
            NS::Error {
                code,
                domain,
                user_info,
            } => json!({"code": code, "domain": domain, "userInfo": user_info.to_json()}),
            NS::Object { class, fields } => {
                let mut m: serde_json::Map<String, J> = fields
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_json()))
                    .collect();
                m.insert("$class".into(), json!(class));
                J::Object(m)
            }
        }
    }
}

// --- archiving ---

struct Archiver {
    objects: Vec<Value>,
    classes: BTreeMap<String, u64>,
}

fn class_chain(name: &str) -> Vec<&str> {
    match name {
        "NSMutableDictionary" => vec!["NSMutableDictionary", "NSDictionary", "NSObject"],
        "NSMutableArray" => vec!["NSMutableArray", "NSArray", "NSObject"],
        "NSMutableSet" => vec!["NSMutableSet", "NSSet", "NSObject"],
        "NSMutableString" => vec!["NSMutableString", "NSString", "NSObject"],
        _ => vec![name, "NSObject"],
    }
}

impl Archiver {
    fn push(&mut self, v: Value) -> Uid {
        self.objects.push(v);
        Uid::new(self.objects.len() as u64 - 1)
    }

    fn class(&mut self, name: &str) -> Uid {
        if let Some(&i) = self.classes.get(name) {
            return Uid::new(i);
        }
        let mut d = Dictionary::new();
        d.insert(
            "$classes".into(),
            Value::Array(class_chain(name).into_iter().map(Value::from).collect()),
        );
        d.insert("$classname".into(), name.into());
        let u = self.push(Value::Dictionary(d));
        self.classes.insert(name.into(), u.get());
        u
    }

    /// Reserves the object's slot first so references inside point back correctly, like Foundation does.
    fn object(&mut self, class: &str, fill: impl FnOnce(&mut Self, &mut Dictionary)) -> Uid {
        let me = self.push(Value::Boolean(false));
        let mut d = Dictionary::new();
        fill(self, &mut d);
        let c = self.class(class);
        d.insert("$class".into(), Value::Uid(c));
        self.objects[me.get() as usize] = Value::Dictionary(d);
        me
    }

    fn archive(&mut self, v: &NS) -> Uid {
        match v {
            NS::Null => self.object("NSNull", |_, _| {}),
            NS::Bool(b) => self.push(Value::Boolean(*b)),
            NS::Int(i) => self.push(Value::Integer((*i).into())),
            NS::UInt(u) => self.push(Value::Integer((*u).into())),
            NS::Real(r) => self.push(Value::Real(*r)),
            NS::Str(s) => self.push(Value::String(s.clone())),
            NS::Data(d) => self.push(Value::Data(d.clone())),
            NS::Array(a) | NS::Set(a) => {
                let class = if matches!(v, NS::Set(_)) {
                    "NSSet"
                } else {
                    "NSArray"
                };
                self.object(class, |ar, d| {
                    let refs: Vec<Value> = a.iter().map(|e| Value::Uid(ar.archive(e))).collect();
                    d.insert("NS.objects".into(), Value::Array(refs));
                })
            }
            NS::Dict(entries) => self.object("NSDictionary", |ar, d| {
                let keys: Vec<Value> = entries
                    .iter()
                    .map(|(k, _)| Value::Uid(ar.archive(k)))
                    .collect();
                let vals: Vec<Value> = entries
                    .iter()
                    .map(|(_, v)| Value::Uid(ar.archive(v)))
                    .collect();
                d.insert("NS.keys".into(), Value::Array(keys));
                d.insert("NS.objects".into(), Value::Array(vals));
            }),
            NS::Uuid(u) => self.object("NSUUID", |_, d| {
                d.insert("NS.uuidbytes".into(), Value::Data(u.to_vec()));
            }),
            NS::Url { base, relative } => self.object("NSURL", |ar, d| {
                let b = match base {
                    Some(b) => ar.archive(b),
                    None => Uid::new(0),
                };
                d.insert("NS.base".into(), Value::Uid(b));
                let r = ar.archive(&NS::Str(relative.clone()));
                d.insert("NS.relative".into(), Value::Uid(r));
            }),
            NS::Date(t) => self.object("NSDate", |_, d| {
                d.insert("NS.time".into(), Value::Real(*t));
            }),
            NS::Error {
                code,
                domain,
                user_info,
            } => self.object("NSError", |ar, d| {
                d.insert("NSCode".into(), Value::Integer((*code).into()));
                let dm = ar.archive(&NS::Str(domain.clone()));
                d.insert("NSDomain".into(), Value::Uid(dm));
                let ui = ar.archive(user_info);
                d.insert("NSUserInfo".into(), Value::Uid(ui));
            }),
            NS::Object { class, fields } => self.object(class, |ar, d| {
                for (k, f) in fields {
                    // inline scalars the way Foundation encodes encodeBool:/encodeInt64:
                    let v = match f {
                        NS::Bool(b) => Value::Boolean(*b),
                        NS::Int(i) => Value::Integer((*i).into()),
                        NS::UInt(u) => Value::Integer((*u).into()),
                        NS::Real(r) => Value::Real(*r),
                        NS::Null => Value::Uid(Uid::new(0)),
                        other => Value::Uid(ar.archive(other)),
                    };
                    d.insert(k.clone(), v);
                }
            }),
        }
    }
}

pub fn archive(v: &NS) -> Value {
    let mut a = Archiver {
        objects: vec![Value::String("$null".into())],
        classes: BTreeMap::new(),
    };
    let root = a.archive(v);
    let mut top = Dictionary::new();
    top.insert("root".into(), Value::Uid(root));
    let mut d = Dictionary::new();
    d.insert("$archiver".into(), "NSKeyedArchiver".into());
    d.insert("$objects".into(), Value::Array(a.objects));
    d.insert("$top".into(), Value::Dictionary(top));
    d.insert("$version".into(), Value::Integer(100000.into()));
    Value::Dictionary(d)
}

pub fn archive_bin(v: &NS) -> Vec<u8> {
    let mut out = vec![];
    plist::to_writer_binary(&mut out, &archive(v)).unwrap();
    out
}

// --- unarchiving ---

const MAX_DEPTH: usize = 128;

struct Unarchiver<'a> {
    objects: &'a [Value],
}

impl Unarchiver<'_> {
    fn resolve(&self, v: &Value, depth: usize) -> Result<NS> {
        match v {
            Value::Uid(u) => self.object(u.get() as usize, depth + 1),
            other => self.value(other, depth),
        }
    }

    fn uid_of(v: &Value) -> Option<usize> {
        match v {
            Value::Uid(u) => Some(u.get() as usize),
            Value::Dictionary(d) => xml_uid(d),
            _ => None,
        }
    }

    fn value(&self, v: &Value, depth: usize) -> Result<NS> {
        Ok(match v {
            Value::Boolean(b) => NS::Bool(*b),
            Value::Integer(i) => match i.as_signed() {
                Some(s) => NS::Int(s),
                None => NS::UInt(i.as_unsigned().unwrap_or(0)),
            },
            Value::Real(r) => NS::Real(*r),
            Value::String(s) if s == "$null" => NS::Null,
            Value::String(s) => NS::Str(s.clone()),
            Value::Data(d) => NS::Data(d.clone()),
            Value::Uid(_) => self.resolve(v, depth)?,
            Value::Array(a) => NS::Array(
                a.iter()
                    .map(|e| self.resolve(e, depth))
                    .collect::<Result<_>>()?,
            ),
            Value::Dictionary(d) => match xml_uid(d) {
                Some(u) => self.object(u, depth + 1)?,
                None => self.class_object(d, depth)?,
            },
            _ => return bail("nskeyedarchiver: unsupported plist value"),
        })
    }

    fn object(&self, i: usize, depth: usize) -> Result<NS> {
        if depth > MAX_DEPTH {
            return bail("nskeyedarchiver: object graph too deep or cyclic");
        }
        let v = self
            .objects
            .get(i)
            .ok_or_else(|| Error::msg(format!("nskeyedarchiver: reference {i} out of range")))?;
        self.value(v, depth)
    }

    fn class_object(&self, d: &Dictionary, depth: usize) -> Result<NS> {
        let Some(c) = d.get("$class").and_then(Self::uid_of) else {
            // a plain dictionary inside the archive
            let mut out = vec![];
            for (k, v) in d {
                out.push((NS::Str(k.clone()), self.resolve(v, depth)?));
            }
            return Ok(NS::Dict(out));
        };
        let class = self
            .objects
            .get(c)
            .and_then(|v| v.as_dictionary())
            .and_then(|cd| cd.get("$classname"))
            .and_then(|v| v.as_string())
            .ok_or_else(|| Error::msg("nskeyedarchiver: bad $class reference"))?;
        let field = |k: &str| -> Result<NS> {
            match d.get(k) {
                Some(v) => self.resolve(v, depth),
                None => Ok(NS::Null),
            }
        };
        let list = |k: &str| -> Result<Vec<NS>> {
            match d.get(k) {
                Some(Value::Array(a)) => a.iter().map(|e| self.resolve(e, depth)).collect(),
                _ => Ok(vec![]),
            }
        };
        Ok(match class {
            "NSDictionary" | "NSMutableDictionary" => {
                let keys = list("NS.keys")?;
                let vals = list("NS.objects")?;
                if keys.len() != vals.len() {
                    return bail("nskeyedarchiver: dictionary keys and objects differ in length");
                }
                NS::Dict(keys.into_iter().zip(vals).collect())
            }
            "NSArray" | "NSMutableArray" => NS::Array(list("NS.objects")?),
            "NSSet" | "NSMutableSet" | "NSOrderedSet" | "NSMutableOrderedSet" => {
                NS::Set(list("NS.objects")?)
            }
            "NSString" | "NSMutableString" => field("NS.string")?,
            "NSData" | "NSMutableData" => field("NS.data")?,
            "NSNull" => NS::Null,
            "NSUUID" => match d.get("NS.uuidbytes") {
                Some(Value::Data(b)) if b.len() == 16 => NS::Uuid(b[..].try_into().unwrap()),
                _ => return bail("nskeyedarchiver: NSUUID without 16 uuid bytes"),
            },
            "NSURL" => {
                let base = field("NS.base")?;
                NS::Url {
                    base: if base == NS::Null {
                        None
                    } else {
                        Some(Box::new(base))
                    },
                    relative: field("NS.relative")?.as_str().unwrap_or("").to_string(),
                }
            }
            "NSDate" => match d.get("NS.time") {
                Some(Value::Real(t)) => NS::Date(*t),
                Some(Value::Integer(t)) => NS::Date(t.as_signed().unwrap_or(0) as f64),
                _ => NS::Date(0.0),
            },
            "NSError" => NS::Error {
                code: match field("NSCode")? {
                    NS::Int(i) => i,
                    NS::UInt(u) => u as i64,
                    _ => 0,
                },
                domain: field("NSDomain")?.as_str().unwrap_or("").to_string(),
                user_info: Box::new(field("NSUserInfo")?),
            },
            _ => {
                let mut fields = BTreeMap::new();
                for (k, v) in d {
                    if k != "$class" {
                        fields.insert(k.clone(), self.resolve(v, depth)?);
                    }
                }
                NS::Object {
                    class: class.to_string(),
                    fields,
                }
            }
        })
    }
}

/// XML plists spell a UID as `{CF$UID: n}`.
fn xml_uid(d: &Dictionary) -> Option<usize> {
    if d.len() == 1 {
        return d
            .get("CF$UID")
            .and_then(|v| v.as_unsigned_integer())
            .map(|u| u as usize);
    }
    None
}

pub fn unarchive(bytes: &[u8]) -> Result<NS> {
    unarchive_all(bytes)?
        .into_iter()
        .next()
        .ok_or_else(|| Error::msg("nskeyedarchiver: empty $top"))
}

/// Every top-level object: `root`, or `$0`, `$1`, ... in order.
pub fn unarchive_all(bytes: &[u8]) -> Result<Vec<NS>> {
    let v: Value = plist::from_bytes(bytes)?;
    let d = v
        .as_dictionary()
        .ok_or_else(|| Error::msg("nskeyedarchiver: archive is not a dictionary"))?;
    if d.get("$archiver").and_then(|v| v.as_string()) != Some("NSKeyedArchiver") {
        return bail("nskeyedarchiver: missing or wrong $archiver");
    }
    if d.get("$version").and_then(|v| v.as_unsigned_integer()) != Some(100000) {
        return bail("nskeyedarchiver: missing or wrong $version");
    }
    let objects = d
        .get("$objects")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::msg("nskeyedarchiver: missing $objects"))?;
    let top = d
        .get("$top")
        .and_then(|v| v.as_dictionary())
        .ok_or_else(|| Error::msg("nskeyedarchiver: missing $top"))?;
    let u = Unarchiver { objects };
    if let Some(root) = top.get("root") {
        return Ok(vec![u.resolve(root, 0)?]);
    }
    let mut keyed: Vec<(usize, &Value)> = top
        .iter()
        .filter_map(|(k, v)| Some((k.strip_prefix('$')?.parse().ok()?, v)))
        .collect();
    if keyed.is_empty() {
        return bail("nskeyedarchiver: missing $top root");
    }
    keyed.sort_by_key(|(i, _)| *i);
    keyed.into_iter().map(|(_, v)| u.resolve(v, 0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Archives written by Foundation, see tests/fixtures/nskeyedarchiver/generate.swift.
    fn fixture(n: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/nskeyedarchiver/{n}")).unwrap()
    }

    const UUID: [u8; 16] = [
        0x45, 0x88, 0xd2, 0xdb, 0x23, 0x40, 0x6c, 0x41, 0xbe, 0x63, 0x45, 0x96, 0xc6, 0xae, 0x7f,
        0xe3,
    ];

    #[test]
    fn decodes_foundation_archives() {
        let cases = [
            (
                "primitives",
                r#"[1,-7,1.5,true,false,"Hello, World!","cmlvcw==",9223372036854775807,18446744073709551615]"#,
            ),
            (
                "collections",
                r#"{"array":[true,"a",42],"date":1000.5,"mutable":"m","nested":[[1],[2,[3]]],"null":null,"set":[5],"uuid":"4588d2db-2340-6c41-be63-4596c6ae7fe3"}"#,
            ),
        ];
        for (n, want) in cases {
            for ext in ["bin", "xml"] {
                let got = unarchive(&fixture(&format!("{n}.{ext}")))
                    .unwrap()
                    .to_json();
                let want: serde_json::Value = serde_json::from_str(want).unwrap();
                assert_eq!(got, want, "{n}.{ext}");
            }
        }
    }

    #[test]
    fn decodes_foundation_classes() {
        assert_eq!(unarchive(&fixture("uuid.bin")).unwrap(), NS::Uuid(UUID));
        assert_eq!(
            unarchive(&fixture("url.bin")).unwrap(),
            NS::Url {
                base: Some(Box::new(NS::Url {
                    base: None,
                    relative: "file:///var/R.app/".into()
                })),
                relative: "PlugIns/R.xctest".into(),
            }
        );
        assert_eq!(
            unarchive(&fixture("error.bin")).unwrap(),
            NS::Error {
                code: 7,
                domain: "com.example".into(),
                user_info: Box::new(NS::Dict(vec![(
                    NS::str("NSLocalizedDescription"),
                    NS::str("boom")
                )])),
            }
        );
        let caps = unarchive(&fixture("capabilities.bin")).unwrap();
        assert!(matches!(&caps, NS::Object { class, .. } if class == "XCTCapabilities"));
        assert_eq!(
            caps.get("capabilities-dictionary").unwrap().to_json(),
            serde_json::json!({"expected failure test capability": 1, "test timeout capability": 1})
        );
        let keys = unarchive(&fixture("uint64-keys.bin")).unwrap();
        let NS::Dict(entries) = &keys else {
            panic!("{keys:?}")
        };
        assert!(entries.contains(&(NS::UInt(u64::MAX), NS::str("max"))));
        let value = unarchive(&fixture("value.bin")).unwrap();
        assert_eq!(value.get("NS.rangeval.length"), Some(&NS::Int(2)));
    }

    // our archives are the same plists Foundation writes
    #[test]
    fn archives_like_foundation() {
        for (f, v) in [
            ("null.bin", NS::Null),
            ("uuid.bin", NS::Uuid(UUID)),
            ("empty-array.bin", NS::Array(vec![])),
            (
                "strings.bin",
                NS::Array(vec![NS::str("a"), NS::str("n"), NS::str("c")]),
            ),
        ] {
            let foundation: Value = plist::from_bytes(&fixture(f)).unwrap();
            assert_eq!(archive(&v), foundation, "{f}");
        }
    }

    #[test]
    fn malformed_archives_are_errors() {
        let good: Value = plist::from_bytes(&fixture("collections.bin")).unwrap();
        let broken = |f: &dyn Fn(&mut Dictionary)| {
            let mut v = good.clone();
            f(v.as_dictionary_mut().unwrap());
            let mut out = vec![];
            plist::to_writer_binary(&mut out, &v).unwrap();
            out
        };
        assert!(unarchive(&broken(&|_| {})).is_ok());
        for k in ["$archiver", "$objects", "$top", "$version"] {
            assert!(unarchive(&broken(&|d| drop(d.remove(k)))).is_err(), "{k}");
        }
        let wrong: [(&str, Value); 3] = [
            ("$archiver", "NSArchiver".into()),
            ("$version", 7.into()),
            (
                "$top",
                Value::Dictionary(dict_of("root", Value::Uid(Uid::new(999)))),
            ),
        ];
        for (k, v) in wrong {
            let e = broken(&|d| drop(d.insert(k.into(), v.clone())));
            assert!(unarchive(&e).is_err(), "{k}");
        }
        let bin = fixture("collections.bin");
        assert!(unarchive(&bin[..bin.len() / 2]).is_err());
    }

    fn dict_of(k: &str, v: Value) -> Dictionary {
        let mut d = Dictionary::new();
        d.insert(k.into(), v);
        d
    }

    #[test]
    fn archive_roundtrips() {
        let cases = vec![
            NS::Array(vec![NS::str("a"), NS::str("n"), NS::str("c")]),
            NS::Array(vec![]),
            NS::dict(vec![
                ("name", NS::str("james")),
                ("age", NS::Int(20)),
                (
                    "children",
                    NS::Array(vec![NS::str("abc"), NS::str("def"), NS::str("ok")]),
                ),
            ]),
            NS::Uuid([7; 16]),
            NS::Url {
                base: None,
                relative: "file:///x".into(),
            },
            NS::obj(
                "XCTCapabilities",
                vec![("capabilities-dictionary", NS::dict(vec![("a", NS::Int(1))]))],
            ),
            NS::Error {
                code: 2,
                domain: "d".into(),
                user_info: Box::new(NS::dict(vec![])),
            },
        ];
        for c in cases {
            let back = unarchive(&archive_bin(&c)).unwrap();
            assert_eq!(back, c);
        }
    }

    #[test]
    fn cyclic_archive_is_rejected() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
            <key>$archiver</key><string>NSKeyedArchiver</string><key>$version</key><integer>100000</integer>
            <key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict>
            <key>$objects</key><array><string>$null</string>
              <dict><key>NS.objects</key><array><dict><key>CF$UID</key><integer>1</integer></dict></array>
                    <key>$class</key><dict><key>CF$UID</key><integer>2</integer></dict></dict>
              <dict><key>$classname</key><string>NSArray</string><key>$classes</key><array><string>NSArray</string></array></dict>
            </array></dict></plist>"#;
        assert!(unarchive(xml.as_bytes()).is_err());
    }
}
