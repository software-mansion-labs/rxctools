//! The code signature format rxc writes, without keys, clocks or I/O: provisioning profiles,
//! entitlements, requirements, code directory checks and the CMS around an RSA signature made
//! elsewhere. It builds for wasm32-unknown-unknown too, as the key holder's half of signing.

pub mod der;

use der::{Der, oid};
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

pub const PAGE_BITS: u8 = 14;
pub const PAGE: usize = 1 << PAGE_BITS;
/// Apple's WWDR G3 intermediate, which issues Apple Development certificates.
pub const WWDR_G3: &[u8] = include_bytes!("certs/apple-wwdr-g3.cer");
/// https://www.apple.com/appleca/AppleIncRootCertificate.cer
pub const APPLE_ROOT_CA: &[u8] = include_bytes!("certs/apple-root-ca.cer");
/// certificate 1[field.1.2.840.113635.100.6.2.1]: issued by Apple's developer intermediate.
const APPLE_DEV_INTERMEDIATE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01];

#[derive(Debug)]
pub struct Error(pub String);

impl Error {
    pub fn msg(s: impl Into<String>) -> Error {
        Error(s.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<plist::Error> for Error {
    fn from(e: plist::Error) -> Self {
        Error(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn bail<T>(s: impl Into<String>) -> Result<T> {
    Err(Error(s.into()))
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub struct Cert<'a> {
    /// Whole DER encodings, as CMS IssuerAndSerialNumber wants them.
    pub issuer: &'a [u8],
    pub serial: &'a [u8],
    /// RSAPublicKey DER from subjectPublicKeyInfo.
    pub public_key: &'a [u8],
    pub common_name: String,
    /// The team id, for Apple developer certificates.
    pub org_unit: String,
}

pub fn parse_cert(der: &[u8]) -> Result<Cert<'_>> {
    let mut tbs = Der(Der(Der(der).expect(0x30)?).expect(0x30)?);
    if tbs.0.first() == Some(&0xa0) {
        tbs.next()?; // version
    }
    let serial = tbs.raw()?;
    tbs.next()?; // signature algorithm
    let issuer = tbs.raw()?;
    tbs.next()?; // validity
    let (mut common_name, mut org_unit) = (String::new(), String::new());
    let mut rdns = Der(tbs.expect(0x30)?);
    while !rdns.is_empty() {
        let mut atvs = Der(rdns.expect(0x31)?);
        while !atvs.is_empty() {
            let mut atv = Der(atvs.expect(0x30)?);
            let (o, (_, v)) = (atv.expect(0x06)?, atv.next()?);
            let v = String::from_utf8_lossy(v).into_owned();
            match o {
                oid::COMMON_NAME => common_name = v,
                oid::ORG_UNIT => org_unit = v,
                _ => {}
            }
        }
    }
    let mut spki = Der(tbs.expect(0x30)?);
    spki.next()?; // algorithm
    let public_key = match spki.expect(0x03)? {
        [0, k @ ..] => k,
        _ => return bail("certificate: malformed public key"),
    };
    Ok(Cert {
        issuer,
        serial,
        public_key,
        common_name,
        org_unit,
    })
}

/// The certificate's common name and team, which a signing certificate must have.
pub fn subject(cert: &[u8]) -> Result<(String, String)> {
    let c = parse_cert(cert)?;
    if c.org_unit.is_empty() {
        return bail("the certificate has no team id (subject OU)");
    }
    Ok((c.common_name, c.org_unit))
}

pub fn parse_profile(raw: &[u8]) -> Result<Dictionary> {
    // the plist sits inside a CMS envelope; the envelope's signature is Apple's business
    let find = |h: &[u8], n: &[u8]| h.windows(n.len()).position(|w| w == n);
    let start = find(raw, b"<?xml");
    let end = start.and_then(|s| find(&raw[s..], b"</plist>").map(|e| s + e + 8));
    match (start, end) {
        (Some(s), Some(e)) => Value::from_reader(std::io::Cursor::new(&raw[s..e]))?
            .into_dictionary()
            .ok_or_else(|| Error::msg("provisioning profile is not a dictionary")),
        _ => bail("not a provisioning profile"),
    }
}

/// The one certificate the profile lists.
// shortcut: refuses team profiles with several certificates; pass the key holder's certificate in
// when remote signing must work with one
pub fn profile_cert(profile: &Dictionary) -> Result<Vec<u8>> {
    let certs = profile
        .get("DeveloperCertificates")
        .and_then(Value::as_array);
    let Some([Value::Data(cert)]) = certs.map(Vec::as_slice) else {
        return bail("the provisioning profile does not list exactly one certificate");
    };
    Ok(cert.clone())
}

/// The profile's entitlements narrowed to this app, the way Xcode writes them: the
/// application identifier and wildcard keychain groups become `TEAM.bundle`.
pub fn entitlements_for(
    profile: &Dictionary,
    cert: &[u8],
    bundle: &str,
    now: SystemTime,
) -> Result<Dictionary> {
    if let Some(expiry) = profile.get("ExpirationDate").and_then(Value::as_date)
        && SystemTime::from(expiry) < now
    {
        return bail(format!(
            "the provisioning profile expired on {}",
            expiry.to_xml_format()
        ));
    }
    let has_cert = profile
        .get("DeveloperCertificates")
        .and_then(Value::as_array)
        .is_some_and(|c| c.iter().any(|c| c.as_data() == Some(cert)));
    if !has_cert {
        return bail("the provisioning profile does not include the p12's certificate");
    }
    let mut ent = profile
        .get("Entitlements")
        .and_then(Value::as_dictionary)
        .cloned()
        .ok_or_else(|| Error::msg("the provisioning profile has no entitlements"))?;
    let app_id = format!("{}.{bundle}", subject(cert)?.1);
    let allowed = ent
        .get("application-identifier")
        .and_then(Value::as_string)
        .unwrap_or_default();
    let covers = match allowed.strip_suffix('*') {
        Some(prefix) => app_id.starts_with(prefix),
        None => allowed == app_id,
    };
    if !covers {
        return bail(format!(
            "the provisioning profile is for {allowed}, which does not cover {app_id}"
        ));
    }
    ent.insert("application-identifier".into(), app_id.clone().into());
    if let Some(Value::Array(groups)) = ent.get_mut("keychain-access-groups") {
        for g in groups.iter_mut() {
            if g.as_string().is_some_and(|g| g.ends_with('*')) {
                *g = app_id.clone().into();
            }
        }
    }
    Ok(ent)
}

pub fn blob(magic: u32, payload: &[u8]) -> Vec<u8> {
    [
        &magic.to_be_bytes()[..],
        &(8 + payload.len() as u32).to_be_bytes()[..],
        payload,
    ]
    .concat()
}

/// The XML and DER entitlements blobs, which code directories hash into slots 5 and 7.
pub fn entitlement_blobs(e: &Dictionary) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut xml = vec![];
    Value::Dictionary(e.clone()).to_writer_xml(&mut xml)?;
    Ok((
        blob(0xfade7171, &xml),
        blob(0xfade7172, &der_entitlements(e)?),
    ))
}

/// The designated requirement Xcode writes for Apple Development certificates.
pub fn requirements(ident: &str, common_name: &str) -> Vec<u8> {
    let mut e = vec![];
    let op = |e: &mut Vec<u8>, v: u32| e.extend(v.to_be_bytes());
    let data = |e: &mut Vec<u8>, b: &[u8]| {
        e.extend((b.len() as u32).to_be_bytes());
        e.extend(b);
        e.resize(e.len().next_multiple_of(4), 0);
    };
    op(&mut e, 6); // and
    op(&mut e, 2); // identifier
    data(&mut e, ident.as_bytes());
    op(&mut e, 6); // and
    op(&mut e, 15); // anchor apple generic
    op(&mut e, 6); // and
    op(&mut e, 11); // certificate field
    op(&mut e, 0); // leaf
    data(&mut e, b"subject.CN");
    op(&mut e, 1); // equals
    data(&mut e, common_name.as_bytes());
    op(&mut e, 14); // certificate generic (extension)
    op(&mut e, 1); // certificate 1
    data(&mut e, APPLE_DEV_INTERMEDIATE);
    op(&mut e, 0); // exists
    let designated = blob(0xfade0c00, &[&1u32.to_be_bytes()[..], &e[..]].concat());
    // one requirement: designated (3), right after the 20-byte set header
    let header = [1u32, 3, 20].map(u32::to_be_bytes).concat();
    blob(0xfade0c01, &[header, designated].concat())
}

/// Entitlements in Apple's DER form: [APPLICATION 16] { 1, [16] { {key, value}... } }.
pub fn der_entitlements(e: &Dictionary) -> Result<Vec<u8>> {
    fn value(v: &Value) -> Result<Vec<u8>> {
        Ok(match v {
            Value::Boolean(b) => vec![0x01, 0x01, if *b { 0xff } else { 0 }],
            Value::String(s) => der::utf8(s),
            Value::Integer(i) => der::int(
                i.as_signed()
                    .ok_or_else(|| Error::msg("entitlements: integer out of range"))?,
            ),
            Value::Array(a) => der::tlv(
                0x30,
                &a.iter().map(value).collect::<Result<Vec<_>>>()?.concat(),
            ),
            Value::Dictionary(d) => {
                let mut pairs: Vec<_> = d.iter().collect();
                pairs.sort_by_key(|p| p.0);
                let pairs = pairs
                    .into_iter()
                    .map(|(k, v)| Ok(der::seq(&[&der::utf8(k), &value(v)?])))
                    .collect::<Result<Vec<_>>>()?;
                der::tlv(0xb0, &pairs.concat())
            }
            _ => {
                return bail(
                    "entitlements: only booleans, strings, integers, arrays and dictionaries are supported",
                );
            }
        })
    }
    Ok(der::tlv(
        0x70,
        &[der::int(1), value(&Value::Dictionary(e.clone()))?].concat(),
    ))
}

/// Fails unless `cd` is a code directory that signing an app with `cert` and `profile` could
/// have produced. Left free are the identifier, the Info.plist, resources and page hashes, and
/// the code and __TEXT extents; the entitlements must be the profile's for the identifier, which
/// is the bundle id for apps and app extensions.
pub fn check_code_directory(
    profile: &Dictionary,
    cert: &[u8],
    cd: &[u8],
    now: SystemTime,
) -> Result<()> {
    let refuse = |why: String| bail(format!("refusing to sign: {why}"));
    let at = |o: usize| {
        cd.get(o..o + 4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize)
            .ok_or_else(|| Error::msg("refusing to sign: not a code directory"))
    };
    let at64 = |o| Ok::<_, Error>(((at(o)? as u64) << 32) | at(o + 4)? as u64);
    if cd.len() < 88 || at(0)? != 0xfade0c02 || at(4)? != cd.len() {
        return refuse("not a code directory".into());
    }
    let (hash_off, n_special, n_code, limit) = (at(16)?, at(24)?, at(28)?, at(32)?);
    // version, identifier offset, spare2, scatter, spare3, code limit 64 (two words); then hash
    // size, SHA-256, platform, page size
    let header = [at(8)?, at(20)?, at(40)?, at(44)?, at(52)?, at(56)?, at(60)?];
    if header != [0x20400, 88, 0, 0, 0, 0, 0] || cd[36..40] != [32, 2, 0, PAGE_BITS] {
        return refuse("not laid out the way rxc lays out code directories".into());
    }
    if at(12)? != 0 {
        return refuse(format!("flags {:#x}, such as ad-hoc", at(12)?));
    }
    let ident = cd[88..].split(|b| *b == 0).next().map(std::str::from_utf8);
    let Some(Ok(ident)) = ident.filter(|_| cd[88..].contains(&0)) else {
        return refuse("no identifier".into());
    };
    let (common_name, team) = subject(cert)?;
    let team_off = 88 + ident.len() + 1;
    let team_z = [team.as_bytes(), b"\0"].concat();
    if at(48)? != team_off || cd.get(team_off..team_off + team_z.len()) != Some(&team_z[..]) {
        return refuse(format!("not for team {team}"));
    }
    let slots_ok = [2, 3, 7].contains(&n_special)
        && n_code == limit.div_ceil(PAGE)
        && hash_off == team_off + team_z.len() + 32 * n_special
        && hash_off + 32 * n_code == cd.len();
    if !slots_ok {
        return refuse("hash slots that do not add up".into());
    }
    let slot = |n: usize| &cd[hash_off - 32 * n..hash_off - 32 * (n - 1)];
    if slot(2) != sha256(&requirements(ident, &common_name)) {
        return refuse("requirements other than rxc's".into());
    }
    let mut exec_flags = vec![0, 1];
    if n_special == 7 {
        let ent = entitlements_for(profile, cert, ident, now)?;
        let (xml, der) = entitlement_blobs(&ent)?;
        let same = slot(4) == [0; 32]
            && slot(5) == sha256(&xml)
            && slot(6) == [0; 32]
            && slot(7) == sha256(&der);
        if !same {
            return refuse(format!("entitlements other than the profile's for {ident}"));
        }
        if ent.get("get-task-allow").and_then(Value::as_boolean) == Some(true) {
            exec_flags.push(0x11);
        }
    }
    if !exec_flags.contains(&at64(80)?) {
        return refuse(format!("exec segment flags {:#x}", at64(80)?));
    }
    Ok(())
}

/// The CMS signed attributes for `cd` as Xcode makes them, in the DER SET form that RSA signs.
pub fn cms_attrs(cd: &[u8], now: SystemTime) -> Result<Vec<u8>> {
    let cdhash = sha256(cd);
    let mut cdhashes = vec![];
    Value::Dictionary(Dictionary::from_iter([(
        "cdhashes".to_string(),
        Value::Array(vec![Value::Data(cdhash[..20].to_vec())]),
    )]))
    .to_writer_xml(&mut cdhashes)?;
    // UTCTime YYMMDDhhmmssZ from YYYY-MM-DDThh:mm:ssZ
    let t = plist::Date::from(now).to_xml_format();
    let utc = [
        &t[2..4],
        &t[5..7],
        &t[8..10],
        &t[11..13],
        &t[14..16],
        &t[17..19],
        "Z",
    ]
    .concat();
    let attr = |o: &[u8], v: &[u8]| der::seq(&[&der::oid(o), &der::set(&[v])]);
    let mut attrs = [
        attr(oid::CONTENT_TYPE, &der::oid(oid::DATA)),
        attr(oid::SIGNING_TIME, &der::tlv(0x17, utc.as_bytes())),
        attr(oid::MESSAGE_DIGEST, &der::octets(&cdhash)),
        attr(
            oid::APPLE_CDHASHES2,
            &der::seq(&[&der::oid(oid::SHA256), &der::octets(&cdhash)]),
        ),
        attr(oid::APPLE_CDHASHES, &der::octets(&cdhashes)),
    ];
    attrs.sort(); // DER orders SET OF by encoding
    Ok(der::tlv(0x31, &attrs.concat()))
}

/// Detached CMS SignedData over a code directory, as Xcode makes it: `cert` with Apple's chain,
/// the attributes from [`cms_attrs`] and the RSASSA-PKCS1-v1_5 SHA-256 `signature` over them.
pub fn signed_data(cert: &[u8], attrs: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    let c = parse_cert(cert)?;
    let signer_info = der::seq(&[
        &der::int(1),
        &der::seq(&[c.issuer, c.serial]),
        &der::alg(oid::SHA256),
        &der::tlv(0xa0, Der(attrs).expect(0x31)?),
        &der::alg(oid::SHA256_RSA),
        &der::octets(signature),
    ]);
    // shortcut: always chains through WWDR G3, which issues Apple Development certificates
    // today; read the issuer from the certificate if Apple moves them to another intermediate
    let certs = [cert, WWDR_G3, APPLE_ROOT_CA].concat();
    let signed = der::seq(&[
        &der::int(1),
        &der::set(&[&der::alg(oid::SHA256)]),
        &der::seq(&[&der::oid(oid::DATA)]),
        &der::tlv(0xa0, &certs),
        &der::set(&[&signer_info]),
    ]);
    Ok(der::seq(&[
        &der::oid(oid::SIGNED_DATA),
        &der::tlv(0xa0, &signed),
    ]))
}

/// A key holder's first step: the attributes to sign for `cd`, once it passes
/// [`check_code_directory`] for the certificate the profile lists.
pub fn signed_attrs(profile: &[u8], cd: &[u8], now: SystemTime) -> Result<Vec<u8>> {
    let profile = parse_profile(profile)?;
    check_code_directory(&profile, &profile_cert(&profile)?, cd, now)?;
    cms_attrs(cd, now)
}

/// The second step: the CMS from those attributes and the key holder's signature over them.
pub fn cms(profile: &[u8], attrs: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    signed_data(&profile_cert(&parse_profile(profile)?)?, attrs, signature)
}
