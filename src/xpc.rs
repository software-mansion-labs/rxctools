//! RemoteXPC: the XPC wire format, the minimal HTTP/2 framing it rides on, and RSD service discovery.

use crate::util::{Error, Result, bail};
use std::collections::BTreeMap;
use std::io::{Read, Write};

const WRAPPER_MAGIC: u32 = 0x29b00b92;
const OBJECT_MAGIC: u32 = 0x42133742;
const BODY_VERSION: u32 = 5;

pub const ALWAYS_SET: u32 = 0x1;
pub const DATA_FLAG: u32 = 0x100;
pub const HEARTBEAT_REQUEST: u32 = 0x10000;
pub const INIT_HANDSHAKE: u32 = 0x400000;

#[derive(Clone, Debug, PartialEq)]
pub enum X {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Date(i64),
    Data(Vec<u8>),
    Str(String),
    Uuid([u8; 16]),
    Array(Vec<X>),
    Dict(BTreeMap<String, X>),
    FileTransfer { msg_id: u64, size: u64 },
}

impl X {
    pub fn get(&self, k: &str) -> Option<&X> {
        match self {
            X::Dict(d) => d.get(k),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            X::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            X::I64(i) => Some(*i),
            X::U64(u) => Some(*u as i64),
            _ => None,
        }
    }
}

impl From<&str> for X {
    fn from(s: &str) -> X {
        X::Str(s.into())
    }
}
impl From<String> for X {
    fn from(s: String) -> X {
        X::Str(s)
    }
}
impl From<bool> for X {
    fn from(b: bool) -> X {
        X::Bool(b)
    }
}

pub fn xdict(pairs: Vec<(&str, X)>) -> X {
    X::Dict(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

#[derive(Debug, PartialEq)]
pub struct Message {
    pub flags: u32,
    pub body: Option<X>,
    pub id: u64,
}

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

fn encode_object(out: &mut Vec<u8>, v: &X) {
    let ty = |out: &mut Vec<u8>, t: u32| out.extend_from_slice(&t.to_le_bytes());
    match v {
        X::Null => ty(out, 0x1000),
        X::Bool(b) => {
            ty(out, 0x2000);
            out.extend_from_slice(&[*b as u8, 0, 0, 0]);
        }
        X::I64(i) => {
            ty(out, 0x3000);
            out.extend_from_slice(&i.to_le_bytes());
        }
        X::U64(u) => {
            ty(out, 0x4000);
            out.extend_from_slice(&u.to_le_bytes());
        }
        X::F64(f) => {
            ty(out, 0x5000);
            out.extend_from_slice(&f.to_le_bytes());
        }
        X::Date(d) => {
            ty(out, 0x7000);
            out.extend_from_slice(&d.to_le_bytes());
        }
        X::Data(d) => {
            ty(out, 0x8000);
            out.extend_from_slice(&(d.len() as u32).to_le_bytes());
            out.extend_from_slice(d);
            out.extend(std::iter::repeat_n(0, pad4(d.len())));
        }
        X::Str(s) => {
            ty(out, 0x9000);
            out.extend_from_slice(&(s.len() as u32 + 1).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
            out.extend(std::iter::repeat_n(0, 1 + pad4(s.len() + 1)));
        }
        X::Uuid(u) => {
            ty(out, 0xa000);
            out.extend_from_slice(u);
        }
        X::Array(a) => {
            let mut body = vec![];
            for e in a {
                encode_object(&mut body, e);
            }
            ty(out, 0xe000);
            out.extend_from_slice(&(body.len() as u32 + 4).to_le_bytes());
            out.extend_from_slice(&(a.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
        }
        X::Dict(d) => {
            let mut body = vec![];
            body.extend_from_slice(&(d.len() as u32).to_le_bytes());
            for (k, v) in d {
                body.extend_from_slice(k.as_bytes());
                body.extend(std::iter::repeat_n(0, 1 + pad4(k.len() + 1)));
                encode_object(&mut body, v);
            }
            ty(out, 0xf000);
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
        }
        X::FileTransfer { msg_id, size } => {
            ty(out, 0x1a000);
            out.extend_from_slice(&msg_id.to_le_bytes());
            encode_object(out, &xdict(vec![("s", X::U64(*size))]));
        }
    }
}

pub fn encode_message(m: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&WRAPPER_MAGIC.to_le_bytes());
    out.extend_from_slice(&m.flags.to_le_bytes());
    match &m.body {
        None => {
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&m.id.to_le_bytes());
        }
        Some(b) => {
            let mut body = vec![];
            encode_object(&mut body, b);
            out.extend_from_slice(&(body.len() as u64 + 8).to_le_bytes());
            out.extend_from_slice(&m.id.to_le_bytes());
            out.extend_from_slice(&OBJECT_MAGIC.to_le_bytes());
            out.extend_from_slice(&BODY_VERSION.to_le_bytes());
            out.extend_from_slice(&body);
        }
    }
    out
}

struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return bail(format!("xpc: need {n} bytes, have {}", self.0.len()));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

fn decode_object(c: &mut Cur) -> Result<X> {
    let t = c.u32()?;
    Ok(match t {
        0x1000 => X::Null,
        0x2000 => {
            let b = c.take(4)?;
            X::Bool(b[0] != 0)
        }
        0x3000 => X::I64(c.u64()? as i64),
        0x4000 => X::U64(c.u64()?),
        0x5000 => X::F64(f64::from_bits(c.u64()?)),
        0x7000 => X::Date(c.u64()? as i64),
        0x8000 => {
            let l = c.u32()? as usize;
            let d = c.take(l)?.to_vec();
            c.take(pad4(l))?;
            X::Data(d)
        }
        0x9000 => {
            let l = c.u32()? as usize;
            let s = c.take(l)?;
            c.take(pad4(l))?;
            X::Str(
                String::from_utf8_lossy(s)
                    .trim_end_matches('\0')
                    .to_string(),
            )
        }
        0xa000 => X::Uuid(c.take(16)?.try_into().unwrap()),
        0xe000 => {
            let _len = c.u32()?;
            let n = c.u32()? as usize;
            if n > c.0.len() {
                return bail("xpc: array count exceeds payload");
            }
            let mut a = Vec::with_capacity(n);
            for _ in 0..n {
                a.push(decode_object(c)?);
            }
            X::Array(a)
        }
        0xf000 => {
            let _len = c.u32()?;
            let n = c.u32()? as usize;
            if n > c.0.len() {
                return bail("xpc: dictionary count exceeds payload");
            }
            let mut d = BTreeMap::new();
            for _ in 0..n {
                let end =
                    c.0.iter()
                        .position(|&b| b == 0)
                        .ok_or_else(|| Error::msg("xpc: unterminated key"))?;
                let k = String::from_utf8_lossy(c.take(end)?).to_string();
                c.take(1 + pad4(end + 1))?;
                let v = decode_object(c)?;
                d.insert(k, v);
            }
            X::Dict(d)
        }
        0x1a000 => {
            let msg_id = c.u64()?;
            let d = decode_object(c)?;
            let size = match d.get("s") {
                Some(X::U64(s)) => *s,
                _ => return bail("xpc: file transfer without size"),
            };
            X::FileTransfer { msg_id, size }
        }
        _ => return bail(format!("xpc: unknown type 0x{t:x}")),
    })
}

pub fn decode_message(r: &mut impl Read) -> Result<Message> {
    let mut h = [0u8; 24];
    r.read_exact(&mut h)?;
    if u32::from_le_bytes(h[0..4].try_into().unwrap()) != WRAPPER_MAGIC {
        return bail(format!(
            "DecodeMessage: wrong magic number 0x{:x}",
            u32::from_le_bytes(h[0..4].try_into().unwrap())
        ));
    }
    let flags = u32::from_le_bytes(h[4..8].try_into().unwrap());
    let len = u64::from_le_bytes(h[8..16].try_into().unwrap());
    let id = u64::from_le_bytes(h[16..24].try_into().unwrap());
    if len == 0 {
        return Ok(Message {
            flags,
            body: None,
            id,
        });
    }
    if len < 8 || len > crate::util::MAX_MESSAGE as u64 {
        return bail(format!("xpc: bad body length {len}"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    let mut c = Cur(&body);
    if c.u32()? != OBJECT_MAGIC {
        return bail("xpc: wrong object magic");
    }
    if c.u32()? != BODY_VERSION {
        return bail("xpc: unexpected body version");
    }
    Ok(Message {
        flags,
        body: Some(decode_object(&mut c)?),
        id,
    })
}

// --- HTTP/2, just enough for the two XPC streams ---

const H2_DATA: u8 = 0;
const H2_HEADERS: u8 = 1;
const H2_RST: u8 = 3;
const H2_SETTINGS: u8 = 4;
const H2_GOAWAY: u8 = 7;
const H2_WINDOW_UPDATE: u8 = 8;

fn h2_frame(out: &mut Vec<u8>, ty: u8, flags: u8, stream: u32, payload: &[u8]) {
    let l = payload.len() as u32;
    out.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8, ty, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
}

pub const CLIENT_SERVER: u32 = 1;
pub const SERVER_CLIENT: u32 = 3;

pub struct XpcConn<S: Read + Write> {
    pub s: S,
    bufs: [Vec<u8>; 2],
    opened: [bool; 2],
    out: Vec<u8>,
}

impl<S: Read + Write> XpcConn<S> {
    /// HTTP/2 preface + settings and the three-message XPC handshake, all written in one go.
    pub fn connect(s: S) -> Result<XpcConn<S>> {
        let mut c = XpcConn {
            s,
            bufs: [vec![], vec![]],
            opened: [false; 2],
            out: Vec::with_capacity(512),
        };
        c.out.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let mut settings = vec![];
        settings.extend_from_slice(&3u16.to_be_bytes()); // max concurrent streams
        settings.extend_from_slice(&100u32.to_be_bytes());
        settings.extend_from_slice(&4u16.to_be_bytes()); // initial window size
        settings.extend_from_slice(&1048576u32.to_be_bytes());
        h2_frame(&mut c.out, H2_SETTINGS, 0, 0, &settings);
        h2_frame(&mut c.out, H2_WINDOW_UPDATE, 0, 0, &983041u32.to_be_bytes());
        c.queue(
            CLIENT_SERVER,
            &Message {
                flags: ALWAYS_SET,
                body: Some(X::Dict(BTreeMap::new())),
                id: 0,
            },
        );
        c.queue(
            SERVER_CLIENT,
            &Message {
                flags: INIT_HANDSHAKE | ALWAYS_SET,
                body: None,
                id: 0,
            },
        );
        c.queue(
            CLIENT_SERVER,
            &Message {
                flags: 0x201,
                body: None,
                id: 0,
            },
        );
        c.flush()?;
        c.recv(CLIENT_SERVER)?;
        c.recv(SERVER_CLIENT)?;
        c.recv(CLIENT_SERVER)?;
        Ok(c)
    }

    fn queue(&mut self, stream: u32, m: &Message) {
        let i = (stream == SERVER_CLIENT) as usize;
        if !self.opened[i] {
            self.opened[i] = true;
            h2_frame(&mut self.out, H2_HEADERS, 0x4, stream, &[]);
        }
        h2_frame(&mut self.out, H2_DATA, 0, stream, &encode_message(m));
    }

    fn flush(&mut self) -> Result<()> {
        self.s.write_all(&self.out)?;
        self.s.flush()?;
        self.out.clear();
        Ok(())
    }

    pub fn send(&mut self, body: X, extra_flags: u32) -> Result<()> {
        self.queue(
            CLIENT_SERVER,
            &Message {
                flags: ALWAYS_SET | DATA_FLAG | extra_flags,
                body: Some(body),
                id: 1,
            },
        );
        self.flush()
    }

    fn read_frame(&mut self) -> Result<()> {
        let mut h = [0u8; 9];
        self.s.read_exact(&mut h)?;
        let len = (h[0] as usize) << 16 | (h[1] as usize) << 8 | h[2] as usize;
        let (ty, flags) = (h[3], h[4]);
        let stream = u32::from_be_bytes(h[5..9].try_into().unwrap()) & 0x7fff_ffff;
        let mut p = vec![0u8; len];
        self.s.read_exact(&mut p)?;
        match ty {
            H2_DATA => match stream {
                CLIENT_SERVER => self.bufs[0].extend_from_slice(&p),
                SERVER_CLIENT => self.bufs[1].extend_from_slice(&p),
                _ => return bail(format!("readDataFrame: unknown stream id {stream}")),
            },
            H2_SETTINGS if flags & 1 == 0 => {
                h2_frame(&mut self.out, H2_SETTINGS, 1, 0, &[]);
                self.flush()?;
            }
            H2_GOAWAY => return bail("received GOAWAY"),
            H2_RST => return bail("got RST frame"),
            _ => {}
        }
        Ok(())
    }

    /// Next XPC message on `stream`.
    pub fn recv(&mut self, stream: u32) -> Result<Message> {
        let i = (stream == SERVER_CLIENT) as usize;
        loop {
            let b = &self.bufs[i];
            if b.len() >= 24 {
                let body_len = u64::from_le_bytes(b[8..16].try_into().unwrap()) as usize;
                if b.len() >= 24 + body_len {
                    let mut cur = &b[..24 + body_len];
                    let m = decode_message(&mut cur)?;
                    self.bufs[i].drain(..24 + body_len);
                    return Ok(m);
                }
            }
            self.read_frame()?;
        }
    }

    /// Next message on `stream` that carries a body (the device interleaves empty keep-alives).
    pub fn recv_body(&mut self, stream: u32) -> Result<X> {
        loop {
            if let Some(b) = self.recv(stream)?.body {
                return Ok(b);
            }
        }
    }
}

/// RSD handshake: the services the device offers through the tunnel, name -> port.
pub fn parse_rsd_handshake(m: &X) -> Result<(String, BTreeMap<String, u16>)> {
    if m.get("MessageType").and_then(|v| v.as_str()) != Some("Handshake") {
        return bail("Handshake: unknown response");
    }
    let udid = m
        .get("Properties")
        .and_then(|p| p.get("UniqueDeviceID"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if udid.is_empty() {
        return bail("Handshake: could not read UDID");
    }
    let mut out = BTreeMap::new();
    if let Some(X::Dict(services)) = m.get("Services") {
        for (name, s) in services {
            // a malformed port on one entry must not abort the others
            if let Some(p) = s
                .get("Port")
                .and_then(|v| v.as_str())
                .and_then(|p| p.parse().ok())
            {
                out.insert(name.clone(), p);
            }
        }
    }
    Ok((udid, out))
}

pub fn rsd_handshake<S: Read + Write>(s: S) -> Result<(String, BTreeMap<String, u16>)> {
    let mut c = XpcConn::connect(s)?;
    let m = c.recv_body(CLIENT_SERVER)?;
    parse_rsd_handshake(&m)
}

/// Port of `name`, falling back to its `.shim.remote` variant.
pub fn service_port(services: &BTreeMap<String, u16>, name: &str) -> Option<u16> {
    services
        .get(name)
        .or_else(|| services.get(&format!("{name}.shim.remote")))
        .copied()
}

pub fn coredevice_request(device_id: &str, feature: &str, input: X) -> X {
    xdict(vec![
        ("CoreDevice.CoreDeviceDDIProtocolVersion", X::I64(0)),
        ("CoreDevice.action", xdict(vec![])),
        (
            "CoreDevice.coreDeviceVersion",
            xdict(vec![
                (
                    "components",
                    X::Array(vec![
                        X::U64(0x15c),
                        X::U64(1),
                        X::U64(0),
                        X::U64(0),
                        X::U64(0),
                    ]),
                ),
                ("originalComponentsCount", X::I64(2)),
                ("stringValue", "348.1".into()),
            ]),
        ),
        ("CoreDevice.deviceIdentifier", device_id.into()),
        ("CoreDevice.featureIdentifier", feature.into()),
        ("CoreDevice.input", input),
        (
            "CoreDevice.invocationIdentifier",
            uuid::Uuid::new_v4().to_string().to_uppercase().into(),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0x45, 0x88, 0xd2, 0xdb, 0x23, 0x40, 0x6c, 0x41, 0xbe, 0x63, 0x45, 0x96, 0xc6, 0xae, 0x7f,
        0xe3,
    ];

    /// Wrapper header (magic, flags, body length, message id), then the body.
    fn wrap(flags: u32, id: u64, body: &[u8]) -> Vec<u8> {
        let mut m = vec![0x92, 0x0b, 0xb0, 0x29];
        m.extend(flags.to_le_bytes());
        m.extend((body.len() as u64).to_le_bytes());
        m.extend(id.to_le_bytes());
        m.extend_from_slice(body);
        m
    }

    /// Object magic and version 5, then a dictionary: type, byte length (count included), count.
    fn dict_body(count: u32, entries: &[&[u8]]) -> Vec<u8> {
        let entries = entries.concat();
        let mut b = vec![0x42, 0x37, 0x13, 0x42, 5, 0, 0, 0, 0x00, 0xf0, 0, 0];
        b.extend(((entries.len() + 4) as u32).to_le_bytes());
        b.extend(count.to_le_bytes());
        b.extend(entries);
        b
    }

    /// One entry of every type, keys sorted; keys and strings are NUL-terminated and padded to 4.
    fn every_type() -> Vec<u8> {
        let (f, n) = (1.5f64.to_le_bytes(), (-1i64).to_le_bytes());
        let entries: &[&[u8]] = &[
            b"args\0\0\0\0",
            &[0x00, 0xe0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0], // array: byte length, count
            &[0x00, 0x90, 0, 0, 2, 0, 0, 0],              // string: length with the NUL
            b"x\0\0\0",
            b"data\0\0\0\0",
            &[0x00, 0x80, 0, 0, 3, 0, 0, 0, 1, 2, 3, 0],
            b"env\0",
            &[0x00, 0xf0, 0, 0, 28, 0, 0, 0, 1, 0, 0, 0],
            b"TERM\0\0\0\0",
            &[0x00, 0x90, 0, 0, 5, 0, 0, 0],
            b"dumb\0\0\0\0",
            b"f\0\0\0",
            &[0x00, 0x50, 0, 0],
            &f,
            b"n\0\0\0",
            &[0x00, 0x30, 0, 0],
            &n,
            b"null\0\0\0\0",
            &[0x00, 0x10, 0, 0],
            b"ok\0\0",
            &[0x00, 0x20, 0, 0, 1, 0, 0, 0],
            b"pid\0",
            &[0x00, 0x40, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0],
            b"uuid\0\0\0\0",
            &[0x00, 0xa0, 0, 0],
            &UUID,
        ];
        wrap(ALWAYS_SET | DATA_FLAG, 1, &dict_body(9, entries))
    }

    #[test]
    fn empty_dictionary_and_header_only() {
        let raw = wrap(ALWAYS_SET, 0, &dict_body(0, &[]));
        let m = decode_message(&mut &raw[..]).unwrap();
        assert_eq!((m.flags, m.id), (ALWAYS_SET, 0));
        assert_eq!(m.body, Some(X::Dict(BTreeMap::new())));
        assert_eq!(encode_message(&m), raw);
        let raw = wrap(ALWAYS_SET | INIT_HANDSHAKE, 0, &[]);
        let m = decode_message(&mut &raw[..]).unwrap();
        assert_eq!(m.body, None);
        assert_eq!(encode_message(&m), raw);
    }

    #[test]
    fn dictionary_of_every_type() {
        let raw = every_type();
        let m = decode_message(&mut &raw[..]).unwrap();
        assert_eq!((m.flags, m.id), (ALWAYS_SET | DATA_FLAG, 1));
        assert_eq!(
            m.body,
            Some(xdict(vec![
                ("args", X::Array(vec!["x".into()])),
                ("data", X::Data(vec![1, 2, 3])),
                ("env", xdict(vec![("TERM", "dumb".into())])),
                ("f", X::F64(1.5)),
                ("n", X::I64(-1)),
                ("null", X::Null),
                ("ok", X::Bool(true)),
                ("pid", X::U64(7)),
                ("uuid", X::Uuid(UUID)),
            ]))
        );
        assert_eq!(encode_message(&m), raw);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let uuid: [u8; 16] = [
            0x45, 0x88, 0xd2, 0xdb, 0x23, 0x40, 0x6c, 0x41, 0xbe, 0x63, 0x45, 0x96, 0xc6, 0xae,
            0x7f, 0xe3,
        ];
        let cases = vec![
            Some(xdict(vec![])),
            None,
            Some(xdict(vec![
                ("key", "value".into()),
                ("key-key", "value".into()),
            ])),
            Some(xdict(vec![
                ("key1", "string-val".into()),
                (
                    "nested-dict",
                    xdict(vec![
                        ("bool", X::Bool(true)),
                        ("int64", X::I64(123)),
                        ("uint64", X::U64(321)),
                        ("data", X::Data(vec![1])),
                        ("double", X::F64(1.2)),
                    ]),
                ),
            ])),
            Some(xdict(vec![("null", X::Null)])),
            Some(xdict(vec![(
                "array",
                X::Array(vec![X::U64(1), X::U64(2), X::U64(3)]),
            )])),
            Some(xdict(vec![("uuidvalue", X::Uuid(uuid))])),
        ];
        for body in cases {
            let m = Message {
                flags: ALWAYS_SET | DATA_FLAG,
                body: body.clone(),
                id: 0,
            };
            let bytes = encode_message(&m);
            let d = decode_message(&mut &bytes[..]).unwrap();
            assert_eq!(d.body, body);
            assert_eq!(d.flags, ALWAYS_SET | DATA_FLAG);
        }
    }

    #[test]
    fn rsd_ports_and_shim_fallback() {
        let services = xdict(vec![
            (
                "com.apple.dt.testmanagerd.remote",
                xdict(vec![("Port", "50340".into())]),
            ),
            (
                "com.apple.syslog_relay.shim.remote",
                xdict(vec![("Port", "50343".into())]),
            ),
            (
                "com.apple.broken",
                xdict(vec![("Port", "not-a-number".into())]),
            ),
        ]);
        let m = xdict(vec![
            ("MessageType", "Handshake".into()),
            (
                "Properties",
                xdict(vec![("UniqueDeviceID", "00008030-001".into())]),
            ),
            ("Services", services),
        ]);
        let (udid, s) = parse_rsd_handshake(&m).unwrap();
        assert_eq!(udid, "00008030-001");
        assert_eq!(
            service_port(&s, "com.apple.dt.testmanagerd.remote"),
            Some(50340)
        );
        assert_eq!(service_port(&s, "com.apple.syslog_relay"), Some(50343));
        assert_eq!(service_port(&s, "com.apple.broken"), None);
        assert!(parse_rsd_handshake(&xdict(vec![("MessageType", "Other".into())])).is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_message(&mut &[0u8; 24][..]).is_err());
        let mut m = encode_message(&Message {
            flags: 1,
            body: Some(xdict(vec![("a", X::U64(1))])),
            id: 0,
        });
        let n = m.len();
        m.truncate(n - 3);
        assert!(decode_message(&mut &m[..]).is_err());
    }
}
