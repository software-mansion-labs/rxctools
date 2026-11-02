//! usbmuxd client: device list, pair records and raw connections to device ports.

use crate::util::{Error, Result};
use plist::{Dictionary, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;

pub enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            Stream::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            Stream::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `USBMUXD_SOCKET_ADDRESS`: `host:port` is TCP, a bare path is a unix socket,
/// `scheme://address` is explicit.
pub fn socket_address() -> String {
    match std::env::var("USBMUXD_SOCKET_ADDRESS") {
        Ok(s) if !s.is_empty() => {
            if let Some(i) = s.find("://") {
                format!("{}{}", s[..i].to_lowercase(), &s[i..])
            } else if s.contains(':') {
                format!("tcp://{s}")
            } else {
                format!("unix://{s}")
            }
        }
        _ => "unix:///var/run/usbmuxd".into(),
    }
}

fn open_socket() -> Result<Stream> {
    let addr = socket_address();
    let (scheme, rest) = addr.split_once("://").unwrap();
    Ok(match scheme {
        "tcp" => {
            let s = TcpStream::connect(rest)
                .map_err(|e| Error::msg(format!("connect usbmuxd {rest}: {e}")))?;
            s.set_nodelay(true).ok();
            Stream::Tcp(s)
        }
        _ => Stream::Unix(
            UnixStream::connect(rest)
                .map_err(|e| Error::msg(format!("connect usbmuxd {rest}: {e}")))?,
        ),
    })
}

#[derive(Clone, Debug)]
pub struct DeviceEntry {
    pub device_id: u64,
    pub serial: String,
    pub connection_type: String,
}

pub struct Mux {
    pub s: Stream,
    tag: u32,
}

pub fn encode_message(tag: u32, msg: &Dictionary) -> Vec<u8> {
    let mut body = Vec::new();
    plist::to_writer_xml(&mut body, msg).unwrap();
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&(16 + body.len() as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&8u32.to_le_bytes());
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Reads one usbmux message; returns (header tag, payload plist).
pub fn decode_message(r: &mut impl Read) -> Result<(u32, Value)> {
    let mut h = [0u8; 16];
    r.read_exact(&mut h)?;
    let len = u32::from_le_bytes(h[0..4].try_into().unwrap());
    if len < 16 {
        return Err(Error::msg(format!(
            "invalid usbmux header length {len}, must be at least 16"
        )));
    }
    if len > crate::util::MAX_MESSAGE {
        return Err(Error::msg(format!(
            "usbmux message length {len} exceeds maximum allowed size"
        )));
    }
    let mut body = vec![0u8; len as usize - 16];
    r.read_exact(&mut body)?;
    let tag = u32::from_le_bytes(h[12..16].try_into().unwrap());
    Ok((tag, plist::from_bytes(&body)?))
}

fn base_request(kind: &str) -> Dictionary {
    let mut d = Dictionary::new();
    d.insert("MessageType".into(), kind.into());
    d.insert("ProgName".into(), "rxc".into());
    d.insert("ClientVersionString".into(), "usbmuxd-471.8.1".into());
    d.insert("BundleID".into(), "rxc".into());
    d.insert("kLibUSBMuxVersion".into(), 3.into());
    d
}

impl Mux {
    pub fn connect() -> Result<Mux> {
        Ok(Mux {
            s: open_socket()?,
            tag: 0,
        })
    }

    pub fn send(&mut self, msg: &Dictionary) -> Result<u32> {
        self.tag += 1;
        self.s.write_all(&encode_message(self.tag, msg))?;
        Ok(self.tag)
    }

    pub fn recv(&mut self) -> Result<Dictionary> {
        let (_, v) = decode_message(&mut self.s)?;
        v.into_dictionary()
            .ok_or_else(|| Error::msg("usbmux reply is not a dictionary"))
    }

    pub fn send_list_devices(&mut self) -> Result<()> {
        self.send(&base_request("ListDevices")).map(|_| ())
    }

    pub fn send_read_pair_record(&mut self, udid: &str) -> Result<()> {
        let mut d = base_request("ReadPairRecord");
        d.insert("PairRecordID".into(), udid.into());
        self.send(&d).map(|_| ())
    }

    pub fn read_device_list(&mut self) -> Result<Vec<DeviceEntry>> {
        let r = self.recv()?;
        Ok(parse_device_list(&r))
    }

    pub fn list_devices(&mut self) -> Result<Vec<DeviceEntry>> {
        self.send_list_devices()?;
        self.read_device_list()
    }

    pub fn read_pair_record_reply(&mut self) -> Result<Dictionary> {
        let r = self.recv()?;
        let data = r
            .get("PairRecordData")
            .and_then(|v| v.as_data())
            .ok_or_else(|| Error::msg(format!("could not read pair record: {r:?}")))?;
        plist::from_bytes::<Dictionary>(data).map_err(Into::into)
    }

    /// Turns this usbmux connection into a raw byte stream to `port` on the device.
    pub fn connect_port(mut self, device_id: u64, port: u16) -> Result<Stream> {
        self.send_connect(device_id, port)?;
        self.finish_connect(port)
    }

    pub fn send_connect(&mut self, device_id: u64, port: u16) -> Result<()> {
        let mut d = base_request("Connect");
        d.insert("DeviceID".into(), Value::Integer(device_id.into()));
        d.insert(
            "PortNumber".into(),
            Value::Integer((port.swap_bytes() as u64).into()),
        );
        self.send(&d).map(|_| ())
    }

    pub fn finish_connect(mut self, port: u16) -> Result<Stream> {
        let r = self.recv()?;
        let n = r
            .get("Number")
            .and_then(|v| v.as_unsigned_integer())
            .unwrap_or(1);
        if n != 0 {
            return Err(Error::msg(format!(
                "usbmux connect to port {port} failed with result {n}"
            )));
        }
        Ok(self.s)
    }
}

pub fn parse_device_list(r: &Dictionary) -> Vec<DeviceEntry> {
    let mut out = vec![];
    if let Some(list) = r.get("DeviceList").and_then(|v| v.as_array()) {
        for d in list {
            let Some(d) = d.as_dictionary() else { continue };
            let props = d
                .get("Properties")
                .and_then(|v| v.as_dictionary())
                .cloned()
                .unwrap_or_default();
            out.push(DeviceEntry {
                device_id: d
                    .get("DeviceID")
                    .and_then(|v| v.as_unsigned_integer())
                    .unwrap_or(0),
                serial: props
                    .get("SerialNumber")
                    .and_then(|v| v.as_string())
                    .unwrap_or_default()
                    .to_string(),
                connection_type: props
                    .get("ConnectionType")
                    .and_then(|v| v.as_string())
                    .unwrap_or_default()
                    .to_string(),
            });
        }
    }
    out
}

/// A usbmux socket that has already seen one round trip. Relayed endpoints (usbfluxd over TCP, for
/// example) set up their upstream lazily on the first message, which costs a few hundred ms; doing that
/// on a spare socket in parallel hides it from the critical path.
pub struct WarmMux {
    handle: std::thread::JoinHandle<Result<(Mux, Vec<DeviceEntry>)>>,
}

impl WarmMux {
    pub fn spawn() -> WarmMux {
        WarmMux {
            handle: std::thread::spawn(|| {
                let mut m = Mux::connect()?;
                let list = m.list_devices()?;
                Ok((m, list))
            }),
        }
    }
    pub fn get(self) -> Result<(Mux, Vec<DeviceEntry>)> {
        self.handle
            .join()
            .map_err(|_| Error::msg("usbmux warmup thread panicked"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usbmuxd_socket_address() {
        let cases = [
            ("", "unix:///var/run/usbmuxd"),
            ("127.0.0.1:27015", "tcp://127.0.0.1:27015"),
            ("/var/run/usbmuxd", "unix:///var/run/usbmuxd"),
            ("TCP://127.0.0.1:1", "tcp://127.0.0.1:1"),
            ("unix:///tmp/x", "unix:///tmp/x"),
        ];
        for (input, want) in cases {
            unsafe { std::env::set_var("USBMUXD_SOCKET_ADDRESS", input) };
            assert_eq!(socket_address(), want, "input {input:?}");
        }
        unsafe { std::env::remove_var("USBMUXD_SOCKET_ADDRESS") };
    }

    #[test]
    fn codec_roundtrip() {
        let mut d = base_request("ListDevices");
        d.insert("Number".into(), 5.into());
        let bytes = encode_message(7, &d);
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize,
            bytes.len()
        );
        assert_eq!(&bytes[4..12], &[1, 0, 0, 0, 8, 0, 0, 0]);
        let (tag, v) = decode_message(&mut &bytes[..]).unwrap();
        assert_eq!(tag, 7);
        assert_eq!(v.into_dictionary().unwrap(), d);
    }

    // a truncated or undersized header is an error, not a panic
    #[test]
    fn codec_errors() {
        assert!(decode_message(&mut &[0u8; 3][..]).is_err());
        let mut short = [0u8; 16];
        short[0] = 4;
        assert!(decode_message(&mut &short[..]).is_err());
    }

    #[test]
    fn device_list_reply() {
        let mut props = Dictionary::new();
        props.insert("SerialNumber".into(), "00008120-0001".into());
        props.insert("ConnectionType".into(), "USB".into());
        let mut dev = Dictionary::new();
        dev.insert("DeviceID".into(), 4.into());
        dev.insert("Properties".into(), props.into());
        let mut reply = Dictionary::new();
        reply.insert("DeviceList".into(), vec![Value::Dictionary(dev)].into());
        let list = parse_device_list(&reply);
        assert_eq!(
            (
                list[0].device_id,
                list[0].serial.as_str(),
                list[0].connection_type.as_str()
            ),
            (4, "00008120-0001", "USB")
        );
    }
}
