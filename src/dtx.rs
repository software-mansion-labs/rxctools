//! DTX, the RPC protocol of instruments and testmanagerd: framing, auxiliary arguments, channels.

use crate::nskeyed::{self, NS};
use crate::util::{Error, Result, bail};
use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAGIC: u32 = 0x795B3D1F;
pub const METHOD_INVOCATION: u32 = 2;
pub const RESPONSE_WITH_RETURN_VALUE: u32 = 3;
pub const ERROR: u32 = 4;

#[derive(Clone, Debug, PartialEq)]
pub enum Aux {
    Null,
    Str(String),
    Bytes(Vec<u8>),
    U32(u32),
    I64(i64),
}

impl Aux {
    pub fn archived(v: &NS) -> Aux {
        Aux::Bytes(nskeyed::archive_bin(v))
    }
    pub fn unarchive(&self) -> Option<NS> {
        match self {
            Aux::Bytes(b) => nskeyed::unarchive(b).ok(),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Msg {
    pub fragment_index: u16,
    pub fragments: u16,
    pub identifier: u32,
    pub conversation_index: u32,
    pub channel: i32,
    pub expects_reply: bool,
    pub msg_type: u32,
    pub aux: Vec<Aux>,
    pub payload: Vec<u8>,
}

impl Msg {
    pub fn payload_object(&self) -> Option<NS> {
        if self.payload.is_empty() {
            return None;
        }
        nskeyed::unarchive(&self.payload).ok()
    }
    /// The selector of a method invocation.
    pub fn selector(&self) -> Option<String> {
        self.payload_object()
            .and_then(|p| p.as_str().map(|s| s.to_string()))
    }
    pub fn args(&self) -> Vec<Option<NS>> {
        self.aux.iter().map(|a| a.unarchive()).collect()
    }
}

pub fn encode_aux(aux: &[Aux]) -> Vec<u8> {
    let mut out = vec![];
    for a in aux {
        out.extend_from_slice(&0x0au32.to_le_bytes()); // null key
        match a {
            Aux::Null => out.extend_from_slice(&0x0au32.to_le_bytes()),
            Aux::Str(s) => {
                out.extend_from_slice(&1u32.to_le_bytes());
                out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
            Aux::Bytes(b) => {
                out.extend_from_slice(&2u32.to_le_bytes());
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
            Aux::U32(u) => {
                out.extend_from_slice(&3u32.to_le_bytes());
                out.extend_from_slice(&u.to_le_bytes());
            }
            Aux::I64(i) => {
                out.extend_from_slice(&6u32.to_le_bytes());
                out.extend_from_slice(&i.to_le_bytes());
            }
        }
    }
    out
}

/// Values of the primitive dictionary; keys are always null in DTX method calls and are dropped.
pub fn decode_aux(mut b: &[u8]) -> Result<Vec<Aux>> {
    let mut out = vec![];
    let mut is_key = true;
    while b.len() >= 4 {
        let t = u32::from_le_bytes(b[..4].try_into().unwrap());
        b = &b[4..];
        let v = match t {
            0x0a => Aux::Null,
            3 => {
                if b.len() < 4 {
                    return bail("dtx aux: truncated uint32");
                }
                let v = u32::from_le_bytes(b[..4].try_into().unwrap());
                b = &b[4..];
                Aux::U32(v)
            }
            6 => {
                if b.len() < 8 {
                    return bail("dtx aux: truncated int64");
                }
                let v = i64::from_le_bytes(b[..8].try_into().unwrap());
                b = &b[8..];
                Aux::I64(v)
            }
            1 | 2 => {
                if b.len() < 4 {
                    return bail("dtx aux: truncated length");
                }
                let l = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
                if b.len() < 4 + l {
                    return bail("dtx aux: insufficient bytes for data");
                }
                let d = b[4..4 + l].to_vec();
                b = &b[4 + l..];
                if t == 1 {
                    Aux::Str(String::from_utf8_lossy(&d).to_string())
                } else {
                    Aux::Bytes(d)
                }
            }
            _ => return bail(format!("unknown DtxPrimitiveDictionaryType: {t}")),
        };
        if is_key && t == 0x0a {
            is_key = false;
            continue;
        }
        out.push(v);
        is_key = true;
    }
    Ok(out)
}

pub fn encode(m: &Msg) -> Vec<u8> {
    let aux = encode_aux(&m.aux);
    let aux_with_header = if aux.is_empty() { 0 } else { aux.len() + 16 };
    let body_len = 16 + aux_with_header + m.payload.len();
    let mut out = Vec::with_capacity(32 + body_len);
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&32u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(body_len as u32).to_le_bytes());
    out.extend_from_slice(&m.identifier.to_le_bytes());
    out.extend_from_slice(&m.conversation_index.to_le_bytes());
    out.extend_from_slice(&(m.channel as u32).to_le_bytes());
    out.extend_from_slice(&(m.expects_reply as u32).to_le_bytes());
    out.extend_from_slice(&m.msg_type.to_le_bytes());
    out.extend_from_slice(&(aux_with_header as u32).to_le_bytes());
    out.extend_from_slice(&((aux_with_header + m.payload.len()) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    if !aux.is_empty() {
        out.extend_from_slice(&496u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(aux.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&aux);
    }
    out.extend_from_slice(&m.payload);
    out
}

pub fn ack(m: &Msg) -> Vec<u8> {
    encode(&Msg {
        identifier: m.identifier,
        conversation_index: m.conversation_index + 1,
        channel: m.channel,
        ..Default::default()
    })
}

fn header(h: &[u8; 32]) -> Result<(Msg, usize)> {
    if u32::from_be_bytes(h[0..4].try_into().unwrap()) != MAGIC {
        return bail(format!("Wrong Magic: {:x?}", &h[0..4]));
    }
    let u32le = |i: usize| u32::from_le_bytes(h[i..i + 4].try_into().unwrap());
    let len = u32le(12) as usize;
    if len > crate::util::MAX_MESSAGE as usize {
        return bail(format!("dtx message length {len} out of range"));
    }
    Ok((
        Msg {
            fragment_index: u16::from_le_bytes([h[8], h[9]]),
            fragments: u16::from_le_bytes([h[10], h[11]]),
            identifier: u32le(16),
            conversation_index: u32le(20),
            channel: u32le(24) as i32,
            expects_reply: u32le(28) == 1,
            ..Default::default()
        },
        len,
    ))
}

fn body(m: &mut Msg, b: &[u8]) -> Result<()> {
    if b.len() < 16 {
        return bail("dtx: payload header truncated");
    }
    let u32le = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
    m.msg_type = u32le(0);
    let aux_len = u32le(4) as usize;
    let total = u32le(8) as usize;
    if total > b.len() - 16 || aux_len > total {
        return bail("dtx: payload lengths exceed message");
    }
    if aux_len > 0 {
        if aux_len < 16 {
            return bail("dtx: auxiliary header truncated");
        }
        let size = u32::from_le_bytes(b[16 + 8..16 + 12].try_into().unwrap()) as usize;
        if 32 + size > b.len() {
            return bail("dtx: auxiliary exceeds message");
        }
        m.aux = decode_aux(&b[32..32 + size])?;
    }
    m.payload = b[16 + aux_len..16 + total].to_vec();
    Ok(())
}

#[cfg(test)]
const ACK: u32 = 0;

/// Decodes one message from the front of `data`; returns it and the remaining bytes. Fragments come
/// back as they are (see `Reader` for reassembly).
#[cfg(test)]
pub fn decode(data: &[u8]) -> Result<(Msg, &[u8])> {
    if data.len() < 32 {
        return bail("dtx: header truncated");
    }
    let (mut m, len) = header(data[..32].try_into().unwrap())?;
    if m.fragments > 1 && m.fragment_index == 0 {
        return Ok((m, &data[32..]));
    }
    if data.len() < 32 + len {
        return bail("dtx: message truncated");
    }
    let b = &data[32..32 + len];
    if m.fragments > 1 {
        m.payload = b.to_vec();
    } else {
        body(&mut m, b)?;
    }
    Ok((m, &data[32 + len..]))
}

/// Reads whole messages from a stream, reassembling fragments.
pub struct Reader<R: Read> {
    r: R,
    partial: HashMap<(u32, i32), (Msg, Vec<u8>, usize)>,
}

impl<R: Read> Reader<R> {
    pub fn new(r: R) -> Self {
        Reader {
            r,
            partial: HashMap::new(),
        }
    }

    pub fn read(&mut self) -> Result<Msg> {
        loop {
            let mut h = [0u8; 32];
            self.r.read_exact(&mut h)?;
            let (mut m, len) = header(&h)?;
            if m.fragments > 1 && m.fragment_index == 0 {
                self.partial
                    .insert((m.identifier, m.channel), (m, Vec::with_capacity(len), len));
                continue;
            }
            let mut b = vec![0u8; len];
            self.r.read_exact(&mut b)?;
            if m.fragments <= 1 {
                body(&mut m, &b)?;
                return Ok(m);
            }
            let key = (m.identifier, m.channel);
            let Some(entry) = self.partial.get_mut(&key) else {
                continue;
            };
            entry.1.extend_from_slice(&b);
            if m.fragment_index + 1 == m.fragments {
                let (mut first, data, _) = self.partial.remove(&key).unwrap();
                first.fragments = 1;
                body(&mut first, &data)?;
                return Ok(first);
            }
        }
    }
}

type Handler = Box<dyn Fn(&Dtx, &Msg) -> Option<Vec<u8>> + Send + Sync>;

/// A DTX connection with a reader thread: replies go to waiting callers, everything else to `handler`,
/// which may return a reply payload; otherwise messages that expect a reply are acked.
pub struct Dtx {
    w: Mutex<TcpStream>,
    next_id: AtomicU32,
    next_channel: AtomicI32,
    waiters: Mutex<HashMap<u32, Sender<Msg>>>,
    pub closed: AtomicBool,
    handler: Mutex<Option<Handler>>,
}

pub const TIMEOUT: Duration = Duration::from_secs(30);

impl Dtx {
    pub fn new(s: TcpStream) -> Result<Arc<Dtx>> {
        let r = s.try_clone()?;
        let d = Arc::new(Dtx {
            w: Mutex::new(s),
            next_id: AtomicU32::new(1),
            next_channel: AtomicI32::new(1),
            waiters: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            handler: Mutex::new(None),
        });
        let d2 = d.clone();
        std::thread::spawn(move || {
            let mut reader = Reader::new(BufReader::with_capacity(256 * 1024, r));
            loop {
                let m = match reader.read() {
                    Ok(m) => m,
                    Err(e) => {
                        crate::debug!("dtx connection closed", "err" => e.0);
                        d2.closed.store(true, Ordering::SeqCst);
                        d2.waiters.lock().unwrap().clear();
                        if let Some(h) = d2.handler.lock().unwrap().as_ref() {
                            h(
                                &d2,
                                &Msg {
                                    msg_type: u32::MAX,
                                    ..Default::default()
                                },
                            );
                        }
                        return;
                    }
                };
                if m.conversation_index > 0
                    && let Some(tx) = d2.waiters.lock().unwrap().remove(&m.identifier)
                {
                    let _ = tx.send(m);
                    continue;
                }
                let reply = d2.handler.lock().unwrap().as_ref().and_then(|h| h(&d2, &m));
                if let Some(r) = reply {
                    let _ = d2.send_raw(&r);
                } else if m.expects_reply {
                    let _ = d2.send_raw(&ack(&m));
                }
            }
        });
        Ok(d)
    }

    pub fn set_handler(&self, h: Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }

    pub fn send_raw(&self, b: &[u8]) -> Result<()> {
        let mut w = self.w.lock().unwrap();
        w.write_all(b)?;
        Ok(())
    }

    /// Sends a method invocation; with `wait`, blocks for the reply.
    pub fn invoke(
        &self,
        channel: i32,
        selector: &str,
        args: Vec<Aux>,
        wait: bool,
    ) -> Result<Option<Msg>> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let m = Msg {
            identifier: id,
            channel,
            expects_reply: wait,
            msg_type: METHOD_INVOCATION,
            aux: args,
            payload: nskeyed::archive_bin(&NS::str(selector)),
            ..Default::default()
        };
        let rx = if wait {
            let (tx, rx) = std::sync::mpsc::channel();
            self.waiters.lock().unwrap().insert(id, tx);
            Some(rx)
        } else {
            None
        };
        self.send_raw(&encode(&m))?;
        let Some(rx) = rx else { return Ok(None) };
        let reply = rx.recv_timeout(TIMEOUT).map_err(|_| {
            if self.closed.load(Ordering::SeqCst) {
                Error::msg(format!("connection closed while waiting for {selector}"))
            } else {
                Error::msg(format!("timed out waiting for {selector}"))
            }
        })?;
        if reply.msg_type == ERROR {
            let e = reply
                .payload_object()
                .map(|p| p.to_json().to_string())
                .unwrap_or_default();
            return bail(format!(
                "failed invoking method '{selector}' with error: {e}"
            ));
        }
        Ok(Some(reply))
    }

    pub fn call(&self, channel: i32, selector: &str, args: Vec<Aux>) -> Result<Msg> {
        Ok(self.invoke(channel, selector, args, true)?.unwrap())
    }

    /// Opens a channel without waiting for the device to confirm it; calls on it queue behind the request.
    pub fn request_channel(&self, identifier: &str, wait: bool) -> Result<i32> {
        let code = self.next_channel.fetch_add(1, Ordering::SeqCst);
        self.invoke(
            0,
            "_requestChannelWithCode:identifier:",
            vec![Aux::U32(code as u32), Aux::archived(&NS::str(identifier))],
            wait,
        )?;
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message laid out field by field: the 32-byte message header, the 16-byte payload header,
    /// the auxiliary primitive dictionary with null keys, then the archived payload.
    fn wire(
        id: u32,
        channel: u32,
        reply: bool,
        kind: u32,
        aux: &[(u32, &[u8])],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut entries = vec![];
        for (t, v) in aux {
            entries.extend(0x0au32.to_le_bytes());
            entries.extend(t.to_le_bytes());
            entries.extend_from_slice(v);
        }
        let aux_len = if entries.is_empty() {
            0
        } else {
            16 + entries.len()
        };
        let mut out = vec![0x79, 0x5b, 0x3d, 0x1f]; // magic
        out.extend(32u32.to_le_bytes()); // header length
        out.extend(0u16.to_le_bytes()); // fragment index
        out.extend(1u16.to_le_bytes()); // fragment count
        out.extend(((16 + aux_len + payload.len()) as u32).to_le_bytes());
        out.extend(id.to_le_bytes());
        out.extend(0u32.to_le_bytes()); // conversation index
        out.extend(channel.to_le_bytes());
        out.extend((reply as u32).to_le_bytes());
        out.extend(kind.to_le_bytes());
        out.extend((aux_len as u32).to_le_bytes());
        out.extend(((aux_len + payload.len()) as u64).to_le_bytes());
        if !entries.is_empty() {
            out.extend(0x1f0u64.to_le_bytes()); // buffer capacity
            out.extend((entries.len() as u64).to_le_bytes());
            out.extend(entries);
        }
        out.extend_from_slice(payload);
        out
    }

    fn sized(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u32).to_le_bytes()[..], b].concat()
    }

    const DEVICEINFO: &str = "com.apple.instruments.server.services.deviceinfo";

    fn request_channel() -> (Msg, Vec<u8>) {
        let ident = nskeyed::archive_bin(&NS::str(DEVICEINFO));
        let payload = nskeyed::archive_bin(&NS::str("_requestChannelWithCode:identifier:"));
        let dat = wire(
            3,
            0,
            true,
            2,
            &[(3, &1u32.to_le_bytes()), (2, &sized(&ident))],
            &payload,
        );
        let m = Msg {
            identifier: 3,
            expects_reply: true,
            msg_type: 2,
            aux: vec![Aux::U32(1), Aux::Bytes(ident)],
            payload,
            ..Default::default()
        };
        (m, dat)
    }

    #[test]
    fn codec_matches_the_wire_layout() {
        let (m, dat) = request_channel();
        assert_eq!(encode(&m), dat);
        let (d, rest) = decode(&dat).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            (
                d.identifier,
                d.channel,
                d.expects_reply,
                d.msg_type,
                d.fragments
            ),
            (3, 0, true, 2, 1)
        );
        assert_eq!(
            d.selector().as_deref(),
            Some("_requestChannelWithCode:identifier:")
        );
        assert_eq!(d.aux[0], Aux::U32(1));
        assert_eq!(
            d.args()[1].as_ref().and_then(|a| a.as_str()),
            Some(DEVICEINFO)
        );
    }

    #[test]
    fn a_stream_of_messages_decodes() {
        let (_, a) = request_channel();
        let b = wire(3, 0, false, 3, &[], &nskeyed::archive_bin(&NS::Int(42)));
        let c = wire(
            4,
            1,
            false,
            2,
            &[(6, &(-2i64).to_le_bytes()), (1, &sized(b"hi"))],
            &[],
        );
        let stream = [a, b, c].concat();
        let mut r = Reader::new(&stream[..]);
        assert_eq!(r.read().unwrap().identifier, 3);
        let reply = r.read().unwrap();
        assert_eq!(
            (reply.msg_type, reply.payload_object()),
            (3, Some(NS::Int(42)))
        );
        let last = r.read().unwrap();
        assert_eq!((last.channel, last.payload.len()), (1, 0));
        assert_eq!(last.aux, [Aux::I64(-2), Aux::Str("hi".into())]);
        assert!(r.read().is_err());
    }

    // A message split in three: a header-only first fragment carrying the whole length, then the
    // body in two pieces under copies of the header.
    #[test]
    fn fragmented_message() {
        let (_, whole) = request_channel();
        let body = &whole[32..];
        let frag = |index: u16, len: usize, part: &[u8]| {
            let mut h = whole[..32].to_vec();
            h[8..10].copy_from_slice(&index.to_le_bytes());
            h[10..12].copy_from_slice(&3u16.to_le_bytes());
            h[12..16].copy_from_slice(&(len as u32).to_le_bytes());
            [h, part.to_vec()].concat()
        };
        let (p1, p2) = body.split_at(100);
        let dat = [
            frag(0, body.len(), &[]),
            frag(1, p1.len(), p1),
            frag(2, p2.len(), p2),
        ]
        .concat();
        let (m, rest) = decode(&dat).unwrap();
        assert_eq!(
            (m.fragments, m.fragment_index, rest.len()),
            (3, 0, dat.len() - 32)
        );
        let (m, rest) = decode(rest).unwrap();
        assert_eq!(
            (m.fragments, m.fragment_index, rest.len()),
            (3, 1, 32 + p2.len())
        );
        let (m, rest) = decode(rest).unwrap();
        assert_eq!((m.fragments, m.fragment_index, rest.len()), (3, 2, 0));
        let full = Reader::new(&dat[..]).read().unwrap();
        assert_eq!(
            full.selector().as_deref(),
            Some("_requestChannelWithCode:identifier:")
        );
        assert_eq!(
            full.args()[1].as_ref().and_then(|a| a.as_str()),
            Some(DEVICEINFO)
        );
    }

    #[test]
    fn ack_and_encoder() {
        let a = ack(&Msg::default());
        assert_eq!(a.len(), 48);
        let (m, _) = decode(&a).unwrap();
        assert_eq!((m.msg_type, m.conversation_index), (ACK, 1));
        for (aux, reply) in [(vec![], false), (vec![], true), (vec![Aux::U32(5)], false)] {
            let msg = Msg {
                fragment_index: 1,
                conversation_index: 2,
                expects_reply: reply,
                aux,
                payload: nskeyed::archive_bin(&NS::str("test")),
                ..Default::default()
            };
            let (d, _) = decode(&encode(&msg)).unwrap();
            assert_eq!(
                (
                    d.channel,
                    d.identifier,
                    d.conversation_index,
                    d.expects_reply,
                    d.msg_type
                ),
                (msg.channel, msg.identifier, 2, reply, 0)
            );
            assert_eq!(d.aux, msg.aux);
        }
    }

    #[test]
    fn rejects_truncated_and_oversized() {
        let (_, dat) = request_channel();
        assert!(decode(&dat[..dat.len() - 1]).is_err());
        assert!(decode(&dat[..20]).is_err());
        let mut bad = dat.clone();
        bad[0] = 0;
        assert!(decode(&bad).is_err());
        assert!(decode_aux(&[2, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]).is_err());
    }
}
