//! The device's screen and touches the way Xcode's Device Hub gets them: displayservice streams HEVC
//! over RTP to a UDP port on the tunnel, and universalhidservice takes touchscreen reports. Needs the
//! developer disk image mounted.

use crate::lockdown::Device;
use crate::tunnel::{self, OwnTunnel, Udp};
use crate::util::{Error, Result, bail};
use crate::xctest::coredevice_call;
use crate::xpc::{X, XpcConn, xdict};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DISPLAY_SERVICE: &str = "com.apple.coredevice.displayservice";
pub const HID_SERVICE: &str = "com.apple.coredevice.hid.universalhidservice";
/// Touch states for [`Touch::send`]: a finger on the screen, and its lift.
pub const TOUCH_CONTACT: u8 = 0xC2;
pub const TOUCH_RELEASE: u8 = 0x02;

/// The feature set and endpoint Device Hub offers: a Mac sharing the phone's screen.
const FEATURES: u64 = 140;
const CALL_INFO: (&str, &str, &str) = ("Mac17,7", "2205.3.1", "25F71");
const PHONE_AUDIO_PORT: u64 = 50000;
const PHONE_VIDEO_PORT: u64 = 50001;
/// The RTP payload type the offer gives HEVC.
const HEVC_PAYLOAD: u8 = 100;
const HEVC_FLS: &str = "FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;";
/// The phone takes touches only once it has noticed the stream.
const TOUCH_DELAY: Duration = Duration::from_millis(300);

/// One HEVC access unit, in Annex B form.
#[derive(Debug, PartialEq)]
pub struct Frame {
    pub data: Vec<u8>,
    /// RTP's 90 kHz clock.
    pub timestamp: u32,
    /// An IRAP picture (NAL types 16 to 23); its VPS, SPS and PPS come first.
    pub irap: bool,
}

/// The screen's frames, until dropped; the stream stops then.
pub struct Stream {
    video: Udp,
    depacketizer: Depacketizer,
    buf: Vec<u8>,
    display: XpcConn<TcpStream>,
    // the session needs the audio stream; what nobody reads of it stays bounded in the tunnel
    _audio: Udp,
    _tunnel: Arc<OwnTunnel>,
    udid: String,
    session: uuid::Uuid,
}

/// Each device's newest stream in this process. A phone streams to one session at a time and stops
/// all of them on any stop, so only the newest one may stop.
// shortcut: a stream another process starts is not seen here, and an older stream's stop ends it
static NEWEST: Mutex<BTreeMap<String, uuid::Uuid>> = Mutex::new(BTreeMap::new());

/// Touches on the screen, while the [`Stream`] runs.
pub struct Touch {
    hid: XpcConn<TcpStream>,
    ready: Instant,
    _tunnel: Arc<OwnTunnel>,
}

/// Starts the screen stream through a tunnel of its own, which closes when both handles are gone.
/// A device streams to one [`Stream`] at a time: a newer one takes the screen, and the older one's
/// [`Stream::next_frame`] then fails.
pub fn start(dev: &mut Device) -> Result<(Stream, Touch)> {
    let t = Arc::new(tunnel::open(dev)?);
    let connect = |service| -> Result<XpcConn<TcpStream>> {
        let s = t.tunnel.connect_service(service)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        XpcConn::connect(s)
    };
    let display = connect(DISPLAY_SERVICE)?;
    let (audio, video) = (t.tunnel.bind_udp()?, t.tunnel.bind_udp()?);
    video.set_read_timeout(Some(Duration::from_secs(10)))?;
    let session = uuid::Uuid::new_v4();
    let o = offer(6, &audio_blob(rand_u32(), ntp_now()))?;
    let audio_start = start_parameters("audio", &audio, &t, PHONE_AUDIO_PORT, o, session);
    let o = offer(5, &screen_blob(session.as_u128() as u32, ntp_now()))?;
    let video_start = start_parameters("video", &video, &t, PHONE_VIDEO_PORT, o, session);
    // made first so that its Drop stops the session when a later step fails
    let mut stream = Stream {
        video,
        depacketizer: Depacketizer::default(),
        buf: vec![],
        display,
        _audio: audio,
        _tunnel: t.clone(),
        udid: dev.udid().to_string(),
        session,
    };
    newest().insert(stream.udid.clone(), session);
    // the audio stream opens the screen-sharing session that the video stream joins
    coredevice_call(&mut stream.display, START, None, audio_start)?;
    coredevice_call(&mut stream.display, START, None, video_start)?;
    let ready = Instant::now() + TOUCH_DELAY;
    let hid = connect(HID_SERVICE)?;
    Ok((
        stream,
        Touch {
            hid,
            ready,
            _tunnel: t,
        },
    ))
}

const START: &str = "com.apple.coredevice.feature.startmediastream";

impl Stream {
    /// The next frame. Blocks while the screen does not change. Fails once a frame is lost, which
    /// happens when frames are not read as fast as they come: the frames after it cannot be
    /// decoded, so start the stream again.
    pub fn next_frame(&mut self) -> Result<Frame> {
        loop {
            // the phone sends RTCP every second even when the screen does not change
            self.video.recv(&mut self.buf).map_err(|e| {
                Error::msg(format!(
                    "screen stream: nothing from the device ({e}); it went away, or a newer stream took its screen"
                ))
            })?;
            if let Some(f) = self.depacketizer.push(&self.buf) {
                return Ok(f);
            }
            if self.depacketizer.lost {
                return bail("screen stream: frames lost, the stream was read too slowly");
            }
        }
    }
}

fn newest() -> MutexGuard<'static, BTreeMap<String, uuid::Uuid>> {
    NEWEST.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Drop for Stream {
    fn drop(&mut self) {
        // held through the stop, so that no newer stream starts in between
        let mut newest = newest();
        if newest.get(&self.udid) != Some(&self.session) {
            return;
        }
        newest.remove(&self.udid);
        let _ = coredevice_call(
            &mut self.display,
            "com.apple.coredevice.feature.stopmediastream",
            Some("com.apple.coredevice.action.mediastreamstop"),
            xdict(vec![("stopAll", X::Bool(true))]),
        );
    }
}

impl Touch {
    /// One touch sample: `state` is [`TOUCH_CONTACT`] or [`TOUCH_RELEASE`], and `x`, `y` run from 0
    /// to 65535 across the screen. iOS drops a touch lifted at once, so hold one for 50 ms or more.
    pub fn send(&mut self, state: u8, x: u16, y: u16) -> Result<()> {
        std::thread::sleep(self.ready.saturating_duration_since(Instant::now()));
        let report = touch_report(state, x, y, now_nanos());
        let send = xdict(vec![("_0", X::Data(report)), ("_1", X::U64(257))]);
        self.hid.send(
            xdict(vec![
                (
                    "featureIdentifier",
                    "com.apple.coredevice.feature.remote.universalhidservice".into(),
                ),
                ("messageType", "Request".into()),
                ("payload", xdict(vec![("send", send)])),
            ]),
            0,
        )
    }
}

/// A 58-byte main-touchscreen HID report with one contact.
fn touch_report(state: u8, x: u16, y: u16, timestamp: u64) -> Vec<u8> {
    let mut r = vec![0u8; 58];
    r[..4].copy_from_slice(&[0x09, 1, 5, state]);
    r[4..6].copy_from_slice(&x.to_le_bytes());
    r[6..8].copy_from_slice(&y.to_le_bytes());
    r[40] = 2;
    r[44..50].copy_from_slice(&timestamp.to_le_bytes()[..6]);
    r
}

/// `MediaStreamStartParameters`: the phone sends from `phone_port` to `to`.
fn start_parameters(
    kind: &str,
    to: &Udp,
    t: &OwnTunnel,
    phone_port: u64,
    offer: Vec<u8>,
    session: uuid::Uuid,
) -> X {
    let int = |v| xdict(vec![("int", X::I64(v))]);
    let mut options = vec![
        ("AVCMediaStreamNegotiatorTransportProtocolType", int(2)),
        ("AVCMediaStreamNegotiatorAccessNetworkType", int(1)),
        (
            "avcMediaStreamOptionClientSessionID",
            xdict(vec![("uuid", X::Uuid(*session.as_bytes()))]),
        ),
    ];
    if kind == "video" {
        options.push((
            "CoreDeviceVideoDisplayMode",
            xdict(vec![("string", "DisplayByID".into())]),
        ));
        options.push(("VideoStreamForDisplayID", int(1)));
    }
    xdict(vec![
        ("receiverIP", to.address.ip().to_string().as_str().into()),
        ("receiverPort", X::U64(to.address.port().into())),
        ("senderIP", t.tunnel.address.to_string().as_str().into()),
        ("senderPort", X::U64(phone_port)),
        // shortcut: the phone ends the stream this many seconds after the last RTCP from us, and we
        // send none, so streams last a day at most; receiver reports would make it a liveness check
        ("timeout", X::U64(86400)),
        ("type", kind.into()),
        ("direction", "output".into()),
        ("negotiatorOffer", X::Data(offer)),
        ("clientSupportedFeatures", X::U64(FEATURES)),
        ("options", xdict(options)),
    ])
}

/// The `negotiatorOffer` plist: mode 5 for the screen, 6 for its audio.
fn offer(mode: i64, blob: &[u8]) -> Result<Vec<u8>> {
    let mut z = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
    z.write_all(blob)?;
    let mut info = vec![];
    pb_uint(&mut info, 1, 0);
    pb_uint(&mut info, 2, 1);
    for (field, s) in [(3, CALL_INFO.0), (4, CALL_INFO.1), (5, CALL_INFO.2)] {
        pb_bytes(&mut info, field, s.as_bytes());
    }
    let call_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let d = crate::lockdown::dict(&[
        ("avcMediaStreamOptionCallID", call_id.into()),
        (
            "avcMediaStreamNegotiatorMediaBlob",
            plist::Value::Data(z.finish()?),
        ),
        ("avcMediaStreamNegotiatorMode", mode.into()),
        (
            "avcMediaStreamOptionRemoteEndpointInfo",
            plist::Value::Data(info),
        ),
    ]);
    let mut out = vec![];
    plist::to_writer_binary(&mut out, &d).map_err(|e| crate::util::Error::msg(e.to_string()))?;
    Ok(out)
}

/// AVConference's media blob for the screen: H.264 and HEVC payloads, HEVC preferred.
fn screen_blob(session: u32, ntp: u64) -> Vec<u8> {
    let format = |variant| {
        let mut m = vec![];
        for (f, v) in [(1, 1), (2, variant), (3, 0xc3c3), (4, 0)] {
            pb_uint(&mut m, f, v);
        }
        m
    };
    let codec = |payload, formats: &[u64], fls: &str, last| {
        let mut c = vec![];
        pb_uint(&mut c, 1, payload);
        for &v in formats {
            pb_bytes(&mut c, 2, &format(v));
        }
        pb_bytes(&mut c, 3, fls.as_bytes());
        pb_uint(&mut c, 4, last);
        c
    };
    let mut video = vec![];
    pb_uint(&mut video, 1, session.into());
    pb_uint(&mut video, 2, 0);
    pb_bytes(&mut video, 3, &codec(123, &[1, 2, 1, 2], "FLS;SW:1;", 1));
    pb_bytes(&mut video, 3, &codec(100, &[1, 2], HEVC_FLS, 14));
    for (f, v) in [(7, 1), (8, 63), (12, 1)] {
        pb_uint(&mut video, f, v);
    }
    blob(5, &video, ntp)
}

fn audio_blob(session: u32, ntp: u64) -> Vec<u8> {
    let mut audio = vec![];
    for (f, v) in [
        (1, session.into()),
        (2, 0),
        (3, 0),
        (4, 24_191),
        (5, 0),
        (6, 0),
    ] {
        pb_uint(&mut audio, f, v);
    }
    blob(3, &audio, ntp)
}

/// The fields around the stream's own: version, user agent, bandwidth ladder, NTP time.
fn blob(field: u64, stream: &[u8], ntp: u64) -> Vec<u8> {
    let mut e = vec![];
    pb_uint(&mut e, 1, 1);
    pb_uint(&mut e, 2, 1);
    pb_bytes(&mut e, field, stream);
    pb_bytes(&mut e, 6, b"Viceroy 1.7.0");
    pb_uint(&mut e, 8, 0);
    for (id, value, flags) in [
        (0, 20_000_000, Some(0x18000)),
        (4074, 0, Some(0x4000)),
        (0, 60_000_000, Some(0x40000)),
        (0, 40_000_000, Some(0x3000)),
        (16, 4100, None),
        (0, 6_000_000, Some(0x20000)),
        (4, 6500, None),
        (0, 100_000_000, Some(0x100000)),
        (1, 299, None),
        (0, 75_000_000, Some(0x80000)),
    ] {
        let mut m = vec![];
        pb_uint(&mut m, 1, id);
        pb_uint(&mut m, 2, value);
        if let Some(f) = flags {
            pb_uint(&mut m, 3, f);
        }
        pb_bytes(&mut e, 9, &m);
    }
    for (f, v) in [(13, ntp), (14, 2), (16, 0), (18, 1)] {
        pb_uint(&mut e, f, v);
    }
    e
}

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn pb_uint(out: &mut Vec<u8>, field: u64, v: u64) {
    varint(out, field << 3);
    varint(out, v);
}

fn pb_bytes(out: &mut Vec<u8>, field: u64, b: &[u8]) {
    varint(out, field << 3 | 2);
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn ntp_now() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    ((now.as_secs() + 2_208_988_800) << 32)
        | ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000)
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn rand_u32() -> u32 {
    uuid::Uuid::new_v4().as_u128() as u32
}

/// RTP packets with HEVC payloads (RFC 7798: single NAL units, aggregation and fragmentation
/// units) into access units, one per RTP marker bit.
#[derive(Default)]
struct Depacketizer {
    au: Vec<u8>,
    fu: Option<Vec<u8>>,
    next_seq: Option<u16>,
    broken: bool,
    /// A frame was dropped; the frames after it reference it.
    lost: bool,
    vcl: bool,
    irap: bool,
    params_in_au: bool,
    vps: Vec<u8>,
    sps: Vec<u8>,
    pps: Vec<u8>,
}

impl Depacketizer {
    /// Takes one RTP packet; the access unit it completes, if any.
    // shortcut: a lost or reordered packet drops its frame, fine for the USB tunnel's in-order delivery
    fn push(&mut self, packet: &[u8]) -> Option<Frame> {
        let (seq, timestamp, marker, payload) = rtp(packet)?;
        if self.next_seq.is_some_and(|n| n != seq) {
            self.broken = true;
            self.fu = None;
        }
        self.next_seq = Some(seq.wrapping_add(1));
        self.payload(payload);
        if !marker {
            return None;
        }
        let frame = Frame {
            data: std::mem::take(&mut self.au),
            timestamp,
            irap: self.irap,
        };
        let whole = !self.broken && !frame.data.is_empty();
        self.lost |= self.broken;
        (self.fu, self.broken, self.vcl, self.irap, self.params_in_au) =
            (None, false, false, false, false);
        whole.then_some(frame)
    }

    fn payload(&mut self, p: &[u8]) {
        if p.len() < 3 {
            return;
        }
        match p[0] >> 1 & 63 {
            48 => {
                let mut rest = &p[2..];
                while rest.len() >= 2 {
                    let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                    let Some(nal) = rest.get(2..2 + n) else {
                        self.broken = true;
                        return;
                    };
                    self.nal(nal);
                    rest = &rest[2 + n..];
                }
            }
            49 => {
                let (start, end, kind) = (p[2] & 0x80 != 0, p[2] & 0x40 != 0, p[2] & 63);
                if start {
                    self.fu = Some(vec![p[0] & 0x81 | kind << 1, p[1]]);
                }
                let Some(fu) = &mut self.fu else {
                    self.broken = true;
                    return;
                };
                fu.extend_from_slice(&p[3..]);
                if end && let Some(nal) = self.fu.take() {
                    self.nal(&nal);
                }
            }
            _ => self.nal(p),
        }
    }

    fn nal(&mut self, nal: &[u8]) {
        if nal.len() < 2 {
            return;
        }
        let kind = nal[0] >> 1 & 63;
        match kind {
            32 => self.vps = nal.to_vec(),
            33 => self.sps = nal.to_vec(),
            34 => self.pps = nal.to_vec(),
            _ => {}
        }
        self.params_in_au |= (32..=34).contains(&kind);
        if kind <= 31 && !self.vcl {
            self.vcl = true;
            self.irap = (16..=23).contains(&kind);
            if self.irap && !self.params_in_au {
                for set in [&self.vps, &self.sps, &self.pps] {
                    if !set.is_empty() {
                        self.au.extend_from_slice(&[0, 0, 0, 1]);
                        self.au.extend_from_slice(set);
                    }
                }
            }
        }
        self.au.extend_from_slice(&[0, 0, 0, 1]);
        self.au.extend_from_slice(nal);
    }
}

/// An HEVC RTP packet's sequence number, timestamp, marker bit and payload; other packets, RTCP
/// among them, are left out.
fn rtp(p: &[u8]) -> Option<(u16, u32, bool, &[u8])> {
    if p.len() < 12 || p[0] >> 6 != 2 || p[1] & 0x7f != HEVC_PAYLOAD {
        return None;
    }
    let mut start = 12 + 4 * (p[0] & 15) as usize;
    if p[0] & 0x10 != 0 {
        let words = u16::from_be_bytes([*p.get(start + 2)?, *p.get(start + 3)?]) as usize;
        start += 4 + 4 * words;
    }
    let pad = if p[0] & 0x20 != 0 {
        *p.last()? as usize
    } else {
        0
    };
    let payload = p.get(start..p.len().checked_sub(pad)?)?;
    let seq = u16::from_be_bytes([p[2], p[3]]);
    let timestamp = u32::from_be_bytes(p[4..8].try_into().unwrap());
    Some((seq, timestamp, p[1] & 0x80 != 0, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(seq: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, if marker { 0x80 | 100 } else { 100 }];
        p.extend(seq.to_be_bytes());
        p.extend(9000u32.to_be_bytes());
        p.extend([0; 4]);
        p.extend(payload);
        p
    }

    #[test]
    fn rtp_to_access_units() {
        let (vps, sps, pps) = ([32 << 1, 1, 0xaa], [33 << 1, 1, 0xbb], [34 << 1, 1, 0xcc]);
        let idr = [19 << 1, 1, 1, 2, 3, 4];
        let start = [0, 0, 0, 1];
        let mut d = Depacketizer::default();
        // VPS, SPS and PPS aggregated, then an IDR in three fragments
        let mut ap = vec![48 << 1, 1];
        for nal in [&vps[..], &sps, &pps] {
            ap.extend((nal.len() as u16).to_be_bytes());
            ap.extend(nal);
        }
        assert_eq!(d.push(&packet(1, false, &ap)), None);
        let fu = |flags: u8, part: &[u8]| [&[49 << 1, 1, flags | 19][..], part].concat();
        assert_eq!(d.push(&packet(2, false, &fu(0x80, &[1, 2]))), None);
        assert_eq!(d.push(&packet(3, false, &fu(0, &[3]))), None);
        let f = d.push(&packet(4, true, &fu(0x40, &[4]))).unwrap();
        let want: Vec<u8> = [&vps[..], &sps, &pps, &idr]
            .iter()
            .flat_map(|n| [&start[..], n].concat())
            .collect();
        assert_eq!((f.data, f.timestamp, f.irap), (want, 9000, true));

        // a P frame, then a lost packet drops the next frame
        let p = [1 << 1, 1, 7];
        let f = d.push(&packet(5, true, &p)).unwrap();
        assert_eq!((f.data, f.irap), ([&start[..], &p].concat(), false));
        assert!(!d.lost);
        assert_eq!(d.push(&packet(7, true, &p)), None);
        assert!(d.lost);

        // a later IDR on its own gets the parameter sets again
        let f = d.push(&packet(8, true, &idr)).unwrap();
        assert!(f.irap && f.data.starts_with(&[&start[..], &vps].concat()));
        assert!(f.data.ends_with(&[&start[..], &idr].concat()));
    }

    #[test]
    fn touch_report_layout() {
        let r = touch_report(TOUCH_CONTACT, 0x1234, 0xffff, 0xaabb_ccdd_eeff_0011);
        assert_eq!(r.len(), 58);
        assert_eq!(r[..8], [0x09, 1, 5, 0xc2, 0x34, 0x12, 0xff, 0xff]);
        assert_eq!(r[40..50], [2, 0, 0, 0, 0x11, 0, 0xff, 0xee, 0xdd, 0xcc]);
    }
}
