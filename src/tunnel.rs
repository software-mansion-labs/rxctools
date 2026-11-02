//! iOS 17+ tunnel in user space: CoreDeviceProxy over lockdown, a smoltcp IPv6/TCP stack on top of it,
//! a local TCP proxy into that stack and an HTTP API that tells clients where to find it.

use crate::lockdown::{DevStream, Device};
use crate::util::{Error, Result, bail};
use crate::xpc;
use mio::net::{TcpListener as MioListener, TcpStream as MioTcp};
use mio::{Events, Interest, Poll, Token};
use serde_json::{Value as J, json};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device as PhyDevice, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv6Address};
use std::collections::{BTreeMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv6Addr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const CORE_DEVICE_PROXY: &str = "com.apple.internal.devicecompute.CoreDeviceProxy";
/// Where `manage tunnel` serves its tunnel list, and where other commands look for it.
pub const DEFAULT_API: &str = "127.0.0.1:50550";
const REQUESTED_MTU: u32 = 16000;

pub fn api_addr(arg: Option<&str>) -> &str {
    arg.unwrap_or(DEFAULT_API)
}

#[derive(Debug)]
pub struct TunnelParams {
    pub server_address: Ipv6Addr,
    pub server_rsd_port: u16,
    pub client_address: Ipv6Addr,
    pub prefix_len: u8,
    pub mtu: usize,
}

pub fn cdtunnel_request(mtu: u32) -> Vec<u8> {
    let body = json!({"type": "clientHandshakeRequest", "mtu": mtu}).to_string();
    let mut out = b"CDTunnel".to_vec();
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

pub fn parse_cdtunnel_response(r: &mut impl Read) -> Result<TunnelParams> {
    let mut h = [0u8; 10];
    r.read_exact(&mut h)?;
    if &h[..8] != b"CDTunnel" {
        return bail("CDTunnel: bad magic");
    }
    let mut body = vec![0u8; u16::from_be_bytes([h[8], h[9]]) as usize];
    r.read_exact(&mut body)?;
    let v: J = serde_json::from_slice(&body)?;
    let ip = |s: &J| -> Result<Ipv6Addr> {
        s.as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::msg(format!("CDTunnel: bad address in {v}")))
    };
    let cp = &v["clientParameters"];
    let mask: Ipv6Addr = cp["netmask"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0));
    Ok(TunnelParams {
        server_address: ip(&v["serverAddress"])?,
        server_rsd_port: v["serverRSDPort"].as_u64().unwrap_or(58783) as u16,
        client_address: ip(&cp["address"])?,
        prefix_len: u128::from(mask).count_ones() as u8,
        mtu: cp["mtu"].as_u64().unwrap_or(1280) as usize,
    })
}

// --- smoltcp device backed by packet queues ---

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl PhyDevice for QueueDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: SInstant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }
    fn transmit(&mut self, _: SInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

// --- the device link: TLS over a non-blocking socket ---

enum MioSock {
    Tcp(MioTcp),
    Unix(mio::net::UnixStream),
}

impl Read for MioSock {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            MioSock::Tcp(s) => s.read(b),
            MioSock::Unix(s) => s.read(b),
        }
    }
}
impl Write for MioSock {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            MioSock::Tcp(s) => s.write(b),
            MioSock::Unix(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Link {
    tls: rustls::ClientConnection,
    sock: MioSock,
    inbuf: Vec<u8>,
}

impl Link {
    /// Reads whatever the device sent; returns false on EOF.
    fn read(&mut self, rx: &mut VecDeque<Vec<u8>>) -> Result<bool> {
        let mut alive = true;
        loop {
            match self.tls.read_tls(&mut self.sock) {
                Ok(0) => {
                    alive = false;
                    break;
                }
                Ok(_) => {
                    self.tls.process_new_packets()?;
                    self.drain_plaintext();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        self.drain_plaintext();
        while self.inbuf.len() >= 40 {
            if self.inbuf[0] >> 4 != 6 {
                return bail(format!(
                    "not an IPv6 packet: version {}",
                    self.inbuf[0] >> 4
                ));
            }
            let total = 40 + u16::from_be_bytes([self.inbuf[4], self.inbuf[5]]) as usize;
            if self.inbuf.len() < total {
                break;
            }
            rx.push_back(self.inbuf.drain(..total).collect());
        }
        Ok(alive)
    }

    fn drain_plaintext(&mut self) {
        let mut buf = [0u8; 65536];
        loop {
            match self.tls.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => self.inbuf.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
    }

    fn write(&mut self, tx: &mut VecDeque<Vec<u8>>) -> Result<()> {
        while let Some(p) = tx.pop_front() {
            self.tls.writer().write_all(&p)?;
        }
        while self.tls.wants_write() {
            match self.tls.write_tls(&mut self.sock) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

// --- local proxy clients ---

const CLIENT_BUF: usize = 1 << 20;

struct Client {
    sock: MioTcp,
    handle: Option<SocketHandle>,
    to_dev: Vec<u8>,
    to_client: Vec<u8>,
    eof: bool,
    fin_sent: bool,
    was_connected: bool,
    dead: bool,
}

pub struct Shared {
    pub info: Mutex<Option<J>>,
}

/// Runs until the device goes away. Logs "tunnel ready" once services are reachable.
pub fn run_daemon(udid: Option<&str>, api: &str, proxy_port: u16) -> Result<()> {
    let shared = Arc::new(Shared {
        info: Mutex::new(None),
    });
    let info_listener = std::net::TcpListener::bind(api)
        .map_err(|e| Error::msg(format!("tunnel API on {api}: {e}")))?;
    {
        let shared = shared.clone();
        std::thread::spawn(move || serve_info(info_listener, shared));
    }
    crate::debug!("tunnel API listening", "address" => api);

    let mut dev = Device::open(udid, true, 1)?;
    let udid = dev.udid().to_string();
    crate::info!("connecting tunnel", "device" => udid);
    let mut stream = dev.connect_service(CORE_DEVICE_PROXY)?;
    stream.write_all(&cdtunnel_request(REQUESTED_MTU))?;
    stream.flush()?;
    let params = parse_cdtunnel_response(&mut stream)?;
    crate::debug!("tunnel parameters", "params" => format!("{params:?}"));
    let DevStream::Tls(tls) = stream else {
        return bail("CoreDeviceProxy connection is not encrypted");
    };
    let rustls::StreamOwned { conn, sock } = *tls;
    let sock = match sock {
        crate::usbmux::Stream::Tcp(s) => {
            s.set_nonblocking(true)?;
            MioSock::Tcp(MioTcp::from_std(s))
        }
        crate::usbmux::Stream::Unix(s) => {
            s.set_nonblocking(true)?;
            MioSock::Unix(mio::net::UnixStream::from_std(s))
        }
    };
    let mut link = Link {
        tls: conn,
        sock,
        inbuf: vec![],
    };
    link.tls.set_buffer_limit(None);

    let listener_std = std::net::TcpListener::bind(("127.0.0.1", proxy_port))?;
    let proxy_port = listener_std.local_addr()?.port();
    listener_std.set_nonblocking(true)?;
    let mut listener = MioListener::from_std(listener_std);

    // Cache the RSD service list in the background, through our own proxy, then announce.
    {
        let shared = shared.clone();
        let (addr, rsd_port, udid) = (params.server_address, params.server_rsd_port, udid.clone());
        std::thread::spawn(move || {
            let services = (|| -> Result<BTreeMap<String, u16>> {
                let s = proxy_connect(proxy_port, addr, rsd_port)?;
                Ok(xpc::rsd_handshake(s)?.1)
            })();
            let services = match services {
                Ok(s) => s,
                Err(e) => {
                    crate::util::log(
                        "ERROR",
                        "RSD handshake through the tunnel failed",
                        &[("err", json!(e.0))],
                    );
                    std::process::exit(1);
                }
            };
            *shared.info.lock().unwrap() = Some(json!({
                "identifier": udid, "address": addr.to_string(), "rsdPort": rsd_port,
                "proxyPort": proxy_port, "services": services,
            }));
            crate::info!("tunnel ready", "device" => udid, "proxyPort" => proxy_port);
        });
    }

    event_loop(&mut link, &mut listener, &params)
}

fn event_loop(link: &mut Link, listener: &mut MioListener, params: &TunnelParams) -> Result<()> {
    const DEV: Token = Token(0);
    const LISTENER: Token = Token(1);
    let mut poll = Poll::new()?;
    match &mut link.sock {
        MioSock::Tcp(s) => {
            poll.registry()
                .register(s, DEV, Interest::READABLE | Interest::WRITABLE)?
        }
        MioSock::Unix(s) => {
            poll.registry()
                .register(s, DEV, Interest::READABLE | Interest::WRITABLE)?
        }
    }
    poll.registry()
        .register(listener, LISTENER, Interest::READABLE)?;

    let mut device = QueueDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
        mtu: params.mtu,
    };
    let mut cfg = Config::new(HardwareAddress::Ip);
    cfg.random_seed = std::process::id() as u64
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
    let start = std::time::Instant::now();
    let now = || SInstant::from_micros(start.elapsed().as_micros() as i64);
    let mut iface = Interface::new(cfg, &mut device, now());
    let client_addr = Ipv6Address::from(params.client_address.octets());
    iface.update_ip_addrs(|a| {
        a.push(IpCidr::new(IpAddress::Ipv6(client_addr), params.prefix_len))
            .unwrap();
    });
    let mut sockets = SocketSet::new(vec![]);
    let mut clients: BTreeMap<usize, Client> = BTreeMap::new();
    let mut next_token = 2usize;
    let mut next_port: u16 = 49152;
    let mut events = Events::with_capacity(256);
    let mut buf = vec![0u8; 256 * 1024];

    loop {
        let timeout = iface
            .poll_delay(now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()));
        if let Err(e) = poll.poll(
            &mut events,
            timeout
                .map(|t| t.min(Duration::from_millis(500)))
                .or(Some(Duration::from_millis(500))),
        ) && e.kind() != ErrorKind::Interrupted
        {
            return Err(e.into());
        }
        for ev in events.iter() {
            if ev.token() == LISTENER {
                loop {
                    match listener.accept() {
                        Ok((mut s, _)) => {
                            s.set_nodelay(true).ok();
                            let t = next_token;
                            next_token += 1;
                            poll.registry().register(
                                &mut s,
                                Token(t),
                                Interest::READABLE | Interest::WRITABLE,
                            )?;
                            clients.insert(
                                t,
                                Client {
                                    sock: s,
                                    handle: None,
                                    to_dev: vec![],
                                    to_client: vec![],
                                    eof: false,
                                    fin_sent: false,
                                    was_connected: false,
                                    dead: false,
                                },
                            );
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        if !link.read(&mut device.rx)? {
            return bail("the device closed the tunnel");
        }

        // client -> buffers, and open stack sockets for new clients
        for c in clients.values_mut() {
            while !c.eof && c.to_dev.len() < CLIENT_BUF {
                match c.sock.read(&mut buf) {
                    Ok(0) => c.eof = true,
                    Ok(n) => c.to_dev.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => {
                        c.eof = true;
                        c.dead = true;
                    }
                }
            }
            if c.handle.is_none() && c.to_dev.len() >= 20 {
                let ip: [u8; 16] = c.to_dev[..16].try_into().unwrap();
                let port = u32::from_le_bytes(c.to_dev[16..20].try_into().unwrap()) as u16;
                c.to_dev.drain(..20);
                let mut s = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; 1 << 20]),
                    tcp::SocketBuffer::new(vec![0; 1 << 20]),
                );
                s.set_nagle_enabled(false);
                s.set_ack_delay(None);
                next_port = if next_port >= 65000 {
                    49152
                } else {
                    next_port + 1
                };
                let remote = IpEndpoint::new(IpAddress::Ipv6(Ipv6Address::from(ip)), port);
                if s.connect(iface.context(), remote, next_port).is_err() {
                    c.dead = true;
                    continue;
                }
                crate::debug!("Received connection request to device", "port" => port);
                c.handle = Some(sockets.add(s));
            } else if c.handle.is_none() && c.eof {
                c.dead = true;
            }
        }

        // Pump until the stack has nothing more to say this round.
        for _ in 0..4 {
            iface.poll(now(), &mut device, &mut sockets);
            let mut progress = false;
            for c in clients.values_mut() {
                let Some(h) = c.handle else { continue };
                let s = sockets.get_mut::<tcp::Socket>(h);
                if s.may_send() {
                    c.was_connected = true;
                }
                if !c.to_dev.is_empty()
                    && s.can_send()
                    && let Ok(n) = s.send_slice(&c.to_dev)
                    && n > 0
                {
                    c.to_dev.drain(..n);
                    progress = true;
                }
                if c.eof && c.to_dev.is_empty() && !c.fin_sent && c.was_connected {
                    s.close();
                    c.fin_sent = true;
                    progress = true;
                }
                while s.can_recv() && c.to_client.len() < CLIENT_BUF {
                    match s.recv_slice(&mut buf) {
                        Ok(n) if n > 0 => {
                            c.to_client.extend_from_slice(&buf[..n]);
                            progress = true;
                        }
                        _ => break,
                    }
                }
                while !c.to_client.is_empty() {
                    match c.sock.write(&c.to_client) {
                        Ok(n) => {
                            c.to_client.drain(..n);
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                        Err(_) => {
                            c.dead = true;
                            break;
                        }
                    }
                }
                let st = s.state();
                let remote_done =
                    (c.was_connected && !s.may_recv() && !s.can_recv()) || st == tcp::State::Closed;
                if remote_done
                    && c.to_client.is_empty()
                    && (st == tcp::State::Closed || st == tcp::State::TimeWait || !s.may_recv())
                {
                    c.dead = true;
                }
            }
            if !progress {
                break;
            }
        }
        iface.poll(now(), &mut device, &mut sockets);

        let dead: Vec<usize> = clients
            .iter()
            .filter(|(_, c)| c.dead)
            .map(|(t, _)| *t)
            .collect();
        for t in dead {
            let mut c = clients.remove(&t).unwrap();
            let _ = poll.registry().deregister(&mut c.sock);
            if let Some(h) = c.handle {
                let s = sockets.get_mut::<tcp::Socket>(h);
                if s.state() != tcp::State::Closed && s.state() != tcp::State::TimeWait {
                    s.abort();
                }
                iface.poll(now(), &mut device, &mut sockets);
                sockets.remove(h);
            }
        }
        link.write(&mut device.tx)?;
    }
}

/// Opens a TCP connection to `addr:port` on the device through the daemon's userspace proxy.
pub fn proxy_connect(proxy_port: u16, addr: Ipv6Addr, port: u16) -> Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port))?;
    s.set_nodelay(true)?;
    let mut hdr = addr.octets().to_vec();
    hdr.extend_from_slice(&(port as u32).to_le_bytes());
    s.write_all(&hdr)?;
    Ok(s)
}

fn serve_info(l: std::net::TcpListener, shared: Arc<Shared>) {
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        let shared = shared.clone();
        std::thread::spawn(move || {
            let mut req = vec![];
            let mut b = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut b) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => req.extend_from_slice(&b[..n]),
                }
                if req.len() > 65536 {
                    return;
                }
            }
            let line = String::from_utf8_lossy(&req)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            let mut parts = line.split_whitespace();
            let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let info = shared.info.lock().unwrap().clone();
            let (code, body) = match (method, path) {
                // still starting: `Tunnel::find` waits for it
                ("GET", _) if info.is_none() => (503, "[]".into()),
                ("GET", "/tunnels") => (200, J::Array(info.into_iter().collect()).to_string()),
                ("GET", p) if p.starts_with("/tunnels/") => match info {
                    Some(i) if i["identifier"] == p["/tunnels/".len()..] => (200, i.to_string()),
                    _ => (404, "tunnel not found".into()),
                },
                _ => (404, String::new()),
            };
            let reason = if code == 200 { "OK" } else { "Error" };
            let _ = s.write_all(
                format!("HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes(),
            );
        });
    }
}

pub fn http_get(api: &str, path: &str) -> Result<(u16, String)> {
    let mut s = TcpStream::connect(api).map_err(|e| {
        Error::msg(format!(
            "no tunnel API on {api} ({e}): run `rxc tunnel run`"
        ))
    })?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {api}\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    let code = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = out
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((code, body))
}

/// A running tunnel as the tunnel API describes it, plus the RSD services.
#[derive(Clone)]
pub struct Tunnel {
    pub address: Ipv6Addr,
    pub rsd_port: u16,
    pub udid: String,
    pub proxy_port: u16,
    pub services: BTreeMap<String, u16>,
}

impl Tunnel {
    pub fn find(udid: Option<&str>, api: &str) -> Result<Tunnel> {
        // a tunnel that is still starting answers 503, so `rxc tunnel run &` can go right before
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let get = |path: &str| -> Result<(u16, String)> {
            loop {
                let r = http_get(api, path)?;
                if r.0 != 503 || std::time::Instant::now() > deadline {
                    return Ok(r);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        let udid = match crate::lockdown::requested_udid(udid) {
            Some(u) => u,
            None => {
                let (_, body) = get("/tunnels")?;
                let v: J = serde_json::from_str(&body)?;
                v.get(0)
                    .and_then(|t| t["identifier"].as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| Error::msg("no tunnel running: run `rxc tunnel run`"))?
            }
        };
        let (code, body) = get(&format!("/tunnels/{udid}"))?;
        if code != 200 {
            return bail(format!(
                "no tunnel to {udid} on {api}: run `rxc tunnel run --device {udid}`"
            ));
        }
        let v: J = serde_json::from_str(&body)?;
        let address: Ipv6Addr = v["address"]
            .as_str()
            .and_then(|a| a.parse().ok())
            .ok_or_else(|| Error::msg("tunnel without address"))?;
        let rsd_port = v["rsdPort"].as_u64().unwrap_or(0) as u16;
        let proxy_port = v["proxyPort"].as_u64().unwrap_or(0) as u16;
        let mut t = Tunnel {
            address,
            rsd_port,
            udid,
            proxy_port,
            services: BTreeMap::new(),
        };
        match v.get("services").and_then(|s| s.as_object()) {
            Some(s) => {
                t.services = s
                    .iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_u64()? as u16)))
                    .collect()
            }
            None => t.services = xpc::rsd_handshake(t.connect(rsd_port)?)?.1,
        }
        Ok(t)
    }

    pub fn connect(&self, port: u16) -> Result<TcpStream> {
        proxy_connect(self.proxy_port, self.address, port)
    }

    pub fn port(&self, service: &str) -> Result<u16> {
        xpc::service_port(&self.services, service).ok_or_else(|| {
            Error::msg(format!(
                "service {service} is not available in RSD (is the developer disk image mounted?)"
            ))
        })
    }

    pub fn connect_service(&self, service: &str) -> Result<TcpStream> {
        self.connect(self.port(service)?)
    }

    /// Shim services speak the lockdown plist protocol after an RSDCheckin.
    pub fn connect_shim(&self, service: &str) -> Result<TcpStream> {
        let mut s = self.connect_service(service)?;
        crate::lockdown::write_plist(
            &mut s,
            &crate::lockdown::dict(&[
                ("Label", "rxc".into()),
                ("ProtocolVersion", "2".into()),
                ("Request", "RSDCheckin".into()),
            ]),
        )?;
        crate::lockdown::read_plist(&mut s)?;
        crate::lockdown::read_plist(&mut s)?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdtunnel_framing() {
        let req = cdtunnel_request(16000);
        assert_eq!(&req[..8], b"CDTunnel");
        let n = u16::from_be_bytes([req[8], req[9]]) as usize;
        let v: J = serde_json::from_slice(&req[10..10 + n]).unwrap();
        assert_eq!(v["type"], "clientHandshakeRequest");

        let body = br#"{"clientParameters":{"address":"fd87:293:3265::2","mtu":16000,"netmask":"ffff:ffff:ffff:ffff::"},"serverAddress":"fd87:293:3265::1","type":"serverHandshakeResponse","serverRSDPort":58783}"#;
        let mut resp = b"CDTunnel".to_vec();
        resp.extend_from_slice(&(body.len() as u16).to_be_bytes());
        resp.extend_from_slice(body);
        let p = parse_cdtunnel_response(&mut &resp[..]).unwrap();
        assert_eq!(
            p.server_address,
            "fd87:293:3265::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            p.client_address,
            "fd87:293:3265::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!((p.prefix_len, p.mtu, p.server_rsd_port), (64, 16000, 58783));
    }

    #[test]
    fn tunnel_api() {
        let shared = Arc::new(Shared {
            info: Mutex::new(None),
        });
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let api = l.local_addr().unwrap().to_string();
        let s2 = shared.clone();
        std::thread::spawn(move || serve_info(l, s2));
        assert_eq!(http_get(&api, "/tunnels").unwrap(), (503, "[]".into()));
        assert_eq!(http_get(&api, "/tunnels/abc").unwrap().0, 503);
        // find waits for a tunnel that is still starting
        let s3 = shared.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            *s3.info.lock().unwrap() = Some(json!({"identifier": "abc", "address": "fd00::1",
                "rsdPort": 1, "proxyPort": 9, "services": {"com.apple.x": 5}}));
        });
        let t = Tunnel::find(None, &api).unwrap();
        assert_eq!((t.udid.as_str(), t.rsd_port, t.proxy_port), ("abc", 1, 9));
        assert_eq!(t.port("com.apple.x").unwrap(), 5);
        assert!(Tunnel::find(Some("other"), &api).is_err());
    }
}
