//! lockdownd: plist framing, sessions with the pair record's TLS identity, StartService.

use crate::usbmux::{DeviceEntry, Mux, Stream, WarmMux};
use crate::util::{Error, Result, bail};
use plist::{Dictionary, Value};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use std::io::{Read, Write};
use std::sync::Arc;

pub const LOCKDOWN_PORT: u16 = 62078;

pub enum DevStream {
    Plain(Stream),
    Tls(Box<StreamOwned<ClientConnection, Stream>>),
}

impl Read for DevStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DevStream::Plain(s) => s.read(buf),
            DevStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for DevStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            DevStream::Plain(s) => s.write(buf),
            DevStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            DevStream::Plain(s) => s.flush(),
            DevStream::Tls(s) => s.flush(),
        }
    }
}

#[derive(Clone)]
pub struct PairRecord {
    pub host_id: String,
    pub system_buid: String,
    pub host_cert: Vec<u8>,
    pub host_key: Vec<u8>,
}

impl PairRecord {
    pub fn from_dict(d: &Dictionary) -> Result<PairRecord> {
        let data = |k: &str| d.get(k).and_then(|v| v.as_data()).map(|b| b.to_vec());
        let string = |k: &str| d.get(k).and_then(|v| v.as_string()).map(|s| s.to_string());
        Ok(PairRecord {
            host_id: string("HostID").ok_or_else(|| Error::msg("pair record without HostID"))?,
            system_buid: string("SystemBUID").unwrap_or_default(),
            host_cert: data("HostCertificate")
                .ok_or_else(|| Error::msg("pair record without HostCertificate"))?,
            host_key: data("HostPrivateKey")
                .ok_or_else(|| Error::msg("pair record without HostPrivateKey"))?,
        })
    }

    pub fn tls_config(&self) -> Result<Arc<ClientConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = CertificateDer::from_pem_slice(&self.host_cert)
            .map_err(|e| Error::msg(format!("host certificate: {e}")))?;
        let key = PrivateKeyDer::from_pem_slice(&self.host_key)
            .map_err(|e| Error::msg(format!("host private key: {e}")))?;
        let mut cfg = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DeviceCertVerifier(provider)))
            .with_client_auth_cert(vec![cert], key)?;
        cfg.enable_sni = false;
        Ok(Arc::new(cfg))
    }
}

/// The phone presents a certificate issued by the pairing root, which no web PKI knows; we accept
/// it, but still check the handshake signatures against it.
#[derive(Debug)]
struct DeviceCertVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for DeviceCertVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn tls_wrap(s: Stream, cfg: Arc<ClientConfig>) -> Result<DevStream> {
    let conn = ClientConnection::new(cfg, ServerName::try_from("lockdown").unwrap())?;
    let mut tls = StreamOwned::new(conn, s);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(DevStream::Tls(Box::new(tls)))
}

/// 4 byte big endian length + XML plist, the framing of lockdownd and most lockdown services.
pub fn write_plist(w: &mut impl Write, d: &Dictionary) -> Result<()> {
    let mut body = Vec::new();
    plist::to_writer_xml(&mut body, d)?;
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    w.write_all(&out)?;
    w.flush()?;
    Ok(())
}

pub fn read_plist(r: &mut impl Read) -> Result<Dictionary> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);
    if len > crate::util::MAX_MESSAGE {
        return bail(format!(
            "lockdown payload length {len} exceeds maximum allowed size"
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    plist::from_bytes::<Dictionary>(&body).map_err(Into::into)
}

pub fn dict(pairs: &[(&str, Value)]) -> Dictionary {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

pub struct Lockdown {
    pub s: Option<DevStream>,
}

impl Lockdown {
    pub fn request(&mut self, d: &Dictionary) -> Result<Dictionary> {
        let s = self.s.as_mut().unwrap();
        write_plist(s, d)?;
        let r = read_plist(s)?;
        if let Some(e) = r.get("Error").and_then(|v| v.as_string()) {
            return bail(format!(
                "lockdown {} failed: {e}",
                d.get("Request").and_then(|v| v.as_string()).unwrap_or("")
            ));
        }
        Ok(r)
    }

    pub fn start_session(&mut self, pair: &PairRecord) -> Result<()> {
        let r = self.request(&dict(&[
            ("Label", "rxc".into()),
            ("ProtocolVersion", "2".into()),
            ("Request", "StartSession".into()),
            ("HostID", pair.host_id.clone().into()),
            ("SystemBUID", pair.system_buid.clone().into()),
        ]))?;
        if r.get("EnableSessionSSL")
            .and_then(|v| v.as_boolean())
            .unwrap_or(false)
        {
            let DevStream::Plain(s) = self.s.take().unwrap() else {
                return bail("session already encrypted");
            };
            self.s = Some(tls_wrap(s, pair.tls_config()?)?);
        }
        Ok(())
    }

    /// (port, EnableServiceSSL)
    pub fn start_service(&mut self, name: &str) -> Result<(u16, bool)> {
        let r = self
            .request(&dict(&[
                ("Label", "rxc".into()),
                ("Request", "StartService".into()),
                ("Service", name.into()),
            ]))
            .map_err(|e| Error::msg(format!("Could not start service:{name} with reason:'{e}'. Have you mounted the Developer Image?")))?;
        let port = r
            .get("Port")
            .and_then(|v| v.as_unsigned_integer())
            .ok_or_else(|| Error::msg(format!("no port for {name}: {r:?}")))?;
        Ok((
            port as u16,
            r.get("EnableServiceSSL")
                .and_then(|v| v.as_boolean())
                .unwrap_or(false),
        ))
    }

    pub fn get_value(&mut self, domain: Option<&str>, key: Option<&str>) -> Result<Value> {
        let mut d = dict(&[("Label", "rxc".into()), ("Request", "GetValue".into())]);
        if let Some(k) = key {
            d.insert("Key".into(), k.into());
        }
        if let Some(dm) = domain {
            d.insert("Domain".into(), dm.into());
        }
        let mut r = self.request(&d)?;
        r.remove("Value")
            .ok_or_else(|| Error::msg("GetValue returned no Value"))
    }

    pub fn set_value(&mut self, domain: Option<&str>, key: &str, value: Value) -> Result<()> {
        let mut d = dict(&[
            ("Label", "rxc".into()),
            ("Request", "SetValue".into()),
            ("Key", key.into()),
            ("Value", value),
        ]);
        if let Some(dm) = domain {
            d.insert("Domain".into(), dm.into());
        }
        self.request(&d).map(|_| ())
    }
}

/// One device and the usbmux sockets this command will need, opened in parallel up front.
pub struct Device {
    pub entry: DeviceEntry,
    pub pair: Option<PairRecord>,
    main: Option<Mux>,
    spares: Vec<WarmMux>,
    lockdown: Option<Lockdown>,
    tls: Option<Arc<ClientConfig>>,
}

pub fn requested_udid(udid: Option<&str>) -> Option<String> {
    udid.filter(|s| !s.is_empty()).map(|s| s.to_string())
}

impl Device {
    /// `spare_sockets`: how many extra service connections the command will open.
    pub fn open(udid: Option<&str>, need_pair: bool, spare_sockets: usize) -> Result<Device> {
        let spares: Vec<WarmMux> = (0..spare_sockets).map(|_| WarmMux::spawn()).collect();
        let udid = requested_udid(udid);
        let mut m = Mux::connect()?;
        m.send_list_devices()?;
        let pipelined_pair = need_pair && udid.is_some();
        if pipelined_pair {
            m.send_read_pair_record(udid.as_deref().unwrap())?;
        }
        let list = m.read_device_list()?;
        let entry = match &udid {
            Some(u) => list.iter().find(|d| &d.serial == u).cloned(),
            None => list.first().cloned(),
        }
        .ok_or_else(|| match &udid {
            Some(u) => Error::msg(format!(
                "Device '{u}' not found. Is it attached to the machine?"
            )),
            None => Error::msg("no device found"),
        })?;
        crate::debug!("device list received");
        let pair = if pipelined_pair {
            Some(PairRecord::from_dict(&m.read_pair_record_reply()?)?)
        } else if need_pair {
            m.send_read_pair_record(&entry.serial)?;
            Some(PairRecord::from_dict(&m.read_pair_record_reply()?)?)
        } else {
            None
        };
        Ok(Device {
            entry,
            pair,
            main: Some(m),
            spares,
            lockdown: None,
            tls: None,
        })
    }

    pub fn udid(&self) -> &str {
        &self.entry.serial
    }

    fn mux(&mut self) -> Result<Mux> {
        if let Some(m) = self.main.take() {
            return Ok(m);
        }
        if !self.spares.is_empty() {
            return Ok(self.spares.remove(0).get()?.0);
        }
        Mux::connect()
    }

    pub fn connect_port(&mut self, port: u16) -> Result<Stream> {
        let id = self.entry.device_id;
        self.mux()?.connect_port(id, port)
    }

    pub fn lockdown(&mut self) -> Result<&mut Lockdown> {
        if self.lockdown.is_none() {
            let s = self.connect_port(LOCKDOWN_PORT)?;
            self.lockdown = Some(Lockdown {
                s: Some(DevStream::Plain(s)),
            });
        }
        Ok(self.lockdown.as_mut().unwrap())
    }

    pub fn lockdown_session(&mut self) -> Result<&mut Lockdown> {
        let encrypted = matches!(
            self.lockdown.as_ref().and_then(|l| l.s.as_ref()),
            Some(DevStream::Tls(_))
        );
        if !encrypted {
            let pair = self
                .pair
                .clone()
                .ok_or_else(|| Error::msg("no pair record"))?;
            self.lockdown()?.start_session(&pair)?;
        }
        Ok(self.lockdown.as_mut().unwrap())
    }

    pub fn tls_config(&mut self) -> Result<Arc<ClientConfig>> {
        if self.tls.is_none() {
            self.tls = Some(
                self.pair
                    .as_ref()
                    .ok_or_else(|| Error::msg("no pair record"))?
                    .tls_config()?,
            );
        }
        Ok(self.tls.clone().unwrap())
    }

    /// StartService over the lockdown session, then connect to the service (TLS when asked to).
    pub fn connect_service(&mut self, name: &str) -> Result<DevStream> {
        self.lockdown_session()?;
        crate::debug!("lockdown session up");
        let (port, ssl) = self.lockdown_session()?.start_service(name)?;
        crate::debug!("service started", "service" => name, "port" => port, "ssl" => ssl);
        let s = self.connect_port(port)?;
        if ssl {
            let cfg = self.tls_config()?;
            return tls_wrap(s, cfg);
        }
        Ok(DevStream::Plain(s))
    }
}
