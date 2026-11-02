//! Errors, JSON logging, small helpers.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_MESSAGE: u32 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct Error(pub String);

impl Error {
    pub fn msg(s: impl Into<String>) -> Error {
        Error(s.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

macro_rules! from_err {
    ($($t:ty),*) => {$(
        impl From<$t> for Error {
            fn from(e: $t) -> Self { Error(e.to_string()) }
        }
    )*};
}
from_err!(
    std::io::Error,
    plist::Error,
    rustls::Error,
    serde_json::Error,
    std::string::FromUtf8Error
);

pub type Result<T> = std::result::Result<T, Error>;

pub fn bail<T>(s: impl Into<String>) -> Result<T> {
    Err(Error(s.into()))
}

/// RFC 3339 UTC timestamp with microseconds.
pub fn timestamp() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339(d.as_secs() as i64, d.subsec_micros())
}

pub fn rfc3339(secs: i64, micros: u32) -> String {
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        micros
    )
}

/// `file://` URL of an absolute path, percent-encoding what a URL path cannot hold.
pub fn file_url(path: &str) -> String {
    let mut s = String::from("file://");
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"/-._~!$&'()*+,;=:@".contains(&b) {
            s.push(b as char);
        } else {
            s += &format!("%{b:02X}");
        }
    }
    s
}

pub static VERBOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// One log line on stderr: `msg key=value ...`. `-v` adds debug lines and milliseconds since start,
/// `-q` leaves only warnings and errors.
pub fn log(level: &str, msg: &str, kv: &[(&str, serde_json::Value)]) {
    use std::sync::atomic::Ordering::Relaxed;
    let verbose = VERBOSE.load(Relaxed);
    if (level == "DEBUG" && !verbose) || (level == "INFO" && QUIET.load(Relaxed)) {
        return;
    }
    let mut line = String::new();
    if verbose {
        let ms = START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis();
        line += &format!("[{ms:>6}ms] ");
    }
    line += match level {
        "ERROR" => "error: ",
        "WARN" => "warning: ",
        _ => "",
    };
    line += msg;
    for (k, v) in kv {
        match v {
            serde_json::Value::String(s) => line += &format!(" {k}={s}"),
            v => line += &format!(" {k}={v}"),
        }
    }
    eprintln!("{line}");
}

#[macro_export]
macro_rules! info {
    ($msg:expr $(, $k:expr => $v:expr)* $(,)?) => {
        $crate::util::log("INFO", &$msg, &[$(($k, serde_json::json!($v))),*])
    };
}

#[macro_export]
macro_rules! debug {
    ($msg:expr $(, $k:expr => $v:expr)* $(,)?) => {
        $crate::util::log("DEBUG", &$msg, &[$(($k, serde_json::json!($v))),*])
    };
}

/// https://www.apple.com/appleca/AppleIncRootCertificate.cer
pub const APPLE_ROOT_CA: &[u8] = include_bytes!("certs/apple-root-ca.cer");

/// Minimal HTTPS client for the few internet calls rxc makes (Apple's TSS, the developer disk image
/// download). It speaks HTTP/1.0, so the body is never chunked and ends with the connection, and it
/// follows redirects. Writes the body to `out` and returns the status code.
pub fn https(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    out: &mut dyn std::io::Write,
) -> Result<u16> {
    use rustls::pki_types::ServerName;
    use std::io::{BufRead, Read, Write};
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    // gs.apple.com chains to Apple Root CA, which Mozilla's store (webpki-roots) leaves out
    roots.add(rustls::pki_types::CertificateDer::from(APPLE_ROOT_CA))?;
    let cfg = std::sync::Arc::new(
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    let mut url = url.to_string();
    for _ in 0..5 {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| Error::msg(format!("not an https URL: {url}")))?;
        let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let (name, port) = match host.rsplit_once(':') {
            Some((h, p)) => (
                h,
                p.parse()
                    .map_err(|_| Error::msg(format!("bad port in {url}")))?,
            ),
            None => (host, 443),
        };
        let server = ServerName::try_from(name.to_string())
            .map_err(|e| Error::msg(format!("{name}: {e}")))?;
        let conn = rustls::ClientConnection::new(cfg.clone(), server)?;
        let mut tls = rustls::StreamOwned::new(conn, std::net::TcpStream::connect((name, port))?);
        let mut req = format!(
            "{method} {} HTTP/1.0\r\nHost: {host}\r\nContent-Length: {}\r\n",
            if path.is_empty() { "/" } else { path },
            body.len()
        );
        for (k, v) in headers {
            req += &format!("{k}: {v}\r\n");
        }
        req += "\r\n";
        tls.write_all(req.as_bytes())?;
        tls.write_all(body)?;
        tls.flush()?;

        let mut r = std::io::BufReader::new(tls);
        let mut line = String::new();
        r.read_line(&mut line)?;
        let status: u16 = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::msg(format!("bad HTTP status line from {host}: {line:?}")))?;
        let (mut location, mut length) = (None, None);
        loop {
            line.clear();
            if r.read_line(&mut line)? == 0 || line.trim_end().is_empty() {
                break;
            }
            if let Some((k, v)) = line.trim_end().split_once(':') {
                match k.to_ascii_lowercase().as_str() {
                    "location" => location = Some(v.trim().to_string()),
                    "content-length" => length = v.trim().parse::<u64>().ok(),
                    _ => {}
                }
            }
        }
        if let (300..=399, Some(l)) = (status, location) {
            url = if l.starts_with('/') {
                format!("https://{host}{l}")
            } else {
                l
            };
            continue;
        }
        match length {
            Some(n) => {
                if std::io::copy(&mut r.take(n), out)? != n {
                    return bail(format!(
                        "{url}: connection closed before the whole body arrived"
                    ));
                }
            }
            None => match std::io::copy(&mut r, out) {
                // servers that close without TLS close_notify
                Err(e) if e.kind() != std::io::ErrorKind::UnexpectedEof => return Err(e.into()),
                _ => {}
            },
        }
        return Ok(status);
    }
    bail(format!("{url}: too many redirects"))
}

/// Extracts a zip archive into `dest`, refusing entries that would land outside it.
pub fn unzip(archive: &std::path::Path, dest: &std::path::Path) -> Result<()> {
    let err = |e: zip::result::ZipError| {
        Error::msg(format!("could not unzip {}: {e}", archive.display()))
    };
    zip::ZipArchive::new(std::fs::File::open(archive)?)
        .map_err(err)?
        .extract(dest)
        .map_err(err)
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(super::base64(b""), "");
        assert_eq!(super::base64(b"f"), "Zg==");
        assert_eq!(super::base64(b"fo"), "Zm8=");
        assert_eq!(super::base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn apple_root_ca_is_the_published_one() {
        let d = ring::digest::digest(&ring::digest::SHA256, super::APPLE_ROOT_CA);
        assert_eq!(
            super::hex(d.as_ref()),
            "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
        );
    }

    #[test]
    fn unzip_refuses_escaping_entries() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("rxc-unzip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let archive = dir.join("evil.zip");
        let mut w = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.start_file("../escaped.txt", opts).unwrap();
        w.write_all(b"x").unwrap();
        w.start_file("Restore/ok.txt", opts).unwrap();
        w.write_all(b"y").unwrap();
        w.finish().unwrap();
        let _ = super::unzip(&archive, &dir.join("out"));
        assert!(!dir.join("escaped.txt").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn file_urls() {
        assert_eq!(
            super::file_url("/var/A b/\u{17c}.app/"),
            "file:///var/A%20b/%C5%BC.app/"
        );
    }

    #[test]
    fn timestamp_shape() {
        let t = super::timestamp();
        assert_eq!(t.len(), 27, "{t}");
        assert!(t.starts_with("20") && t.ends_with('Z'));
    }
}
