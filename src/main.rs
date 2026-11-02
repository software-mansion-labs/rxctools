//! `rxc`: Xcode's iPhone tools without Xcode, on macOS or Linux, over usbmuxd, lockdown and the
//! iOS 17+ tunnel. Like `xcrun`, it takes the tool's name first: `rxc devicectl …`,
//! `rxc xcodebuild test-without-building …` and `rxc devmodectl single …` follow Apple's tools;
//! `rxc tunnel` and `rxc sign` do what Xcode keeps to itself, and `rxc lockdown` reads and writes
//! the device's lockdown values.

mod der;
mod dtx;
mod image;
mod instruments;
mod lockdown;
mod nskeyed;
mod p12;
mod services;
mod sign;
mod tunnel;
mod usbmux;
mod util;
mod xctest;
mod xpc;

use lockdown::Device;
use serde_json::{Value as J, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use util::{Error, Result, bail};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Every command and its options, under the Xcode tool it stands in for; those the tool has too
/// keep its names. `tunnel`, `sign` and `lockdown` have no Xcode counterpart.
const COMMANDS: &[(&str, &str)] = &[
    ("devicectl list devices", ""),
    ("devicectl device info details", "--device <udid>"),
    (
        "devicectl device info apps",
        "--device <udid> [--include-all-apps] [--include-default-apps] [--bundle-id <id>]",
    ),
    ("devicectl device info processes", "--device <udid>"),
    (
        "devicectl device info ddiServices",
        "--device <udid> [--no-auto-mount-ddis]",
    ),
    ("devicectl device install app", "--device <udid> <path>"),
    (
        "devicectl device uninstall app",
        "--device <udid> <bundle-identifier>",
    ),
    (
        "devicectl device process launch",
        "--device <udid> [--terminate-existing] [--environment-variables <json>] \
         [--payload-url <url>] <bundle-identifier> [<arguments> ...]",
    ),
    (
        "devicectl device process terminate",
        "--device <udid> --pid <pid> [--kill]",
    ),
    (
        "devicectl device capture screenshot",
        "--device <udid> --destination <path>",
    ),
    ("devicectl manage ddis update", ""),
    (
        "xcodebuild test-without-building",
        "-xctestrun <file> -destination id=<udid>",
    ),
    ("devmodectl single", "<udid>"),
    ("tunnel run", "--device <udid> [--proxy-port <port>]"),
    ("tunnel list", ""),
    (
        "sign app",
        "<.app or .ipa> --p12 <file> [--p12-password <password>] --profile <mobileprovision> \
         [--output <path>] [--bundle-id <id>] [--install]",
    ),
    (
        "lockdown get",
        "--device <udid> [--domain <domain>] [<key>]",
    ),
    (
        "lockdown set",
        "--device <udid> [--domain <domain>] <key> <string value>",
    ),
];

const OPTIONS: &str = "options:
  -d, --device <udid>       the device; the first one when left out
  -j, --json-output <path>  write the result as JSON to a file, or to stdout with '-'
  -v, --verbose             debug logging
  -q, --quiet               errors only
  --tunnel <host:port>      where `rxc tunnel run` serves its tunnel list (default 127.0.0.1:50550)
  --version";

// Options that take a value; everything else starting with `-` is a boolean flag.
const VALUE_OPTS: &[&str] = &[
    "--device",
    "--json-output",
    "--bundle-id",
    "--environment-variables",
    "--payload-url",
    "--pid",
    "--destination",
    "--tunnel",
    "--proxy-port",
    "-xctestrun",
    "-destination",
    "--p12",
    "--p12-password",
    "--profile",
    "--output",
    "--domain",
];

/// Human-readable output goes to stderr when the JSON document takes stdout.
static HUMAN_TO_STDERR: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
pub struct Args {
    pub pos: Vec<String>,
    pub opts: HashMap<String, Vec<String>>,
}

impl Args {
    pub fn parse(raw: &[String]) -> Result<Args> {
        let mut a = Args::default();
        let mut i = 0;
        while i < raw.len() {
            let s = &raw[i];
            if s == "--" {
                a.pos.extend(raw[i + 1..].iter().cloned());
                break;
            }
            if s.starts_with('-') && s.len() > 1 {
                let (k, v) = match s.split_once('=') {
                    Some((k, v)) if k.starts_with("--") => (k.to_string(), Some(v.to_string())),
                    _ => (s.clone(), None),
                };
                let k = match k.as_str() {
                    "-d" => "--device",
                    "-j" => "--json-output",
                    "-p" => "--pid",
                    "-e" => "--environment-variables",
                    "-v" => "--verbose",
                    "-q" => "--quiet",
                    "-h" => "--help",
                    k => k,
                }
                .to_string();
                let v = if v.is_none() && VALUE_OPTS.contains(&k.as_str()) {
                    i += 1;
                    Some(
                        raw.get(i)
                            .cloned()
                            .ok_or_else(|| Error::msg(format!("{k} needs a value")))?,
                    )
                } else {
                    v
                };
                a.opts.entry(k).or_default().push(v.unwrap_or_default());
            } else {
                a.pos.push(s.clone());
            }
            i += 1;
        }
        Ok(a)
    }
    pub fn flag(&self, k: &str) -> bool {
        self.opts.contains_key(k)
    }
    pub fn opt(&self, k: &str) -> Option<&str> {
        self.opts
            .get(k)
            .and_then(|v| v.last())
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
    }
    /// `--device`, or the `id=` of an xcodebuild `-destination`.
    pub fn udid(&self) -> Option<&str> {
        self.opt("--device").or_else(|| {
            self.opt("-destination")?
                .split(',')
                .find_map(|kv| kv.trim().strip_prefix("id="))
        })
    }
}

fn say(s: impl std::fmt::Display) {
    if util::QUIET.load(Relaxed) {
    } else if HUMAN_TO_STDERR.load(Relaxed) {
        eprintln!("{s}");
    } else {
        println!("{s}");
    }
}

/// Columns padded to their widest cell, under a header and a dashed line.
fn table(headers: &[&str], rows: Vec<Vec<String>>) {
    let mut w: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let padded: Vec<String> = cells
            .iter()
            .zip(&w)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        padded.join("   ").trim_end().to_string()
    };
    say(line(headers.iter().map(|h| h.to_string()).collect()));
    say(line(w.iter().map(|n| "-".repeat(*n)).collect()));
    for r in rows {
        say(line(r));
    }
}

/// A string at a JSON pointer, for tables.
fn at(v: &J, ptr: &str) -> String {
    match v.pointer(ptr) {
        Some(J::String(s)) => s.clone(),
        Some(J::Null) | None => String::new(),
        Some(x) => x.to_string(),
    }
}

/// Is `w` the tool word of some command?
fn is_tool(w: &str) -> bool {
    COMMANDS.iter().any(|(c, _)| c.split(' ').next() == Some(w))
}

/// The commands of the tool named first in `words`, or all of them.
fn usage(words: &[String]) -> String {
    let tool = words.first().filter(|w| is_tool(w));
    let mut s = String::from("usage: rxc <tool> <command> [options]\n\n");
    for (c, o) in COMMANDS {
        if tool.is_none_or(|t| c.split(' ').next() == Some(t.as_str())) {
            s += format!("  rxc {c} {o}").trim_end();
            s += "\n";
        }
    }
    s + "\n" + OPTIONS
}

fn main() {
    util::START.get_or_init(std::time::Instant::now);
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let a = Args::parse(&raw).unwrap_or_else(|e| fatal(&e));
    util::VERBOSE.store(a.flag("--verbose"), Relaxed);
    util::QUIET.store(a.flag("--quiet"), Relaxed);
    if a.flag("--version") {
        println!("{VERSION}");
        return;
    }
    let found = COMMANDS.iter().find(|(c, _)| {
        let words: Vec<&str> = c.split(' ').collect();
        a.pos.len() >= words.len() && a.pos[..words.len()] == words[..]
    });
    let Some((command, opts)) = found else {
        if a.pos.is_empty() || a.flag("--help") || (a.pos.len() == 1 && is_tool(&a.pos[0])) {
            println!("{}", usage(&a.pos));
            return;
        }
        eprintln!("{}", usage(&a.pos));
        fatal(&Error::msg(format!("unknown command: {}", a.pos.join(" "))));
    };
    if a.flag("--help") {
        println!("usage: rxc {command} {opts}\n\n{OPTIONS}");
        return;
    }
    let json_out = a.opt("--json-output");
    HUMAN_TO_STDERR.store(
        matches!(json_out, Some("-" | "/dev/stdout" | "/dev/fd/1")),
        Relaxed,
    );
    let rest = &a.pos[command.split(' ').count()..];
    let r = run(command, rest, &a);
    let json_written = json_out.is_none_or(|path| write_json(path, command, &raw, &r));
    if let Err(e) = r {
        fatal(&e);
    }
    if !json_written {
        std::process::exit(1);
    }
}

fn fatal(e: &Error) -> ! {
    util::log("ERROR", &e.0, &[]);
    std::process::exit(1);
}

/// The document `devicectl --json-output` writes: what ran and how it went, then the result.
/// Without `rxc` in front, the arguments and command type read as devicectl's own. False when
/// the file could not be written.
fn write_json(path: &str, command: &str, raw: &[String], r: &Result<J>) -> bool {
    let mut doc = json!({"info": {
        "arguments": raw,
        "commandType": command.replace(' ', "."),
        "environment": {},
        "jsonVersion": 2,
        "outcome": if r.is_ok() { "success" } else { "failed" },
        "version": VERSION,
    }});
    match r {
        Ok(v) => doc["result"] = v.clone(),
        Err(e) => doc["error"] = json!({"userInfo": {"NSLocalizedDescription": {"string": e.0}}}),
    }
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    if HUMAN_TO_STDERR.load(Relaxed) {
        print!("{text}");
    } else if let Err(e) = std::fs::write(path, text) {
        util::log("ERROR", &format!("--json-output {path}: {e}"), &[]);
        return false;
    }
    true
}

fn run(command: &str, rest: &[String], a: &Args) -> Result<J> {
    let arg = |what: &str| {
        rest.first()
            .map(|s| s.as_str())
            .ok_or_else(|| Error::msg(format!("missing <{what}>")))
    };
    Ok(match command {
        "devicectl list devices" => list_devices()?,
        "tunnel list" => {
            let (_, body) = tunnel::http_get(tunnel::api_addr(a.opt("--tunnel")), "/tunnels")?;
            let list: J = serde_json::from_str(&body)?;
            let rows = list.as_array().into_iter().flatten();
            table(
                &["Identifier", "Address", "RSD Port", "Proxy Port"],
                rows.map(|t| {
                    ["/identifier", "/address", "/rsdPort", "/proxyPort"]
                        .iter()
                        .map(|p| at(t, p))
                        .collect()
                })
                .collect(),
            );
            json!({ "tunnels": list })
        }
        "devicectl device info details" => details(a)?,
        "devicectl device info apps" => apps(a)?,
        "devicectl device info processes" => {
            let t = open_tunnel(a)?;
            let list = instruments::process_list(&*instruments::connect(&t)?)?;
            table(
                &["PID", "Executable"],
                list.iter()
                    .map(|p| vec![at(p, "/processIdentifier"), at(p, "/executable")])
                    .collect(),
            );
            json!({"deviceIdentifier": t.udid, "runningProcesses": list})
        }
        "devicectl device info ddiServices" => ddi_services(a)?,
        "devicectl device install app" => install(a, arg("path")?)?,
        "devicectl device uninstall app" => {
            let bundle = arg("bundle-identifier")?;
            let mut d = Device::open(a.udid(), true, 1)?;
            services::uninstall(
                &mut d.connect_service(services::INSTALLATION_PROXY)?,
                bundle,
            )?;
            say("App uninstalled.");
            json!({"deviceIdentifier": d.udid(), "uninstalledApplications": [{"bundleID": bundle}]})
        }
        "devicectl device process launch" => launch(a, arg("bundle-identifier")?, &rest[1..])?,
        "devicectl device process terminate" => {
            let pid: u64 = a
                .opt("--pid")
                .and_then(|p| p.parse().ok())
                .ok_or_else(|| Error::msg("--pid <pid> is required"))?;
            let t = open_tunnel(a)?;
            let (name, sig) = if a.flag("--kill") {
                ("SIGKILL", 9)
            } else {
                ("SIGTERM", 15)
            };
            instruments::signal(&*instruments::connect(&t)?, pid, sig)?;
            say(format!("Sent {name} to process {pid}."));
            json!({"deviceIdentifier": t.udid, "process": {"processIdentifier": pid}})
        }
        "devicectl device capture screenshot" => {
            let dest = a
                .opt("--destination")
                .ok_or_else(|| Error::msg("--destination <path> is required"))?;
            let t = open_tunnel(a)?;
            std::fs::write(dest, instruments::screenshot(&*instruments::connect(&t)?)?)?;
            say(format!("Screenshot saved to {dest}"));
            json!({"deviceIdentifier": t.udid, "destination": dest})
        }
        // devmodectl takes the UDID as an argument
        "devmodectl single" => developer_mode(rest.first().map(|s| s.as_str()).or(a.udid()))?,
        "devicectl manage ddis update" => {
            let dir = image::download(&ddi_dir())?;
            say(format!("Developer disk image ready in {}", dir.display()));
            json!({"hostDDI": util::file_url(&format!("{}/", dir.display()))})
        }
        "tunnel run" => {
            let proxy_port = match a.opt("--proxy-port") {
                Some(p) => p
                    .parse()
                    .map_err(|_| Error::msg(format!("--proxy-port: not a port: {p}")))?,
                None => 0,
            };
            tunnel::run_daemon(a.udid(), tunnel::api_addr(a.opt("--tunnel")), proxy_port)?;
            json!({})
        }
        "sign app" => sign_app(a, arg("path")?)?,
        "xcodebuild test-without-building" => {
            let path = a
                .opt("-xctestrun")
                .ok_or_else(|| Error::msg("-xctestrun <file> is required"))?;
            let bytes = std::fs::read(path)
                .map_err(|e| Error::msg(format!("failed to open xctestrun file: {e}")))?;
            let t = open_tunnel(a)?;
            // the runner's own output; stdout belongs to the JSON document with `-j -`
            let out: Box<dyn std::io::Write + Send> = if HUMAN_TO_STDERR.load(Relaxed) {
                Box::new(std::io::stderr())
            } else {
                Box::new(std::io::stdout())
            };
            // shortcut: activities are reported like Xcode does; RXC_REPORT_ACTIVITIES=0 turns them off
            let report = std::env::var("RXC_REPORT_ACTIVITIES")
                .map(|v| v != "0")
                .unwrap_or(true);
            xctest::run(&t, &bytes, report, out)?;
            json!({})
        }
        "lockdown get" => {
            let (domain, key) = (a.opt("--domain"), rest.first().map(|s| s.as_str()));
            let mut d = Device::open(a.udid(), true, 0)?;
            let value = plist_json(&d.lockdown_session()?.get_value(domain, key)?);
            say(match &value {
                J::String(s) => s.clone(),
                J::Array(_) | J::Object(_) => serde_json::to_string_pretty(&value)?,
                v => v.to_string(),
            });
            json!({"deviceIdentifier": d.udid(), "domain": domain, "key": key, "value": value})
        }
        "lockdown set" => {
            let (Some(key), Some(value)) = (rest.first(), rest.get(1)) else {
                return bail("missing <key> <string value>");
            };
            let domain = a.opt("--domain");
            let mut d = Device::open(a.udid(), true, 0)?;
            d.lockdown_session()?
                .set_value(domain, key, value.as_str().into())?;
            say(format!("{key} set to {value}."));
            json!({"deviceIdentifier": d.udid(), "domain": domain, "key": key, "value": value})
        }
        _ => unreachable!("{command} is in COMMANDS"),
    })
}

/// A lockdown value as JSON, data in base64.
fn plist_json(v: &plist::Value) -> J {
    use plist::Value as P;
    match v {
        P::String(s) => s.as_str().into(),
        P::Boolean(b) => (*b).into(),
        P::Integer(i) => i
            .as_signed()
            .map(J::from)
            .unwrap_or_else(|| i.as_unsigned().into()),
        P::Real(r) => (*r).into(),
        P::Data(d) => util::base64(d).into(),
        P::Date(d) => d.to_xml_format().into(),
        P::Array(a) => a.iter().map(plist_json).collect(),
        P::Dictionary(d) => d.iter().map(|(k, v)| (k.clone(), plist_json(v))).collect(),
        _ => J::Null,
    }
}

pub fn open_tunnel(a: &Args) -> Result<tunnel::Tunnel> {
    tunnel::Tunnel::find(a.udid(), tunnel::api_addr(a.opt("--tunnel")))
}

/// A device the way `devicectl list devices` describes it, from usbmux and lockdown's values
/// (none when lockdown would not talk to us).
fn device_json(entry: &usbmux::DeviceEntry, values: Option<&plist::Dictionary>) -> J {
    let s = |k: &str| {
        values
            .and_then(|v| v.get(k))
            .and_then(|v| v.as_string())
            .unwrap_or("")
    };
    let udid = entry.serial.as_str();
    let transport = if entry.connection_type == "Network" {
        "localNetwork"
    } else {
        "wired"
    };
    let pairing = if values.is_some() {
        "paired"
    } else {
        "unpaired"
    };
    let hardware = json!({
        "udid": udid, "productType": s("ProductType"), "hardwareModel": s("HardwareModel"),
        "deviceType": s("DeviceClass"), "platform": "iOS", "serialNumber": s("SerialNumber"),
        "ecid": values.and_then(|v| v.get("UniqueChipID")).and_then(|v| v.as_unsigned_integer()),
        "cpuType": {"name": s("CPUArchitecture")},
    });
    // devicectl moves to `properties`; both are written, as it does for now
    json!({
        "identifier": udid,
        "connectionProperties": {"pairingState": pairing, "transportType": transport},
        "deviceProperties": {
            "name": s("DeviceName"), "osVersionNumber": s("ProductVersion"), "osBuildUpdate": s("BuildVersion"),
        },
        "hardwareProperties": hardware,
        "properties": {
            "connection": {"pairingState": pairing, "transportType": transport},
            "hardware": hardware,
            "software": {
                "osVersionNumber": {"stringValue": s("ProductVersion")},
                "osBuildVersions": {"buildVersion": {"name": s("BuildVersion")}},
            },
            "state": {"name": s("DeviceName")},
        },
    })
}

fn list_devices() -> Result<J> {
    let entries = usbmux::Mux::connect()?.list_devices()?;
    let lookups: Vec<_> = entries
        .into_iter()
        .map(|e| {
            std::thread::spawn(move || {
                let v = Device::open(Some(&e.serial), true, 0)
                    .and_then(|mut d| d.lockdown_session()?.get_value(None, None));
                if let Err(err) = &v {
                    debug!("lockdown did not answer", "device" => e.serial, "err" => err.0);
                }
                device_json(&e, v.ok().as_ref().and_then(|v| v.as_dictionary()))
            })
        })
        .collect();
    let devices = lookups
        .into_iter()
        .map(|h| h.join().map_err(|_| Error::msg("device lookup panicked")))
        .collect::<Result<Vec<J>>>()?;
    table(
        &["Name", "Identifier", "State", "Model"],
        devices
            .iter()
            .map(|d| {
                let state = match at(d, "/connectionProperties/pairingState").as_str() {
                    "paired" => "available (paired)",
                    _ => "unavailable",
                };
                vec![
                    at(d, "/deviceProperties/name"),
                    at(d, "/identifier"),
                    state.into(),
                    at(d, "/hardwareProperties/productType"),
                ]
            })
            .collect(),
    );
    Ok(json!({ "devices": devices }))
}

fn details(a: &Args) -> Result<J> {
    let mut d = Device::open(a.udid(), true, 1)?;
    let values = d.lockdown_session()?.get_value(None, None)?;
    let mut s = d.connect_service(image::SERVICE)?;
    let dev_mode = image::dev_mode_enabled(&mut s).unwrap_or(false);
    let ddi = image::mounted(&mut s).unwrap_or(false);
    let mut j = device_json(&d.entry, values.as_dictionary());
    j["deviceProperties"]["developerModeStatus"] =
        if dev_mode { "enabled" } else { "disabled" }.into();
    j["deviceProperties"]["ddiServicesAvailable"] = ddi.into();
    say(format!(
        "{} ({}), iOS {} ({})",
        at(&j, "/deviceProperties/name"),
        at(&j, "/hardwareProperties/productType"),
        at(&j, "/deviceProperties/osVersionNumber"),
        at(&j, "/deviceProperties/osBuildUpdate")
    ));
    say(format!("identifier: {}", d.udid()));
    say(format!(
        "developer mode: {}",
        at(&j, "/deviceProperties/developerModeStatus")
    ));
    say(format!("developer disk image services: {ddi}"));
    Ok(j)
}

/// Third-party apps by default, like devicectl; `--include-default-apps` adds Apple's.
fn apps(a: &Args) -> Result<J> {
    let all = a.flag("--include-all-apps");
    let defaults = all || a.flag("--include-default-apps");
    let mut d = Device::open(a.udid(), true, 1)?;
    let mut s = d.connect_service(services::INSTALLATION_PROXY)?;
    let request = services::browse_request(if defaults { "" } else { "User" }, all || !defaults);
    let s_of = |app: &plist::Dictionary, k: &str| {
        app.get(k)
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string()
    };
    let apps: Vec<J> = services::browse(&mut s, &request)?
        .iter()
        .filter_map(|app| {
            let id = s_of(app, "CFBundleIdentifier");
            let hidden = app
                .get("SBAppTags")
                .and_then(|t| t.as_array())
                .is_some_and(|t| t.iter().any(|t| t.as_string() == Some("hidden")));
            if (hidden && !all) || a.opt("--bundle-id").is_some_and(|b| b != id) {
                return None;
            }
            let name = Some(s_of(app, "CFBundleDisplayName"))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| s_of(app, "CFBundleName"));
            Some(json!({
                "appClip": app.get("IsAppClip").and_then(|v| v.as_boolean()).unwrap_or(false),
                "bundleIdentifier": id,
                "bundleVersion": s_of(app, "CFBundleVersion"),
                "defaultApp": s_of(app, "ApplicationType") == "System",
                "hidden": hidden,
                "name": name,
                "url": util::file_url(&format!("{}/", s_of(app, "Path"))),
                "version": s_of(app, "CFBundleShortVersionString"),
            }))
        })
        .collect();
    table(
        &["Name", "Bundle Identifier", "Version", "Bundle Version"],
        apps.iter()
            .map(|p| {
                ["/name", "/bundleIdentifier", "/version", "/bundleVersion"]
                    .iter()
                    .map(|k| at(p, k))
                    .collect()
            })
            .collect(),
    );
    Ok(json!({
        "apps": apps, "defaultAppsIncluded": defaults, "deviceIdentifier": d.udid(),
        "hiddenAppsIncluded": all, "removableAppsIncluded": true,
    }))
}

fn install(a: &Args, path: &str) -> Result<J> {
    let p = path.to_string();
    // zip the bundle while the connection is being set up
    let prep = std::thread::spawn(move || services::prepare_install(Path::new(&p)));
    let mut d = Device::open(a.udid(), true, 1)?;
    debug!("installing", "path" => path, "device" => d.udid());
    let mut s = d.connect_service(services::ZIP_CONDUIT)?;
    debug!("zip conduit connected");
    let (init, stream, bundle_id) = prep
        .join()
        .map_err(|_| Error::msg("prepare thread panicked"))??;
    services::zip_conduit_install(&mut s, &init, &stream)?;
    say("App installed:");
    if let Some(b) = &bundle_id {
        say(format!("• bundleID: {b}"));
    }
    Ok(json!({
        "deviceIdentifier": d.udid(),
        "installedApplications": bundle_id.iter().map(|b| json!({"bundleID": b})).collect::<Vec<_>>(),
    }))
}

/// Re-signs with the certificate in a .p12 and a provisioning profile, then installs with `--install`.
fn sign_app(a: &Args, path: &str) -> Result<J> {
    let read = |what: &str, k: &str| {
        let file = a
            .opt(k)
            .ok_or_else(|| Error::msg(format!("{k} <{what}> is required")))?;
        std::fs::read(file).map_err(|e| Error::msg(format!("failed reading {what}: {e}")))
    };
    let path = Path::new(path);
    let output = a
        .opt("--output")
        .map(PathBuf::from)
        .unwrap_or_else(|| sign::default_output(path));
    let signer = sign::Signer::new(
        &read("file", "--p12")?,
        a.opt("--p12-password").unwrap_or_default(),
    )?;
    let profile = read("mobileprovision", "--profile")?;
    let bundle = sign::sign_app(path, &output, &signer, &profile, a.opt("--bundle-id"))?;
    let output = output.display().to_string();
    say(format!("Signed {bundle} into {output}"));
    let mut result = json!({"bundleID": bundle, "path": output});
    if a.flag("--install") {
        result["install"] = install(a, &output)?;
    }
    Ok(result)
}

fn launch(a: &Args, bundle: &str, args: &[String]) -> Result<J> {
    let env: BTreeMap<String, String> = match a.opt("--environment-variables") {
        Some(j) => serde_json::from_str(j).map_err(|e| {
            Error::msg(format!(
                "--environment-variables takes a JSON object of strings: {e}"
            ))
        })?,
        None => BTreeMap::new(),
    };
    let terminate_existing = a.flag("--terminate-existing");
    let t = open_tunnel(a)?;
    let pid = match a.opt("--payload-url") {
        // instruments' launcher cannot hand a URL to the app; CoreDevice's can
        Some(url) => {
            let l = xctest::Launch {
                args,
                env: &env,
                platform_opts: &plist::Dictionary::new(),
                stdio: None,
                terminate_existing,
                payload_url: Some(url),
            };
            xctest::launch_app(&t, bundle, &l)? as u64
        }
        None => instruments::launch(
            &*instruments::connect(&t)?,
            bundle,
            args,
            &env.into_iter().collect::<Vec<_>>(),
            terminate_existing,
        )?,
    };
    say(format!(
        "Launched application with {bundle} bundle identifier."
    ));
    Ok(json!({"deviceIdentifier": t.udid, "process": {"processIdentifier": pid}}))
}

/// Where `devicectl manage ddis update` keeps the developer disk image. A personalized image's
/// `Restore` directory put anywhere under it is used too.
fn ddi_dir() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir)
        .join("rxc/ddis")
}

/// The device's iOS version and its major number.
fn ios_version(d: &mut Device) -> Result<(String, u32)> {
    let v = d
        .lockdown_session()?
        .get_value(None, Some("ProductVersion"))?;
    let v = v.as_string().unwrap_or("?").to_string();
    let major = v
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or(0);
    Ok((v, major))
}

/// Mounts the developer disk image unless it is there or `--no-auto-mount-ddis` says not to.
fn ddi_services(a: &Args) -> Result<J> {
    let mut d = Device::open(a.udid(), true, 2)?;
    let udid = d.udid().to_string();
    let mut s = d.connect_service(image::SERVICE)?;
    let mut mounted = image::mounted(&mut s)?;
    if !mounted && !a.flag("--no-auto-mount-ddis") {
        let (version, major) = ios_version(&mut d)?;
        if major < 17 {
            return bail(format!(
                "rxc mounts only the personalized developer disk images of iOS 17 and later, device runs {version}"
            ));
        }
        if !image::dev_mode_enabled(&mut s).unwrap_or(false) {
            // as Xcode does: show the toggle in Settings
            let _ = services::amfi(&mut d.connect_service(services::AMFI)?, 0);
            return bail(
                "Developer Mode is disabled: turn it on in Settings > Privacy & Security > Developer Mode",
            );
        }
        let path = image::download(&ddi_dir())?;
        image::mount(&mut d, s, &path)?;
        mounted = true;
    }
    say(format!(
        "Developer Disk Image Services are {} on {udid}.",
        if mounted { "enabled" } else { "not enabled" }
    ));
    Ok(json!({"deviceIdentifier": udid, "ddiServicesAvailable": mounted}))
}

/// AMFI action 1 turns developer mode on and restarts the device, action 2 then confirms it in
/// place of the prompt on the device. When action 1 is refused (a passcode is set), action 0 at
/// least reveals the toggle in Settings.
fn developer_mode(udid: Option<&str>) -> Result<J> {
    use std::time::{Duration, Instant};
    let mut d = Device::open(udid, true, 2)?;
    let (version, major) = ios_version(&mut d)?;
    if major < 16 {
        return bail(format!(
            "Developer Mode came with iOS 16, this device runs iOS {version}"
        ));
    }
    let udid = d.udid().to_string();
    let result = json!({"deviceIdentifier": udid, "developerModeStatus": "enabled"});
    if image::dev_mode_enabled(&mut d.connect_service(image::SERVICE)?)? {
        say("Developer Mode is already enabled.");
        return Ok(result);
    }
    let amfi = |udid: &str, action| {
        Device::open(Some(udid), true, 0)
            .and_then(|mut d| services::amfi(&mut d.connect_service(services::AMFI)?, action))
    };
    if let Err(e) = services::amfi(&mut d.connect_service(services::AMFI)?, 1) {
        let _ = amfi(&udid, 0);
        return bail(format!(
            "the device refused to enable Developer Mode ({e}); turn it on in Settings > Privacy & Security > Developer Mode"
        ));
    }
    info!("Developer Mode enabled, waiting for the device to restart", "device" => udid);
    let present = || {
        usbmux::Mux::connect()
            .and_then(|mut m| m.list_devices())
            .is_ok_and(|l| l.iter().any(|e| e.serial == udid))
    };
    let wait = |want: bool, secs: u64| {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if present() == want {
                return true;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        false
    };
    // the device may be back before the first look
    wait(false, 60);
    if !wait(true, 180) {
        return bail("the device did not come back within 240 seconds of the restart");
    }
    let mut last = Error::msg("");
    // lockdown takes a moment after the device reappears
    for _ in 0..10 {
        match amfi(&udid, 2) {
            Ok(()) => {
                say("Developer Mode enabled.");
                return Ok(result);
            }
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    bail(format!(
        "the device restarted, but confirming Developer Mode failed ({last}); confirm it in the prompt on the device"
    ))
}

#[cfg(test)]
mod tests {
    use super::Args;

    fn parse(s: &str) -> Args {
        Args::parse(&s.split(' ').map(String::from).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn devicectl_and_xcodebuild_arguments() {
        let a = parse(
            "devicectl device process launch -d U -e {} --terminate-existing com.x -- -flag v",
        );
        assert_eq!(
            a.pos,
            ["devicectl", "device", "process", "launch", "com.x", "-flag", "v"]
        );
        assert_eq!(a.udid(), Some("U"));
        assert_eq!(a.opt("--environment-variables"), Some("{}"));
        assert!(a.flag("--terminate-existing"));
        // xcodebuild takes its action anywhere among the options
        let a = parse(
            "xcodebuild -xctestrun f.xctestrun test-without-building -destination platform=iOS,id=U",
        );
        assert_eq!(a.pos, ["xcodebuild", "test-without-building"]);
        assert_eq!(
            (a.opt("-xctestrun"), a.udid()),
            (Some("f.xctestrun"), Some("U"))
        );
        assert_eq!(
            parse("devicectl list devices --json-output=-").opt("--json-output"),
            Some("-")
        );
    }

    #[test]
    fn every_command_is_under_a_tool() {
        let tools = [
            "devicectl",
            "xcodebuild",
            "devmodectl",
            "tunnel",
            "sign",
            "lockdown",
        ];
        for (c, _) in super::COMMANDS {
            assert!(tools.contains(&c.split(' ').next().unwrap()), "{c}");
        }
        let u = super::usage(&["devmodectl".into()]);
        assert!(u.contains("rxc devmodectl single") && !u.contains("devicectl"));
    }

    #[test]
    fn lockdown_values_as_json() {
        let v = plist::Value::Dictionary(super::lockdown::dict(&[
            ("ProductVersion", "18.7.8".into()),
            ("PasswordProtected", false.into()),
            ("UniqueChipID", u64::MAX.into()),
            ("Key", plist::Value::Data(vec![1, 2, 3])),
            ("Codes", vec![plist::Value::from(-1)].into()),
        ]));
        assert_eq!(
            super::plist_json(&v),
            serde_json::json!({"ProductVersion": "18.7.8", "PasswordProtected": false,
                "UniqueChipID": u64::MAX, "Key": "AQID", "Codes": [-1]})
        );
    }
}
