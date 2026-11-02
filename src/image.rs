//! Developer disk images through mobile_image_mounter: list and mount the iOS 17+
//! personalized image, which Apple's TSS signs for each device and nonce, and download it.

use crate::lockdown::{DevStream, Device, dict, read_plist, write_plist};
use crate::util::{Error, Result, bail};
use crate::{debug, info};
use plist::{Dictionary, Value};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub const SERVICE: &str = "com.apple.mobile.mobile_image_mounter";
/// The universal iOS 17+ personalized image; a copy already under the base dir is reused.
const DDI: &str = "ddi-17E5179g";
const DDI_URL: &str = "https://deviceboxhq.com/ddi-17E5179g.zip";
/// That zip's SHA-256: a changed or cut-short download fails here, not on the device.
const DDI_SHA256: &str = "b74e5d038df88fcf954f2a503bcbeb94a3fb78ad508a557665ac6bf325bece1a";
const TSS_URL: &str = "https://gs.apple.com/TSS/controller?action=2";

fn call(s: &mut DevStream, req: Dictionary) -> Result<Dictionary> {
    write_plist(s, &req)?;
    read_plist(s)
}

/// Fails unless the reply carries `status`. The device reports refusals (locked, developer mode
/// off, nothing mounted) in the reply as `Error` and `DetailedError`.
fn expect(r: &Dictionary, command: &str, status: &str) -> Result<()> {
    let text = |k: &str| {
        r.get(k).map(|v| {
            v.as_string()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{v:?}"))
        })
    };
    if let Some(e) = text("Error") {
        return match text("DetailedError") {
            Some(d) => bail(format!("{command}: device responded with error: {e}: {d}")),
            None => bail(format!("{command}: device responded with error: {e}")),
        };
    }
    if r.get("Status").and_then(|v| v.as_string()) != Some(status) {
        return bail(format!("{command}: unexpected response: {r:?}"));
    }
    Ok(())
}

/// Whether a developer disk image is mounted at /System/Developer. iOS 27 mounts it as a cryptex,
/// which only the list of mounted devices shows; `LookupImage` reports it on iOS 17 and 18.
pub fn mounted(s: &mut DevStream) -> Result<bool> {
    let r = call(s, dict(&[("Command", "CopyDevices".into())]))?;
    if let Some(e) = r.get("Error") {
        return bail(format!("CopyDevices: device responded with error: {e:?}"));
    }
    if developer_mount(&r) {
        return Ok(true);
    }
    let r = call(
        s,
        dict(&[
            ("Command", "LookupImage".into()),
            ("ImageType", "Personalized".into()),
        ]),
    )?;
    Ok(r.get("ImageSignature")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty()))
}

fn developer_mount(r: &Dictionary) -> bool {
    let entries = r.get("EntryList").and_then(|v| v.as_array());
    entries.into_iter().flatten().any(|e| {
        let e = e.as_dictionary();
        let get = |k| e.and_then(|e| e.get(k));
        get("MountPath").and_then(|v| v.as_string()) == Some("/System/Developer")
            && get("IsMounted").and_then(|v| v.as_boolean()) != Some(false)
    })
}

pub fn dev_mode_enabled(s: &mut DevStream) -> Result<bool> {
    let r = call(s, dict(&[("Command", "QueryDeveloperModeStatus".into())]))?;
    Ok(r.get("DeveloperModeStatus")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false))
}

/// Mounts the personalized image whose `Restore` directory is `restore`, over `s` (a connection to
/// [`SERVICE`] on `d`). Reuses the manifest the device kept from an earlier mount of this image
/// when it has one; otherwise Apple's TSS signs the image for the device's current nonce.
pub fn mount(d: &mut Device, mut s: DevStream, restore: &Path) -> Result<()> {
    let manifest: Dictionary = plist::from_file(restore.join("BuildManifest.plist"))
        .map_err(|e| Error::msg(format!("MountImage: failed to load build manifest: {e}")))?;
    let r = call(
        &mut s,
        dict(&[
            ("Command", "QueryPersonalizationIdentifiers".into()),
            ("PersonalizedImageType", "DeveloperDiskImage".into()),
        ]),
    )?;
    let ids = r
        .get("PersonalizationIdentifiers")
        .and_then(|v| v.as_dictionary())
        .ok_or_else(|| {
            Error::msg(format!(
                "queryIdentifiers: response has no 'PersonalizationIdentifiers' entry: {r:?}"
            ))
        })?
        .clone();
    let identity = find_identity(&manifest, number(&ids, "BoardId"), number(&ids, "ChipID"))?;
    let dmg = component_path(identity, &["PersonalizedDMG", "PersonalizedDmg"])
        .and_then(|p| safe_join(restore, &p))?;
    let image = std::fs::read(&dmg).map_err(|e| {
        Error::msg(format!(
            "failed to open developer disk dmg file '{}': {e}",
            dmg.display()
        ))
    })?;

    let digest = ring::digest::digest(&ring::digest::SHA384, &image);
    let r = call(
        &mut s,
        dict(&[
            ("Command", "QueryPersonalizationManifest".into()),
            ("PersonalizedImageType", "DeveloperDiskImage".into()),
            ("ImageType", "DeveloperDiskImage".into()),
            ("ImageSignature", Value::Data(digest.as_ref().to_vec())),
        ]),
    )?;
    // RXC_IMAGE_FORCE_TSS=1 exercises the TSS path on a device that kept a manifest
    let reuse = r
        .get("ImageSignature")
        .and_then(|v| v.as_data())
        .filter(|_| std::env::var_os("RXC_IMAGE_FORCE_TSS").is_none());
    let signature = match reuse {
        Some(sig) => {
            debug!("the device kept a manifest for this image, skipping TSS");
            sig.to_vec()
        }
        None => {
            info!("asking Apple's TSS to sign the developer disk image");
            // the service hangs up after a manifest query it cannot answer
            s = d.connect_service(SERVICE)?;
            let r = call(
                &mut s,
                dict(&[
                    ("Command", "QueryNonce".into()),
                    ("HostProcessName", "CoreDeviceService".into()),
                    ("PersonalizedImageType", "DeveloperDiskImage".into()),
                ]),
            )?;
            let nonce = r
                .get("PersonalizationNonce")
                .and_then(|v| v.as_data())
                .ok_or_else(|| {
                    Error::msg(format!(
                        "queryPersonalizedImageNonce: could not get nonce from response {r:?}"
                    ))
                })?
                .to_vec();
            let ecid = d
                .lockdown_session()?
                .get_value(None, Some("UniqueChipID"))?
                .as_unsigned_integer()
                .ok_or_else(|| Error::msg("could not get ECID from device"))?;
            tss_signature(&tss_request(identity, &ids, &nonce, ecid))?
        }
    };

    let r = call(
        &mut s,
        dict(&[
            ("Command", "ReceiveBytes".into()),
            ("ImageSignature", Value::Data(signature.clone())),
            ("ImageSize", (image.len() as u64).into()),
            ("ImageType", "Personalized".into()),
        ]),
    )?;
    expect(&r, "ReceiveBytes", "ReceiveBytesAck")?;
    s.write_all(&image)?;
    s.flush()?;
    expect(&read_plist(&mut s)?, "ReceiveBytes", "Complete")?;
    debug!("image uploaded", "bytes" => image.len());

    let trust_cache = std::fs::read(
        component_path(identity, &["LoadableTrustCache"]).and_then(|p| safe_join(restore, &p))?,
    )
    .map_err(|e| Error::msg(format!("MountImage: could not load trust-cache. {e}")))?;
    let r = call(
        &mut s,
        dict(&[
            ("Command", "MountImage".into()),
            ("ImageSignature", Value::Data(signature)),
            ("ImageType", "Personalized".into()),
            ("ImageTrustCache", Value::Data(trust_cache)),
        ]),
    )?;
    expect(&r, "MountImage", "Complete")?;
    write_plist(&mut s, &dict(&[("Command", "Hangup".into())]))
}

fn number(d: &Dictionary, k: &str) -> u64 {
    d.get(k).and_then(|v| v.as_unsigned_integer()).unwrap_or(0)
}

/// The build identity for this board and chip; the manifest writes their ids as hex strings.
fn find_identity(manifest: &Dictionary, board: u64, chip: u64) -> Result<&Dictionary> {
    let hex = |d: &Dictionary, k: &str| {
        d.get(k)
            .and_then(|v| v.as_string())
            .and_then(|s| u64::from_str_radix(s.to_lowercase().trim_start_matches("0x"), 16).ok())
    };
    manifest
        .get("BuildIdentities")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_dictionary())
        .find(|i| hex(i, "ApBoardID") == Some(board) && hex(i, "ApChipID") == Some(chip))
        .ok_or_else(|| Error::msg(format!("findIdentity: failed to find identity for ApBoardId 0x{board:x} and ApChipId 0x{chip:x}")))
}

fn components(identity: &Dictionary) -> impl Iterator<Item = (&String, &Dictionary)> {
    identity
        .get("Manifest")
        .and_then(|v| v.as_dictionary())
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| Some((k, v.as_dictionary()?)))
}

fn component_path(identity: &Dictionary, names: &[&str]) -> Result<String> {
    components(identity)
        .find(|(k, _)| names.contains(&k.as_str()))
        .and_then(|(_, c)| {
            c.get("Info")?
                .as_dictionary()?
                .get("Path")?
                .as_string()
                .map(|s| s.to_string())
        })
        .ok_or_else(|| Error::msg(format!("build manifest has no path for {}", names[0])))
}

/// `base/rel`, refusing a `rel` that would leave `base` (the manifest comes from a download).
fn safe_join(base: &Path, rel: &str) -> Result<PathBuf> {
    if Path::new(rel)
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return bail(format!("path '{rel}' would escape '{}'", base.display()));
    }
    Ok(base.join(rel))
}

/// The TSS request for a personalized developer disk image, as Apple's libauthinstall sends it.
fn tss_request(identity: &Dictionary, ids: &Dictionary, nonce: &[u8], ecid: u64) -> Dictionary {
    let mut req = dict(&[
        ("@ApImg4Ticket", true.into()),
        ("@BBTicket", true.into()),
        ("@HostPlatformInfo", "mac".into()),
        ("@VersionInfo", "libauthinstall-1104.0.9".into()),
        ("@UUID", uuid::Uuid::new_v4().to_string().into()),
        ("ApBoardID", number(ids, "BoardId").into()),
        ("ApChipID", number(ids, "ChipID").into()),
        ("ApECID", ecid.into()),
        ("ApNonce", Value::Data(nonce.to_vec())),
        ("ApProductionMode", true.into()),
        ("ApSecurityDomain", number(ids, "SecurityDomain").into()),
        ("ApSecurityMode", true.into()),
        ("SepNonce", Value::Data(vec![0; 20])),
        ("UID_MODE", false.into()),
    ]);
    // developer disk images are personalized for a production, secure, img4 device
    let params = dict(&[
        ("ApProductionMode", true.into()),
        ("ApSecurityMode", true.into()),
        ("ApSupportsImg4", true.into()),
    ]);
    let rules = components(identity)
        .find(|(k, _)| *k == "LoadableTrustCache")
        .and_then(|(_, c)| {
            c.get("Info")?
                .as_dictionary()?
                .get("RestoreRequestRules")?
                .as_array()
                .cloned()
        })
        .unwrap_or_default();
    for (key, c) in components(identity) {
        if c.get("Trusted").and_then(|v| v.as_boolean()) != Some(true) {
            continue;
        }
        let mut e = dict(&[
            (
                "Digest",
                c.get("Digest").cloned().unwrap_or(Value::Data(vec![])),
            ),
            ("Trusted", true.into()),
        ]);
        for k in ["EPRO", "ESEC"] {
            if let Some(v) = c.get(k) {
                e.insert(k.into(), v.clone());
            }
        }
        // Modern manifests carry EPRO/ESEC only as rules; without them TSS answers status 94.
        apply_rules(&mut e, &params, &rules);
        if key == "PersonalizedDMG" || key == "PersonalizedDmg" {
            let name = c
                .get("Name")
                .and_then(|v| v.as_string())
                .filter(|s| !s.is_empty())
                .unwrap_or("DeveloperDiskImage");
            e.insert("Name".into(), name.into());
        }
        req.insert(key.clone(), Value::Dictionary(e));
    }
    for (k, v) in ids {
        if k.starts_with("Ap,") {
            req.insert(k.clone(), v.clone());
        }
    }
    req
}

/// Applies the actions of every rule whose conditions the device parameters meet, like
/// libauthinstall. A condition rxc does not model leaves its rule unmatched.
fn apply_rules(e: &mut Dictionary, params: &Dictionary, rules: &[Value]) {
    let param = |cond: &str| match cond {
        "ApRawProductionMode" | "ApCurrentProductionMode" => params.get("ApProductionMode"),
        "ApRawSecurityMode" => params.get("ApSecurityMode"),
        "ApRequiresImage4" => params.get("ApSupportsImg4"),
        "ApDemotionPolicyOverride" => params.get("DemotionPolicy"),
        "ApInRomDFU" => params.get("ApInRomDFU"),
        _ => None,
    };
    for rule in rules.iter().filter_map(|r| r.as_dictionary()) {
        let conditions = rule.get("Conditions").and_then(|v| v.as_dictionary());
        if !conditions.is_none_or(|c| c.iter().all(|(k, want)| param(k) == Some(want))) {
            continue;
        }
        for (k, v) in rule
            .get("Actions")
            .and_then(|v| v.as_dictionary())
            .into_iter()
            .flatten()
        {
            // 255 means "leave unchanged"
            if v.as_unsigned_integer() != Some(255) {
                e.insert(k.clone(), v.clone());
            }
        }
    }
}

fn tss_signature(req: &Dictionary) -> Result<Vec<u8>> {
    let mut body = vec![];
    plist::to_writer_xml(&mut body, req)?;
    let mut resp = vec![];
    let headers = [
        ("Content-Type", "text/xml; charset=\"utf-8\""),
        ("User-Agent", "InetURL/1.0"),
        ("Cache-Control", "no-cache"),
    ];
    let status = crate::util::https("POST", TSS_URL, &headers, &body, &mut resp)?;
    if status != 200 {
        return bail(format!("getSignature: unexpected response status {status}"));
    }
    parse_tss(&String::from_utf8_lossy(&resp))
}

/// `STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=<plist>`; the plist comes last and may contain `&`.
fn parse_tss(s: &str) -> Result<Vec<u8>> {
    let field = |k: &str| s.find(k).map(|i| &s[i + k.len()..]);
    let until_amp = |v: &str| v[..v.find('&').unwrap_or(v.len())].to_string();
    let status: i64 = field("STATUS=")
        .map(until_amp)
        .unwrap_or_default()
        .parse()
        .map_err(|_| Error::msg(format!("TSS response without status: {s:.200}")))?;
    if status != 0 {
        return bail(format!(
            "unexpected status in response {status}: {:?}",
            field("MESSAGE=").map(until_amp).unwrap_or_default()
        ));
    }
    let ticket: Dictionary =
        plist::from_bytes(field("REQUEST_STRING=").unwrap_or("").as_bytes())
            .map_err(|e| Error::msg(format!("getSignature: failed to decode plist data: {e}")))?;
    ticket
        .get("ApImg4Ticket")
        .and_then(|v| v.as_data())
        .map(|d| d.to_vec())
        .ok_or_else(|| Error::msg("getSignature: could not get 'ApImg4Ticket' value from response"))
}

/// The personalized image's `Restore` directory under `basedir`, downloading and unpacking it the
/// first time.
pub fn download(basedir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(basedir)?;
    if let Some(dir) = find_restore(basedir) {
        debug!("developer disk image found", "path" => dir.display().to_string());
        return Ok(dir);
    }
    let archive = basedir.join(format!("{DDI}.zip"));
    let dest = basedir.join(DDI);
    // other rxc processes may be setting the image up too: work under hidden names of our own,
    // which find_restore skips, then rename into place
    let own = |what: &str| basedir.join(format!(".{DDI}.{}.{what}", std::process::id()));
    let sha256 = |p: &Path| {
        std::fs::read(p)
            .map(|b| crate::util::hex(ring::digest::digest(&ring::digest::SHA256, &b).as_ref()))
    };
    if sha256(&archive).ok().as_deref() != Some(DDI_SHA256) {
        info!("downloading the developer disk image", "url" => DDI_URL, "path" => archive.display().to_string());
        let part = own("zip");
        let status =
            crate::util::https("GET", DDI_URL, &[], &[], &mut std::fs::File::create(&part)?)?;
        let got = sha256(&part)?;
        let problem = if status != 200 {
            format!("unexpected status code {status}")
        } else if got != DDI_SHA256 {
            format!("SHA-256 {got}, expected {DDI_SHA256}")
        } else {
            String::new()
        };
        if !problem.is_empty() {
            let _ = std::fs::remove_file(&part);
            return bail(format!("downloading {DDI_URL}: {problem}"));
        }
        std::fs::rename(&part, &archive)?;
    }
    let unpacked = own("unzip");
    if let Err(e) = crate::util::unzip(&archive, &unpacked) {
        let _ = std::fs::remove_dir_all(&unpacked);
        return Err(e);
    }
    if std::fs::rename(&unpacked, &dest).is_err() {
        // another process got there first
        let _ = std::fs::remove_dir_all(&unpacked);
    }
    Ok(dest.join("Restore"))
}

/// A `Restore` directory with a BuildManifest.plist anywhere under `basedir`: the pinned image by
/// the name of the directory holding it, then one whose name contains the pinned name, then the
/// first in path order.
fn find_restore(basedir: &Path) -> Option<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            let hidden = e.file_name().to_string_lossy().starts_with('.');
            if p.is_dir() && !p.is_symlink() && !hidden {
                if p.file_name().is_some_and(|n| n == "Restore")
                    && p.join("BuildManifest.plist").is_file()
                {
                    out.push(p.clone());
                }
                walk(&p, out);
            }
        }
    }
    let mut dirs = vec![];
    walk(basedir, &mut dirs);
    dirs.sort();
    let name = |p: &PathBuf| {
        p.parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    };
    let pick = dirs
        .iter()
        .find(|p| name(p) == DDI)
        .or_else(|| dirs.iter().find(|p| name(p).contains(DDI)))
        .or(dirs.first());
    pick.cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The rules modern DDI manifests attach to LoadableTrustCache
    fn trust_cache_rules() -> Vec<Value> {
        let rule = |action: (&str, bool), conds: &[(&str, bool)]| {
            let c: Dictionary = conds
                .iter()
                .map(|(k, v)| (k.to_string(), Value::Boolean(*v)))
                .collect();
            Value::Dictionary(dict(&[
                (
                    "Actions",
                    Value::Dictionary(dict(&[(action.0, action.1.into())])),
                ),
                ("Conditions", Value::Dictionary(c)),
            ]))
        };
        vec![
            rule(
                ("EPRO", false),
                &[
                    ("ApCurrentProductionMode", false),
                    ("ApRequiresImage4", true),
                ],
            ),
            rule(
                ("EPRO", true),
                &[
                    ("ApCurrentProductionMode", true),
                    ("ApRequiresImage4", true),
                ],
            ),
            rule(
                ("ESEC", false),
                &[("ApRawSecurityMode", false), ("ApRequiresImage4", true)],
            ),
            rule(
                ("ESEC", true),
                &[("ApRawSecurityMode", true), ("ApRequiresImage4", true)],
            ),
        ]
    }

    fn params(production: bool, secure: bool) -> Dictionary {
        dict(&[
            ("ApProductionMode", production.into()),
            ("ApSecurityMode", secure.into()),
            ("ApSupportsImg4", true.into()),
        ])
    }

    #[test]
    fn rules_production_secure_and_development() {
        let mut e = Dictionary::new();
        apply_rules(&mut e, &params(true, true), &trust_cache_rules());
        assert_eq!(
            (e.get("EPRO"), e.get("ESEC")),
            (Some(&Value::Boolean(true)), Some(&Value::Boolean(true)))
        );
        let mut e = Dictionary::new();
        apply_rules(&mut e, &params(false, false), &trust_cache_rules());
        assert_eq!(
            (e.get("EPRO"), e.get("ESEC")),
            (Some(&Value::Boolean(false)), Some(&Value::Boolean(false)))
        );
    }

    #[test]
    fn rules_unmatched_conditions_and_sentinel() {
        let rule = |k: &str, v: Value, cond: &str| {
            Value::Dictionary(dict(&[
                ("Actions", Value::Dictionary(dict(&[(k, v)]))),
                (
                    "Conditions",
                    Value::Dictionary(dict(&[(cond, true.into())])),
                ),
            ]))
        };
        let p = dict(&[
            ("ApProductionMode", true.into()),
            ("ApSupportsImg4", true.into()),
        ]);
        let mut e = Dictionary::new();
        apply_rules(
            &mut e,
            &p,
            &[
                rule("EPRO", false.into(), "ApInRomDFU"),
                rule("ESEC", true.into(), "SomeUnknownCondition"),
            ],
        );
        assert!(e.is_empty());
        let mut e = dict(&[("EPRO", true.into())]);
        apply_rules(
            &mut e,
            &p,
            &[rule("EPRO", 255u64.into(), "ApCurrentProductionMode")],
        );
        assert_eq!(e.get("EPRO"), Some(&Value::Boolean(true)));
    }

    #[test]
    fn tss_response() {
        let ticket = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>ApImg4Ticket</key><data>AQID</data><key>Note</key><string>a &amp; b</string></dict></plist>";
        assert_eq!(
            parse_tss(&format!("STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING={ticket}")).unwrap(),
            vec![1, 2, 3]
        );
        let e = parse_tss("STATUS=94&MESSAGE=This device isn't eligible for the requested build.")
            .unwrap_err();
        assert!(e.0.contains("94") && e.0.contains("isn't eligible"), "{e}");
        assert!(parse_tss("STATUS=0&MESSAGE=SUCCESS").is_err());
    }

    #[test]
    fn developer_mount_from_copy_devices() {
        let entry = |path: &str, mounted: bool| {
            Value::from(dict(&[
                ("DiskImageType", "Personalized".into()),
                ("IsMounted", mounted.into()),
                ("MountPath", path.into()),
            ]))
        };
        let reply = |entries: Vec<Value>| dict(&[("EntryList", entries.into())]);
        assert!(developer_mount(&reply(vec![entry(
            "/System/Developer",
            true
        )])));
        assert!(!developer_mount(&reply(vec![entry(
            "/System/Developer",
            false
        )])));
        assert!(!developer_mount(&reply(vec![entry(
            "/private/var/mnt",
            true
        )])));
        assert!(!developer_mount(&reply(vec![])));
        assert!(!developer_mount(&Dictionary::new()));
    }

    #[test]
    fn device_errors_are_reported() {
        // iOS 26.5.2 mounting with Developer Mode off
        let r = dict(&[
            ("Error", "ImageMountFailed".into()),
            ("DetailedError", "Developer mode is not enabled.".into()),
        ]);
        assert_eq!(
            expect(&r, "MountImage", "Complete").unwrap_err().0,
            "MountImage: device responded with error: ImageMountFailed: Developer mode is not enabled."
        );
        assert!(
            expect(
                &dict(&[("Status", "ReceiveBytesAck".into())]),
                "ReceiveBytes",
                "Complete"
            )
            .is_err()
        );
        assert!(
            expect(
                &dict(&[("Status", "Complete".into())]),
                "MountImage",
                "Complete"
            )
            .is_ok()
        );
    }

    #[test]
    fn identity_and_paths() {
        let identity = |board: &str, chip: &str| {
            Value::Dictionary(dict(&[
                ("ApBoardID", board.into()),
                ("ApChipID", chip.into()),
                (
                    "Manifest",
                    Value::Dictionary(dict(&[(
                        "PersonalizedDMG",
                        Value::Dictionary(dict(&[(
                            "Info",
                            Value::Dictionary(dict(&[("Path", "x.dmg".into())])),
                        )])),
                    )])),
                ),
            ]))
        };
        let m = dict(&[(
            "BuildIdentities",
            Value::Array(vec![identity("0x0C", "0x8120"), identity("0x0E", "0x8120")]),
        )]);
        let i = find_identity(&m, 0xe, 0x8120).unwrap();
        assert_eq!(i.get("ApBoardID").and_then(|v| v.as_string()), Some("0x0E"));
        assert_eq!(
            component_path(i, &["PersonalizedDMG", "PersonalizedDmg"]).unwrap(),
            "x.dmg"
        );
        assert!(find_identity(&m, 0x1, 0x8120).is_err());
        assert!(
            safe_join(Path::new("/b"), "../x").is_err()
                && safe_join(Path::new("/b"), "/etc/x").is_err()
        );
        assert_eq!(
            safe_join(Path::new("/b"), "Firmware/x.trustcache").unwrap(),
            Path::new("/b/Firmware/x.trustcache")
        );
    }

    #[test]
    fn present_image_selection() {
        let base = std::env::temp_dir().join(format!("rxc-ddi-{}", std::process::id()));
        let write = |dir: &Path| {
            std::fs::create_dir_all(dir.join("Restore")).unwrap();
            std::fs::write(dir.join("Restore/BuildManifest.plist"), "m").unwrap();
            dir.join("Restore")
        };
        // another process still unpacking
        write(&base.join(format!(".{DDI}.1.unzip")));
        assert_eq!(find_restore(&base), None);
        let ancestor = write(&base.join(format!("{DDI}-backup/someimage")));
        assert_eq!(find_restore(&base), Some(ancestor));
        let older = write(&base.join("ddi-15F31d"));
        assert_eq!(find_restore(&base), Some(older), "first in path order");
        write(&base.join(format!("aaaa-{DDI}-copy")));
        let pinned = write(&base.join(DDI));
        assert_eq!(find_restore(&base), Some(pinned));
        std::fs::remove_dir_all(&base).unwrap();
    }
}
