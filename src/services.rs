//! installation_proxy (browse, uninstall), streaming_zip_conduit (install) and AMFI
//! (developer mode).

use crate::lockdown::{dict, read_plist, write_plist};
use crate::util::{Error, Result, bail};
use plist::Dictionary;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const INSTALLATION_PROXY: &str = "com.apple.mobile.installation_proxy";
pub const ZIP_CONDUIT: &str = "com.apple.streaming_zip_conduit";
pub const AMFI: &str = "com.apple.amfi.lockdown";

/// AMFI developer mode actions: 0 reveals the toggle in Settings, 1 turns developer mode on (the
/// device restarts; refused while a passcode is set), 2 confirms it after the restart.
pub fn amfi(s: &mut (impl Read + Write), action: u64) -> Result<()> {
    write_plist(s, &dict(&[("action", action.into())]))?;
    let r = read_plist(s)?;
    if let Some(e) = r.get("Error") {
        return bail(
            e.as_string()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{e:?}")),
        );
    }
    if r.contains_key("success") {
        return Ok(());
    }
    bail("no error or success was reported")
}

pub fn browse_request(app_type: &str, show_launch_prohibited: bool) -> Dictionary {
    let mut opts = Dictionary::new();
    if !app_type.is_empty() && app_type != "Filesharing" {
        opts.insert("ApplicationType".into(), app_type.into());
    }
    if show_launch_prohibited {
        opts.insert("ShowLaunchProhibitedApps".into(), true.into());
    }
    dict(&[("ClientOptions", opts.into()), ("Command", "Browse".into())])
}

// Caps on the browse loop, so a misbehaving device cannot keep it spinning.
const MAX_BROWSE_CHUNKS: usize = 10_000;
const MAX_BROWSE_ENTRIES: u64 = 100_000;

pub fn browse(s: &mut (impl Read + Write), request: &Dictionary) -> Result<Vec<Dictionary>> {
    write_plist(s, request)?;
    read_browse(s)
}

pub fn read_browse(s: &mut impl Read) -> Result<Vec<Dictionary>> {
    let mut apps = vec![];
    let mut total = 0u64;
    for _ in 0..MAX_BROWSE_CHUNKS {
        let r = read_plist(s)?;
        if let Some(e) = r.get("Error") {
            return bail(format!("browse failed: {e:?}"));
        }
        total += r
            .get("CurrentAmount")
            .and_then(|v| v.as_unsigned_integer())
            .unwrap_or(0);
        if total > MAX_BROWSE_ENTRIES {
            return bail(format!(
                "browseApps: device reported {total} app entries, exceeding limit of {MAX_BROWSE_ENTRIES}"
            ));
        }
        if let Some(list) = r.get("CurrentList").and_then(|v| v.as_array()) {
            apps.extend(list.iter().filter_map(|a| a.as_dictionary().cloned()));
        }
        if r.get("Status").and_then(|v| v.as_string()) == Some("Complete") {
            return Ok(apps);
        }
    }
    bail(format!(
        "browseApps: exceeded {MAX_BROWSE_CHUNKS} response chunks without receiving Status \"Complete\", device likely stuck"
    ))
}

pub fn uninstall(s: &mut (impl Read + Write), bundle_id: &str) -> Result<()> {
    write_plist(
        s,
        &dict(&[
            ("Command", "Uninstall".into()),
            ("ApplicationIdentifier", bundle_id.into()),
            ("ClientOptions", Dictionary::new().into()),
        ]),
    )?;
    loop {
        let r = read_plist(s)?;
        if let Some(e) = r.get("Error") {
            return bail(format!(
                "received uninstall error: {}",
                e.as_string().unwrap_or("?")
            ));
        }
        match r.get("Status").and_then(|v| v.as_string()) {
            Some("Complete") => return Ok(()),
            Some(st) => crate::debug!("uninstall status", "status" => st),
            None => return bail(format!("unknown status update: {r:?}")),
        }
    }
}

// Permissions Xcode sends.
const STD_DIR_PERM: i64 = 16877;
const STD_FILE_PERM: i64 = -32348;
const CENTRAL_DIRECTORY_HEADER: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
// A 0x5455 "UT" extra field as Xcode writes it; the device does not care about its content.
const ZIP_EXTRA: [u8; 32] = [
    0x55, 0x54, 0x0D, 0x00, 0x07, 0xF3, 0xA2, 0xEC, 0x60, 0xF6, 0xA2, 0xEC, 0x60, 0xF3, 0xA2, 0xEC,
    0x60, 0x75, 0x78, 0x0B, 0x00, 0x01, 0x04, 0xF5, 0x01, 0x00, 0x00, 0x04, 0x14, 0x00, 0x00, 0x00,
];

fn zip_local_header(out: &mut Vec<u8>, name: &str, crc: u32, size: u32) {
    out.extend_from_slice(&0x04034b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes()); // version
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // stored
    out.extend_from_slice(&0xBDEFu16.to_le_bytes());
    out.extend_from_slice(&0x52ECu16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(ZIP_EXTRA.len() as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&ZIP_EXTRA);
}

/// filepath.Walk order: the root, then entries sorted by name, depth first.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    out.push(dir.to_path_buf());
    if dir.is_dir() && !dir.is_symlink() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for e in entries {
            walk(&e, out)?;
        }
    }
    Ok(())
}

pub struct ZipEntry {
    name: String,
    data: Option<Vec<u8>>, // None for directories
}

/// The entries to stream for an unpacked .app: names relative to the bundle, the bundle root itself
/// keeps its full path (the device ignores it).
pub fn app_entries(app: &Path) -> Result<(Vec<ZipEntry>, u64)> {
    let mut paths = vec![];
    walk(app, &mut paths)?;
    let prefix = format!("{}/", app.display());
    let mut total = 0u64;
    let mut entries = Vec::with_capacity(paths.len());
    for p in paths {
        let meta = std::fs::symlink_metadata(&p)?;
        total += meta.len();
        let mut name = p.display().to_string();
        if let Some(rest) = name.strip_prefix(&prefix) {
            name = rest.to_string();
        }
        if meta.is_dir() {
            if !name.ends_with('/') {
                name.push('/');
            }
            entries.push(ZipEntry { name, data: None });
        } else if meta.file_type().is_symlink() {
            entries.push(ZipEntry {
                name,
                data: Some(std::fs::read_link(&p)?.display().to_string().into_bytes()),
            });
        } else {
            entries.push(ZipEntry {
                name,
                data: Some(std::fs::read(&p)?),
            });
        }
    }
    Ok((entries, total))
}

fn ipa_entries(ipa: &Path) -> Result<(Vec<ZipEntry>, u64)> {
    // shortcut: an .ipa is unpacked into a temp dir and sent like a directory, which costs a disk
    // round trip; stream the archive's entries directly if large IPAs matter.
    let tmp = std::env::temp_dir().join(format!("rxc-ipa-{}", std::process::id()));
    crate::util::unzip(ipa, &tmp)?;
    let mut paths = vec![];
    walk(&tmp, &mut paths)?;
    let prefix = format!("{}/", tmp.display());
    let mut total = 0;
    let mut entries = vec![];
    for p in paths.into_iter().skip(1) {
        let meta = std::fs::symlink_metadata(&p)?;
        let mut name = p
            .display()
            .to_string()
            .strip_prefix(&prefix)
            .unwrap()
            .to_string();
        if meta.is_dir() {
            name.push('/');
            entries.push(ZipEntry { name, data: None });
        } else {
            total += meta.len();
            entries.push(ZipEntry {
                name,
                data: Some(std::fs::read(&p)?),
            });
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok((entries, total))
}

pub fn zip_stream(entries: &[ZipEntry], total: u64) -> Result<Vec<u8>> {
    let meta = dict(&[
        ("RecordCount", ((2 + entries.len()) as i64).into()),
        ("StandardDirectoryPerms", STD_DIR_PERM.into()),
        ("StandardFilePerms", STD_FILE_PERM.into()),
        ("TotalUncompressedBytes", total.into()),
        ("Version", 2.into()),
    ]);
    let mut meta_bytes = Vec::new();
    plist::to_writer_xml(&mut meta_bytes, &meta)?;
    let cap = entries
        .iter()
        .map(|e| e.data.as_ref().map_or(0, |d| d.len()) + e.name.len() + 62)
        .sum::<usize>();
    let mut out = Vec::with_capacity(cap + meta_bytes.len() + 200);
    zip_local_header(&mut out, "META-INF/", 0, 0);
    zip_local_header(
        &mut out,
        "META-INF/com.apple.ZipMetadata.plist",
        crc32fast::hash(&meta_bytes),
        meta_bytes.len() as u32,
    );
    out.extend_from_slice(&meta_bytes);
    for e in entries {
        match &e.data {
            None => zip_local_header(&mut out, &e.name, 0, 0),
            Some(d) => {
                zip_local_header(&mut out, &e.name, crc32fast::hash(d), d.len() as u32);
                out.extend_from_slice(d);
            }
        }
    }
    out.extend_from_slice(&CENTRAL_DIRECTORY_HEADER);
    Ok(out)
}

pub fn init_transfer(app_name: &str) -> Dictionary {
    dict(&[
        (
            "InstallOptionsDictionary",
            dict(&[
                ("DisableDeltaTransfer", 1.into()),
                (
                    "InstallDeltaTypeKey",
                    "InstallDeltaTypeSparseIPAFiles".into(),
                ),
                ("IsUserInitiated", 1.into()),
                ("PackageType", "Customer".into()),
                ("PreferWifi", 1.into()),
            ])
            .into(),
        ),
        ("InstallTransferredDirectory", 1.into()),
        ("MediaSubdir", format!("PublicStaging/{app_name}").into()),
        ("UserInitiatedTransfer", 0.into()),
    ])
}

/// Prepares everything that does not need the device, so it can run while the connection is set up.
/// Also returns the app's bundle id when its Info.plist has one.
pub fn prepare_install(path: &Path) -> Result<(Dictionary, Vec<u8>, Option<String>)> {
    let is_dir = std::fs::metadata(path)
        .map_err(|e| Error::msg(format!("{}: {e}", path.display())))?
        .is_dir();
    let base = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let (entries, total) = if is_dir {
        app_entries(path)?
    } else {
        ipa_entries(path)?
    };
    let bundle_id = entries
        .iter()
        .find(|e| {
            e.name == "Info.plist"
                || (e.name.starts_with("Payload/")
                    && e.name.ends_with(".app/Info.plist")
                    && e.name.matches('/').count() == 2)
        })
        .and_then(|e| plist::from_bytes::<Dictionary>(e.data.as_deref()?).ok())
        .and_then(|d| d.get("CFBundleIdentifier")?.as_string().map(String::from));
    let name = if is_dir { format!("{base}.ipa") } else { base };
    Ok((
        init_transfer(&name),
        zip_stream(&entries, total)?,
        bundle_id,
    ))
}

pub fn zip_conduit_install(
    s: &mut (impl Read + Write),
    init: &Dictionary,
    stream: &[u8],
) -> Result<()> {
    write_plist(s, init)?;
    s.write_all(stream)?;
    s.flush()?;
    crate::debug!("zip stream sent", "bytes" => stream.len());
    loop {
        let r = read_plist(s)?;
        if r.get("Status").and_then(|v| v.as_string()) == Some("DataComplete") {
            return Ok(());
        }
        let Some(p) = r.get("InstallProgressDict").and_then(|v| v.as_dictionary()) else {
            return bail(format!(
                "invalid progressUpdate, missing InstallProgressDict field:+{r:?}"
            ));
        };
        if let Some(e) = p.get("Error").and_then(|v| v.as_string()) {
            let desc = p
                .get("ErrorDescription")
                .and_then(|v| v.as_string())
                .unwrap_or("");
            if e == "ApplicationVerificationFailed" {
                return bail(format!(
                    "your app is not properly signed for this device, check your codesigning and provisioningprofile. original error: '{e}' errorDescription:'{desc}'"
                ));
            }
            return bail(format!(
                "failed installing: '{e}' errorDescription:'{desc}'"
            ));
        }
        crate::debug!("installing",
            "status" => p.get("Status").and_then(|v| v.as_string()).unwrap_or(""),
            "percentComplete" => p.get("PercentComplete").and_then(|v| v.as_unsigned_integer()).unwrap_or(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(d: &Dictionary) -> Vec<u8> {
        let mut v = vec![];
        write_plist(&mut v, d).unwrap();
        v
    }

    #[test]
    fn browse_happy_path() {
        let app = |id: &str| plist::Value::from(dict(&[("CFBundleIdentifier", id.into())]));
        let mut input = frame(&dict(&[
            ("CurrentAmount", 1.into()),
            ("CurrentList", vec![app("a.b.c")].into()),
            ("Status", "BrowsingApplications".into()),
        ]));
        input.extend(frame(&dict(&[
            ("CurrentAmount", 1.into()),
            ("CurrentList", vec![app("d.e.f")].into()),
            ("Status", "Complete".into()),
        ])));
        let apps = read_browse(&mut &input[..]).unwrap();
        let ids: Vec<_> = apps
            .iter()
            .map(|a| a["CFBundleIdentifier"].as_string().unwrap())
            .collect();
        assert_eq!(ids, ["a.b.c", "d.e.f"]);
    }

    #[test]
    fn browse_errors() {
        let input = frame(&dict(&[
            ("CurrentAmount", (MAX_BROWSE_ENTRIES + 1).into()),
            ("Status", "x".into()),
        ]));
        assert!(
            read_browse(&mut &input[..])
                .unwrap_err()
                .0
                .contains("exceeding limit")
        );
        assert!(read_browse(&mut &[0u8, 0, 0, 9, 1, 2][..]).is_err());
        let mut garbage = vec![0, 0, 0, 4];
        garbage.extend(b"zzzz");
        assert!(read_browse(&mut &garbage[..]).is_err());
    }

    #[test]
    fn browse_request_options() {
        let r = browse_request("User", true);
        let o = r["ClientOptions"].as_dictionary().unwrap();
        assert_eq!(o["ApplicationType"].as_string(), Some("User"));
        assert_eq!(o["ShowLaunchProhibitedApps"].as_boolean(), Some(true));
        assert!(
            browse_request("", false)["ClientOptions"]
                .as_dictionary()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn install_reads_the_bundle_id() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("rxc-bundle-id-{}", std::process::id()));
        let app = dir.join("X.app");
        std::fs::create_dir_all(&app).unwrap();
        let mut info = vec![];
        plist::to_writer_xml(
            &mut info,
            &dict(&[("CFBundleIdentifier", "com.example.x".into())]),
        )
        .unwrap();
        std::fs::write(app.join("Info.plist"), &info).unwrap();
        assert_eq!(
            prepare_install(&app).unwrap().2.as_deref(),
            Some("com.example.x")
        );

        let ipa = dir.join("X.ipa");
        let mut w = zip::ZipWriter::new(std::fs::File::create(&ipa).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file("Payload/X.app/PlugIns/E.appex/Info.plist", opts)
            .unwrap();
        w.write_all(b"not the app").unwrap();
        w.start_file("Payload/X.app/Info.plist", opts).unwrap();
        w.write_all(&info).unwrap();
        w.finish().unwrap();
        assert_eq!(
            prepare_install(&ipa).unwrap().2.as_deref(),
            Some("com.example.x")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn zip_stream_layout() {
        let dir = std::env::temp_dir().join(format!("rxc-zip-test-{}", std::process::id()));
        let app = dir.join("X.app");
        std::fs::create_dir_all(app.join("sub")).unwrap();
        std::fs::write(app.join("Info.plist"), b"hello").unwrap();
        std::fs::write(app.join("sub/b"), b"").unwrap();
        let (entries, _) = app_entries(&app).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(
            names,
            [
                format!("{}/", app.display()),
                "Info.plist".into(),
                "sub/".into(),
                "sub/b".into()
            ]
        );
        let z = zip_stream(&entries, 5).unwrap();
        assert_eq!(&z[..4], &[0x50, 0x4b, 0x03, 0x04]);
        assert_eq!(&z[z.len() - 4..], &CENTRAL_DIRECTORY_HEADER);
        let at = z.windows(10).position(|w| w == b"Info.plist").unwrap();
        // crc32 of "hello" sits 16 bytes into the local header, which starts 30 bytes before the name
        assert_eq!(
            u32::from_le_bytes(z[at - 16..at - 12].try_into().unwrap()),
            crc32fast::hash(b"hello")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
