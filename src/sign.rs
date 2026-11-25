//! `ios sign app`: re-signs an .app or .ipa with a .p12 identity and a provisioning profile.
//!
//! The signature is laid out the way Xcode signs for iOS 17+: one SHA-256 code directory with
//! 16 KiB pages, requirements, XML and DER entitlements, and a CMS signature carrying Apple's
//! cdhash attributes. Nested bundles and loose Mach-O files are signed inside-out, each bundle's
//! resources sealed in `_CodeSignature/CodeResources`.

use crate::p12;
use crate::util::{Error, Result, bail};
use plist::{Dictionary, Value};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, digest};
use rxc_sign::{PAGE, PAGE_BITS, blob, entitlement_blobs, entitlements_for, parse_profile};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const BUNDLE_EXTENSIONS: &[&str] = &["app", "appex", "framework", "xctest"];

pub struct Signer {
    key: Key,
    cert: Vec<u8>,
    common_name: String,
    team: String,
}

/// What makes the CMS signatures: the p12's key, or whoever holds it.
enum Key {
    Local(Box<ring::signature::RsaKeyPair>),
    Remote(Box<Cms>),
}

type Cms = dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync;

impl Signer {
    pub fn new(p12: &[u8], password: &str) -> Result<Signer> {
        let id = p12::load(p12, password)?;
        Signer::with(Key::Local(Box::new(id.key)), id.cert)
    }

    /// A signer without the private key: the certificate is the one the profile lists, and `cms`
    /// turns each code directory into the DER CMS signature over it, as the key holder does with
    /// [`rxc_sign::signed_attrs`] and [`rxc_sign::cms`].
    pub fn remote(
        profile: &[u8],
        cms: impl Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync + 'static,
    ) -> Result<Signer> {
        let cert = rxc_sign::profile_cert(&parse_profile(profile)?)?;
        Signer::with(Key::Remote(Box::new(cms)), cert)
    }

    fn with(key: Key, cert: Vec<u8>) -> Result<Signer> {
        let (common_name, team) = rxc_sign::subject(&cert)?;
        Ok(Signer {
            common_name,
            team,
            key,
            cert,
        })
    }
}

/// `App.ipa` -> `App-signed.ipa`.
pub fn default_output(path: &Path) -> PathBuf {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let name = match path.extension() {
        Some(e) => format!("{stem}-signed.{}", e.to_string_lossy()),
        None => format!("{stem}-signed"),
    };
    path.with_file_name(name)
}

/// Signs `path` (.app or .ipa) into `output`, an .ipa when its name ends in .ipa, returning the
/// bundle id it was signed for.
pub fn sign_app(
    path: &Path,
    output: &Path,
    signer: &Signer,
    profile: &[u8],
    bundle_id: Option<&str>,
) -> Result<String> {
    let profile_plist = parse_profile(profile)?;
    let is_ipa = |p: &Path| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("ipa"));
    if output.exists() {
        let same = path.canonicalize().ok() == output.canonicalize().ok();
        let replaceable = is_ipa(output) || output.extension().is_some_and(|e| e == "app");
        if same || !replaceable {
            return bail(format!("{} already exists", output.display()));
        }
        if output.is_dir() {
            std::fs::remove_dir_all(output)?;
        } else {
            std::fs::remove_file(output)?;
        }
    }
    let prov = Provision {
        signer,
        profile: &profile_plist,
        raw: profile,
        rename: None,
    };
    if !is_ipa(path) && !is_ipa(output) {
        copy_tree(path, output)?;
        let result = prepare(output, &prov, bundle_id);
        if result.is_err() {
            let _ = std::fs::remove_dir_all(output);
        }
        return result;
    }
    // one folder per call: a server may sign several apps at once
    static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let work = std::env::temp_dir().join(format!("rxc-sign-{}-{call}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let staged = if is_ipa(path) {
        crate::util::unzip(path, &work).and_then(|_| find_payload_app(&work))
    } else {
        let app = path.canonicalize()?;
        let app = work
            .join("Payload")
            .join(app.file_name().unwrap_or_default());
        copy_tree(path, &app).map(|_| app)
    };
    let result = staged
        .and_then(|app| prepare(&app, &prov, bundle_id))
        .and_then(|bundle| zip_dir(&work, output).map(|_| bundle));
    let _ = std::fs::remove_dir_all(&work);
    result
}

/// The identity and profile an app is signed with, and the bundle id rename `--bundle-id` asks
/// for (old, new), which the apps and app extensions nested in it follow.
#[derive(Clone)]
struct Provision<'a> {
    signer: &'a Signer,
    profile: &'a Dictionary,
    raw: &'a [u8],
    rename: Option<(String, String)>,
}

/// Sets the bundle id, embeds the profile and signs the staged bundle in place; `bundle_id`
/// renames it, and nested apps and extensions keep the new id as their prefix.
fn prepare(app: &Path, prov: &Provision, bundle_id: Option<&str>) -> Result<String> {
    let info_path = app.join("Info.plist");
    let mut info = read_plist(&info_path)?;
    let current = info
        .get("CFBundleIdentifier")
        .and_then(Value::as_string)
        .ok_or_else(|| {
            Error::msg(format!(
                "{}: Info.plist has no CFBundleIdentifier",
                app.display()
            ))
        })?
        .to_string();
    let mut prov = prov.clone();
    if let Some(b) = bundle_id {
        prov.rename = Some((current.clone(), b.to_string()));
    }
    let renamed = |id: &str| match &prov.rename {
        Some((old, new)) if id == old || id.starts_with(&format!("{old}.")) => {
            Some(format!("{new}{}", &id[old.len()..]))
        }
        _ => None,
    };
    let bundle = renamed(&current).unwrap_or_else(|| current.clone());
    // the ids naming other bundles move too: a Watch app's iPhone app, a WatchKit extension's
    // Watch app
    let mut changed = false;
    for key in ["CFBundleIdentifier", "WKCompanionAppBundleIdentifier"] {
        if let Some(id) = info.get(key).and_then(Value::as_string).and_then(renamed) {
            info.insert(key.into(), id.into());
            changed = true;
        }
    }
    if let Some(attrs) = info
        .get_mut("NSExtension")
        .and_then(Value::as_dictionary_mut)
        .and_then(|e| e.get_mut("NSExtensionAttributes"))
        .and_then(Value::as_dictionary_mut)
        && let Some(id) = attrs
            .get("WKAppBundleIdentifier")
            .and_then(Value::as_string)
            .and_then(renamed)
    {
        attrs.insert("WKAppBundleIdentifier".into(), id.into());
        changed = true;
    }
    if changed {
        Value::Dictionary(info).to_file_binary(&info_path)?;
    }
    let entitlements =
        entitlements_for(prov.profile, &prov.signer.cert, &bundle, SystemTime::now())?;
    std::fs::write(app.join("embedded.mobileprovision"), prov.raw)?;
    sign_bundle(app, Some(prov.signer), Some(&entitlements), Some(&prov))?;
    Ok(bundle)
}

/// Signs everything nested in `dir` inside-out, seals its resources, then signs its executable.
/// `signer` None makes an ad-hoc signature (tests check those with Apple's codesign). With `prov`,
/// nested apps and app extensions are provisioned like the app.
fn sign_bundle(
    dir: &Path,
    signer: Option<&Signer>,
    entitlements: Option<&Dictionary>,
    prov: Option<&Provision>,
) -> Result<()> {
    let info_bytes = std::fs::read(dir.join("Info.plist"))?;
    let info = read_plist(&dir.join("Info.plist"))?;
    let field = |k: &str| {
        info.get(k)
            .and_then(Value::as_string)
            .ok_or_else(|| Error::msg(format!("{}: Info.plist has no {k}", dir.display())))
    };
    let (exe, ident) = (field("CFBundleExecutable")?, field("CFBundleIdentifier")?);
    sign_nested(dir, &dir.join(exe), signer, prov)?;
    let resources = code_resources(dir, exe)?;
    std::fs::create_dir_all(dir.join("_CodeSignature"))?;
    std::fs::write(dir.join("_CodeSignature/CodeResources"), &resources)?;
    sign_file(
        &dir.join(exe),
        &Code {
            ident,
            signer,
            info_plist: Some(&info_bytes),
            resources: Some(&resources),
            entitlements,
        },
    )
}

fn sign_nested(
    dir: &Path,
    main_exe: &Path,
    signer: Option<&Signer>,
    prov: Option<&Provision>,
) -> Result<()> {
    for p in sorted_entries(dir)? {
        let ft = std::fs::symlink_metadata(&p)?.file_type();
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or_default();
        if ft.is_dir() {
            if ext == "dSYM" {
                continue;
            } else if BUNDLE_EXTENSIONS.contains(&ext) && p.join("Info.plist").exists() {
                match prov {
                    // extensions and the apps in Watch/ and AppClips/ need a profile of their own
                    Some(prov) if ext == "appex" || ext == "app" => {
                        prepare(&p, prov, None)?;
                    }
                    _ => sign_bundle(&p, signer, None, None)?,
                }
            } else {
                sign_nested(&p, main_exe, signer, prov)?;
            }
        } else if ft.is_file() && p != main_exe && is_macho(&p)? {
            let stem = p.file_stem().unwrap_or_default().to_string_lossy();
            sign_file(
                &p,
                &Code {
                    ident: &stem,
                    signer,
                    info_plist: None,
                    resources: None,
                    entitlements: None,
                },
            )?;
        }
    }
    Ok(())
}

fn is_macho(p: &Path) -> Result<bool> {
    use std::io::Read;
    let mut head = [0u8; 8];
    let n = std::fs::File::open(p)?.read(&mut head)?;
    Ok(n == 8
        && (head[..4] == [0xcf, 0xfa, 0xed, 0xfe]
            // CAFEBABE is also Java's magic; a fat header has a small arch count instead of a version
            || (head[..4] == [0xca, 0xfe, 0xba, 0xbe] && u32::from_be_bytes([head[4], head[5], head[6], head[7]]) < 20)))
}

/// What goes into one Mach-O's signature besides its code.
struct Code<'a> {
    ident: &'a str,
    signer: Option<&'a Signer>,
    info_plist: Option<&'a [u8]>,
    resources: Option<&'a [u8]>,
    entitlements: Option<&'a Dictionary>,
}

fn sign_file(path: &Path, c: &Code) -> Result<()> {
    let data = std::fs::read(path)?;
    let signed =
        sign_macho(&data, c).map_err(|e| Error::msg(format!("{}: {e}", path.display())))?;
    Ok(std::fs::write(path, signed)?)
}

fn sign_macho(data: &[u8], c: &Code) -> Result<Vec<u8>> {
    if !data.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        return sign_thin(data, c);
    }
    let n = be32(data, 4)? as usize;
    let header = 8 + 20 * n;
    let mut slices = vec![];
    for i in 0..n {
        let a = 8 + 20 * i;
        let (off, size, align) = (
            be32(data, a + 8)? as usize,
            be32(data, a + 12)? as usize,
            be32(data, a + 16)?,
        );
        let slice = data
            .get(off..off + size)
            .filter(|_| align <= 16)
            .ok_or_else(|| Error::msg("malformed fat header"))?;
        slices.push((a, sign_thin(slice, c)?, 1usize << align));
    }
    let mut out = data
        .get(..header)
        .ok_or_else(|| Error::msg("malformed fat header"))?
        .to_vec();
    for (a, s, align) in slices {
        let off = out.len().next_multiple_of(align);
        out.resize(off, 0);
        out[a + 8..a + 12].copy_from_slice(&(off as u32).to_be_bytes());
        out[a + 12..a + 16].copy_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend(s);
    }
    Ok(out)
}

fn sign_thin(d: &[u8], c: &Code) -> Result<Vec<u8>> {
    if le32(d, 0)? != 0xfeedfacf {
        return bail("not a 64-bit Mach-O");
    }
    let (filetype, ncmds, cmds_end) = (le32(d, 12)?, le32(d, 16)?, 32 + le32(d, 20)? as usize);
    let (mut sig_cmd, mut linkedit, mut text) = (None, None, (0, 0));
    let mut first_section = d.len();
    let mut off = 32;
    for _ in 0..ncmds {
        let (cmd, size) = (le32(d, off)?, le32(d, off + 4)? as usize);
        if size < 8 || off + size > cmds_end {
            return bail("malformed load commands");
        }
        if cmd == 0x19 {
            for i in 0..le32(d, off + 64)? as usize {
                match le32(d, off + 72 + 80 * i + 48)? as usize {
                    0 => {} // zero-fill
                    o => first_section = first_section.min(o),
                }
            }
        }
        match cmd {
            0x19 if d.get(off + 8..off + 15) == Some(b"__TEXT\0") => {
                text = (le64(d, off + 40)?, le64(d, off + 48)?)
            }
            0x19 if d.get(off + 8..off + 19) == Some(b"__LINKEDIT\0") => linkedit = Some(off),
            0x1d => sig_cmd = Some(off),
            // LC_ENCRYPTION_INFO_64 with a cryptid
            0x2c if le32(d, off + 16)? != 0 => {
                return bail(
                    "encrypted with FairPlay (an App Store or TestFlight build); re-signing needs a decrypted build",
                );
            }
            _ => {}
        }
        off += size;
    }
    let linkedit = linkedit.ok_or_else(|| Error::msg("no __LINKEDIT segment"))?;
    let unsigned;
    let (d, sig_cmd) = match sig_cmd {
        Some(o) => (d, o),
        None => {
            // append LC_CODE_SIGNATURE in the padding before the first section; the signature
            // goes at the end of the file, which __LINKEDIT ends at
            if cmds_end + 16 > first_section {
                return bail("no room for a code signature load command");
            }
            let mut v = d.to_vec();
            v.resize(d.len().next_multiple_of(16), 0);
            let lc = [0x1d, 16, v.len() as u32, 0].map(u32::to_le_bytes).concat();
            v[cmds_end..cmds_end + 16].copy_from_slice(&lc);
            v[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
            v[20..24].copy_from_slice(&((cmds_end - 32 + 16) as u32).to_le_bytes());
            unsigned = v;
            (&unsigned[..], cmds_end)
        }
    };
    let limit = le32(d, sig_cmd + 8)? as usize;
    let linkedit_off = le64(d, linkedit + 40)? as usize;
    if limit > d.len() || linkedit_off > limit {
        return bail("code signature outside the file");
    }

    let team = c.signer.map(|s| s.team.as_str());
    let requirements = match c.signer {
        Some(s) => rxc_sign::requirements(c.ident, &s.common_name),
        None => blob(0xfade0c01, &0u32.to_be_bytes()),
    };
    let ents = c.entitlements.map(entitlement_blobs).transpose()?;
    let n_special = match (&ents, c.info_plist) {
        (Some(_), _) => 7,
        (None, Some(_)) => 3,
        (None, None) => 2,
    };
    let cd_len = 88
        + c.ident.len()
        + 1
        + team.map_or(0, |t| t.len() + 1)
        + 32 * (n_special + limit.div_ceil(PAGE));
    let cms_room = c.signer.map_or(8, |s| {
        s.cert.len() + rxc_sign::WWDR_G3.len() + rxc_sign::APPLE_ROOT_CA.len() + 2048
    });
    let ents_len = ents.as_ref().map_or(0, |(x, d)| x.len() + d.len());
    let blob_count = if ents.is_some() { 5 } else { 3 };
    let room = (12 + 8 * blob_count + cd_len + requirements.len() + ents_len + cms_room)
        .next_multiple_of(16);

    // the new signature size and __LINKEDIT extent are part of the hashed header
    let mut out = d[..limit].to_vec();
    out[sig_cmd + 12..sig_cmd + 16].copy_from_slice(&(room as u32).to_le_bytes());
    let filesize = (limit + room - linkedit_off) as u64;
    let vmsize = le64(d, linkedit + 32)?.max(filesize.next_multiple_of(PAGE as u64));
    out[linkedit + 32..linkedit + 40].copy_from_slice(&vmsize.to_le_bytes());
    out[linkedit + 48..linkedit + 56].copy_from_slice(&filesize.to_le_bytes());

    let hash = |b: &[u8]| -> [u8; 32] { digest(&SHA256, b).as_ref().try_into().unwrap() };
    let mut special = vec![[0u8; 32]; n_special];
    if let Some(info) = c.info_plist {
        special[0] = hash(info);
    }
    special[1] = hash(&requirements);
    if let Some(res) = c.resources {
        special[2] = hash(res);
    }
    if let Some((xml, der)) = &ents {
        special[4] = hash(xml);
        special[6] = hash(der);
    }
    let get_task_allow = c
        .entitlements
        .and_then(|e| e.get("get-task-allow"))
        .and_then(Value::as_boolean)
        == Some(true);
    let exec_flags = match filetype {
        2 if get_task_allow => 0x11, // main binary, allow unsigned (debugging)
        2 => 0x1,
        _ => 0,
    };
    let mut cd = vec![];
    for v in [
        0xfade0c02,
        cd_len,
        0x20400,
        if c.signer.is_some() { 0 } else { 2 }, // CS_ADHOC
        cd_len - 32 * limit.div_ceil(PAGE),
        88,
        n_special,
        limit.div_ceil(PAGE),
        limit,
    ] {
        cd.extend((v as u32).to_be_bytes());
    }
    cd.extend([32, 2, 0, PAGE_BITS]); // hash size, SHA-256, platform, page size
    let team_off = team.map_or(0, |_| 88 + c.ident.len() + 1) as u32;
    for v in [0u32, 0, team_off, 0] {
        cd.extend(v.to_be_bytes()); // spare2, scatter, team offset, spare3
    }
    for v in [0, text.0, text.1, exec_flags] {
        cd.extend(v.to_be_bytes()); // code limit 64, exec segment base, limit, flags
    }
    cd.extend(c.ident.as_bytes());
    cd.push(0);
    if let Some(t) = team {
        cd.extend(t.as_bytes());
        cd.push(0);
    }
    for h in special.iter().rev() {
        cd.extend(h);
    }
    for page in out.chunks(PAGE) {
        cd.extend(hash(page));
    }
    debug_assert_eq!(cd.len(), cd_len);

    let cms = match c.signer {
        Some(s) => blob(0xfade0b01, &cms(s, &cd)?),
        None => blob(0xfade0b01, &[]),
    };
    let mut blobs: Vec<(u32, &[u8])> = vec![(0, &cd), (2, &requirements)];
    if let Some((xml, der)) = &ents {
        blobs.extend([(5, &xml[..]), (7, &der[..])]);
    }
    blobs.push((0x10000, &cms));
    let total = 12 + 8 * blobs.len() + blobs.iter().map(|b| b.1.len()).sum::<usize>();
    if total > room {
        return bail("signature larger than the space reserved for it");
    }
    out.extend(0xfade0cc0u32.to_be_bytes());
    out.extend((total as u32).to_be_bytes());
    out.extend((blobs.len() as u32).to_be_bytes());
    let mut at = 12 + 8 * blobs.len();
    for (slot, b) in &blobs {
        out.extend(slot.to_be_bytes());
        out.extend((at as u32).to_be_bytes());
        at += b.len();
    }
    for (_, b) in &blobs {
        out.extend(*b);
    }
    out.resize(limit + room, 0);
    Ok(out)
}

/// Detached CMS SignedData over the code directory, as Xcode makes it.
fn cms(s: &Signer, cd: &[u8]) -> Result<Vec<u8>> {
    let key = match &s.key {
        Key::Remote(cms) => return cms(cd),
        Key::Local(key) => key,
    };
    let attrs = rxc_sign::cms_attrs(cd, SystemTime::now())?;
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        &attrs,
        &mut sig,
    )
    .map_err(|_| Error::msg("RSA signing failed"))?;
    Ok(rxc_sign::signed_data(&s.cert, &attrs, &sig)?)
}

/// `_CodeSignature/CodeResources` with Xcode's iOS rules: every file but the executable, SHA-1
/// in `files`, SHA-256 in `files2`.
fn code_resources(bundle: &Path, exe: &str) -> Result<Vec<u8>> {
    let (mut files, mut files2) = (Dictionary::new(), Dictionary::new());
    for rel in tree(bundle)? {
        let name = rel.rsplit('/').next().unwrap_or_default();
        if rel == exe
            || rel == "_CodeSignature/CodeResources"
            || name == ".DS_Store"
            || rel.ends_with(".lproj/locversion.plist")
        {
            continue;
        }
        let optional = rel.contains(".lproj/") && !rel.starts_with("Base.lproj/");
        let p = bundle.join(&rel);
        let mut entry = Dictionary::new();
        if std::fs::symlink_metadata(&p)?.file_type().is_symlink() {
            let target = std::fs::read_link(&p)?.to_string_lossy().into_owned();
            entry.insert("symlink".into(), target.into());
        } else {
            let data = std::fs::read(&p)?;
            let sha1 = Value::Data(digest(&SHA1, &data).as_ref().to_vec());
            files.insert(
                rel.clone(),
                match optional {
                    true => Value::Dictionary(Dictionary::from_iter([
                        ("hash".to_string(), sha1),
                        ("optional".to_string(), true.into()),
                    ])),
                    false => sha1,
                },
            );
            entry.insert(
                "hash2".into(),
                Value::Data(digest(&SHA256, &data).as_ref().to_vec()),
            );
        }
        if optional {
            entry.insert("optional".into(), true.into());
        }
        if rel != "Info.plist" && rel != "PkgInfo" {
            files2.insert(rel, entry.into());
        }
    }
    let rule = |omit: bool, optional: bool, weight: f64| {
        let mut d = Dictionary::new();
        if omit {
            d.insert("omit".into(), true.into());
        }
        if optional {
            d.insert("optional".into(), true.into());
        }
        d.insert("weight".into(), Value::Real(weight));
        Value::Dictionary(d)
    };
    let common = [
        ("^.*", Value::Boolean(true)),
        ("^.*\\.lproj/", rule(false, true, 1000.)),
        ("^.*\\.lproj/locversion.plist$", rule(true, false, 1100.)),
        ("^Base\\.lproj/", rule(false, false, 1010.)),
    ];
    let rules = common
        .iter()
        .cloned()
        .chain([("^version.plist$", Value::Boolean(true))]);
    let rules2 = common.iter().cloned().chain([
        (".*\\.dSYM($|/)", rule(false, false, 11.)),
        ("^(.*/)?\\.DS_Store$", rule(true, false, 2000.)),
        ("^Info\\.plist$", rule(true, false, 20.)),
        ("^PkgInfo$", rule(true, false, 20.)),
        ("^embedded\\.provisionprofile$", rule(false, false, 20.)),
        ("^version\\.plist$", rule(false, false, 20.)),
    ]);
    fn dict<'a>(it: impl Iterator<Item = (&'a str, Value)>) -> Value {
        Value::Dictionary(it.map(|(k, v)| (k.to_string(), v)).collect())
    }
    let mut out = vec![];
    Value::Dictionary(Dictionary::from_iter([
        ("files".to_string(), Value::Dictionary(files)),
        ("files2".to_string(), Value::Dictionary(files2)),
        ("rules".to_string(), dict(rules)),
        ("rules2".to_string(), dict(rules2)),
    ]))
    .to_writer_xml(&mut out)?;
    Ok(out)
}

fn read_plist(p: &Path) -> Result<Dictionary> {
    Value::from_file(p)?
        .into_dictionary()
        .ok_or_else(|| Error::msg(format!("{}: not a dictionary", p.display())))
}

fn sorted_entries(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    v.sort();
    Ok(v)
}

/// Relative paths of every file and symlink under `root`, sorted.
fn tree(root: &Path) -> Result<Vec<String>> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
        for p in sorted_entries(dir)? {
            if std::fs::symlink_metadata(&p)?.is_dir() {
                walk(root, &p, out)?;
            } else if let Ok(rel) = p.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }
    let mut out = vec![];
    walk(root, root, &mut out)?;
    Ok(out)
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    if !src.is_dir() {
        return bail(format!("{} is not an .app folder or .ipa", src.display()));
    }
    std::fs::create_dir_all(dst)?;
    for p in sorted_entries(src)? {
        let to = dst.join(p.file_name().unwrap_or_default());
        let ft = std::fs::symlink_metadata(&p)?.file_type();
        if ft.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&p)?, &to)?;
        } else if ft.is_dir() {
            copy_tree(&p, &to)?;
        } else {
            std::fs::copy(&p, &to)?;
        }
    }
    Ok(())
}

fn find_payload_app(dir: &Path) -> Result<PathBuf> {
    sorted_entries(&dir.join("Payload"))
        .ok()
        .and_then(|v| {
            v.into_iter()
                .find(|p| p.extension().is_some_and(|e| e == "app"))
        })
        .ok_or_else(|| Error::msg("the .ipa has no Payload/*.app"))
}

fn zip_dir(src: &Path, out: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let zerr = |e: zip::result::ZipError| Error::msg(format!("{}: {e}", out.display()));
    let mut w = zip::ZipWriter::new(std::fs::File::create(out)?);
    for rel in tree(src)? {
        let p = src.join(&rel);
        let meta = std::fs::symlink_metadata(&p)?;
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(meta.permissions().mode());
        if meta.file_type().is_symlink() {
            w.add_symlink(rel, std::fs::read_link(&p)?.to_string_lossy(), opts)
                .map_err(zerr)?;
        } else {
            w.start_file(rel, opts).map_err(zerr)?;
            std::io::copy(&mut std::fs::File::open(&p)?, &mut w)?;
        }
    }
    w.finish().map_err(zerr)?;
    Ok(())
}

fn be32(d: &[u8], at: usize) -> Result<u32> {
    d.get(at..at + 4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .ok_or_else(|| Error::msg("truncated Mach-O"))
}

fn le32(d: &[u8], at: usize) -> Result<u32> {
    d.get(at..at + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| Error::msg("truncated Mach-O"))
}

fn le64(d: &[u8], at: usize) -> Result<u64> {
    d.get(at..at + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| Error::msg("truncated Mach-O"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rxc_sign::der::{self, Der, oid};
    use rxc_sign::{APPLE_ROOT_CA, WWDR_G3, der_entitlements};
    use std::fs;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sign");

    fn signer() -> Signer {
        Signer::new(
            &fs::read(format!("{FIXTURES}/pbes2-aes256.p12")).unwrap(),
            "test",
        )
        .unwrap()
    }

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rxc-sign-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_info(dir: &Path, exe: &str, id: &str) {
        let d = Dictionary::from_iter([
            ("CFBundleExecutable".to_string(), Value::from(exe)),
            ("CFBundleIdentifier".to_string(), Value::from(id)),
        ]);
        Value::Dictionary(d)
            .to_file_binary(dir.join("Info.plist"))
            .unwrap();
    }

    /// T.app: a fat executable, resources, a localization, a loose dylib and a nested test
    /// bundle; the fixture binaries come from clang without any signature.
    fn bundle(root: &Path) -> PathBuf {
        let app = root.join("T.app");
        for d in ["en.lproj", "Frameworks", "PlugIns/P.xctest"] {
            fs::create_dir_all(app.join(d)).unwrap();
        }
        fs::copy(format!("{FIXTURES}/hello"), app.join("T")).unwrap();
        fs::copy(format!("{FIXTURES}/hello"), app.join("PlugIns/P.xctest/P")).unwrap();
        fs::copy(
            format!("{FIXTURES}/libhello.dylib"),
            app.join("Frameworks/libhello.dylib"),
        )
        .unwrap();
        fs::write(app.join("PkgInfo"), "APPL????").unwrap();
        fs::write(app.join("a.txt"), "resource").unwrap();
        fs::write(app.join("en.lproj/L.strings"), "\"k\" = \"v\";").unwrap();
        write_info(&app, "T", "com.example.app");
        write_info(&app.join("PlugIns/P.xctest"), "P", "com.example.app.tests");
        app
    }

    fn profile(app_id: &str, expires_in: i64, cert: &[u8]) -> Vec<u8> {
        let expiry = std::time::SystemTime::now()
            .checked_add(std::time::Duration::from_secs(expires_in.max(0) as u64))
            .unwrap()
            - std::time::Duration::from_secs((-expires_in).max(0) as u64);
        let ent = Dictionary::from_iter([
            ("application-identifier".to_string(), Value::from(app_id)),
            (
                "com.apple.developer.team-identifier".to_string(),
                Value::from("TESTTEAM01"),
            ),
            ("get-task-allow".to_string(), Value::Boolean(true)),
            (
                "keychain-access-groups".to_string(),
                Value::Array(vec![Value::from("TESTTEAM01.*")]),
            ),
        ]);
        let p = Dictionary::from_iter([
            ("ExpirationDate".to_string(), Value::Date(expiry.into())),
            (
                "DeveloperCertificates".to_string(),
                Value::Array(vec![Value::Data(cert.to_vec())]),
            ),
            ("Entitlements".to_string(), Value::Dictionary(ent)),
        ]);
        // a profile is this plist in a CMS envelope; the envelope is not read
        let mut out = b"0\x80\x06\x09junk".to_vec();
        Value::Dictionary(p).to_writer_xml(&mut out).unwrap();
        out.extend(b"\0\0trailer");
        out
    }

    struct Parsed {
        cd: Vec<u8>,
        blobs: Vec<(u32, Vec<u8>)>,
    }

    /// Every slice's signature, with each page and special slot hash checked against the file.
    fn check(path: &Path, special: &[(usize, Vec<u8>)]) -> Vec<Parsed> {
        let data = fs::read(path).unwrap();
        let slices: Vec<&[u8]> = if data.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
            (0..be32(&data, 4).unwrap() as usize)
                .map(|i| {
                    let a = 8 + 20 * i;
                    let (o, n) = (be32(&data, a + 8).unwrap(), be32(&data, a + 12).unwrap());
                    &data[o as usize..(o + n) as usize]
                })
                .collect()
        } else {
            vec![&data]
        };
        slices
            .into_iter()
            .map(|d| {
                let mut off = 32;
                let sig = loop {
                    if le32(d, off).unwrap() == 0x1d {
                        break off;
                    }
                    off += le32(d, off + 4).unwrap() as usize;
                };
                let (so, size) = (
                    le32(d, sig + 8).unwrap() as usize,
                    le32(d, sig + 12).unwrap(),
                );
                assert_eq!(so + size as usize, d.len(), "signature ends the slice");
                let sb = &d[so..];
                assert_eq!(be32(sb, 0).unwrap(), 0xfade0cc0);
                let blobs: Vec<(u32, Vec<u8>)> = (0..be32(sb, 8).unwrap() as usize)
                    .map(|i| {
                        let (t, o) = (be32(sb, 12 + 8 * i).unwrap(), be32(sb, 16 + 8 * i).unwrap());
                        let o = o as usize;
                        (t, sb[o..o + be32(sb, o + 4).unwrap() as usize].to_vec())
                    })
                    .collect();
                let cd = blobs[0].1.clone();
                let (hash_off, n_special, n_code, limit) = (
                    be32(&cd, 16).unwrap() as usize,
                    be32(&cd, 24).unwrap() as usize,
                    be32(&cd, 28).unwrap() as usize,
                    be32(&cd, 32).unwrap() as usize,
                );
                assert_eq!(limit, so);
                assert_eq!(cd[39], PAGE_BITS);
                for (i, page) in d[..limit].chunks(PAGE).enumerate() {
                    assert_eq!(
                        &cd[hash_off + 32 * i..hash_off + 32 * i + 32],
                        digest(&SHA256, page).as_ref(),
                        "page {i}"
                    );
                }
                assert_eq!(n_code, limit.div_ceil(PAGE));
                let slot = |n: usize| &cd[hash_off - 32 * n..hash_off - 32 * (n - 1)];
                let req = &blobs.iter().find(|b| b.0 == 2).unwrap().1;
                assert_eq!(slot(2), digest(&SHA256, req).as_ref());
                for (n, content) in special {
                    assert!(*n <= n_special);
                    assert_eq!(slot(*n), digest(&SHA256, content).as_ref(), "slot {n}");
                }
                Parsed { cd, blobs }
            })
            .collect()
    }

    /// The CMS blob signs the code directory hash with the test certificate's key.
    fn check_cms(p: &Parsed) {
        let cms = &p.blobs.iter().find(|b| b.0 == 0x10000).unwrap().1[8..];
        let mut ci = Der(Der(cms).expect(0x30).unwrap());
        assert_eq!(ci.expect(0x06).unwrap(), oid::SIGNED_DATA);
        let mut sd = Der(Der(ci.expect(0xa0).unwrap()).expect(0x30).unwrap());
        sd.uint().unwrap();
        sd.next().unwrap();
        sd.next().unwrap();
        let mut certs = Der(sd.expect(0xa0).unwrap());
        let leaf = certs.raw().unwrap();
        assert_eq!(certs.raw().unwrap(), WWDR_G3);
        assert_eq!(certs.raw().unwrap(), APPLE_ROOT_CA);
        let mut si = Der(Der(sd.expect(0x31).unwrap()).expect(0x30).unwrap());
        si.uint().unwrap();
        si.next().unwrap();
        si.next().unwrap();
        let attrs = si.expect(0xa0).unwrap();
        si.next().unwrap();
        let sig = si.octets().unwrap();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            rxc_sign::parse_cert(leaf).unwrap().public_key,
        )
        .verify(&der::tlv(0x31, attrs), &sig)
        .unwrap();
        let mut a = Der(attrs);
        let mut digest_attr = None;
        while !a.is_empty() {
            let mut attr = Der(a.expect(0x30).unwrap());
            if attr.expect(0x06).unwrap() == oid::MESSAGE_DIGEST {
                digest_attr = Some(Der(attr.expect(0x31).unwrap()).octets().unwrap());
            }
        }
        assert_eq!(digest_attr.unwrap(), digest(&SHA256, &p.cd).as_ref());
    }

    #[test]
    fn signs_bundles_inside_out() {
        let root = temp("bundle");
        let app = bundle(&root);
        let s = signer();
        let mut ent = Dictionary::new();
        ent.insert("get-task-allow".into(), true.into());
        sign_bundle(&app, Some(&s), Some(&ent), None).unwrap();

        let resources = fs::read(app.join("_CodeSignature/CodeResources")).unwrap();
        let info = fs::read(app.join("Info.plist")).unwrap();
        for p in check(&app.join("T"), &[(1, info), (3, resources.clone())]) {
            let slots: Vec<u32> = p.blobs.iter().map(|b| b.0).collect();
            assert_eq!(slots, [0, 2, 5, 7, 0x10000]);
            assert_eq!(be32(&p.cd, 24).unwrap(), 7);
            assert_eq!(u64::from_be_bytes(p.cd[80..88].try_into().unwrap()), 0x11);
            check_cms(&p);
        }
        let nested = app.join("PlugIns/P.xctest");
        let nested_res = fs::read(nested.join("_CodeSignature/CodeResources")).unwrap();
        for p in check(&nested.join("P"), &[(3, nested_res)]) {
            assert_eq!(be32(&p.cd, 24).unwrap(), 3);
            check_cms(&p);
        }
        for p in check(&app.join("Frameworks/libhello.dylib"), &[]) {
            assert_eq!(be32(&p.cd, 24).unwrap(), 2);
            assert!(p.cd.windows(9).any(|w| w == b"libhello\0"));
        }

        let res = Value::from_reader(std::io::Cursor::new(&resources)).unwrap();
        let res = res.as_dictionary().unwrap();
        let files2 = res["files2"].as_dictionary().unwrap();
        let keys: Vec<&str> = files2.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "Frameworks/libhello.dylib",
                "PlugIns/P.xctest/Info.plist",
                "PlugIns/P.xctest/P",
                "PlugIns/P.xctest/_CodeSignature/CodeResources",
                "a.txt",
                "en.lproj/L.strings"
            ]
        );
        assert_eq!(
            files2["en.lproj/L.strings"].as_dictionary().unwrap()["optional"],
            Value::Boolean(true)
        );
        assert!(
            res["files"]
                .as_dictionary()
                .unwrap()
                .contains_key("Info.plist")
        );

        // re-signing an already signed bundle reuses the signature slots
        sign_bundle(&app, Some(&s), Some(&ent), None).unwrap();
        check(&app.join("T"), &[]);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn signs_app_and_ipa_for_the_profile() {
        let root = temp("app");
        let app = bundle(&root);
        let widget = app.join("PlugIns/W.appex");
        fs::create_dir_all(&widget).unwrap();
        fs::copy(format!("{FIXTURES}/hello"), widget.join("W")).unwrap();
        write_info(&widget, "W", "com.example.app.widget");
        let watch = app.join("Watch/WA.app");
        fs::create_dir_all(&watch).unwrap();
        fs::copy(format!("{FIXTURES}/hello"), watch.join("WA")).unwrap();
        write_info(&watch, "WA", "com.example.app.watchkitapp");
        let mut wi = read_plist(&watch.join("Info.plist")).unwrap();
        wi.insert(
            "WKCompanionAppBundleIdentifier".into(),
            "com.example.app".into(),
        );
        Value::Dictionary(wi)
            .to_file_binary(watch.join("Info.plist"))
            .unwrap();
        // a watchOS 2-6 WatchKit extension names its Watch app
        let wext = watch.join("PlugIns/WE.appex");
        fs::create_dir_all(&wext).unwrap();
        fs::copy(format!("{FIXTURES}/hello"), wext.join("WE")).unwrap();
        write_info(&wext, "WE", "com.example.app.watchkitapp.watchkitextension");
        let mut ei = read_plist(&wext.join("Info.plist")).unwrap();
        let attrs = Dictionary::from_iter([(
            "WKAppBundleIdentifier".to_string(),
            Value::from("com.example.app.watchkitapp"),
        )]);
        let ext = Dictionary::from_iter([(
            "NSExtensionAttributes".to_string(),
            Value::Dictionary(attrs),
        )]);
        ei.insert("NSExtension".into(), Value::Dictionary(ext));
        Value::Dictionary(ei)
            .to_file_binary(wext.join("Info.plist"))
            .unwrap();
        let s = signer();
        let cert = fs::read(format!("{FIXTURES}/cert.der")).unwrap();
        let prof = profile("TESTTEAM01.*", 3600, &cert);

        let out = root.join("Out.app");
        let id = sign_app(&app, &out, &s, &prof, Some("com.example.renamed")).unwrap();
        assert_eq!(id, "com.example.renamed");
        assert_eq!(
            fs::read(out.join("embedded.mobileprovision")).unwrap(),
            prof
        );
        let info = read_plist(&out.join("Info.plist")).unwrap();
        assert_eq!(
            info["CFBundleIdentifier"],
            Value::from("com.example.renamed")
        );
        let p = &check(&out.join("T"), &[])[0];
        let xml = &p.blobs.iter().find(|b| b.0 == 5).unwrap().1[8..];
        let ent = Value::from_reader(std::io::Cursor::new(xml)).unwrap();
        let ent = ent.as_dictionary().unwrap();
        let app_id = Value::from("TESTTEAM01.com.example.renamed");
        assert_eq!(ent["application-identifier"], app_id);
        assert_eq!(ent["keychain-access-groups"], Value::Array(vec![app_id]));
        assert!(p.cd.windows(11).any(|w| w == b"TESTTEAM01\0"));

        // the extension is provisioned like the app and follows its new id; the test bundle is not
        let w = out.join("PlugIns/W.appex");
        assert_eq!(fs::read(w.join("embedded.mobileprovision")).unwrap(), prof);
        let w_id = "com.example.renamed.widget";
        assert_eq!(
            read_plist(&w.join("Info.plist")).unwrap()["CFBundleIdentifier"],
            Value::from(w_id)
        );
        let p = &check(&w.join("W"), &[])[0];
        let xml = &p.blobs.iter().find(|b| b.0 == 5).unwrap().1[8..];
        let ent = Value::from_reader(std::io::Cursor::new(xml)).unwrap();
        assert_eq!(
            ent.as_dictionary().unwrap()["application-identifier"],
            Value::from(format!("TESTTEAM01.{w_id}"))
        );
        let wi = read_plist(&out.join("Watch/WA.app/Info.plist")).unwrap();
        assert_eq!(
            wi["CFBundleIdentifier"],
            Value::from("com.example.renamed.watchkitapp")
        );
        assert_eq!(
            wi["WKCompanionAppBundleIdentifier"],
            Value::from("com.example.renamed")
        );
        let ei = read_plist(&out.join("Watch/WA.app/PlugIns/WE.appex/Info.plist")).unwrap();
        assert_eq!(
            ei["CFBundleIdentifier"],
            Value::from("com.example.renamed.watchkitapp.watchkitextension")
        );
        assert_eq!(
            ei["NSExtension"].as_dictionary().unwrap()["NSExtensionAttributes"]
                .as_dictionary()
                .unwrap()["WKAppBundleIdentifier"],
            Value::from("com.example.renamed.watchkitapp")
        );
        let tests = out.join("PlugIns/P.xctest");
        assert!(!tests.join("embedded.mobileprovision").exists());
        assert_eq!(
            read_plist(&tests.join("Info.plist")).unwrap()["CFBundleIdentifier"],
            Value::from("com.example.app.tests")
        );

        // .ipa in, .ipa out, executables stay executable
        let ipa = root.join("T.ipa");
        let payload = root.join("ipa");
        copy_tree(&app, &payload.join("Payload/T.app")).unwrap();
        zip_dir(&payload, &ipa).unwrap();
        let signed_ipa = default_output(&ipa);
        assert_eq!(signed_ipa, root.join("T-signed.ipa"));
        sign_app(&ipa, &signed_ipa, &s, &prof, None).unwrap();
        let unpacked = root.join("unpacked");
        crate::util::unzip(&signed_ipa, &unpacked).unwrap();
        let exe = unpacked.join("Payload/T.app/T");
        check(&exe, &[]);
        // .app in, .ipa out
        let app_ipa = root.join("A.ipa");
        sign_app(&app, &app_ipa, &s, &prof, None).unwrap();
        crate::util::unzip(&app_ipa, &root.join("unpacked-app")).unwrap();
        check(&root.join("unpacked-app/Payload/T.app/T"), &[]);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&exe).unwrap().permissions().mode() & 0o111,
            0o111
        );

        // refuses what the profile does not allow
        let err = |p: &[u8], bundle: Option<&str>| {
            sign_app(&app, &root.join("X.app"), &s, p, bundle)
                .err()
                .unwrap()
                .0
        };
        assert!(
            err(&profile("TESTTEAM01.com.other", 3600, &cert), None).contains("does not cover")
        );
        assert!(err(&profile("TESTTEAM01.*", -60, &cert), None).contains("expired"));
        assert!(err(&profile("TESTTEAM01.*", 3600, b"other"), None).contains("certificate"));
        assert!(!root.join("X.app").exists());
        assert!(sign_app(&app, &app, &s, &prof, None).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn signs_through_the_key_holder() {
        let root = temp("remote");
        let app = bundle(&root);
        let cert = fs::read(format!("{FIXTURES}/cert.der")).unwrap();
        let prof = profile("TESTTEAM01.*", 3600, &cert);
        let key = p12::load(
            &fs::read(format!("{FIXTURES}/pbes2-aes256.p12")).unwrap(),
            "test",
        )
        .unwrap()
        .key;
        let cds = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let (seen, held) = (cds.clone(), prof.clone());
        // what the key holder does, with the RSA step in between
        let remote = Signer::remote(&prof, move |cd| {
            seen.lock().unwrap().push(cd.to_vec());
            let attrs = rxc_sign::signed_attrs(&held, cd, SystemTime::now())?;
            let mut sig = vec![0; key.public().modulus_len()];
            let rng = ring::rand::SystemRandom::new();
            key.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, &attrs, &mut sig)
                .unwrap();
            Ok(rxc_sign::cms(&held, &attrs, &sig)?)
        })
        .unwrap();
        let out = root.join("Out.app");
        sign_app(&app, &out, &remote, &prof, None).unwrap();
        for exe in ["T", "PlugIns/P.xctest/P", "Frameworks/libhello.dylib"] {
            check(&out.join(exe), &[]).iter().for_each(check_cms);
        }

        let cd = cds.lock().unwrap()[..]
            .iter()
            .find(|cd| be32(cd, 24).unwrap() == 7)
            .unwrap()
            .clone();
        assert!(rxc_sign::signed_attrs(&prof, &cd, SystemTime::now()).is_ok());
        let refused = |change: &dyn Fn(&mut Vec<u8>)| {
            let mut cd = cd.clone();
            change(&mut cd);
            rxc_sign::signed_attrs(&prof, &cd, SystemTime::now())
                .unwrap_err()
                .0
        };
        let team = cd.windows(10).position(|w| w == b"TESTTEAM01").unwrap();
        let ent_slot = be32(&cd, 16).unwrap() as usize - 32 * 5;
        assert!(refused(&|cd| *cd = b"bytes to sign".to_vec()).contains("not a code directory"));
        assert!(refused(&|cd| cd[team] = b'X').contains("not for team TESTTEAM01"));
        assert!(refused(&|cd| cd[ent_slot] ^= 1).contains("entitlements other than"));
        assert!(refused(&|cd| cd[15] = 2).contains("ad-hoc"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn refuses_fairplay_encrypted_binaries() {
        let fat = fs::read(format!("{FIXTURES}/hello")).unwrap();
        let (o, n) = (
            be32(&fat, 16).unwrap() as usize,
            be32(&fat, 20).unwrap() as usize,
        );
        let thin = &fat[o..o + n];
        // LC_ENCRYPTION_INFO_64 appended in the padding after the load commands
        let with_cryptid = |id: u32| {
            let mut d = thin.to_vec();
            let (ncmds, size) = (le32(&d, 16).unwrap(), le32(&d, 20).unwrap());
            let end = 32 + size as usize;
            assert!(d[end..end + 24].iter().all(|b| *b == 0));
            d[end..end + 24]
                .copy_from_slice(&[0x2c, 24, 0, 0, id, 0].map(u32::to_le_bytes).concat());
            d[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
            d[20..24].copy_from_slice(&(size + 24).to_le_bytes());
            d
        };
        let code = Code {
            ident: "hello",
            signer: None,
            info_plist: None,
            resources: None,
            entitlements: None,
        };
        let e = sign_macho(&with_cryptid(1), &code).unwrap_err();
        assert!(e.0.contains("FairPlay"), "{e}");
        assert!(sign_macho(&with_cryptid(0), &code).is_ok());
    }

    // The runner's entitlements as Xcode 27 signed them, XML and DER.
    #[test]
    fn der_entitlements_match_xcode() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>application-identifier</key><string>QVKPZD8SE7.com.argent.runner.tqvkpzd8se7.uitests.xctrunner</string>
<key>com.apple.developer.team-identifier</key><string>QVKPZD8SE7</string>
<key>get-task-allow</key><true/>
<key>keychain-access-groups</key><array><string>QVKPZD8SE7.com.argent.runner.tqvkpzd8se7.uitests.xctrunner</string></array>
</dict></plist>"#;
        let ent = Value::from_reader(std::io::Cursor::new(xml)).unwrap();
        let der = der_entitlements(ent.as_dictionary().unwrap()).unwrap();
        assert_eq!(
            crate::util::hex(&der),
            "7081fc020101b081f630540c166170706c69636174696f6e2d6964656e7469666965720c3a51564b505a44385345372e636f6d2e617267656e742e72756e6e65722e7471766b707a64387365372e756974657374732e78637472756e6e657230310c23636f6d2e6170706c652e646576656c6f7065722e7465616d2d6964656e7469666965720c0a51564b505a443853453730130c0e6765742d7461736b2d616c6c6f770101ff30560c166b6579636861696e2d6163636573732d67726f757073303c0c3a51564b505a44385345372e636f6d2e617267656e742e72756e6e65722e7471766b707a64387365372e756974657374732e78637472756e6e6572"
        );
    }

    /// Apple's codesign accepts our signatures: fully for ad-hoc, and for the test identity
    /// everything but the Apple anchor its self-signed certificate cannot have.
    #[cfg(target_os = "macos")]
    #[test]
    fn codesign_accepts_the_signatures() {
        let codesign = |args: &[&str], p: &Path| {
            let o = std::process::Command::new("codesign")
                .args(args)
                .arg(p)
                .output()
                .unwrap();
            let out = String::from_utf8_lossy(&o.stderr) + String::from_utf8_lossy(&o.stdout);
            (o.status.success(), out.into_owned())
        };
        let root = temp("codesign");
        let app = bundle(&root);
        let mut ent = Dictionary::new();
        ent.insert("get-task-allow".into(), true.into());
        sign_bundle(&app, None, Some(&ent), None).unwrap();
        let (ok, out) = codesign(&["--verify", "--deep", "--strict", "-vv"], &app);
        assert!(ok, "{out}");

        sign_bundle(&app, Some(&signer()), Some(&ent), None).unwrap();
        let (_, out) = codesign(&["--verify", "--deep", "--strict", "-vv"], &app);
        assert!(out.contains("valid on disk"), "{out}");
        assert!(
            out.contains("does not satisfy its designated Requirement"),
            "{out}"
        );
        let (_, out) = codesign(&["-d", "-r-"], &app);
        assert!(
            out.contains(concat!(
                r#"designated => identifier "com.example.app" and anchor apple generic and "#,
                r#"certificate leaf[subject.CN] = "Apple Development: rios test (TESTTEAM01)" "#,
                r#"and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */"#
            )),
            "{out}"
        );
        let (_, out) = codesign(&["-d", "-vvvv"], &app);
        for want in [
            "Authority=Apple Development: rios test (TESTTEAM01)",
            "TeamIdentifier=TESTTEAM01",
            "Info.plist entries=2",
            "Sealed Resources version=2 rules=10 files=6",
            "Page size=16384",
            "Executable Segment flags=0x11",
        ] {
            assert!(out.contains(want), "{want} not in {out}");
        }
        fs::remove_dir_all(&root).unwrap();
    }
}
