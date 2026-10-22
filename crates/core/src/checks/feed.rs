//! brainproxy's own checks feed (docs/CHECKS.md, "The brainproxy feed"): the
//! `checks/` folder of the brainproxy repository, pulled at a commit like the
//! Nuclei templates, so new detections arrive without a new release.
//!
//! The feed decides what every install sends to its targets, so it is signed:
//! `feed.json` lists every file with its sha256 and a serial, and `feed.sig` is
//! an Ed25519 signature over it by a key compiled into the binary
//! (`feed_keys.txt`). An update verifies the signature and every file before
//! anything is stored, refuses an older serial (rollback), and stores only the
//! listed files. A pinned commit and tarball sha256 only show what was
//! downloaded; the signature shows who published it.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};

use base64::Engine;
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fetch::{sha256_hex, tar_gz_files, GitHub};

pub const FEED_REPO: &str = "r4nd0mth1ngs/brainproxy";
/// The feed's folder in the repository.
pub const FEED_PATH: &str = "checks";
const MANIFEST: &str = "feed.json";
const SIGNATURE: &str = "feed.sig";
/// The store's record of the installed feed (source commit, counts).
const STATE: &str = "manifest.json";
/// Prefixed to the signed bytes, so a feed signature means nothing elsewhere.
const CONTEXT: &[u8] = b"brainproxy-feed-v1\n";
const FORMAT: u32 = 1;
/// The whole feed, at most (it is a few KiB today).
const MAX_FEED: usize = 32 << 20;
const SECRET_HEADER: &str = "brainproxy feed secret key";
const TRUSTED_KEYS: &str = include_str!("feed_keys.txt");

pub fn feed_dir(home: &Path) -> PathBuf {
    home.join("checks").join("brainproxy")
}

/// `feed.json`: what the signature covers.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct FeedManifest {
    pub format: u32,
    /// Grows with every signed release of the feed; an update to a lower one is refused.
    pub serial: u64,
    /// Path inside the feed -> sha256 (hex).
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignatureFile {
    /// First 8 bytes of the public key's sha256, hex.
    key: String,
    /// Ed25519 signature over CONTEXT + feed.json, base64.
    signature: String,
}

/// The installed feed, as recorded by the last update.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedState {
    pub repository: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub commit: String,
    /// sha256 of the downloaded tarball (empty for `--from DIR`).
    pub sha256: String,
    /// "github" or "dir:<path>".
    pub source: String,
    pub updated_unix: u64,
    pub serial: u64,
    /// Id of the key that signed it.
    pub key: String,
    /// Files in the feed (checks and payload files).
    pub files: usize,
    /// Checks that load in this version, of which passive ones.
    pub checks: usize,
    pub passive: usize,
    /// Active checks tagged `quick-check` (one-click scans in the desktop app),
    /// except those deferring to a built-in rule (the app has that one's scan).
    #[serde(default)]
    pub quick_checks: Vec<QuickCheck>,
    /// Checks this version can't load, with the reason (a newer brainproxy may).
    pub skipped: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickCheck {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FeedUpdate {
    #[serde(flatten)]
    pub state: FeedState,
    /// The feed was already installed at this serial; nothing changed.
    pub unchanged: bool,
    pub added: Vec<Change>,
    pub changed: Vec<Change>,
    pub removed: Vec<Change>,
}

pub enum FeedSource {
    GitHub {
        repo: String,
        reference: String,
    },
    /// The feed folder (with feed.json), or a checkout of the repository.
    Dir(PathBuf),
}

/// The public keys this build trusts (`feed_keys.txt`).
pub fn trusted_keys() -> Vec<Vec<u8>> {
    TRUSTED_KEYS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| base64::engine::general_purpose::STANDARD.decode(l).ok())
        .filter(|k| k.len() == 32)
        .collect()
}

fn key_id(public: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(&sha2::Sha256::digest(public)[..8])
}

/// A file the feed may carry: a check under `http/` or `passive/`, or a payload
/// file under `helpers/`; plain components and a small character set only.
fn feed_path(rel: &str) -> bool {
    let check =
        (rel.starts_with("http/") || rel.starts_with("passive/")) && (rel.ends_with(".yaml") || rel.ends_with(".yml"));
    let helper = rel.starts_with("helpers/") && !rel.ends_with('/');
    (check || helper)
        && Path::new(rel).components().all(|c| matches!(c, Component::Normal(_)))
        && rel.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b))
}

/// Checks the signature and every listed file: the manifest, the key id it was signed with.
fn verify(files: &BTreeMap<String, Vec<u8>>, keys: &[Vec<u8>]) -> Result<(FeedManifest, String)> {
    let refuse = |m: String| Error::InvalidInput(format!("brainproxy feed refused: {m}"));
    let manifest = files.get(MANIFEST).ok_or_else(|| refuse(format!("no {MANIFEST}")))?;
    let sig = files.get(SIGNATURE).ok_or_else(|| refuse(format!("not signed (no {SIGNATURE})")))?;
    let sig: SignatureFile =
        serde_json::from_slice(sig).map_err(|e| refuse(format!("{SIGNATURE} is not readable: {e}")))?;
    if keys.is_empty() {
        return Err(refuse("this build trusts no feed signing key".into()));
    }
    let key = keys
        .iter()
        .find(|k| key_id(k) == sig.key)
        .ok_or_else(|| refuse(format!("signed with key {}, which this build doesn't trust", sig.key)))?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(sig.signature.trim())
        .map_err(|_| refuse("bad signature encoding".into()))?;
    let signed = [CONTEXT, manifest.as_slice()].concat();
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&signed, &signature)
        .map_err(|_| refuse(format!("{MANIFEST} doesn't match its signature")))?;
    let m: FeedManifest =
        serde_json::from_slice(manifest).map_err(|e| refuse(format!("{MANIFEST} is not readable: {e}")))?;
    if m.format != FORMAT {
        return Err(refuse(format!("feed format {} (this version reads {FORMAT}; update brainproxy)", m.format)));
    }
    for (rel, want) in &m.files {
        if !feed_path(rel) {
            return Err(refuse(format!("unexpected path {rel:?}")));
        }
        let data = files.get(rel).ok_or_else(|| refuse(format!("{rel} is missing")))?;
        if !sha256_hex(data).eq_ignore_ascii_case(want) {
            return Err(refuse(format!("{rel} doesn't match its sha256 in {MANIFEST}")));
        }
    }
    Ok((m, sig.key))
}

/// Reads a feed folder (regular files only, symlinks are not followed).
fn read_dir_files(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>, total: &mut usize) -> Result<()> {
        for e in std::fs::read_dir(dir)? {
            let p = e?.path();
            let ft = std::fs::symlink_metadata(&p)?.file_type();
            if ft.is_dir() {
                walk(base, &p, out, total)?;
            } else if ft.is_file() {
                let rel = p.strip_prefix(base).map_err(|e| Error::Protocol(e.to_string()))?;
                let rel = rel.to_string_lossy().replace('\\', "/");
                if rel == MANIFEST || rel == SIGNATURE || feed_path(&rel) {
                    let data = std::fs::read(&p)?;
                    *total += data.len();
                    if *total > MAX_FEED {
                        return Err(Error::InvalidInput("the feed is too large".into()));
                    }
                    out.insert(rel, data);
                }
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out, &mut 0)?;
    Ok(out)
}

/// The feed folder in `dir`: `dir` itself or its `checks/` (a repository checkout).
fn locate(dir: &Path) -> Result<PathBuf> {
    [dir.to_path_buf(), dir.join(FEED_PATH)]
        .into_iter()
        .find(|d| d.join(MANIFEST).is_file())
        .ok_or_else(|| Error::NotFound(format!("{MANIFEST} in {} or its {FEED_PATH}/", dir.display())))
}

/// Verifies a feed folder against `keys` (this build's when None): `checks feed verify`.
pub fn verify_dir(dir: &Path, keys: Option<&[Vec<u8>]>) -> Result<FeedManifest> {
    let files = read_dir_files(&locate(dir)?)?;
    let trusted = trusted_keys();
    Ok(verify(&files, keys.unwrap_or(&trusted))?.0)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn read_state(dir: &Path) -> Option<FeedState> {
    serde_json::from_slice(&std::fs::read(dir.join(STATE)).ok()?).ok()
}

fn read_manifest(dir: &Path) -> Option<FeedManifest> {
    serde_json::from_slice(&std::fs::read(dir.join(MANIFEST)).ok()?).ok()
}

/// Downloads (or imports) the feed, verifies it, and replaces `checks/brainproxy/`
/// with it. `keys` are the trusted public keys (`trusted_keys()` outside tests).
pub async fn update_feed(
    home: &Path,
    source: FeedSource,
    keys: &[Vec<u8>],
    allow_downgrade: bool,
) -> Result<FeedUpdate> {
    let mut state = FeedState::default();
    let files = match source {
        FeedSource::GitHub { repo, reference } => {
            let gh = GitHub::new()?;
            let commit = gh.resolve(&repo, &reference).await?;
            let gz = gh.tarball(&repo, &commit).await?;
            let mut files = BTreeMap::new();
            let mut total = 0usize;
            let prefix = format!("{FEED_PATH}/");
            // Entries are "<repo>-<commit>/checks/...".
            tar_gz_files(&gz, |path, data| {
                let Some(rel) = path.split_once('/').and_then(|(_, p)| p.strip_prefix(&prefix)) else {
                    return Ok(());
                };
                if rel == MANIFEST || rel == SIGNATURE || feed_path(rel) {
                    total += data.len();
                    if total > MAX_FEED {
                        return Err(Error::InvalidInput("the feed is too large".into()));
                    }
                    files.insert(rel.to_string(), data.to_vec());
                }
                Ok(())
            })?;
            state.repository = format!("https://github.com/{repo}");
            state.reference = reference;
            state.commit = commit;
            state.sha256 = sha256_hex(&gz);
            state.source = "github".into();
            files
        }
        FeedSource::Dir(dir) => {
            state.source = format!("dir:{}", dir.display());
            read_dir_files(&locate(&dir)?)?
        }
    };
    // Nothing is written before the feed checks out.
    let (manifest, key) = verify(&files, keys)?;
    let dest = feed_dir(home);
    let previous = read_manifest(&dest);
    if let Some(prev) = &previous {
        if manifest.serial < prev.serial && !allow_downgrade {
            return Err(Error::Conflict(format!(
                "the feed's serial {} is older than the installed one ({}); refusing a rollback \
                 (--allow-downgrade to install it anyway)",
                manifest.serial, prev.serial
            )));
        }
    }
    let root = home.join("checks");
    std::fs::create_dir_all(&root)?;
    let staging = root.join(".brainproxy.new");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    for rel in manifest.files.keys().map(String::as_str).chain([MANIFEST, SIGNATURE]) {
        let p = staging.join(rel);
        std::fs::create_dir_all(p.parent().unwrap_or(&staging))?;
        std::fs::write(p, &files[rel])?;
    }
    // Inputs and an OOB listener are decided at scan time, as for nuclei.
    let opts = super::LoadOptions { any_inputs: true, oob: true, ..Default::default() };
    let loaded = super::load(std::slice::from_ref(&staging), &opts)?;
    let rel = |p: &Path| p.strip_prefix(&staging).unwrap_or(p).to_string_lossy().replace('\\', "/");
    let ids: HashMap<String, String> = loaded.checks.iter().map(|c| (rel(&c.file), c.id.clone())).collect();
    state.updated_unix = now();
    state.serial = manifest.serial;
    state.key = key;
    state.files = manifest.files.len();
    state.checks = loaded.checks.len();
    state.passive = loaded.checks.iter().filter(|c| c.passive).count();
    state.quick_checks = loaded
        .checks
        .iter()
        .filter(|c| !c.passive && c.defer_to.is_none() && c.tags.iter().any(|t| t == "quick-check"))
        .map(|c| QuickCheck { id: c.id.clone(), name: c.name.clone(), description: c.description.clone() })
        .collect();
    state.skipped = loaded.skipped.iter().map(|s| (rel(&s.file), s.reason.clone())).collect();
    std::fs::write(
        staging.join(STATE),
        serde_json::to_vec_pretty(&state).map_err(|e| Error::Protocol(e.to_string()))?,
    )?;

    // What changed, by file, against the installed feed.
    let old = previous.map(|m| m.files).unwrap_or_default();
    let old_ids: HashMap<String, String> = std::fs::read(dest.join(STATE))
        .ok()
        .and_then(|_| super::load(std::slice::from_ref(&dest), &opts).ok())
        .map(|l| {
            l.checks
                .into_iter()
                .map(|c| (c.file.strip_prefix(&dest).unwrap_or(&c.file).to_string_lossy().replace('\\', "/"), c.id))
                .collect()
        })
        .unwrap_or_default();
    let change = |f: &String, ids: &HashMap<String, String>| Change { file: f.clone(), id: ids.get(f).cloned() };
    let mut update = FeedUpdate { state, unchanged: false, added: vec![], changed: vec![], removed: vec![] };
    for (f, sha) in &manifest.files {
        match old.get(f) {
            None => update.added.push(change(f, &ids)),
            Some(o) if o != sha => update.changed.push(change(f, &ids)),
            _ => {}
        }
    }
    update.removed = old.keys().filter(|f| !manifest.files.contains_key(*f)).map(|f| change(f, &old_ids)).collect();
    update.unchanged = !old.is_empty() && old == manifest.files;

    let backup = root.join(".brainproxy.old");
    if backup.exists() {
        std::fs::remove_dir_all(&backup)?;
    }
    if dest.exists() {
        std::fs::rename(&dest, &backup)?;
    }
    std::fs::rename(&staging, &dest)?;
    if backup.exists() {
        std::fs::remove_dir_all(&backup)?;
    }
    Ok(update)
}

#[derive(Debug, Serialize)]
pub struct FeedStatus {
    pub dir: PathBuf,
    pub repository: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed: Option<FeedState>,
    /// Signing keys this build trusts (0: it accepts no feed).
    pub trusted_keys: usize,
}

pub fn feed_status(home: &Path) -> FeedStatus {
    FeedStatus {
        dir: feed_dir(home),
        repository: format!("https://github.com/{FEED_REPO}"),
        installed: read_state(&feed_dir(home)),
        trusted_keys: trusted_keys().len(),
    }
}

/// Creates a signing key at `path` (never overwritten, owner-only on Unix) and
/// returns its public key (base64) for `feed_keys.txt`.
pub fn keygen(path: &Path) -> Result<String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| std::io::Error::other(e.to_string()))?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|e| Error::Protocol(e.to_string()))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => {
            Error::Conflict(format!("{} exists; not overwriting a key", path.display()))
        }
        _ => e.into(),
    })?;
    use std::io::Write;
    writeln!(f, "{SECRET_HEADER}\n{}", b64.encode(seed))?;
    Ok(b64.encode(ring::signature::KeyPair::public_key(&pair)))
}

fn read_secret(path: &Path) -> Result<Ed25519KeyPair> {
    let text = std::fs::read_to_string(path)?;
    let mut lines = text.lines();
    let bad =
        || Error::InvalidInput(format!("{} is not a feed secret key (brainproxy checks feed keygen)", path.display()));
    if lines.next().map(str::trim) != Some(SECRET_HEADER) {
        return Err(bad());
    }
    let seed = lines
        .next()
        .and_then(|l| base64::engine::general_purpose::STANDARD.decode(l.trim()).ok())
        .filter(|s| s.len() == 32)
        .ok_or_else(bad)?;
    Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| bad())
}

/// Writes `feed.json` for the feed folder `dir` (every check and payload file,
/// with a serial above the previous one) and signs it into `feed.sig`. Refuses
/// a feed with a check that doesn't load. Returns the manifest and key id.
pub fn sign_feed(dir: &Path, key: &Path) -> Result<(FeedManifest, String)> {
    let pair = read_secret(key)?;
    let opts = super::LoadOptions { any_inputs: true, oob: true, ..Default::default() };
    let loaded = super::load(&[dir.to_path_buf()], &opts)?;
    if let Some(s) = loaded.skipped.first() {
        return Err(Error::InvalidInput(format!(
            "{} doesn't load ({}); fix it before signing ({} not loaded in all)",
            s.file.display(),
            s.reason,
            loaded.skipped.len()
        )));
    }
    let files = read_dir_files(dir)?;
    let previous = files.get(MANIFEST).and_then(|m| serde_json::from_slice::<FeedManifest>(m).ok());
    let manifest = FeedManifest {
        format: FORMAT,
        serial: now().max(previous.map_or(0, |p| p.serial + 1)),
        files: files
            .iter()
            .filter(|(rel, _)| feed_path(rel))
            .map(|(rel, data)| (rel.clone(), sha256_hex(data)))
            .collect(),
    };
    if manifest.files.is_empty() {
        return Err(Error::NotFound(format!("checks in {} (http/, passive/)", dir.display())));
    }
    let mut bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| Error::Protocol(e.to_string()))?;
    bytes.push(b'\n');
    let public = ring::signature::KeyPair::public_key(&pair).as_ref().to_vec();
    let sig = SignatureFile {
        key: key_id(&public),
        signature: base64::engine::general_purpose::STANDARD.encode(pair.sign(&[CONTEXT, &bytes].concat())),
    };
    let mut sig_bytes = serde_json::to_vec_pretty(&sig).map_err(|e| Error::Protocol(e.to_string()))?;
    sig_bytes.push(b'\n');
    std::fs::write(dir.join(MANIFEST), &bytes)?;
    std::fs::write(dir.join(SIGNATURE), &sig_bytes)?;
    Ok((manifest, sig.key))
}

/// The public key (base64) of a secret key file, to check which key signs.
pub fn public_key(key: &Path) -> Result<String> {
    let pair = read_secret(key)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(ring::signature::KeyPair::public_key(&pair)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bp-feed-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A copy of the repository's feed folder, signed with a new key: (folder, public key).
    fn signed_copy(dir: &Path) -> (PathBuf, Vec<u8>) {
        let feed = dir.join("checks");
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../checks");
        for (rel, data) in read_dir_files(&src).unwrap() {
            if feed_path(&rel) {
                let p = feed.join(&rel);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, data).unwrap();
            }
        }
        let key = dir.join("feed.key");
        let public = keygen(&key).unwrap();
        sign_feed(&feed, &key).unwrap();
        (feed, base64::engine::general_purpose::STANDARD.decode(public).unwrap())
    }

    fn update(home: &Path, feed: &Path, keys: &[Vec<u8>]) -> Result<FeedUpdate> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(update_feed(home, FeedSource::Dir(feed.to_path_buf()), keys, false))
    }

    #[test]
    fn signed_feed_installs_and_reports_changes() {
        let dir = tmp("install");
        let (feed, key) = signed_copy(&dir);
        let keys = vec![key];
        assert!(verify_dir(&feed, Some(&keys)).is_ok());
        let home = dir.join("home");
        let u = update(&home, &feed, &keys).unwrap();
        assert!(!u.unchanged && u.changed.is_empty() && u.removed.is_empty());
        assert!(u.added.iter().any(|c| c.id.as_deref() == Some("CVE-2026-109618-php-version")), "{:?}", u.added);
        assert_eq!((u.state.checks, u.state.passive), (2, 1));
        assert!(u.state.skipped.is_empty(), "{:?}", u.state.skipped);
        assert!(feed_dir(&home).join("passive/cves/2026/CVE-2026-109618-php-version.yaml").is_file());
        assert_eq!(feed_status(&home).installed.unwrap().serial, u.state.serial);
        // Unlisted files (this README) are not stored.
        assert!(!feed_dir(&home).join("README.md").exists());
        assert!(update(&home, &feed, &keys).unwrap().unchanged);

        // A new signed release: the change is listed.
        let f = feed.join("passive/cves/2026/CVE-2026-109618-php-version.yaml");
        let text = std::fs::read_to_string(&f).unwrap().replace("severity: high", "severity: medium");
        std::fs::write(&f, text).unwrap();
        sign_feed(&feed, &dir.join("feed.key")).unwrap();
        let u = update(&home, &feed, &keys).unwrap();
        assert_eq!(u.changed.len(), 1, "{:?}", u.changed);
        assert_eq!(u.changed[0].id.as_deref(), Some("CVE-2026-109618-php-version"));
    }

    #[test]
    fn tampered_unsigned_or_foreign_feeds_are_refused_before_storing() {
        let dir = tmp("tamper");
        let (feed, key) = signed_copy(&dir);
        let keys = vec![key];
        let home = dir.join("home");
        let refused = |r: Result<FeedUpdate>, what: &str| {
            let e = r.err().unwrap_or_else(|| panic!("{what}: accepted")).to_string();
            assert!(e.contains("brainproxy feed refused"), "{what}: {e}");
            assert!(!feed_dir(&home).exists(), "{what}: something was stored");
        };
        // No trusted key, or another one.
        refused(update(&home, &feed, &[]), "no keys");
        let other = tmp("tamper-other");
        let (_, other_key) = signed_copy(&other);
        refused(update(&home, &feed, &[other_key]), "foreign key");
        // A check changed after signing.
        let f = feed.join("http/cves/2026/CVE-2026-109619-php2shell-multipart.yaml");
        let original = std::fs::read(&f).unwrap();
        std::fs::write(&f, [&original[..], b"\n# more\n"].concat()).unwrap();
        refused(update(&home, &feed, &keys), "changed file");
        // A listed file missing.
        std::fs::remove_file(&f).unwrap();
        refused(update(&home, &feed, &keys), "missing file");
        std::fs::write(&f, &original).unwrap();
        // The manifest changed (a file added to it), or the signature removed.
        let m = feed.join(MANIFEST);
        let signed = std::fs::read_to_string(&m).unwrap();
        let mut manifest: FeedManifest = serde_json::from_str(&signed).unwrap();
        manifest.files.insert("http/x.yaml".into(), sha256_hex(b"x"));
        std::fs::write(&m, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        refused(update(&home, &feed, &keys), "changed manifest");
        std::fs::write(&m, &signed).unwrap();
        let sig = std::fs::read(feed.join(SIGNATURE)).unwrap();
        std::fs::remove_file(feed.join(SIGNATURE)).unwrap();
        refused(update(&home, &feed, &keys), "unsigned");
        std::fs::write(feed.join(SIGNATURE), sig).unwrap();
        assert!(update(&home, &feed, &keys).is_ok());
    }

    #[test]
    fn an_older_feed_is_refused_unless_allowed() {
        let dir = tmp("rollback");
        let (feed, key) = signed_copy(&dir);
        let keys = vec![key];
        let home = dir.join("home");
        let old = dir.join("old");
        std::fs::create_dir_all(&old).unwrap();
        for (rel, data) in read_dir_files(&feed).unwrap() {
            let p = old.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, data).unwrap();
        }
        sign_feed(&feed, &dir.join("feed.key")).unwrap();
        update(&home, &feed, &keys).unwrap();
        let e = update(&home, &old, &keys).unwrap_err();
        assert!(matches!(e, Error::Conflict(_)), "{e}");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(update_feed(&home, FeedSource::Dir(old), &keys, true)).unwrap();
    }

    /// Every check in the repository's feed loads, and once the feed is signed, a change
    /// without a new signature fails here (the files no longer match feed.json).
    #[test]
    fn the_repository_feed_loads_and_matches_its_signature() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../checks");
        let opts = super::super::LoadOptions { any_inputs: true, oob: true, ..Default::default() };
        let loaded = super::super::load(std::slice::from_ref(&dir), &opts).unwrap();
        assert!(loaded.skipped.is_empty(), "{:?}", loaded.skipped);
        assert!(!loaded.checks.is_empty());
        if dir.join(MANIFEST).exists() {
            verify_dir(&dir, None).unwrap();
        }
    }

    #[test]
    fn feed_paths_and_signing_rules() {
        for ok in ["http/a.yaml", "passive/x/y.yml", "helpers/wordlists/u.txt"] {
            assert!(feed_path(ok), "{ok}");
        }
        for bad in
            ["feed.json", "README.md", "http/../x.yaml", "/http/a.yaml", "http/a.txt", "other/a.yaml", "http/a b.yaml"]
        {
            assert!(!feed_path(bad), "{bad}");
        }
        let dir = tmp("sign");
        let key = dir.join("k");
        keygen(&key).unwrap();
        // Keys are never overwritten.
        assert!(matches!(keygen(&key), Err(Error::Conflict(_))));
        // A check that doesn't load is not signed.
        std::fs::create_dir_all(dir.join("f/http")).unwrap();
        std::fs::write(dir.join("f/http/bad.yaml"), "id: x\nhttp:\n  - path: [a]\n    matchers: [{type: nope}]\n")
            .unwrap();
        assert!(sign_feed(&dir.join("f"), &key).is_err());
        assert!(!dir.join("f/feed.json").exists());
        // The serial grows even when signed twice within a second.
        std::fs::write(
            dir.join("f/http/bad.yaml"),
            "id: x\nhttp:\n  - path: ['{{BaseURL}}/']\n    matchers: [{type: status, status: [200]}]\n",
        )
        .unwrap();
        let (a, _) = sign_feed(&dir.join("f"), &key).unwrap();
        let (b, _) = sign_feed(&dir.join("f"), &key).unwrap();
        assert!(b.serial > a.serial);
    }
}
