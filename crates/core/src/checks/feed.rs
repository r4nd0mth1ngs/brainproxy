//! brainproxy's own checks as a signed feed (docs/CHECKS.md, "The brainproxy feed").
//!
//! The feed is the `feed/` folder of the brainproxy repository: check templates plus
//! `feed.json`, which lists every file with its sha256, and `feed.sig`, an Ed25519
//! signature over `feed.json` by a key compiled into brainproxy. `checks update
//! --source brainproxy` verifies the signature before anything else, then fetches
//! only the listed files and checks each one's hash, so a store holds nothing that
//! wasn't signed. A pinned commit and a tarball hash only prove what was downloaded;
//! the signature proves who published it.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use super::store::{brainproxy_dir, install, keep_loadable, Changes, Manifest, Source};
use crate::error::{Error, Result};
use crate::fetch::{sha256_hex, GitHub};

/// Public keys (base64, raw 32 bytes) whose signatures the feed is accepted with.
/// Rotating: add the new key, release, sign with it, then drop the old one.
pub const TRUSTED_KEYS: &[&str] = &[
    // 7266f3166674d19b, made 2026-10-23
    "UJR0olUL4gRjoR4Zyh5wCyTMkq8eKJOgHpZ28jHtUmM=",
];

pub const FEED_REPO: &str = "r4nd0mth1ngs/brainproxy";
/// The feed's folder in the repository.
pub const FEED_DIR: &str = "feed";
const LIST: &str = "feed.json";
const SIG: &str = "feed.sig";
const MAX_FILES: usize = 5000;

/// `feed.json`: every file of the feed with its sha256.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct FeedList {
    pub version: u32,
    pub files: BTreeMap<String, String>,
}

/// A feed path: plain components, a template (`*.yaml`/`*.yml`) or a `helpers/` file.
fn feed_path(rel: &str) -> bool {
    let p = Path::new(rel);
    !rel.is_empty()
        && p.components().all(|c| matches!(c, Component::Normal(_)))
        && rel.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b))
        && (rel.ends_with(".yaml") || rel.ends_with(".yml") || rel.starts_with("helpers/"))
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// A key's id: the first 16 hex digits of the sha256 of its public key.
pub fn key_id(public: &[u8]) -> String {
    sha256_hex(public)[..16].to_string()
}

/// Checks `sig` (`<key id> <base64 signature>`) over `list` against `keys`; returns
/// the signing key's id and the parsed list.
pub fn verify(list: &[u8], sig: &[u8], keys: &[&str]) -> Result<(String, FeedList)> {
    let bad = |m: &str| Error::InvalidInput(format!("feed signature: {m}"));
    let sig = std::str::from_utf8(sig).map_err(|_| bad("not text"))?;
    let (id, sig) = sig.trim().split_once(' ').ok_or_else(|| bad("expected `<key id> <signature>`"))?;
    let sig = b64().decode(sig.trim()).map_err(|_| bad("signature is not base64"))?;
    let key = keys
        .iter()
        .filter_map(|k| b64().decode(k).ok())
        .find(|k| key_id(k) == id)
        .ok_or_else(|| bad(&format!("key {id} is not trusted by this brainproxy version")))?;
    UnparsedPublicKey::new(&ED25519, &key).verify(list, &sig).map_err(|_| bad("doesn't match feed.json"))?;
    let parsed: FeedList = serde_json::from_slice(list).map_err(|e| Error::InvalidInput(format!("feed.json: {e}")))?;
    if parsed.version != 1 {
        return Err(Error::InvalidInput(format!("feed.json version {} (update brainproxy)", parsed.version)));
    }
    if parsed.files.len() > MAX_FILES {
        return Err(Error::InvalidInput(format!("feed.json lists more than {MAX_FILES} files")));
    }
    if let Some(p) = parsed.files.keys().find(|p| !feed_path(p)) {
        return Err(Error::InvalidInput(format!("feed.json: bad path {p:?}")));
    }
    Ok((id.to_string(), parsed))
}

/// A new signing key: the PKCS#8 document as base64 (keep it secret), the public
/// key as base64 (goes into `TRUSTED_KEYS`), and its id.
pub fn keygen() -> Result<(String, String, String)> {
    let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| Error::Protocol("key generation failed".into()))?;
    let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).map_err(|_| Error::Protocol("bad generated key".into()))?;
    let public = pair.public_key().as_ref();
    Ok((b64().encode(doc.as_ref()), b64().encode(public), key_id(public)))
}

/// Writes `feed.json` for every feed file under `dir` and `feed.sig` signed with
/// `key` (a `keygen` private key, base64). Returns the key id and the file count.
pub fn sign(dir: &Path, key: &str) -> Result<(String, usize)> {
    let doc = b64().decode(key.trim()).map_err(|_| Error::InvalidInput("signing key is not base64".into()))?;
    let pair = Ed25519KeyPair::from_pkcs8(&doc).map_err(|_| Error::InvalidInput("not an Ed25519 key".into()))?;
    let mut found = Vec::new();
    collect(dir, &mut found)?;
    let mut files = BTreeMap::new();
    for f in found {
        let rel = f.strip_prefix(dir).map_err(|e| Error::Protocol(e.to_string()))?.to_string_lossy().replace('\\', "/");
        if rel == LIST || rel == SIG {
            continue;
        }
        if !feed_path(&rel) {
            return Err(Error::InvalidInput(format!("{rel}: not a feed file (*.yaml or helpers/, plain names)")));
        }
        files.insert(rel, sha256_hex(&std::fs::read(&f)?));
    }
    let list = FeedList { version: 1, files };
    let mut bytes = serde_json::to_vec_pretty(&list).map_err(|e| Error::Protocol(e.to_string()))?;
    bytes.push(b'\n');
    let id = key_id(pair.public_key().as_ref());
    let sig = format!("{id} {}\n", b64().encode(pair.sign(&bytes).as_ref()));
    std::fs::write(dir.join(LIST), &bytes)?;
    std::fs::write(dir.join(SIG), sig)?;
    Ok((id, list.files.len()))
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        let ft = std::fs::symlink_metadata(&p)?.file_type();
        if ft.is_dir() {
            collect(&p, out)?;
        } else if ft.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

/// Updates `<home>/checks/brainproxy/` from the feed: GitHub (`repo` at `reference`,
/// resolved to a commit) or a local copy (`feed/` itself or a checkout holding it).
/// `sha256`, if given, is the expected hash of `feed.json`.
pub async fn update(home: &Path, source: Source) -> Result<Manifest> {
    update_with(home, source, TRUSTED_KEYS).await
}

pub(crate) async fn update_with(home: &Path, source: Source, keys: &[&str]) -> Result<Manifest> {
    if keys.is_empty() {
        return Err(Error::InvalidInput("this brainproxy build trusts no feed signing key".into()));
    }
    let root = home.join("checks");
    std::fs::create_dir_all(&root)?;
    let _lock = crate::data::update_lock(home)?;
    let staging = root.join(".brainproxy.new");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    let mut m = Manifest::default();
    // Verifies the list, then writes each listed file whose hash matches.
    let result = async {
        let (id, list) = match &source {
            Source::GitHub { repo, reference, sha256 } => {
                let gh = GitHub::new()?;
                let commit = gh.resolve(repo, reference).await?;
                let raw = |p: &str| {
                    let path = format!("{FEED_DIR}/{p}");
                    let (gh, repo, commit) = (&gh, repo.clone(), commit.clone());
                    async move { gh.raw_file(&repo, &commit, &path).await }
                };
                let (list_bytes, sig) = (raw(LIST).await?, raw(SIG).await?);
                check_sha(&list_bytes, sha256.as_deref())?;
                let (id, list) = verify(&list_bytes, &sig, keys)?;
                std::fs::create_dir_all(&staging)?;
                for (rel, want) in &list.files {
                    put(&staging, rel, want, &raw(rel).await?)?;
                }
                m.repository = format!("https://github.com/{repo}");
                m.reference = reference.clone();
                m.commit = commit;
                m.sha256 = sha256_hex(&list_bytes);
                m.source = "github".into();
                (id, list)
            }
            Source::Dir(dir) => {
                let dir = if dir.join(LIST).is_file() { dir.clone() } else { dir.join(FEED_DIR) };
                let list_bytes = std::fs::read(dir.join(LIST))
                    .map_err(|e| Error::NotFound(format!("{}: {e}", dir.join(LIST).display())))?;
                let (id, list) = verify(&list_bytes, &std::fs::read(dir.join(SIG))?, keys)?;
                std::fs::create_dir_all(&staging)?;
                for (rel, want) in &list.files {
                    put(&staging, rel, want, &std::fs::read(dir.join(rel))?)?;
                }
                m.sha256 = sha256_hex(&list_bytes);
                m.source = format!("dir:{}", dir.display());
                (id, list)
            }
        };
        m.signed_by = id;
        m.templates = list.files.keys().filter(|p| !p.starts_with("helpers/")).count();
        m.helpers = list.files.len() - m.templates;
        let (stored, skipped) = keep_loadable(&staging)?;
        m.stored = stored;
        m.skipped = skipped;
        m.changes = Some(changes(&brainproxy_dir(home), &staging)?);
        install(&staging, &brainproxy_dir(home), &mut m)
    }
    .await;
    if result.is_err() && staging.exists() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result.map(|_| m)
}

/// Templates added, changed, or removed between the installed store and `staging`.
fn changes(old: &Path, new: &Path) -> Result<Changes> {
    let files = |dir: &Path| -> Result<BTreeMap<String, String>> {
        let mut found = Vec::new();
        if dir.is_dir() {
            super::walk(dir, &mut found)?;
        }
        found
            .into_iter()
            .map(|f| {
                let rel = f.strip_prefix(dir).unwrap_or(&f).to_string_lossy().replace('\\', "/");
                Ok((rel, sha256_hex(&std::fs::read(&f)?)))
            })
            .collect()
    };
    let (old, new) = (files(old)?, files(new)?);
    let mut c = Changes::default();
    for (rel, sha) in &new {
        match old.get(rel) {
            None => c.added.push(rel.clone()),
            Some(o) if o != sha => c.changed.push(rel.clone()),
            _ => {}
        }
    }
    c.removed = old.keys().filter(|k| !new.contains_key(*k)).cloned().collect();
    Ok(c)
}

fn check_sha(data: &[u8], want: Option<&str>) -> Result<()> {
    let got = sha256_hex(data);
    match want {
        Some(w) if !w.eq_ignore_ascii_case(&got) => {
            Err(Error::InvalidInput(format!("feed.json sha256 is {got}, expected {w}")))
        }
        _ => Ok(()),
    }
}

fn put(staging: &Path, rel: &str, want: &str, data: &[u8]) -> Result<()> {
    if data.len() as u64 > crate::fetch::MAX_TAR_ENTRY {
        return Err(Error::InvalidInput(format!("feed file {rel} is too large")));
    }
    let got = sha256_hex(data);
    if !got.eq_ignore_ascii_case(want) {
        return Err(Error::InvalidInput(format!("feed file {rel}: sha256 {got}, feed.json says {want}")));
    }
    let dest = staging.join(rel);
    std::fs::create_dir_all(dest.parent().unwrap_or(staging))?;
    std::fs::write(dest, data)?;
    Ok(())
}
