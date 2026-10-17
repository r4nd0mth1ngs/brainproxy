//! Check stores under the home directory: `checks/local/` for checks written by
//! hand (or by an agent), `checks/nuclei/` for the Nuclei HTTP templates that
//! `checks update` imports. Only templates that load are stored, with the
//! repository's `helpers/` (payload files templates refer to); the manifest
//! records the source commit, the tarball's sha256, and why others were skipped.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fetch::{sha256_hex, tar_gz_files, GitHub};

pub fn local_dir(home: &Path) -> PathBuf {
    home.join("checks").join("local")
}

pub fn nuclei_dir(home: &Path) -> PathBuf {
    home.join("checks").join("nuclei")
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Manifest {
    pub repository: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub commit: String,
    /// sha256 of the downloaded tarball (empty for `--from DIR`).
    pub sha256: String,
    /// "github" or "dir:<path>".
    pub source: String,
    pub updated_unix: u64,
    /// HTTP templates seen in the source.
    pub templates: usize,
    pub stored: usize,
    /// Files kept from `helpers/` (payload wordlists).
    #[serde(default)]
    pub helpers: usize,
    /// Skip reasons with counts, most common first (top 30).
    pub skipped: Vec<(String, usize)>,
}

pub enum Source {
    GitHub {
        repo: String,
        reference: String,
        /// Expected tarball sha256; the update fails on a mismatch.
        sha256: Option<String>,
    },
    /// A nuclei-templates checkout (its `http/` directory is used when present).
    Dir(PathBuf),
}

pub type UpdateResult = Manifest;

/// `helpers/` files kept in the store, at most (they are ~5 MiB upstream).
const MAX_HELPERS: u64 = 64 << 20;

/// A path inside the store: a template (`http/...yaml`) or a helper file
/// (`helpers/...`), plain components only.
fn store_path(rel: &str) -> Option<(PathBuf, bool)> {
    let p = Path::new(rel);
    let template = rel.starts_with("http/") && (rel.ends_with(".yaml") || rel.ends_with(".yml"));
    let helper = rel.starts_with("helpers/") && !rel.ends_with('/');
    let ok = p.components().all(|c| matches!(c, Component::Normal(_)))
        && (template || helper)
        && rel.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b));
    ok.then(|| (p.to_path_buf(), template))
}

/// Imports templates into `checks/nuclei/`, replacing the previous set only
/// once the new one is complete.
pub async fn update(home: &Path, source: Source) -> Result<UpdateResult> {
    let root = home.join("checks");
    std::fs::create_dir_all(&root)?;
    let staging = root.join(".nuclei.new");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    let mut m = Manifest::default();
    let mut helper_bytes = 0u64;
    let mut write = |rel: &str, data: &[u8]| -> Result<()> {
        let Some((p, template)) = store_path(rel) else { return Ok(()) };
        if !template {
            helper_bytes += data.len() as u64;
            if helper_bytes > MAX_HELPERS {
                return Ok(());
            }
        }
        let dest = staging.join(p);
        std::fs::create_dir_all(dest.parent().unwrap())?;
        std::fs::write(dest, data)?;
        if template {
            m.templates += 1;
        } else {
            m.helpers += 1;
        }
        Ok(())
    };
    let (repository, reference, commit, sha256, source_name) = match source {
        Source::GitHub { repo, reference, sha256 } => {
            let gh = GitHub::new()?;
            let commit = gh.resolve(&repo, &reference).await?;
            let gz = gh.tarball(&repo, &commit).await?;
            let got = sha256_hex(&gz);
            if let Some(want) = sha256.filter(|w| !w.eq_ignore_ascii_case(&got)) {
                return Err(Error::InvalidInput(format!("tarball sha256 is {got}, expected {want}")));
            }
            // Entries are "<repo>-<commit>/http/...".
            tar_gz_files(&gz, |path, data| match path.split_once('/') {
                Some((_, rel)) => write(rel, data),
                None => Ok(()),
            })?;
            (format!("https://github.com/{repo}"), reference, commit, got, "github".to_string())
        }
        Source::Dir(dir) => {
            let base = if dir.join("http").is_dir() { dir.clone() } else { dir.join("..") };
            let mut files = Vec::new();
            collect(&base.join("http"), &mut files)?;
            if base.join("helpers").is_dir() {
                collect(&base.join("helpers"), &mut files)?;
            }
            for f in files {
                let rel = f.strip_prefix(&base).map_err(|e| Error::Protocol(e.to_string()))?;
                let rel = rel.to_string_lossy().replace('\\', "/");
                if std::fs::metadata(&f)?.len() <= crate::fetch::MAX_TAR_ENTRY {
                    write(&rel, &std::fs::read(&f)?)?;
                }
            }
            (String::new(), String::new(), String::new(), String::new(), format!("dir:{}", dir.display()))
        }
    };
    if m.templates == 0 {
        std::fs::remove_dir_all(&staging)?;
        return Err(Error::NotFound("no HTTP templates (http/*.yaml) in the source".into()));
    }
    // Keep only templates that load, so the store is exactly what can run
    // (payload files resolve against the staging root, later the store).
    // Templates needing inputs stay: `--check-var` enables them at scan time.
    let opts = super::LoadOptions { any_inputs: true, ..Default::default() };
    let loaded = super::load(std::slice::from_ref(&staging), &opts)?;
    for s in &loaded.skipped {
        let _ = std::fs::remove_file(&s.file);
    }
    m.stored = loaded.checks.len();
    m.skipped = loaded.reasons().into_iter().take(30).collect();
    m.repository = repository;
    m.reference = reference;
    m.commit = commit;
    m.sha256 = sha256;
    m.source = source_name;
    m.updated_unix =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&m).map_err(|e| Error::Protocol(e.to_string()))?,
    )?;
    let dest = nuclei_dir(home);
    let old = root.join(".nuclei.old");
    if old.exists() {
        std::fs::remove_dir_all(&old)?;
    }
    if dest.exists() {
        std::fs::rename(&dest, &old)?;
    }
    std::fs::rename(&staging, &dest)?;
    if old.exists() {
        std::fs::remove_dir_all(&old)?;
    }
    Ok(m)
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Err(Error::NotFound(format!("{} (expected a nuclei-templates checkout)", dir.display())));
    }
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

#[derive(Debug, Serialize)]
pub struct StoreStatus {
    pub nuclei_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nuclei: Option<Manifest>,
    pub local_dir: PathBuf,
    pub local_files: usize,
}

pub fn nuclei_status(home: &Path) -> StoreStatus {
    let nuclei =
        std::fs::read(nuclei_dir(home).join("manifest.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let mut files = Vec::new();
    let _ = super::walk(&local_dir(home), &mut files);
    StoreStatus { nuclei_dir: nuclei_dir(home), nuclei, local_dir: local_dir(home), local_files: files.len() }
}

#[cfg(test)]
/// Some(true) for a template path, Some(false) for a helper file, None if refused.
pub(crate) fn tests_store_path(rel: &str) -> Option<bool> {
    store_path(rel).map(|(_, template)| template)
}
