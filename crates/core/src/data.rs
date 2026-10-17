//! Runtime-updatable rule data (docs/RULE_UPDATES.md, layer 2).
//!
//! The ZAP pattern lists some rules read are embedded at build time. `scan data
//! update` stores newer copies under `<home>/rules/` with a manifest (ref, commit,
//! sha256, entry count). A rule uses a stored copy only when the CLI set the home
//! (`set_home`), the manifest lists the file, its sha256 still matches, and it
//! passes the same validation as at update time; otherwise the embedded copy.
//! Unit tests never set the home, so they always see the embedded data.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fetch::{sha256_hex, GitHub};
use crate::scan::active::rules::probes::hidden_files;
use crate::scan::passive::rules::content::{application_error, debug_errors};
use crate::scan::passive::rules::params::common as params_common;

pub const ZAP_REPO: &str = "zaproxy/zap-extensions";
/// Data files are small; anything bigger is not what we expect.
const MAX_FILE: usize = 4 << 20;

pub struct DataFile {
    pub name: &'static str,
    /// Path in zap-extensions (same as zap-sync.json).
    pub upstream: &'static str,
    pub embedded: &'static str,
    /// Parses the text the way the rules do; returns the number of entries.
    pub validate: fn(&str) -> Result<usize>,
    /// Rule ids that read it.
    pub rules: &'static [u32],
}

pub static FILES: [DataFile; 4] = [
    DataFile {
        name: "application_errors.xml",
        upstream: "addOns/pscanrules/src/main/zapHomeFiles/xml/application_errors.xml",
        embedded: application_error::EMBEDDED,
        validate: application_error::validate,
        rules: &[90022],
    },
    DataFile {
        name: "debug-error-messages.txt",
        upstream: "addOns/pscanrules/src/main/zapHomeFiles/xml/debug-error-messages.txt",
        embedded: debug_errors::EMBEDDED,
        validate: debug_errors::validate,
        rules: &[10023],
    },
    DataFile {
        name: "URL-information-disclosure-messages.txt",
        upstream: "addOns/pscanrules/src/main/zapHomeFiles/xml/URL-information-disclosure-messages.txt",
        embedded: params_common::SENSITIVE_EMBEDDED,
        validate: params_common::validate_sensitive,
        rules: &[10024, 10025],
    },
    DataFile {
        name: "hidden_files.json",
        upstream: "addOns/ascanrules/src/main/zapHomeFiles/json/hidden_files.json",
        embedded: hidden_files::EMBEDDED,
        validate: hidden_files::validate,
        rules: &[40035],
    },
];

static HOME: OnceLock<PathBuf> = OnceLock::new();

/// Lets rules load updated data from `<home>/rules/`. Call before any scanning.
pub fn set_home(home: &Path) {
    let _ = HOME.set(home.to_path_buf());
}

pub fn rules_dir(home: &Path) -> PathBuf {
    home.join("rules")
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Manifest {
    pub repository: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub commit: String,
    /// "github" or "dir:<path>".
    pub source: String,
    pub updated_unix: u64,
    pub files: BTreeMap<String, ManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub upstream: String,
    pub sha256: String,
    pub entries: usize,
}

fn read_manifest(dir: &Path) -> Option<Manifest> {
    serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).ok()?).ok()
}

/// The stored copy of `file` if it is listed, unchanged, and valid.
fn stored(dir: &Path, manifest: &Manifest, file: &DataFile) -> Option<(String, usize)> {
    let m = manifest.files.get(file.name)?;
    let text = std::fs::read_to_string(dir.join(file.name)).ok()?;
    if sha256_hex(text.as_bytes()) != m.sha256 {
        return None;
    }
    let entries = check(file, &text).ok()?;
    Some((text, entries))
}

/// The text rules should use for the data file `name`.
pub fn get(name: &str) -> &'static str {
    static LOADED: OnceLock<BTreeMap<&'static str, &'static str>> = OnceLock::new();
    let loaded = LOADED.get_or_init(|| {
        let dir = HOME.get().map(|h| rules_dir(h));
        let manifest = dir.as_deref().and_then(read_manifest);
        FILES
            .iter()
            .map(|f| {
                let text = match (&dir, &manifest) {
                    (Some(d), Some(m)) => stored(d, m, f).map(|(t, _)| &*Box::leak(t.into_boxed_str())),
                    _ => None,
                };
                (f.name, text.unwrap_or(f.embedded))
            })
            .collect()
    });
    loaded.get(name).copied().unwrap_or_else(|| panic!("unknown data file {name}"))
}

/// Validates a candidate: size, the rules' own parser, and at least half the
/// embedded entries (so a truncated file can't quietly disable a rule).
fn check(file: &DataFile, text: &str) -> Result<usize> {
    if text.len() > MAX_FILE {
        return Err(Error::InvalidInput(format!("{}: larger than {} MiB", file.name, MAX_FILE >> 20)));
    }
    let n = (file.validate)(text).map_err(|e| Error::InvalidInput(format!("{}: {e}", file.name)))?;
    let min = (file.validate)(file.embedded).unwrap_or(0).div_ceil(2);
    if n < min {
        return Err(Error::InvalidInput(format!(
            "{}: only {n} entries (embedded copy has at least {})",
            file.name, min
        )));
    }
    Ok(n)
}

#[derive(Debug, Serialize)]
pub struct FileStatus {
    pub name: &'static str,
    pub upstream: &'static str,
    pub rules: &'static [u32],
    /// "downloaded" or "embedded".
    pub active: &'static str,
    pub entries: usize,
    pub embedded_entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Why a stored copy isn't used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub dir: PathBuf,
    pub embedded_commit: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Manifest>,
    pub files: Vec<FileStatus>,
}

/// The commit the embedded copies come from (zap-sync.json).
pub fn embedded_commit() -> &'static str {
    static C: OnceLock<String> = OnceLock::new();
    C.get_or_init(|| {
        serde_json::from_str::<serde_json::Value>(include_str!("../../../zap-sync.json"))
            .ok()
            .and_then(|v| v["commit"].as_str().map(str::to_string))
            .unwrap_or_default()
    })
}

pub fn status(home: &Path) -> Status {
    let dir = rules_dir(home);
    let manifest = read_manifest(&dir);
    let files = FILES
        .iter()
        .map(|f| {
            let embedded_entries = (f.validate)(f.embedded).unwrap_or(0);
            let mut s = FileStatus {
                name: f.name,
                upstream: f.upstream,
                rules: f.rules,
                active: "embedded",
                entries: embedded_entries,
                embedded_entries,
                sha256: None,
                problem: None,
            };
            if let Some(m) = manifest.as_ref().filter(|m| m.files.contains_key(f.name)) {
                match stored(&dir, m, f) {
                    Some((text, n)) => {
                        s.active = "downloaded";
                        s.entries = n;
                        s.sha256 = Some(sha256_hex(text.as_bytes()));
                    }
                    None => s.problem = Some("stored copy missing, modified, or invalid; using embedded".into()),
                }
            }
            s
        })
        .collect();
    Status { dir, embedded_commit: embedded_commit(), manifest, files }
}

/// Where `update` takes the files from.
pub enum Source {
    /// zap-extensions on GitHub at a branch, tag, or commit.
    GitHub { reference: String },
    /// A zap-extensions checkout (upstream paths) or a directory with the files by name.
    Dir(PathBuf),
}

#[derive(Debug, Serialize)]
pub struct UpdateResult {
    pub dir: PathBuf,
    pub commit: String,
    pub updated: Vec<String>,
    pub unchanged: Vec<String>,
    /// Files that failed validation (the previous copy stays in use).
    pub rejected: BTreeMap<String, String>,
}

/// Fetches, validates, and stores the data files. Each file is checked on its own;
/// a rejected file keeps whatever copy was in use before.
pub async fn update(home: &Path, source: Source) -> Result<UpdateResult> {
    let (reference, commit, source_name, texts) = match source {
        Source::GitHub { reference } => {
            let gh = GitHub::new()?;
            let commit = gh.resolve(ZAP_REPO, &reference).await?;
            let mut texts = Vec::new();
            for f in &FILES {
                texts.push(
                    gh.raw_file(ZAP_REPO, &commit, f.upstream).await.map(|b| String::from_utf8_lossy(&b).into_owned()),
                );
            }
            (reference, commit, "github".to_string(), texts)
        }
        Source::Dir(d) => {
            let texts = FILES
                .iter()
                .map(|f| {
                    let p = [d.join(f.upstream), d.join(f.name)].into_iter().find(|p| p.is_file());
                    let p =
                        p.ok_or_else(|| Error::NotFound(format!("{} (or {}) in {}", f.name, f.upstream, d.display())))?;
                    Ok(std::fs::read_to_string(p)?)
                })
                .collect();
            (String::new(), String::new(), format!("dir:{}", d.display()), texts)
        }
    };
    let dir = rules_dir(home);
    std::fs::create_dir_all(&dir)?;
    let mut manifest = read_manifest(&dir).unwrap_or_default();
    let mut result = UpdateResult {
        dir: dir.clone(),
        commit: commit.clone(),
        updated: vec![],
        unchanged: vec![],
        rejected: BTreeMap::new(),
    };
    for (f, text) in FILES.iter().zip(texts) {
        let checked = text.and_then(|t| check(f, &t).map(|n| (t, n)));
        let (text, entries) = match checked {
            Ok(v) => v,
            Err(e) => {
                result.rejected.insert(f.name.to_string(), e.to_string());
                continue;
            }
        };
        let sha256 = sha256_hex(text.as_bytes());
        if manifest.files.get(f.name).is_some_and(|m| m.sha256 == sha256) && dir.join(f.name).is_file() {
            result.unchanged.push(f.name.to_string());
            continue;
        }
        let tmp = dir.join(format!(".{}.tmp", f.name));
        std::fs::write(&tmp, &text)?;
        std::fs::rename(&tmp, dir.join(f.name))?;
        manifest.files.insert(f.name.to_string(), ManifestFile { upstream: f.upstream.to_string(), sha256, entries });
        result.updated.push(f.name.to_string());
    }
    manifest.repository = format!("https://github.com/{ZAP_REPO}");
    manifest.reference = reference;
    manifest.commit = commit;
    manifest.source = source_name;
    manifest.updated_unix =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let tmp = dir.join(".manifest.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&manifest).map_err(|e| Error::Protocol(e.to_string()))?)?;
    std::fs::rename(&tmp, dir.join("manifest.json"))?;
    Ok(result)
}

/// Deletes the stored copies; rules use the embedded data again.
pub fn reset(home: &Path) -> Result<bool> {
    let dir = rules_dir(home);
    if !dir.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(dir)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_files_validate() {
        for f in &FILES {
            let n = (f.validate)(f.embedded).unwrap();
            assert!(n > 0, "{}", f.name);
            assert_eq!(get(f.name), f.embedded);
        }
        assert_eq!(embedded_commit().len(), 40);
    }

    #[tokio::test]
    async fn update_from_dir_validates_and_status_reports() {
        let home = std::env::temp_dir().join(format!("bp-data-{}", std::process::id()));
        let src = home.join("src");
        std::fs::create_dir_all(&src).unwrap();
        for f in &FILES {
            std::fs::write(src.join(f.name), f.embedded).unwrap();
        }
        // One more debug message is accepted; a broken hidden_files.json is rejected.
        std::fs::write(src.join("debug-error-messages.txt"), format!("{}\nBrand new error\n", debug_errors::EMBEDDED))
            .unwrap();
        std::fs::write(src.join("hidden_files.json"), "{\"files\": []}").unwrap();
        let r = update(&home, Source::Dir(src.clone())).await.unwrap();
        assert_eq!(r.updated.len(), 3, "{r:?}");
        assert!(r.rejected["hidden_files.json"].contains("only 0 entries"), "{r:?}");

        let s = status(&home);
        let by = |n: &str| s.files.iter().find(|f| f.name == n).unwrap();
        assert_eq!(by("debug-error-messages.txt").active, "downloaded");
        assert_eq!(by("debug-error-messages.txt").entries, by("debug-error-messages.txt").embedded_entries + 1);
        assert_eq!(by("hidden_files.json").active, "embedded");

        // A stored file edited after the update is ignored.
        std::fs::write(rules_dir(&home).join("debug-error-messages.txt"), "tampered\n").unwrap();
        let s = status(&home);
        assert_eq!(s.files.iter().find(|f| f.name == "debug-error-messages.txt").unwrap().active, "embedded");

        assert!(reset(&home).unwrap());
        assert!(status(&home).manifest.is_none());
        std::fs::remove_dir_all(&home).unwrap();
    }
}
