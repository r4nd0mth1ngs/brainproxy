//! `checks`: declarative checks (Nuclei HTTP template subset + brainproxy extensions).

use std::path::{Path, PathBuf};

use brainproxy_core::checks::{self, FeedSource, Filter, Source};
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::json;

use crate::output::Out;
use crate::scan_cmd::RiskArg;

#[derive(Subcommand)]
pub enum ChecksCmd {
    /// List loadable checks (and, with --skipped, templates that were not loaded and why).
    List(ListArgs),
    /// Parse templates and report, per file, whether they load and why not.
    Validate {
        /// Template files or directories.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// A template input (Nuclei's -var), as for `scan active --check-var`. Repeatable.
        #[arg(long = "check-var", value_name = "NAME=VALUE", value_parser = check_var)]
        check_vars: Vec<(String, String)>,
    },
    /// Download checks pinned to a commit: the Nuclei HTTP templates into <home>/checks/nuclei
    /// (default), or brainproxy's own signed feed into <home>/checks/brainproxy (--source brainproxy).
    #[command(after_help = "Downloads go only to GitHub over verified TLS and respect the system scope; the ref is \
        resolved to a commit first and the manifest records it with the tarball's sha256. Only Nuclei templates \
        that load are stored. The brainproxy feed must be signed by a key built into brainproxy: the signature \
        and every file's sha256 are checked before anything is stored, and an older feed than the installed one \
        is refused. On runners without internet access use --from with a checkout (the same checks apply).")]
    Update(UpdateArgs),
    /// Show the check stores: source commit, counts, and skip reasons.
    Status,
    /// Maintain the brainproxy feed: create a signing key, sign the feed, verify a signature.
    #[command(subcommand)]
    Feed(FeedCmd),
}

#[derive(Subcommand)]
pub enum FeedCmd {
    /// Create an Ed25519 signing key (never overwrites); prints the public key for
    /// crates/core/src/checks/feed_keys.txt. Keep the key file offline.
    Keygen {
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Write feed.json (every check with its sha256, a new serial) and feed.sig for a feed folder.
    Sign {
        /// The feed folder (checks/ in the brainproxy repository).
        #[arg(default_value = "checks")]
        dir: PathBuf,
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
    },
    /// Check a feed folder's signature and files against the keys built into this brainproxy.
    Verify {
        #[arg(default_value = "checks")]
        dir: PathBuf,
    },
}

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum UpdateSource {
    /// projectdiscovery/nuclei-templates.
    Nuclei,
    /// brainproxy's own signed checks feed.
    Brainproxy,
}

#[derive(clap::Args)]
pub struct ListArgs {
    /// `brainproxy`, `nuclei`, `local`, `all` (default), or template files/directories.
    selectors: Vec<String>,
    /// Only checks whose id or name contains this text.
    #[arg(long)]
    filter: Option<String>,
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    exclude_tags: Vec<String>,
    /// Also list checks with these tags (or in a folder of that name), whatever the other
    /// filters say, as `scan active --check-include-tags` selects them.
    #[arg(long, value_delimiter = ',')]
    include_tags: Vec<String>,
    #[arg(long, value_enum)]
    severity: Option<RiskArg>,
    /// List templates that were not loaded instead.
    #[arg(long)]
    skipped: bool,
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// A template input (Nuclei's -var), as for `scan active --check-var`. Repeatable.
    #[arg(long = "check-var", value_name = "NAME=VALUE", value_parser = check_var)]
    check_vars: Vec<(String, String)>,
}

/// clap parser for `--check-var NAME=VALUE`.
pub fn check_var(s: &str) -> Result<(String, String), String> {
    checks::parse_var(s).map_err(|e| e.to_string())
}

/// Whether the project has a running OOB listener (interactsh templates load
/// then, as they would for `scan active`). A missing project has none.
fn oob_running(project: &Path) -> bool {
    project.is_file()
        && brainproxy_core::store::Store::open(project)
            .ok()
            .and_then(|s| crate::oob_cmd::running(&s).ok().flatten())
            .is_some()
}

#[derive(clap::Args)]
pub struct UpdateArgs {
    /// Which checks to update.
    #[arg(long, value_enum, default_value = "nuclei")]
    source: UpdateSource,
    /// Branch, tag, or commit of the repository.
    #[arg(long = "ref", default_value = "main")]
    reference: String,
    /// Repository (default: projectdiscovery/nuclei-templates, or r4nd0mth1ngs/brainproxy for the feed).
    #[arg(long)]
    repo: Option<String>,
    /// Expected sha256 of the tarball; the update fails on a mismatch (Nuclei templates).
    #[arg(long, conflicts_with = "from")]
    sha256: Option<String>,
    /// Import from a local checkout instead of downloading (a nuclei-templates checkout, or
    /// the brainproxy repository or its checks/ folder).
    #[arg(long, value_name = "DIR")]
    from: Option<PathBuf>,
    /// Install a brainproxy feed older than the installed one (normally refused as a rollback).
    #[arg(long)]
    allow_downgrade: bool,
    /// Run detached; returns a job id for `job wait|status|stop`.
    #[arg(long)]
    background: bool,
    #[arg(long, hide = true)]
    job_id: Option<i64>,
}

pub fn checks_cmd(project: &Path, home: &Path, cmd: ChecksCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        ChecksCmd::List(a) => list(project, home, a, out),
        ChecksCmd::Validate { paths, limit, check_vars } => {
            let opts = checks::LoadOptions { vars: check_vars, oob: oob_running(project), ..Default::default() };
            let loaded = checks::load(&paths, &opts)?;
            let files: Vec<_> = loaded
                .checks
                .iter()
                .map(|c| {
                    json!({"file": c.file, "id": c.id, "ok": true, "scope": c.scope, "requests": c.requests,
                        "passive": c.passive})
                })
                .chain(
                    loaded
                        .skipped
                        .iter()
                        .map(|s| json!({"file": s.file, "id": s.id, "ok": false, "kind": s.kind, "reason": s.reason})),
                )
                .collect();
            let total = files.len();
            let shown: Vec<_> = files.into_iter().take(limit).collect();
            let data = json!({"ok": loaded.checks.len(), "not_loaded": loaded.skipped.len(), "files": shown,
                "truncated": total > limit});
            out.ok(data, || {
                let mut lines = vec![format!("{} loaded, {} not loaded", loaded.checks.len(), loaded.skipped.len())];
                for s in loaded.skipped.iter().take(limit) {
                    lines.push(format!("  {}: {} ({})", s.file.display(), s.reason, s.kind));
                }
                lines.join("\n")
            });
            Ok(())
        }
        ChecksCmd::Update(a) => {
            if let Some(d) = &a.from {
                if !d.is_dir() {
                    return Err(Error::NotFound(format!("directory {}", d.display())));
                }
            }
            if a.background {
                return crate::jobs_cmd::spawn_background("checks-update", project, home, out);
            }
            if a.source == UpdateSource::Brainproxy {
                return update_feed(project, home, a, out);
            }
            let source = match a.from {
                Some(d) => Source::Dir(d),
                None => Source::GitHub {
                    repo: a.repo.unwrap_or_else(|| "projectdiscovery/nuclei-templates".into()),
                    reference: a.reference,
                    sha256: a.sha256,
                },
            };
            let run = || -> Result<serde_json::Value, Error> {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                Ok(json!(rt.block_on(checks::update(home, source))?))
            };
            let v = if a.job_id.is_some() { crate::jobs_cmd::run_job(project, a.job_id, |_| run())? } else { run()? };
            out.ok(v.clone(), || {
                format!(
                    "stored {} of {} HTTP templates (commit {})",
                    v["stored"],
                    v["templates"],
                    v["commit"].as_str().filter(|c| !c.is_empty()).unwrap_or("-")
                )
            });
            Ok(())
        }
        ChecksCmd::Feed(cmd) => feed(cmd, out),
        ChecksCmd::Status => {
            let s = checks::nuclei_status(home);
            let feed = checks::feed_status(home);
            let mut v = json!(s);
            v["brainproxy"] = json!(feed);
            out.ok(v.clone(), || {
                let brainproxy = match &feed.installed {
                    Some(f) => {
                        let from = if f.repository.is_empty() {
                            f.source.clone()
                        } else {
                            format!("{} {}", f.repository, short(&f.commit))
                        };
                        format!("{} checks ({} passive) from {from}, serial {}", f.checks, f.passive, f.serial)
                    }
                    None => "none (brainproxy checks update --source brainproxy)".into(),
                };
                let nuclei = match &s.nuclei {
                    Some(m) => format!("{} templates from {} {} ({})", m.stored, m.repository, m.commit, m.source),
                    None => "none (brainproxy checks update)".into(),
                };
                format!(
                    "brainproxy: {brainproxy}\nnuclei: {nuclei}\nlocal: {} files in {}",
                    s.local_files,
                    s.local_dir.display()
                )
            });
            Ok(())
        }
    }
}

fn list(project: &Path, home: &Path, a: ListArgs, out: &Out) -> Result<(), Error> {
    let selectors = if a.selectors.is_empty() { vec!["all".to_string()] } else { a.selectors.clone() };
    let opts = checks::LoadOptions { vars: a.check_vars.clone(), oob: oob_running(project), ..Default::default() };
    let loaded = checks::load(&checks::resolve_selectors(home, &selectors), &opts)?;
    let filter = Filter {
        ids: vec![],
        tags: a.tags.clone(),
        exclude_tags: a.exclude_tags.clone(),
        min_risk: a.severity.map(RiskArg::get),
        include_tags: a.include_tags.clone(),
    };
    let text = a.filter.as_deref().map(str::to_ascii_lowercase);
    let matching: Vec<&checks::Check> = loaded
        .checks
        .iter()
        .filter(|c| filter.keep(c))
        .filter(|c| {
            text.as_deref()
                .is_none_or(|t| c.id.to_ascii_lowercase().contains(t) || c.name.to_ascii_lowercase().contains(t))
        })
        .collect();
    let mut data = json!({
        "loaded": loaded.checks.len(),
        "matching": matching.len(),
        "not_loaded": loaded.skipped.len(),
        "not_loaded_reasons": loaded.reasons().into_iter().take(10).collect::<Vec<_>>(),
    });
    if a.skipped {
        data["skipped"] = json!(loaded.skipped.iter().take(a.limit).collect::<Vec<_>>());
        data["truncated"] = json!(loaded.skipped.len() > a.limit);
    } else {
        data["checks"] = json!(matching.iter().take(a.limit).collect::<Vec<_>>());
        data["truncated"] = json!(matching.len() > a.limit);
    }
    out.ok(data, || {
        let mut lines = vec![format!(
            "{} checks ({} matching), {} templates not loaded",
            loaded.checks.len(),
            matching.len(),
            loaded.skipped.len()
        )];
        if a.skipped {
            for s in loaded.skipped.iter().take(a.limit) {
                lines.push(format!("  {}: {}", s.file.display(), s.reason));
            }
        } else {
            for c in matching.iter().take(a.limit) {
                lines.push(format!("  {:<8} {:<40} {}", c.severity, c.id, c.name));
            }
        }
        lines.join("\n")
    });
    Ok(())
}

fn short(commit: &str) -> &str {
    if commit.is_empty() {
        "-"
    } else {
        &commit[..commit.len().min(10)]
    }
}

/// `checks update --source brainproxy`: the signed feed into <home>/checks/brainproxy.
fn update_feed(project: &Path, home: &Path, a: UpdateArgs, out: &Out) -> Result<(), Error> {
    if a.sha256.is_some() {
        return Err(Error::InvalidInput(
            "--sha256 is for Nuclei templates; the feed is checked by its signature".into(),
        ));
    }
    let source = match a.from {
        Some(d) => FeedSource::Dir(d),
        None => FeedSource::GitHub { repo: a.repo.unwrap_or_else(|| checks::FEED_REPO.into()), reference: a.reference },
    };
    let allow_downgrade = a.allow_downgrade;
    let run = || -> Result<serde_json::Value, Error> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        Ok(json!(rt.block_on(checks::update_feed(home, source, &checks::trusted_keys(), allow_downgrade))?))
    };
    let v = if a.job_id.is_some() { crate::jobs_cmd::run_job(project, a.job_id, |_| run())? } else { run()? };
    out.ok(v.clone(), || {
        let mut lines = vec![format!(
            "brainproxy feed: {} checks ({} passive), serial {}, commit {}{}",
            v["checks"],
            v["passive"],
            v["serial"],
            short(v["commit"].as_str().unwrap_or("")),
            if v["unchanged"] == true { ", unchanged" } else { "" }
        )];
        for (what, key) in [("added", "added"), ("changed", "changed"), ("removed", "removed")] {
            for c in v[key].as_array().into_iter().flatten() {
                let id = c["id"].as_str().map(|i| format!(" ({i})")).unwrap_or_default();
                lines.push(format!("  {what:<8} {}{id}", c["file"].as_str().unwrap_or("")));
            }
        }
        for s in v["skipped"].as_array().into_iter().flatten() {
            lines.push(format!("  not loaded: {}: {}", s[0].as_str().unwrap_or(""), s[1].as_str().unwrap_or("")));
        }
        lines.join("\n")
    });
    Ok(())
}

fn feed(cmd: FeedCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        FeedCmd::Keygen { out: path } => {
            let public = checks::keygen(&path)?;
            let v = json!({"key_file": path, "public_key": public});
            out.ok(v, || {
                format!(
                    "secret key written to {} (keep it offline)\npublic key, for crates/core/src/checks/feed_keys.txt:\n{public}",
                    path.display()
                )
            });
        }
        FeedCmd::Sign { dir, key } => {
            let (m, key_id) = checks::sign_feed(&dir, &key)?;
            let v = json!({"dir": dir, "serial": m.serial, "files": m.files.len(), "key": key_id,
                "public_key": checks::public_key(&key)?});
            out.ok(v, || {
                format!("signed {} files in {} (serial {}, key {key_id})", m.files.len(), dir.display(), m.serial)
            });
        }
        FeedCmd::Verify { dir } => {
            let m = checks::verify_dir(&dir, None)?;
            let v = json!({"dir": dir, "serial": m.serial, "files": m.files.len()});
            out.ok(v, || {
                format!("{}: signature and {} files check out (serial {})", dir.display(), m.files.len(), m.serial)
            });
        }
    }
    Ok(())
}
