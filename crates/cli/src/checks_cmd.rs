//! `checks`: declarative checks (Nuclei HTTP template subset + brainproxy extensions).

use std::path::{Path, PathBuf};

use brainproxy_core::checks::{self, Filter, Severity, Source};
use brainproxy_core::Error;
use clap::{Subcommand, ValueEnum};
use serde_json::json;

use crate::output::Out;

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
    /// Download the Nuclei HTTP templates (pinned to a commit) into <home>/checks/nuclei, or import a checkout.
    #[command(after_help = "Downloads go only to GitHub over verified TLS and respect the system scope; the ref is \
        resolved to a commit first and the manifest records it with the tarball's sha256. Only templates that \
        load are stored. On runners without internet access use --from with a nuclei-templates checkout.")]
    Update(UpdateArgs),
    /// Show the template stores: source commit, counts, and skip reasons.
    Status,
    /// Maintain the brainproxy feed: make a signing key, sign a feed folder, verify one.
    #[command(subcommand)]
    Feed(FeedCmd),
}

#[derive(Subcommand)]
pub enum FeedCmd {
    /// Make an Ed25519 signing key; prints the public key for TRUSTED_KEYS (crates/core/src/checks/feed.rs).
    Keygen {
        /// Where to write the private key (owner-only; keep it out of the repository).
        #[arg(long)]
        out: PathBuf,
    },
    /// Write feed.json (every file with its sha256) and feed.sig for a feed folder.
    Sign {
        dir: PathBuf,
        /// The private key from `checks feed keygen`.
        #[arg(long)]
        key: PathBuf,
    },
    /// Check a feed folder's signature and file hashes against the keys this build trusts.
    Verify { dir: PathBuf },
}

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum FeedSource {
    /// projectdiscovery/nuclei-templates, into <home>/checks/nuclei.
    Nuclei,
    /// brainproxy's own signed checks, into <home>/checks/brainproxy.
    Brainproxy,
}

#[derive(clap::Args)]
pub struct ListArgs {
    /// `nuclei`, `local`, `all` (default), or template files/directories.
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
    /// Only checks of at least this template severity (`high` includes critical).
    #[arg(long, value_enum)]
    severity: Option<SeverityArg>,
    /// Only checks of at most this template severity, e.g. `--severity-max medium`.
    #[arg(long, value_enum)]
    severity_max: Option<SeverityArg>,
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
    /// Which checks: Nuclei templates or brainproxy's signed feed.
    #[arg(long, value_enum, default_value = "nuclei")]
    source: FeedSource,
    /// Branch, tag, or commit of the repository. A full 40-character commit id needs no GitHub
    /// API request.
    #[arg(long = "ref", default_value = "main")]
    reference: String,
    /// Default: projectdiscovery/nuclei-templates, or r4nd0mth1ngs/brainproxy for the feed.
    #[arg(long)]
    repo: Option<String>,
    /// Expected sha256 of the tarball (the feed: of feed.json); the update fails on a mismatch.
    #[arg(long)]
    sha256: Option<String>,
    /// Import from a local checkout instead of downloading (the feed's signature is still checked).
    #[arg(long, value_name = "DIR")]
    from: Option<PathBuf>,
    /// Run detached; returns a job id for `job wait|status|stop`.
    #[arg(long)]
    background: bool,
    #[arg(long, hide = true)]
    job_id: Option<i64>,
}

/// A template named by path. Through MCP it is a file in the project's folder (see
/// [`crate::mcp::local_document`]), as a template's requests are sent and its errors read back;
/// a folder is refused, as a link inside it could lead out of the project's.
pub(crate) fn local_template(project: &Path, flag: &str, path: &Path) -> Result<PathBuf, Error> {
    let instead = "put the template there, or use a store (nuclei, brainproxy, local) a person filled";
    let file = crate::mcp::local_path(project, flag, path, instead)?;
    if crate::mcp::in_tool_call() && file.is_dir() {
        return Err(Error::InvalidInput(format!(
            "{flag} {:?}: through MCP name template files, not a folder (a link in it could lead out of the \
             project's folder)",
            path.display().to_string()
        )));
    }
    Ok(file)
}

pub fn checks_cmd(project: &Path, home: &Path, cmd: ChecksCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        ChecksCmd::List(a) => list(project, home, a, out),
        ChecksCmd::Validate { paths, limit, check_vars } => {
            let paths =
                paths.iter().map(|p| local_template(project, "checks validate", p)).collect::<Result<Vec<_>, _>>()?;
            let opts = checks::LoadOptions { vars: check_vars, oob: oob_running(project), ..Default::default() };
            let loaded = checks::load(&paths, &opts)?;
            let files: Vec<_> = loaded
                .checks
                .iter()
                .map(|c| json!({"file": c.file, "id": c.id, "ok": true, "scope": c.scope, "requests": c.requests}))
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
            if a.from.is_some() {
                crate::mcp::check_local_folder("checks update --from", "run it without --from to download them")?;
            }
            if let Some(d) = &a.from {
                if !d.is_dir() {
                    return Err(Error::NotFound(format!("directory {}", d.display())));
                }
            }
            if a.background {
                return crate::jobs_cmd::spawn_background("checks-update", project, home, out);
            }
            let feed = a.source == FeedSource::Brainproxy;
            let default_repo = if feed { checks::feed::FEED_REPO } else { "projectdiscovery/nuclei-templates" };
            let source = match a.from {
                Some(d) => Source::Dir(d),
                None => Source::GitHub {
                    repo: a.repo.unwrap_or_else(|| default_repo.into()),
                    reference: a.reference,
                    sha256: a.sha256,
                },
            };
            let run = || -> Result<serde_json::Value, Error> {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                Ok(if feed {
                    json!(rt.block_on(checks::feed::update(home, source))?)
                } else {
                    json!(rt.block_on(checks::update(home, source))?)
                })
            };
            let v = if a.job_id.is_some() { crate::jobs_cmd::run_job(project, a.job_id, |_| run())? } else { run()? };
            out.ok(v.clone(), || {
                let mut s = format!(
                    "stored {} of {} {} (commit {})",
                    v["stored"],
                    v["templates"],
                    if feed { "feed checks" } else { "HTTP templates" },
                    v["commit"].as_str().filter(|c| !c.is_empty()).unwrap_or("-")
                );
                for kind in ["added", "changed", "removed"] {
                    for f in v["changes"][kind].as_array().into_iter().flatten() {
                        s.push_str(&format!("\n  {kind}: {}", f.as_str().unwrap_or("")));
                    }
                }
                s
            });
            Ok(())
        }
        ChecksCmd::Status => {
            let s = checks::nuclei_status(home);
            let v = json!(s);
            out.ok(v.clone(), || {
                let nuclei = match &s.nuclei {
                    Some(m) => format!("{} templates from {} {} ({})", m.stored, m.repository, m.commit, m.source),
                    None => "none (brainproxy checks update)".into(),
                };
                let feed = match &s.brainproxy {
                    Some(m) => format!(
                        "{} checks, {} {} ({}), signed by {}",
                        m.stored, m.repository, m.commit, m.source, m.signed_by
                    ),
                    None => "none (brainproxy checks update --source brainproxy)".into(),
                };
                format!(
                    "nuclei: {nuclei}\nbrainproxy: {feed}\nlocal: {} files in {}",
                    s.local_files,
                    s.local_dir.display()
                )
            });
            Ok(())
        }
        ChecksCmd::Feed(cmd) => feed(cmd, out),
    }
}

fn list(project: &Path, home: &Path, a: ListArgs, out: &Out) -> Result<(), Error> {
    let (min_severity, max_severity) = severity_band(a.severity, a.severity_max, "--severity")?;
    let selectors = if a.selectors.is_empty() { vec!["all".to_string()] } else { a.selectors.clone() };
    let opts = checks::LoadOptions { vars: a.check_vars.clone(), oob: oob_running(project), ..Default::default() };
    let loaded = checks::load(&checks::resolve_selectors(home, &selectors), &opts)?;
    let filter = Filter {
        ids: vec![],
        tags: a.tags.clone(),
        exclude_tags: a.exclude_tags.clone(),
        min_severity,
        max_severity,
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

fn feed(cmd: FeedCmd, out: &Out) -> Result<(), Error> {
    use checks::feed;
    match cmd {
        FeedCmd::Keygen { out: path } => {
            if path.exists() {
                return Err(Error::InvalidInput(format!("{} exists; not overwriting a key", path.display())));
            }
            let (private, public, id) = feed::keygen()?;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            std::io::Write::write_all(&mut opts.open(&path)?, format!("{private}\n").as_bytes())?;
            let v = json!({"key": path, "public_key": public, "key_id": id});
            out.ok(v, || {
                format!(
                    "private key: {} (keep it secret, back it up)\npublic key {id}: {public}\nadd the public key to TRUSTED_KEYS in crates/core/src/checks/feed.rs",
                    path.display()
                )
            });
        }
        FeedCmd::Sign { dir, key } => {
            let (id, files) = feed::sign(&dir, &std::fs::read_to_string(&key)?)?;
            out.ok(json!({"dir": dir, "key_id": id, "files": files}), || {
                format!("signed {files} files in {} with key {id}", dir.display())
            });
        }
        FeedCmd::Verify { dir } => {
            crate::mcp::check_local_folder(
                "checks feed verify",
                "`checks update --source brainproxy` checks the feed it downloads",
            )?;
            let read = |n: &str| {
                std::fs::read(dir.join(n)).map_err(|e| Error::NotFound(format!("{}: {e}", dir.join(n).display())))
            };
            let (id, list) = feed::verify(&read("feed.json")?, &read("feed.sig")?, feed::TRUSTED_KEYS)?;
            for (rel, want) in &list.files {
                let got = brainproxy_core::fetch::sha256_hex(&read(rel)?);
                if &got != want {
                    return Err(Error::InvalidInput(format!(
                        "{rel}: sha256 {got}, feed.json says {want}; sign the feed again"
                    )));
                }
            }
            out.ok(json!({"dir": dir, "key_id": id, "files": list.files.len()}), || {
                format!("{} files verified, signed by {id}", list.files.len())
            });
        }
    }
    Ok(())
}

/// A template severity for the check filters; `critical` is above `high`.
#[derive(Clone, Copy, ValueEnum)]
pub enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityArg {
    fn get(self) -> Severity {
        [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical][self as usize]
    }
}

/// The severity bounds of `<flag>` and `<flag>-max`, refused when the cap is below the floor.
pub fn severity_band(
    min: Option<SeverityArg>,
    max: Option<SeverityArg>,
    flag: &str,
) -> Result<(Option<Severity>, Option<Severity>), Error> {
    let (min, max) = (min.map(SeverityArg::get), max.map(SeverityArg::get));
    if let (Some(lo), Some(hi)) = (min, max) {
        if hi < lo {
            return Err(Error::InvalidInput(format!("{flag}-max {} is below {flag} {}", hi.as_str(), lo.as_str())));
        }
    }
    Ok((min, max))
}
