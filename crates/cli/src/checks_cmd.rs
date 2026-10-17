//! `checks`: declarative checks (Nuclei HTTP template subset + brainproxy extensions).

use std::path::{Path, PathBuf};

use brainproxy_core::checks::{self, Filter, Source};
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
    },
    /// Download the Nuclei HTTP templates (pinned to a commit) into <home>/checks/nuclei, or import a checkout.
    #[command(after_help = "Downloads go only to GitHub over verified TLS and respect the system scope; the ref is \
        resolved to a commit first and the manifest records it with the tarball's sha256. Only templates that \
        load are stored. On runners without internet access use --from with a nuclei-templates checkout.")]
    Update(UpdateArgs),
    /// Show the template stores: source commit, counts, and skip reasons.
    Status,
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
    #[arg(long, value_enum)]
    severity: Option<RiskArg>,
    /// List templates that were not loaded instead.
    #[arg(long)]
    skipped: bool,
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

#[derive(clap::Args)]
pub struct UpdateArgs {
    /// Branch, tag, or commit of the templates repository.
    #[arg(long = "ref", default_value = "main")]
    reference: String,
    #[arg(long, default_value = "projectdiscovery/nuclei-templates")]
    repo: String,
    /// Expected sha256 of the tarball; the update fails on a mismatch.
    #[arg(long)]
    sha256: Option<String>,
    /// Import from a local nuclei-templates checkout instead of downloading.
    #[arg(long, value_name = "DIR")]
    from: Option<PathBuf>,
    /// Run detached; returns a job id for `job wait|status|stop`.
    #[arg(long)]
    background: bool,
    #[arg(long, hide = true)]
    job_id: Option<i64>,
}

pub fn checks_cmd(project: &Path, home: &Path, cmd: ChecksCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        ChecksCmd::List(a) => list(home, a, out),
        ChecksCmd::Validate { paths, limit } => {
            let loaded = checks::load(&paths)?;
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
            if let Some(d) = &a.from {
                if !d.is_dir() {
                    return Err(Error::NotFound(format!("directory {}", d.display())));
                }
            }
            if a.background {
                return crate::jobs_cmd::spawn_background("checks-update", project, home, out);
            }
            let source = match a.from {
                Some(d) => Source::Dir(d),
                None => Source::GitHub { repo: a.repo, reference: a.reference, sha256: a.sha256 },
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
        ChecksCmd::Status => {
            let s = checks::nuclei_status(home);
            let v = json!(s);
            out.ok(v.clone(), || {
                let nuclei = match &s.nuclei {
                    Some(m) => format!("{} templates from {} {} ({})", m.stored, m.repository, m.commit, m.source),
                    None => "none (brainproxy checks update)".into(),
                };
                format!("nuclei: {nuclei}\nlocal: {} files in {}", s.local_files, s.local_dir.display())
            });
            Ok(())
        }
    }
}

fn list(home: &Path, a: ListArgs, out: &Out) -> Result<(), Error> {
    let selectors = if a.selectors.is_empty() { vec!["all".to_string()] } else { a.selectors.clone() };
    let loaded = checks::load(&checks::resolve_selectors(home, &selectors))?;
    let filter = Filter {
        ids: vec![],
        tags: a.tags.clone(),
        exclude_tags: a.exclude_tags.clone(),
        min_risk: a.severity.map(RiskArg::get),
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
