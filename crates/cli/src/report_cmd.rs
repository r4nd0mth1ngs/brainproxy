//! `report`: findings as JSON, Markdown, HTML, or SARIF.

use std::path::{Path, PathBuf};

use brainproxy_core::scan::compare;
use brainproxy_core::scan::findings_db::FindingFilter;
use brainproxy_core::scan::passive;
use brainproxy_core::scan::report::{self, ReportKind, ReportOptions};
use brainproxy_core::scan::{Confidence, Risk};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::ValueEnum;
use serde_json::json;

use crate::output::Out;
use crate::scan_cmd::RiskArg;

#[derive(clap::Args)]
pub struct ReportArgs {
    /// Report format.
    #[arg(value_enum, default_value = "json")]
    kind: KindArg,
    /// Write the report to FILE; stdout then gets a short summary (envelope in JSON mode).
    /// An existing file is kept unless --force.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Overwrite an existing --output file.
    #[arg(long)]
    force: bool,
    /// Report title.
    #[arg(long)]
    title: Option<String>,
    /// Minimum risk.
    #[arg(long, value_enum)]
    risk: Option<RiskArg>,
    /// Minimum confidence.
    #[arg(long, value_enum)]
    confidence: Option<ConfidenceArg>,
    /// Only findings from this scanner.
    #[arg(long, value_parser = ["passive", "active", "authz"])]
    source: Option<String>,
    /// Triage state to include (default: open and confirmed, i.e. hides false positives).
    #[arg(long, value_parser = ["open", "confirmed", "false_positive", "false-positive", "all"])]
    state: Option<String>,
    #[arg(long)]
    host: Option<String>,
    /// Alert ref or rule id, e.g. 10020 or 10020-1.
    #[arg(long)]
    alert: Option<String>,
    /// Only what this background active scan found, for the first time or again (`findings
    /// compare --scan`'s new and unchanged), not findings from before it that it didn't see again.
    #[arg(long, value_name = "JOB")]
    scan: Option<i64>,
    /// Maximum findings to include; the summary says when more matched.
    #[arg(long, default_value_t = 500)]
    limit: usize,
    /// Maximum bytes of each request/response body in the evidence.
    #[arg(long, default_value_t = 4096)]
    max_evidence: usize,
    /// Leave out the request/response evidence from history.
    #[arg(long)]
    no_evidence: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    Json,
    #[value(alias = "md")]
    Markdown,
    Html,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ConfidenceArg {
    Low,
    Medium,
    High,
}

impl ConfidenceArg {
    pub fn get(self) -> Confidence {
        match self {
            ConfidenceArg::Low => Confidence::Low,
            ConfidenceArg::Medium => Confidence::Medium,
            ConfidenceArg::High => Confidence::High,
        }
    }
}

impl RiskArg {
    pub fn get(self) -> Risk {
        match self {
            RiskArg::Info => Risk::Info,
            RiskArg::Low => Risk::Low,
            RiskArg::Medium => Risk::Medium,
            RiskArg::High => Risk::High,
        }
    }
}

pub fn report(project: &Path, a: ReportArgs, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    // Like `findings`, reflect everything captured so far.
    passive::scan_pending(&mut store)?;
    let kind = match a.kind {
        KindArg::Json => ReportKind::Json,
        KindArg::Markdown => ReportKind::Markdown,
        KindArg::Html => ReportKind::Html,
        KindArg::Sarif => ReportKind::Sarif,
    };
    let ids = match a.scan {
        Some(job) => {
            let (scope, _) = crate::compare_cmd::scan_baseline(&store, job, false, &mut vec![])?;
            let found = compare::compare_scan(&store, &scope)?;
            Some(found.new.iter().chain(&found.unchanged).filter_map(|f| f.id).collect())
        }
        None => None,
    };
    let opts = ReportOptions {
        filter: FindingFilter {
            min_risk: a.risk.map(RiskArg::get),
            min_confidence: a.confidence.map(ConfidenceArg::get),
            host: a.host,
            alert_ref: a.alert,
            state: a.state,
            source: a.source,
            ids,
            examples: 0,
        },
        title: a.title,
        limit: a.limit,
        evidence: !a.no_evidence,
        max_evidence: a.max_evidence,
        scan: a.scan,
    };
    let r = report::build(&store, &opts)?;
    let summary = json!({
        "kind": kind.as_str(),
        "total": r.summary.total,
        "included": r.summary.included,
        "truncated": r.summary.truncated,
        "alert_types": r.summary.alert_types,
        "by_risk": r.summary.by_risk,
    });

    if let Some(path) = a.output {
        let content = report::render(&r, kind);
        crate::output::write_file(&path, content.as_bytes(), a.force)?;
        let mut data = summary;
        data["path"] = json!(path.display().to_string());
        data["bytes"] = json!(content.len());
        out.ok(data, || {
            format!(
                "wrote {} report to {} ({} of {} findings, {} alert types)",
                kind.as_str(),
                path.display(),
                r.summary.included,
                r.summary.total,
                r.summary.alert_types
            )
        });
    } else if out.json() {
        // The JSON report is the data itself; other formats travel as one string.
        let data = match kind {
            ReportKind::Json => serde_json::to_value(&r).unwrap_or_default(),
            _ => {
                let mut d = summary;
                d["content"] = json!(report::render(&r, kind));
                d
            }
        };
        out.ok(data, String::new);
    } else {
        out.raw(report::render(&r, kind).as_bytes());
    }
    Ok(())
}
