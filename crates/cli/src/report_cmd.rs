//! `report`: findings as JSON, Markdown, HTML, SARIF, PDF or DOCX, in a layout of sections for
//! an audience, with branding; `report-profile` keeps layouts by name.

use std::path::{Path, PathBuf};

use brainproxy_core::scan::compare;
use brainproxy_core::scan::findings_db::FindingFilter;
use brainproxy_core::scan::layout::{self, Layout, LayoutArgs, Preset, Section};
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
    /// Only findings from this scanner, or those added by hand (manual).
    #[arg(long, value_parser = ["passive", "active", "authz", "manual"])]
    source: Option<String>,
    /// Triage state to include (default: work still to do, i.e. open, confirmed and retest
    /// pending: false positives, accepted risks, fixed findings and removed findings added by
    /// hand are left out; all includes them).
    #[arg(long, value_parser = crate::scan_cmd::STATE_VALUES)]
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
    /// Quote session cookies, credentials and tokens as recorded. By default they are shown as
    /// [redacted], here and in the evidence, URLs and bodies the report quotes.
    #[arg(long)]
    no_redact: bool,
    #[command(flatten)]
    layout: LayoutFlags,
    /// Start from this saved layout (`report-profile save`); the flags above override it.
    #[arg(long, value_name = "NAME")]
    profile: Option<String>,
    /// Include narratives nobody has reviewed yet, marked as drafts.
    #[arg(long)]
    drafts: bool,
}

#[derive(clap::Subcommand)]
pub enum SummaryCmd {
    /// The executive summary and who wrote and reviewed it.
    Show,
    /// Write the executive summary ("" clears it). It is a draft, left out of reports (unless
    /// report --drafts), until a person reviews it.
    Set {
        #[arg(long, conflicts_with = "file")]
        text: Option<String>,
        /// Read it from FILE ('-' for stdin; through MCP only '-').
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// Mark the summary reviewed; a person does this, not through MCP.
    Review {
        /// The hash of the text you read (`report-summary show` gives it).
        #[arg(long)]
        hash: String,
    },
}

/// `report-summary`: the executive summary at the top of reports.
pub fn summary(project: &Path, cmd: SummaryCmd, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    match cmd {
        SummaryCmd::Show => {}
        SummaryCmd::Set { text, file } => store.summary_set(&crate::scan_cmd::text_arg("--text", text, file)?)?,
        SummaryCmd::Review { hash } => store.summary_review(&hash)?,
    }
    let n = store.summary()?;
    out.ok(json!({"summary": n}), || match &n {
        Some(n) => format!("{}\n\n({})", n.text, n.credit()),
        None => "no executive summary".into(),
    });
    Ok(())
}

/// How a report looks (HTML, Markdown, PDF, DOCX; JSON adds the posture and retest data).
#[derive(clap::Args, Default)]
pub struct LayoutFlags {
    /// Who it is for: technical (everything; the default), executive (verdict, priorities,
    /// posture, the list of issues), developer (each issue with its evidence and a curl line to
    /// reproduce it), retest (what changed since --since).
    #[arg(long, value_enum)]
    preset: Option<PresetArg>,
    /// Sections in place of the preset's: summary, fixfirst, posture, list, issues, evidence,
    /// reproduce, retest, about.
    #[arg(long, value_delimiter = ',', value_name = "SECTIONS")]
    sections: Option<Vec<String>>,
    /// Who the report is from, on its cover ("" clears a profile's).
    #[arg(long)]
    company: Option<String>,
    /// A PNG, JPEG, GIF or WebP logo for the cover (at most 256 KiB; "" clears a profile's).
    #[arg(long, value_name = "FILE")]
    logo: Option<PathBuf>,
    /// Colour of the cover and headings, #rrggbb ("" clears a profile's).
    #[arg(long, value_name = "COLOUR")]
    accent: Option<String>,
    /// For the retest section: changes from this day on (YYYY-MM-DD; default the last 30 days;
    /// "" clears a profile's).
    #[arg(long, value_name = "DAY")]
    since: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum PresetArg {
    Technical,
    Executive,
    Developer,
    Retest,
}

impl LayoutFlags {
    /// The settings given, a logo read from its file.
    fn args(&self) -> Result<LayoutArgs, Error> {
        let sections = match &self.sections {
            Some(list) => Some(list.iter().map(|s| s.trim().parse()).collect::<Result<Vec<Section>, _>>()?),
            None => None,
        };
        let logo = match &self.logo {
            // An empty path clears a profile's logo.
            Some(path) if path.as_os_str().is_empty() => Some(String::new()),
            // A file would copy whatever the server can read into a report the agent reads back.
            Some(_) if crate::mcp::in_tool_call() => {
                return Err(Error::InvalidInput(
                    "--logo: through MCP no file is read; save the logo in a profile from the app or a terminal \
                     (report-profile save NAME --logo FILE) and use --profile NAME"
                        .into(),
                ))
            }
            Some(path) => {
                let bytes = std::fs::read(path).map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => Error::NotFound(format!("logo {}", path.display())),
                    _ => Error::Io(e),
                })?;
                Some(layout::logo_data_uri(&bytes)?)
            }
            None => None,
        };
        Ok(LayoutArgs {
            preset: self.preset.map(|p| match p {
                PresetArg::Technical => Preset::Technical,
                PresetArg::Executive => Preset::Executive,
                PresetArg::Developer => Preset::Developer,
                PresetArg::Retest => Preset::Retest,
            }),
            sections,
            company: self.company.clone(),
            logo,
            accent: self.accent.clone(),
            since: self.since.clone(),
        })
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    Json,
    #[value(alias = "md")]
    Markdown,
    Html,
    Sarif,
    /// The HTML report printed by a headless Chromium (needs --output).
    Pdf,
    /// A Word document (needs --output).
    Docx,
    /// One row per finding, for spreadsheets.
    Csv,
    /// JUnit XML for CI dashboards: a failing test per open finding.
    Junit,
    /// DefectDojo's Generic Findings Import JSON.
    #[value(name = "defectdojo")]
    DefectDojo,
}

#[derive(clap::Subcommand)]
pub enum ProfileCmd {
    /// Every saved layout.
    List,
    /// One saved layout.
    Show {
        name: String,
    },
    /// Save a layout under NAME (replacing one of that name), from these flags, on top of
    /// --from's when given (a saved logo is kept unless --logo replaces or clears it).
    Save {
        name: String,
        #[arg(long, value_name = "PROFILE")]
        from: Option<String>,
        #[command(flatten)]
        layout: LayoutFlags,
    },
    Remove {
        name: String,
    },
}

/// `report-profile`: saved report layouts.
pub fn profile(project: &Path, cmd: ProfileCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    let shown = |l: &Layout| {
        // A logo is shown by size: it is kilobytes of base64.
        let mut v = serde_json::to_value(l).unwrap_or_default();
        if let Some(logo) = l.logo.as_ref() {
            v["logo"] = json!(format!("{} bytes", logo.len()));
        }
        v
    };
    match cmd {
        ProfileCmd::List => {
            let list: Vec<serde_json::Value> = store
                .report_profiles()?
                .iter()
                .map(|(name, l, updated)| json!({"name": name, "layout": shown(l), "updated": updated}))
                .collect();
            out.ok(json!({"profiles": list}), || {
                list.iter()
                    .map(|p| format!("{}  {}", p["name"].as_str().unwrap_or(""), p["layout"]))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        ProfileCmd::Show { name } => {
            let l = store.report_profile(&name)?;
            let v = json!({"name": name, "layout": shown(&l)});
            out.ok(v.clone(), || serde_json::to_string_pretty(&v).unwrap_or_default());
        }
        ProfileCmd::Save { name, from, layout } => {
            let base = match &from {
                Some(p) => store.report_profile(p)?,
                None => Layout::default(),
            };
            let l = base.overlay(&layout.args()?);
            store.report_profile_save(&name, &l)?;
            out.ok(json!({"name": name, "layout": shown(&l)}), || format!("saved report profile {name}"));
        }
        ProfileCmd::Remove { name } => {
            store.report_profile_remove(&name)?;
            out.ok(json!({"name": name, "removed": true}), || format!("removed report profile {name}"));
        }
    }
    Ok(())
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
            RiskArg::Critical => Risk::Critical,
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
        KindArg::Html | KindArg::Pdf | KindArg::Docx => ReportKind::Html,
        KindArg::Sarif => ReportKind::Sarif,
        KindArg::Csv => ReportKind::Csv,
        KindArg::Junit => ReportKind::Junit,
        KindArg::DefectDojo => ReportKind::DefectDojo,
    };
    let binary = matches!(a.kind, KindArg::Pdf | KindArg::Docx);
    if binary && a.output.is_none() {
        return Err(Error::InvalidInput("a PDF or DOCX report needs --output FILE".into()));
    }
    let base = match &a.profile {
        Some(name) => store.report_profile(name)?,
        None => Layout::default(),
    };
    let layout = base.overlay(&a.layout.args()?);
    layout.validate()?;
    // Found before anything is built, so a missing browser fails fast.
    let browser = match a.kind {
        KindArg::Pdf => Some(crate::browser_cmd::chromium(None)?),
        _ => None,
    };
    // With a scan: its findings, and whether each is new in it or was found before (SARIF's
    // baselineState).
    let (ids, baseline) = match a.scan {
        Some(job) => {
            let (scope, _) = crate::compare_cmd::scan_baseline(&store, job, false, &mut vec![])?;
            let found = compare::compare_scan(&store, &scope)?;
            let baseline: std::collections::HashMap<i64, bool> = found
                .new
                .iter()
                .map(|f| (f, true))
                .chain(found.unchanged.iter().map(|f| (f, false)))
                .filter_map(|(f, new)| Some((f.id?, new)))
                .collect();
            (Some(baseline.keys().copied().collect()), Some(baseline))
        }
        None => (None, None),
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
            issue: None,
            examples: 0,
        },
        title: a.title,
        limit: a.limit,
        evidence: !a.no_evidence,
        max_evidence: a.max_evidence,
        scan: a.scan,
        baseline,
        redact: !a.no_redact,
        layout,
        drafts: a.drafts,
    };
    let r = report::build(&store, &opts)?;
    let kind_name = match a.kind {
        KindArg::Pdf => "pdf",
        KindArg::Docx => "docx",
        _ => kind.as_str(),
    };
    let summary = json!({
        "kind": kind_name,
        "preset": r.layout.preset.as_str(),
        "total": r.summary.total,
        "included": r.summary.included,
        "truncated": r.summary.truncated,
        "alert_types": r.summary.alert_types,
        "by_risk": r.summary.by_risk,
        "redacted": r.summary.redacted,
    });

    if let Some(path) = a.output {
        let content: Vec<u8> = match (a.kind, browser) {
            (KindArg::Pdf, Some(browser)) => {
                let html = report::render_print_html(&r);
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(Error::Io)?;
                rt.block_on(brainproxy_core::browser_crawl::print_pdf(&browser, &html))?
            }
            (KindArg::Docx, _) => report::render_docx(&r),
            _ => report::render(&r, kind).into_bytes(),
        };
        crate::output::write_file(&path, &content, a.force)?;
        let mut data = summary;
        data["path"] = json!(path.display().to_string());
        data["bytes"] = json!(content.len());
        out.ok(data, || {
            format!(
                "wrote {} report to {} ({} of {} findings, {} alert types)",
                kind_name,
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
