//! CLI for the passive scanner and findings.

use std::path::Path;

use brainproxy_core::scan::findings_db::{FindingFilter, ManualFinding};
use brainproxy_core::scan::passive::{self, PassiveSettings, SETTINGS_KEY};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::{Subcommand, ValueEnum};
use serde_json::json;

use crate::output::Out;

#[derive(Subcommand)]
pub enum ScanCmd {
    /// Active scan: attack targets with the active rules (all requests stay inside the engagement scope).
    #[command(after_help = "From history, GET, HEAD, OPTIONS and POST requests are attacked by default; others \
        need --include-methods or --history-id. POST requests are replayed with attack payloads, often many \
        times, and can change data or trigger side effects such as email. \
        When any are attacked, the result has post_targets (how many) and post_hint.")]
    Active(Box<crate::active_cmd::ActiveArgs>),
    /// Run the passive rules over captures not scanned yet (this also happens
    /// automatically after send, proxy traffic, and before `findings`).
    Passive {
        /// Rescan all history and count passive findings again. Findings found again keep their
        /// id, state, note and who set them; ones not found again are removed, except triaged
        /// ones (state changed or a note), which are kept with 0 hits.
        #[arg(long)]
        rescan: bool,
    },
    /// List passive rules (or active rules with --active) and whether they're enabled.
    Rules {
        /// Only rules whose name or id contains this text.
        #[arg(long)]
        filter: Option<String>,
        /// List the active rules instead.
        #[arg(long)]
        active: bool,
    },
    /// Enable passive rules by id, or passive checks by check id.
    Enable { ids: Vec<String> },
    /// Disable passive rules by id, or passive checks by check id.
    Disable { ids: Vec<String> },
    /// ZAP data files the rules read (error patterns, hidden files, sensitive names): status, update, reset.
    #[command(subcommand)]
    Data(DataCmd),
    /// Show, or with SOURCES replace, which history sources are passively scanned (default: proxy,send,crawl,crawl-browser).
    Sources {
        #[arg(value_delimiter = ',')]
        sources: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum DataCmd {
    /// Which copy (embedded or downloaded) each data file uses, with entry counts.
    Status,
    /// Fetch the data files from zap-extensions at a ref (resolved to a commit), validate, and store them.
    #[command(after_help = "Files go to <home>/rules with a manifest (commit, sha256). Each file is parsed with the \
        rules' own parser and must keep at least half the embedded entries; a rejected file keeps the previous \
        copy. Downloads go only to GitHub over verified TLS and respect the system scope; offline, use --from \
        with a zap-extensions checkout or a directory holding the files. New data applies to commands started \
        afterwards (restart a running proxy).")]
    Update {
        /// Branch, tag, or commit of zaproxy/zap-extensions. A full 40-character commit id needs
        /// no GitHub API request.
        #[arg(long = "ref", default_value = "main")]
        reference: String,
        #[arg(long, value_name = "DIR")]
        from: Option<std::path::PathBuf>,
    },
    /// Delete the downloaded copies; rules use the embedded data again.
    Reset,
}

#[derive(Subcommand)]
pub enum FindingsCmd {
    /// Findings grouped by alert type (default), or one row per instance with --all.
    List {
        /// Minimum risk.
        #[arg(long, value_enum)]
        risk: Option<RiskArg>,
        /// Minimum confidence.
        #[arg(long, value_enum)]
        confidence: Option<crate::report_cmd::ConfidenceArg>,
        #[arg(long)]
        host: Option<String>,
        /// Alert ref or rule id, e.g. 10020 or 10020-1.
        #[arg(long)]
        alert: Option<String>,
        /// open, confirmed, false_positive, fixed, accepted_risk, retest_pending, removed, or all,
        /// or several separated by commas (default: work still to do, so it hides false
        /// positives, fixed and accepted findings, and removed findings added by hand).
        #[arg(long)]
        state: Option<String>,
        /// Only findings from this scanner, or those added by hand (manual).
        #[arg(long, value_parser = ["passive", "active", "authz", "manual"])]
        source: Option<String>,
        /// One row per instance instead of grouping.
        #[arg(long)]
        all: bool,
        /// Example URLs per group.
        #[arg(long, default_value_t = 3)]
        examples: usize,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Compare findings with a baseline (new, unchanged, fixed) and optionally fail on a risk (exit code 5).
    #[command(
        after_help = "The baseline is a file (`report json --state all --no-evidence`), a background active scan of this project (--scan), or nothing, when every finding is new. Findings \
        match by alert, method, URL without its query, and parameter. A false-positive or accepted-risk mark on either side stays \
        with the finding. Findings added by hand are outside every --scan (no scan looks for them); against a \
        file they compare like any other. Exit codes: 5 when --fail-on finds something; 4 when the baseline, project, or job \
        doesn't exist (--allow-missing-baseline treats a missing baseline file as empty); 2 for a baseline that \
        isn't usable or a --fail-on on a scan that didn't complete. The full result is printed in every case."
    )]
    Compare(crate::compare_cmd::CompareArgs),
    /// One finding with description, solution, references, and evidence.
    Show { id: i64 },
    /// Issues: one root cause (an alert type on one host) with the findings it was seen at,
    /// riskiest first.
    Issues {
        /// Minimum risk.
        #[arg(long, value_enum)]
        risk: Option<RiskArg>,
        /// Minimum confidence.
        #[arg(long, value_enum)]
        confidence: Option<crate::report_cmd::ConfidenceArg>,
        #[arg(long)]
        host: Option<String>,
        /// Alert ref or rule id, e.g. 10020 or 10020-1.
        #[arg(long)]
        alert: Option<String>,
        /// States of the findings counted, as for `findings list` (default: work still to do).
        #[arg(long)]
        state: Option<String>,
        /// Only findings from this scanner, or those added by hand (manual).
        #[arg(long, value_parser = ["passive", "active", "authz", "manual"])]
        source: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Show, split, merge, or rename an issue.
    #[command(subcommand)]
    Issue(IssueCmd),
    /// A finding's timeline: found, triaged, noted, retested, moved between issues, seen again
    /// after it was fixed, removed; each with who did it and when.
    Timeline { id: i64 },
    /// Send a finding's request again and record whether it is still there.
    #[command(after_help = "Passive findings: the latest request is sent again (history source retest) \
        and the finding's own rule reads that response. Not reproduced marks it fixed, and a fixed or \
        retest_pending finding still there is open again (--no-mark records the outcome only; false \
        positives and accepted risks keep their state). A rule that is switched off is refused (kind \
        conflict), and so is a reply of another status class than the finding's request had (a \
        login redirect, an error page) that doesn't show it. Only GET, HEAD and OPTIONS are sent unless --allow-unsafe. Active findings are \
        retested by scanning again (the error gives the command), findings added by hand by hand, and \
        access-control findings with authz run. The outcome is on the finding's timeline.")]
    Retest(crate::retest_cmd::RetestArgs),
    /// Open work at a glance: open issues and findings by risk, findings by state, risk ×
    /// confidence, the hosts with most open findings, what each active scan found new and no
    /// longer found, retest outcomes and regressions.
    Posture,
    /// Triage one or more findings, or every finding of an issue: all of them change, or none does.
    Mark {
        /// One or more finding ids. (Named `id`, so an agent's `{"id": 5}` keeps working.)
        #[arg(value_name = "ID", required_unless_present = "issue", num_args = 1..)]
        id: Vec<i64>,
        /// Every finding of this issue (`findings issues`), as well as any IDs given. Repeatable.
        #[arg(long, value_name = "ISSUE")]
        issue: Vec<i64>,
        #[arg(long, value_enum)]
        state: Option<StateArg>,
        /// A note on the finding, shown in reports; an empty note clears it. Either way the
        /// finding counts as triaged, so a rescan that no longer finds it keeps it.
        #[arg(long)]
        note: Option<String>,
    },
    /// Record a finding by hand, such as one from a manual test (source manual). Nothing is sent.
    #[command(after_help = "Findings with the same title share an alert type (manual:<title>), which holds the \
        description and solution: leaving one out keeps the type's, and one that differs from it is refused \
        (kind conflict) unless --replace-text, which keeps the earlier text (findings show lists it in \
        replaced_texts). The same title, method, URL without its query, and parameter as an existing finding \
        is refused (kind conflict). Without --url, the URL and method are the first --history-id entry's; a \
        linked entry on another host or port is warned about. The first linked entry is the report's \
        evidence. Through MCP, the *-file flags only take '-' (the call's stdin) and --replace-text is \
        refused. Text on the command line is visible in the process list; --input-json keeps the URL, \
        evidence and write-ups off it.")]
    Add(Box<AddArgs>),
    /// Remove findings added by hand (`findings add`); scanner findings can only be marked.
    #[command(after_help = "A removed finding is kept with state removed, hidden unless --state all, so a \
        compare against a baseline that had it lists it as removed, not fixed. findings show says when it \
        was removed and the state it had. The same issue can be added again. Refused through MCP: an agent \
        marks a finding false_positive with a note instead.")]
    Remove {
        #[arg(required = true)]
        ids: Vec<i64>,
    },
}

#[derive(Subcommand)]
pub enum IssueCmd {
    /// One issue with its findings and its own timeline (title changes).
    Show { id: i64 },
    /// Move findings out of their issue into a new one: two bugs that share a rule and host.
    Split {
        /// Findings of one issue.
        #[arg(required = true)]
        findings: Vec<i64>,
        /// The new issue's title (default: the alert's name).
        #[arg(long)]
        title: Option<String>,
    },
    /// Move every finding of the other issues into the first: one bug seen on several hosts.
    Merge {
        into: i64,
        #[arg(required = true)]
        from: Vec<i64>,
    },
    /// Give an issue a title of its own, shown in place of the alert's name; "" restores it.
    Title { id: i64, title: String },
}

#[derive(clap::Args)]
pub struct AddArgs {
    /// The issue's name, as reports show it.
    #[arg(long)]
    title: String,
    #[arg(long, value_enum)]
    risk: RiskArg,
    #[arg(long, value_enum, default_value = "medium")]
    confidence: crate::report_cmd::ConfidenceArg,
    /// Where it is: an http(s) or ws(s) URL. Default: the first --history-id entry's.
    #[arg(long)]
    url: Option<String>,
    /// Request method. Default: the first --history-id entry's, else GET.
    #[arg(long)]
    method: Option<String>,
    /// Affected parameter, header, or cookie.
    #[arg(long, default_value = "")]
    param: String,
    #[arg(long, value_name = "ID")]
    cwe: Option<u32>,
    /// History entries that show it (repeatable or comma-separated); the first is the evidence.
    #[arg(long = "history-id", value_name = "ID", value_delimiter = ',')]
    history: Vec<i64>,
    /// What the issue is and why it matters.
    #[arg(long, conflicts_with = "description_file")]
    description: Option<String>,
    /// Read the description from FILE ('-' reads stdin).
    #[arg(long, value_name = "FILE")]
    description_file: Option<String>,
    /// How to fix it.
    #[arg(long, conflicts_with = "solution_file")]
    solution: Option<String>,
    /// Read the solution from FILE ('-' reads stdin).
    #[arg(long, value_name = "FILE")]
    solution_file: Option<String>,
    /// What shows it, such as a line of the response.
    #[arg(long, conflicts_with = "evidence_file")]
    evidence: Option<String>,
    /// Read the evidence from FILE ('-' reads stdin).
    #[arg(long, value_name = "FILE")]
    evidence_file: Option<String>,
    /// Read JSON from stdin: {"description": "...", "solution": "...", "evidence": "...", "url":
    /// "...", "method": "..."}. Each is optional; use it instead of the text flags above (and of
    /// --url and --method, to keep a token in the URL out of the process list).
    #[arg(long, conflicts_with_all = [
        "description", "description_file", "solution", "solution_file", "evidence", "evidence_file",
    ])]
    input_json: bool,
    /// Replace the description or solution that findings with this title share when the one
    /// given differs (the earlier text is kept). Refused through MCP.
    #[arg(long)]
    replace_text: bool,
}

/// What `--input-json` reads from stdin.
#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TextInput {
    #[serde(default)]
    description: String,
    #[serde(default)]
    solution: String,
    #[serde(default)]
    evidence: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    method: Option<String>,
}

impl AddArgs {
    /// The finding, with long texts read from their files or stdin.
    fn finding(self) -> Result<ManualFinding, Error> {
        let stdin_readers = [&self.description_file, &self.solution_file, &self.evidence_file]
            .iter()
            .filter(|f| f.as_deref() == Some("-"))
            .count();
        if stdin_readers > 1 {
            return Err(Error::InvalidInput(
                "only one of --description-file, --solution-file and --evidence-file can read stdin".into(),
            ));
        }
        // An agent can't tell whose write-up it would replace, so it can't replace one.
        if self.replace_text && crate::mcp::in_tool_call() {
            return Err(Error::InvalidInput(
                "--replace-text is refused through MCP: the shared write-up may be a person's; leave the \
                 description and solution out, or use another title"
                    .into(),
            ));
        }
        let texts: TextInput = if self.input_json {
            serde_json::from_slice(&crate::read_input(None)?)
                .map_err(|e| Error::InvalidInput(format!("--input-json: {e}")))?
        } else {
            TextInput {
                description: text_arg("--description-file", self.description, self.description_file)?,
                solution: text_arg("--solution-file", self.solution, self.solution_file)?,
                evidence: text_arg("--evidence-file", self.evidence, self.evidence_file)?,
                url: None,
                method: None,
            }
        };
        for (flag, given, from_json) in [("--url", &self.url, &texts.url), ("--method", &self.method, &texts.method)] {
            if given.is_some() && from_json.is_some() {
                return Err(Error::InvalidInput(format!(
                    "give the {} either as {flag} or in --input-json, not both",
                    &flag[2..]
                )));
            }
        }
        Ok(ManualFinding {
            title: self.title,
            risk: self.risk.get(),
            confidence: self.confidence.get(),
            url: self.url.or(texts.url),
            method: self.method.or(texts.method),
            param: self.param,
            evidence: texts.evidence,
            description: texts.description,
            solution: texts.solution,
            cwe: self.cwe,
            history: self.history,
            replace_text: self.replace_text,
        })
    }
}

/// A text flag's value, or its file's ('-' reads stdin). Through MCP only stdin: a file would
/// copy anything the server can read into the project, for the agent to read back.
fn text_arg(flag: &str, text: Option<String>, file: Option<String>) -> Result<String, Error> {
    match file.as_deref() {
        None => Ok(text.unwrap_or_default()),
        Some("-") => String::from_utf8(crate::read_input(None)?)
            .map_err(|_| Error::InvalidInput(format!("{flag}: stdin is not UTF-8 text"))),
        Some(_) if crate::mcp::in_tool_call() => Err(Error::InvalidInput(format!(
            "{flag}: through MCP only '-' is accepted (pass the text as the call's stdin)"
        ))),
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => String::from_utf8(bytes).map_err(|_| Error::InvalidInput(format!("{flag}: not UTF-8 text"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NotFound(format!("{flag} {path}"))),
            Err(e) => Err(e.into()),
        },
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum RiskArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// What `--state` takes where one state picks findings (report, compare).
pub const STATE_VALUES: [&str; 11] = [
    "open",
    "confirmed",
    "false_positive",
    "false-positive",
    "fixed",
    "accepted_risk",
    "accepted-risk",
    "retest_pending",
    "retest-pending",
    "removed",
    "all",
];

#[derive(Clone, Copy, ValueEnum)]
pub enum StateArg {
    Open,
    Confirmed,
    #[value(alias = "false_positive")]
    FalsePositive,
    /// No longer there (a retest that doesn't reproduce it sets this too).
    Fixed,
    /// Known and accepted, not to be fixed; left out of gates like a false positive.
    #[value(alias = "accepted_risk")]
    AcceptedRisk,
    /// Fixed by the developers, waiting for a retest.
    #[value(alias = "retest_pending")]
    RetestPending,
}

impl StateArg {
    pub fn as_str(self) -> &'static str {
        match self {
            StateArg::Open => "open",
            StateArg::Confirmed => "confirmed",
            StateArg::FalsePositive => "false_positive",
            StateArg::Fixed => "fixed",
            StateArg::AcceptedRisk => "accepted_risk",
            StateArg::RetestPending => "retest_pending",
        }
    }
}

pub fn scan(project: &Path, home: &Path, cmd: ScanCmd, out: &Out) -> Result<(), Error> {
    if let ScanCmd::Active(args) = cmd {
        return crate::active_cmd::active(project, home, *args, out);
    }
    if let ScanCmd::Data(cmd) = cmd {
        return data_cmd(home, cmd, out);
    }
    let mut store = Store::open(project)?;
    match cmd {
        ScanCmd::Active(_) | ScanCmd::Data(_) => unreachable!(),
        ScanCmd::Passive { rescan } => {
            let stats = if rescan { passive::rescan(&mut store)? } else { passive::scan_pending(&mut store)? };
            out.ok(json!(stats), || {
                let mut text = format!("scanned {} captures, {} new findings", stats.scanned, stats.new_findings);
                if let (Some(removed), Some(kept)) = (stats.removed, stats.kept_not_found) {
                    text += &format!(
                        "; {removed} not found again and removed, {kept} triaged ones not found again and kept"
                    );
                }
                text
            });
        }
        ScanCmd::Rules { filter, active: true } => {
            let rules: Vec<_> = brainproxy_core::scan::active::all_rules()
                .iter()
                .filter(|r| {
                    filter.as_deref().is_none_or(|f| {
                        r.name().to_ascii_lowercase().contains(&f.to_ascii_lowercase()) || r.id().to_string().contains(f)
                    })
                })
                .map(|r| {
                    let max_risk = r.alerts().iter().map(|a| a.risk).max().map(|r| r.as_str());
                    json!({"id": r.id(), "name": r.name(), "scope": r.scope(), "max_risk": max_risk,
                        "alerts": r.alerts().iter().map(|a| json!({"alert_ref": a.alert_ref, "name": a.name, "risk": a.risk.as_str()})).collect::<Vec<_>>()})
                })
                .collect();
            out.ok(json!({"count": rules.len(), "rules": rules}), || {
                rules
                    .iter()
                    .map(|r| {
                        format!(
                            "{:>6}  {:<6} {:<7} {}",
                            r["id"],
                            r["scope"].as_str().unwrap_or(""),
                            r["max_risk"].as_str().unwrap_or(""),
                            r["name"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        ScanCmd::Rules { filter, .. } => {
            let settings: PassiveSettings = store.setting(SETTINGS_KEY)?;
            let rules: Vec<_> = passive::all_rules()
                .iter()
                .filter(|r| {
                    filter.as_deref().is_none_or(|f| {
                        r.name().to_ascii_lowercase().contains(&f.to_ascii_lowercase()) || r.id().to_string().contains(f)
                    })
                })
                .map(|r| {
                    let max_risk = r.alerts().iter().map(|a| a.risk).max().map(|r| r.as_str());
                    json!({
                        "id": r.id(),
                        "name": r.name(),
                        "enabled": !settings.disabled.contains(&r.id()),
                        "max_risk": max_risk,
                        "alerts": r.alerts().iter().map(|a| json!({"alert_ref": a.alert_ref, "name": a.name, "risk": a.risk.as_str()})).collect::<Vec<_>>(),
                    })
                })
                .chain(passive::checks().iter().filter(|c| {
                    filter.as_deref().is_none_or(|f| {
                        let f = f.to_ascii_lowercase();
                        c.def().name.to_ascii_lowercase().contains(&f) || c.id().to_ascii_lowercase().contains(&f)
                    })
                }).map(|c| {
                    let d = c.def();
                    json!({
                        "id": c.id(),
                        "name": d.name,
                        "check": true,
                        "enabled": !settings.disabled_checks.iter().any(|x| x == c.id()),
                        "max_risk": d.risk.as_str(),
                        "alerts": [{"alert_ref": d.alert_ref, "name": d.name, "risk": d.risk.as_str()}],
                    })
                }))
                .collect();
            out.ok(json!({"count": rules.len(), "sources": settings.sources, "rules": rules}), || {
                rules
                    .iter()
                    .map(|r| {
                        format!(
                            "{:>6}  {:<4} {:<7} {}",
                            r["id"],
                            if r["enabled"] == true { "on" } else { "off" },
                            r["max_risk"].as_str().unwrap_or(""),
                            r["name"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        ScanCmd::Enable { ids } => update_disabled(&store, &ids, false, out)?,
        ScanCmd::Disable { ids } => update_disabled(&store, &ids, true, out)?,
        ScanCmd::Sources { sources } => {
            let mut settings: PassiveSettings = store.setting(SETTINGS_KEY)?;
            // No arguments shows the current list; it used to clear it.
            if !sources.is_empty() {
                settings.sources = sources;
                store.set_setting(SETTINGS_KEY, &settings)?;
            }
            out.ok(json!(settings), || format!("passive sources: {}", settings.sources.join(",")));
        }
    }
    Ok(())
}

/// `ids` are rule ids (numbers) or passive check ids.
fn update_disabled(store: &Store, ids: &[String], disable: bool, out: &Out) -> Result<(), Error> {
    if ids.is_empty() {
        return Err(Error::InvalidInput("give at least one rule id".into()));
    }
    let known: Vec<u32> = passive::all_rules().iter().map(|r| r.id()).collect();
    let (mut rules, mut checks) = (Vec::new(), Vec::new());
    for id in ids {
        match id.parse::<u32>() {
            Ok(n) if known.contains(&n) => rules.push(n),
            Ok(_) => return Err(Error::NotFound(format!("passive rule {id}"))),
            Err(_) if passive::checks().iter().any(|c| c.id() == id) => checks.push(id.clone()),
            Err(_) => return Err(Error::NotFound(format!("passive rule or check {id}"))),
        }
    }
    let mut settings: PassiveSettings = store.setting(SETTINGS_KEY)?;
    settings.disabled.retain(|d| !rules.contains(d));
    settings.disabled_checks.retain(|d| !checks.contains(d));
    if disable {
        settings.disabled.extend_from_slice(&rules);
        settings.disabled_checks.extend(checks);
    }
    settings.disabled.sort_unstable();
    settings.disabled_checks.sort();
    store.set_setting(SETTINGS_KEY, &settings)?;
    out.ok(json!(settings), || format!("disabled rules: {:?}", settings.disabled));
    Ok(())
}

pub fn findings(project: &Path, cmd: FindingsCmd, out: &Out) -> Result<(), Error> {
    if let FindingsCmd::Compare(args) = cmd {
        return crate::compare_cmd::compare(project, args, out);
    }
    if let FindingsCmd::Retest(args) = cmd {
        return crate::retest_cmd::retest(project, args, out);
    }
    let mut store = Store::open(project)?;
    // Findings always reflect everything captured so far.
    passive::scan_pending(&mut store)?;
    match cmd {
        FindingsCmd::Compare(_) | FindingsCmd::Retest(_) => unreachable!(),
        FindingsCmd::Issues { risk, confidence, host, alert, state, source, limit } => {
            let filter = FindingFilter {
                min_risk: risk.map(RiskArg::get),
                min_confidence: confidence.map(|c| c.get()),
                host,
                alert_ref: alert,
                state,
                source,
                ids: None,
                issue: None,
                examples: 0,
            };
            let issues = store.issues_list(&filter, limit)?;
            out.ok(json!({"count": issues.len(), "issues": issues}), || {
                issues
                    .iter()
                    .map(|i| {
                        format!(
                            "{:>5}  {:<8} {:<50} {}  {} instance(s)",
                            i["id"],
                            i["risk"].as_str().unwrap_or(""),
                            i["title"].as_str().unwrap_or(""),
                            i["host"].as_str().unwrap_or(""),
                            i["instances"]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        FindingsCmd::Issue(cmd) => match cmd {
            IssueCmd::Show { id } => {
                let issue = store.issue_get(id)?;
                out.ok(issue.clone(), || serde_json::to_string_pretty(&issue).unwrap_or_default());
            }
            IssueCmd::Split { findings, title } => {
                let id = store.issue_split(&findings, title.as_deref())?;
                out.ok(json!({"issue": id, "findings": findings}), || {
                    format!("moved {} finding(s) to new issue {id}", findings.len())
                });
            }
            IssueCmd::Merge { into, from } => {
                let moved = store.issues_merge(into, &from)?;
                out.ok(json!({"into": into, "from": from, "moved": moved}), || {
                    format!("moved {moved} finding(s) into issue {into}")
                });
            }
            IssueCmd::Title { id, title } => {
                store.issue_set_title(id, &title)?;
                let issue = store.issue_get(id).ok();
                let shown = issue.as_ref().map(|i| i["title"].clone()).unwrap_or(json!(title));
                out.ok(json!({"id": id, "title": shown}), || format!("issue {id} is now {shown}"));
            }
        },
        FindingsCmd::Timeline { id } => {
            let events = store.finding_events(id)?;
            out.ok(json!({"id": id, "events": events}), || {
                events
                    .iter()
                    .map(|e| {
                        let change = match (e["old"].as_str(), e["new"].as_str()) {
                            (Some(o), Some(n)) => format!("{o} -> {n}"),
                            (None, Some(n)) => n.to_string(),
                            _ => String::new(),
                        };
                        format!(
                            "{}  {:<9} {change} {}  ({})",
                            e["time"].as_str().unwrap_or(""),
                            e["kind"].as_str().unwrap_or(""),
                            e["text"].as_str().unwrap_or(""),
                            e["by"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        FindingsCmd::Posture => {
            let p = store.posture()?;
            out.ok(p.clone(), || serde_json::to_string_pretty(&p).unwrap_or_default());
        }
        FindingsCmd::List { risk, confidence, host, alert, state, source, all, examples, limit } => {
            let filter = FindingFilter {
                min_risk: risk.map(RiskArg::get),
                min_confidence: confidence.map(|c| c.get()),
                host,
                alert_ref: alert,
                state,
                source,
                ids: None,
                issue: None,
                examples,
            };
            if all {
                let items = store.findings_list(&filter, limit)?;
                out.ok(json!({"count": items.len(), "items": items}), || {
                    items
                        .iter()
                        .map(|f| {
                            format!(
                                "{:>5}  {:<6} {:<45} {} {}  (added {})",
                                f["id"],
                                f["risk"].as_str().unwrap_or(""),
                                f["name"].as_str().unwrap_or(""),
                                f["url"].as_str().unwrap_or(""),
                                f["param"].as_str().unwrap_or(""),
                                brainproxy_core::provenance::describe(f["origin"].as_str())
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                });
            } else {
                let groups = store.findings_grouped(&filter)?;
                let mut by_risk = serde_json::Map::new();
                for g in &groups {
                    let r = g["risk"].as_str().unwrap_or("info").to_string();
                    let n = by_risk.get(&r).and_then(|v| v.as_i64()).unwrap_or(0) + 1;
                    by_risk.insert(r, json!(n));
                }
                out.ok(json!({"alert_types": groups.len(), "by_risk": by_risk, "groups": groups}), || {
                    groups
                        .iter()
                        .map(|g| {
                            format!(
                                "{:<6} {:<8} {:<50} {} instance(s)",
                                g["risk"].as_str().unwrap_or(""),
                                g["alert_ref"].as_str().unwrap_or(""),
                                g["name"].as_str().unwrap_or(""),
                                g["instances"]
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                });
            }
        }
        FindingsCmd::Show { id } => {
            let f = store.finding_get(id)?;
            out.ok(f.clone(), || serde_json::to_string_pretty(&f).unwrap_or_default());
        }
        FindingsCmd::Mark { id: mut ids, issue, state, note } => {
            if state.is_none() && note.is_none() {
                return Err(Error::InvalidInput("give --state and/or --note".into()));
            }
            for i in issue {
                ids.extend(store.issue_finding_ids(i)?);
            }
            ids.sort_unstable();
            ids.dedup();
            let state = state.map(StateArg::as_str);
            store.findings_mark(&ids, state, note.as_deref())?;
            // `note` is as given: "" when it was cleared, null when it was left alone.
            match ids.as_slice() {
                [id] => out.ok(json!({"id": id, "ids": ids, "state": state, "note": note}), || {
                    format!("updated finding {id}")
                }),
                _ => out.ok(json!({"ids": ids, "state": state, "note": note}), || {
                    format!("updated {} findings", ids.len())
                }),
            }
        }
        FindingsCmd::Add(args) => {
            let f = args.finding()?;
            let replaced = store.manual_texts_replaced(&f)?;
            let id = store.finding_add(&f)?;
            let finding = store.finding_get(id)?;
            let url = finding["url"].as_str().unwrap_or_default();
            let mut warnings: Vec<String> = outside_scope(&store, url).into_iter().collect();
            if !replaced.is_empty() {
                warnings.push(format!(
                    "replaced the {} that every finding titled {:?} shares (the earlier text is kept in replaced_texts)",
                    replaced.join(" and "),
                    f.title.trim()
                ));
            }
            // An entry on another site may be linked by mistake, and would be the report's evidence.
            let links = store.finding_links(id)?;
            for l in links.iter().filter(|l| l["other_site"] == true) {
                warnings.push(format!(
                    "history entry {} is {} {}, not on the finding's host and port",
                    l["id"],
                    l["method"].as_str().unwrap_or_default(),
                    l["url"].as_str().unwrap_or_default()
                ));
            }
            let text = format!("added finding {id} ({})", finding["alert_ref"].as_str().unwrap_or_default());
            out.ok(json!({"id": id, "finding": finding, "history": links, "warnings": warnings}), || {
                warnings.iter().map(|w| format!("warning: {w}\n")).collect::<String>() + &text
            });
        }
        FindingsCmd::Remove { ids } => {
            // An agent can't tell a person's finding from its own, so it marks rather than removes.
            if crate::mcp::in_tool_call() {
                return Err(Error::InvalidInput(
                    "findings remove is refused through MCP: mark the finding false_positive with a note instead"
                        .into(),
                ));
            }
            let removed = store.findings_remove(&ids)?;
            out.ok(json!({"removed": removed, "ids": ids}), || format!("removed {removed} finding(s)"));
        }
    }
    Ok(())
}

/// A warning when a finding's URL can't be in the engagement scope. Nothing is sent, so it is
/// recorded anyway; the report would still show a site that wasn't to be tested.
fn outside_scope(store: &Store, url: &str) -> Option<String> {
    store.engagement().ok().flatten()?;
    let http = url.strip_prefix("ws").map_or_else(|| url.to_string(), |rest| format!("http{rest}"));
    let target = brainproxy_core::http::Target::from_url(&http).ok()?;
    let guard = store.guard().ok()?;
    (!guard.may_allow(&target.host, target.port))
        .then(|| format!("{}:{} is outside the engagement scope", target.host, target.port))
}

fn data_cmd(home: &Path, cmd: DataCmd, out: &Out) -> Result<(), Error> {
    use brainproxy_core::data;
    match cmd {
        DataCmd::Status => {
            let s = data::status(home);
            let v = json!(s);
            out.ok(v, || {
                let mut lines = vec![format!("embedded copies from zap-extensions {}", s.embedded_commit)];
                for f in &s.files {
                    lines.push(format!("  {:<42} {:<10} {} entries", f.name, f.active, f.entries));
                }
                lines.join("\n")
            });
        }
        DataCmd::Update { reference, from } => {
            let source = match from {
                Some(d) => data::Source::Dir(d),
                None => data::Source::GitHub { reference },
            };
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            let r = rt.block_on(data::update(home, source))?;
            let v = json!(r);
            out.ok(v, || {
                let mut s = format!("updated {:?}, unchanged {:?}", r.updated, r.unchanged);
                for (f, why) in &r.rejected {
                    s.push_str(&format!("\nrejected {f}: {why}"));
                }
                s
            });
        }
        DataCmd::Reset => {
            let removed = data::reset(home)?;
            out.ok(json!({"removed": removed}), || {
                if removed {
                    "removed downloaded data; using embedded copies".into()
                } else {
                    "nothing to remove".into()
                }
            });
        }
    }
    Ok(())
}
