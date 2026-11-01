//! `findings compare`: new, unchanged, and fixed findings against a baseline, and the severity
//! gate CI runs on them. The logic is in `brainproxy_core::scan::compare`; the desktop app's
//! compare view calls this command.

use std::path::{Path, PathBuf};

use brainproxy_core::scan::compare::{self, Item, ScanScope};
use brainproxy_core::scan::passive;
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Parser;
use serde_json::{json, Map, Value};

use crate::output::Out;
use crate::scan_cmd::RiskArg;

/// The process exit code when `--fail-on` finds something.
pub const GATE_FAILED: i32 = 5;

#[derive(clap::Args)]
pub struct CompareArgs {
    /// Baseline findings: a file from `report json`. Without --baseline or --scan the baseline
    /// is empty, so every finding is new.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Compare with an empty baseline, instead of failing, when the --baseline file doesn't
    /// exist (a first run). Every finding is then new, so a gate still sees them all.
    #[arg(long, requires = "baseline")]
    allow_missing_baseline: bool,
    /// The findings to compare, from a `report json` file, instead of the --project ones.
    #[arg(long, value_name = "FILE", conflicts_with = "scan")]
    current: Option<PathBuf>,
    /// Compare with a background active scan of this project, by job id: first found by it,
    /// found again by it, or covered by it and not found again.
    #[arg(long, value_name = "JOB", conflicts_with = "baseline")]
    scan: Option<i64>,
    /// Exit with code 5 when a finding at or above this risk is present (false positives never
    /// count, and with --scan only what that scan found counts).
    #[arg(long, value_enum, value_name = "RISK")]
    fail_on: Option<RiskArg>,
    /// With --fail-on: only count new findings, not those already in the baseline.
    #[arg(long, requires = "fail_on")]
    new_only: bool,
    /// Triage state to list: open, confirmed, false_positive, or all (default hides false
    /// positives). --fail-on doesn't depend on it.
    #[arg(long, value_parser = ["open", "confirmed", "false_positive", "false-positive", "all"])]
    state: Option<String>,
    /// Maximum findings listed per group; counts and the gate always cover all of them.
    #[arg(long, default_value_t = 1000)]
    limit: usize,
}

pub fn compare(project: &Path, a: CompareArgs, out: &Out) -> Result<(), Error> {
    let mut warnings = Vec::new();
    let mut baseline = json!({"kind": "none"});
    let mut current = json!({"kind": "project", "path": project});
    let comparison = if let Some(job) = a.scan {
        let store = open_project(project)?;
        let (scope, scan) = scan_baseline(&store, job, a.fail_on.is_some(), &mut warnings)?;
        baseline = scan;
        compare::compare_scan(&store, &scope)?
    } else {
        if let Some(path) = &a.baseline {
            refuse_same_file(path, a.current.as_deref().unwrap_or(project))?;
        }
        let base = match &a.baseline {
            None => vec![],
            Some(path) if a.allow_missing_baseline && !path.exists() => {
                baseline = json!({"kind": "none", "path": path, "missing": true});
                warnings.push(format!("no baseline at {}: every finding counts as new", path.display()));
                vec![]
            }
            Some(path) => {
                let set = compare::load_set(path)?;
                baseline = json!({"kind": "report", "path": path, "missing": false});
                warnings.extend(set.warnings);
                set.items
            }
        };
        let items = match &a.current {
            Some(path) => {
                let set = compare::load_set(path)?;
                // Findings a filter left out would pass the gate unseen.
                if let (Some(why), true) = (set.warnings.first(), a.fail_on.is_some()) {
                    return Err(Error::InvalidInput(format!("--fail-on needs every finding: {why}")));
                }
                current = json!({"kind": "report", "path": path});
                warnings.extend(set.warnings);
                set.items
            }
            None => compare::project_items(&open_project(project)?)?,
        };
        compare::compare_sets(base, items)
    };

    let gate = a.fail_on.map(|risk| {
        let risk = risk.get();
        (risk, comparison.gate(risk, a.new_only))
    });
    let failed = gate.as_ref().is_some_and(|(_, hits)| !hits.is_empty());
    let gate_json = gate.as_ref().map_or(Value::Null, |(risk, hits)| {
        json!({
            "fail_on": risk.as_str(),
            "new_only": a.new_only,
            "passed": !failed,
            "exit_code": if failed { GATE_FAILED } else { 0 },
            "count": hits.len(),
            "findings": hits.iter().take(a.limit).collect::<Vec<_>>(),
        })
    });

    let (new, unchanged, fixed) = (
        listed(&comparison.new, &a.state),
        listed(&comparison.unchanged, &a.state),
        listed(&comparison.fixed, &a.state),
    );
    let gate_cut = gate.as_ref().is_some_and(|(_, hits)| hits.len() > a.limit);
    let truncated = gate_cut || [&new, &unchanged, &fixed].iter().any(|l| l.len() > a.limit);
    let data = json!({
        "baseline": baseline,
        "current": current,
        "summary": {
            "new": new.len(),
            "unchanged": unchanged.len(),
            "fixed": fixed.len(),
            "other": comparison.other,
            "by_risk": {"new": by_risk(&new), "unchanged": by_risk(&unchanged), "fixed": by_risk(&fixed)},
            "truncated": truncated,
        },
        "new": &new[..new.len().min(a.limit)],
        "unchanged": &unchanged[..unchanged.len().min(a.limit)],
        "fixed": &fixed[..fixed.len().min(a.limit)],
        "gate": gate_json,
        "warnings": warnings,
    });
    out.ok(data.clone(), || text(&data));
    if failed {
        std::process::exit(GATE_FAILED);
    }
    Ok(())
}

/// The project as it stands, with everything captured so far passively scanned. Unlike most
/// commands this doesn't create it: a gate on a mistyped path must not pass on an empty project.
fn open_project(project: &Path) -> Result<Store, Error> {
    if !project.exists() {
        return Err(Error::NotFound(format!("project {}", project.display())));
    }
    let mut store = Store::open(project)?;
    passive::scan_pending(&mut store)?;
    Ok(store)
}

/// A file compared with itself would show nothing new and pass any gate.
fn refuse_same_file(baseline: &Path, current: &Path) -> Result<(), Error> {
    match (std::fs::canonicalize(baseline), std::fs::canonicalize(current)) {
        (Ok(b), Ok(c)) if b == c => Err(Error::InvalidInput(format!(
            "the baseline and the findings to compare are the same file: {}",
            b.display()
        ))),
        _ => Ok(()),
    }
}

/// The job's scope and how it is shown as the baseline. A gate needs the scan to have finished:
/// a failed one found nothing, which would otherwise pass.
fn scan_baseline(
    store: &Store,
    id: i64,
    gating: bool,
    warnings: &mut Vec<String>,
) -> Result<(ScanScope, Value), Error> {
    let job = store.job_get(id)?;
    let (kind, state) = (job["kind"].as_str().unwrap_or(""), job["state"].as_str().unwrap_or(""));
    if kind != "active-scan" {
        return Err(Error::InvalidInput(format!("job {id} is a {kind} job, not an active scan")));
    }
    // --max-minutes ends a scan early, yet it completes: only its result says so.
    let result = &job["result"];
    let timed_out = result["timed_out"] == true || result["crawl"]["timed_out"] == true;
    let incomplete = match state {
        "completed" if timed_out => Some("timed out".to_string()),
        "completed" => None,
        other => Some(other.to_string()),
    };
    if let Some(how) = incomplete {
        if gating {
            return Err(Error::Conflict(format!(
                "job {id} is {how}, so a gate can't vouch for it; wait for a scan that completes"
            )));
        }
        warnings.push(format!("job {id} is {how}: it may not have covered everything, so \"fixed\" may overstate"));
    }
    let args: Vec<String> = serde_json::from_value(job["args"].clone()).unwrap_or_default();
    let mut scope = match crate::Cli::try_parse_from(std::iter::once("brainproxy".to_string()).chain(args)) {
        Ok(crate::Cli { command: crate::Cmd::Scan(crate::scan_cmd::ScanCmd::Active(a)), .. }) => a.scope(),
        // Written by another version, say: nothing is known to be covered, so nothing is "fixed".
        _ => {
            warnings.push(format!("job {id}'s arguments can't be read: nothing counts as fixed"));
            ScanScope { origins: Some(vec![]), ..Default::default() }
        }
    };
    scope.start = job["time"].as_str().unwrap_or_default().to_string();
    scope.end = job["finished_time"].as_str().map(str::to_string);
    let shown = json!({"kind": "scan", "job": id, "state": state, "scope": scope});
    Ok((scope, shown))
}

/// The findings a --state shows (default: all but false positives).
fn listed<'a>(items: &'a [Item], state: &Option<String>) -> Vec<&'a Item> {
    let state = state.as_ref().map(|s| s.replace('-', "_"));
    items
        .iter()
        .filter(|f| match state.as_deref() {
            None => !f.false_positive(),
            Some("all") => true,
            Some(s) => f.state == s,
        })
        .collect()
}

fn by_risk(items: &[&Item]) -> Value {
    let mut counts = Map::new();
    for f in items {
        let n = counts.get(&f.risk).and_then(Value::as_u64).unwrap_or(0) + 1;
        counts.insert(f.risk.clone(), json!(n));
    }
    Value::Object(counts)
}

fn text(data: &Value) -> String {
    let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let row = |title: &str, f: &Value| {
        format!("{title:<6} {:<6} {:<45} {} {}", s(&f["risk"]), s(&f["name"]), s(&f["url"]), s(&f["param"]))
    };
    let list = |v: &Value| v.as_array().cloned().unwrap_or_default();
    let mut lines: Vec<String> = list(&data["warnings"]).iter().map(|w| format!("warning: {}", s(w))).collect();
    let sum = &data["summary"];
    lines.push(format!("{} new, {} unchanged, {} fixed", sum["new"], sum["unchanged"], sum["fixed"]));
    if sum["other"].as_u64().unwrap_or(0) > 0 {
        lines.push(format!("{} outside the scan", sum["other"]));
    }
    lines.extend(list(&data["new"]).iter().map(|f| row("new", f)));
    lines.extend(list(&data["fixed"]).iter().map(|f| row("fixed", f)));
    let gate = &data["gate"];
    if !gate.is_null() {
        let what = if gate["new_only"] == true { "new findings" } else { "findings" };
        let risk = s(&gate["fail_on"]);
        if gate["passed"] == true {
            lines.push(format!("gate passed: no {what} at or above {risk}"));
        } else {
            lines.extend(list(&gate["findings"]).iter().map(|f| row("gate", f)));
            lines.push(format!("gate FAILED: {} {what} at or above {risk}", gate["count"]));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(args: &[&str]) -> ScanScope {
        let argv = ["brainproxy", "scan", "active"].iter().chain(args).map(|s| s.to_string());
        match crate::Cli::try_parse_from(argv) {
            Ok(crate::Cli { command: crate::Cmd::Scan(crate::scan_cmd::ScanCmd::Active(a)), .. }) => a.scope(),
            _ => panic!("bad args {args:?}"),
        }
    }

    #[test]
    fn a_scans_scope_comes_from_its_arguments() {
        let s =
            scope(&["http://a.test:8080/x", "b.test:81", "--crawl", "--strength", "medium", "--rules=40018,100002"]);
        assert_eq!(s.origins.unwrap(), ["http://a.test:8080", "https://b.test:81"]);
        assert_eq!(s.rules.unwrap(), [40018, 100002]);
        assert!(s.exclude_rules.is_empty() && s.ported_rules && s.check_ids.is_empty() && s.crawled);
        // A site after a flag, and the default port, as the scan itself reads them.
        assert_eq!(scope(&["--strength", "low", "http://a.test:80/"]).origins.unwrap(), ["http://a.test"]);
        assert_eq!(scope(&[]).origins, None);
        // A preset changes how hard the scan attacks, not what it covers.
        let p = scope(&["http://a.test:8080/x", "--crawl", "--preset", "standard"]);
        assert_eq!((p.origins.unwrap(), p.crawled), (vec!["http://a.test:8080".to_string()], true));
        // Requests picked by a filter: no site counts as covered.
        assert_eq!(scope(&["--history-id", "5"]).origins.unwrap(), Vec::<String>::new());
        assert_eq!(scope(&["--where", "1=1"]).origins.unwrap(), Vec::<String>::new());
        let t = scope(&["a.test", "--no-rules", "--checks", "nuclei", "--check-ids=x,y", "--exclude-rules", "40018"]);
        assert_eq!(
            (t.ported_rules, t.check_ids, t.exclude_rules),
            (false, vec!["x".to_string(), "y".to_string()], vec![40018])
        );
        // Checks picked by severity or tags: which ran isn't known.
        assert!(scope(&["a.test", "--checks", "nuclei", "--check-severity", "high"]).check_ids.is_empty());
        assert!(scope(&["a.test", "--checks", "nuclei", "--check-ids", "x", "--check-tags", "cve"])
            .check_ids
            .is_empty());
    }
}
