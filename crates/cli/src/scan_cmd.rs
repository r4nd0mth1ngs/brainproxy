//! CLI for the passive scanner and findings.

use std::path::Path;

use brainproxy_core::scan::findings_db::FindingFilter;
use brainproxy_core::scan::passive::{self, PassiveSettings, SETTINGS_KEY};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::{Subcommand, ValueEnum};
use serde_json::json;

use crate::output::Out;

#[derive(Subcommand)]
pub enum ScanCmd {
    /// Active scan: attack targets with the active rules (all requests stay inside the engagement scope).
    Active(Box<crate::active_cmd::ActiveArgs>),
    /// Run the passive rules over captures not scanned yet (this also happens
    /// automatically after send, proxy traffic, and before `findings`).
    Passive {
        /// Delete passive findings and rescan all history.
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
    /// Enable passive rules by id.
    Enable { ids: Vec<u32> },
    /// Disable passive rules by id.
    Disable { ids: Vec<u32> },
    /// ZAP data files the rules read (error patterns, hidden files, sensitive names): status, update, reset.
    #[command(subcommand)]
    Data(DataCmd),
    /// Choose which history sources are passively scanned (default: proxy,send,crawl).
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
        /// Branch, tag, or commit of zaproxy/zap-extensions.
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
        /// open, confirmed, false_positive, or all (default hides false positives).
        #[arg(long)]
        state: Option<String>,
        /// Only findings from this scanner.
        #[arg(long, value_parser = ["passive", "active"])]
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
    /// One finding with description, solution, references, and evidence.
    Show { id: i64 },
    /// Triage a finding.
    Mark {
        id: i64,
        #[arg(long, value_enum)]
        state: Option<StateArg>,
        #[arg(long)]
        note: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum RiskArg {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum StateArg {
    Open,
    Confirmed,
    #[value(alias = "false_positive")]
    FalsePositive,
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
            out.ok(json!(stats), || format!("scanned {} captures, {} new findings", stats.scanned, stats.new_findings));
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
            settings.sources = sources;
            store.set_setting(SETTINGS_KEY, &settings)?;
            out.ok(json!(settings), || format!("passive sources: {}", settings.sources.join(",")));
        }
    }
    Ok(())
}

fn update_disabled(store: &Store, ids: &[u32], disable: bool, out: &Out) -> Result<(), Error> {
    if ids.is_empty() {
        return Err(Error::InvalidInput("give at least one rule id".into()));
    }
    let known: Vec<u32> = passive::all_rules().iter().map(|r| r.id()).collect();
    if let Some(bad) = ids.iter().find(|id| !known.contains(id)) {
        return Err(Error::NotFound(format!("passive rule {bad}")));
    }
    let mut settings: PassiveSettings = store.setting(SETTINGS_KEY)?;
    settings.disabled.retain(|d| !ids.contains(d));
    if disable {
        settings.disabled.extend_from_slice(ids);
    }
    settings.disabled.sort_unstable();
    store.set_setting(SETTINGS_KEY, &settings)?;
    out.ok(json!(settings), || format!("disabled rules: {:?}", settings.disabled));
    Ok(())
}

pub fn findings(project: &Path, cmd: FindingsCmd, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    // Findings always reflect everything captured so far.
    passive::scan_pending(&mut store)?;
    match cmd {
        FindingsCmd::List { risk, confidence, host, alert, state, source, all, examples, limit } => {
            let filter = FindingFilter {
                min_risk: risk.map(RiskArg::get),
                min_confidence: confidence.map(|c| c.get()),
                host,
                alert_ref: alert,
                state,
                source,
                examples,
            };
            if all {
                let items = store.findings_list(&filter, limit)?;
                out.ok(json!({"count": items.len(), "items": items}), || {
                    items
                        .iter()
                        .map(|f| {
                            format!(
                                "{:>5}  {:<6} {:<45} {} {}",
                                f["id"],
                                f["risk"].as_str().unwrap_or(""),
                                f["name"].as_str().unwrap_or(""),
                                f["url"].as_str().unwrap_or(""),
                                f["param"].as_str().unwrap_or("")
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
        FindingsCmd::Mark { id, state, note } => {
            if state.is_none() && note.is_none() {
                return Err(Error::InvalidInput("give --state and/or --note".into()));
            }
            let state = state.map(|s| match s {
                StateArg::Open => "open",
                StateArg::Confirmed => "confirmed",
                StateArg::FalsePositive => "false_positive",
            });
            store.finding_mark(id, state, note.as_deref())?;
            out.ok(json!({"id": id, "state": state, "note": note}), || format!("updated finding {id}"));
        }
    }
    Ok(())
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
