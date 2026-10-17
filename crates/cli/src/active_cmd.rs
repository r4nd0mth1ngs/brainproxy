//! `scan active`: choose targets, run the active rules, summarise findings.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use brainproxy_core::auth::AuthSession;
use brainproxy_core::http::{Client, RawRequest, SendOptions, Target};
use brainproxy_core::scan::active::{self, points, ActiveConfig, PointOptions, ScanTarget, Strength};
use brainproxy_core::scan::findings_db::FindingFilter;
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::ValueEnum;
use serde_json::json;

use crate::output::Out;

#[derive(clap::Args)]
pub struct ActiveArgs {
    /// URLs to attack (fetched first as the baseline). Without URLs, --history-id or
    /// --where, every crawled/proxied/sent/imported request in history is a target.
    urls: Vec<String>,
    /// History entry to attack. Repeatable.
    #[arg(long = "history-id")]
    history_ids: Vec<i64>,
    /// SQL condition selecting history rows to attack, e.g. "host = 'app.test' AND path LIKE '/api/%'".
    #[arg(long = "where")]
    where_sql: Option<String>,
    #[arg(long, value_enum, default_value = "medium")]
    strength: StrengthArg,
    /// Only these rule ids (comma-separated).
    #[arg(long, value_delimiter = ',')]
    rules: Vec<u32>,
    /// Skip these rule ids (comma-separated).
    #[arg(long, value_delimiter = ',')]
    exclude_rules: Vec<u32>,
    /// Also inject into cookies.
    #[arg(long)]
    cookies: bool,
    /// Also inject into this request header (e.g. User-Agent). Repeatable.
    #[arg(long = "inject-header")]
    inject_headers: Vec<String>,
    #[arg(long)]
    no_query: bool,
    #[arg(long)]
    no_form: bool,
    #[arg(long)]
    no_json: bool,
    /// Concurrent rule units.
    #[arg(short = 'c', long, default_value_t = 10)]
    concurrency: usize,
    /// Maximum requests per second.
    #[arg(long)]
    rate: Option<f64>,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    /// Stop the scan after this many minutes.
    #[arg(long)]
    max_minutes: Option<f64>,
    /// Maximum distinct targets (after de-duplication).
    #[arg(long, default_value_t = 200)]
    max_targets: usize,
    #[arg(long)]
    verify_tls: bool,
    /// Scan logged in with this auth profile; re-logs in when the session is lost.
    #[arg(long, value_name = "NAME")]
    auth: Option<String>,
    /// Run detached; returns a job id for `job wait|status|stop`.
    #[arg(long)]
    background: bool,
    #[arg(long, hide = true)]
    job_id: Option<i64>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum StrengthArg {
    Low,
    Medium,
    High,
    Insane,
}

pub fn active(project: &Path, home: &Path, args: ActiveArgs, out: &Out) -> Result<(), Error> {
    let guard = crate::project_guard(project)?;
    if let Some(bad) =
        args.rules.iter().chain(&args.exclude_rules).find(|id| !active::all_rules().iter().any(|r| r.id() == **id))
    {
        return Err(Error::NotFound(format!("active rule {bad}")));
    }
    for u in &args.urls {
        crate::require_in_scope(&guard, &Target::from_url(u)?)?;
    }
    if args.background {
        return crate::jobs_cmd::spawn_background("active-scan", project, home, out);
    }
    let send = SendOptions {
        timeout: Duration::from_secs_f64(args.timeout.max(0.1)),
        verify_tls: args.verify_tls,
        sni: None,
        guard: Some(guard.clone()),
    };
    let point_opts = PointOptions {
        query: !args.no_query,
        form: !args.no_form,
        json: !args.no_json,
        cookies: args.cookies,
        headers: args.inject_headers.clone(),
    };
    let auth = crate::auth_cmd::maybe_session(project, args.auth.as_deref(), &send)?;
    let (targets, skipped) = select_targets(project, &args, &send, &point_opts, auth.as_deref())?;
    if targets.is_empty() {
        return Err(Error::InvalidInput(
            "no in-scope targets: pass URLs, --history-id, --where, or crawl/proxy the target first".into(),
        ));
    }
    let cfg = ActiveConfig {
        strength: match args.strength {
            StrengthArg::Low => Strength::Low,
            StrengthArg::Medium => Strength::Medium,
            StrengthArg::High => Strength::High,
            StrengthArg::Insane => Strength::Insane,
        },
        concurrency: args.concurrency.clamp(1, 200),
        rate: args.rate,
        send,
        points: point_opts,
        rules: (!args.rules.is_empty()).then(|| args.rules.clone()),
        exclude_rules: args.exclude_rules.clone(),
        max_duration: args.max_minutes.map(|m| Duration::from_secs_f64(m * 60.0)),
        auth: auth.clone(),
    };
    let result = crate::jobs_cmd::run_job(project, args.job_id, |ctl| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let summary = rt.block_on(active::run(project, targets, cfg, ctl));
        if let Some(a) = &auth {
            a.save()?;
        }
        let summary = summary?;
        let store = Store::open(project)?;
        let findings = store.findings_grouped(&FindingFilter {
            source: Some("active".into()),
            examples: 3,
            ..Default::default()
        })?;
        let mut v = json!(summary);
        v["skipped_out_of_scope"] = json!(skipped);
        v["active_findings"] = json!(findings);
        v["hint"] = json!(
            "Details: brainproxy findings show ID; all active findings: brainproxy findings list --source active"
        );
        Ok(v)
    })?;
    out.ok(result.clone(), || {
        let mut lines = vec![format!(
            "active scan: {} targets, {} units, {} requests, {} new findings",
            result["targets"], result["units"], result["requests"], result["new_findings"]
        )];
        for g in result["active_findings"].as_array().into_iter().flatten() {
            lines.push(format!(
                "  {:<6} {:<8} {} ({} instance(s))",
                g["risk"].as_str().unwrap_or(""),
                g["alert_ref"].as_str().unwrap_or(""),
                g["name"].as_str().unwrap_or(""),
                g["instances"]
            ));
        }
        lines.join("\n")
    });
    Ok(())
}

/// Picks and de-duplicates targets; returns them with the number skipped as out of scope.
fn select_targets(
    project: &Path,
    args: &ActiveArgs,
    send: &SendOptions,
    opts: &PointOptions,
    auth: Option<&AuthSession>,
) -> Result<(Vec<ScanTarget>, usize), Error> {
    let store = Store::open(project)?;
    let mut ids: Vec<i64> = args.history_ids.clone();
    if let Some(w) = &args.where_sql {
        let ro = Store::open_read_only(project)?;
        let r = ro.query(
            &format!("SELECT id FROM history WHERE ({w}) AND status IS NOT NULL ORDER BY id"),
            &[],
            100_000,
            50,
        )?;
        ids.extend(r.rows.iter().filter_map(|row| row[0].as_i64()));
    }
    let mut targets = Vec::new();
    if !args.urls.is_empty() {
        let client = Client::new(send.clone());
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        for u in &args.urls {
            let (req, target) = RawRequest::build("GET", u, &[], b"")?;
            let ex = match auth {
                Some(a) => rt.block_on(a.send(&req, &target))?,
                None => rt.block_on(client.send(&req, &target))?,
            };
            let id = store.record_exchange("scan", &ex)?;
            targets.push(ScanTarget {
                history_id: Some(id),
                target,
                request: ex.request,
                response: ex.response,
                duration_ms: Some(ex.duration_ms),
            });
        }
    }
    if args.urls.is_empty() && ids.is_empty() && args.where_sql.is_none() {
        let ro = Store::open_read_only(project)?;
        let r = ro.query(
            "SELECT id FROM history WHERE source IN ('crawl', 'proxy', 'send', 'import') AND status IS NOT NULL ORDER BY id",
            &[],
            100_000,
            50,
        )?;
        ids.extend(r.rows.iter().filter_map(|row| row[0].as_i64()));
    }
    let guard = send.guard.clone().expect("guard");
    let mut skipped = 0;
    for id in ids {
        let item = store.get(id)?;
        if item.response.is_empty() {
            continue;
        }
        if !guard.may_allow(&item.target.host, item.target.port) {
            skipped += 1;
            continue;
        }
        targets.push(ScanTarget {
            history_id: Some(id),
            target: item.target,
            request: item.request,
            response: item.response,
            duration_ms: item.entry.duration_ms.map(|d| d.max(0) as u64),
        });
    }
    // One target per method + origin + path + parameter names.
    let mut seen = HashSet::new();
    targets.retain(|t| {
        let head = RawRequest::from_bytes(t.request.clone()).head().ok();
        let method = head.as_ref().map(|h| h.method.clone()).unwrap_or_default();
        let path = head.map(|h| h.target.split('?').next().unwrap_or("").to_string()).unwrap_or_default();
        let mut names: Vec<String> = points::points(&t.request, opts).into_iter().map(|p| p.name).collect();
        names.sort();
        seen.insert((method, t.target.origin(), path, names))
    });
    targets.truncate(args.max_targets);
    Ok((targets, skipped))
}
