//! `scan active`: choose targets, run the active rules, summarise findings.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use brainproxy_core::auth::AuthSession;
use brainproxy_core::checks;
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
    /// Crawl and audit: crawl from each URL first (in scope, forms submitted, same auth and
    /// limits), then attack every recorded request on those sites, not only the URLs.
    #[arg(long)]
    crawl: bool,
    /// Link depth for --crawl.
    #[arg(long, default_value_t = 5, requires = "crawl")]
    crawl_depth: usize,
    /// Maximum crawl requests for --crawl.
    #[arg(long, default_value_t = 500, requires = "crawl")]
    crawl_max_pages: usize,
    /// Let --crawl follow links to any port and scheme on the URLs' hosts (and attack
    /// what it finds there), not only the URLs' origins.
    #[arg(long, requires = "crawl")]
    crawl_any_port: bool,
    /// Also attack requests from history with these methods (comma-separated, or `all`).
    /// By default only GET, HEAD, OPTIONS and POST are replayed; --history-id is always attacked.
    #[arg(long, value_delimiter = ',', value_name = "METHODS")]
    include_methods: Vec<String>,
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
    /// Run only the declarative checks from --checks, not the ported ZAP rules.
    #[arg(long)]
    no_rules: bool,
    /// Declarative checks to run as well: `brainproxy` (the signed feed from `checks update
    /// --source brainproxy`), `nuclei` (templates from `checks update`), `local`
    /// (<home>/checks/local), `all`, or a template file/directory. Repeatable or comma-separated.
    /// Passive checks among them are left out (the passive scanner runs them).
    #[arg(long, value_delimiter = ',', value_name = "SELECTOR")]
    checks: Vec<String>,
    /// Only checks with any of these tags (comma-separated), e.g. cve,exposure.
    #[arg(long, value_delimiter = ',')]
    check_tags: Vec<String>,
    /// Skip checks with any of these tags.
    #[arg(long, value_delimiter = ',', default_value = "dos,fuzz,intrusive")]
    check_exclude_tags: Vec<String>,
    /// Also run checks with any of these tags (or in a folder of that name), whatever
    /// --check-severity and the other check filters say (Nuclei's -itags), e.g. eol.
    #[arg(long, value_delimiter = ',')]
    check_include_tags: Vec<String>,
    /// Only these check ids (comma-separated).
    #[arg(long, value_delimiter = ',')]
    check_ids: Vec<String>,
    /// Only checks of at least this severity.
    #[arg(long, value_enum)]
    check_severity: Option<crate::scan_cmd::RiskArg>,
    /// A template input (Nuclei's -var), e.g. username=admin; templates using
    /// inputs that aren't given are not loaded. Repeatable.
    #[arg(long = "check-var", value_name = "NAME=VALUE", value_parser = crate::checks_cmd::check_var)]
    check_vars: Vec<(String, String)>,
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
    /// Per-request timeout in seconds for `--checks` templates (at most --timeout); a
    /// template's own `@timeout` overrides it.
    #[arg(long, default_value_t = 10.0)]
    check_timeout: f64,
    /// Stop the scan after this many minutes.
    #[arg(long)]
    max_minutes: Option<f64>,
    /// Maximum distinct targets (after de-duplication).
    #[arg(long, default_value_t = 200)]
    max_targets: usize,
    #[arg(long)]
    verify_tls: bool,
    /// Send over HTTP/2 (ALPN h2 for https, prior knowledge for http).
    #[arg(long)]
    http2: bool,
    /// Scan logged in with this auth profile; re-logs in when the session is lost.
    #[arg(long, value_name = "NAME")]
    auth: Option<String>,
    /// Seconds to wait for out-of-band callbacks after the last check (needs `oob start`).
    #[arg(long, default_value_t = 5.0)]
    oob_wait: f64,
    /// Skip out-of-band checks even when an OOB listener is running.
    #[arg(long)]
    no_oob: bool,
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
    if args.crawl && args.urls.is_empty() {
        return Err(Error::InvalidInput("--crawl needs at least one URL to start from".into()));
    }
    if args.no_rules && args.checks.is_empty() {
        return Err(Error::InvalidInput("--no-rules needs --checks".into()));
    }
    let oob = if args.no_oob { None } else { crate::oob_cmd::running(&Store::open(project)?)?.map(|s| s.endpoint) };
    let (checks, check_summary) = load_checks(home, &args, oob.is_some())?;
    if args.background {
        return crate::jobs_cmd::spawn_background("active-scan", project, home, out);
    }
    let send = SendOptions {
        timeout: Duration::from_secs_f64(args.timeout.max(0.1)),
        verify_tls: args.verify_tls,
        sni: None,
        guard: Some(guard.clone()),
        http2: args.http2,
    };
    let point_opts = PointOptions {
        query: !args.no_query,
        form: !args.no_form,
        json: !args.no_json,
        cookies: args.cookies,
        headers: args.inject_headers.clone(),
    };
    let auth = crate::auth_cmd::maybe_session(project, args.auth.as_deref(), &send)?;
    // With --crawl the targets are chosen after the crawl, inside the job.
    let selected = if args.crawl {
        None
    } else {
        Some(select_targets(project, &Selection::from_args(&args), &send, &point_opts, auth.as_deref())?)
    };
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
        no_rules: args.no_rules,
        checks: brainproxy_core::checks::into_rules(
            checks,
            Duration::from_secs_f64(args.check_timeout.clamp(0.1, args.timeout.max(0.1))),
        ),
        max_duration: args.max_minutes.map(|m| Duration::from_secs_f64(m * 60.0)),
        auth: auth.clone(),
        oob,
        oob_wait: Duration::from_secs_f64(args.oob_wait.clamp(0.0, 3600.0)),
    };
    let result = crate::jobs_cmd::run_job(project, args.job_id, |ctl| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let mut crawled = serde_json::Value::Null;
        let (targets, skipped, skipped_methods) = match selected {
            Some(s) => s,
            None => {
                let crawl_cfg = brainproxy_core::crawl::CrawlConfig {
                    seeds: args.urls.clone(),
                    max_depth: args.crawl_depth,
                    max_pages: args.crawl_max_pages,
                    max_per_path: 30,
                    concurrency: cfg.concurrency,
                    rate: args.rate,
                    send: cfg.send.clone(),
                    headers: vec![],
                    subdomains: false,
                    any_port: args.crawl_any_port,
                    path_prefix: None,
                    exclude: vec![regex::Regex::new(brainproxy_core::crawl::DEFAULT_EXCLUDE).expect("valid default")],
                    submit_forms: true,
                    robots: true,
                    sitemap: true,
                    auth: auth.clone(),
                };
                let c = rt.block_on(brainproxy_core::crawl::crawl(project, crawl_cfg, ctl.clone()))?;
                crawled =
                    json!({"requests": c.requests, "endpoints": c.endpoints.len(), "depth_reached": c.depth_reached});
                if ctl.stopped() {
                    return Ok(json!({"crawl": crawled, "stopped": true}));
                }
                select_targets(project, &Selection::sites(&args), &cfg.send, &cfg.points, auth.as_deref())?
            }
        };
        if targets.is_empty() {
            return Err(Error::InvalidInput(
                "no in-scope targets: pass URLs, --history-id, --where, or crawl/proxy the target first".into(),
            ));
        }
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
        if skipped_methods > 0 {
            v["skipped_methods"] = json!(skipped_methods);
            v["methods_hint"] = json!("Requests other than GET, HEAD, OPTIONS and POST were not attacked; add --include-methods to attack them.");
        }
        if !crawled.is_null() {
            v["crawl"] = crawled;
        }
        if !check_summary.is_null() {
            v["checks"] = check_summary.clone();
        }
        v["active_findings"] = json!(findings);
        v["hint"] = json!(
            "Details: brainproxy findings show ID; all active findings: brainproxy findings list --source active"
        );
        if v["oob"].is_null() && !args.no_oob {
            v["oob_hint"] = json!("Out-of-band checks were skipped: no OOB listener (brainproxy oob start).");
        } else if !v["oob"].is_null() {
            v["oob_hint"] = json!("Callbacks that arrive later are raised by `brainproxy oob poll`.");
        }
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

/// Loads and filters the --checks templates; returns them with a summary for the output.
fn load_checks(home: &Path, args: &ActiveArgs, oob: bool) -> Result<(Vec<checks::Check>, serde_json::Value), Error> {
    if args.checks.is_empty() {
        return Ok((vec![], serde_json::Value::Null));
    }
    let opts = checks::LoadOptions { vars: args.check_vars.clone(), oob, ..Default::default() };
    let loaded = checks::load(&checks::resolve_selectors(home, &args.checks), &opts)?;
    let filter = checks::Filter {
        ids: args.check_ids.clone(),
        tags: args.check_tags.clone(),
        exclude_tags: args.check_exclude_tags.iter().filter(|t| !t.is_empty()).cloned().collect(),
        min_risk: args.check_severity.map(crate::scan_cmd::RiskArg::get),
        include_tags: args.check_include_tags.clone(),
    };
    // Only the signed feed may replace a built-in rule.
    let feed = checks::feed_dir(home);
    let (passive, active): (Vec<checks::Check>, Vec<checks::Check>) =
        loaded.checks.iter().cloned().partition(|c| c.passive);
    let total = active.len();
    let selected: Vec<checks::Check> = active
        .into_iter()
        .filter(|c| filter.keep(c))
        .map(|mut c| {
            if !c.file.starts_with(&feed) {
                c.replaces = None;
            }
            c
        })
        .collect();
    let summary = json!({
        "selected": selected.len(),
        "passive": passive.len(),
        "filtered_out": total - selected.len(),
        "not_loaded": loaded.skipped.len(),
        "not_loaded_reasons": loaded.reasons().into_iter().take(5).collect::<Vec<_>>(),
    });
    if selected.is_empty() {
        return Err(Error::InvalidInput(format!(
            "no checks selected from {:?} ({total} loaded, {} not loaded; see `brainproxy checks list`)",
            args.checks,
            loaded.skipped.len()
        )));
    }
    Ok((selected, summary))
}

/// Which requests to attack.
struct Selection {
    urls: Vec<String>,
    history_ids: Vec<i64>,
    where_sql: Option<String>,
    max_targets: usize,
    /// Methods attacked besides the default ones (upper case; `ALL` for every method).
    include_methods: Vec<String>,
}

/// Methods attacked by default: replaying others (DELETE, PUT, PATCH, ...) can change data.
const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST"];

impl Selection {
    fn from_args(args: &ActiveArgs) -> Self {
        Selection {
            urls: args.urls.clone(),
            history_ids: args.history_ids.clone(),
            where_sql: args.where_sql.clone(),
            max_targets: args.max_targets,
            include_methods: args.include_methods.iter().map(|m| m.trim().to_ascii_uppercase()).collect(),
        }
    }

    /// After --crawl: every recorded request on the seed URLs' sites (scheme, host, port).
    fn sites(args: &ActiveArgs) -> Self {
        let sites: Vec<String> = args
            .urls
            .iter()
            .filter_map(|u| Target::from_url(u).ok())
            .map(|t| {
                let q = |s: &str| s.replace('\'', "''");
                let host = format!("host = '{}'", q(&t.host));
                if args.crawl_any_port {
                    host
                } else if t.scheme == "http" {
                    // The crawl follows an http site to https on 443.
                    format!(
                        "({host} AND ((scheme = 'http' AND port = {}) OR (scheme = 'https' AND port = 443)))",
                        t.port
                    )
                } else {
                    format!("({host} AND scheme = '{}' AND port = {})", q(&t.scheme), t.port)
                }
            })
            .collect();
        let site = sites.join(" OR ");
        let mut where_sql = format!("({site}) AND source IN ('crawl', 'proxy', 'send', 'import')");
        if let Some(w) = &args.where_sql {
            where_sql = format!("{where_sql} AND ({w})");
        }
        Selection { urls: vec![], history_ids: vec![], where_sql: Some(where_sql), ..Self::from_args(args) }
    }
}

/// Picks and de-duplicates targets; returns them with the numbers skipped as out of
/// scope and for their method.
fn select_targets(
    project: &Path,
    args: &Selection,
    send: &SendOptions,
    opts: &PointOptions,
    auth: Option<&AuthSession>,
) -> Result<(Vec<ScanTarget>, usize, usize), Error> {
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
    let mut skipped_methods = 0;
    let all_methods = args.include_methods.iter().any(|m| m == "ALL");
    targets.retain(|t| {
        let head = RawRequest::from_bytes(t.request.clone()).head().ok();
        let method = head.as_ref().map(|h| h.method.to_ascii_uppercase()).unwrap_or_default();
        let explicit = t.history_id.is_some_and(|id| args.history_ids.contains(&id));
        if !(all_methods
            || explicit
            || SAFE_METHODS.contains(&method.as_str())
            || args.include_methods.contains(&method))
        {
            skipped_methods += 1;
            return false;
        }
        let path = head.map(|h| h.target.split('?').next().unwrap_or("").to_string()).unwrap_or_default();
        let mut names: Vec<String> = points::points(&t.request, opts).into_iter().map(|p| p.name).collect();
        names.sort();
        seen.insert((method, t.target.origin(), path, names))
    });
    targets.truncate(args.max_targets);
    Ok((targets, skipped, skipped_methods))
}
