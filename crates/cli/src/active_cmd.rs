//! `scan active`: choose targets, run the active rules, summarise findings.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use brainproxy_core::apiimport::api::{self, DEFAULT_METHODS};
use brainproxy_core::apiimport::{self, RunConfig};
use brainproxy_core::auth::AuthSession;
use brainproxy_core::checks;
use brainproxy_core::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use brainproxy_core::scan::active::{self, points, ActiveConfig, PointOptions, ScanTarget, Strength};
use brainproxy_core::scan::compare::ScanScope;
use brainproxy_core::scan::findings_db::FindingFilter;
use brainproxy_core::session::Tool;
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
    /// Scan an API from its description (OpenAPI 3.x, Swagger 2.0, or Postman v2.0/v2.1; a file or
    /// an http(s) URL): build requests as `import api` does, send each selected in-scope
    /// operation once as a baseline, then attack exactly those.
    #[arg(long, value_name = "SOURCE", conflicts_with_all = ["urls", "crawl", "history_ids", "where_sql"])]
    api: Option<String>,
    /// With --api: send to this server instead: scheme://host[:port] replaces the origin; with a path, the whole base.
    #[arg(long, requires = "api")]
    base_url: Option<String>,
    /// With --api: use the document's Nth server (from 0) instead of the first.
    #[arg(long, value_name = "N", requires = "api")]
    server: Option<usize>,
    /// With --api: Postman variable, NAME=VALUE. Repeatable.
    #[arg(long = "var", value_name = "NAME=VALUE", requires = "api")]
    vars: Vec<String>,
    /// With --api: only the requests at these indexes (comma-separated), as `import api --dry-run` numbers them.
    #[arg(long, value_delimiter = ',', value_name = "INDEXES", requires = "api")]
    only: Option<Vec<usize>>,
    /// With --api: refuse a document whose sha256 isn't this.
    #[arg(long, value_name = "HEX", requires = "api")]
    expect_sha256: Option<String>,
    /// Crawl and audit: crawl from each URL first (in scope, forms submitted, same auth and
    /// limits), then attack every recorded request on those sites, not only the URLs.
    #[arg(long)]
    crawl: bool,
    /// A scan depth, as the app's guided scan offers them: `quick` (--strength medium
    /// --crawl-depth 3 --crawl-max-pages 150), `standard` (--strength high --crawl-depth 5
    /// --crawl-max-pages 500 --cookies --url-path), or `thorough` (--strength insane
    /// --crawl-depth 8 --crawl-max-pages 1500 --cookies --url-path). Flags given as well win.
    #[arg(long, value_enum, value_name = "DEPTH")]
    preset: Option<PresetArg>,
    /// Link depth for --crawl [default: 5].
    #[arg(long, requires = "crawl")]
    crawl_depth: Option<usize>,
    /// Maximum crawl requests for --crawl [default: 500].
    #[arg(long, requires = "crawl")]
    crawl_max_pages: Option<usize>,
    /// Let --crawl follow links to any port and scheme on the URLs' hosts (and attack
    /// what it finds there), not only the URLs' origins.
    #[arg(long, requires = "crawl")]
    crawl_any_port: bool,
    /// With --crawl: after the plain crawl, crawl again in a headless Chromium-based browser that
    /// runs JavaScript (clicks, client-side routes, XHR/fetch calls), so single-page apps are covered.
    /// Destructive-looking elements aren't clicked; see `crawl --help`.
    #[arg(long, requires = "crawl")]
    browser: bool,
    /// With --browser: the browser to use, an id from `browser list`.
    #[arg(long, value_name = "ID", requires = "browser")]
    browser_id: Option<String>,
    /// Also attack requests from history with these methods (comma-separated, or `all`).
    /// By default only GET, HEAD, OPTIONS and POST are replayed, and POST can change data or
    /// trigger side effects such as email; --history-id is always attacked.
    #[arg(long, value_delimiter = ',', value_name = "METHODS")]
    include_methods: Vec<String>,
    /// History entry to attack. Repeatable.
    #[arg(long = "history-id")]
    history_ids: Vec<i64>,
    /// SQL condition selecting history rows to attack, e.g. "host = 'app.test' AND path LIKE '/api/%'".
    #[arg(long = "where")]
    where_sql: Option<String>,
    /// Attack strength [default: medium].
    #[arg(long, value_enum)]
    strength: Option<StrengthArg>,
    /// Only these rule ids (comma-separated).
    #[arg(long, value_delimiter = ',')]
    rules: Vec<u32>,
    /// Skip these rule ids (comma-separated).
    #[arg(long, value_delimiter = ',')]
    exclude_rules: Vec<u32>,
    /// Run only the declarative checks from --checks, not the ported ZAP rules.
    #[arg(long)]
    no_rules: bool,
    /// Declarative checks to run as well: `nuclei` (templates from `checks update`), `local`
    /// (<home>/checks/local), `all`, or a template file/directory. Repeatable or comma-separated.
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
    /// Only checks of at least this template severity (`high` includes critical).
    #[arg(long, value_enum)]
    check_severity: Option<crate::checks_cmd::SeverityArg>,
    /// Only checks of at most this template severity, e.g. `--check-severity high
    /// --check-severity-max high` for high but not critical. --check-include-tags still wins.
    #[arg(long, value_enum)]
    check_severity_max: Option<crate::checks_cmd::SeverityArg>,
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
    #[arg(long)]
    no_multipart: bool,
    #[arg(long)]
    no_xml: bool,
    /// Also inject into URL path segments, such as IDs in REST paths. Requests that differ
    /// only by an ID (/users/1, /users/2) or an asset's file name count as one target unless
    /// named by URL or --history-id; a fixed segment is attacked once per origin and method.
    #[arg(long)]
    url_path: bool,
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
    /// Maximum distinct targets, after de-duplication [default: 200; with --api, every
    /// selected operation, and those a cap leaves out are reported as targets_dropped].
    #[arg(long)]
    max_targets: Option<usize>,
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

impl ActiveArgs {
    /// What these arguments cover, for comparing findings with the scan. Sites are read the way
    /// the scan reads them; the scan's time window is the job's.
    pub fn scope(&self) -> ScanScope {
        let picked = !self.history_ids.is_empty() || self.where_sql.is_some() || self.api.is_some();
        let origins = if !self.urls.is_empty() {
            Some(self.urls.iter().filter_map(|u| Target::from_url(u).ok()).map(|t| t.origin()).collect())
        } else if picked {
            Some(vec![])
        } else {
            None
        };
        let by_id_only =
            self.check_severity.is_none() && self.check_severity_max.is_none() && self.check_tags.is_empty();
        let numbers = |ids: &[u32]| ids.iter().map(|&id| i64::from(id)).collect::<Vec<_>>();
        ScanScope {
            origins,
            rules: (!self.rules.is_empty()).then(|| numbers(&self.rules)),
            exclude_rules: numbers(&self.exclude_rules),
            ported_rules: !self.no_rules,
            check_ids: if !self.checks.is_empty() && by_id_only { self.check_ids.clone() } else { vec![] },
            crawled: self.crawl,
            ..Default::default()
        }
    }
}

impl ActiveArgs {
    fn api_options(&self) -> Result<api::Options, Error> {
        Ok(api::Options {
            base_url: self.base_url.clone(),
            server: self.server,
            vars: crate::import_cmd::parse_vars(&self.vars)?,
            expect_sha256: self.expect_sha256.clone(),
            spec_url: None,
        })
    }

    /// Clap's `requires` doesn't catch these next to a URL, which conflicts with --api.
    fn check_api_flags(&self) -> Result<(), Error> {
        let given = self.base_url.is_some()
            || self.server.is_some()
            || !self.vars.is_empty()
            || self.only.is_some()
            || self.expect_sha256.is_some();
        if given && self.api.is_none() {
            return Err(Error::InvalidInput(
                "--base-url, --server, --var, --only and --expect-sha256 need --api".into(),
            ));
        }
        Ok(())
    }

    fn api_selection(&self) -> api::Selection {
        crate::import_cmd::selection(&self.include_methods, self.only.clone())
    }

    fn preset(&self) -> Option<Preset> {
        self.preset.map(PresetArg::get)
    }

    fn strength(&self) -> StrengthArg {
        self.strength.or(self.preset().map(|p| p.strength)).unwrap_or(StrengthArg::Medium)
    }

    fn crawl_depth(&self) -> usize {
        self.crawl_depth.or(self.preset().map(|p| p.crawl_depth)).unwrap_or(5)
    }

    fn crawl_max_pages(&self) -> usize {
        self.crawl_max_pages.or(self.preset().map(|p| p.crawl_max_pages)).unwrap_or(500)
    }

    fn cookies(&self) -> bool {
        self.cookies || self.preset().is_some_and(|p| p.cookies)
    }

    fn url_path(&self) -> bool {
        self.url_path || self.preset().is_some_and(|p| p.url_path)
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PresetArg {
    Quick,
    Standard,
    Thorough,
}

/// The settings a --preset stands for. The app's guided scan passes the preset, so this is the
/// one definition of its depths.
#[derive(Clone, Copy)]
struct Preset {
    strength: StrengthArg,
    crawl_depth: usize,
    crawl_max_pages: usize,
    cookies: bool,
    url_path: bool,
}

impl PresetArg {
    fn get(self) -> Preset {
        match self {
            // Medium, not low: low strength skips the SQL injection payloads that matter most.
            PresetArg::Quick => Preset {
                strength: StrengthArg::Medium,
                crawl_depth: 3,
                crawl_max_pages: 150,
                cookies: false,
                url_path: false,
            },
            // Attacking path segments adds many requests, so a site that fills --max-targets can
            // take half an hour.
            PresetArg::Standard => Preset {
                strength: StrengthArg::High,
                crawl_depth: 5,
                crawl_max_pages: 500,
                cookies: true,
                url_path: true,
            },
            PresetArg::Thorough => Preset {
                strength: StrengthArg::Insane,
                crawl_depth: 8,
                crawl_max_pages: 1500,
                cookies: true,
                url_path: true,
            },
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq)]
pub enum StrengthArg {
    Low,
    Medium,
    High,
    Insane,
}

pub fn active(project: &Path, home: &Path, args: ActiveArgs, out: &Out) -> Result<(), Error> {
    args.check_api_flags()?;
    let guard = crate::project_guard(project)?;
    let band = crate::checks_cmd::severity_band(args.check_severity, args.check_severity_max, "--check-severity")?;
    if let Some(bad) =
        args.rules.iter().chain(&args.exclude_rules).find(|id| !active::all_rules().iter().any(|r| r.id() == **id))
    {
        return Err(Error::NotFound(format!("active rule {bad}")));
    }
    for u in &args.urls {
        crate::require_in_scope(&guard, &Target::from_url(u)?)?;
    }
    if let Some(source) = &args.api {
        api::check_source(source)?;
        if crate::import_cmd::is_url(source) {
            crate::require_in_scope(&guard, &Target::from_url(source)?)?;
        }
        if source == "-" && args.background {
            return Err(Error::InvalidInput("--background can't read stdin; pass a file".into()));
        }
    }
    if args.crawl && args.urls.is_empty() {
        return Err(Error::InvalidInput("--crawl needs at least one URL to start from".into()));
    }
    if args.no_rules && args.checks.is_empty() {
        return Err(Error::InvalidInput("--no-rules needs --checks".into()));
    }
    let oob = if args.no_oob { None } else { crate::oob_cmd::running(&Store::open(project)?)?.map(|s| s.endpoint) };
    let (checks, check_summary) = load_checks(home, &args, band, oob.is_some())?;
    let browser = args.browser.then(|| crate::browser_cmd::chromium(args.browser_id.as_deref())).transpose()?;
    if args.background {
        if let Some(source) = &args.api {
            crate::import_cmd::check_background_args(&crate::import_cmd::parse_vars(&args.vars)?, &[])?;
            if let Some(b) = &args.base_url {
                api::check_base_url(b)?;
            }
            // A local file can be checked now, so the caller gets the error and not a failed job.
            if !crate::import_cmd::is_url(source) {
                let loaded = api::load(&crate::import_cmd::read_local(source)?, &args.api_options()?)?;
                crate::import_cmd::check_background_doc(&loaded)?;
                loaded.check_runnable(&loaded.plan(&args.api_selection(), &guard)?)?;
            } else {
                let from = crate::import_cmd::RemoteFetch {
                    auth: args.auth.as_deref(),
                    headers: &[],
                    tool: Tool::Scan,
                    timeout: args.timeout,
                    verify_tls: args.verify_tls,
                };
                crate::import_cmd::check_remote_vars(project, &guard, source, args.api_options()?, from)?;
            }
        }
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
        multipart: !args.no_multipart,
        xml: !args.no_xml,
        path: args.url_path(),
        cookies: args.cookies(),
        headers: args.inject_headers.clone(),
    };
    let auth = crate::auth_cmd::maybe_session(project, args.auth.as_deref(), &send)?;
    let api_import = match &args.api {
        Some(source) => {
            let fetch = crate::import_cmd::Fetcher {
                project,
                send: &send,
                record: false,
                auth: auth.as_deref(),
                headers: &[],
                tool: Tool::Scan,
            };
            let loaded = crate::import_cmd::load_api(&fetch, source, args.api_options()?)?;
            let plan = loaded.plan(&args.api_selection(), &guard)?;
            loaded.check_runnable(&plan)?;
            Some((loaded, plan))
        }
        None => None,
    };
    // With --crawl or --api the targets are chosen inside the job.
    let selected = if args.crawl || api_import.is_some() {
        None
    } else {
        Some(select_targets(project, &Selection::from_args(&args), &send, &point_opts, auth.as_deref())?)
    };
    let cfg = ActiveConfig {
        strength: match args.strength() {
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
        let mut imported = serde_json::Value::Null;
        let mut targets_dropped = 0;
        let (targets, skipped, skipped_methods) = match (selected, api_import) {
            (Some(s), _) => s,
            (None, Some((loaded, plan))) => {
                let (requests, _) = plan.to_send(usize::MAX);
                let run_cfg = RunConfig {
                    send: cfg.send.clone(),
                    headers: vec![],
                    concurrency: cfg.concurrency,
                    rate: args.rate,
                    auth: auth.clone(),
                    list_limit: usize::MAX,
                    tool: Tool::Scan,
                    stage: Some("baseline"),
                };
                let baselines = rt.block_on(apiimport::run(project, requests, run_cfg, ctl.clone()));
                if let Some(a) = &auth {
                    a.save()?;
                }
                let baselines = baselines?;
                baselines.check_any_in_scope()?;
                imported = json!({
                    "format": loaded.format,
                    "built": loaded.requests.len(),
                    "selected": plan.selected(),
                    "sent": baselines.sent,
                    "by_status": baselines.by_status,
                    "errors": baselines.errors,
                    "skipped_out_of_scope": baselines.skipped_out_of_scope,
                    "out_of_scope_hosts": baselines.out_of_scope_hosts,
                    "skipped": loaded.skipped,
                    "warnings": loaded.warnings,
                    "credentials": loaded.credentials,
                });
                if ctl.stopped() {
                    return Ok(json!({"import": imported, "stopped": true}));
                }
                // A baseline that got no response has nothing to compare an attack with.
                let ids: Vec<i64> =
                    baselines.requests.iter().filter(|r| r.error.is_none()).map(|r| r.history_id).collect();
                if ids.is_empty() {
                    return Err(Error::Connect(format!(
                        "none of the {} baseline requests got a response, so there is nothing to scan",
                        baselines.sent
                    )));
                }
                let selection = Selection {
                    urls: vec![],
                    history_ids: ids.clone(),
                    where_sql: None,
                    max_targets: usize::MAX,
                    include_methods: vec![],
                };
                let mut picked = select_targets(project, &selection, &cfg.send, &cfg.points, auth.as_deref())?;
                if let Some(cap) = args.max_targets {
                    targets_dropped = picked.0.len().saturating_sub(cap);
                    picked.0.truncate(cap);
                }
                picked
            }
            (None, None) => {
                let crawl_cfg = brainproxy_core::crawl::CrawlConfig {
                    seeds: args.urls.clone(),
                    max_depth: args.crawl_depth(),
                    max_pages: args.crawl_max_pages(),
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
                    max_duration: cfg.max_duration,
                };
                let crawl_started = std::time::Instant::now();
                let c = rt.block_on(brainproxy_core::crawl::crawl(project, crawl_cfg.clone(), ctl.clone()))?;
                crawled =
                    json!({"requests": c.requests, "endpoints": c.endpoints.len(), "depth_reached": c.depth_reached});
                if let (Some(path), false) = (browser, ctl.stopped()) {
                    let avoid = crate::crawl_cmd::avoid_patterns(&[], false)?;
                    // --max-minutes covers the two crawls together.
                    let mut crawl_cfg = crawl_cfg;
                    crawl_cfg.max_duration = crawl_cfg.max_duration.map(|d| d.saturating_sub(crawl_started.elapsed()));
                    let b = crate::crawl_cmd::browser_config(home, crawl_cfg, path, true, avoid, false)?;
                    let b = rt.block_on(brainproxy_core::browser_crawl::crawl(project, b, ctl.clone()))?;
                    crawled["browser"] = json!({
                        "sandbox": b.sandbox,
                        "requests": b.requests,
                        "endpoints": b.endpoint_count,
                        "api_calls": b.api_call_count,
                        "states": b.states,
                        "clicks": b.clicks,
                        "forms_submitted": b.forms_submitted,
                        "not_clicked": b.not_clicked_count,
                        "blocked_requests": b.blocked_count,
                    });
                }
                // The scan's own clock starts after this, so its timed_out won't say.
                if cfg.max_duration.is_some_and(|d| crawl_started.elapsed() >= d) {
                    crawled["timed_out"] = json!(true);
                }
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
        // Before the attack, while a person at the terminal can still stop it.
        let posts = post_targets(&targets);
        if posts > 0 && !out.json() {
            eprintln!("warning: {posts} POST target(s). {POST_HINT}");
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
        if posts > 0 {
            v["post_targets"] = json!(posts);
            v["post_hint"] = json!(POST_HINT);
        }
        if !crawled.is_null() {
            v["crawl"] = crawled;
        }
        if !imported.is_null() {
            v["import"] = imported;
        }
        if targets_dropped > 0 {
            v["targets_dropped"] = json!(targets_dropped);
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
fn load_checks(
    home: &Path,
    args: &ActiveArgs,
    (min_severity, max_severity): (Option<checks::Severity>, Option<checks::Severity>),
    oob: bool,
) -> Result<(Vec<checks::Check>, serde_json::Value), Error> {
    if args.checks.is_empty() {
        return Ok((vec![], serde_json::Value::Null));
    }
    let opts = checks::LoadOptions { vars: args.check_vars.clone(), oob, ..Default::default() };
    let loaded = checks::load(&checks::resolve_selectors(home, &args.checks), &opts)?;
    let filter = checks::Filter {
        ids: args.check_ids.clone(),
        tags: args.check_tags.clone(),
        exclude_tags: args.check_exclude_tags.iter().filter(|t| !t.is_empty()).cloned().collect(),
        min_severity,
        max_severity,
        include_tags: args.check_include_tags.clone(),
    };
    let total = loaded.checks.len();
    let selected: Vec<checks::Check> = loaded.checks.iter().filter(|c| filter.keep(c)).cloned().collect();
    let summary = json!({
        "selected": selected.len(),
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

const POST_HINT: &str = "POST requests are replayed with attack payloads, often many times, and can change data or trigger side effects such as email.";

/// Targets replayed as POST.
fn post_targets(targets: &[ScanTarget]) -> usize {
    targets
        .iter()
        .filter(|t| {
            RawRequest::from_bytes(t.request.clone()).head().is_ok_and(|h| h.method.eq_ignore_ascii_case("POST"))
        })
        .count()
}

impl Selection {
    fn from_args(args: &ActiveArgs) -> Self {
        Selection {
            urls: args.urls.clone(),
            history_ids: args.history_ids.clone(),
            where_sql: args.where_sql.clone(),
            max_targets: args.max_targets.unwrap_or(200),
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
        let mut where_sql = format!("({site}) AND source IN ('crawl', 'crawl-browser', 'proxy', 'send', 'import')");
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
    // The requests asked for by URL or history id, not by a filter.
    let mut named: HashSet<i64> = args.history_ids.iter().copied().collect();
    if !args.urls.is_empty() {
        let client = Client::new(send.clone());
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        for u in &args.urls {
            let (req, target) = RawRequest::build("GET", u, &[], b"")?;
            let ex = match auth {
                Some(a) => rt.block_on(a.send_as(Tool::Scan, &req, &target))?,
                None => rt.block_on(client.send(&req, &target))?,
            };
            let id = store.record_exchange("scan", &ex)?;
            named.insert(id);
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
            "SELECT id FROM history WHERE source IN ('crawl', 'crawl-browser', 'proxy', 'send', 'import') AND status IS NOT NULL ORDER BY id",
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
    // One target per method + origin + path + parameter names. With URL path attacks the
    // path is the route (`/users/{id}`), unless the user named this very request, and the
    // route is attacked through a request that worked, if any: it keeps its place in the
    // list, so --max-targets cuts the same routes whatever they answered.
    let ok = |t: &ScanTarget| parse_response_head(&t.response).is_ok_and(|h| (200..300).contains(&h.status));
    let mut seen = HashMap::new();
    let mut kept: Vec<ScanTarget> = Vec::new();
    let mut skipped_methods = 0;
    let all_methods = args.include_methods.iter().any(|m| m == "ALL");
    for t in targets {
        let head = RawRequest::from_bytes(t.request.clone()).head().ok();
        let method = head.as_ref().map(|h| h.method.to_ascii_uppercase()).unwrap_or_default();
        let explicit = t.history_id.is_some_and(|id| args.history_ids.contains(&id));
        if !(all_methods
            || explicit
            || DEFAULT_METHODS.contains(&method.as_str())
            || args.include_methods.contains(&method))
        {
            skipped_methods += 1;
            continue;
        }
        let by_route = opts.path && !t.history_id.is_some_and(|id| named.contains(&id));
        let path = head
            .map(|h| if by_route { points::route(&h.target) } else { h.target.split('?').next().unwrap_or("").into() })
            .unwrap_or_default();
        let mut names: Vec<String> = points::points(&t.request, opts).into_iter().map(|p| p.name).collect();
        names.sort();
        match seen.entry((method, t.target.origin(), path, names)) {
            Entry::Vacant(e) => {
                e.insert(kept.len());
                kept.push(t);
            }
            Entry::Occupied(e) => {
                if opts.path && ok(&t) && !ok(&kept[*e.get()]) {
                    kept[*e.get()] = t;
                }
            }
        }
    }
    kept.truncate(args.max_targets);
    Ok((kept, skipped, skipped_methods))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> ActiveArgs {
        let argv =
            ["brainproxy", "scan", "active", "http://a.test/", "--crawl"].iter().chain(args).map(|s| s.to_string());
        match crate::Cli::try_parse_from(argv) {
            Ok(crate::Cli { command: crate::Cmd::Scan(crate::scan_cmd::ScanCmd::Active(a)), .. }) => *a,
            _ => panic!("bad args {args:?}"),
        }
    }

    fn settings(a: &ActiveArgs) -> (StrengthArg, usize, usize, bool, bool) {
        (a.strength(), a.crawl_depth(), a.crawl_max_pages(), a.cookies(), a.url_path())
    }

    /// Each preset is exactly the flags the app's guided scan passed before it had presets.
    #[test]
    fn presets_expand_to_the_guided_scans_flags() {
        let golden: [(&str, &[&str]); 3] = [
            ("quick", &["--strength", "medium", "--crawl-depth", "3", "--crawl-max-pages", "150"]),
            (
                "standard",
                &["--strength", "high", "--crawl-depth", "5", "--crawl-max-pages", "500", "--cookies", "--url-path"],
            ),
            (
                "thorough",
                &["--strength", "insane", "--crawl-depth", "8", "--crawl-max-pages", "1500", "--cookies", "--url-path"],
            ),
        ];
        for (preset, flags) in golden {
            assert_eq!(settings(&parse(&["--preset", preset])), settings(&parse(flags)), "{preset}");
        }
        // Without a preset, the defaults.
        assert_eq!(settings(&parse(&[])), (StrengthArg::Medium, 5, 500, false, false));
    }

    #[test]
    fn api_flags_need_api_and_exclude_other_targets() {
        let parsed = |args: &[&str]| {
            let argv = ["brainproxy", "scan", "active"].iter().chain(args).map(|s| s.to_string());
            match crate::Cli::try_parse_from(argv) {
                Ok(crate::Cli { command: crate::Cmd::Scan(crate::scan_cmd::ScanCmd::Active(a)), .. }) => Some(*a),
                _ => None,
            }
        };
        let all = [
            "--api",
            "s.yaml",
            "--base-url",
            "http://a.test",
            "--server",
            "1",
            "--var",
            "a=b",
            "--only",
            "0,3",
            "--expect-sha256",
            "ab",
            "--preset",
            "quick",
            "--include-methods",
            "PUT",
        ];
        assert!(parsed(&all).unwrap().check_api_flags().is_ok());
        for bad in [
            &["--api", "s.yaml", "http://a.test/"][..],
            &["--api", "s.yaml", "--crawl"],
            &["--api", "s.yaml", "--history-id", "1"],
            &["--api", "s.yaml", "--where", "1=1"],
            &["--server", "1"],
        ] {
            assert!(parsed(bad).is_none(), "{bad:?}");
        }
        for flag in [
            &["--server", "1"][..],
            &["--base-url", "http://b.test"],
            &["--var", "a=b"],
            &["--only", "1"],
            &["--expect-sha256", "ab"],
        ] {
            let args: Vec<&str> = ["http://a.test/"].iter().chain(flag).copied().collect();
            assert!(parsed(&args).unwrap().check_api_flags().is_err(), "{flag:?}");
        }
    }

    #[test]
    fn explicit_flags_override_the_preset() {
        let a = parse(&["--preset", "thorough", "--strength", "low", "--crawl-max-pages", "20"]);
        assert_eq!(settings(&a), (StrengthArg::Low, 8, 20, true, true));
        let a = parse(&["--crawl-depth", "1", "--preset=quick", "--cookies"]);
        assert_eq!(settings(&a), (StrengthArg::Medium, 1, 150, true, false));
    }
}
