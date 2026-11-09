//! CLI for the spider.

use std::path::Path;

use std::sync::Arc;

use brainproxy_core::browser_crawl::{self, BrowserCrawlConfig, DEFAULT_AVOID};
use brainproxy_core::crawl::{self, CrawlConfig, DEFAULT_EXCLUDE};
use brainproxy_core::http::SendOptions;
use brainproxy_core::Error;
use regex::Regex;
use serde_json::json;

use crate::output::Out;

#[derive(clap::Args)]
#[command(after_help = "--browser crawls in a headless Chromium-based browser (see `browser list`) that runs the \
    site's JavaScript: it waits for each page to settle, follows links and client-side routes (pushState, #/hash), \
    clicks buttons, menus and other clickable elements, fills fields with test values and submits forms, once per \
    distinct page state. The browser goes only through the crawl's own proxy, so every request (XHR and fetch \
    included) is checked against the engagement scope and recorded as history source crawl-browser. Elements \
    and links labelled like logout, delete or remove are not clicked, page loads that would leave the crawl's sites or \
    --path-prefix are not sent, confirm() dialogs answer no, logout-like URLs and DELETE \
    requests are not sent (--allow-destructive and --no-default-exclude lift that). --max-pages counts page loads, \
    clicks and form submissions, including those that return to a page state; robots.txt, sitemaps, --concurrency and --http2 apply to the plain crawl only. \
    Linux and macOS; a temporary browser profile is used and removed. Chromium's sandbox stays on: to run without it \
    (as root, or where user namespaces are off) set BRAINPROXY_BROWSER_NO_SANDBOX=1, and the summary then says \
    \"sandbox\": false.")]
pub struct CrawlArgs {
    /// Seed URLs. The crawl stays on their origins (scheme, host and port; an http
    /// seed also covers https on port 443 of the same host).
    #[arg(required = true)]
    urls: Vec<String>,
    /// Link depth from the seeds.
    #[arg(long, default_value_t = 5)]
    depth: usize,
    /// Maximum requests in total.
    #[arg(long, default_value_t = 500)]
    max_pages: usize,
    /// Maximum requests per method + path (stops pagination/calendar traps).
    #[arg(long, default_value_t = 30)]
    max_per_path: usize,
    #[arg(short = 'c', long, default_value_t = 10)]
    concurrency: usize,
    /// Maximum requests per second.
    #[arg(long)]
    rate: Option<f64>,
    /// Header for every request, e.g. "Cookie: session=..." for a logged-in crawl. Repeatable.
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// Crawl logged in with this auth profile (see `auth add`); re-logs in when the session is lost.
    #[arg(long, value_name = "NAME")]
    auth: Option<String>,
    /// Also crawl subdomains of the seed hosts.
    #[arg(long)]
    subdomains: bool,
    /// Follow links to any port and scheme on the seed hosts, not only the seeds' origins.
    #[arg(long)]
    any_port: bool,
    /// Only crawl paths starting with this prefix.
    #[arg(long)]
    path_prefix: Option<String>,
    /// Never request URLs matching this regex. Repeatable. Logout-like URLs are excluded by default.
    #[arg(long)]
    exclude: Vec<String>,
    /// Don't exclude logout-like URLs.
    #[arg(long)]
    no_default_exclude: bool,
    /// Don't submit forms.
    #[arg(long)]
    no_forms: bool,
    #[arg(long)]
    no_robots: bool,
    #[arg(long)]
    no_sitemap: bool,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 15.0)]
    timeout: f64,
    #[arg(long)]
    verify_tls: bool,
    /// Send over HTTP/2 (ALPN h2 for https, prior knowledge for http).
    #[arg(long)]
    http2: bool,
    /// Stop crawling after this many minutes (with --browser, 30 unless given).
    #[arg(long)]
    max_minutes: Option<f64>,
    /// Crawl in a headless Chromium-based browser that runs JavaScript (single-page apps).
    #[arg(long)]
    browser: bool,
    /// With --browser: the browser to use, an id from `browser list` (default: the first Chromium-based one).
    #[arg(long, value_name = "ID", requires = "browser")]
    browser_id: Option<String>,
    /// With --browser: show the browser window instead of running headless (for debugging).
    #[arg(long, requires = "browser")]
    headful: bool,
    /// With --browser: don't click elements whose label (text, title, id, name, class, href) matches this regex. Repeatable.
    #[arg(long, value_name = "REGEX", requires = "browser")]
    avoid: Vec<String>,
    /// With --browser: also click elements labelled like logout, delete or remove, and send DELETE requests.
    #[arg(long, requires = "browser")]
    allow_destructive: bool,
    /// Run detached; returns a job id for `job wait|status|stop`.
    #[arg(long)]
    background: bool,
    #[arg(long, hide = true)]
    job_id: Option<i64>,
}

pub fn crawl(project: &Path, home: &Path, args: CrawlArgs, out: &Out) -> Result<(), Error> {
    let guard = crate::project_guard(project)?;
    for seed in &args.urls {
        crate::require_in_scope(&guard, &brainproxy_core::http::Target::from_url(seed)?)?;
    }
    // Found before going to the background, so a missing browser is reported at once.
    let browser = args.browser.then(|| crate::browser_cmd::chromium(args.browser_id.as_deref())).transpose()?;
    let avoid = avoid_patterns(&args.avoid, args.allow_destructive)?;
    if args.background {
        return crate::jobs_cmd::spawn_background("crawl", project, home, out);
    }
    let mut exclude = Vec::new();
    if !args.no_default_exclude {
        exclude.push(Regex::new(DEFAULT_EXCLUDE).expect("valid default"));
    }
    for e in &args.exclude {
        exclude.push(Regex::new(e).map_err(|err| Error::InvalidInput(format!("--exclude {e:?}: {err}")))?);
    }
    let headers = args.headers.iter().map(|h| crate::request_args::parse_header(h)).collect::<Result<Vec<_>, _>>()?;
    let send = SendOptions {
        timeout: std::time::Duration::from_secs_f64(args.timeout.max(0.1)),
        verify_tls: args.verify_tls,
        sni: None,
        guard: Some(guard),
        http2: args.http2,
        host: brainproxy_core::http::client::HostPolicy::for_process(false),
        stream: Default::default(),
    };
    let auth = crate::auth_cmd::maybe_session(project, args.auth.as_deref(), &send)?;
    let cfg = CrawlConfig {
        seeds: args.urls.clone(),
        max_depth: args.depth,
        max_pages: args.max_pages,
        max_per_path: args.max_per_path.max(1),
        concurrency: args.concurrency.clamp(1, 200),
        rate: args.rate,
        send,
        headers,
        subdomains: args.subdomains,
        any_port: args.any_port,
        path_prefix: args.path_prefix.clone(),
        exclude,
        submit_forms: !args.no_forms,
        robots: !args.no_robots,
        sitemap: !args.no_sitemap,
        auth: auth.clone(),
        max_duration: args.max_minutes.map(|m| std::time::Duration::from_secs_f64(m.max(0.0) * 60.0)),
    };
    let browser_cfg = match browser {
        Some(path) => Some(browser_config(home, cfg.clone(), path, !args.headful, avoid, args.allow_destructive)?),
        None => None,
    };
    let summary = crate::jobs_cmd::run_job(project, args.job_id, |ctl| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let s = match browser_cfg {
            Some(b) => rt.block_on(browser_crawl::crawl(project, b, ctl)).map(|s| json!(s)),
            None => rt.block_on(crawl::crawl(project, cfg, ctl)).map(|s| json!(s)),
        };
        if let Some(a) = &auth {
            a.save()?;
        }
        s
    })?;
    out.ok(summary.clone(), || {
        let mut lines = vec![format!(
            "crawled {} requests, {} endpoints, {} new findings",
            summary["requests"], summary["endpoint_count"], summary["new_findings"]
        )];
        if summary["mode"] == "browser" {
            lines[0].push_str(&format!(
                " ({} pages loaded, {} clicks, {} forms, {} states, {} API calls)",
                summary["pages_loaded"],
                summary["clicks"],
                summary["forms_submitted"],
                summary["states"],
                summary["api_call_count"]
            ));
            if summary["sandbox"] == false {
                lines.push("warning: Chromium ran without its sandbox (BRAINPROXY_BROWSER_NO_SANDBOX)".into());
            }
        }
        for e in summary["endpoints"].as_array().into_iter().flatten() {
            let params: Vec<&str> = e["params"].as_array().into_iter().flatten().filter_map(|p| p.as_str()).collect();
            lines.push(format!(
                "  {:<6} {} {}",
                e["method"].as_str().unwrap_or(""),
                e["path"].as_str().unwrap_or(""),
                params.join(",")
            ));
        }
        lines.join("\n")
    });
    Ok(())
}

/// Labels never clicked by the browser crawl: the default destructive ones (unless
/// allowed) and any given with --avoid.
pub(crate) fn avoid_patterns(extra: &[String], allow_destructive: bool) -> Result<Vec<Regex>, Error> {
    let mut avoid = Vec::new();
    if !allow_destructive {
        avoid.push(Regex::new(DEFAULT_AVOID).expect("valid default"));
    }
    for a in extra {
        avoid.push(Regex::new(a).map_err(|err| Error::InvalidInput(format!("--avoid {a:?}: {err}")))?);
    }
    Ok(avoid)
}

/// A browser crawl with the plain crawl's seeds, limits and scope.
pub(crate) fn browser_config(
    home: &Path,
    crawl: CrawlConfig,
    browser: std::path::PathBuf,
    headless: bool,
    avoid: Vec<Regex>,
    allow_destructive: bool,
) -> Result<BrowserCrawlConfig, Error> {
    let (ca, _) = crate::proxy_cmd::load_ca(home)?;
    Ok(BrowserCrawlConfig { crawl, browser, headless, ca: Arc::new(ca), avoid, block_delete: !allow_destructive })
}
