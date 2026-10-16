//! CLI for the spider.

use std::path::Path;

use brainproxy_core::crawl::{self, CrawlConfig, DEFAULT_EXCLUDE};
use brainproxy_core::http::SendOptions;
use brainproxy_core::Error;
use regex::Regex;
use serde_json::json;

use crate::output::Out;

#[derive(clap::Args)]
pub struct CrawlArgs {
    /// Seed URLs. The crawl stays on their hosts.
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
    /// Also crawl subdomains of the seed hosts.
    #[arg(long)]
    subdomains: bool,
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
    /// Run detached; returns a job id for `job wait|status|stop`.
    #[arg(long)]
    background: bool,
    #[arg(long, hide = true)]
    job_id: Option<i64>,
}

pub fn crawl(project: &Path, home: &Path, args: CrawlArgs, out: &Out) -> Result<(), Error> {
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
    let cfg = CrawlConfig {
        seeds: args.urls.clone(),
        max_depth: args.depth,
        max_pages: args.max_pages,
        max_per_path: args.max_per_path.max(1),
        concurrency: args.concurrency.clamp(1, 200),
        rate: args.rate,
        send: SendOptions {
            timeout: std::time::Duration::from_secs_f64(args.timeout.max(0.1)),
            verify_tls: args.verify_tls,
            sni: None,
        },
        headers,
        subdomains: args.subdomains,
        path_prefix: args.path_prefix.clone(),
        exclude,
        submit_forms: !args.no_forms,
        robots: !args.no_robots,
        sitemap: !args.no_sitemap,
    };
    let summary = crate::jobs_cmd::run_job(project, args.job_id, |ctl| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let s = rt.block_on(crawl::crawl(project, cfg, ctl))?;
        Ok(json!(s))
    })?;
    out.ok(summary.clone(), || {
        let mut lines = vec![format!(
            "crawled {} requests, {} endpoints, {} new findings",
            summary["requests"], summary["endpoint_count"], summary["new_findings"]
        )];
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
