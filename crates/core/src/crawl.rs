//! Spider: breadth-first crawl from seed URLs. Follows links, redirects, frames,
//! scripts, meta refreshes, forms (submitted with generated values), robots.txt,
//! sitemap.xml, and URL paths written in page text or scripts (placeholder values
//! such as `…` or `{id}` filled in), staying inside a host/path scope. Cookies the
//! site sets are kept in a per-crawl jar and sent back. Every fetched exchange is
//! recorded (source "crawl") and passively scanned.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Serialize;
use url::Url;

use crate::auth::AuthSession;
use crate::capture::{decode_body, Capture};
use crate::error::{Error, Result};
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use crate::jobs::JobControl;
use crate::scan::message::SetCookie;
use crate::scan::passive::util::{decode_entities, now_unix, parse_http_date, tags, Tag};
use crate::store::Store;

#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub seeds: Vec<String>,
    pub max_depth: usize,
    pub max_pages: usize,
    /// Visits allowed per method + path (stops calendars and pagination traps).
    pub max_per_path: usize,
    pub concurrency: usize,
    pub rate: Option<f64>,
    pub send: SendOptions,
    /// Extra headers on every request (e.g. Cookie or Authorization for logged-in crawls).
    pub headers: Vec<(String, String)>,
    /// Also crawl subdomains of the seed hosts.
    pub subdomains: bool,
    /// Any port and scheme on the seed hosts. Otherwise only the seeds' origins
    /// (scheme, host, port), plus https on port 443 for an http seed.
    pub any_port: bool,
    /// Only crawl paths starting with this prefix.
    pub path_prefix: Option<String>,
    /// URLs matching any of these are never requested.
    pub exclude: Vec<Regex>,
    pub submit_forms: bool,
    pub robots: bool,
    pub sitemap: bool,
    /// Logged-in session applied to every request (re-login on logout).
    pub auth: Option<Arc<AuthSession>>,
    /// Stop crawling after this long.
    pub max_duration: Option<Duration>,
}

pub const DEFAULT_EXCLUDE: &str = r"(?i)(log|sign)[-_]?out|/logoff";

const STATIC_EXT: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tif", "tiff", "woff", "woff2", "ttf", "eot", "otf",
    "mp3", "mp4", "webm", "avi", "mov", "pdf", "zip", "gz", "tar", "rar", "7z", "exe", "dmg", "iso", "css", "map",
];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Req {
    method: String,
    url: String,
    body: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    pub params: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CrawlSummary {
    pub requests: usize,
    pub by_status: BTreeMap<String, usize>,
    pub depth_reached: usize,
    pub forms_submitted: usize,
    pub endpoints: Vec<Endpoint>,
    pub endpoint_count: usize,
    pub out_of_scope_hosts: Vec<String>,
    pub errors: usize,
    /// Exchanges that could not be saved to the project (e.g. too large).
    pub record_errors: usize,
    pub stopped: bool,
    pub limit_reached: bool,
    pub new_findings: usize,
    pub elapsed_ms: u64,
}

pub(crate) struct Scope {
    hosts: Vec<String>,
    /// Seed origins: (scheme, host, port).
    origins: Vec<(String, String, u16)>,
    any_port: bool,
    subdomains: bool,
    path_prefix: Option<String>,
    exclude: Vec<Regex>,
}

impl Scope {
    /// The crawl scope of `seeds` under `cfg`'s host, port and path rules.
    pub(crate) fn new(seeds: &[Url], cfg: &CrawlConfig) -> Scope {
        Scope {
            hosts: seeds.iter().filter_map(|u| u.host_str().map(|h| h.to_ascii_lowercase())).collect(),
            origins: seeds
                .iter()
                .filter_map(|u| {
                    Some((u.scheme().to_string(), u.host_str()?.to_ascii_lowercase(), u.port_or_known_default()?))
                })
                .collect(),
            any_port: cfg.any_port,
            subdomains: cfg.subdomains,
            path_prefix: cfg.path_prefix.clone(),
            exclude: cfg.exclude.clone(),
        }
    }

    pub(crate) fn host_allowed(&self, u: &Url) -> bool {
        let Some(host) = u.host_str().map(|h| h.to_ascii_lowercase()) else { return false };
        self.hosts.iter().any(|h| self.same_host(&host, h))
    }

    fn same_host(&self, host: &str, seed: &str) -> bool {
        host == seed || (self.subdomains && host.ends_with(&format!(".{seed}")))
    }

    /// On a seed's origin; an http seed also covers https on 443 (sites redirect there).
    fn origin_allowed(&self, u: &Url) -> bool {
        let (Some(host), Some(port)) = (u.host_str().map(|h| h.to_ascii_lowercase()), u.port_or_known_default()) else {
            return false;
        };
        self.origins.iter().any(|(scheme, h, p)| {
            self.same_host(&host, h)
                && ((u.scheme() == scheme && port == *p) || (scheme == "http" && u.scheme() == "https" && port == 443))
        })
    }

    /// On the crawl's sites: a seed host (or subdomain with `subdomains`) and, unless
    /// `any_port`, a seed origin. Path prefix and exclusions aside.
    pub(crate) fn on_site(&self, u: &Url) -> bool {
        self.host_allowed(u) && (self.any_port || self.origin_allowed(u)) && matches!(u.scheme(), "http" | "https")
    }

    pub(crate) fn allows(&self, u: &Url) -> bool {
        self.on_site(u)
            && self.path_prefix.as_deref().is_none_or(|p| u.path().starts_with(p))
            && !self.exclude.iter().any(|r| r.is_match(u.as_str()))
    }
}

/// The seed URLs (https:// assumed without a scheme); at least one.
pub(crate) fn parse_seeds(seeds: &[String]) -> Result<Vec<Url>> {
    let mut out = Vec::new();
    for s in seeds {
        let s = if s.contains("://") { s.clone() } else { format!("https://{s}") };
        out.push(Url::parse(&s).map_err(|e| Error::InvalidInput(format!("bad seed URL {s:?}: {e}")))?);
    }
    if out.is_empty() {
        return Err(Error::InvalidInput("give at least one seed URL".into()));
    }
    Ok(out)
}

pub(crate) type Writer = std::thread::JoinHandle<Result<(usize, usize)>>;

/// Saving and the passive scan on their own thread, beside the fetches. The thread
/// ends once every sender is dropped; [`join_writer`] gives (new findings, record errors).
pub(crate) fn spawn_writer(project: &Path) -> Result<(std::sync::mpsc::Sender<Capture>, Writer)> {
    let (save, saved) = std::sync::mpsc::channel::<Capture>();
    let mut store = Store::open(project)?;
    let writer = std::thread::spawn(move || -> Result<(usize, usize)> {
        let (mut new_findings, mut record_errors) = (0, 0);
        while let Ok(first) = saved.recv() {
            let mut captures = vec![first];
            captures.extend(saved.try_iter().take(255));
            // One unsavable exchange (e.g. a huge body) must not abort the crawl:
            // fall back to saving one by one and count what fails.
            if let Err(e) = store.record_batch(&captures) {
                eprintln!("brainproxy: crawl: saving {} exchanges failed ({e}); saving one by one", captures.len());
                for c in &captures {
                    if let Err(e) = store.record(c) {
                        eprintln!("brainproxy: crawl: exchange not saved: {e}");
                        record_errors += 1;
                    }
                }
            }
            new_findings += crate::scan::passive::scan_pending(&mut store)?.new_findings;
        }
        Ok((new_findings, record_errors))
    });
    Ok((save, writer))
}

pub(crate) async fn join_writer(writer: Writer) -> Result<(usize, usize)> {
    tokio::task::spawn_blocking(move || writer.join())
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?
        .map_err(|_| Error::Protocol("crawl writer panicked".into()))?
}

pub async fn crawl(project: &Path, cfg: CrawlConfig, ctl: JobControl) -> Result<CrawlSummary> {
    let started = Instant::now();
    let seeds = parse_seeds(&cfg.seeds)?;
    let scope = Scope::new(&seeds, &cfg);
    let (save, writer) = spawn_writer(project)?;

    let client = Arc::new(Client::new(cfg.send.clone()));
    // One limiter for the whole crawl: --rate holds across tasks and depths.
    let limiter = crate::scan::active::Limiter::new(cfg.rate).map(Arc::new);
    let mut summary = CrawlSummary::default();
    let mut seen: HashSet<Req> = HashSet::new();
    let mut per_path: HashMap<(String, String), usize> = HashMap::new();
    let mut endpoints: HashSet<Endpoint> = HashSet::new();
    let mut out_of_scope: HashSet<String> = HashSet::new();
    let jar = Arc::new(Mutex::new(CookieJar::default()));

    // Breadth first: a FIFO of (request, depth), with up to `concurrency` fetches in flight.
    let mut queue: VecDeque<(Req, usize)> = VecDeque::new();
    let push = |req: Req, depth: usize, queue: &mut VecDeque<(Req, usize)>, seen: &mut HashSet<Req>| {
        if seen.insert(req.clone()) {
            queue.push_back((req, depth));
        }
    };
    // The seeds, robots.txt and sitemap.xml pass the same filters (--path-prefix, --exclude)
    // as every link found later.
    for u in &seeds {
        let mut start = vec![u.clone()];
        let mut origin = u.clone();
        origin.set_query(None);
        origin.set_fragment(None);
        if cfg.robots {
            origin.set_path("/robots.txt");
            start.push(origin.clone());
        }
        if cfg.sitemap {
            origin.set_path("/sitemap.xml");
            start.push(origin.clone());
        }
        for u in start.iter().filter(|u| scope.allows(u)) {
            push(Req { method: "GET".into(), url: strip_fragment(u), body: None }, 0, &mut queue, &mut seen);
        }
    }

    let mut running = tokio::task::JoinSet::new();
    let mut sent = 0;
    loop {
        // Start fetches up to the limit, within the page budget and per-path cap.
        while running.len() < cfg.concurrency.max(1) && !ctl.stopped() {
            let Some((req, depth)) = queue.pop_front() else { break };
            if sent >= cfg.max_pages || cfg.max_duration.is_some_and(|d| started.elapsed() >= d) {
                summary.limit_reached = true;
                queue.clear();
                break;
            }
            let path = Url::parse(&req.url).map(|u| u.path().to_string()).unwrap_or_default();
            let n = per_path.entry((req.method.clone(), path)).or_default();
            if *n >= cfg.max_per_path {
                continue;
            }
            *n += 1;
            sent += 1;
            summary.depth_reached = summary.depth_reached.max(depth);
            let (client, headers, ctl, auth, jar, limiter) =
                (client.clone(), cfg.headers.clone(), ctl.clone(), cfg.auth.clone(), jar.clone(), limiter.clone());
            running.spawn(async move {
                if let Some(l) = &limiter {
                    l.wait().await;
                }
                if ctl.stopped() {
                    return None;
                }
                let result = fetch(&client, auth.as_deref(), &jar, &req, &headers).await;
                Some((req, depth, result))
            });
        }
        let Some(done) = running.join_next().await else { break };
        let Ok(Some((req, depth, (target, raw_req, outcome)))) = done else { continue };
        summary.requests += 1;
        let capture = match outcome {
            Err(e) => {
                summary.errors += 1;
                *summary.by_status.entry("error".into()).or_default() += 1;
                // A Host the scope doesn't list, refused as the request went out.
                if let Some(h) = crate::http::client::refused_host(&e).filter(|_| out_of_scope.len() < 50) {
                    out_of_scope.insert(h);
                }
                Capture::new("crawl", &target, &raw_req, None, None, Some(&e.to_string()))
            }
            Ok((response, ms)) => {
                let page = Url::parse(&req.url).ok();
                // The final response, after any interim ones (100 Continue, 103 Early Hints).
                let last = crate::http::client::final_response(&response);
                if let (Some(page), Ok(head)) = (page.as_ref(), parse_response_head(last)) {
                    *summary.by_status.entry(head.status.to_string()).or_default() += 1;
                    endpoints.insert(endpoint(&req, page));
                    let body = decode_body(&head.headers, split_head_body(last).1);
                    let found = if depth < cfg.max_depth {
                        extract(page, &head.headers, &body, cfg.submit_forms)
                    } else {
                        vec![]
                    };
                    for f in found {
                        let Ok(mut u) = Url::parse(&f.url) else { continue };
                        fill_placeholders(&mut u);
                        if !scope.allows(&u) {
                            if let Some(h) = u.host_str().filter(|_| !scope.host_allowed(&u)) {
                                if out_of_scope.len() < 50 {
                                    out_of_scope.insert(h.to_ascii_lowercase());
                                }
                            }
                            continue;
                        }
                        if is_static(&u) {
                            continue;
                        }
                        if f.form {
                            summary.forms_submitted += 1;
                        }
                        push(
                            Req { method: f.method, url: strip_fragment(&u), body: f.body },
                            depth + 1,
                            &mut queue,
                            &mut seen,
                        );
                    }
                }
                Capture::new("crawl", &target, &raw_req, Some(&response), Some(ms as i64), None)
            }
        };
        let _ = save.send(capture);
        if summary.requests % 10 == 0 {
            ctl.set_progress(serde_json::json!({
                "depth": summary.depth_reached,
                "requests": summary.requests,
                "queued": queue.len(),
                "endpoints": endpoints.len(),
            }));
        }
    }
    drop(save);
    let (new_findings, record_errors) = join_writer(writer).await?;
    summary.new_findings = new_findings;
    summary.record_errors = record_errors;

    summary.stopped = ctl.stopped();
    let mut eps: Vec<Endpoint> = endpoints.into_iter().collect();
    eps.sort();
    summary.endpoint_count = eps.len();
    eps.truncate(200);
    summary.endpoints = eps;
    let mut oos: Vec<String> = out_of_scope.into_iter().collect();
    oos.sort();
    summary.out_of_scope_hosts = oos;
    summary.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(summary)
}

type FetchResult = (Target, Vec<u8>, Result<(Vec<u8>, u64)>);

async fn fetch(
    client: &Client,
    auth: Option<&AuthSession>,
    jar: &Mutex<CookieJar>,
    req: &Req,
    headers: &[(String, String)],
) -> FetchResult {
    let mut hdrs = headers.to_vec();
    let url = Url::parse(&req.url).ok();
    if let Some(jarred) = url.as_ref().map(|u| jar.lock().unwrap().cookies(u)).filter(|c| !c.is_empty()) {
        // Cookies given with --header win over the jar's cookies of the same name.
        match hdrs.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
            Some((_, v)) => {
                let given: Vec<String> =
                    v.split(';').filter_map(|p| p.split('=').next()).map(|n| n.trim().to_string()).collect();
                for (n, val) in jarred.iter().filter(|(n, _)| !given.contains(n)) {
                    v.push_str(&format!("; {n}={val}"));
                }
            }
            None => hdrs
                .push(("Cookie".into(), jarred.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("; "))),
        }
    }
    if req.body.is_some() && !hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
        hdrs.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
    }
    if !hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("connection")) {
        hdrs.push(("Connection".into(), "keep-alive".into()));
    }
    let built = RawRequest::build(&req.method, &req.url, &hdrs, req.body.as_deref().unwrap_or("").as_bytes());
    let (raw, target) = match built {
        Ok(v) => v,
        Err(e) => {
            let target =
                Target::from_url(&req.url).unwrap_or(Target { scheme: "http".into(), host: String::new(), port: 80 });
            return (target, Vec::new(), Err(e));
        }
    };
    let sent = match auth {
        Some(a) => a.send_as(crate::session::Tool::Crawl, &raw, &target).await,
        None => client.send(&raw, &target).await,
    };
    match sent {
        // Record the request actually sent (with the session applied).
        Ok(ex) => {
            if let Some(u) = &url {
                jar.lock().unwrap().observe(u, &ex.response);
            }
            (target, ex.request, Ok((ex.response, ex.duration_ms)))
        }
        Err(e) => (target, raw.into_bytes(), Err(e)),
    }
}

/// Cookies set during one crawl (an RFC 6265 subset): host-only and Domain
/// cookies, Path matching, Secure, Expires/Max-Age, and deletion.
#[derive(Default)]
struct CookieJar(Vec<JarCookie>);

struct JarCookie {
    name: String,
    value: String,
    domain: String,
    host_only: bool,
    path: String,
    secure: bool,
    expires: Option<i64>,
}

impl CookieJar {
    /// Learns the Set-Cookie headers of a response (and of interim 1xx responses).
    fn observe(&mut self, url: &Url, response: &[u8]) {
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else { return };
        let now = now_unix();
        let mut rest = response;
        while let Ok(head) = parse_response_head(rest) {
            for (_, v) in head.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")) {
                let c = SetCookie::parse(v);
                if c.name.is_empty() {
                    continue;
                }
                let domain = c.attr("domain").map(|d| d.trim_start_matches('.').to_ascii_lowercase());
                let (domain, host_only) = match domain.filter(|d| !d.is_empty()) {
                    Some(d) if host == d || host.ends_with(&format!(".{d}")) => (d, false),
                    Some(_) => continue, // a cookie for another site is ignored
                    None => (host.clone(), true),
                };
                // Default path: the request path up to its last '/'.
                let path = c.attr("path").filter(|p| p.starts_with('/')).map(str::to_string).unwrap_or_else(|| {
                    let p = url.path();
                    match p.rfind('/') {
                        Some(i) if i > 0 => p[..i].to_string(),
                        _ => "/".into(),
                    }
                });
                let expires = match c.attr("max-age").and_then(|m| m.parse::<i64>().ok()) {
                    Some(age) => Some(now + age),
                    None => c.attr("expires").and_then(parse_http_date),
                };
                self.0.retain(|j| !(j.name == c.name && j.domain == domain && j.path == path));
                if expires.is_none_or(|t| t > now) {
                    let secure = c.has("secure");
                    self.0.push(JarCookie { name: c.name, value: c.value, domain, host_only, path, secure, expires });
                }
            }
            if (100..200).contains(&head.status) && head.status != 101 {
                rest = split_head_body(rest).1;
            } else {
                break;
            }
        }
    }

    /// Name/value pairs to send to `url`, longest path first.
    fn cookies(&self, url: &Url) -> Vec<(String, String)> {
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else { return vec![] };
        let (path, now) = (url.path(), now_unix());
        let mut out: Vec<&JarCookie> = self
            .0
            .iter()
            .filter(|c| {
                (host == c.domain || !c.host_only && host.ends_with(&format!(".{}", c.domain)))
                    && (path == c.path
                        || path.starts_with(&c.path)
                            && (c.path.ends_with('/') || path[c.path.len()..].starts_with('/')))
                    && (!c.secure || url.scheme() == "https")
                    && c.expires.is_none_or(|t| t > now)
            })
            .collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.path.len()));
        out.into_iter().map(|c| (c.name.clone(), c.value.clone())).collect()
    }
}

/// Whether a URL value is a documentation placeholder rather than a real value,
/// e.g. `…`, `...`, `{key}`, `<key>`, `[key]`, `:key`, `$KEY`, `xxx`.
fn is_placeholder(v: &str) -> bool {
    let v = v.trim();
    let wrapped = |a: char, b: char| v.len() >= 2 && v.starts_with(a) && v.ends_with(b);
    (!v.is_empty() && v.chars().all(|c| c == '.' || c == '…') && v != ".")
        || (v.len() >= 3 && v.chars().all(|c| c == 'x' || c == 'X'))
        || wrapped('{', '}')
        || wrapped('<', '>')
        || wrapped('[', ']')
        || (v.len() >= 2
            && (v.starts_with(':') || v.starts_with('$'))
            && v[1..].chars().all(|c| c.is_alphanumeric() || c == '_' || c == '{' || c == '}'))
}

/// Replaces placeholder query values and path segments with test values so the
/// parameter can be requested and attacked.
fn fill_placeholders(u: &mut Url) {
    let segments: Vec<String> =
        u.path_segments().map(|s| s.map(crate::scan::message::url_decode).collect()).unwrap_or_default();
    if segments.iter().any(|s| is_placeholder(s)) {
        let path: Vec<&str> = segments.iter().map(|s| if is_placeholder(s) { "1" } else { s.as_str() }).collect();
        u.set_path(&path.join("/"));
    }
    let pairs: Vec<(String, String)> = u.query_pairs().into_owned().collect();
    if pairs.iter().any(|(_, v)| is_placeholder(v)) {
        let filled: Vec<(String, String)> = pairs
            .into_iter()
            .map(|(k, v)| {
                let v = if is_placeholder(&v) { field_value(&k, "text", None) } else { v };
                (k, v)
            })
            .collect();
        u.query_pairs_mut().clear().extend_pairs(filled);
    }
}

fn endpoint(req: &Req, page: &Url) -> Endpoint {
    let mut params: Vec<String> = page.query_pairs().map(|(k, _)| k.into_owned()).collect();
    if let Some(b) = &req.body {
        params.extend(b.split('&').filter_map(|p| p.split('=').next()).map(crate::scan::message::url_decode));
    }
    params.sort();
    params.dedup();
    Endpoint { method: req.method.clone(), path: page.path().to_string(), params }
}

pub(crate) fn strip_fragment(u: &Url) -> String {
    let mut u = u.clone();
    u.set_fragment(None);
    u.to_string()
}

pub(crate) fn is_static(u: &Url) -> bool {
    let path = u.path().to_ascii_lowercase();
    path.rsplit_once('.').is_some_and(|(_, ext)| STATIC_EXT.contains(&ext))
}

#[derive(Debug)]
struct Found {
    method: String,
    url: String,
    body: Option<String>,
    form: bool,
}

/// Links and form submissions found in a response.
fn extract(page: &Url, headers: &[(String, String)], body: &[u8], forms: bool) -> Vec<Found> {
    let mut out = Vec::new();
    let link = |base: &Url, href: &str, out: &mut Vec<Found>| {
        let href = href.trim();
        if href.is_empty()
            || href.starts_with('#')
            || href.starts_with("javascript:")
            || href.starts_with("mailto:")
            || href.starts_with("data:")
        {
            return;
        }
        if let Ok(u) = base.join(href) {
            out.push(Found { method: "GET".into(), url: u.to_string(), body: None, form: false });
        }
    };
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("location") || k.eq_ignore_ascii_case("content-location") {
            link(page, v, &mut out);
        } else if k.eq_ignore_ascii_case("refresh") {
            if let Some(u) = refresh_url(v) {
                link(page, &u, &mut out);
            }
        }
    }
    let ct = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    let text = String::from_utf8_lossy(body);
    let path = page.path().to_ascii_lowercase();

    if path.ends_with("/robots.txt") {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim().replace('*', "");
                if (k == "allow" || k == "disallow" || k == "sitemap") && !v.is_empty() {
                    link(page, &v, &mut out);
                }
            }
        }
        return out;
    }
    if path.ends_with(".xml") || ct.contains("xml") && !ct.contains("html") {
        static LOC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<loc>\s*([^<\s]+)\s*</loc>").unwrap());
        for c in LOC.captures_iter(&text) {
            link(page, &decode_entities(&c[1]), &mut out);
        }
        if !ct.contains("html") {
            return out;
        }
    }
    if ct.contains("javascript") || ct.contains("json") {
        // Quoted absolute paths in scripts, e.g. fetch("/api/items").
        static PATHS: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#"["'`](/[A-Za-z0-9_\-./{}:~%]{1,150}(?:\?[^"'`\s]{0,200})?)["'`]"#).unwrap());
        for c in PATHS.captures_iter(&text) {
            if !c[1].starts_with("//") {
                link(page, &c[1], &mut out);
            }
        }
        return out;
    }
    if !ct.contains("html") {
        if ct.is_empty() || ct.starts_with("text/") {
            text_links(page, &text, &mut out);
        }
        return out;
    }

    let all = tags(&text);
    let base = all
        .iter()
        .find(|t| t.name == "base")
        .and_then(|t| t.attr("href"))
        .and_then(|h| page.join(h).ok())
        .unwrap_or_else(|| page.clone());
    for t in &all {
        let attr = match t.name.as_str() {
            "a" | "area" | "link" => "href",
            "script" | "iframe" | "frame" | "embed" => "src",
            "meta" => {
                if t.attr("http-equiv").is_some_and(|v| v.eq_ignore_ascii_case("refresh")) {
                    if let Some(u) = t.attr("content").and_then(refresh_url) {
                        link(&base, &u, &mut out);
                    }
                }
                continue;
            }
            _ => continue,
        };
        if let Some(h) = t.attr(attr) {
            link(&base, h, &mut out);
        }
    }
    if forms {
        out.extend(form_requests(&text, &all, &base));
    }
    // URLs written in the page text (e.g. "open /docs?key=… from your email"),
    // including inline scripts; tags are dropped so attributes aren't matched twice.
    static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->|<[^>]*>").unwrap());
    text_links(&base, &decode_entities(&TAG.replace_all(&text, " ")), &mut out);
    out
}

/// Same-site paths and absolute URLs mentioned in plain text, at most 200 per page.
fn text_links(base: &Url, text: &str, out: &mut Vec<Found>) {
    static URLS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?:^|[\s(\[,;=>"'`])((?:https?://[A-Za-z0-9.\-]+(?::\d+)?)?/[A-Za-z0-9_\-.~%/{}:]+(?:\?[^\s"'`()\[\]]*)?)"#,
        )
        .unwrap()
    });
    for c in URLS.captures_iter(text).take(200) {
        let raw = c[1].trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if raw.starts_with("//") || raw.len() < 2 {
            continue;
        }
        if let Ok(u) = base.join(raw) {
            out.push(Found { method: "GET".into(), url: u.to_string(), body: None, form: false });
        }
    }
}

fn refresh_url(v: &str) -> Option<String> {
    let lower = v.to_ascii_lowercase();
    let i = lower.find("url=")?;
    Some(v[i + 4..].trim().trim_matches(['\'', '"']).to_string())
}

/// Forms submitted per page; the rest are ignored.
const MAX_FORMS: usize = 200;

/// One request per form (at most `MAX_FORMS`), filled with existing or generated values.
/// Linear in the page: one forward pass over the tags and the `</form` closers.
fn form_requests(html: &str, all: &[Tag], base: &Url) -> Vec<Found> {
    use crate::scan::passive::util::find_ci;
    let mut out = Vec::new();
    let forms: Vec<usize> = all.iter().enumerate().filter(|(_, t)| t.name == "form").map(|(i, _)| i).collect();
    let mut close = None; // the next `</form` at or after the current form
    for (n, &fi) in forms.iter().enumerate().take(MAX_FORMS) {
        let form = &all[fi];
        // Fields between this form's start and the next </form> (or next form).
        if close.is_none_or(|c| c < form.end) {
            close = Some(find_ci(html, "</form", form.end).unwrap_or(html.len()));
        }
        let next_form = forms.get(n + 1).map(|&j| all[j].start).unwrap_or(html.len());
        let end = close.unwrap_or(html.len()).min(next_form);
        let inside = &all[fi + 1..forms.get(n + 1).copied().unwrap_or(all.len())];
        let inside = &inside[..inside.partition_point(|t| t.start < end)];
        let mut fields: Vec<(String, String)> = Vec::new();
        let mut radios: HashSet<String> = HashSet::new();
        for (k, t) in inside.iter().enumerate() {
            let Some(name) = t.attr("name").filter(|n| !n.is_empty()) else { continue };
            match t.name.as_str() {
                "input" => {
                    let ty = t.attr("type").unwrap_or("text").to_ascii_lowercase();
                    match ty.as_str() {
                        "submit" | "button" | "image" | "reset" | "file" => {
                            if ty == "submit" && t.has("value") {
                                fields.push((name.into(), t.attr("value").unwrap_or("").into()));
                            }
                        }
                        "checkbox" => fields.push((name.into(), t.attr("value").unwrap_or("on").into())),
                        "radio" => {
                            if radios.insert(name.to_string()) {
                                fields.push((name.into(), t.attr("value").unwrap_or("on").into()));
                            }
                        }
                        _ => fields.push((name.into(), field_value(name, &ty, t.attr("value")))),
                    }
                }
                "select" => {
                    // The first option before the next select (closing tags aren't in `all`).
                    let first = inside[k + 1..].iter().take_while(|o| o.name != "select").find(|o| o.name == "option");
                    let v = first.and_then(|o| o.attr("value").map(str::to_string)).unwrap_or_default();
                    fields.push((name.into(), v));
                }
                "textarea" => fields.push((name.into(), field_value(name, "text", None))),
                _ => {}
            }
        }
        let action = form
            .attr("action")
            .filter(|a| !a.trim().is_empty())
            .and_then(|a| base.join(a).ok())
            .unwrap_or_else(|| base.clone());
        let method = form.attr("method").unwrap_or("get").to_ascii_uppercase();
        let encoded =
            fields.iter().map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v))).collect::<Vec<_>>().join("&");
        if method == "POST" {
            out.push(Found { method: "POST".into(), url: action.to_string(), body: Some(encoded), form: true });
        } else {
            let mut u = action.clone();
            u.set_query(if encoded.is_empty() { None } else { Some(&encoded) });
            out.push(Found { method: "GET".into(), url: u.to_string(), body: None, form: true });
        }
    }
    out
}

/// A plausible value for a form field (like ZAP's default value generator).
pub(crate) fn field_value(name: &str, ty: &str, existing: Option<&str>) -> String {
    if let Some(v) = existing.filter(|v| !v.is_empty()) {
        return v.to_string();
    }
    let n = name.to_ascii_lowercase();
    match ty {
        "email" => "foo-bar@example.com".into(),
        "number" | "range" => "1".into(),
        "tel" => "9999999999".into(),
        "url" => "https://www.example.com".into(),
        "date" => "2018-01-01".into(),
        "time" => "12:00".into(),
        "color" => "#ffffff".into(),
        "password" => "ZAP-Password1".into(),
        _ if n.contains("mail") => "foo-bar@example.com".into(),
        _ if n.contains("phone") || n.contains("tel") => "9999999999".into(),
        _ if n.contains("url") || n.contains("website") => "https://www.example.com".into(),
        _ if n.contains("age") || n.contains("year") || n.contains("count") || n.contains("qty") || n == "id" => {
            "1".into()
        }
        _ => "brainproxy".into(),
    }
}

fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn extracts_links_forms_and_robots() {
        let page = Url::parse("https://a.test/dir/page.html").unwrap();
        let html = r#"<a href="other.html#x">o</a><a href="/abs?x=1">a</a><a href="javascript:void(0)">j</a>
            <script src="//cdn.test/x.js"></script><meta http-equiv="refresh" content="5; url=/next">
            <form action="/login" method="post"><input name="user"><input type="password" name="pw">
            <input type="email" name="mail"><select name="c"><option value="uk">UK</option></select>
            <input type="submit" value="Go"></form><form><input name="q" value="hi"></form>"#;
        let headers = vec![("Content-Type".to_string(), "text/html".to_string())];
        let found = extract(&page, &headers, html.as_bytes(), true);
        let urls: Vec<&str> = found.iter().map(|f| f.url.as_str()).collect();
        assert!(urls.contains(&"https://a.test/dir/other.html#x"));
        assert!(urls.contains(&"https://a.test/abs?x=1"));
        assert!(urls.contains(&"https://cdn.test/x.js"));
        assert!(urls.contains(&"https://a.test/next"));
        let post = found.iter().find(|f| f.method == "POST").unwrap();
        assert_eq!(post.url, "https://a.test/login");
        assert_eq!(post.body.as_deref(), Some("user=brainproxy&pw=ZAP-Password1&mail=foo-bar%40example.com&c=uk"));
        assert!(found.iter().any(|f| f.url == "https://a.test/dir/page.html?q=hi"));

        let robots = Url::parse("https://a.test/robots.txt").unwrap();
        let found = extract(&robots, &[], b"User-agent: *\nDisallow: /admin/ # secret\nAllow: /pub*\n", false);
        let urls: Vec<&str> = found.iter().map(|f| f.url.as_str()).collect();
        assert_eq!(urls, ["https://a.test/admin/", "https://a.test/pub"]);

        let js = Url::parse("https://a.test/app.js").unwrap();
        let h = vec![("Content-Type".to_string(), "application/javascript".to_string())];
        let found = extract(&js, &h, br#"fetch("/api/items?limit=5"); x = '//cdn'"#, false);
        assert_eq!(found[0].url, "https://a.test/api/items?limit=5");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn extracts_urls_from_page_text_and_fills_placeholders() {
        let page = Url::parse("http://a.test/api/doc.html").unwrap();
        let html = "<p>Open it from your email\n(<code>/api/doc.html?publickey=&hellip;</code>). See /help/{topic}, \
            http://a.test/x?id=xxx and http://other.test/y. Not km/h or 24/7.</p><a href=\"/linked\">l</a>";
        let headers = vec![("Content-Type".to_string(), "text/html".to_string())];
        let mut urls: Vec<String> = extract(&page, &headers, html.as_bytes(), false)
            .into_iter()
            .map(|f| {
                let mut u = Url::parse(&f.url).unwrap();
                fill_placeholders(&mut u);
                u.to_string()
            })
            .collect();
        urls.sort();
        assert_eq!(
            urls,
            [
                "http://a.test/api/doc.html?publickey=brainproxy",
                "http://a.test/help/1",
                "http://a.test/linked",
                "http://a.test/x?id=1",
                "http://other.test/y",
            ]
        );
        // Plain text (and 4xx bodies, which are parsed like any other).
        let h = vec![("Content-Type".to_string(), "text/plain".to_string())];
        let found = extract(&page, &h, b"GET /v1/users/:id?fields=<fields> returns a user", false);
        let mut u = Url::parse(&found[0].url).unwrap();
        fill_placeholders(&mut u);
        assert_eq!(u.as_str(), "http://a.test/v1/users/1?fields=brainproxy");
        for p in ["…", "...", "{key}", "<key>", "[key]", "xxx", ":id", "$KEY"] {
            assert!(is_placeholder(p), "{p}");
        }
        for v in ["1", "abc", ".", "x", "", "a.b"] {
            assert!(!is_placeholder(v), "{v}");
        }
    }

    #[test]
    fn cookie_jar_scopes_and_expires() {
        let mut jar = CookieJar::default();
        let login = Url::parse("http://a.test/app/login").unwrap();
        jar.observe(
            &login,
            b"HTTP/1.1 200 OK\r\nSet-Cookie: dev=1; Path=/; Max-Age=3600\r\nSet-Cookie: here=2\r\n\
              Set-Cookie: sec=3; Secure\r\nSet-Cookie: dom=4; Domain=.a.test; Path=/\r\n\
              Set-Cookie: evil=5; Domain=b.test\r\nSet-Cookie: old=6; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n\r\n",
        );
        let names = |jar: &CookieJar, u: &str| -> Vec<String> {
            jar.cookies(&Url::parse(u).unwrap()).into_iter().map(|(n, _)| n).collect()
        };
        // `here` defaults to path /app; `sec` is https only; `evil` and `old` are dropped.
        assert_eq!(names(&jar, "http://a.test/app/x"), ["here", "dev", "dom"]);
        assert_eq!(names(&jar, "http://a.test/application"), ["dev", "dom"]);
        assert_eq!(names(&jar, "https://a.test/app"), ["here", "sec", "dev", "dom"]);
        assert_eq!(names(&jar, "http://sub.a.test/"), ["dom"]);
        assert!(names(&jar, "http://b.test/").is_empty());
        // Replaced, then deleted with Max-Age=0.
        jar.observe(&login, b"HTTP/1.1 200 OK\r\nSet-Cookie: dev=new; Path=/\r\n\r\n");
        assert_eq!(
            jar.cookies(&Url::parse("http://a.test/").unwrap()),
            [("dom".into(), "4".into()), ("dev".into(), "new".into())]
        );
        jar.observe(&login, b"HTTP/1.1 200 OK\r\nSet-Cookie: dev=; Path=/; Max-Age=0\r\n\r\n");
        assert_eq!(names(&jar, "http://a.test/"), ["dom"]);
    }

    #[test]
    fn scope_rules() {
        let scope = Scope {
            hosts: vec!["a.test".into()],
            origins: vec![("https".into(), "a.test".into(), 443)],
            any_port: false,
            subdomains: false,
            path_prefix: Some("/app".into()),
            exclude: vec![Regex::new(DEFAULT_EXCLUDE).unwrap()],
        };
        assert!(scope.allows(&Url::parse("https://a.test/app/x").unwrap()));
        assert!(!scope.allows(&Url::parse("https://a.test/other").unwrap()));
        assert!(!scope.allows(&Url::parse("https://b.a.test/app").unwrap()));
        assert!(!scope.allows(&Url::parse("https://a.test/app/logout").unwrap()));
        assert!(!scope.allows(&Url::parse("ftp://a.test/app").unwrap()));
    }

    #[test]
    fn scope_keeps_the_seed_origin_unless_any_port() {
        let mut scope = Scope {
            hosts: vec!["a.test".into()],
            origins: vec![("http".into(), "a.test".into(), 8080)],
            any_port: false,
            subdomains: false,
            path_prefix: None,
            exclude: vec![],
        };
        let ok = |s: &Scope, u: &str| s.allows(&Url::parse(u).unwrap());
        assert!(ok(&scope, "http://a.test:8080/x"));
        // http -> https on the same host is the same site.
        assert!(ok(&scope, "https://a.test/x"));
        assert!(!ok(&scope, "http://a.test:8081/internal-admin"));
        assert!(!ok(&scope, "http://a.test/x"));
        assert!(!ok(&scope, "https://a.test:8443/x"));
        scope.any_port = true;
        assert!(ok(&scope, "http://a.test:8081/internal-admin"));
        assert!(!ok(&scope, "http://b.test:8080/x"));
    }

    #[test]
    fn form_extraction_is_linear_and_capped() {
        let page = Url::parse("http://a.test/").unwrap();
        let headers = vec![("Content-Type".to_string(), "text/html".to_string())];
        // 40,000 unclosed forms took ~9 s when each form scanned to the end of the page.
        let html = "<form><input name=a>".repeat(40_000);
        let started = Instant::now();
        let found = extract(&page, &headers, html.as_bytes(), true);
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
        let forms: Vec<&Found> = found.iter().filter(|f| f.form).collect();
        assert_eq!(forms.len(), MAX_FORMS);
        assert!(forms.iter().all(|f| f.url == "http://a.test/?a=brainproxy"), "{forms:?}");
        // Fields stop at </form>; a select takes its first option.
        let html = "<form method=post><select name=s><option value=x><option value=y></select></form>\
                    <input name=outside><form><select name=t></select><input name=b></form>";
        let found = extract(&page, &headers, html.as_bytes(), true);
        let bodies: Vec<String> =
            found.iter().filter(|f| f.form).map(|f| f.body.clone().unwrap_or_else(|| f.url.clone())).collect();
        assert_eq!(bodies, ["s=x", "http://a.test/?t=&b=brainproxy"]);
    }
}
