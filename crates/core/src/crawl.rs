//! Spider: breadth-first crawl from seed URLs. Follows links, redirects, frames,
//! scripts, meta refreshes, forms (submitted with generated values), robots.txt,
//! sitemap.xml, URL paths written in page text or scripts (placeholder values
//! such as `…`, `{id}` or a template literal's `${id}` filled in), and the chunks a
//! bundle loads by relative path, staying inside a host/path scope. Cookies the
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
use crate::sent::{RowBatch, RowWrite, Rows};
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
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "tif", "tiff", "woff", "woff2", "ttf", "eot",
    "otf", "mp3", "mp4", "webm", "avi", "mov", "pdf", "zip", "gz", "tar", "rar", "7z", "exe", "dmg", "iso", "css",
    "map",
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

/// A path a script or page names, with the method the code uses if it shows one.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unconfirmed {
    pub method: String,
    pub path: String,
    pub params: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CrawlSummary {
    pub requests: usize,
    pub by_status: BTreeMap<String, usize>,
    pub depth_reached: usize,
    pub forms_submitted: usize,
    /// At most 200; `endpoint_count` has the total.
    pub endpoints: Vec<Endpoint>,
    pub endpoint_count: usize,
    /// `endpoints` lists only the first 200.
    pub endpoints_truncated: bool,
    /// Responses that were a copy of the site's answer to any unknown path (its catch-all
    /// page, such as a single-page app's index.html), after the first: not counted as
    /// endpoints, and their links aren't read again.
    pub fallback_pages: usize,
    /// Paths found only in scripts or page text that aren't endpoints yet: a method other
    /// than GET is written beside them (not requested), or a GET answered 405 or 5xx.
    pub unconfirmed_endpoints: Vec<Unconfirmed>,
    pub unconfirmed_count: usize,
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

/// What a crawl's writer thread saves.
pub(crate) enum Save {
    /// The row of a request about to go out, or its completion (see [`Rows`]).
    Row(RowWrite),
    /// A request that wasn't sent (blocked, or refused before it went out).
    Unsent(Box<Capture>),
}

/// The rows of a crawl's requests (source `source`), saved by its writer thread `save`.
pub(crate) fn rows(source: &'static str, save: &std::sync::mpsc::Sender<Save>) -> Rows {
    let save = save.clone();
    Rows::new(source, move |w| drop(save.send(Save::Row(w))))
}

/// Saving and the passive scan on their own thread, beside the fetches. Everything queued
/// since the last write is written in one transaction. The thread ends once every sender
/// (and every [`Rows`] made by [`rows`]) is dropped; [`join_writer`] gives (new findings,
/// record errors).
pub(crate) fn spawn_writer(project: &Path) -> Result<(std::sync::mpsc::Sender<Save>, Writer)> {
    let (save, saved) = std::sync::mpsc::channel::<Save>();
    let mut store = Store::open(project)?;
    let writer = std::thread::spawn(move || -> Result<(usize, usize)> {
        let (mut new_findings, mut record_errors) = (0, 0);
        while let Ok(first) = saved.recv() {
            let mut rows = RowBatch::default();
            let mut unsent = Vec::new();
            for s in std::iter::once(first).chain(saved.try_iter().take(255)) {
                match s {
                    Save::Row(w) => rows.push(w),
                    Save::Unsent(c) => unsent.push(*c),
                }
            }
            // One unsavable exchange (e.g. a huge body) must not abort the crawl: these
            // fall back to saving one by one and count what fails.
            let written = rows.write(&mut store);
            record_errors += written.failed;
            if !unsent.is_empty() {
                if let Err(e) = store.record_batch(&unsent) {
                    eprintln!("brainproxy: crawl: saving {} rows failed ({e}); saving one by one", unsent.len());
                    for c in &unsent {
                        if let Err(e) = store.record(c) {
                            eprintln!("brainproxy: crawl: row not saved: {e}");
                            record_errors += 1;
                        }
                    }
                }
            }
            // A row the passive scan passed while it was pending is scanned now.
            for id in written.completed {
                new_findings += crate::scan::passive::scan_late(&mut store, id)?;
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
    let rows = rows("crawl", &save).sent_by(&client);

    // One limiter for the whole crawl: --rate holds across tasks and depths.
    let limiter = crate::scan::active::Limiter::new(cfg.rate).map(Arc::new);
    let mut summary = CrawlSummary::default();
    let mut seen: HashSet<Req> = HashSet::new();
    let mut per_path: HashMap<(String, String), usize> = HashMap::new();
    let mut endpoints: HashSet<Endpoint> = HashSet::new();
    let mut out_of_scope: HashSet<String> = HashSet::new();
    let jar = Arc::new(Mutex::new(CookieJar::default()));
    let mut sent = 0;

    // Single-page apps (and soft-404 sites) answer every unknown path with the same page. Its
    // relative links resolve against each path it is served at (`/a/b` → `/a/main.js`, which is
    // that page again), so reading every copy multiplies the crawl. A path that can't exist
    // shows what that answer looks like on each seed's origin.
    let mut fallbacks: HashMap<String, (u16, u64)> = HashMap::new();
    for u in &seeds {
        let origin = u.origin().ascii_serialization();
        // A budget that only covers the seeds has no room for copies to skip.
        if fallbacks.contains_key(&origin) || ctl.stopped() || sent + seeds.len() >= cfg.max_pages {
            continue;
        }
        let Some(probe) = fallback_probe(u).filter(|p| scope.allows(p)) else { continue };
        if let Some(l) = &limiter {
            l.wait().await;
        }
        let req = Req { method: "GET".into(), url: probe.to_string(), body: None };
        sent += 1;
        let (target, raw_req, recorded, outcome) =
            fetch(&client, &rows, cfg.auth.as_deref(), &jar, &req, &cfg.headers).await;
        summary.requests += 1;
        match outcome.as_deref().map(crate::http::client::final_response).map(|r| (parse_response_head(r), r)) {
            Ok((Ok(head), last)) => {
                *summary.by_status.entry(head.status.to_string()).or_default() += 1;
                let body = decode_body(&head.headers, split_head_body(last).1);
                fallbacks.insert(origin, (head.status, body_hash(&body)));
            }
            Ok((Err(_), _)) => *summary.by_status.entry("error".into()).or_default() += 1,
            Err(e) => failed(&mut summary, &mut out_of_scope, &save, (&target, &raw_req, recorded), e),
        }
    }
    // Origins whose catch-all page has been read once.
    let mut fallback_read: HashSet<String> = HashSet::new();

    let mut unconfirmed: BTreeMap<(String, String), Unconfirmed> = BTreeMap::new();
    let mut unconfirm = |method: &str, u: &Url, reason: String| {
        let ep = endpoint(&Req { method: method.into(), url: String::new(), body: None }, u);
        unconfirmed.entry((ep.method.clone(), ep.path.clone())).or_insert(Unconfirmed {
            method: ep.method,
            path: ep.path,
            params: ep.params,
            reason,
        });
    };

    // Breadth first: a FIFO of (request, depth, whether its URL was guessed from text), with up
    // to `concurrency` fetches in flight.
    let mut queue: VecDeque<(Req, usize, bool)> = VecDeque::new();
    let push = |req: Req, depth: usize, guessed: bool, queue: &mut VecDeque<_>, seen: &mut HashSet<Req>| {
        if seen.insert(req.clone()) {
            queue.push_back((req, depth, guessed));
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
            push(Req { method: "GET".into(), url: strip_fragment(u), body: None }, 0, false, &mut queue, &mut seen);
        }
    }

    let mut running = tokio::task::JoinSet::new();
    loop {
        // Start fetches up to the limit, within the page budget and per-path cap.
        while running.len() < cfg.concurrency.max(1) && !ctl.stopped() {
            let Some((req, depth, guessed)) = queue.pop_front() else { break };
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
            let (client, headers, ctl, auth, jar, limiter, rows) = (
                client.clone(),
                cfg.headers.clone(),
                ctl.clone(),
                cfg.auth.clone(),
                jar.clone(),
                limiter.clone(),
                rows.clone(),
            );
            running.spawn(async move {
                if let Some(l) = &limiter {
                    l.wait().await;
                }
                if ctl.stopped() {
                    return None;
                }
                let result = fetch(&client, &rows, auth.as_deref(), &jar, &req, &headers).await;
                Some((req, depth, guessed, result))
            });
        }
        let Some(done) = running.join_next().await else { break };
        let Ok(Some((req, depth, guessed, (target, raw_req, recorded, outcome)))) = done else { continue };
        summary.requests += 1;
        match outcome {
            Err(e) => failed(&mut summary, &mut out_of_scope, &save, (&target, &raw_req, recorded), &e),
            Ok(response) => {
                let page = Url::parse(&req.url).ok();
                // The final response, after any interim ones (100 Continue, 103 Early Hints).
                let last = crate::http::client::final_response(&response);
                if let (Some(page), Ok(head)) = (page.as_ref(), parse_response_head(last)) {
                    *summary.by_status.entry(head.status.to_string()).or_default() += 1;
                    let body = decode_body(&head.headers, split_head_body(last).1);
                    let origin = page.origin().ascii_serialization();
                    // The first copy is read: a seed is often the app's own page.
                    let copy = fallbacks.get(&origin) == Some(&(head.status, body_hash(&body)))
                        && !fallback_read.insert(origin);
                    // A path read from a script may take another method: a GET it refuses or fails
                    // on isn't a page, and the error page's stack trace isn't a list of links.
                    let refused = guessed && req.method == "GET" && (head.status == 405 || head.status >= 500);
                    if copy {
                        summary.fallback_pages += 1;
                    } else if refused {
                        unconfirm("GET", page, format!("GET answered {}", head.status));
                    } else {
                        endpoints.insert(endpoint(&req, page));
                    }
                    let found = if depth < cfg.max_depth && !copy && !refused {
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
                        // Sent as GET it would only fail, and sent as written it would need a
                        // body the crawler can't know: listed instead.
                        if let Some(m) = f.hint {
                            unconfirm(m, &u, format!("{m} in the script; not requested"));
                            continue;
                        }
                        if f.form {
                            summary.forms_submitted += 1;
                        }
                        push(
                            Req { method: f.method, url: strip_fragment(&u), body: f.body },
                            depth + 1,
                            f.guessed,
                            &mut queue,
                            &mut seen,
                        );
                    }
                }
            }
        }
        if summary.requests % 10 == 0 {
            ctl.set_progress(serde_json::json!({
                "depth": summary.depth_reached,
                "requests": summary.requests,
                "queued": queue.len(),
                "endpoints": endpoints.len(),
            }));
        }
    }
    drop((save, rows));
    let (new_findings, record_errors) = join_writer(writer).await?;
    summary.new_findings = new_findings;
    summary.record_errors = record_errors;

    summary.stopped = ctl.stopped();
    let mut eps: Vec<Endpoint> = endpoints.into_iter().collect();
    eps.sort();
    summary.endpoint_count = eps.len();
    summary.endpoints_truncated = eps.len() > 200;
    eps.truncate(200);
    summary.endpoints = eps;
    summary.unconfirmed_count = unconfirmed.len();
    summary.unconfirmed_endpoints = unconfirmed.into_values().take(200).collect();
    let mut oos: Vec<String> = out_of_scope.into_iter().collect();
    oos.sort();
    summary.out_of_scope_hosts = oos;
    summary.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(summary)
}

/// Counts a request that failed. Its row says how; one refused before it went out gets one now.
fn failed(
    summary: &mut CrawlSummary,
    out_of_scope: &mut HashSet<String>,
    save: &std::sync::mpsc::Sender<Save>,
    (target, raw_req, recorded): (&Target, &[u8], bool),
    e: &Error,
) {
    summary.errors += 1;
    *summary.by_status.entry("error".into()).or_default() += 1;
    // A Host the scope doesn't list, refused as the request went out.
    if let Some(h) = crate::http::client::refused_host(e).filter(|_| out_of_scope.len() < 50) {
        out_of_scope.insert(h);
    }
    if !recorded {
        let _ =
            save.send(Save::Unsent(Box::new(Capture::new("crawl", target, raw_req, None, None, Some(&e.to_string())))));
    }
}

/// The target, the request (as sent, if it was), whether it has a row, and the response.
type FetchResult = (Target, Vec<u8>, bool, Result<Vec<u8>>);

/// Sends `req`, each request on record (in `rows`) before it goes out.
async fn fetch(
    client: &Client,
    rows: &Rows,
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
            return (target, Vec::new(), false, Err(e));
        }
    };
    let (ids, sent) = rows.send_with(client, auth, crate::session::Tool::Crawl, &raw, &target).await;
    match sent {
        Ok(ex) => {
            if let Some(u) = &url {
                jar.lock().unwrap().observe(u, &ex.response);
            }
            (target, ex.request, true, Ok(ex.response))
        }
        Err(e) => (target, raw.into_bytes(), !ids.is_empty(), Err(e)),
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

/// A path that can't exist, beside the seed (so it stays under a path prefix).
fn fallback_probe(seed: &Url) -> Option<Url> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).ok()?;
    let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
    seed.join(&format!("brainproxy-{name}")).ok()
}

/// Identifies a body exactly; a catch-all page that echoes the path or a nonce isn't caught.
fn body_hash(body: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    body.hash(&mut h);
    h.finish()
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
    /// Read from a script or page text rather than a link, form or header.
    guessed: bool,
    /// The method the script uses for it, when that isn't GET.
    hint: Option<&'static str>,
}

impl Found {
    fn get(url: &Url, guessed: bool) -> Found {
        Found { method: "GET".into(), url: url.to_string(), body: None, form: false, guessed, hint: None }
    }
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
            out.push(Found::get(&u, false));
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
        // Template literals, as compiled apps write their API calls (`/api/users/${id}`): each
        // `${…}` becomes a placeholder, filled in like `{id}`.
        let (text, _) = interpolate(&text);
        // Quoted absolute paths in scripts, e.g. fetch("/api/items"), also after a base URL
        // interpolated first (`${this.host}/rest/items`), which is where Angular services keep
        // theirs. A concatenated base (`host + "/api/x"`) leaves the path quoted on its own.
        static PATHS: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"["'`]((?:\{x\})*)(/[A-Za-z0-9_\-./{}:~%]{1,150}(?:\?[^"'`\s]{0,200})?)["'`]"#).unwrap()
        });
        for c in PATHS.captures_iter(&text) {
            let (Some(whole), Some(lead)) = (c.get(0), c.get(1)) else { continue };
            let path = &c[2];
            // Minified code joins anything with "/" (`${a}/${b}`, `len + "/160"`, a parse
            // table's `O'/SQ` between two different quote characters): only a path with a word
            // in it, quoted alike at both ends, with a query of `name=value` pairs, is taken.
            let quoted_alike = whole.as_str().bytes().next() == whole.as_str().bytes().last();
            let query_ok = path.split_once('?').is_none_or(|(_, q)| {
                q.is_empty() || q.split('&').all(|p| p.contains('=') && !p.contains(['<', '>', '!', '?']))
            });
            if path.starts_with("//")
                || !has_word(path)
                || !quoted_alike
                || !query_ok
                || string_argument(&text, whole.start())
            {
                continue;
            }
            // One that starts with another value (`${this.host}/${id}/reviews`) has a base that
            // holds a path of its own, unknown here.
            if !lead.as_str().is_empty() && path.starts_with("/{x}") {
                continue;
            }
            let joined = path;
            if let Ok(u) = page.join(joined) {
                out.push(Found { hint: method_hint(&text, whole.range()), ..Found::get(&u, true) });
            }
        }
        chunk_links(page, &text, &mut out);
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

/// The method a script sends `at` (a quoted path in `text`) with, when it says and it isn't
/// GET: `http.post(`…`, b)`, `$.ajax("/x", {type: "PUT"})`, `fetch("/x", {method: "POST"})`.
fn method_hint(text: &str, at: std::ops::Range<usize>) -> Option<&'static str> {
    // The call's opening, with nothing between it and the path that ends an expression.
    static BEFORE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\.(post|put|patch|delete)\s*\(\s*[^;()]{0,80}$").unwrap());
    // The options object right after the path, in the same call.
    static AFTER: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)^[^;()]{0,100}?\b(?:method|type)\s*:\s*["'`](post|put|patch|delete)["'`]"#).unwrap()
    });
    let before = window(text, at.start.saturating_sub(100), at.start);
    let after = window(text, at.end, at.end.saturating_add(150));
    let m = BEFORE.captures(before).or_else(|| AFTER.captures(after))?;
    ["POST", "PUT", "PATCH", "DELETE"].into_iter().find(|v| v.eq_ignore_ascii_case(&m[1]))
}

/// `text[from..to]`, both ends moved inwards to char boundaries.
fn window(text: &str, from: usize, to: usize) -> &str {
    let to = to.min(text.len());
    let (mut from, mut to) = (from.min(to), to);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    while to > from && !text.is_char_boundary(to) {
        to -= 1;
    }
    text.get(from..to).unwrap_or("")
}

/// `text` with each template literal's `${…}` replaced by the placeholder `{x}` (filled in like
/// `{id}`), and where each placeholder starts in the result with the expression it replaced.
fn interpolate(text: &str) -> (String, Vec<(usize, String)>) {
    static INTERPOLATION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{([^{}`]{0,100})\}").unwrap());
    let (mut out, mut exprs, mut last) = (String::with_capacity(text.len()), Vec::new(), 0);
    for c in INTERPOLATION.captures_iter(text) {
        let (Some(m), Some(expr)) = (c.get(0), c.get(1)) else { continue };
        out.push_str(&text[last..m.start()]);
        exprs.push((out.len(), expr.as_str().to_string()));
        out.push_str("{x}");
        last = m.end();
    }
    out.push_str(&text[last..]);
    (out, exprs)
}

/// Whether the string at `at` is an argument of a string method (`url.replace("/v3/", "/ws/v3/")`,
/// `s.split("/")`): text being edited, not a path the app requests.
fn string_argument(text: &str, at: usize) -> bool {
    static CALL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\.(?:replace|replaceAll|split|join)\(\s*(?:[^,()]{0,80},\s*)?$").unwrap());
    CALL.is_match(window(text, at.saturating_sub(100), at))
}

/// Two letters in a row outside the `{x}` placeholders: `/rest/items`, not `/{x}` or `/0/1`.
fn has_word(path: &str) -> bool {
    path.replace("{x}", "/").as_bytes().windows(2).any(|w| w[0].is_ascii_alphabetic() && w[1].is_ascii_alphabetic())
}

/// Scripts a bundle loads later by a relative path: the code-split chunks of each route, where
/// single-page apps keep most of their API calls. `./x.js` and `../x.js` are relative to the
/// script (dynamic `import()`). A bare `assets/x.js` (Vite's preload list, webpack's chunk
/// paths) is relative to where the app is served: the script's parent folder when the path starts
/// with the script's own folder (`/app/assets/index.js` loading `assets/x.js`), else the origin's
/// root. At most 200 per script.
fn chunk_links(script: &Url, text: &str, out: &mut Vec<Found>) {
    static CHUNKS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"["'`]((?:\.\.?/)*[A-Za-z0-9_\-.]+(?:/[A-Za-z0-9_\-.]+)*\.m?js)["'`]"#).unwrap());
    let folders: Vec<&str> = script.path_segments().map(|s| s.collect()).unwrap_or_default();
    let dir = folders.len().checked_sub(2).and_then(|i| folders.get(i)).copied().unwrap_or_default();
    for c in CHUNKS.captures_iter(text).take(200) {
        let path = &c[1];
        let joined = if path.starts_with("./") || path.starts_with("../") {
            script.join(path)
        } else if let Some((first, _)) = path.split_once('/') {
            let base = if !dir.is_empty() && first == dir { "../" } else { "/" };
            script.join(base).and_then(|b| b.join(path))
        } else {
            // A bare file name is as likely a word in a message as a chunk.
            continue;
        };
        if let Ok(u) = joined {
            out.push(Found::get(&u, false));
        }
    }
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
        let Some(m) = c.get(1) else { continue };
        let raw = m.as_str().trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if raw.starts_with("//") || raw.len() < 2 || stack_frame(raw, &text[m.end()..]) {
            continue;
        }
        if let Ok(u) = base.join(raw) {
            out.push(Found::get(&u, true));
        }
    }
}

/// Whether `path` (followed by `after`) names a source file in a stack trace rather than a
/// page: `/app/x.js:68:18` (Node, Ruby's `x.rb:12:in`), `File "/app/x.py", line 12` (Python),
/// `/var/www/x.php(12)` or `/var/www/x.php on line 7` (PHP).
fn stack_frame(path: &str, after: &str) -> bool {
    static LINE_COL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\.[A-Za-z][A-Za-z0-9]{0,9}:\d+(?::\d+)?(?::in)?$").unwrap());
    static LINE_AFTER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^(?:\(\d+\)|"?,? line \d|"?\s+on line \d)"#).unwrap());
    LINE_COL.is_match(path) || LINE_AFTER.is_match(after)
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
            out.push(Found { body: Some(encoded), form: true, method: "POST".into(), ..Found::get(&action, false) });
        } else {
            let mut u = action.clone();
            u.set_query(if encoded.is_empty() { None } else { Some(&encoded) });
            out.push(Found { form: true, ..Found::get(&u, false) });
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

    /// A single-page app's bundle: API calls in template literals, and its routes' chunks.
    #[test]
    fn extracts_template_paths_and_chunks_from_bundles() {
        let h = vec![("Content-Type".to_string(), "text/javascript".to_string())];
        let urls = |script: &str, body: &str| -> Vec<String> {
            let mut out: Vec<String> = extract(&Url::parse(script).unwrap(), &h, body.as_bytes(), false)
                .into_iter()
                .map(|f| {
                    let mut u = Url::parse(&f.url).unwrap();
                    fill_placeholders(&mut u);
                    u.to_string()
                })
                .collect();
            out.sort();
            out
        };
        let bundle = r#"a.get(`/api/users/${e.id}/posts?page=${n}`); fetch(`/api/items`);
            this.http.get(`${this.hostServer}/rest/products/search?q=${q}`); h.post(this.host + "/api/login", b);
            this.http.put(`${this.host}/rest/basket/${id}/checkout`, {}); u = `${a}/${b}`; v = `${a}/${n}/0`;
            w = `${this.host}/${id}/reviews`;
            const r = [{path:"/about",component:()=>t(()=>import("./About-x1.js"),__vite__mapDeps([0,1]))}];
            const d = ["assets/About-x1.js","assets/About-x1.css","assets/vendor-y2.mjs"];
            throw Error("see index.js"); x = "https://cdn.test/lib.js"; y = `${a}${b}.js`"#;
        assert_eq!(
            urls("https://a.test/assets/index-CM.js", bundle),
            [
                "https://a.test/about",
                "https://a.test/api/items",
                "https://a.test/api/login",
                "https://a.test/api/users/1/posts?page=1",
                "https://a.test/assets/About-x1.js",
                "https://a.test/assets/About-x1.js",
                "https://a.test/assets/vendor-y2.mjs",
                "https://a.test/rest/basket/1/checkout",
                "https://a.test/rest/products/search?q=brainproxy",
            ]
        );
        // Served under a path: chunks stay under it.
        assert_eq!(
            urls("https://a.test/app/assets/index.js", r#"["assets/x.js"]; import("../lazy/y.js")"#),
            ["https://a.test/app/assets/x.js", "https://a.test/app/lazy/y.js"]
        );
        // A chunk folder that isn't the script's own: from the origin's root.
        assert_eq!(urls("https://a.test/static/main.js", r#"["js/chunk-1.js"]"#), ["https://a.test/js/chunk-1.js"]);
    }

    /// Strings in real minified bundles (an Angular app, ethers, a lezer parse table) that look
    /// like paths but aren't: character counters, derivation paths, string-replace arguments,
    /// a bare interpolation and the text between two different quote characters.
    #[test]
    fn minified_code_that_only_looks_like_paths_is_skipped() {
        let h = vec![("Content-Type".to_string(), "application/javascript".to_string())];
        let js = r#"wi$1(4),ff(``,s.value?.length||0,`/160`),wi$1(),Ri$1(n.feedbackControl);ff(``,d.value?.length||0,`/20`);
            ff(``,t.challenge().codingChallengeStatus,`/2`);an=`m/44'/60'/0'/0/0`;x=`m/44'/60'/${r}'/0/0`;
            let o=i.url.replace(/^http/i,`ws`).replace(`/v3/`,`/ws/v3/`);get(t){return this.http.get(`${this.host}/${t}`)}
            let e=`/${r}`;i=e.startsWith(`//`)?`/.${e}`:e;
            p="O'/SQ`O<<JQO'/_Q?MtO<<JQOOQO<<Hy<<HyOOQ!0LfAN?fAN?f";q="OG27WO'/pQ`OG27WO'/xQ?MtO<<JgO'0VQ?MvO1G2";
            fetch(`/api/Feedbacks`);r=this.router.navigate([`/2fa/enter`])"#;
        let found = extract(&Url::parse("http://a.test/main.js").unwrap(), &h, js.as_bytes(), false);
        let urls: Vec<&str> = found.iter().map(|f| f.url.as_str()).collect();
        assert_eq!(urls, ["http://a.test/api/Feedbacks", "http://a.test/2fa/enter"]);
    }

    /// An error page's stack trace names server files, not links (Express's 403 page).
    #[test]
    fn stack_trace_paths_are_not_links() {
        let page = Url::parse("http://a.test/ftp/coupons_2013.md.bak").unwrap();
        let headers = vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string())];
        let html = r#"<h2><em>403</em> Error: Only .md and .pdf files are allowed!</h2><ul id="stacktrace">
            <li> &nbsp; &nbsp;at verify (/juice-shop/build/routes/fileServer.js:68:18)</li>
            <li> &nbsp; &nbsp;at /juice-shop/build/routes/fileServer.js:52:13</li>
            <li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li>
            <li> &nbsp; &nbsp;at FSReqCallback.oncomplete (node:fs:199:5)</li></ul>
            <pre>File "/srv/app/views.py", line 12, in index
            #0 /var/www/html/index.php(12): run()
            Warning: x in /var/www/html/lib.php on line 7
            /app/lib/x.rb:12:in `call'</pre><p>See /help for more.</p>"#;
        let found = extract(&page, &headers, html.as_bytes(), false);
        let urls: Vec<&str> = found.iter().map(|f| f.url.as_str()).collect();
        assert_eq!(urls, ["http://a.test/help"]);
    }

    /// The method a bundle calls a path with, so a POST-only route isn't sent as GET.
    #[test]
    fn script_paths_carry_the_method_the_code_uses() {
        let h = vec![("Content-Type".to_string(), "text/javascript".to_string())];
        let js = r#"this.http.post(`${this.host}/rest/user/login`, e); this.http.get(this.host + "/api/Users");
            fetch("/api/feedback", {headers: {a: 1}, method: "PUT"}); $.ajax("/old", {type: 'patch'});
            n.delete(this.host + "/api/Cards/" + id); a.post(x); fetch("/api/after"); y = {method: "POST"};
            fetch("ünï/x".length, "/api/wide")"#;
        let found = extract(&Url::parse("https://a.test/main.js").unwrap(), &h, js.as_bytes(), false);
        let hints: Vec<(&str, Option<&str>)> = found.iter().map(|f| (f.url.as_str(), f.hint)).collect();
        assert_eq!(
            hints,
            [
                ("https://a.test/rest/user/login", Some("POST")),
                ("https://a.test/api/Users", None),
                ("https://a.test/api/feedback", Some("PUT")),
                ("https://a.test/old", Some("PATCH")),
                ("https://a.test/api/Cards/", Some("DELETE")),
                ("https://a.test/api/after", None),
                ("https://a.test/api/wide", None),
            ]
        );
        assert!(found.iter().all(|f| f.guessed && f.method == "GET"));
        // Windows cut inside a character move to its boundary.
        assert_eq!(window("aéb", 2, 3), "");
        assert_eq!(window("aéb", 0, 2), "a");
        assert_eq!(window("aéb", 5, 9), "");
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
    fn images_fonts_and_styles_are_static() {
        for p in ["/a.png", "/img/x-1x.AVIF", "/f.woff2", "/s.css"] {
            assert!(is_static(&Url::parse(&format!("https://a.test{p}")).unwrap()), "{p}");
        }
        assert!(!is_static(&Url::parse("https://a.test/main.js").unwrap()));
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
