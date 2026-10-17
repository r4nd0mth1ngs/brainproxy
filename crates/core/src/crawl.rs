//! Spider: breadth-first crawl from seed URLs. Follows links, redirects, frames,
//! scripts, meta refreshes, forms (submitted with generated values), robots.txt,
//! and sitemap.xml, staying inside a host/path scope. Every fetched exchange is
//! recorded (source "crawl") and passively scanned.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Serialize;
use tokio::sync::Semaphore;
use url::Url;

use crate::auth::AuthSession;
use crate::capture::{decode_body, Capture};
use crate::error::{Error, Result};
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use crate::jobs::JobControl;
use crate::scan::passive::util::{decode_entities, tags, Tag};
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
    /// Only crawl paths starting with this prefix.
    pub path_prefix: Option<String>,
    /// URLs matching any of these are never requested.
    pub exclude: Vec<Regex>,
    pub submit_forms: bool,
    pub robots: bool,
    pub sitemap: bool,
    /// Logged-in session applied to every request (re-login on logout).
    pub auth: Option<Arc<AuthSession>>,
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
    pub stopped: bool,
    pub limit_reached: bool,
    pub new_findings: usize,
    pub elapsed_ms: u64,
}

struct Scope {
    hosts: Vec<String>,
    subdomains: bool,
    path_prefix: Option<String>,
    exclude: Vec<Regex>,
}

impl Scope {
    fn host_allowed(&self, u: &Url) -> bool {
        let Some(host) = u.host_str().map(|h| h.to_ascii_lowercase()) else { return false };
        self.hosts.iter().any(|h| host == *h || (self.subdomains && host.ends_with(&format!(".{h}"))))
    }

    fn allows(&self, u: &Url) -> bool {
        self.host_allowed(u)
            && matches!(u.scheme(), "http" | "https")
            && self.path_prefix.as_deref().is_none_or(|p| u.path().starts_with(p))
            && !self.exclude.iter().any(|r| r.is_match(u.as_str()))
    }
}

pub async fn crawl(project: &Path, cfg: CrawlConfig, ctl: JobControl) -> Result<CrawlSummary> {
    let started = Instant::now();
    let mut seeds = Vec::new();
    for s in &cfg.seeds {
        let s = if s.contains("://") { s.clone() } else { format!("https://{s}") };
        seeds.push(Url::parse(&s).map_err(|e| Error::InvalidInput(format!("bad seed URL {s:?}: {e}")))?);
    }
    if seeds.is_empty() {
        return Err(Error::InvalidInput("give at least one seed URL".into()));
    }
    let scope = Scope {
        hosts: seeds.iter().filter_map(|u| u.host_str().map(|h| h.to_ascii_lowercase())).collect(),
        subdomains: cfg.subdomains,
        path_prefix: cfg.path_prefix.clone(),
        exclude: cfg.exclude.clone(),
    };

    let mut store = Store::open(project)?;
    let client = Arc::new(Client::new(cfg.send.clone()));
    let limiter = cfg.rate.filter(|r| *r > 0.0).map(|r| Duration::from_secs_f64(1.0 / r));
    let mut summary = CrawlSummary::default();
    let mut seen: HashSet<Req> = HashSet::new();
    let mut per_path: HashMap<(String, String), usize> = HashMap::new();
    let mut endpoints: HashSet<Endpoint> = HashSet::new();
    let mut out_of_scope: HashSet<String> = HashSet::new();

    let mut level: Vec<Req> = Vec::new();
    let push = |req: Req, level: &mut Vec<Req>, seen: &mut HashSet<Req>| {
        if seen.insert(req.clone()) {
            level.push(req);
        }
    };
    for u in &seeds {
        push(Req { method: "GET".into(), url: strip_fragment(u), body: None }, &mut level, &mut seen);
        let mut origin = u.clone();
        origin.set_query(None);
        if cfg.robots {
            origin.set_path("/robots.txt");
            push(Req { method: "GET".into(), url: origin.to_string(), body: None }, &mut level, &mut seen);
        }
        if cfg.sitemap {
            origin.set_path("/sitemap.xml");
            push(Req { method: "GET".into(), url: origin.to_string(), body: None }, &mut level, &mut seen);
        }
    }

    for depth in 0..=cfg.max_depth {
        if level.is_empty() || ctl.stopped() {
            break;
        }
        summary.depth_reached = depth;
        // Enforce the page budget and per-path cap before fetching.
        let mut batch = Vec::new();
        for req in level.drain(..) {
            if summary.requests + batch.len() >= cfg.max_pages {
                summary.limit_reached = true;
                break;
            }
            let path = Url::parse(&req.url).map(|u| u.path().to_string()).unwrap_or_default();
            let n = per_path.entry((req.method.clone(), path)).or_default();
            if *n >= cfg.max_per_path {
                continue;
            }
            *n += 1;
            batch.push(req);
        }

        let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
        let mut tasks = Vec::new();
        for (i, req) in batch.iter().cloned().enumerate() {
            let (sem, client, headers, ctl, auth) =
                (sem.clone(), client.clone(), cfg.headers.clone(), ctl.clone(), cfg.auth.clone());
            let delay = limiter.map(|d| d * (i as u32 / cfg.concurrency.max(1) as u32));
            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                if ctl.stopped() {
                    return None;
                }
                if let Some(d) = delay {
                    tokio::time::sleep(d).await;
                }
                Some(fetch(&client, auth.as_deref(), &req, &headers).await)
            }));
        }

        let mut captures = Vec::new();
        let mut next = Vec::new();
        for (req, task) in batch.iter().zip(tasks) {
            let Ok(Some(result)) = task.await else { continue };
            summary.requests += 1;
            let (target, raw_req, outcome) = result;
            match outcome {
                Err(e) => {
                    summary.errors += 1;
                    *summary.by_status.entry("error".into()).or_default() += 1;
                    captures.push(Capture::new("crawl", &target, &raw_req, None, None, Some(&e.to_string())));
                }
                Ok((response, ms)) => {
                    let page = Url::parse(&req.url).ok();
                    if let (Some(page), Ok(head)) = (page.as_ref(), parse_response_head(&response)) {
                        *summary.by_status.entry(head.status.to_string()).or_default() += 1;
                        endpoints.insert(endpoint(req, page));
                        let body = decode_body(&head.headers, split_head_body(&response).1);
                        let found = extract(page, &head.headers, &body, cfg.submit_forms);
                        for f in found {
                            let Ok(u) = Url::parse(&f.url) else { continue };
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
                            let r = Req { method: f.method, url: strip_fragment(&u), body: f.body };
                            if seen.insert(r.clone()) {
                                next.push(r);
                            }
                        }
                    }
                    captures.push(Capture::new("crawl", &target, &raw_req, Some(&response), Some(ms as i64), None));
                }
            }
        }
        store.record_batch(&captures)?;
        summary.new_findings += crate::scan::passive::scan_pending(&mut store)?.new_findings;
        ctl.set_progress(serde_json::json!({
            "depth": depth,
            "requests": summary.requests,
            "queued_next": next.len(),
            "endpoints": endpoints.len(),
        }));
        level = next;
        if summary.requests >= cfg.max_pages {
            summary.limit_reached = !level.is_empty();
            break;
        }
    }

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

async fn fetch(client: &Client, auth: Option<&AuthSession>, req: &Req, headers: &[(String, String)]) -> FetchResult {
    let mut hdrs = headers.to_vec();
    if req.body.is_some() && !hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
        hdrs.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
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
        Some(a) => a.send(&raw, &target).await,
        None => client.send(&raw, &target).await,
    };
    match sent {
        // Record the request actually sent (with the session applied).
        Ok(ex) => (target, ex.request, Ok((ex.response, ex.duration_ms))),
        Err(e) => (target, raw.into_bytes(), Err(e)),
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

fn strip_fragment(u: &Url) -> String {
    let mut u = u.clone();
    u.set_fragment(None);
    u.to_string()
}

fn is_static(u: &Url) -> bool {
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
        static PATHS: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"["'`](/[A-Za-z0-9_\-./]{1,150}(?:\?[A-Za-z0-9_\-.=&%]{0,150})?)["'`]"#).unwrap()
        });
        for c in PATHS.captures_iter(&text) {
            if !c[1].starts_with("//") {
                link(page, &c[1], &mut out);
            }
        }
        return out;
    }
    if !ct.contains("html") && !ct.is_empty() {
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
    out
}

fn refresh_url(v: &str) -> Option<String> {
    let lower = v.to_ascii_lowercase();
    let i = lower.find("url=")?;
    Some(v[i + 4..].trim().trim_matches(['\'', '"']).to_string())
}

/// One request per form, filled with existing or generated values.
fn form_requests(html: &str, all: &[Tag], base: &Url) -> Vec<Found> {
    let mut out = Vec::new();
    let forms: Vec<&Tag> = all.iter().filter(|t| t.name == "form").collect();
    for (i, form) in forms.iter().enumerate() {
        // Fields between this form's start and the next </form> (or next form).
        let end = crate::scan::passive::util::find_ci(html, "</form", form.end)
            .unwrap_or(html.len())
            .min(forms.get(i + 1).map(|f| f.start).unwrap_or(html.len()));
        let mut fields: Vec<(String, String)> = Vec::new();
        let mut radios: HashSet<String> = HashSet::new();
        for t in all.iter().filter(|t| t.start > form.start && t.start < end) {
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
                    let close = crate::scan::passive::util::find_ci(html, "</select", t.end).unwrap_or(end);
                    let first = all.iter().find(|o| o.name == "option" && o.start > t.start && o.start < close);
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
fn field_value(name: &str, ty: &str, existing: Option<&str>) -> String {
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
    fn scope_rules() {
        let scope = Scope {
            hosts: vec!["a.test".into()],
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
}
