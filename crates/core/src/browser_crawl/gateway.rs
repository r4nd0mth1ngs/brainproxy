//! The browser crawl's own proxy, on a loopback port for the crawl's lifetime. It is the
//! browser's only way out: it opens TLS with the project CA, sends each request with the
//! engagement-guarded client (scope checked after DNS, as everywhere), adds `-H` headers
//! and the `--auth` session to requests for the crawl's hosts, holds to `--rate`, refuses
//! excluded URLs (logout) and, unless destructive actions are allowed, DELETE requests,
//! and records every exchange (source `crawl-browser`). It also counts requests in
//! flight, which tells the crawler when the page has gone quiet.
//!
//! A separate proxy from `proxy run` on purpose: it needs no running proxy, never holds a
//! request in the intercept queue, and its limits apply only to the crawl.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::auth::AuthSession;
use crate::capture::{decode_body, Capture};
use crate::crawl::{is_static, Endpoint, Scope};
use crate::error::{Error, Result};
use crate::http::client::{close_after, final_response};
use crate::http::{parse_response_head, Client, RawRequest, Target, WireReader};
use crate::proxy::ca::CertAuthority;
use crate::proxy::server::{error_response, resolve_target, wants_close, Prefixed};
use crate::scan::active::Limiter;

/// Requests blocked or refused that are listed in the summary.
const MAX_LISTED: usize = 50;

pub(crate) struct Options {
    pub ca: Arc<CertAuthority>,
    pub client: Client,
    pub auth: Option<Arc<AuthSession>>,
    pub headers: Vec<(String, String)>,
    pub scope: Arc<Scope>,
    pub exclude: Vec<Regex>,
    pub block_delete: bool,
    pub rate: Option<f64>,
}

#[derive(Default)]
pub(crate) struct Stats {
    pub requests: usize,
    pub by_status: BTreeMap<String, usize>,
    pub errors: usize,
    pub endpoints: HashSet<Endpoint>,
    /// XHR and fetch() calls (Sec-Fetch-Dest: empty, or X-Requested-With).
    pub api_calls: HashSet<Endpoint>,
    pub blocked: Vec<String>,
    pub blocked_count: usize,
    /// Hosts the engagement scope refused.
    pub refused_hosts: BTreeSet<String>,
}

struct Shared {
    opts: Options,
    limiter: Option<Limiter>,
    save: Mutex<mpsc::Sender<Capture>>,
    in_flight: AtomicUsize,
    last_done: Mutex<Instant>,
    stats: Mutex<Stats>,
}

pub(crate) struct Gateway {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Gateway {
    pub async fn start(opts: Options, save: mpsc::Sender<Capture>) -> Result<Gateway> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared {
            limiter: Limiter::new(opts.rate),
            opts,
            save: Mutex::new(save),
            in_flight: AtomicUsize::new(0),
            last_done: Mutex::new(Instant::now()),
            stats: Mutex::default(),
        });
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let s = shared.clone();
        let task = tokio::spawn(async move {
            let mut conns = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let Ok((tcp, peer)) = accepted else { continue };
                        // Only the browser on this machine.
                        if !peer.ip().is_loopback() {
                            continue;
                        }
                        tcp.set_nodelay(true).ok();
                        let s = s.clone();
                        conns.spawn(async move {
                            let _ = handle_connection(&s, tcp).await;
                        });
                    }
                    Some(_) = conns.join_next(), if !conns.is_empty() => {}
                }
            }
            conns.abort_all();
        });
        Ok(Gateway { addr, shared, stop: Some(stop), task })
    }

    /// How long no request has been in flight (zero while one is).
    pub fn idle_for(&self) -> Duration {
        if self.shared.in_flight.load(Ordering::SeqCst) > 0 {
            return Duration::ZERO;
        }
        self.shared.last_done.lock().unwrap().elapsed()
    }

    pub fn with_stats<T>(&self, f: impl FnOnce(&Stats) -> T) -> T {
        f(&self.shared.stats.lock().unwrap())
    }

    /// Stops serving and lets go of the capture channel; returns the statistics.
    pub async fn stop(mut self) -> Stats {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        let _ = (&mut self.task).await;
        // Connection tasks that are still being torn down must not keep the writer alive.
        drop(std::mem::replace(&mut *self.shared.save.lock().unwrap(), mpsc::channel().0));
        std::mem::take(&mut *self.shared.stats.lock().unwrap())
    }
}

/// Counts a request in flight until dropped.
struct InFlight<'a>(&'a Shared);

impl<'a> InFlight<'a> {
    fn new(s: &'a Shared) -> Self {
        s.in_flight.fetch_add(1, Ordering::SeqCst);
        InFlight(s)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        *self.0.last_done.lock().unwrap() = Instant::now();
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn handle_connection(s: &Arc<Shared>, mut tcp: TcpStream) -> Result<()> {
    let mut reader = WireReader::new();
    let Some(head) = reader.peek_request_head(&mut tcp).await? else { return Ok(()) };
    let head = RawRequest::from_bytes(head).head()?;
    if !head.method.eq_ignore_ascii_case("CONNECT") {
        return serve(s, tcp, reader, None).await;
    }
    reader.read_request(&mut tcp).await?;
    let target = Target::from_url(&format!("https://{}", head.target))
        .map_err(|_| Error::Protocol(format!("bad CONNECT target {:?}", head.target)))?;
    if s.opts.client.options().guard.as_ref().is_none_or(|g| !g.may_allow(&target.host, target.port)) {
        refused(s, &target.host);
        let msg = format!("{}:{} is outside the engagement scope", target.host, target.port);
        tcp.write_all(&error_response(403, "out_of_scope", &msg)).await?;
        return Ok(());
    }
    tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    let mut stream = Prefixed::new(reader.into_leftover(), tcp);
    // TLS records start with 0x16 (handshake). Anything else is plain HTTP over the tunnel.
    if stream.peek_byte().await? != Some(0x16) {
        let plain = Target { scheme: "http".into(), ..target };
        return serve(s, stream, WireReader::new(), Some(plain)).await;
    }
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let start = acceptor.await.map_err(|e| Error::Tls(format!("client hello: {e}")))?;
    let host = start.client_hello().server_name().map(str::to_string).unwrap_or_else(|| target.host.clone());
    let config = s.opts.ca.server_config(&host)?;
    let tls = start.into_stream(config).await.map_err(|e| Error::Tls(format!("client handshake: {e}")))?;
    serve(s, tls, WireReader::new(), Some(target)).await
}

fn refused(s: &Shared, host: &str) {
    let mut st = s.stats.lock().unwrap();
    if st.refused_hosts.len() < MAX_LISTED {
        st.refused_hosts.insert(host.to_ascii_lowercase());
    }
}

/// HTTP/1.x requests from one browser connection.
async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send>(
    s: &Arc<Shared>,
    mut client: S,
    mut reader: WireReader,
    default_target: Option<Target>,
) -> Result<()> {
    loop {
        let Some(head_bytes) = reader.peek_request_head(&mut client).await? else { return Ok(()) };
        let head = RawRequest::from_bytes(head_bytes).head()?;
        if head.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("expect") && v.eq_ignore_ascii_case("100-continue"))
        {
            client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        }
        let Some(raw) = reader.read_request(&mut client).await? else { return Ok(()) };
        let (target, request) = match resolve_target(raw, default_target.as_ref(), false) {
            Ok(v) => v,
            Err(e) => {
                client.write_all(&error_response(400, "bad_request", &e.to_string())).await?;
                return Ok(());
            }
        };
        let req_head = RawRequest::from_bytes(request.clone()).head()?;
        let client_close = wants_close(&req_head.version, &req_head.headers);
        let method = req_head.method.clone();
        let (response, upgraded) = handle(s, &target, request).await;
        client.write_all(&response).await?;
        client.flush().await?;
        if let Some(mut up) = upgraded {
            // A WebSocket: the two sides talk directly from here on.
            let to_upstream = reader.into_leftover();
            let to_client = up.reader.into_leftover();
            up.stream.write_all(&to_upstream).await?;
            client.write_all(&to_client).await?;
            tokio::io::copy_bidirectional(&mut client, &mut up.stream).await?;
            return Ok(());
        }
        let resp_head = parse_response_head(final_response(&response)).ok();
        let server_close = resp_head.as_ref().is_none_or(|h| {
            wants_close(&h.version, &h.headers)
                || (h.header("content-length").is_none()
                    && !h.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
                    && !method.eq_ignore_ascii_case("HEAD")
                    && !matches!(h.status, 100..=199 | 204 | 304))
        });
        if client_close || server_close {
            let _ = client.shutdown().await;
            return Ok(());
        }
    }
}

/// Why a request isn't sent, if it isn't.
fn blocked_reason(url: &str, method: &str, exclude: &[Regex], block_delete: bool) -> Option<&'static str> {
    if exclude.iter().any(|r| r.is_match(url)) {
        Some("the URL matches a crawl exclusion (logout-like URLs by default)")
    } else if block_delete && method.eq_ignore_ascii_case("DELETE") {
        Some("DELETE requests are not sent unless destructive actions are allowed")
    } else {
        None
    }
}

/// One request: blocked, or sent and recorded. Returns the response for the browser and,
/// for a 101 upgrade, the upstream connection.
async fn handle(s: &Shared, target: &Target, mut request: Vec<u8>) -> (Vec<u8>, Option<crate::http::client::Conn>) {
    let Ok(head) = RawRequest::from_bytes(request.clone()).head() else {
        return (error_response(400, "bad_request", "unreadable request"), None);
    };
    let method = head.method.clone();
    let url = format!("{}{}", target.origin(), head.target);
    let parsed = Url::parse(&url).ok();
    // The crawl's own sites (seed origins): only they get its headers and session.
    let ours = parsed.as_ref().is_some_and(|u| s.opts.scope.on_site(u));
    // A page load (a link, form, redirect or script navigating the tab or a frame) must stay
    // inside the crawl scope; the page's own API and asset requests may go elsewhere in the engagement.
    let leaves_scope = is_navigation(&head.headers) && !parsed.as_ref().is_some_and(|u| s.opts.scope.allows(u));

    if let Some(reason) = blocked_reason(&url, &method, &s.opts.exclude, s.opts.block_delete)
        .or(leaves_scope.then_some("the page would leave the crawl's sites or path prefix"))
    {
        let msg = format!("not sent by the browser crawl: {reason}");
        send_capture(s, Capture::new("crawl-browser", target, &request, None, None, Some(&msg)));
        let mut st = s.stats.lock().unwrap();
        st.blocked_count += 1;
        if st.blocked.len() < MAX_LISTED {
            st.blocked.push(format!("{method} {url}"));
        }
        return (error_response(403, "blocked", &msg), None);
    }

    let auth = s.opts.auth.as_deref().filter(|_| ours);
    if ours {
        let mut req = RawRequest::from_bytes(request);
        for (k, v) in &s.opts.headers {
            req = add_header(req, k, v);
        }
        request = req.into_bytes();
        if let Some(a) = auth {
            request = a.apply_to(&request, &[], target);
        }
    }
    // In flight while it waits for its turn too, so the page isn't taken as settled.
    let _busy = InFlight::new(s);
    if let Some(l) = &s.limiter {
        l.wait().await;
    }
    let generation = auth.map(|a| a.generation()).unwrap_or(0);
    let started = Instant::now();
    let mut sent = forward(s, target, &request, &method).await;
    if let (Some(a), Ok((_, response))) = (auth, &sent) {
        a.observe(response);
        // Session lost: log in again and replay with the new session.
        if a.is_logged_out(response) && a.relogin(generation).await {
            request = a.apply_to(&request, &[], target);
            sent = forward(s, target, &request, &method).await;
            if let Ok((_, response)) = &sent {
                a.observe(response);
            }
        }
    }
    let duration = started.elapsed().as_millis() as i64;
    let (conn, response) = match sent {
        Ok(v) => v,
        Err(e) => {
            if matches!(e, Error::OutOfScope(_)) {
                refused(s, &target.host);
                return (error_response(403, e.kind(), &e.to_string()), None);
            }
            send_capture(s, Capture::new("crawl-browser", target, &request, None, None, Some(&e.to_string())));
            let mut st = s.stats.lock().unwrap();
            st.requests += 1;
            st.errors += 1;
            *st.by_status.entry("error".into()).or_default() += 1;
            return (error_response(502, e.kind(), &e.to_string()), None);
        }
    };
    let status = parse_response_head(final_response(&response)).ok().map(|h| h.status);
    send_capture(s, Capture::new("crawl-browser", target, &request, Some(&response), Some(duration), None));
    {
        let mut st = s.stats.lock().unwrap();
        st.requests += 1;
        *st.by_status.entry(status.map(|c| c.to_string()).unwrap_or_else(|| "error".into())).or_default() += 1;
        if let Some(u) = parsed.as_ref().filter(|u| ours && !is_static(u)) {
            let ep = endpoint(&method, u, &head.headers, RawRequest::from_bytes(request.clone()).body());
            if is_api_call(&head.headers) {
                st.api_calls.insert(ep.clone());
            }
            st.endpoints.insert(ep);
        }
    }
    if status == Some(101) {
        return (response, Some(conn));
    }
    if !close_after(&request, &response, &method) {
        s.opts.client.checkin(target, conn);
    }
    (response, None)
}

async fn forward(
    s: &Shared,
    target: &Target,
    request: &[u8],
    method: &str,
) -> Result<(crate::http::client::Conn, Vec<u8>)> {
    let timeout = s.opts.client.options().timeout;
    tokio::time::timeout(timeout, s.opts.client.exchange(request, target, method))
        .await
        .map_err(|_| Error::Timeout(timeout))?
}

/// Sets a header; a Cookie header is merged with the browser's cookies (given ones win).
fn add_header(req: RawRequest, name: &str, value: &str) -> RawRequest {
    let existing = req.head().ok().and_then(|h| header(&h.headers, "cookie").map(str::to_string));
    let Some(existing) = existing.filter(|_| name.eq_ignore_ascii_case("cookie")) else {
        return req.set_header(name, value);
    };
    let cookie_name = |p: &str| p.split('=').next().unwrap_or("").trim().to_string();
    let given: Vec<String> = value.split(';').map(cookie_name).collect();
    let mut merged = value.trim().to_string();
    for part in existing.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        if !given.contains(&cookie_name(part)) {
            merged.push_str("; ");
            merged.push_str(part);
        }
    }
    req.set_header("Cookie", &merged)
}

/// A page load of the tab or a frame. Chromium sends `Sec-Fetch-*` only to https and loopback;
/// on plain http a navigation is the request that asks for HTML first. A script can ask the
/// same in fetch(), which is then held to the crawl's sites too; it can't do the reverse.
fn is_navigation(headers: &[(String, String)]) -> bool {
    match header(headers, "sec-fetch-mode") {
        Some(mode) => mode == "navigate",
        None => accept_starts_with(headers, &["text/html"]),
    }
}

/// An XHR or fetch() call. Without `Sec-Fetch-Dest` (plain http), anything that isn't a
/// navigation and doesn't ask for an asset type; the caller has already left out static paths.
fn is_api_call(headers: &[(String, String)]) -> bool {
    if header(headers, "x-requested-with").is_some() {
        return true;
    }
    match header(headers, "sec-fetch-dest") {
        Some(dest) => dest == "empty",
        None => !is_navigation(headers) && !accept_starts_with(headers, &["image/", "text/css", "video/", "audio/"]),
    }
}

fn accept_starts_with(headers: &[(String, String)], types: &[&str]) -> bool {
    let accept = header(headers, "accept").unwrap_or("").to_ascii_lowercase();
    types.iter().any(|t| accept.starts_with(t))
}

fn send_capture(s: &Shared, c: Capture) {
    let _ = s.save.lock().unwrap().send(c);
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim())
}

/// Method, path and parameter names: query, form fields, and top-level JSON keys.
fn endpoint(method: &str, u: &Url, headers: &[(String, String)], body: &[u8]) -> Endpoint {
    let mut params: Vec<String> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
    let ct = header(headers, "content-type").unwrap_or("").to_ascii_lowercase();
    let body = decode_body(headers, body);
    if ct.contains("x-www-form-urlencoded") {
        params.extend(url::form_urlencoded::parse(&body).map(|(k, _)| k.into_owned()));
    } else if ct.contains("json") {
        if let Ok(serde_json::Value::Object(m)) = serde_json::from_slice(&body) {
            params.extend(m.keys().cloned());
        }
    }
    params.sort();
    params.dedup();
    Endpoint { method: method.to_ascii_uppercase(), path: u.path().to_string(), params }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn navigations_and_api_calls_are_told_apart_with_and_without_sec_fetch() {
        const PAGE: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8";
        // https and loopback.
        let nav = headers(&[("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Dest", "document"), ("Accept", PAGE)]);
        assert!(is_navigation(&nav) && !is_api_call(&nav));
        let fetch = headers(&[("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Dest", "empty"), ("Accept", "*/*")]);
        assert!(!is_navigation(&fetch) && is_api_call(&fetch));
        let script = headers(&[("Sec-Fetch-Mode", "no-cors"), ("Sec-Fetch-Dest", "script"), ("Accept", "*/*")]);
        assert!(!is_navigation(&script) && !is_api_call(&script));
        // Plain http: Chromium sends no Sec-Fetch headers.
        let nav = headers(&[("Accept", PAGE), ("Upgrade-Insecure-Requests", "1")]);
        assert!(is_navigation(&nav) && !is_api_call(&nav));
        let fetch = headers(&[("Accept", "*/*")]);
        assert!(!is_navigation(&fetch) && is_api_call(&fetch));
        let json = headers(&[("Accept", "application/json")]);
        assert!(!is_navigation(&json) && is_api_call(&json));
        let image = headers(&[("Accept", "image/avif,image/webp,*/*;q=0.8")]);
        assert!(!is_navigation(&image) && !is_api_call(&image));
        let css = headers(&[("Accept", "text/css,*/*;q=0.1")]);
        assert!(!is_navigation(&css) && !is_api_call(&css));
        let xhr = headers(&[("Accept", "text/html"), ("X-Requested-With", "XMLHttpRequest")]);
        assert!(is_api_call(&xhr));
    }

    #[test]
    fn logout_urls_and_deletes_are_not_sent() {
        let exclude = vec![Regex::new(crate::crawl::DEFAULT_EXCLUDE).unwrap()];
        assert!(blocked_reason("https://a.test/account/logout", "GET", &exclude, true).is_some());
        assert!(blocked_reason("https://a.test/api/items/3", "DELETE", &exclude, true).is_some());
        assert!(blocked_reason("https://a.test/api/items/3", "delete", &exclude, true).is_some());
        assert!(blocked_reason("https://a.test/api/items/3", "DELETE", &exclude, false).is_none());
        assert!(blocked_reason("https://a.test/api/items", "POST", &exclude, true).is_none());
    }

    #[test]
    fn header_cookies_merge_with_the_browsers() {
        let req =
            RawRequest::from_bytes(b"GET / HTTP/1.1\r\nHost: a.test\r\nCookie: sid=old; theme=dark\r\n\r\n".to_vec());
        let out = add_header(req, "Cookie", "sid=given");
        let head = out.head().unwrap();
        assert_eq!(header(&head.headers, "cookie"), Some("sid=given; theme=dark"));
        let req = RawRequest::from_bytes(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec());
        let head = add_header(req, "X-Test", "1").head().unwrap();
        assert_eq!(header(&head.headers, "x-test"), Some("1"));
    }

    #[test]
    fn endpoints_name_query_form_and_json_params() {
        let u = Url::parse("https://a.test/api/items?page=2&q=x").unwrap();
        let json = vec![("Content-Type".to_string(), "application/json".to_string())];
        let ep = endpoint("post", &u, &json, br#"{"name":"a","tags":[1]}"#);
        assert_eq!(ep.method, "POST");
        assert_eq!(ep.path, "/api/items");
        assert_eq!(ep.params, ["name", "page", "q", "tags"]);
        let form = vec![("content-type".to_string(), "application/x-www-form-urlencoded".to_string())];
        assert_eq!(endpoint("POST", &u, &form, b"user=a&pw=b").params, ["page", "pw", "q", "user"]);
    }
}
