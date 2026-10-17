//! The intercepting proxy: HTTP/1.x forward proxy with CONNECT, TLS
//! interception for in-scope hosts, match-and-replace rules, an intercept queue
//! resolved through the project database, and capture recording.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::auth::AuthSession;
use crate::capture::Capture;
use crate::error::{Error, Result};
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Target, WireReader};
use crate::proxy::ca::CertAuthority;
use crate::proxy::config::{
    apply_request_rules, apply_response_rules, compile_rules, CompiledIntercept, CompiledRule, CompiledScope,
    InterceptSettings, Rule, Scope, TimeoutAction, INTERCEPT_KEY, RULES_KEY, SCOPE_KEY,
};
use crate::store::Store;

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const SETTINGS_REFRESH: Duration = Duration::from_millis(300);

pub struct ProxyOptions {
    pub project: PathBuf,
    pub upstream: SendOptions,
    /// Logged-in session applied to in-scope requests (re-login on logout).
    pub auth: Option<Arc<AuthSession>>,
}

/// Settings in effect, reloaded whenever the project's settings version changes.
#[derive(Default)]
struct Live {
    version: i64,
    scope: CompiledScope,
    rules: Vec<CompiledRule>,
    intercept: CompiledIntercept,
}

struct Ctx {
    ca: Arc<CertAuthority>,
    auth: Option<Arc<AuthSession>>,
    guard: Option<Arc<crate::guard::Guard>>,
    client: Client,
    control: Mutex<Store>,
    live: RwLock<Arc<Live>>,
    recorder: Mutex<mpsc::Sender<Capture>>,
    stats: Stats,
}

#[derive(Default)]
pub struct Stats {
    pub connections: AtomicU64,
    pub requests: AtomicU64,
    pub errors: AtomicU64,
}

/// Runs the proxy on `listener` until `shutdown` resolves, then flushes captures.
pub async fn run(
    listener: TcpListener,
    ca: Arc<CertAuthority>,
    opts: ProxyOptions,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let control = Store::open(&opts.project)?;
    let (tx, rx) = mpsc::channel::<Capture>();
    let mut writer_store = Store::open(&opts.project)?;
    let writer = std::thread::spawn(move || {
        while let Ok(first) = rx.recv() {
            let mut batch = vec![first];
            while let Ok(c) = rx.try_recv() {
                batch.push(c);
                if batch.len() >= 256 {
                    break;
                }
            }
            if let Err(e) = writer_store.record_batch(&batch) {
                eprintln!("brainproxy: failed to record {} captures: {e}", batch.len());
            }
            if let Err(e) = crate::scan::passive::scan_pending(&mut writer_store) {
                eprintln!("brainproxy: passive scan failed: {e}");
            }
        }
    });

    let ctx = Arc::new(Ctx {
        ca,
        guard: opts.upstream.guard.clone(),
        auth: opts.auth.clone(),
        client: Client::new(opts.upstream),
        control: Mutex::new(control),
        live: RwLock::new(Arc::new(Live { version: -1, ..Default::default() })),
        recorder: Mutex::new(tx),
        stats: Stats::default(),
    });
    reload(&ctx).await;

    let refresher = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SETTINGS_REFRESH).await;
                reload(&ctx).await;
            }
        })
    };

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((tcp, peer)) = accepted else { continue };
                tcp.set_nodelay(true).ok();
                ctx.stats.connections.fetch_add(1, Ordering::Relaxed);
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(&ctx, tcp, peer).await {
                        ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
                        if !matches!(e, Error::Io(_)) {
                            eprintln!("brainproxy: {peer}: {e}");
                        }
                    }
                });
            }
        }
    }
    refresher.abort();
    // Dropping the last sender ends the writer thread once queued captures are written.
    drop(std::mem::replace(&mut *ctx.recorder.lock().unwrap(), mpsc::channel().0));
    drop(ctx);
    let _ = tokio::task::spawn_blocking(move || writer.join()).await;
    Ok(())
}

async fn reload(ctx: &Arc<Ctx>) {
    let current = ctx.live.read().unwrap().version;
    let c = ctx.clone();
    let loaded = tokio::task::spawn_blocking(move || -> Result<Option<Live>> {
        let store = c.control.lock().unwrap();
        let version = store.settings_version()?;
        if version == current {
            return Ok(None);
        }
        let scope: Scope = store.setting(SCOPE_KEY)?;
        let rules: Vec<Rule> = store.setting(RULES_KEY)?;
        let intercept: InterceptSettings = store.setting(INTERCEPT_KEY)?;
        Ok(Some(Live {
            version,
            scope: scope.compile()?,
            rules: compile_rules(&rules)?,
            intercept: intercept.compile()?,
        }))
    })
    .await;
    match loaded {
        Ok(Ok(Some(live))) => *ctx.live.write().unwrap() = Arc::new(live),
        Ok(Ok(None)) => {}
        Ok(Err(e)) => eprintln!("brainproxy: settings not reloaded: {e}"),
        Err(e) => eprintln!("brainproxy: settings reload panicked: {e}"),
    }
}

fn live(ctx: &Ctx) -> Arc<Live> {
    ctx.live.read().unwrap().clone()
}

async fn handle_connection(ctx: &Arc<Ctx>, mut tcp: TcpStream, _peer: SocketAddr) -> Result<()> {
    let mut reader = WireReader::new();
    let Some(head) = reader.peek_request_head(&mut tcp).await? else { return Ok(()) };
    let head = RawRequest::from_bytes(head).head()?;
    if !head.method.eq_ignore_ascii_case("CONNECT") {
        return serve_http(ctx, tcp, reader, None).await;
    }

    reader.read_request(&mut tcp).await?;
    let authority = head.target.clone();
    let target = Target::from_url(&format!("https://{authority}"))
        .map_err(|_| Error::Protocol(format!("bad CONNECT target {authority:?}")))?;
    // Refuse tunnels to targets that can't be in the engagement scope.
    if ctx.guard.as_ref().is_none_or(|g| !g.may_allow(&target.host, target.port)) {
        let msg = format!("{}:{} is outside the engagement scope", target.host, target.port);
        tcp.write_all(&error_response(403, "out_of_scope", &msg)).await?;
        return Ok(());
    }
    tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    let mut stream = Prefixed::new(reader.into_leftover(), tcp);

    if !live(ctx).scope.allows(&target.host) {
        return tunnel(ctx, stream, &target).await;
    }
    // TLS records start with 0x16 (handshake). Anything else is plain HTTP over the tunnel.
    let first = stream.peek_byte().await?;
    if first != Some(0x16) {
        let plain = Target { scheme: "http".into(), ..target };
        return serve_http(ctx, stream, WireReader::new(), Some(plain)).await;
    }
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let start = acceptor.await.map_err(|e| Error::Tls(format!("client hello: {e}")))?;
    let sni = start.client_hello().server_name().map(str::to_string);
    let cert_host = sni.clone().unwrap_or_else(|| target.host.clone());
    let config = ctx.ca.server_config(&cert_host)?;
    let tls = start.into_stream(config).await.map_err(|e| Error::Tls(format!("client handshake: {e}")))?;
    serve_http(ctx, tls, WireReader::new(), Some(target)).await
}

/// Relays bytes without inspecting them (out-of-scope CONNECT).
async fn tunnel<S: AsyncRead + AsyncWrite + Unpin>(ctx: &Arc<Ctx>, mut client: S, target: &Target) -> Result<()> {
    let plain = Target { scheme: "http".into(), ..target.clone() };
    let mut upstream = ctx.client.connect(&plain).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Serves HTTP/1.x requests from one client connection. With `default_target`
/// (inside a CONNECT tunnel) requests are origin-form; otherwise they must be
/// absolute-form proxy requests.
async fn serve_http<S: AsyncRead + AsyncWrite + Unpin + Send>(
    ctx: &Arc<Ctx>,
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
        ctx.stats.requests.fetch_add(1, Ordering::Relaxed);

        let (target, mut request) = match resolve_target(raw, default_target.as_ref()) {
            Ok(v) => v,
            Err(e) => {
                client.write_all(&error_response(400, "bad_request", &e.to_string())).await?;
                return Ok(());
            }
        };
        let req_head = RawRequest::from_bytes(request.clone()).head()?;
        let client_close = wants_close(&req_head.version, &req_head.headers);
        let method = req_head.method.clone();
        let url = format!("{}{}", target.origin(), req_head.target);
        let path = req_head.target.split('?').next().unwrap_or("/").to_string();

        let live = live(ctx);
        let in_scope = live.scope.allows(&target.host);
        let record = in_scope || live.scope.record_out_of_scope;

        let auth = ctx.auth.as_ref().filter(|_| in_scope);
        if in_scope {
            request = apply_request_rules(&live.rules, request);
            if let Some(a) = auth {
                request = a.apply(&request, &[]);
            }
            if live.intercept.matches(false, &method, &target.host, &path) {
                match hold(ctx, &live.intercept, "request", &method, &url, None, request.clone()).await? {
                    Some(edited) => request = edited,
                    None => {
                        client.write_all(&error_response(502, "dropped", "request dropped by brainproxy")).await?;
                        if client_close {
                            return Ok(());
                        }
                        continue;
                    }
                }
            }
        }

        let generation = auth.map(|a| a.generation()).unwrap_or(0);
        let started = Instant::now();
        let mut upstream_reader = WireReader::new();
        let mut upstream = forward(ctx, &target, &request, &method, &mut upstream_reader).await;
        if let (Some(a), Ok((_, response))) = (auth, &upstream) {
            a.observe(response);
            // Session lost: log in again and replay the request with the new session.
            if a.is_logged_out(response) && a.relogin(generation).await {
                request = a.apply(&request, &[]);
                upstream_reader = WireReader::new();
                upstream = forward(ctx, &target, &request, &method, &mut upstream_reader).await;
                if let Ok((_, response)) = &upstream {
                    a.observe(response);
                }
            }
        }
        let (mut upstream_stream, response) = match upstream {
            Ok(v) => v,
            Err(e) => {
                ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
                if record {
                    send_capture(ctx, Capture::new("proxy", &target, &request, None, None, Some(&e.to_string())));
                }
                let status = if matches!(e, Error::OutOfScope(_)) { 403 } else { 502 };
                client.write_all(&error_response(status, e.kind(), &e.to_string())).await?;
                if client_close {
                    return Ok(());
                }
                continue;
            }
        };
        let duration = started.elapsed().as_millis() as i64;
        let resp_head = parse_response_head(final_response(&response)).ok();
        let status = resp_head.as_ref().map(|h| h.status);
        if record {
            send_capture(ctx, Capture::new("proxy", &target, &request, Some(&response), Some(duration), None));
        }

        // WebSocket and other upgrades: hand the raw streams to each other.
        if status == Some(101) {
            client.write_all(&response).await?;
            let pending_to_upstream = reader.into_leftover();
            let pending_to_client = upstream_reader.into_leftover();
            upstream_stream.write_all(&pending_to_upstream).await?;
            client.write_all(&pending_to_client).await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
            return Ok(());
        }
        drop(upstream_stream);

        let mut response = if in_scope { apply_response_rules(&live.rules, response) } else { response };
        if in_scope && live.intercept.matches(true, &method, &target.host, &path) {
            match hold(ctx, &live.intercept, "response", &method, &url, status, response.clone()).await? {
                Some(edited) => response = edited,
                None => {
                    client.write_all(&error_response(502, "dropped", "response dropped by brainproxy")).await?;
                    return Ok(());
                }
            }
        }
        client.write_all(&response).await?;
        client.flush().await?;

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

/// Works out the upstream target and rewrites absolute-form requests to origin-form.
fn resolve_target(raw: Vec<u8>, default_target: Option<&Target>) -> Result<(Target, Vec<u8>)> {
    let req = RawRequest::from_bytes(raw);
    let head = req.head()?;
    if let Some(t) = default_target {
        return Ok((t.clone(), req.into_bytes()));
    }
    if !(head.target.starts_with("http://") || head.target.starts_with("https://")) {
        return Err(Error::InvalidInput(
            "brainproxy is an HTTP proxy: send absolute-form requests (e.g. curl -x) or use CONNECT".into(),
        ));
    }
    let target = Target::from_url(&head.target)?;
    let after_scheme = &head.target[head.target.find("://").unwrap() + 3..];
    let origin_form = after_scheme.find('/').map(|i| &after_scheme[i..]).unwrap_or("/").to_string();
    // Rewrite only the request line; keep every other byte as the client sent it.
    let bytes = req.into_bytes();
    let line_end = crate::http::request::find(&bytes, b"\r\n").unwrap_or(bytes.len());
    let mut out = format!("{} {} {}", head.method, origin_form, head.version).into_bytes();
    out.extend_from_slice(&bytes[line_end..]);
    let req = RawRequest::from_bytes(out).remove_header("Proxy-Connection").remove_header("Proxy-Authorization");
    Ok((target, req.into_bytes()))
}

async fn forward(
    ctx: &Arc<Ctx>,
    target: &Target,
    request: &[u8],
    method: &str,
    reader: &mut WireReader,
) -> Result<(crate::http::Stream, Vec<u8>)> {
    let mut stream = ctx.client.connect(target).await?;
    stream.write_all(request).await?;
    stream.flush().await?;
    let response = tokio::time::timeout(Duration::from_secs(120), reader.read_response(&mut stream, method))
        .await
        .map_err(|_| Error::Timeout(Duration::from_secs(120)))??;
    Ok((stream, response))
}

/// Holds a message in the intercept queue until it is forwarded (possibly
/// edited), dropped, or times out. Returns `None` when it should be dropped.
async fn hold(
    ctx: &Arc<Ctx>,
    intercept: &CompiledIntercept,
    direction: &'static str,
    method: &str,
    url: &str,
    status: Option<u16>,
    message: Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    let id = {
        let (c, method, url, msg) = (ctx.clone(), method.to_string(), url.to_string(), message.clone());
        tokio::task::spawn_blocking(move || {
            c.control.lock().unwrap().intercept_create(direction, &method, &url, status, &msg)
        })
        .await
        .map_err(|e| Error::Protocol(e.to_string()))??
    };
    let deadline = Instant::now() + Duration::from_secs(intercept.settings.timeout_secs);
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let c = ctx.clone();
        let (state, edited) = tokio::task::spawn_blocking(move || c.control.lock().unwrap().intercept_state(id))
            .await
            .map_err(|e| Error::Protocol(e.to_string()))??;
        match state.as_str() {
            "forwarded" => return Ok(Some(edited.unwrap_or(message))),
            "dropped" => return Ok(None),
            _ if Instant::now() >= deadline => {
                let c = ctx.clone();
                // The CLI may resolve it at the same moment; whoever wins decides.
                let expired = tokio::task::spawn_blocking(move || {
                    c.control.lock().unwrap().intercept_resolve(id, "expired", None)
                })
                .await
                .map_err(|e| Error::Protocol(e.to_string()))?;
                if expired.is_err() {
                    continue;
                }
                return Ok(match intercept.settings.timeout_action {
                    TimeoutAction::Forward => Some(message),
                    TimeoutAction::Drop => None,
                });
            }
            _ => {}
        }
    }
}

fn send_capture(ctx: &Ctx, capture: Capture) {
    let _ = ctx.recorder.lock().unwrap().send(capture);
}

fn final_response(resp: &[u8]) -> &[u8] {
    let mut start = 0;
    while let Ok(h) = parse_response_head(&resp[start..]) {
        if (100..200).contains(&h.status) && h.status != 101 {
            start += crate::http::request::split_head_body(&resp[start..]).0.len();
        } else {
            break;
        }
    }
    &resp[start..]
}

fn wants_close(version: &str, headers: &[(String, String)]) -> bool {
    let conn = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("connection")).map(|(_, v)| v.to_ascii_lowercase());
    match conn {
        Some(v) if v.contains("close") => true,
        Some(v) if v.contains("keep-alive") => false,
        _ => version.eq_ignore_ascii_case("HTTP/1.0"),
    }
}

fn error_response(status: u16, kind: &str, message: &str) -> Vec<u8> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Bad Gateway",
    };
    let body = format!("brainproxy: {message}\n");
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nX-Brainproxy-Error: {kind}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A stream with some already-read bytes put back in front.
struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> Prefixed<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, pos: 0, inner }
    }

    async fn peek_byte(&mut self) -> Result<Option<u8>> {
        if self.pos < self.prefix.len() {
            return Ok(Some(self.prefix[self.pos]));
        }
        let mut b = [0u8; 1];
        let n = self.inner.read(&mut b).await?;
        if n == 0 {
            return Ok(None);
        }
        self.prefix = vec![b[0]];
        self.pos = 0;
        Ok(Some(b[0]))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_absolute_form() {
        let (t, out) = resolve_target(
            b"GET http://a.test:8080/x?y=1 HTTP/1.1\r\nHost: a.test:8080\r\nProxy-Connection: keep-alive\r\n\r\n"
                .to_vec(),
            None,
        )
        .unwrap();
        assert_eq!(t.origin(), "http://a.test:8080");
        assert_eq!(out, b"GET /x?y=1 HTTP/1.1\r\nHost: a.test:8080\r\n\r\n");
        assert!(resolve_target(b"GET /x HTTP/1.1\r\n\r\n".to_vec(), None).is_err());
    }
}
