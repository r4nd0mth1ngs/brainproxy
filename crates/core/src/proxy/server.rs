//! The intercepting proxy: HTTP/1.x forward proxy with CONNECT, TLS
//! interception for in-scope hosts (HTTP/2 to clients that offer it), match-and-replace rules, an intercept queue
//! resolved through the project database, capture recording, and live access-control
//! testing of recorded requests.
//!
//! Connection options: TLS pass-through hosts are tunnelled without being
//! decrypted (still scope-checked, and recorded as a connection), and with
//! `invisible` the listener also serves clients that don't know they're proxied:
//! origin-form requests are routed by their Host header and TLS by its SNI. A
//! `redirect` target sends everything from the listener to one origin.

use std::collections::HashMap;
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
use tokio::sync::Semaphore;

use crate::auth::AuthSession;
use crate::authz::live::Live as LiveAuthz;
use crate::capture::Capture;
use crate::error::{Error, Result};
use crate::http::client::{close_after, cut_short, final_response, Conn};
use crate::http::h2::h2_error;
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Target, WireReader};
use crate::proxy::ca::CertAuthority;
use crate::proxy::config::{
    apply_request_rules, apply_response_rules, compile_rules, CompiledIntercept, CompiledRule, CompiledScope,
    InterceptSettings, Rule, Scope, TimeoutAction, INTERCEPT_KEY, RULES_KEY, SCOPE_KEY,
};
use crate::proxy::h2 as h2p;
use crate::session::Tool;
use crate::store::Store;
use crate::ws::db::WsEvent;
use crate::ws::relay::{Hold, Hooks};
use crate::ws::{Deflate, Direction, Message};

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const SETTINGS_REFRESH: Duration = Duration::from_millis(300);
/// Bytes of captures and WebSocket messages that may wait for the recorder thread.
const RECORD_BUDGET: usize = 64 * 1024 * 1024;
/// What a queued record counts for besides its bodies, so small ones are bounded too.
const RECORD_OVERHEAD: usize = 1024;

pub struct ProxyOptions {
    pub project: PathBuf,
    pub upstream: SendOptions,
    /// Logged-in session applied to in-scope requests (re-login on logout).
    pub auth: Option<Arc<AuthSession>>,
    /// Offer HTTP/2 (ALPN `h2`) to clients on intercepted TLS connections.
    pub http2: bool,
    /// Also accept clients that don't know they're proxied (route by Host / SNI).
    pub invisible: bool,
    /// Send every request from this listener to this origin (implies `invisible`).
    pub redirect: Option<Target>,
    /// Live access-control testing: in-scope requests are offered to it once recorded.
    pub authz: Option<Arc<LiveAuthz>>,
}

/// A capture for the writer, with the request to offer for live access-control testing.
struct Recorded {
    capture: Capture,
    authz: Option<(Target, Vec<u8>)>,
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
    recorder: Recorder,
    authz: Option<Arc<LiveAuthz>>,
    /// Names WebSocket connections for the recorder.
    ws_keys: AtomicU64,
    stats: Stats,
    http2: bool,
    /// Whether each https origin negotiated HTTP/2 (tried for HTTP/2 clients).
    h2_origins: Mutex<HashMap<String, bool>>,
    invisible: bool,
    redirect: Option<Target>,
}

/// What the recorder thread writes, in order.
enum Record {
    Capture(Box<Recorded>),
    Ws(WsEvent),
}

/// The queue to the recorder thread, bounded by bytes (each record holds its permits until it
/// is written). HTTP captures and connection open/close wait for room, so none is lost: the
/// request that made one is delayed instead. WebSocket messages never wait, so a slow disk
/// can't stall the relay: one that doesn't fit is left out and the connection says so.
struct Recorder {
    tx: Mutex<mpsc::Sender<(Record, u32)>>,
    budget: Arc<Semaphore>,
}

impl Recorder {
    fn new() -> (Self, mpsc::Receiver<(Record, u32)>) {
        let (tx, rx) = mpsc::channel();
        (Self { tx: Mutex::new(tx), budget: Arc::new(Semaphore::new(RECORD_BUDGET)) }, rx)
    }

    fn cost(bytes: usize) -> u32 {
        bytes.saturating_add(RECORD_OVERHEAD).min(RECORD_BUDGET) as u32
    }

    /// Queues a record, waiting for room.
    async fn send(&self, record: Record, bytes: usize) {
        let cost = Self::cost(bytes);
        if let Ok(permits) = self.budget.acquire_many(cost).await {
            permits.forget();
        }
        self.push(record, cost);
    }

    /// Queues a record if there is room now; `make` runs only then. Returns whether it did.
    fn try_send(&self, bytes: usize, make: impl FnOnce() -> Record) -> bool {
        let cost = Self::cost(bytes);
        let Ok(permits) = self.budget.try_acquire_many(cost) else { return false };
        permits.forget();
        self.push(make(), cost);
        true
    }

    fn push(&self, record: Record, cost: u32) {
        if self.tx.lock().unwrap().send((record, cost)).is_err() {
            self.budget.add_permits(cost as usize);
        }
    }
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
    const STALE_WS: &str = "the proxy stopped before the connection closed";
    let control = Store::open(&opts.project)?;
    control.ws_close_stale("proxy", STALE_WS)?;
    let (recorder, rx) = Recorder::new();
    let budget = recorder.budget.clone();
    let mut writer_store = Store::open(&opts.project)?;
    let authz = opts.authz.clone();
    let writer = std::thread::spawn(move || {
        let mut ws_ids = HashMap::new();
        while let Ok(first) = rx.recv() {
            let (mut batch, mut ws, mut cost) = (Vec::new(), Vec::new(), 0);
            for (r, c) in std::iter::once(first).chain(std::iter::from_fn(|| rx.try_recv().ok()).take(255)) {
                cost += c as usize;
                match r {
                    Record::Capture(c) => batch.push(*c),
                    Record::Ws(e) => ws.push(e),
                }
            }
            let (captures, offers): (Vec<Capture>, Vec<_>) = batch.into_iter().map(|r| (r.capture, r.authz)).unzip();
            match writer_store.record_batch(&captures) {
                Ok(ids) => {
                    // Offered once recorded, so results point at the history entry.
                    if let Some(live) = &authz {
                        for ((id, offer), c) in ids.into_iter().zip(offers).zip(&captures) {
                            if let Some((target, request)) = offer {
                                live.offer(id, &target, &request, c.status, c.resp_content_type.as_deref());
                            }
                        }
                    }
                }
                Err(e) => eprintln!("brainproxy: failed to record {} captures: {e}", captures.len()),
            }
            if let Err(e) = writer_store.ws_record(&ws, &mut ws_ids) {
                eprintln!("brainproxy: failed to record {} WebSocket events: {e}", ws.len());
            }
            // Written (or given up on): their room is free again.
            drop((captures, ws));
            budget.add_permits(cost);
            if let Err(e) = crate::scan::passive::scan_pending(&mut writer_store) {
                eprintln!("brainproxy: passive scan failed: {e}");
            }
        }
        if let Err(e) = writer_store.ws_close_stale("proxy", STALE_WS) {
            eprintln!("brainproxy: WebSocket connections left open: {e}");
        }
    });

    let ctx = Arc::new(Ctx {
        ca,
        guard: opts.upstream.guard.clone(),
        auth: opts.auth.clone(),
        client: Client::new(opts.upstream),
        control: Mutex::new(control),
        live: RwLock::new(Arc::new(Live { version: -1, ..Default::default() })),
        recorder,
        authz: opts.authz,
        ws_keys: AtomicU64::new(0),
        stats: Stats::default(),
        http2: opts.http2,
        h2_origins: Mutex::default(),
        invisible: opts.invisible || opts.redirect.is_some(),
        redirect: opts.redirect,
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
    drop(std::mem::replace(&mut *ctx.recorder.tx.lock().unwrap(), mpsc::channel().0));
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
        // Connection options and platform credentials go to the guard every client shares.
        if let Some(g) = &c.guard {
            g.net.set(store.connection_compiled()?);
        }
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
    if ctx.invisible {
        let mut first = [0u8; 1];
        if tcp.peek(&mut first).await? == 1 && first[0] == 0x16 {
            return serve_invisible_tls(ctx, tcp).await;
        }
    }
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

    if passthrough(ctx, &target) {
        return pass_through(ctx, stream, &target).await;
    }
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
    let mut config = ctx.ca.server_config(&cert_host)?;
    let offers_h2 = start.client_hello().alpn().is_some_and(|mut p| p.any(|p| p == b"h2"));
    if ctx.http2 && offers_h2 {
        let mut h2_config = (*config).clone();
        h2_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config = Arc::new(h2_config);
    }
    let tls = start.into_stream(config).await.map_err(|e| Error::Tls(format!("client handshake: {e}")))?;
    if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
        return serve_h2(ctx, tls, target).await;
    }
    serve_http(ctx, tls, WireReader::new(), Some(target)).await
}

/// Relays bytes without inspecting them (out-of-scope CONNECT). The upstream
/// connection goes through the guard (and the connection options) like any other.
async fn tunnel<S: AsyncRead + AsyncWrite + Unpin>(ctx: &Arc<Ctx>, mut client: S, target: &Target) -> Result<()> {
    let target = ctx.redirect.as_ref().unwrap_or(target);
    let plain = Target { scheme: "http".into(), ..target.clone() };
    let mut upstream = ctx.client.connect(&plain).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Whether the connection options say to tunnel this host's TLS undecrypted.
fn passthrough(ctx: &Ctx, target: &Target) -> bool {
    ctx.guard.as_ref().is_some_and(|g| g.net.get().passthrough(&target.host, target.port))
}

/// A TLS pass-through connection: tunnelled like [`tunnel`] and recorded as a
/// `CONNECT` entry (no response: nothing was decrypted) with the byte counts.
async fn pass_through<S: AsyncRead + AsyncWrite + Unpin>(ctx: &Arc<Ctx>, mut client: S, target: &Target) -> Result<()> {
    let upstream_target = ctx.redirect.as_ref().unwrap_or(target);
    let authority = target.host_header();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    let started = Instant::now();
    let plain = Target { scheme: "http".into(), ..upstream_target.clone() };
    let result = async {
        let mut upstream = ctx.client.connect(&plain).await?;
        Ok::<_, Error>(tokio::io::copy_bidirectional(&mut client, &mut upstream).await?)
    }
    .await;
    let note = match &result {
        Ok((up, down)) => format!("TLS pass-through, not decrypted: {up} bytes sent, {down} received"),
        Err(e) => format!("TLS pass-through: {e}"),
    };
    let https = Target { scheme: "https".into(), ..target.clone() };
    let duration = Some(started.elapsed().as_millis() as i64);
    send_capture(ctx, Capture::new("proxy", &https, request.as_bytes(), None, duration, Some(&note)), None).await;
    result.map(|_| ())
}

/// A client that sent TLS straight to the listener (invisible proxying): the host
/// comes from the ClientHello's SNI (or the redirect target), port 443.
async fn serve_invisible_tls(ctx: &Arc<Ctx>, mut tcp: TcpStream) -> Result<()> {
    let (hello, handshake) = read_client_hello(&mut tcp).await?;
    // From the client, so checked before it is used for routing or a certificate.
    let sni = sni_from_client_hello(&handshake);
    if let Some(name) = sni.as_deref().filter(|n| !valid_client_host(n) || n.parse::<std::net::IpAddr>().is_ok()) {
        return Err(Error::Protocol(format!("invisible proxy: bad TLS server name {name:?}")));
    }
    let target = match (&ctx.redirect, &sni) {
        (Some(r), _) => r.clone(),
        (None, Some(name)) => Target::from_url(&format!("https://{name}:443"))
            .map_err(|_| Error::Protocol(format!("bad TLS server name {name:?}")))?,
        (None, None) => return Err(Error::Protocol("invisible proxy: TLS client sent no server name (SNI)".into())),
    };
    let name = sni.unwrap_or_else(|| target.host.clone());
    let named = Target { host: name.clone(), port: 443, scheme: "https".into() };
    let stream = Prefixed::new(hello, tcp);
    if passthrough(ctx, &named) {
        return pass_through(ctx, stream, &named).await;
    }
    if !live(ctx).scope.allows(&name) {
        return tunnel(ctx, stream, &named).await;
    }
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let start = acceptor.await.map_err(|e| Error::Tls(format!("client hello: {e}")))?;
    let mut config = ctx.ca.server_config(&name)?;
    let offers_h2 = start.client_hello().alpn().is_some_and(|mut p| p.any(|p| p == b"h2"));
    if ctx.http2 && offers_h2 {
        let mut h2_config = (*config).clone();
        h2_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config = Arc::new(h2_config);
    }
    let tls = start.into_stream(config).await.map_err(|e| Error::Tls(format!("client handshake: {e}")))?;
    if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
        return serve_h2(ctx, tls, named).await;
    }
    serve_http(ctx, tls, WireReader::new(), Some(named)).await
}

/// Longest ClientHello read to find the SNI.
const MAX_CLIENT_HELLO: usize = 64 * 1024;

/// The ClientHello: the raw records (replayed to the acceptor or the pass-through
/// tunnel) and the handshake message they carry, which may span several records.
async fn read_client_hello(tcp: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let (mut raw, mut handshake) = (Vec::new(), Vec::new());
    loop {
        let mut head = [0u8; 5];
        tcp.read_exact(&mut head).await?;
        if head[0] != 0x16 {
            return Err(Error::Protocol("invisible proxy: expected a TLS handshake record".into()));
        }
        let len = u16::from_be_bytes([head[3], head[4]]) as usize;
        let mut body = vec![0u8; len];
        tcp.read_exact(&mut body).await?;
        raw.extend_from_slice(&head);
        raw.extend_from_slice(&body);
        handshake.extend_from_slice(&body);
        // Type (1 byte), length (3), then the message.
        if handshake.len() >= 4 {
            let want = 4 + u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
            if handshake.len() >= want || want > MAX_CLIENT_HELLO {
                return Ok((raw, handshake));
            }
        }
        if raw.len() > MAX_CLIENT_HELLO {
            return Ok((raw, handshake));
        }
    }
}

/// The server_name extension of a ClientHello handshake message, if any.
fn sni_from_client_hello(handshake: &[u8]) -> Option<String> {
    let mut p = Parser(handshake);
    if p.u8()? != 1 {
        return None; // not a ClientHello
    }
    p.take(3)?; // handshake length
    p.take(2 + 32)?; // version, random
    let sid = p.u8()? as usize;
    p.take(sid)?;
    let suites = p.u16()? as usize;
    p.take(suites)?;
    let comp = p.u8()? as usize;
    p.take(comp)?;
    let ext_len = p.u16()? as usize;
    let mut exts = Parser(p.take(ext_len)?);
    while let (Some(kind), Some(len)) = (exts.u16(), exts.u16()) {
        let body = exts.take(len as usize)?;
        if kind == 0 {
            let mut list = Parser(body);
            list.u16()?;
            while let Some(name_type) = list.u8() {
                let n = list.u16()? as usize;
                let name = list.take(n)?;
                if name_type == 0 {
                    return std::str::from_utf8(name).ok().map(str::to_string);
                }
            }
        }
    }
    None
}

struct Parser<'a>(&'a [u8]);

impl<'a> Parser<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
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

        let (target, request) = match resolve_target(raw, default_target.as_ref(), ctx.invisible) {
            Ok(v) => v,
            Err(e) => {
                client.write_all(&error_response(400, "bad_request", &e.to_string())).await?;
                return Ok(());
            }
        };
        let req_head = RawRequest::from_bytes(request.clone()).head()?;
        let client_close = wants_close(&req_head.version, &req_head.headers);
        let method = req_head.method;

        let response = match handle_request(ctx, &target, request, false).await? {
            Reply::Error(response, close) => {
                client.write_all(&response).await?;
                if close || client_close {
                    return Ok(());
                }
                continue;
            }
            Reply::Upgrade(upgrade) => {
                client.write_all(&upgrade.response).await?;
                client.flush().await?;
                return relay_upgrade(ctx, client, reader.into_leftover(), *upgrade).await;
            }
            Reply::Response(response) => response,
        };
        client.write_all(&response).await?;
        client.flush().await?;

        let resp_head = parse_response_head(final_response(&response)).ok();
        // A body cut short (the server closed early) ends the connection, as it did upstream:
        // the client would otherwise wait for the rest.
        let server_close = cut_short(&response, &method)
            || resp_head.as_ref().is_none_or(|h| {
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

/// Serves HTTP/2 to a client that negotiated `h2` on the intercepted TLS
/// connection. Each stream becomes one request in text form and runs on its own task.
async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    ctx: &Arc<Ctx>,
    client: S,
    target: Target,
) -> Result<()> {
    let mut conn = h2::server::handshake(client).await.map_err(h2_error)?;
    while let Some(accepted) = conn.accept().await {
        let (req, respond) = accepted.map_err(h2_error)?;
        ctx.stats.requests.fetch_add(1, Ordering::Relaxed);
        let (ctx, target) = (ctx.clone(), target.clone());
        tokio::spawn(async move {
            if let Err(e) = serve_h2_stream(&ctx, req, respond, &target).await {
                ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
                if !matches!(e, Error::Io(_)) {
                    eprintln!("brainproxy: {}: HTTP/2 stream: {e}", target.origin());
                }
            }
        });
    }
    Ok(())
}

async fn serve_h2_stream(
    ctx: &Arc<Ctx>,
    req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    target: &Target,
) -> Result<()> {
    let (parts, mut body) = req.into_parts();
    let method = parts.method.to_string();
    let response = if parts.method == http::Method::CONNECT {
        error_response(400, "bad_request", "CONNECT over HTTP/2 isn't supported")
    } else {
        let mut data = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(h2_error)?;
            let _ = body.flow_control().release_capacity(chunk.len());
            data.extend_from_slice(&chunk);
            if data.len() > h2p::MAX_BODY {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                return Err(Error::InvalidInput("HTTP/2 request body too large".into()));
            }
        }
        let request = h2p::request_text(&parts, &data, target);
        match handle_request(ctx, target, request, true).await? {
            Reply::Response(response) | Reply::Error(response, _) => response,
            // Upgrades don't exist in HTTP/2; an HTTP/1.1 origin that answers 101 anyway gets nothing.
            Reply::Upgrade(u) => {
                if let Some(c) = u.capture {
                    send_capture(ctx, c, None).await;
                }
                u.response
            }
        }
    };
    let (head, body) = match h2p::response_parts(&response, &method) {
        Ok(v) => v,
        Err(e) => h2p::response_parts(&error_response(502, e.kind(), &e.to_string()), &method)?,
    };
    let mut send = respond.send_response(head, body.is_empty()).map_err(h2_error)?;
    if !body.is_empty() {
        send.send_data(body, true).map_err(h2_error)?;
    }
    Ok(())
}

/// What goes back to the client for one request.
enum Reply {
    /// The response, after rules and intercept.
    Response(Vec<u8>),
    /// A 101 response (sent as received) and the connection to relay from then on.
    Upgrade(Box<Upgrade>),
    /// A brainproxy error response; `true` ends the client connection.
    Error(Vec<u8>, bool),
}

struct Upgrade {
    response: Vec<u8>,
    conn: Option<Conn>,
    /// The upgrade exchange, when it is to be recorded.
    capture: Option<Capture>,
    /// Intercept may apply (as to the upgrade request).
    in_scope: bool,
    host: String,
    path: String,
    url: String,
}

/// One request through scope, rules, auth, and intercept, forwarded upstream
/// and recorded. `h2` marks a request from an HTTP/2 client (text form
/// `METHOD path HTTP/2`): it goes upstream over HTTP/2 when the origin
/// negotiates it, else as HTTP/1.1.
async fn handle_request(ctx: &Arc<Ctx>, target: &Target, mut request: Vec<u8>, h2: bool) -> Result<Reply> {
    let target = ctx.redirect.as_ref().unwrap_or(target);
    let req_head = RawRequest::from_bytes(request.clone()).head()?;
    let method = req_head.method.clone();
    let url = format!("{}{}", target.origin(), req_head.target);
    let path = req_head.target.split('?').next().unwrap_or("/").to_string();

    let live = live(ctx);
    let record = live.scope.allows(&target.host) || live.scope.record_out_of_scope;
    // Intercept, rules, and the auth session apply only to requests that can go out: in the
    // proxy scope and allowed by the engagement. A request the guard will refuse anyway is
    // never held for a decision.
    let in_scope =
        live.scope.allows(&target.host) && ctx.guard.as_ref().is_some_and(|g| g.may_allow(&target.host, target.port));

    let auth = ctx.auth.as_ref().filter(|_| in_scope);
    let mut prepared = None;
    if in_scope {
        request = apply_request_rules(&live.rules, request);
        if let Some(a) = auth {
            let p = a.prepare(Tool::Proxy, target, &request, &[], &[]).await;
            request = p.request.clone();
            prepared = Some(p);
        }
        if live.intercept.matches(false, &method, &target.host, &path) {
            match hold(ctx, &live.intercept, "request", &method, &url, None, request.clone()).await? {
                Some(edited) => request = edited,
                None => {
                    return Ok(Reply::Error(error_response(502, "dropped", "request dropped by brainproxy"), false))
                }
            }
        }
    }

    // A rule or an edit may have changed the method (GET to HEAD): the response is framed
    // by the one sent.
    let method = RawRequest::from_bytes(request.clone()).head().map(|h| h.method).unwrap_or(method);
    let started = Instant::now();
    let mut upstream = forward(ctx, target, &request, &method, h2).await;
    if let (Some(a), Some(p), Ok(up)) = (auth, &prepared, &upstream) {
        // Session lost or stale session values: log in again or refresh them, and
        // replay the request with the new session.
        if a.after_response(p, &up.response).await {
            request = a.prepare(Tool::Proxy, target, &request, &[], &[]).await.request;
            upstream = forward(ctx, target, &request, &method, h2).await;
            if let Ok(up) = &upstream {
                a.observe(&up.response);
            }
        }
    }
    let Upstream { conn, sent, response } = match upstream {
        Ok(v) => v,
        Err(e) => {
            ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
            if record {
                send_capture(ctx, Capture::new("proxy", target, &request, None, None, Some(&e.to_string())), None)
                    .await;
            }
            let status = if matches!(e, Error::OutOfScope(_)) { 403 } else { 502 };
            return Ok(Reply::Error(error_response(status, e.kind(), &e.to_string()), false));
        }
    };
    let duration = started.elapsed().as_millis() as i64;
    let status = parse_response_head(final_response(&response)).ok().map(|h| h.status);
    let capture = record.then(|| Capture::new("proxy", target, &sent, Some(&response), Some(duration), None));
    if status == Some(101) {
        let upgrade = Upgrade { response, conn, capture, in_scope, host: target.host.clone(), path, url };
        return Ok(Reply::Upgrade(Box::new(upgrade)));
    }
    if let Some(c) = capture {
        // Live access-control testing gets the in-scope requests, as sent.
        let authz = (in_scope && ctx.authz.is_some()).then(|| (target.clone(), sent.clone()));
        send_capture(ctx, c, authz).await;
    }
    if let Some(conn) = conn.filter(|_| !close_after(&sent, &response, &method)) {
        ctx.client.checkin(target, conn);
    }

    let mut response = if in_scope { apply_response_rules(&live.rules, response) } else { response };
    if in_scope && live.intercept.matches(true, &method, &target.host, &path) {
        match hold(ctx, &live.intercept, "response", &method, &url, status, response.clone()).await? {
            Some(edited) => response = edited,
            None => return Ok(Reply::Error(error_response(502, "dropped", "response dropped by brainproxy"), true)),
        }
    }
    Ok(Reply::Response(response))
}

/// Relays a connection after a 101: WebSocket frames are parsed, recorded and may be held in
/// intercept; any other protocol is relayed as raw bytes.
async fn relay_upgrade<S: AsyncRead + AsyncWrite + Unpin + Send>(
    ctx: &Arc<Ctx>,
    mut client: S,
    from_client: Vec<u8>,
    upgrade: Upgrade,
) -> Result<()> {
    let Upgrade { response, conn, capture, in_scope, host, path, url } = upgrade;
    let Some(mut conn) = conn else { return Ok(()) };
    let from_server = std::mem::take(&mut conn.reader).into_leftover();
    // After any 1xx interim responses (103 Early Hints).
    let head = parse_response_head(final_response(&response)).ok().filter(crate::ws::is_upgrade_response);
    let Some(head) = head else {
        if let Some(c) = capture {
            send_capture(ctx, c, None).await;
        }
        conn.stream.write_all(&from_client).await?;
        client.write_all(&from_server).await?;
        tokio::io::copy_bidirectional(&mut client, &mut conn.stream).await?;
        return Ok(());
    };
    let key = ctx.ws_keys.fetch_add(1, Ordering::Relaxed);
    let recording = capture.is_some();
    let url = crate::ws::ws_url(&url);
    if let Some(capture) = capture {
        let bytes = capture_bytes(&capture);
        let open = WsEvent::Open {
            key,
            capture: Box::new(capture),
            source: "proxy",
            url: url.clone(),
            time: crate::ws::now_iso(),
        };
        ctx.recorder.send(Record::Ws(open), bytes).await;
    }
    let hooks = WsHooks { ctx: ctx.clone(), key, recording, in_scope, host, path, url, unrecorded: AtomicU64::new(0) };
    let ended =
        crate::ws::relay::relay(client, from_client, conn.stream, from_server, Deflate::from_response(&head), &hooks)
            .await;
    if recording {
        let unrecorded = hooks.unrecorded.load(Ordering::Relaxed);
        let backlog = (unrecorded > 0).then(|| format!("{unrecorded} messages not recorded: the recorder was behind"));
        let error = match (ended.error, backlog) {
            (Some(a), Some(b)) => Some(format!("{a}; {b}")),
            (a, b) => a.or(b),
        };
        let close = WsEvent::Close {
            key,
            time: crate::ws::now_iso(),
            code: ended.close_code,
            reason: ended.close_reason,
            error,
        };
        ctx.recorder.send(Record::Ws(close), 0).await;
    }
    Ok(())
}

/// The proxy's side of a relayed WebSocket connection: recording and intercept.
struct WsHooks {
    /// Messages left out because the recorder's queue was full.
    unrecorded: AtomicU64,
    ctx: Arc<Ctx>,
    key: u64,
    recording: bool,
    in_scope: bool,
    host: String,
    path: String,
    url: String,
}

impl Hooks for WsHooks {
    fn record(&self, direction: Direction, message: &Message, intercept: Option<&'static str>) {
        if self.recording {
            let queued = self.ctx.recorder.try_send(message.payload.len(), || {
                Record::Ws(WsEvent::Message { key: self.key, direction, message: message.clone(), intercept })
            });
            if !queued {
                self.unrecorded.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn should_hold(&self, direction: Direction) -> bool {
        self.in_scope && live(&self.ctx).intercept.matches_ws(direction, &self.host, &self.path)
    }

    async fn hold(&self, direction: Direction, message: &Message) -> Hold {
        let live = live(&self.ctx);
        let held = hold(
            &self.ctx,
            &live.intercept,
            direction.intercept_direction(),
            "WS",
            &self.url,
            None,
            message.payload.clone(),
        )
        .await;
        match held {
            Ok(Some(p)) if p == message.payload => Hold::Forward,
            Ok(Some(p)) => Hold::Edited(p),
            Ok(None) => Hold::Drop,
            Err(e) => {
                eprintln!("brainproxy: {}: WebSocket message not held: {e}", self.url);
                Hold::Forward
            }
        }
    }
}

/// Works out the upstream target and rewrites absolute-form requests to origin-form.
/// With `by_host` (invisible proxying), an origin-form request goes to its Host
/// header's host and port over http.
pub(crate) fn resolve_target(
    raw: Vec<u8>,
    default_target: Option<&Target>,
    by_host: bool,
) -> Result<(Target, Vec<u8>)> {
    let req = RawRequest::from_bytes(raw);
    let head = req.head()?;
    if let Some(t) = default_target {
        return Ok((t.clone(), req.into_bytes()));
    }
    if by_host && head.target.starts_with('/') {
        let host = head
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.trim().to_string())
            .filter(|h| !h.is_empty())
            .ok_or_else(|| Error::InvalidInput("invisible proxy: the request has no Host header".into()))?;
        if !valid_authority(&host) {
            return Err(Error::InvalidInput(format!("invisible proxy: bad Host header {host:?}")));
        }
        let target = Target::from_url(&format!("http://{host}"))
            .map_err(|_| Error::InvalidInput(format!("invisible proxy: bad Host header {host:?}")))?;
        return Ok((target, req.into_bytes()));
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

/// A host name from a client (SNI, Host header): DNS characters only, with at most one
/// trailing dot. The URL parser would otherwise read `a@b` as host `b` and `a/b` as host `a`.
fn valid_client_host(host: &str) -> bool {
    crate::connection::valid_name(host.strip_suffix('.').unwrap_or(host))
}

/// A Host header value: `host`, `host:port`, `[v6]`, or `[v6]:port`.
fn valid_authority(value: &str) -> bool {
    let port_ok = |p: &str| p.parse::<u16>().is_ok();
    if let Some(rest) = value.strip_prefix('[') {
        let Some((ip, after)) = rest.split_once(']') else { return false };
        return ip.parse::<std::net::Ipv6Addr>().is_ok()
            && (after.is_empty() || after.strip_prefix(':').is_some_and(port_ok));
    }
    match value.split_once(':') {
        Some((host, port)) => valid_client_host(host) && port_ok(port),
        None => valid_client_host(value),
    }
}

/// An upstream exchange: the HTTP/1.1 connection to pool (none for HTTP/2),
/// the request as sent (the recorded form), and the response.
struct Upstream {
    conn: Option<Conn>,
    sent: Vec<u8>,
    response: Vec<u8>,
}

async fn forward(ctx: &Arc<Ctx>, target: &Target, request: &[u8], method: &str, h2: bool) -> Result<Upstream> {
    // HTTP/2 client requests use HTTP/2 upstream unless the origin is known not to.
    let origin = target.origin();
    // NTLM authenticates a connection, which HTTP/2 doesn't allow: such origins go over HTTP/1.1.
    let try_h2 = h2
        && target.is_tls()
        && !ctx.client.needs_http1(target)
        && ctx.h2_origins.lock().unwrap().get(&origin) != Some(&false);
    if try_h2 {
        // `Client::send` goes over HTTP/2 because the request line says `HTTP/2`.
        match ctx.client.send(&RawRequest::from_bytes(request.to_vec()), target).await {
            Ok(ex) => {
                ctx.h2_origins.lock().unwrap().insert(origin, true);
                return Ok(Upstream { conn: None, sent: ex.request, response: ex.response });
            }
            Err(e) if e.to_string().contains("did not negotiate HTTP/2") => {
                ctx.h2_origins.lock().unwrap().insert(origin, false);
            }
            Err(e) => return Err(e),
        }
    }
    let request = if h2 { h2p::to_http1(request) } else { request.to_vec() };
    let timeout = ctx.client.options().timeout;
    let (conn, response) = tokio::time::timeout(timeout, ctx.client.exchange(&request, target, method))
        .await
        .map_err(|_| Error::Timeout(timeout))??;
    Ok(Upstream { conn: Some(conn), sent: request, response })
}

/// A row in the intercept queue that someone is waiting on. If the wait is abandoned (the
/// WebSocket connection it belongs to ended), nothing would ever resolve the row: it goes
/// from pending to dropped here, since the message won't be delivered.
struct HeldRow {
    ctx: Arc<Ctx>,
    id: i64,
    decided: bool,
}

impl Drop for HeldRow {
    fn drop(&mut self) {
        if !self.decided {
            let (ctx, id) = (self.ctx.clone(), self.id);
            // Not on this thread: drop may run on the async runtime, and the write can wait for a lock.
            std::thread::spawn(move || {
                // It may have been resolved at the same moment; then there is nothing to do.
                let _ = ctx.control.lock().unwrap().intercept_resolve(id, "dropped", None);
            });
        }
    }
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
    let mut row = HeldRow { ctx: ctx.clone(), id, decided: false };
    let deadline = Instant::now() + Duration::from_secs(intercept.settings.timeout_secs);
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let c = ctx.clone();
        let (state, edited) = tokio::task::spawn_blocking(move || c.control.lock().unwrap().intercept_state(id))
            .await
            .map_err(|e| Error::Protocol(e.to_string()))??;
        match state.as_str() {
            "forwarded" => {
                row.decided = true;
                return Ok(Some(edited.unwrap_or(message)));
            }
            "dropped" => {
                row.decided = true;
                return Ok(None);
            }
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
                row.decided = true;
                return Ok(match intercept.settings.timeout_action {
                    TimeoutAction::Forward => Some(message),
                    TimeoutAction::Drop => None,
                });
            }
            _ => {}
        }
    }
}

async fn send_capture(ctx: &Ctx, capture: Capture, authz: Option<(Target, Vec<u8>)>) {
    // A request waiting to be offered for live testing takes room too.
    let bytes = capture_bytes(&capture) + authz.as_ref().map_or(0, |(_, r)| r.len());
    ctx.recorder.send(Record::Capture(Box::new(Recorded { capture, authz })), bytes).await;
}

fn capture_bytes(c: &Capture) -> usize {
    let text = |t: &Option<String>| t.as_ref().map_or(0, String::len);
    c.request.len()
        + c.response.len()
        + c.req_body.len()
        + c.resp_body.as_ref().map_or(0, Vec::len)
        + text(&c.req_body_text)
        + text(&c.resp_body_text)
}

pub(crate) fn wants_close(version: &str, headers: &[(String, String)]) -> bool {
    let conn = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("connection")).map(|(_, v)| v.to_ascii_lowercase());
    match conn {
        Some(v) if v.contains("close") => true,
        Some(v) if v.contains("keep-alive") => false,
        _ => version.eq_ignore_ascii_case("HTTP/1.0"),
    }
}

pub(crate) fn error_response(status: u16, kind: &str, message: &str) -> Vec<u8> {
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
pub(crate) struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> Prefixed<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, pos: 0, inner }
    }

    pub(crate) async fn peek_byte(&mut self) -> Result<Option<u8>> {
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
            false,
        )
        .unwrap();
        assert_eq!(t.origin(), "http://a.test:8080");
        assert_eq!(out, b"GET /x?y=1 HTTP/1.1\r\nHost: a.test:8080\r\n\r\n");
        assert!(resolve_target(b"GET /x HTTP/1.1\r\n\r\n".to_vec(), None, false).is_err());
        // Invisible proxying routes origin-form requests by their Host header.
        let (t, _) = resolve_target(b"GET /x HTTP/1.1\r\nHost: b.test:81\r\n\r\n".to_vec(), None, true).unwrap();
        assert_eq!(t.origin(), "http://b.test:81");
        assert!(resolve_target(b"GET /x HTTP/1.1\r\n\r\n".to_vec(), None, true).is_err());
        for good in ["b.test", "b.test.", "b.test:81", "10.0.0.5:80", "[::1]", "[::1]:81"] {
            assert!(valid_authority(good), "{good}");
        }
        for bad in [
            "a@b.test",
            "a/b",
            "a b",
            "b.test:99999",
            "b.test:1:2",
            "[::1",
            "[nope]",
            "[::1]x",
            "b.test:",
            "é.test",
            "a?b",
            "a#b",
            "",
        ] {
            assert!(!valid_authority(bad), "{bad}");
            let req = format!("GET /x HTTP/1.1\r\nHost: {bad}\r\n\r\n").into_bytes();
            assert!(resolve_target(req, None, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn reads_sni_from_a_client_hello() {
        // A ClientHello with only a server_name extension for "app.test".
        let name = b"app.test";
        let mut sni = vec![0x00, 0x00];
        let list_len = (name.len() + 3) as u16;
        sni.extend_from_slice(&(list_len + 2).to_be_bytes());
        sni.extend_from_slice(&list_len.to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni);
        let mut hs = vec![1, 0, 0, body.len() as u8];
        hs.extend_from_slice(&body);
        assert_eq!(sni_from_client_hello(&hs).as_deref(), Some("app.test"));
        assert_eq!(sni_from_client_hello(&hs[..15]), None);
        // Split over two records, as TLS allows: both are read before parsing.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut records = Vec::new();
            for part in [&hs[..10], &hs[10..]] {
                records.extend_from_slice(&[0x16, 3, 1]);
                records.extend_from_slice(&(part.len() as u16).to_be_bytes());
                records.extend_from_slice(part);
            }
            let sent = records.clone();
            tokio::spawn(async move { TcpStream::connect(addr).await.unwrap().write_all(&sent).await.unwrap() });
            let (mut tcp, _) = listener.accept().await.unwrap();
            let (raw, handshake) = read_client_hello(&mut tcp).await.unwrap();
            assert_eq!((raw, sni_from_client_hello(&handshake).as_deref()), (records, Some("app.test")));
        });
    }

    #[tokio::test]
    async fn a_full_recorder_leaves_out_ws_messages_but_keeps_captures() {
        let (recorder, rx) = Recorder::new();
        let capture = || Record::Capture(Box::new(Recorded { capture: Capture::default(), authz: None }));
        // Fill the budget with messages nobody is writing yet.
        let mut queued = 0;
        while recorder.try_send(1024 * 1024, capture) {
            queued += 1;
        }
        assert!(queued > 0 && queued <= RECORD_BUDGET / (1024 * 1024));
        assert!(!recorder.try_send(1024 * 1024, || panic!("nothing is built for a message left out")));

        // A capture waits for room rather than being lost.
        let waiting = recorder.send(capture(), 1024 * 1024);
        tokio::pin!(waiting);
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut waiting).await.is_err());
        let (_, cost) = rx.recv().unwrap();
        recorder.budget.add_permits(cost as usize);
        tokio::time::timeout(Duration::from_secs(5), &mut waiting).await.unwrap();
        assert_eq!(rx.try_iter().count(), queued);

        // Larger than the whole budget: it still gets through once the queue is empty.
        recorder.budget.add_permits(RECORD_BUDGET - recorder.budget.available_permits());
        tokio::time::timeout(Duration::from_secs(5), recorder.send(capture(), RECORD_BUDGET * 2)).await.unwrap();
        assert_eq!(rx.try_iter().count(), 1);
    }
}
