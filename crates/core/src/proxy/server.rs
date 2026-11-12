//! The intercepting proxy: HTTP/1.x forward proxy with CONNECT, TLS
//! interception for in-scope hosts (HTTP/2 to clients that offer it), match-and-replace rules, an intercept queue
//! resolved through the project database, capture recording, and live access-control
//! testing of recorded requests.
//!
//! Traffic outside the recording scope is forwarded and still leaves a row: a request keeps
//! its request line only, and a CONNECT tunnel (never decrypted) is recorded as a connection.
//!
//! A response that is an event stream (`text/event-stream`) is relayed to the client as it
//! arrives instead of being read whole, over HTTP/1.1 and HTTP/2: its row is written as the
//! stream opens, its events are recorded as they pass, and the row gets the body (as far as a
//! stream may store) when the stream ends or the proxy stops. Response header rules apply to
//! its head; body rules, response intercept and live access-control testing, which need a
//! finished response, leave it alone.
//!
//! Connection options: TLS pass-through hosts are tunnelled without being
//! decrypted (still scope-checked, and recorded as a connection), and with
//! `invisible` the listener also serves clients that don't know they're proxied:
//! origin-form requests are routed by their Host header and TLS by its SNI. A
//! `redirect` target sends everything from the listener to one origin.

use std::borrow::Cow;
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
use crate::filter::Matcher;
use crate::http::client::{close_after, cut_short, final_response, Conn, LiveBody};
use crate::http::h2::h2_error;
use crate::http::wire::Piece;
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Target, WireReader};
use crate::provenance::Edit;
use crate::proxy::ca::CertAuthority;
use crate::proxy::config::{
    filter_matches, CompiledIntercept, CompiledScope, InterceptSettings, Rule, Scope, TimeoutAction, INTERCEPT_KEY,
    RULES_KEY, SCOPE_KEY,
};
use crate::proxy::h2 as h2p;
use crate::rules::{Engine, RuleSet};
use crate::session::Tool;
use crate::sse::db::SseRecord;
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
/// How long stopping waits for requests already sent upstream to be answered. `proxy stop`
/// waits up to 30 seconds for the process to exit, which leaves the rest for writing out
/// the queued captures.
const DRAIN: Duration = Duration::from_secs(3);
/// The error of a request still unanswered when the proxy stopped.
const STOPPED: &str = "proxy stopped before the response arrived";
/// How the error of a row for a request forwarded outside the recording scope starts. The
/// row keeps the request line only, like a `--no-store` row, so narrowing the scope hides
/// what went out but never that it did.
pub const OUT_OF_SCOPE: &str = "outside the recording scope: content omitted";
/// How the error of the `CONNECT` row for a tunnel outside the recording scope starts.
pub const OUT_OF_SCOPE_TUNNEL: &str = "outside the recording scope: tunnelled, not decrypted";
/// How the error of the `CONNECT` row for a TLS pass-through connection starts.
pub const PASSED_THROUGH: &str = "TLS pass-through, not decrypted";
/// The rest of the error of a tunnel's row while it is open. The row is written as the tunnel
/// opens and completed as it closes, so a proxy that is killed leaves this.
const TUNNEL_OPENED: &str = "open, no close recorded yet";
/// The rest of the error of a tunnel's row when it was still open as the proxy stopped.
const TUNNEL_OPEN: &str = "still open when the proxy stopped";
/// The error of an event stream that was still open as the proxy stopped.
const STREAM_OPEN: &str = "still open when the proxy stopped";
/// The error of an event stream a proxy that was killed left open.
const STALE_SSE: &str = "the proxy stopped before the stream ended";
/// Body bytes the event streams open at one time may hold between them while they are
/// recorded (each holds its own until it closes). A stream that would pass it stops being
/// recorded, like one over its own cap.
const STREAM_BUDGET: usize = 256 * 1024 * 1024;

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

tokio::task_local! {
    /// The client of the connection being served, for the captures made while serving it
    /// (set per connection, and again on each HTTP/2 stream's task).
    static PEER: SocketAddr;
}

/// The address of the proxy client being served, outside a connection None.
pub(crate) fn client_addr() -> Option<String> {
    PEER.try_with(|p| p.to_string()).ok()
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
    rules: RuleSet,
    /// Where a rule's script failure is noted, for whoever lists the rules. Made anew with
    /// the rules, so a rule switched off and on is noted afresh.
    rule_failures: crate::rules::FailureLog,
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
    /// Names event streams for the recorder.
    sse_keys: AtomicU64,
    /// Body bytes held by the event streams open now, against [`STREAM_BUDGET`].
    stream_bytes: std::sync::atomic::AtomicUsize,
    stats: Stats,
    http2: bool,
    /// Whether each https origin negotiated HTTP/2 (tried for HTTP/2 clients).
    h2_origins: Mutex<HashMap<String, bool>>,
    invisible: bool,
    redirect: Option<Target>,
    in_flight: Arc<InFlight>,
}

/// Requests forwarded upstream whose exchange isn't recorded yet. Stopping waits for them
/// for a while, then records the ones left as failures; meanwhile no new request goes out.
#[derive(Default)]
struct InFlight(Mutex<FlightState>);

#[derive(Default)]
struct FlightState {
    next: u64,
    stopping: bool,
    /// The row to record if it is still unanswered at the end, and whether its exchange is
    /// being recorded (claimed). The row is made on the connection's task, as every proxy
    /// capture is, so it has what that task knows.
    open: HashMap<u64, (Capture, bool)>,
    /// Tunnels open now (never decrypted), each with the history id of its row and what the
    /// row says should it still be open at the end. Stopping doesn't wait for them: they can
    /// stay open for as long as a client likes.
    tunnels: HashMap<u64, (i64, Capture)>,
    /// Event streams being relayed and recorded, by key. Stopping doesn't wait for them
    /// either: each is closed then with what it has stored so far.
    streams: HashMap<u64, Arc<OpenStream>>,
    /// Stopping has closed the streams open then: one that opens after it isn't tracked.
    streams_taken: bool,
    /// Streams whose closing record is being queued (it may wait for room): stopping waits
    /// for them as it does for requests, or the record would go nowhere.
    closing: usize,
}

/// A stream's closing record on its way to the recorder, until dropped.
struct Closing<'a>(&'a InFlight);

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        self.0 .0.lock().unwrap().closing -= 1;
    }
}

/// One request in [`InFlight`], until dropped: once its exchange is queued for the recorder.
struct Flight {
    set: Arc<InFlight>,
    id: u64,
}

/// One tunnel in [`InFlight`], until dropped.
struct OpenTunnel {
    set: Arc<InFlight>,
    id: u64,
}

impl InFlight {
    /// Registers a request about to go upstream, with its row should it go unanswered;
    /// `None` once the proxy is stopping, when nothing more may be sent.
    fn start(self: &Arc<Self>, unanswered: Capture) -> Option<Flight> {
        let mut s = self.0.lock().unwrap();
        if s.stopping {
            return None;
        }
        s.next += 1;
        let id = s.next;
        s.open.insert(id, (unanswered, false));
        Some(Flight { set: self.clone(), id })
    }

    /// Registers a tunnel about to open, whose row is `row`, with what the row says should it
    /// still be open when the proxy stops; `None` once it is stopping.
    fn open_tunnel(self: &Arc<Self>, row: i64, still_open: Capture) -> Option<OpenTunnel> {
        let mut s = self.0.lock().unwrap();
        if s.stopping {
            return None;
        }
        s.next += 1;
        let id = s.next;
        s.tunnels.insert(id, (row, still_open));
        Some(OpenTunnel { set: self.clone(), id })
    }

    fn stop(&self) {
        self.0.lock().unwrap().stopping = true;
    }

    /// Tracks a stream so that stopping closes it. False once stopping has closed the streams
    /// open then: the caller closes this one itself.
    fn add_stream(&self, stream: Arc<OpenStream>) -> bool {
        let mut s = self.0.lock().unwrap();
        if s.streams_taken {
            return false;
        }
        s.streams.insert(stream.key, stream);
        true
    }

    /// Stops tracking a stream that is closing; stopping waits until the result is dropped.
    fn closing_stream(&self, key: u64) -> Closing<'_> {
        let mut s = self.0.lock().unwrap();
        s.streams.remove(&key);
        s.closing += 1;
        Closing(self)
    }

    /// The event streams open now, no longer tracked: stopping closes them.
    fn take_streams(&self) -> Vec<Arc<OpenStream>> {
        let mut s = self.0.lock().unwrap();
        s.streams_taken = true;
        s.streams.drain().map(|(_, s)| s).collect()
    }

    fn is_empty(&self) -> bool {
        let s = self.0.lock().unwrap();
        s.open.is_empty() && s.closing == 0
    }

    /// Removes the requests nobody is recording yet: their exchanges won't be recorded by
    /// whoever sent them. Returns their rows, as unanswered, and the history ids and final rows
    /// of the tunnels still open.
    fn take_unclaimed(&self) -> (Vec<Capture>, Vec<(i64, Capture)>) {
        let mut s = self.0.lock().unwrap();
        let ids: Vec<u64> = s.open.iter().filter(|(_, v)| !v.1).map(|(k, _)| *k).collect();
        let rows: Vec<Capture> = ids.into_iter().filter_map(|id| s.open.remove(&id)).map(|v| v.0).collect();
        (rows, s.tunnels.drain().map(|(_, t)| t).collect())
    }
}

impl Flight {
    /// Claims the exchange for recording. False if stopping already recorded it as unanswered.
    fn claim(&self) -> bool {
        self.set.0.lock().unwrap().open.get_mut(&self.id).map(|v| v.1 = true).is_some()
    }

    /// The request is answered, but its exchange is recorded later (after a re-login): should
    /// stopping record it first, `answered` is its row, not the unanswered one.
    fn answered(&self, answered: Capture) {
        if let Some(v) = self.set.0.lock().unwrap().open.get_mut(&self.id) {
            v.0 = answered;
        }
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        self.set.0.lock().unwrap().open.remove(&self.id);
    }
}

impl OpenTunnel {
    /// Takes the tunnel's row over as it closes. False if stopping already recorded it.
    fn close(&self) -> bool {
        self.set.0.lock().unwrap().tunnels.remove(&self.id).is_some()
    }
}

impl Drop for OpenTunnel {
    fn drop(&mut self) {
        self.set.0.lock().unwrap().tunnels.remove(&self.id);
    }
}

/// What the recorder thread writes, in order.
enum Record {
    Capture(Box<Recorded>),
    Ws(WsEvent),
    Sse(SseRecord),
}

/// The queue to the recorder thread, bounded by bytes (each record holds its permits until it
/// is written). HTTP captures and connection open/close wait for room, so none is lost: the
/// request that made one is delayed instead. WebSocket messages never wait, so a slow disk
/// can't stall the relay: one that doesn't fit is left out and the connection says so. The
/// events of an event stream go the same way; its opening and closing wait.
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
    control.sse_close_stale("proxy", STALE_SSE)?;
    let (recorder, rx) = Recorder::new();
    let budget = recorder.budget.clone();
    let mut writer_store = Store::open(&opts.project)?;
    let authz = opts.authz.clone();
    // Once the proxy stops, the writer only writes: passive checks of the last captures are
    // left for the next scan, so the queue is flushed before `proxy stop` gives up waiting.
    let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_stopping = stopping.clone();
    let writer = std::thread::spawn(move || {
        let (mut ws_ids, mut sse_ids) = (HashMap::new(), HashMap::new());
        // Stream rows completed while stopping: scanned with their bodies by the next scan.
        let mut unscanned = Vec::new();
        while let Ok(first) = rx.recv() {
            let (mut batch, mut ws, mut sse, mut cost) = (Vec::new(), Vec::new(), Vec::new(), 0);
            for (r, c) in std::iter::once(first).chain(std::iter::from_fn(|| rx.try_recv().ok()).take(255)) {
                cost += c as usize;
                match r {
                    Record::Capture(c) => batch.push(*c),
                    Record::Ws(e) => ws.push(e),
                    Record::Sse(e) => sse.push(e),
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
            let ended = writer_store.sse_record(&sse, &mut sse_ids).unwrap_or_else(|e| {
                eprintln!("brainproxy: failed to record {} event stream records: {e}", sse.len());
                Vec::new()
            });
            // Written (or given up on): their room is free again.
            drop((captures, ws, sse));
            budget.add_permits(cost);
            if writer_stopping.load(Ordering::Relaxed) {
                unscanned.extend(ended);
                continue;
            }
            // A stream's row was scanned with its head as it opened; now it has its body.
            for id in ended {
                if let Err(e) = crate::scan::passive::scan_late(&mut writer_store, id) {
                    eprintln!("brainproxy: passive scan of event stream row {id} failed: {e}");
                }
            }
            if let Err(e) = crate::scan::passive::scan_pending(&mut writer_store) {
                eprintln!("brainproxy: passive scan failed: {e}");
            }
        }
        if let Err(e) = writer_store.ws_close_stale("proxy", STALE_WS) {
            eprintln!("brainproxy: WebSocket connections left open: {e}");
        }
        if let Err(e) = writer_store.sse_close_stale("proxy", STALE_SSE) {
            eprintln!("brainproxy: event streams left open: {e}");
        }
        if let Err(e) = crate::scan::passive::scan_later(&writer_store, &unscanned) {
            eprintln!("brainproxy: {} event stream rows not left for the passive scanner: {e}", unscanned.len());
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
        sse_keys: AtomicU64::new(0),
        stream_bytes: Default::default(),
        stats: Stats::default(),
        http2: opts.http2,
        h2_origins: Mutex::default(),
        invisible: opts.invisible || opts.redirect.is_some(),
        redirect: opts.redirect,
        in_flight: Arc::default(),
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
                tokio::spawn(PEER.scope(peer, async move {
                    if let Err(e) = handle_connection(&ctx, tcp, peer).await {
                        ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
                        if !matches!(e, Error::Io(_)) {
                            eprintln!("brainproxy: {peer}: {e}");
                        }
                    }
                }));
            }
        }
    }
    refresher.abort();
    // Requests already sent upstream get a moment to be answered and recorded; the ones
    // still waiting then are recorded as unanswered.
    ctx.in_flight.stop();
    stopping.store(true, Ordering::Relaxed);
    let deadline = Instant::now() + DRAIN;
    while !ctx.in_flight.is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (unanswered, tunnels) = ctx.in_flight.take_unclaimed();
    for capture in unanswered {
        send_capture(&ctx, capture, None).await;
    }
    for (id, capture) in tunnels {
        complete_tunnel_row(&ctx, id, capture).await;
    }
    // Event streams still open: their rows get what they stored so far.
    for stream in ctx.in_flight.take_streams() {
        stream.close(&ctx, "stopped", Some(STREAM_OPEN.into())).await;
    }
    // Ones being recorded right now are only waiting for room in the queue (or for a
    // WebSocket connection's opening to be queued).
    let deadline = Instant::now() + Duration::from_secs(1);
    while !ctx.in_flight.is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
        // Live access-control testing skips the paths saved now.
        // A bad value keeps the previous skip paths; the other settings still reload.
        if let Some(authz) = &c.authz {
            let saved = store.setting::<crate::authz::noise::SavedSkips>(crate::authz::noise::SKIP_KEY);
            match saved.and_then(|s| crate::authz::noise::PathSkips::compile(&s.paths)) {
                Ok(skips) => authz.set_saved_skips(skips),
                Err(e) => eprintln!("brainproxy: live authz skip paths not reloaded: {e}"),
            }
        }
        // Connection options and platform credentials go to the guard every client shares.
        if let Some(g) = &c.guard {
            g.net.set(store.connection_compiled()?);
        }
        Ok(Some(Live {
            version,
            scope: scope.compile()?,
            rules: RuleSet::compile(&rules)?,
            rule_failures: crate::rules::FailureLog::of(&store),
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
        return tunnel(ctx, stream, &target, PASSED_THROUGH).await;
    }
    if !live(ctx).scope.allows(&target.host) {
        return tunnel(ctx, stream, &target, OUT_OF_SCOPE_TUNNEL).await;
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

/// Relays bytes without inspecting them: a CONNECT outside the recording scope (`why` is
/// [`OUT_OF_SCOPE_TUNNEL`]) or to a TLS pass-through host ([`PASSED_THROUGH`]). The upstream
/// connection goes through the guard (and the connection options) like any other. Either
/// way the tunnel is recorded as a `CONNECT` entry (no response: nothing was decrypted), so
/// traffic the proxy doesn't record still leaves a row. The row is written before anything
/// goes upstream, saying the tunnel is open, and completed with the byte counts as it closes
/// (or as the proxy stops), so a long-lived tunnel shows at once and one killed with the
/// proxy still leaves its row.
async fn tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    ctx: &Arc<Ctx>,
    mut client: S,
    target: &Target,
    why: &str,
) -> Result<()> {
    let upstream_target = ctx.redirect.as_ref().unwrap_or(target);
    let authority = target.host_header();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    let https = Target { scheme: "https".into(), ..target.clone() };
    let row = |note: &str, duration| Capture::new("proxy", &https, request.as_bytes(), None, duration, Some(note));
    let id = record_tunnel_row(ctx, row(&format!("{why}: {TUNNEL_OPENED}"), None)).await?;
    // Completed at the end whether or not it is still open then: the proxy doesn't wait for it.
    let Some(open) = ctx.in_flight.open_tunnel(id, row(&format!("{why}: {TUNNEL_OPEN}"), None)) else {
        complete_tunnel_row(ctx, id, row(&format!("{why}: not opened, the proxy was stopping"), None)).await;
        return Ok(());
    };
    let started = Instant::now();
    let plain = Target { scheme: "http".into(), ..upstream_target.clone() };
    let result = async {
        let mut upstream = ctx.client.connect(&plain).await?;
        Ok::<_, Error>(tokio::io::copy_bidirectional(&mut client, &mut upstream).await?)
    }
    .await;
    let note = match &result {
        Ok((up, down)) => format!("{why}: {up} bytes sent, {down} received"),
        Err(e) => format!("{why}: {e}"),
    };
    let duration = Some(started.elapsed().as_millis() as i64);
    if open.close() {
        complete_tunnel_row(ctx, id, row(&note, duration)).await;
    }
    result.map(|_| ())
}

/// Writes a tunnel's row as it opens, straight to the project rather than through the
/// recorder's queue: it must be there before the tunnel carries anything. Returns its id.
async fn record_tunnel_row(ctx: &Arc<Ctx>, capture: Capture) -> Result<i64> {
    let c = ctx.clone();
    tokio::task::spawn_blocking(move || c.control.lock().unwrap().record(&capture))
        .await
        .map_err(|e| Error::Protocol(format!("recording a tunnel: {e}")))?
}

/// Rewrites tunnel row `id` with how it ended.
async fn complete_tunnel_row(ctx: &Arc<Ctx>, id: i64, capture: Capture) {
    let c = ctx.clone();
    let done = tokio::task::spawn_blocking(move || c.control.lock().unwrap().update_capture(id, &capture)).await;
    let err = match done {
        Ok(Ok(())) => return,
        Ok(Err(e)) => e.to_string(),
        Err(e) => e.to_string(),
    };
    eprintln!("brainproxy: tunnel row {id} not completed: {err}");
}

/// Whether the connection options say to tunnel this host's TLS undecrypted.
fn passthrough(ctx: &Ctx, target: &Target) -> bool {
    ctx.guard.as_ref().is_some_and(|g| g.net.get().passthrough(&target.host, target.port))
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
        return tunnel(ctx, stream, &named, PASSED_THROUGH).await;
    }
    if !live(ctx).scope.allows(&name) {
        return tunnel(ctx, stream, &named, OUT_OF_SCOPE_TUNNEL).await;
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
            Reply::Upgrade(mut upgrade) => {
                if let Err(e) = client.write_all(&upgrade.response).await {
                    // The client is gone, but the upgrade went upstream and was answered.
                    if let Some(c) = upgrade.capture.take() {
                        send_capture(ctx, c, None).await;
                    }
                    return Err(e.into());
                }
                client.flush().await?;
                return relay_upgrade(ctx, client, reader.into_leftover(), *upgrade).await;
            }
            // The connection ends with the stream: nothing after it is read.
            Reply::Stream(stream) => return relay_stream(ctx, client, *stream).await,
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
        let stream = async move {
            if let Err(e) = serve_h2_stream(&ctx, req, respond, &target).await {
                ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
                if !matches!(e, Error::Io(_)) {
                    eprintln!("brainproxy: {}: HTTP/2 stream: {e}", target.origin());
                }
            }
        };
        // A task of its own doesn't see the connection's client address: hand it on.
        match PEER.try_with(|p| *p) {
            Ok(peer) => tokio::spawn(PEER.scope(peer, stream)),
            Err(_) => tokio::spawn(stream),
        };
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
            Reply::Stream(stream) => return relay_stream_h2(ctx, respond, *stream).await,
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
    /// The head of an event stream, and its body to relay as it arrives.
    Stream(Box<StreamReply>),
    /// A brainproxy error response; `true` ends the client connection.
    Error(Vec<u8>, bool),
}

struct Upgrade {
    response: Vec<u8>,
    conn: Option<Conn>,
    /// The upgrade exchange, when it is to be recorded.
    capture: Option<Capture>,
    /// Keeps stopping waiting until the capture is queued.
    flight: Option<Flight>,
    /// Intercept may apply (as to the upgrade request).
    in_scope: bool,
    host: String,
    path: String,
    url: String,
    /// The upgrade request as sent, which the intercept's filter is asked about.
    handshake: (Target, Vec<u8>),
}

/// An event stream on its way to the client.
struct StreamReply {
    /// The response's head, after the header rules.
    head: Vec<u8>,
    body: LiveBody,
    /// Its recording, when it is recorded.
    open: Option<Arc<OpenStream>>,
}

/// An event stream being relayed and recorded. Its row was written as it opened, with the
/// response's head; closing rewrites the row with the body, as far as a stream may store.
struct OpenStream {
    key: u64,
    target: Target,
    /// The request as sent, and the response's head as received.
    sent: Vec<u8>,
    head: Vec<u8>,
    started: Instant,
    edited_by: Vec<Edit>,
    /// The client it is relayed to. Kept, as the proxy closes the stream on another task when it stops.
    client_addr: Option<String>,
    state: Mutex<StreamState>,
}

struct StreamState {
    recorder: crate::sse::Recorder,
    /// Events left out because the recorder's queue was full.
    unrecorded: u64,
    /// What the stream's row already says of its recording (over a cap, events it can't read).
    noted: Option<String>,
    closed: bool,
}

impl OpenStream {
    /// Records what a stream may store of a piece on its way to the client. Events never wait
    /// for the recorder, so a slow disk can't stall the relay: one that doesn't fit is left
    /// out and the stream says so.
    fn record(&self, ctx: &Ctx, piece: &Piece) {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return;
        }
        let held = state.recorder.body().len();
        let full = ctx.stream_bytes.load(Ordering::Relaxed) + piece.wire.len() > STREAM_BUDGET;
        let events = if full && !state.recorder.truncated() {
            state.recorder.cut(format!(
                "recording stopped: the event streams open now hold {} MiB between them",
                STREAM_BUDGET >> 20
            ))
        } else {
            state.recorder.push(piece)
        };
        // What it holds now: more, or less when the body was cut back to where it still reads.
        let now = state.recorder.body().len();
        if now >= held {
            ctx.stream_bytes.fetch_add(now - held, Ordering::Relaxed);
        } else {
            ctx.stream_bytes.fetch_sub(held - now, Ordering::Relaxed);
        }
        for event in events {
            let text = |t: &Option<String>| t.as_ref().map_or(0, String::len);
            let bytes = text(&event.data) + text(&event.event_id) + event.event.len();
            if !ctx.recorder.try_send(bytes, || Record::Sse(SseRecord::Event { key: self.key, event })) {
                state.unrecorded += 1;
            }
        }
        // Over a cap, or events that can't be read: the stream says so now, not only once it
        // closes. If the recorder has no room, the next piece tries again, and closing says it too.
        let note = state.recorder.note().map(str::to_string);
        if note != state.noted {
            let (key, truncated, error) = (self.key, state.recorder.truncated(), note.clone().unwrap_or_default());
            if ctx.recorder.try_send(error.len(), || Record::Sse(SseRecord::Note { key, truncated, error })) {
                state.noted = note;
            }
        }
    }

    /// Closes the recording, once: the row gets the body kept, the stream how it ended.
    async fn close(&self, ctx: &Ctx, ended: &'static str, error: Option<String>) {
        let _closing = ctx.in_flight.closing_stream(self.key);
        let (truncated, body, notes) = {
            let mut state = self.state.lock().unwrap();
            if std::mem::replace(&mut state.closed, true) {
                return;
            }
            let backlog = (state.unrecorded > 0)
                .then(|| format!("{} events not recorded: the recorder was behind", state.unrecorded));
            let notes: Vec<String> =
                [error, state.recorder.note().map(str::to_string), backlog].into_iter().flatten().collect();
            (state.recorder.truncated(), state.recorder.take_body(), notes)
        };
        ctx.stream_bytes.fetch_sub(body.len(), Ordering::Relaxed);
        // Built outside the lock: decoding the body takes a moment, and a relay still running
        // (the proxy is stopping) must not wait for it.
        let response = [self.head.as_slice(), &body].concat();
        drop(body);
        let ms = Some(self.started.elapsed().as_millis() as i64);
        let capture = Capture::new("proxy", &self.target, &self.sent, Some(&response), ms, None);
        let capture = Capture { edited_by: self.edited_by.clone(), client_addr: self.client_addr.clone(), ..capture };
        let bytes = capture_bytes(&capture);
        let record = SseRecord::Close {
            key: self.key,
            time: crate::ws::now_iso(),
            capture: Box::new(capture),
            truncated,
            ended,
            error: (!notes.is_empty()).then(|| notes.join("; ")),
        };
        ctx.recorder.send(Record::Sse(record), bytes).await;
    }
}

/// How a relayed stream ended: who ended it (`server`, `client`, `error`), and the error.
type StreamEnd = (&'static str, Option<String>);

/// Relays an event stream to an HTTP/1.x client as it arrives: the head, then each piece of
/// the body as received, flushed at once. The connection ends with the stream.
async fn relay_stream<S: AsyncRead + AsyncWrite + Unpin + Send>(
    ctx: &Arc<Ctx>,
    client: S,
    stream: StreamReply,
) -> Result<()> {
    let StreamReply { head, mut body, open } = stream;
    let (mut from_client, mut to_client) = tokio::io::split(client);
    let relay = async {
        if let Err(e) = async {
            to_client.write_all(&head).await?;
            to_client.flush().await
        }
        .await
        {
            return ("client", Some(format!("the client went away: {e}")));
        }
        // The client has nothing more to say on this connection: when it closes, the stream
        // is over, even while the server is quiet.
        let client_closed = async {
            let mut scratch = [0u8; 1024];
            while matches!(from_client.read(&mut scratch).await, Ok(n) if n > 0) {}
        };
        tokio::pin!(client_closed);
        loop {
            let piece = tokio::select! {
                piece = body.next() => piece,
                _ = &mut client_closed => return ("client", None),
            };
            match piece {
                Ok(Some(piece)) => {
                    if let Some(open) = &open {
                        open.record(ctx, &piece);
                    }
                    if let Err(e) = async {
                        to_client.write_all(&piece.wire).await?;
                        to_client.flush().await
                    }
                    .await
                    {
                        return ("client", Some(format!("the client went away: {e}")));
                    }
                }
                Ok(None) => return ("server", None),
                Err(e) => return ("error", Some(e.to_string())),
            }
        }
    };
    let (ended, error): StreamEnd = relay.await;
    // The upstream connection closes with the body; the client's is told the stream is over.
    drop(body);
    let _ = to_client.shutdown().await;
    if let Some(open) = open {
        open.close(ctx, ended, error).await;
    }
    Ok(())
}

/// Relays an event stream to an HTTP/2 client as it arrives: the head, then the content of
/// each piece of the body as a DATA frame.
async fn relay_stream_h2(
    ctx: &Arc<Ctx>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    stream: StreamReply,
) -> Result<()> {
    let StreamReply { head, mut body, open } = stream;
    let relay = async {
        // As for a HEAD: the body isn't here to measure a Content-Length against.
        let head = match h2p::response_parts(&head, "HEAD") {
            Ok((head, _)) => head,
            Err(e) => {
                respond.send_reset(h2::Reason::INTERNAL_ERROR);
                return ("error", Some(e.to_string()));
            }
        };
        let mut send = match respond.send_response(head, false) {
            Ok(send) => send,
            Err(e) => return ("client", Some(format!("the client went away: {}", h2_error(e)))),
        };
        loop {
            let piece = tokio::select! {
                piece = body.next() => piece,
                _ = std::future::poll_fn(|cx| send.poll_reset(cx)) => return ("client", None),
            };
            match piece {
                Ok(Some(piece)) => {
                    if let Some(open) = &open {
                        open.record(ctx, &piece);
                    }
                    if let Err(e) = send_h2_data(&mut send, bytes::Bytes::copy_from_slice(piece.data())).await {
                        return ("client", Some(format!("the client went away: {e}")));
                    }
                }
                Ok(None) => {
                    let _ = send.send_data(bytes::Bytes::new(), true);
                    return ("server", None);
                }
                Err(e) => {
                    send.send_reset(h2::Reason::INTERNAL_ERROR);
                    return ("error", Some(e.to_string()));
                }
            }
        }
    };
    let (ended, error): StreamEnd = relay.await;
    drop(body);
    if let Some(open) = open {
        open.close(ctx, ended, error).await;
    }
    Ok(())
}

/// Sends `data` on an HTTP/2 stream as the client's flow-control window allows, so a client
/// that reads slowly holds the relay back instead of filling memory.
async fn send_h2_data(send: &mut h2::SendStream<bytes::Bytes>, mut data: bytes::Bytes) -> Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let room = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(n)) => n,
            Some(Err(e)) => return Err(h2_error(e)),
            None => return Err(Error::Protocol("HTTP/2: the stream closed".into())),
        };
        let chunk = data.split_to(room.min(data.len()));
        if !chunk.is_empty() {
            send.send_data(chunk, false).map_err(h2_error)?;
        }
    }
    Ok(())
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
    // Outside the recording scope the row keeps the request line only (unless out-of-scope
    // traffic is recorded too): every request that goes out leaves a row.
    let omit = (!live.scope.allows(&target.host) && !live.scope.record_out_of_scope).then_some(OUT_OF_SCOPE);
    let row =
        |target: &Target, request: &[u8], response: Option<&[u8]>, ms: Option<i64>, error: Option<&str>| match omit {
            Some(reason) => crate::sent::content_omitted("proxy", target, request, response, ms, error, reason),
            None => Capture::new("proxy", target, request, response, ms, error),
        };
    // Intercept, rules, and the auth session apply only to requests that can go out: in the
    // proxy scope and allowed by the engagement. A request the guard will refuse anyway is
    // never held for a decision.
    let in_scope =
        live.scope.allows(&target.host) && ctx.guard.as_ref().is_some_and(|g| g.may_allow(&target.host, target.port));

    let auth = ctx.auth.as_ref().filter(|_| in_scope);
    let mut prepared = None;
    // Who changed the request on its way: the row's origin is the proxy's, not theirs.
    let mut edited_by = Vec::new();
    // The request as the client sent it, when a rule changed it.
    let mut original_request = None;
    if in_scope {
        let ruled = live.rules.request(Engine::Proxy, &target.host, request);
        live.rule_failures.note(Engine::Proxy, &ruled.failed);
        // A request rule's script blocked or answered it: nothing is sent and no connection is
        // opened, no session applied, and the request isn't held in intercept. The row says what
        // the script did. An answer is taken as a server's response would be: through the
        // response rules and the response intercept (passive checks read it too, and say what
        // they find there is the script's), but it isn't handed to live access-control testing.
        if let Some(stopped) = &ruled.stopped {
            let (edited_by, original_request) = (ruled.edits(), ruled.original.clone());
            let Some(answer) = stopped.answer() else {
                let msg = stopped.message();
                let c = row(target, &ruled.bytes, None, None, Some(&msg));
                send_capture(ctx, Capture { edited_by, original_request, ..c }, None).await;
                return Ok(Reply::Error(error_response(403, "blocked", &msg), false));
            };
            let sent = &ruled.bytes;
            let answered = live.rules.response(Engine::Proxy, &target.host, sent, answer.to_vec());
            live.rule_failures.note(Engine::Proxy, &answered.failed);
            let mut c = Capture { edited_by, original_request, ..row(target, sent, Some(answer), Some(0), None) };
            if answered.changed() {
                c.modified_response = Some(answered.bytes.clone());
                c.response_edits = answered.edits();
            }
            let method =
                RawRequest::from_bytes(sent.clone()).head().map(|h| h.method).unwrap_or_else(|_| method.clone());
            let held = live.intercept.matches(true, &method, &target.host, &path, || {
                Cow::Owned(Capture::new("proxy", target, sent, Some(&answered.bytes), Some(0), None))
            });
            send_capture(ctx, c, None).await;
            let mut response = answered.bytes;
            if held {
                let status = parse_response_head(&response).ok().map(|h| h.status);
                match hold(ctx, &live.intercept, "response", &method, &url, status, response.clone()).await? {
                    Some(released) => response = released.message,
                    None => {
                        return Ok(Reply::Error(error_response(502, "dropped", "response dropped by brainproxy"), true))
                    }
                }
            }
            return Ok(Reply::Response(response));
        }
        // An agent's rule that brings in a Host the scope doesn't list, unless it was saved as a
        // Host-header test, isn't sent: a shared front end may route the request to another site.
        // A person's rule was warned about when it was saved.
        if let Some(host) = ruled.agent_host(ctx.client.options(), target) {
            let msg = format!("out of scope: {}", ruled.host_refusal(&host));
            let c = row(target, &ruled.bytes, None, None, Some(&msg));
            send_capture(ctx, Capture { edited_by: ruled.edits(), original_request: ruled.original, ..c }, None).await;
            return Ok(Reply::Error(error_response(502, "out_of_scope", &msg), false));
        }
        edited_by.extend(ruled.edits());
        request = ruled.bytes;
        original_request = ruled.original;
        if let Some(a) = auth {
            let p = a.prepare(Tool::Proxy, target, &request, &[], &[]).await;
            // The profile and its session rules and macros answer for what they changed.
            if p.request != request {
                edited_by.extend(a.edits(&p));
            }
            request = p.request.clone();
            prepared = Some(p);
        }
        // The filter sees the request as it would go out, after rules and the session.
        let exchange = || Cow::Owned(Capture::new("proxy", target, &request, None, None, None));
        if live.intercept.matches(false, &method, &target.host, &path, exchange) {
            match hold(ctx, &live.intercept, "request", &method, &url, None, request.clone()).await? {
                Some(released) => {
                    request = released.message;
                    edited_by.extend(released.edit);
                }
                None => {
                    return Ok(Reply::Error(error_response(502, "dropped", "request dropped by brainproxy"), false))
                }
            }
        }
    }

    // A rule or an edit may have changed the method (GET to HEAD): the response is framed
    // by the one sent.
    let method = RawRequest::from_bytes(request.clone()).head().map(|h| h.method).unwrap_or(method);
    // The row stopping leaves for a request still unanswered says who changed it, as any does.
    let unanswered = |request: &[u8], edited_by: &[Edit], original: &Option<Vec<u8>>| Capture {
        edited_by: edited_by.to_vec(),
        original_request: original.clone(),
        ..row(target, request, None, None, Some(STOPPED))
    };
    let Some(mut flight) = ctx.in_flight.start(unanswered(&request, &edited_by, &original_request)) else {
        return Ok(Reply::Error(error_response(503, "stopping", "the proxy is stopping"), true));
    };
    let mut started = Instant::now();
    let mut upstream = forward(ctx, target, &request, &method, h2).await;
    if let (Some(a), Some(p), Ok(Upstream { sent, response, .. })) = (auth, &prepared, &upstream) {
        // A re-login can outlast stopping's wait: stopping then records this answer.
        let ms = Some(started.elapsed().as_millis() as i64);
        flight.answered(Capture {
            edited_by: edited_by.clone(),
            original_request: original_request.clone(),
            ..row(target, sent, Some(response), ms, None)
        });
        // Session lost or stale session values: log in again or refresh them, and
        // replay the request with the new session.
        if a.after_response(p, response).await {
            let again = a.prepare(Tool::Proxy, target, &request, &[], &[]).await;
            let edits = if again.request != request { a.edits(&again) } else { Vec::new() };
            let retry = again.request;
            // Not once the proxy is stopping: then the first answer stands.
            if let Some(next) = ctx.in_flight.start(unanswered(&retry, &edited_by, &original_request)) {
                // The first exchange went out and was answered: it has its own row.
                if flight.claim() {
                    let ms = Some(started.elapsed().as_millis() as i64);
                    let c = row(target, sent, Some(response), ms, None);
                    let original_request = original_request.clone();
                    send_capture(ctx, Capture { edited_by: edited_by.clone(), original_request, ..c }, None).await;
                }
                flight = next;
                request = retry;
                for e in edits {
                    if !edited_by.contains(&e) {
                        edited_by.push(e);
                    }
                }
                started = Instant::now();
                upstream = forward(ctx, target, &request, &method, h2).await;
                if let Ok(up) = &upstream {
                    a.observe(&up.response);
                }
            }
        }
    }
    let Upstream { conn, sent, response, body } = match upstream {
        Ok(v) => v,
        Err(e) => {
            ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
            // A request outside both scopes was refused before it went out: no row, as before.
            let refused = omit.is_some() && matches!(e, Error::OutOfScope(_));
            if !refused && flight.claim() {
                let mut c = row(target, &request, None, None, Some(&e.to_string()));
                c.edited_by = edited_by;
                c.original_request = original_request;
                send_capture(ctx, c, None).await;
            }
            let status = if matches!(e, Error::OutOfScope(_)) { 403 } else { 502 };
            return Ok(Reply::Error(error_response(status, e.kind(), &e.to_string()), false));
        }
    };
    let duration = started.elapsed().as_millis() as i64;
    let status = parse_response_head(final_response(&response)).ok().map(|h| h.status);
    // Not recorded again if stopping has already recorded it as unanswered.
    let mut capture = flight.claim().then(|| Capture {
        edited_by,
        original_request,
        ..row(target, &sent, Some(&response), Some(duration), None)
    });
    if status == Some(101) {
        // Outside the recording scope the upgrade's row is all that is kept: no messages.
        if omit.is_some() {
            if let Some(c) = capture.take() {
                send_capture(ctx, c, None).await;
            }
        }
        // In flight until its connection's opening is queued.
        let flight = Some(flight);
        let handshake = (target.clone(), sent);
        let upgrade =
            Upgrade { response, conn, capture, flight, in_scope, host: target.host.clone(), path, url, handshake };
        return Ok(Reply::Upgrade(Box::new(upgrade)));
    }
    if let Some(body) = body {
        // An event stream: relayed as it arrives, so only what applies to a head applies to it.
        let ruled = match in_scope {
            true => live.rules.response_head(Engine::Proxy, &target.host, response.clone()),
            false => crate::rules::Ruled { bytes: response.clone(), ..Default::default() },
        };
        live.rule_failures.note(Engine::Proxy, &ruled.failed);
        // The row keeps the head as received, and beside it what the header rules made of it.
        if let Some(c) = capture.as_mut().filter(|_| ruled.changed()) {
            c.modified_response = Some(ruled.bytes.clone());
            c.response_edits = ruled.edits();
        }
        let head = ruled.bytes;
        let open = match capture {
            // Outside the recording scope the row is all that is kept: no events.
            Some(c) if omit.is_some() => {
                send_capture(ctx, c, None).await;
                None
            }
            Some(c) => match parse_response_head(final_response(&response)) {
                Ok(parsed) => {
                    let open = Arc::new(OpenStream {
                        key: ctx.sse_keys.fetch_add(1, Ordering::Relaxed),
                        target: target.clone(),
                        sent,
                        head: response,
                        started,
                        edited_by: c.edited_by.clone(),
                        client_addr: c.client_addr.clone(),
                        state: Mutex::new(StreamState {
                            recorder: crate::sse::Recorder::new(&parsed),
                            unrecorded: 0,
                            noted: None,
                            closed: false,
                        }),
                    });
                    let bytes = capture_bytes(&c);
                    let record =
                        SseRecord::Open { key: open.key, capture: Box::new(c), url, time: crate::ws::now_iso() };
                    ctx.recorder.send(Record::Sse(record), bytes).await;
                    // Tracked before the request stops being in flight, so stopping closes it.
                    if ctx.in_flight.add_stream(open.clone()) {
                        Some(open)
                    } else {
                        // Stopping has closed the streams already: this one is relayed, not recorded.
                        open.close(ctx, "stopped", Some(STREAM_OPEN.into())).await;
                        None
                    }
                }
                Err(_) => {
                    send_capture(ctx, c, None).await;
                    None
                }
            },
            None => None,
        };
        drop(flight);
        return Ok(Reply::Stream(Box::new(StreamReply { head, body, open })));
    }
    // The row keeps the response as received, and beside it what the rules made of it.
    let ruled = match in_scope {
        true => live.rules.response(Engine::Proxy, &target.host, &sent, response),
        false => crate::rules::Ruled { bytes: response, ..Default::default() },
    };
    live.rule_failures.note(Engine::Proxy, &ruled.failed);
    // Whether intercept holds the response. The filter sees the request that went out and the
    // response the client would get: the row's own exchange when no rule changed the response.
    let held = in_scope
        && live.intercept.matches(true, &method, &target.host, &path, || {
            match capture.as_ref().filter(|_| !ruled.changed()) {
                Some(c) => Cow::Borrowed(c),
                None => Cow::Owned(Capture::new("proxy", target, &sent, Some(&ruled.bytes), Some(duration), None)),
            }
        });
    if let Some(mut c) = capture {
        if ruled.changed() {
            c.modified_response = Some(ruled.bytes.clone());
            c.response_edits = ruled.edits();
        }
        // Live access-control testing gets the in-scope requests, as sent.
        let authz = (in_scope && ctx.authz.is_some()).then(|| (target.clone(), sent.clone()));
        send_capture(ctx, c, authz).await;
    }
    // Recorded: stopping needn't wait for a response held in intercept.
    drop(flight);
    let received = ruled.original.as_deref().unwrap_or(&ruled.bytes);
    if let Some(conn) = conn.filter(|_| !close_after(&sent, received, &method)) {
        ctx.client.checkin(target, conn);
    }

    let mut response = ruled.bytes;
    if held {
        match hold(ctx, &live.intercept, "response", &method, &url, status, response.clone()).await? {
            // The exchange is recorded as received; the intercept row says who edited the response.
            Some(released) => response = released.message,
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
    let Upgrade { response, conn, capture, flight, in_scope, host, path, url, handshake } = upgrade;
    let Some(mut conn) = conn else {
        if let Some(c) = capture {
            send_capture(ctx, c, None).await;
        }
        return Ok(());
    };
    let from_server = std::mem::take(&mut conn.reader).into_leftover();
    // After any 1xx interim responses (103 Early Hints).
    let head = parse_response_head(final_response(&response)).ok().filter(crate::ws::is_upgrade_response);
    let Some(head) = head else {
        if let Some(c) = capture {
            send_capture(ctx, c, None).await;
        }
        drop(flight);
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
    drop(flight);
    let hooks = WsHooks {
        ctx: ctx.clone(),
        key,
        recording,
        in_scope,
        host,
        path,
        url,
        handshake,
        filtered: Mutex::new(None),
        unrecorded: AtomicU64::new(0),
    };
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
    /// The upgrade request as sent: the intercept's filter matches messages by it.
    handshake: (Target, Vec<u8>),
    /// The filter last asked about the handshake and its answer, until the settings change.
    filtered: Mutex<Option<(Arc<Matcher>, bool)>>,
}

impl WsHooks {
    /// Whether the handshake request matches the intercept's filter `m`, worked out once per
    /// filter rather than for every message.
    fn handshake_matches(&self, m: &Arc<Matcher>) -> bool {
        let (target, request) = &self.handshake;
        let ask = || filter_matches(m, &Capture::new("proxy", target, request, None, None, None));
        // A query on `time` may answer differently from one message to the next.
        if !m.is_steady() {
            return ask();
        }
        let mut cached = self.filtered.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, hit)) = cached.as_ref().filter(|(seen, _)| Arc::ptr_eq(seen, m)) {
            return *hit;
        }
        let hit = ask();
        *cached = Some((m.clone(), hit));
        hit
    }
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
        self.in_scope
            && live(&self.ctx).intercept.matches_ws(direction, &self.host, &self.path, |m| self.handshake_matches(m))
    }

    fn rewrite(&self, direction: Direction, message: &Message) -> Option<Vec<u8>> {
        if !self.in_scope {
            return None;
        }
        let engine = match direction {
            Direction::ToServer => Engine::WsToServer,
            Direction::ToClient => Engine::WsToClient,
        };
        let live = live(&self.ctx);
        if !live.rules.rewrites_ws(engine, &self.host) {
            return None;
        }
        let ruled = live.rules.ws_message(engine, &self.host, &message.payload);
        live.rule_failures.note(engine, &ruled.failed);
        ruled.changed().then_some(ruled.bytes)
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
        match held.map(|r| r.map(|r| r.message)) {
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
/// the request as sent (the recorded form), and the response. For an event stream the
/// response is its head, and `body` what is still arriving.
struct Upstream {
    conn: Option<Conn>,
    sent: Vec<u8>,
    response: Vec<u8>,
    body: Option<LiveBody>,
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
        match ctx.client.send_live(&RawRequest::from_bytes(request.to_vec()), target).await {
            Ok((ex, body)) => {
                ctx.h2_origins.lock().unwrap().insert(origin, true);
                return Ok(Upstream { conn: None, sent: ex.request, response: ex.response, body });
            }
            Err(e) if e.to_string().contains("did not negotiate HTTP/2") => {
                ctx.h2_origins.lock().unwrap().insert(origin, false);
            }
            Err(e) => return Err(e),
        }
    }
    let request = if h2 { h2p::to_http1(request) } else { request.to_vec() };
    let timeout = ctx.client.options().timeout;
    // For an event stream the time allowed is the time to its head.
    let (conn, response) = tokio::time::timeout(timeout, ctx.client.exchange_live(&request, target, method))
        .await
        .map_err(|_| Error::Timeout(timeout))??;
    if conn.live.is_some() {
        return Ok(Upstream { conn: None, sent: request, response, body: LiveBody::of(conn) });
    }
    Ok(Upstream { conn: Some(conn), sent: request, response, body: None })
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
                let _ = ctx.control.lock().unwrap().intercept_resolve(id, "dropped", None, None);
            });
        }
    }
}

/// A held message once it may go on: as forwarded, and who edited it, if anyone did.
struct Released {
    message: Vec<u8>,
    edit: Option<Edit>,
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
) -> Result<Option<Released>> {
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
        let held = tokio::task::spawn_blocking(move || c.control.lock().unwrap().intercept_state(id))
            .await
            .map_err(|e| Error::Protocol(e.to_string()))??;
        match held.state.as_str() {
            "forwarded" => {
                row.decided = true;
                // A replacement identical to the message as held is no edit.
                let edit = held.edited.as_ref().filter(|e| **e != message).map(|_| Edit {
                    by: held.resolved_by.clone(),
                    intercept: Some(id),
                    ..Default::default()
                });
                return Ok(Some(Released { message: held.edited.unwrap_or(message), edit }));
            }
            "dropped" => {
                row.decided = true;
                return Ok(None);
            }
            _ if Instant::now() >= deadline => {
                let c = ctx.clone();
                // The CLI may resolve it at the same moment; whoever wins decides.
                let expired = tokio::task::spawn_blocking(move || {
                    c.control.lock().unwrap().intercept_resolve(id, "expired", None, None)
                })
                .await
                .map_err(|e| Error::Protocol(e.to_string()))?;
                if expired.is_err() {
                    continue;
                }
                row.decided = true;
                return Ok(match intercept.settings.timeout_action {
                    TimeoutAction::Forward => Some(Released { message, edit: None }),
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
        + c.original_request.as_ref().map_or(0, Vec::len)
        + c.modified_response.as_ref().map_or(0, Vec::len)
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
        503 => "Service Unavailable",
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
