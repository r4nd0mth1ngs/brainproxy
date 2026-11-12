//! A raw HTTP/1.x client: writes the request bytes as-is and reads one response.
//!
//! Connections are kept alive and reused when both the request and the
//! response allow it. The pool belongs to one `Client` (shared by its clones),
//! whose options, guard included, never change; every pooled connection was
//! opened by [`Client::connect`] for the same scheme, host, and port, so reuse
//! never skips a scope decision.
//!
//! The guard's connection options apply to every connection: host overrides
//! (through [`Guard::resolve`]), upstream proxies, client certificates, and
//! platform authentication (answering 401 challenges). Their generation is part of
//! the pool key, so a running proxy that reloads them opens new connections.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::connection::{ClientIdentity, Compiled, PlatformCred, PlatformScheme, Route};
use crate::error::{Error, Result};
use crate::guard::Guard;
use crate::http::h2::{setup_error, H2Request};
use crate::http::request::RawRequest;
use crate::http::response::parse_response_head;
use crate::http::target::Target;
use crate::http::wire::{LiveFraming, Piece, WireReader};

/// What a client does with a request whose Host header (or request target) names a host the
/// scope doesn't list by name, which a shared front end may send to a site outside the scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPolicy {
    /// Refuse it: an agent's request that doesn't say it is a Host-header test.
    Refuse,
    /// Send it, and note the host (see [`Client::first_foreign_host`]) for the command to warn about.
    Warn,
    /// Send it unremarked: a scan rule's Host-header probe, a proxied client's own request.
    Allow,
}

impl HostPolicy {
    /// Refuse under an MCP tool call unless `test` (`--host-header-test`) says it is meant;
    /// warn otherwise.
    pub fn for_process(test: bool) -> Self {
        if crate::provenance::origin() == "mcp" && !test {
            Self::Refuse
        } else {
            Self::Warn
        }
    }
}

#[derive(Debug, Clone)]
pub struct SendOptions {
    pub timeout: Duration,
    /// Verify the server's TLS certificate. Off by default, as in most
    /// intercepting proxies: test targets often use self-signed certificates.
    pub verify_tls: bool,
    /// Override the TLS SNI name (defaults to the target host).
    pub sni: Option<String>,
    /// Scope every connection must pass. Without one, nothing is sent.
    pub guard: Option<Arc<Guard>>,
    /// Send over HTTP/2 (ALPN `h2` for https, prior knowledge for http).
    pub http2: bool,
    /// Send over HTTP/3 (QUIC, ALPN `h3`) when the target offers it, to its own UDP port or the
    /// endpoint its `Alt-Svc` header named; else over TCP as `http2` says (see
    /// [`Client::h3_note`]).
    pub http3: bool,
    /// What to do with a foreign Host, checked on every request as it goes on the wire
    /// (sessions, auth values and signers applied). Defaults to [`HostPolicy::for_process`].
    pub host: HostPolicy,
    /// How long and how much of an event stream (`text/event-stream`) [`Client::send`] reads
    /// before it stops, so no sender waits on a response that never ends.
    pub stream: crate::sse::StreamLimits,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            verify_tls: false,
            sni: None,
            guard: None,
            http2: false,
            http3: false,
            host: HostPolicy::for_process(false),
            stream: Default::default(),
        }
    }
}

impl SendOptions {
    /// Refuses a `--sni` the scope doesn't list by name, for a TLS `target` (plain HTTP sends
    /// none). Every connection checks it; a command checks it first too, before its rows, so a
    /// refused name leaves none claiming it was sent.
    pub fn check_sni(&self, target: &Target) -> Result<()> {
        // The server name picks the site on a shared front end as much as the address does, so a
        // different one must be in scope by name too: else an in-scope host on a CDN reaches any tenant.
        let Some(sni) = self.sni.as_ref().filter(|_| target.is_tls()) else { return Ok(()) };
        let guard = self.guard.as_ref().ok_or_else(|| Error::OutOfScope("no engagement scope".into()))?;
        if !sni.eq_ignore_ascii_case(&target.host) && !guard.confirms(sni, target.port) {
            return Err(Error::OutOfScope(format!(
                "--sni {sni}: a server name other than the target's must be listed by name in the scope"
            )));
        }
        Ok(())
    }

    /// The first host `request` names in place of `target`'s that the scope doesn't list by
    /// name (see [`SendOptions::foreign_hosts`]).
    pub fn foreign_host(&self, request: &[u8], target: &Target) -> Option<String> {
        self.foreign_hosts(request, target).into_iter().next()
    }

    /// The hosts `request` names in place of `target`'s that the scope doesn't list by name: in
    /// a Host header (HTTP/2 sends it as `:authority`) or a request target that isn't a path.
    /// A head servers may read differently counts too, shown as what it is: a request line
    /// that isn't three tokens with single spaces (a space in the path, an HTTP/0.9 line), a
    /// bare CR or LF, and a second request after the body its framing says.
    pub fn foreign_hosts(&self, request: &[u8], target: &Target) -> Vec<String> {
        // Like the server name, the Host picks the site on a shared front end, but the
        // connection still goes to the target, so the scope's own check never sees it.
        let (head_bytes, body) = crate::http::request::split_head_body(request);
        let head = String::from_utf8_lossy(head_bytes);
        let mut odd = Vec::new();
        if head.split("\r\n").any(|l| l.contains('\r')) {
            odd.push("(a bare CR in the head)".to_string());
        }
        // A lone LF ends a line for some servers and not others ("X: a\n\r\nHost: ...").
        if head_bytes.iter().enumerate().any(|(i, &b)| b == b'\n' && (i == 0 || head_bytes[i - 1] != b'\r')) {
            odd.push("(a bare LF in the head)".to_string());
        }
        if pipelined(&head, body) {
            odd.push("(a second request after the body)".to_string());
        }
        if ambiguous_framing(&head) {
            odd.push(
                "(a body servers may frame differently: Content-Length twice, or with Transfer-Encoding)".to_string(),
            );
        }
        let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r'));
        let line = lines.next().unwrap_or_default();
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty() || p.contains('\t')) {
            odd.push(format!("(a request line that isn't METHOD TARGET VERSION: {line:?})"));
        }
        let named_target = match parts.get(1).copied().unwrap_or_default() {
            "" | "*" => None,
            t if t.starts_with('/') => None,
            // Absolute form: its host, or the target as written when it can't be read as a URL
            // or holds a `\` (which the URL parser reads as `/`, and a server may not).
            t if t.contains("://") && !t.contains('\\') => {
                Some(Target::from_url(t).map_or_else(|_| t.to_string(), |t| t.host))
            }
            t if t.contains("://") => Some(t.to_string()),
            // Authority form (CONNECT), or anything else: the host it names, if it names one.
            t => Some(named_host(t).0),
        };
        let hosts = lines
            .take_while(|l| !l.is_empty())
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
            .map(|v| named_host(v).0);
        let listed = |name: &str| self.guard.as_ref().is_some_and(|g| g.lists_name(name, Some(target.port)));
        let mut out = odd;
        for name in named_target.into_iter().chain(hosts) {
            if !name.eq_ignore_ascii_case(&target.host) && !listed(&name) && !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }
}

/// What follows `Host NAME` in the error of a request [`Client::check_host`] refused.
const REFUSED_HOST: &str = ": a host other than the target's must be listed by name in the scope, as a shared \
     front end may send the request to that site; for a Host-header test pass --host-header-test";

/// The host a request was refused for by [`Client::check_host`], from its error, so a summary can
/// list it among the hosts outside the scope.
pub fn refused_host(e: &Error) -> Option<String> {
    let Error::OutOfScope(m) = e else { return None };
    m.strip_prefix("Host ")?.strip_suffix(REFUSED_HOST).map(str::to_string)
}

/// Whether bytes follow the body `head`'s framing says, starting with what reads as a request
/// line: a server keeping the connection open answers it as a request of its own.
fn pipelined(head: &str, body: &[u8]) -> bool {
    let header = |n: &str| {
        head.split('\n')
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(n))
            .map(|(_, v)| v.trim().to_ascii_lowercase())
    };
    let framed = match (header("transfer-encoding"), header("content-length")) {
        (Some(te), _) if te.ends_with("chunked") => chunked_len(body),
        (_, Some(cl)) => cl.parse::<usize>().ok().map(|n| n.min(body.len())),
        _ => Some(0),
    };
    let Some(rest) = framed.and_then(|n| body.get(n..)) else { return false };
    let rest = String::from_utf8_lossy(rest);
    let line = rest.trim_start_matches(['\r', '\n']).split('\n').next().unwrap_or_default();
    let parts: Vec<&str> = line.trim_end_matches('\r').split_whitespace().collect();
    // Servers match methods and versions case-insensitively often enough (`Get`, `http/1.1`).
    parts.len() >= 2
        && parts[0].bytes().all(|b| b.is_ascii_alphabetic())
        && parts.last().is_some_and(|v| v.to_ascii_uppercase().starts_with("HTTP/"))
}

/// Whether servers may disagree on where `head`'s body ends: Content-Length headers that
/// differ, or Content-Length with Transfer-Encoding. Either can hide a second request in the
/// body (request smuggling) that [`pipelined`] can't see.
fn ambiguous_framing(head: &str) -> bool {
    let values = |n: &str| -> Vec<String> {
        head.split('\n')
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case(n))
            .map(|(_, v)| v.trim().to_string())
            .collect()
    };
    let lengths = values("content-length");
    let differ = lengths.iter().any(|l| l != &lengths[0]);
    differ || (!lengths.is_empty() && !values("transfer-encoding").is_empty())
}

/// The host a Host header's value names, and its port when it gives one. A value that isn't
/// plainly a `host[:port]` (a placeholder, a regex group reference) is given as it is, and is
/// never in scope.
fn named_host(value: &str) -> (String, Option<u16>) {
    let plain = value.chars().all(|c| c.is_ascii_alphanumeric() || ".-_:[]".contains(c));
    let parsed = plain.then(|| url::Url::parse(&format!("http://{value}")).ok()).flatten();
    match parsed.as_ref().and_then(|u| u.host_str().map(|h| (h, u.port()))) {
        Some((host, port)) => (host.trim_start_matches('[').trim_end_matches(']').to_string(), port),
        None => (value.to_string(), None),
    }
}

/// The host `value` names when the scope doesn't list it by name, for a setting that puts it
/// in the Host header of requests still to come (an auth profile's header, a proxy rule's),
/// whatever their target. Without a port, a name listed on any port will do.
pub fn unlisted_host(guard: Option<&Guard>, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (name, port) = named_host(value);
    // The URL parser drops a scheme's default port; it still counts as the one given.
    let given = port.or_else(|| value.rsplit_once(':').and_then(|(_, p)| p.parse().ok()));
    (!guard.is_some_and(|g| g.lists_name(&name, given))).then_some(name)
}

/// A completed round trip.
#[derive(Debug, Clone, Serialize)]
pub struct Exchange {
    pub target: Target,
    #[serde(skip)]
    pub request: Vec<u8>,
    #[serde(skip)]
    pub response: Vec<u8>,
    pub duration_ms: u64,
    /// The TLS server name sent in place of the target's host, recorded with the exchange
    /// (see [`Client::sni`]).
    #[serde(skip)]
    pub sni: Option<String>,
    /// The response was an event stream, read for a bounded time: its events and why reading
    /// stopped. The response holds the body as far as it was read.
    #[serde(skip)]
    pub stream: Option<crate::sse::StreamRead>,
}

/// Idle connections kept per target, and how long one may sit unused.
const POOL_PER_TARGET: usize = 64;
const POOL_IDLE: Duration = Duration::from_secs(30);
/// Longest idle time of a pooled connection a request that must not be repeated may use:
/// such a request isn't retried, and servers often close idle connections after 5 s.
const POOL_IDLE_UNSAFE: Duration = Duration::from_secs(2);

/// An open connection with the reader that holds its unread bytes.
pub struct Conn {
    pub stream: Stream,
    pub reader: WireReader,
    /// Whether it came from the pool (so a failure may just mean the server
    /// closed it while idle).
    pub reused: bool,
    /// The generation of the connection options it was opened with; it isn't
    /// pooled again once they change.
    pub generation: u64,
    /// The response just read was left open (an event stream read with
    /// [`Client::exchange_live`]): how the body still to come is framed.
    pub live: Option<LiveFraming>,
}

/// The body of a response left open, an event stream, read as it arrives. Dropping it ends
/// the exchange: an HTTP/1 connection closes, an HTTP/2 stream is reset.
pub enum LiveBody {
    H1 { conn: Box<Conn>, framing: LiveFraming },
    H2(h2::RecvStream),
    H3(Box<crate::http::h3::Body>),
}

impl LiveBody {
    /// The connection of an [`Client::exchange_live`] whose response was left open.
    pub fn of(mut conn: Conn) -> Option<Self> {
        let framing = conn.live.take()?;
        Some(Self::H1 { conn: Box::new(conn), framing })
    }

    /// The next piece of the body, as soon as any has arrived; `None` once it is over.
    pub async fn next(&mut self) -> Result<Option<Piece>> {
        match self {
            Self::H1 { conn, framing } => conn.reader.next_piece(&mut conn.stream, framing).await,
            Self::H2(body) => match body.data().await {
                None => Ok(None),
                Some(Err(e)) => Err(crate::http::h2::h2_error(e)),
                Some(Ok(chunk)) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    Ok(Some(Piece::plain(chunk.to_vec())))
                }
            },
            Self::H3(body) => Ok(crate::http::h3::next_piece(body).await?.map(Piece::plain)),
        }
    }
}

/// `req` as it goes over TCP: a request line saying `HTTP/3` says `HTTP/2` with `http2`, else
/// `HTTP/1.1`. HTTP/3's text form has no framing of its own (a chunked body was de-chunked), so
/// a body without Content-Length or Transfer-Encoding gets a Content-Length for HTTP/1.1.
pub fn tcp_form(req: &RawRequest, http2: bool) -> std::borrow::Cow<'_, RawRequest> {
    use std::borrow::Cow;
    let Ok(head) = req.head() else { return Cow::Borrowed(req) };
    if !head.version.eq_ignore_ascii_case("HTTP/3") {
        return Cow::Borrowed(req);
    }
    let bytes = req.as_bytes();
    let end = bytes.iter().position(|&b| b == b'\n').unwrap_or(bytes.len());
    let line = String::from_utf8_lossy(&bytes[..end]);
    let cr = line.ends_with('\r');
    let line = line.trim_end_matches('\r');
    let Some((start, _)) = line.rsplit_once(' ') else { return Cow::Borrowed(req) };
    let version = if http2 { "HTTP/2" } else { "HTTP/1.1" };
    let mut out = format!("{start} {version}{}", if cr { "\r" } else { "" }).into_bytes();
    out.extend_from_slice(&bytes[end..]);
    let framed = head
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("transfer-encoding"));
    let body_len = req.split().1.len();
    if !http2 && !framed && body_len > 0 {
        out = with_header(&out, "Content-Length", &body_len.to_string());
    }
    Cow::Owned(RawRequest::from_bytes(out))
}

/// How long a QUIC handshake may take before HTTP/3 counts as not offered (or UDP blocked).
const H3_HANDSHAKE: Duration = Duration::from_secs(3);
/// How many notes about HTTP/3 a client keeps (see [`Client::h3_notes`]).
const H3_NOTES: usize = 8;
/// How long an origin HTTP/3 failed for goes straight to TCP.
const H3_DOWN: Duration = Duration::from_secs(300);

/// The multiplexed connection a request goes on.
#[derive(Clone, Copy)]
enum Mux<'a> {
    /// The pooled HTTP/2 connection to the target (opened if there is none).
    H2,
    H3(&'a crate::http::h3::Conn),
}

/// What [`Client::send_h3`] did.
enum H3 {
    /// Sent: the response, and an event stream's body left open.
    Sent(Vec<u8>, Option<LiveBody>),
    /// Not sent, for this reason: the request goes over TCP.
    NotUsed(String),
}

/// Sockets belong to the runtime that opened them (auth logs in on a short-lived
/// one), so the runtime is part of the key, and so is the generation of the
/// connection options they were opened with.
type PoolKey = (tokio::runtime::Id, u64, String, String, u16);

/// What platform authentication learned about an origin, so later requests carry
/// the header from the start instead of waiting for a 401 each time.
enum Learned {
    Basic,
    Digest(crate::connection::platform::DigestChallenge, u32),
}

/// A host and port.
type HostPort = (String, u16);

#[derive(Default)]
struct Pool {
    idle: Mutex<HashMap<PoolKey, Vec<(Stream, Instant)>>>,
    /// One multiplexed HTTP/2 connection per key.
    h2: Mutex<HashMap<PoolKey, h2::client::SendRequest<bytes::Bytes>>>,
    h2_connecting: tokio::sync::Mutex<()>,
    opened: std::sync::atomic::AtomicU64,
    /// TLS configurations with a client certificate: (generation, certificate index, h2).
    cert_tls: Mutex<HashMap<(u64, usize, bool), TlsConnector>>,
    /// Keyed by generation and origin.
    learned: Mutex<HashMap<(u64, String), Learned>>,
    /// The latest generation seen; entries of older ones are dropped when it changes.
    generation: std::sync::atomic::AtomicU64,
    /// The first foreign host sent under [`HostPolicy::Warn`]: only it is reported.
    foreign: std::sync::OnceLock<String>,
    /// One HTTP/3 connection per key.
    h3: Mutex<HashMap<PoolKey, crate::http::h3::Conn>>,
    /// One handshake at a time per key, so concurrent senders share a connection while
    /// handshakes to other origins (which may wait for an answer that never comes) go ahead.
    h3_connecting: Mutex<HashMap<PoolKey, Arc<tokio::sync::Mutex<()>>>>,
    /// HTTP/3 endpoints origins advertised (`Alt-Svc`), keyed by generation and origin, with
    /// when they expire. Each must pass the guard like any other destination before it's used.
    alt_svc: Mutex<HashMap<(u64, String), (crate::http::h3::AltSvc, Instant)>>,
    /// Origins HTTP/3 just failed for, keyed by generation and origin, with until when and why:
    /// meanwhile their requests go straight to TCP instead of waiting for a handshake each.
    h3_down: Mutex<HashMap<(u64, String), (Instant, String)>>,
    /// Alt-Svc endpoints (host and port) the guard refused, keyed by generation and origin: an
    /// origin that keeps advertising one doesn't make it new again (which would turn HTTP/3
    /// back on for an origin it just failed for, on every response).
    alt_svc_refused: Mutex<HashMap<(u64, String), Vec<HostPort>>>,
    /// What to say about HTTP/3 asked for: why it wasn't used, or an Alt-Svc endpoint the
    /// scope refused. Each once, and the first few only.
    h3_notes: Mutex<Vec<String>>,
}

#[derive(Clone)]
pub struct Client {
    tls: TlsConnector,
    tls_h2: TlsConnector,
    opts: SendOptions,
    pool: Arc<Pool>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("opts", &self.opts).finish_non_exhaustive()
    }
}

/// A TLS client configuration offering `alpn`, verifying certificates or not, and
/// presenting `identity` when given.
pub(crate) fn tls_config(verify: bool, alpn: &[u8], identity: Option<&ClientIdentity>) -> Result<ClientConfig> {
    let builder = if verify {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        ClientConfig::builder().with_root_certificates(roots)
    } else {
        ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(NoVerify))
    };
    let mut config = match identity {
        None => builder.with_no_client_auth(),
        Some(id) => builder
            .with_client_auth_cert(id.chain.clone(), id.key()?)
            .map_err(|e| Error::Tls(format!("client certificate: {e}")))?,
    };
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

impl Client {
    pub fn new(opts: SendOptions) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = tls_config(opts.verify_tls, b"http/1.1", None).expect("TLS configuration without a certificate");
        let h2_config = tls_config(opts.verify_tls, b"h2", None).expect("TLS configuration without a certificate");
        Self {
            tls: TlsConnector::from(Arc::new(config)),
            tls_h2: TlsConnector::from(Arc::new(h2_config)),
            opts,
            pool: Arc::default(),
        }
    }

    /// The connection options in force (none without a guard). When they have
    /// changed, pooled connections, TLS configurations, and learned platform auth
    /// of older generations are dropped.
    fn net(&self) -> Arc<Compiled> {
        let net = self.opts.guard.as_ref().map(|g| g.net.get()).unwrap_or_default();
        let gen = net.generation;
        if self.pool.generation.swap(gen, std::sync::atomic::Ordering::Relaxed) != gen {
            self.pool.idle.lock().unwrap().retain(|k, _| k.1 == gen);
            self.pool.h2.lock().unwrap().retain(|k, _| k.1 == gen);
            self.pool.cert_tls.lock().unwrap().retain(|k, _| k.0 == gen);
            self.pool.learned.lock().unwrap().retain(|k, _| k.0 == gen);
            self.pool.h3.lock().unwrap().retain(|k, _| k.1 == gen);
            self.pool.alt_svc.lock().unwrap().retain(|k, _| k.0 == gen);
            self.pool.h3_down.lock().unwrap().retain(|k, _| k.0 == gen);
            self.pool.alt_svc_refused.lock().unwrap().retain(|k, _| k.0 == gen);
            self.pool.h3_connecting.lock().unwrap().retain(|k, _| k.1 == gen);
        }
        net
    }

    fn pool_key(&self, target: &Target, generation: u64) -> PoolKey {
        let rt = tokio::runtime::Handle::current().id();
        (rt, generation, target.scheme.to_ascii_lowercase(), target.host.to_ascii_lowercase(), target.port)
    }

    /// A new connection, opened with the options in force now.
    async fn fresh(&self, target: &Target) -> Result<Conn> {
        let net = self.net();
        let stream = self.connect_with(target, &net).await?;
        Ok(Conn { stream, reader: WireReader::new(), reused: false, generation: net.generation, live: None })
    }

    pub fn options(&self) -> &SendOptions {
        &self.opts
    }

    /// The server name this client sends to `target` in place of its host (`--sni`), which
    /// the target's history rows record. See [`sent_sni`].
    pub fn sni(&self, target: &Target) -> Option<String> {
        sent_sni(self.opts.sni.as_deref(), target)
    }

    /// The first host outside the scope this client (and its clones) has put in a Host header
    /// or request target (see [`SendOptions::foreign_hosts`]), for a command to warn about.
    pub fn first_foreign_host(&self) -> Option<String> {
        self.pool.foreign.get().cloned()
    }

    /// Applies the Host policy to `bytes` as they go on the wire to `target`: every request
    /// passes here, after sessions, auth values and signers changed it, so none brings in a
    /// Host the check didn't see.
    pub fn check_host(&self, bytes: &[u8], target: &Target) -> Result<()> {
        if self.opts.host == HostPolicy::Allow {
            return Ok(());
        }
        let hosts = self.opts.foreign_hosts(bytes, target);
        let Some(first) = hosts.first() else { return Ok(()) };
        if self.opts.host == HostPolicy::Refuse {
            return Err(Error::OutOfScope(format!("Host {first}{REFUSED_HOST}")));
        }
        let _ = self.pool.foreign.set(first.clone());
        Ok(())
    }

    /// Connections opened so far (pooled reuse doesn't count).
    pub fn connections_opened(&self) -> u64 {
        self.pool.opened.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// A pooled connection to `target` idle for less than `max_idle`, or a new one from
    /// [`Client::connect`].
    pub async fn checkout(&self, target: &Target, max_idle: Duration) -> Result<Conn> {
        let generation = self.net().generation;
        let key = self.pool_key(target, generation);
        let pooled = {
            let mut idle = self.pool.idle.lock().unwrap();
            let list = idle.entry(key).or_default();
            list.retain(|(_, at)| at.elapsed() < POOL_IDLE);
            // The last one is the most recently used.
            list.pop_if(|(_, at)| at.elapsed() < max_idle)
        };
        if let Some((stream, _)) = pooled {
            return Ok(Conn { stream, reader: WireReader::new(), reused: true, generation, live: None });
        }
        self.fresh(target).await
    }

    /// Returns a connection to the pool after a complete exchange. Connections
    /// with unread bytes (a desynchronised server) are dropped.
    /// Connections opened with connection options that have since changed are dropped too.
    pub fn checkin(&self, target: &Target, conn: Conn) {
        if !conn.reader.is_empty() || conn.live.is_some() || conn.generation != self.net().generation {
            return;
        }
        let mut idle = self.pool.idle.lock().unwrap();
        let list = idle.entry(self.pool_key(target, conn.generation)).or_default();
        if list.len() < POOL_PER_TARGET {
            list.push((conn.stream, Instant::now()));
        }
    }

    /// The bytes to put on the wire: auth placeholders replaced with their values
    /// from the guard's vault. Callers record the original bytes. Signing can block (a
    /// script runs for up to its time limit, a key is read from a file, an RSA signature
    /// takes a while), so a request a signer fills is filled on the blocking pool.
    pub async fn fill_auth<'a>(&self, bytes: &'a [u8], target: &Target) -> Result<std::borrow::Cow<'a, [u8]>> {
        let Some(g) = &self.opts.guard else { return Ok(std::borrow::Cow::Borrowed(bytes)) };
        if !g.vault.signs(bytes) {
            return g.vault.resolve(bytes, target);
        }
        let (guard, owned, target) = (g.clone(), bytes.to_vec(), target.clone());
        tokio::task::spawn_blocking(move || guard.vault.resolve(&owned, &target).map(|b| b.into_owned()))
            .await
            .map_err(|e| Error::Protocol(format!("signing stopped: {e}")))?
            .map(std::borrow::Cow::Owned)
    }

    /// Whether [`Client::send`] sends `req` over HTTP/2 (when it isn't sent over HTTP/3).
    fn sends_h2(&self, req: &RawRequest) -> bool {
        self.opts.http2 || req.head().is_ok_and(|h| h.version.eq_ignore_ascii_case("HTTP/2"))
    }

    /// Whether [`Client::send`] tries HTTP/3 for `req`: `http3` is set, or its request line says
    /// `HTTP/3` (a recorded HTTP/3 exchange sent again).
    pub fn tries_h3(&self, req: &RawRequest) -> bool {
        self.opts.http3 || req.head().is_ok_and(|h| h.version.eq_ignore_ascii_case("HTTP/3"))
    }

    /// What to say about HTTP/3 this client (and its clones) was asked for, for a command to
    /// warn about: why it wasn't used (the request then went over TCP), or an Alt-Svc endpoint
    /// the scope refused (it then went to the target's own address). The first few, each once.
    pub fn h3_notes(&self) -> Vec<String> {
        self.pool.h3_notes.lock().unwrap().clone()
    }

    fn h3_note(&self, note: String) {
        let mut notes = self.pool.h3_notes.lock().unwrap();
        if notes.len() < H3_NOTES && !notes.contains(&note) {
            notes.push(note);
        }
    }

    /// The request as [`Client::send`] records it (its `Exchange::request`): the bytes given,
    /// or their HTTP/2 or HTTP/3 text form; auth placeholders stay. Callers that record a
    /// request before it goes out use this, so the row matches what is sent. (When HTTP/3
    /// can't be used, the exchange holds the request as it went over TCP instead.)
    pub fn recorded_request(&self, req: &RawRequest, target: &Target) -> Result<Vec<u8>> {
        if self.tries_h3(req) && target.is_tls() {
            return Ok(H2Request::from_raw_as(req.as_bytes(), target, "HTTP/3")?.recorded);
        }
        let req = &self.over_tcp(req);
        if self.sends_h2(req) {
            return Ok(H2Request::from_raw(req.as_bytes(), target)?.recorded);
        }
        Ok(req.as_bytes().to_vec())
    }

    /// Sends `req` and reads the response. An event stream (`text/event-stream`), which may
    /// never end, is read until it ends or the options' [`crate::sse::StreamLimits`] say stop;
    /// the exchange then holds what arrived, and says so in [`Exchange::stream`].
    pub async fn send(&self, req: &RawRequest, target: &Target) -> Result<Exchange> {
        let started = Instant::now();
        let (mut ex, live) = self.send_live(req, target).await?;
        if let Some(mut body) = live {
            let head = parse_response_head(final_response(&ex.response))?;
            let (rest, read) = crate::sse::read(&head, &mut body, &self.opts.stream).await;
            ex.response.extend_from_slice(&rest);
            ex.stream = Some(read);
            ex.duration_ms = started.elapsed().as_millis() as u64;
        }
        Ok(ex)
    }

    /// [`Client::send`], except that an event stream is left open: the exchange's response is
    /// its head, and the body comes with it to read as it arrives (the proxy relays it). The
    /// timeout covers the time to the head only.
    pub async fn send_live(&self, req: &RawRequest, target: &Target) -> Result<(Exchange, Option<LiveBody>)> {
        let started = Instant::now();
        let deadline = started + self.opts.timeout;
        let wants_h3 = self.tries_h3(req);
        if wants_h3 {
            match self.send_h3(req, target, deadline).await? {
                H3::Sent(response, live) => {
                    let ex = Exchange {
                        target: target.clone(),
                        request: H2Request::from_raw_as(req.as_bytes(), target, "HTTP/3")?.recorded,
                        response,
                        duration_ms: started.elapsed().as_millis() as u64,
                        sni: self.sni(target),
                        stream: None,
                    };
                    return Ok((ex, live));
                }
                H3::NotUsed(why) => {
                    self.h3_note(format!("{}: {why}; sent over TCP", target.origin()));
                }
            }
        }
        let req = &self.over_tcp(req);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (ex, live) = tokio::time::timeout(remaining, self.send_tcp(req, target, started))
            .await
            .map_err(|_| Error::Timeout(self.opts.timeout))??;
        if wants_h3 {
            self.learn_alt_svc(target, &ex.response);
        }
        Ok((ex, live))
    }

    /// `req` as it goes over TCP (see [`tcp_form`]).
    fn over_tcp<'a>(&self, req: &'a RawRequest) -> std::borrow::Cow<'a, RawRequest> {
        tcp_form(req, self.opts.http2)
    }

    /// [`Client::send_live`] over TCP: HTTP/2 or HTTP/1.x.
    async fn send_tcp(
        &self,
        req: &RawRequest,
        target: &Target,
        started: Instant,
    ) -> Result<(Exchange, Option<LiveBody>)> {
        let method = req.head().map(|h| h.method).unwrap_or_else(|_| "GET".into());
        if self.sends_h2(req) {
            let filled = self.fill_auth(req.as_bytes(), target).await?;
            self.check_host(&filled, target)?;
            let (response, live) = self.multiplexed_auth(&filled, target, &method, Mux::H2).await?;
            let ex = Exchange {
                target: target.clone(),
                // Recorded with the auth placeholders, not the values sent.
                request: H2Request::from_raw(req.as_bytes(), target)?.recorded,
                response,
                duration_ms: started.elapsed().as_millis() as u64,
                sni: self.sni(target),
                stream: None,
            };
            return Ok((ex, live));
        }
        let (response, live) = self.round_trip(req.as_bytes(), target, &method).await?;
        let ex = Exchange {
            target: target.clone(),
            request: req.as_bytes().to_vec(),
            response,
            duration_ms: started.elapsed().as_millis() as u64,
            sni: self.sni(target),
            stream: None,
        };
        Ok((ex, live))
    }

    async fn round_trip(&self, bytes: &[u8], target: &Target, method: &str) -> Result<(Vec<u8>, Option<LiveBody>)> {
        let (conn, response) = self.exchange_live(bytes, target, method).await?;
        if conn.live.is_some() {
            return Ok((response, LiveBody::of(conn)));
        }
        if !close_after(bytes, &response, method) {
            self.checkin(target, conn);
        }
        Ok((response, None))
    }

    /// Writes `bytes` on a pooled connection when there is one and reads one
    /// response. A reused connection that fails before any response arrives
    /// was most likely closed by the server while idle, so a request that is safe to
    /// repeat (RFC 9110 9.2.2) is retried once on a new connection. Others (a POST may
    /// have been processed before the connection dropped) are not, and only take a
    /// connection that was idle briefly. The caller decides whether to
    /// [`Client::checkin`] the connection afterwards.
    ///
    /// With platform credentials for the target (and no Authorization header in
    /// the request), a 401 challenge of their scheme is answered here, NTLM's on the
    /// same connection; the response returned is the last one.
    pub async fn exchange(&self, bytes: &[u8], target: &Target, method: &str) -> Result<(Conn, Vec<u8>)> {
        self.exchange_with(bytes, target, method, false).await
    }

    /// [`Client::exchange`], except that an event stream is left open: the response returned
    /// is its head, and the connection's [`Conn::live`] says how the body still to come is
    /// framed ([`LiveBody::of`] reads it). Such a connection is never pooled.
    pub async fn exchange_live(&self, bytes: &[u8], target: &Target, method: &str) -> Result<(Conn, Vec<u8>)> {
        self.exchange_with(bytes, target, method, true).await
    }

    async fn exchange_with(&self, bytes: &[u8], target: &Target, method: &str, live: bool) -> Result<(Conn, Vec<u8>)> {
        let bytes = &*self.fill_auth(bytes, target).await?;
        self.check_host(bytes, target)?;
        match self.platform_cred(target, bytes) {
            Some(cred) => self.exchange_platform(&cred, bytes, target, method, live).await,
            None => self.exchange_once(bytes, target, method, live).await,
        }
    }

    async fn exchange_once(&self, bytes: &[u8], target: &Target, method: &str, live: bool) -> Result<(Conn, Vec<u8>)> {
        let repeatable =
            ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"].iter().any(|m| method.eq_ignore_ascii_case(m));
        let mut c = self.checkout(target, if repeatable { POOL_IDLE } else { POOL_IDLE_UNSAFE }).await?;
        loop {
            let result = async {
                c.stream.write_all(bytes).await?;
                c.stream.flush().await?;
                read_one(&mut c, method, live).await
            }
            .await;
            match result {
                Ok(response) => return Ok((c, response)),
                Err(e) if repeatable && c.reused && c.reader.is_empty() && stale(&e) => {
                    c = self.fresh(target).await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// One request and response on this connection.
    async fn on_conn(&self, mut c: Conn, bytes: &[u8], method: &str, live: bool) -> Result<(Conn, Vec<u8>)> {
        c.stream.write_all(bytes).await?;
        c.stream.flush().await?;
        let response = read_one(&mut c, method, live).await?;
        Ok((c, response))
    }

    /// Whether requests to `target` must use HTTP/1.1: its platform auth is NTLM.
    pub fn needs_http1(&self, target: &Target) -> bool {
        self.net().platform(&target.host, target.port).is_some_and(|c| c.scheme == PlatformScheme::Ntlm)
    }

    /// The platform credentials to use for this request: the target has some, and
    /// the request doesn't bring its own Authorization header.
    fn platform_cred(&self, target: &Target, bytes: &[u8]) -> Option<Arc<PlatformCred>> {
        let cred = self.net().platform(&target.host, target.port)?;
        let (head, _) = crate::http::request::split_head_body(bytes);
        let own = RawRequest::from_bytes(head.to_vec())
            .head()
            .is_ok_and(|h| h.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
        (!own).then_some(cred)
    }

    /// The Authorization value from what an earlier exchange with this origin
    /// learned (Basic, or Digest with the next nonce count).
    fn learned_header(&self, cred: &PlatformCred, target: &Target, method: &str, uri: &str) -> Result<Option<String>> {
        let key = (self.net().generation, target.origin());
        let mut learned = self.pool.learned.lock().unwrap();
        match learned.get_mut(&key) {
            Some(Learned::Basic) => cred.basic().map(Some),
            Some(Learned::Digest(ch, nc)) => {
                *nc += 1;
                cred.digest(ch, method, uri, *nc, &crate::connection::platform::cnonce()).map(Some)
            }
            None => Ok(None),
        }
    }

    fn learn(&self, target: &Target, what: Option<Learned>) {
        let key = (self.net().generation, target.origin());
        let mut learned = self.pool.learned.lock().unwrap();
        match what {
            Some(w) => learned.insert(key, w),
            None => learned.remove(&key),
        };
    }

    /// The Authorization value answering a Basic or Digest challenge in `response`.
    fn answer(
        &self,
        cred: &PlatformCred,
        response: &[u8],
        method: &str,
        uri: &str,
    ) -> Result<Option<(String, Learned)>> {
        use crate::connection::platform::{challenges, cnonce, DigestChallenge};
        let offered = challenges(response);
        Ok(match cred.scheme {
            PlatformScheme::Basic if offered.iter().any(|c| c.scheme == "basic") => {
                Some((cred.basic()?, Learned::Basic))
            }
            PlatformScheme::Digest => match DigestChallenge::pick(&offered) {
                Some(ch) => Some((cred.digest(&ch, method, uri, 1, &cnonce())?, Learned::Digest(ch, 1))),
                None => None,
            },
            _ => None,
        })
    }

    async fn exchange_platform(
        &self,
        cred: &PlatformCred,
        bytes: &[u8],
        target: &Target,
        method: &str,
        live: bool,
    ) -> Result<(Conn, Vec<u8>)> {
        let uri = request_uri(bytes);
        let mut sent = bytes.to_vec();
        if let Some(value) = self.learned_header(cred, target, method, &uri)? {
            sent = with_header(bytes, "Authorization", &value);
        }
        let (conn, response) = self.exchange_once(&sent, target, method, live).await?;
        if status(&response) != Some(401) {
            return Ok((conn, response));
        }
        self.learn(target, None);
        // The next leg goes on this connection if it stays open, else on a new one.
        let next = |conn: Conn, prev: &[u8], prev_resp: &[u8], req: Vec<u8>| {
            let reuse = !close_after(prev, prev_resp, method);
            async move {
                if reuse {
                    self.on_conn(conn, &req, method, live).await
                } else {
                    drop(conn);
                    let c = self.fresh(target).await?;
                    self.on_conn(c, &req, method, live).await
                }
            }
        };
        if cred.scheme == PlatformScheme::Ntlm {
            use crate::connection::platform::{challenges, ntlm_challenge};
            if !challenges(&response).iter().any(|c| c.scheme == "ntlm") {
                return Ok((conn, response));
            }
            // NTLM authenticates the connection: keep it open between the legs.
            let negotiate = RawRequest::from_bytes(with_header(bytes, "Authorization", &cred.ntlm_negotiate()))
                .set_header("Connection", "keep-alive")
                .into_bytes();
            let (conn, challenge) = next(conn, &sent, &response, negotiate.clone()).await?;
            let Some(msg) = ntlm_challenge(&challenges(&challenge)) else { return Ok((conn, challenge)) };
            if status(&challenge) != Some(401) || close_after(&negotiate, &challenge, method) {
                return Ok((conn, challenge));
            }
            let auth = with_header(bytes, "Authorization", &cred.ntlm_authenticate(&msg)?);
            return self.on_conn(conn, &auth, method, live).await;
        }
        let Some((value, learned)) = self.answer(cred, &response, method, &uri)? else { return Ok((conn, response)) };
        let (conn, answered) = next(conn, &sent, &response, with_header(bytes, "Authorization", &value)).await?;
        if status(&answered) != Some(401) {
            self.learn(target, Some(learned));
        }
        Ok((conn, answered))
    }

    /// [`Client::round_trip_h2`] with platform authentication (Basic and Digest:
    /// NTLM needs HTTP/1.1).
    ///
    /// With `live` an event stream's body is left open and returned beside its head.
    /// One request over HTTP/2 or HTTP/3 (`mux`), answering a Basic or Digest challenge of the
    /// target's platform credentials (NTLM needs HTTP/1.1) with a second request. An event
    /// stream's body is left open.
    async fn multiplexed_auth(
        &self,
        filled: &[u8],
        target: &Target,
        method: &str,
        mux: Mux<'_>,
    ) -> Result<(Vec<u8>, Option<LiveBody>)> {
        let send = |bytes: Vec<u8>| self.multiplexed(bytes, target, mux);
        let cred = self.platform_cred(target, filled).filter(|c| c.scheme != PlatformScheme::Ntlm);
        let Some(cred) = cred else {
            return send(filled.to_vec()).await;
        };
        let uri = request_uri(filled);
        let first = match self.learned_header(&cred, target, method, &uri)? {
            Some(value) => with_header(filled, "Authorization", &value),
            None => filled.to_vec(),
        };
        let (response, body) = send(first).await?;
        if status(&response) != Some(401) {
            return Ok((response, body));
        }
        self.learn(target, None);
        let Some((value, learned)) = self.answer(&cred, &response, method, &uri)? else { return Ok((response, body)) };
        let again = with_header(filled, "Authorization", &value);
        let (response, body) = send(again).await?;
        if status(&response) != Some(401) {
            self.learn(target, Some(learned));
        }
        Ok((response, body))
    }

    /// One request on the multiplexed connection `mux` says, its body left open if it's an event stream.
    async fn multiplexed(&self, bytes: Vec<u8>, target: &Target, mux: Mux<'_>) -> Result<(Vec<u8>, Option<LiveBody>)> {
        match mux {
            Mux::H2 => {
                let (response, body) = self.round_trip_h2(&H2Request::from_raw(&bytes, target)?, target, true).await?;
                Ok((response, body.map(LiveBody::H2)))
            }
            Mux::H3(conn) => {
                let r = H2Request::from_raw_as(&bytes, target, "HTTP/3")?;
                let (response, body) = crate::http::h3::round_trip_live(conn, &r, true).await?;
                Ok((response, body.map(|b| LiveBody::H3(Box::new(b)))))
            }
        }
    }

    /// Sends `req` over HTTP/3, or says why it can't be: then nothing was sent, and the caller
    /// sends it over TCP. Once a request has gone out over HTTP/3, a failure is an error, never
    /// a reason to send it again over TCP.
    async fn send_h3(&self, req: &RawRequest, target: &Target, deadline: Instant) -> Result<H3> {
        if !target.is_tls() {
            return Ok(H3::NotUsed("HTTP/3 needs https".into()));
        }
        let net = self.net();
        if net.platform(&target.host, target.port).is_some_and(|c| c.scheme == PlatformScheme::Ntlm) {
            return Ok(H3::NotUsed("its platform authentication (NTLM) needs HTTP/1.1".into()));
        }
        if matches!(net.route(&target.host, target.port), Route::Proxy(_)) {
            return Ok(H3::NotUsed(
                "the connection settings send it through an upstream proxy, which carries TCP only".into(),
            ));
        }
        let down_key = (net.generation, target.origin());
        if let Some(why) = self.h3_down(&down_key) {
            return Ok(H3::NotUsed(why));
        }
        let method = req.head().map(|h| h.method).unwrap_or_else(|_| "GET".into());
        let filled = self.fill_auth(req.as_bytes(), target).await?;
        self.check_host(&filled, target)?;
        // A request HTTP/3 can't carry is refused as it is, not sent another way.
        H2Request::from_raw_as(&filled, target, "HTTP/3")?;
        // Setting up (the wait for another sender's handshake, DNS, the handshakes) may take half
        // the time left at most, so a request HTTP/3 can't carry still has time to go over TCP.
        let budget = deadline.saturating_duration_since(Instant::now()) / 2;
        let setup = tokio::time::timeout(budget, self.h3_conn(target, &net, Instant::now() + budget)).await;
        let setup = setup.unwrap_or_else(|_| {
            Ok(Err(format!("no HTTP/3 connection within {} ms (half the time the request has)", budget.as_millis())))
        });
        let (conn, fresh) = match setup? {
            Ok(c) => c,
            Err(why) => {
                self.pool.h3_down.lock().unwrap().insert(down_key, (Instant::now() + H3_DOWN, why.clone()));
                return Ok(H3::NotUsed(why));
            }
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = tokio::time::timeout(remaining, self.multiplexed_auth(&filled, target, &method, Mux::H3(&conn)))
            .await
            .map_err(|_| Error::Timeout(self.opts.timeout))
            .and_then(|r| r);
        match result {
            Ok((response, live)) => {
                self.learn_alt_svc(target, &response);
                Ok(H3::Sent(response, live))
            }
            Err(e) => {
                if fresh || !conn.is_open() {
                    self.pool.h3.lock().unwrap().remove(&self.pool_key(target, net.generation));
                }
                Err(e)
            }
        }
    }

    /// Why HTTP/3 just failed for the origin `key` names, while it is still to go straight to TCP.
    fn h3_down(&self, key: &(u64, String)) -> Option<String> {
        let down = self.pool.h3_down.lock().unwrap();
        down.get(key).filter(|(until, _)| *until > Instant::now()).map(|(_, why)| why.clone())
    }

    /// The pooled HTTP/3 connection to `target` (and whether it's new), or a new one: to the
    /// HTTP/3 endpoint it advertised if the scope allows that, else to its own address. Each
    /// destination passes the guard before any datagram goes to it. `Err(why)` when none
    /// answered; nothing was sent then.
    async fn h3_conn(
        &self,
        target: &Target,
        net: &Compiled,
        deadline: Instant,
    ) -> Result<std::result::Result<(crate::http::h3::Conn, bool), String>> {
        let key = self.pool_key(target, net.generation);
        let alt_key = (net.generation, target.origin());
        // A connection to an advertised endpoint is used while the origin still advertises it
        // (not cleared, expired or replaced).
        let current = |c: &crate::http::h3::Conn| match &c.advertised {
            None => true,
            Some((host, port)) => self.pool.alt_svc.lock().unwrap().get(&alt_key).is_some_and(|(a, until)| {
                *until > Instant::now() && a.host.eq_ignore_ascii_case(host) && a.port == *port
            }),
        };
        let pooled = || {
            let mut pool = self.pool.h3.lock().unwrap();
            match pool.get(&key) {
                Some(c) if c.is_open() && current(c) => Some(c.clone()),
                Some(_) => {
                    pool.remove(&key);
                    None
                }
                None => None,
            }
        };
        if let Some(c) = pooled() {
            return Ok(Ok((c, false)));
        }
        let lock = self.pool.h3_connecting.lock().unwrap().entry(key.clone()).or_default().clone();
        let _connecting = lock.lock().await;
        if let Some(c) = pooled() {
            return Ok(Ok((c, false)));
        }
        // A sender that waited here while HTTP/3 failed for this origin doesn't try again.
        if let Some(why) = self.h3_down(&(net.generation, target.origin())) {
            return Ok(Err(why));
        }
        let guard = self.opts.guard.as_ref().ok_or_else(|| {
            Error::OutOfScope("no engagement scope: run `brainproxy engagement start --target HOST ...` first".into())
        })?;
        // A server name refused, or a client certificate that can't be loaded, fails before any datagram.
        self.server_name_for(target)?;
        let server_name = self.opts.sni.clone().unwrap_or_else(|| target.host.clone());
        let identity = match net.client_cert(&target.host, target.port) {
            Some((_, id)) if id.error.is_some() => {
                return Err(Error::Tls(format!(
                    "client certificate for {}: {}",
                    target.host,
                    id.error.as_deref().unwrap_or_default()
                )))
            }
            Some((_, id)) => Some(id),
            None => None,
        };
        let config = crate::http::h3::client_config(tls_config(
            self.opts.verify_tls,
            crate::http::h3::ALPN,
            identity.as_deref(),
        )?)?;
        let alt = self
            .pool
            .alt_svc
            .lock()
            .unwrap()
            .get(&alt_key)
            .filter(|(_, until)| *until > Instant::now())
            .map(|(a, _)| a.clone());
        let mut endpoints = Vec::new();
        if let Some(a) = alt.filter(|a| !(a.host.eq_ignore_ascii_case(&target.host) && a.port == target.port)) {
            endpoints.push((a.host, a.port, true));
        }
        endpoints.push((target.host.clone(), target.port, false));
        let mut why = Vec::new();
        for (host, port, advertised) in endpoints {
            // An advertised host the connection settings send through an upstream proxy isn't
            // reached directly either (the target's own route was checked before).
            if advertised && matches!(net.route(&host, port), Route::Proxy(_)) {
                why.push(format!("the Alt-Svc endpoint {host}:{port} goes through an upstream proxy"));
                continue;
            }
            let addrs = match guard.resolve_with(&host, port, net).await {
                Ok(a) => a,
                // An advertised endpoint is a destination of its own: refused, it's never tried.
                Err(e) if advertised => {
                    let note = format!("the Alt-Svc endpoint {host}:{port} of {} isn't used: {e}", target.origin());
                    self.h3_note(note);
                    self.pool.alt_svc.lock().unwrap().remove(&alt_key);
                    let mut refused = self.pool.alt_svc_refused.lock().unwrap();
                    let refused = refused.entry(alt_key.clone()).or_default();
                    // (A few at most: an origin advertises one endpoint at a time.)
                    if refused.len() < 16 && !refused.iter().any(|r| r.0.eq_ignore_ascii_case(&host) && r.1 == port) {
                        refused.push((host.clone(), port));
                    }
                    continue;
                }
                Err(e @ Error::OutOfScope(_)) => return Err(e),
                Err(e) => {
                    why.push(e.to_string());
                    continue;
                }
            };
            for addr in addrs {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                // (`deadline` already leaves the request time to go over TCP.)
                match crate::http::h3::connect(addr, &server_name, config.clone(), left.min(H3_HANDSHAKE)).await {
                    Ok(mut c) => {
                        if advertised {
                            // The rows name the target; this says where its datagrams went.
                            self.h3_note(format!(
                                "{}: HTTP/3 went to its Alt-Svc endpoint {host}:{port} ({addr})",
                                target.origin()
                            ));
                        }
                        c.advertised = advertised.then(|| (host.clone(), port));
                        self.pool.opened.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.pool.h3.lock().unwrap().insert(key, c.clone());
                        return Ok(Ok((c, true)));
                    }
                    Err(e) => why.push(e.to_string()),
                }
            }
        }
        Ok(Err(why.join("; ")))
    }

    /// Remembers (or forgets) the HTTP/3 endpoint `response`'s `Alt-Svc` header advertises for
    /// `target`'s origin, for later requests of this client that ask for HTTP/3.
    pub fn learn_alt_svc(&self, target: &Target, response: &[u8]) {
        if !target.is_tls() {
            return;
        }
        let Ok(head) = parse_response_head(final_response(response)) else { return };
        // The first header that says something about h3 (several Alt-Svc headers are one list).
        let Some(alt) = head
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("alt-svc"))
            .find_map(|(_, v)| crate::http::h3::parse_alt_svc(v, &target.host))
        else {
            return;
        };
        let key = (self.net().generation, target.origin());
        let mut cache = self.pool.alt_svc.lock().unwrap();
        match alt.filter(|a| !a.max_age.is_zero()) {
            // An endpoint the guard refused under these settings stays refused: it isn't
            // remembered again, nor a reason to try HTTP/3 again.
            Some(a)
                if self.pool.alt_svc_refused.lock().unwrap().get(&key).is_some_and(|r| {
                    r.iter().any(|(host, port)| a.host.eq_ignore_ascii_case(host) && a.port == *port)
                }) =>
            {
                cache.remove(&key);
            }
            Some(a) => {
                let until = Instant::now() + a.max_age.min(Duration::from_secs(86_400 * 7));
                // A new endpoint is worth a try even if the target's own address just failed.
                if cache.get(&key).is_none_or(|(old, _)| *old != a) {
                    self.pool.h3_down.lock().unwrap().remove(&key);
                }
                cache.insert(key, (a, until));
            }
            None => {
                cache.remove(&key);
            }
        }
    }

    /// Sends on the pooled HTTP/2 connection to `target`, opening one if there
    /// is none. If the pooled connection has gone away (checked before anything
    /// is sent), a new one is opened.
    async fn round_trip_h2(
        &self,
        req: &H2Request,
        target: &Target,
        live: bool,
    ) -> Result<(Vec<u8>, Option<h2::RecvStream>)> {
        let key = self.pool_key(target, self.net().generation);
        let mut fresh = false;
        let sender = match self.h2_pooled(&key).await {
            Some(s) => s,
            None => {
                // One handshake at a time, so concurrent senders share a connection.
                // One lock for all targets: handshakes to different hosts wait for each other.
                let _connecting = self.pool.h2_connecting.lock().await;
                match self.h2_pooled(&key).await {
                    Some(s) => s,
                    None => {
                        fresh = true;
                        self.h2_handshake(target).await.map_err(|e| setup_error(target, e))?
                    }
                }
            }
        };
        let result = crate::http::h2::round_trip_live(sender, req, live).await;
        if fresh && result.is_err() {
            self.pool.h2.lock().unwrap().remove(&key);
        }
        result.map_err(|e| if fresh { setup_error(target, e) } else { e })
    }

    /// The pooled HTTP/2 sender for `key`, unless its connection has closed.
    async fn h2_pooled(&self, key: &PoolKey) -> Option<h2::client::SendRequest<bytes::Bytes>> {
        let pooled = self.pool.h2.lock().unwrap().get(key).cloned()?;
        match pooled.ready().await {
            Ok(s) => Some(s),
            Err(_) => {
                self.pool.h2.lock().unwrap().remove(key);
                None
            }
        }
    }

    /// Opens an HTTP/2 connection, runs its driver task, and pools the sender.
    async fn h2_handshake(&self, target: &Target) -> Result<h2::client::SendRequest<bytes::Bytes>> {
        let net = self.net();
        let stream = self.connect_h2_with(target, &net).await?;
        let (sender, conn) = h2::client::handshake(stream).await.map_err(crate::http::h2::h2_error)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        // Pooled under the generation it was opened with: a newer one won't find it.
        self.pool.h2.lock().unwrap().insert(self.pool_key(target, net.generation), sender.clone());
        Ok(sender)
    }

    /// A connection ready for HTTP/2 framing: TLS with `h2` negotiated by ALPN
    /// for https (an error if the server picks anything else), plain TCP for
    /// http (prior knowledge). Goes through the scope guard like [`Client::connect`].
    pub async fn connect_h2(&self, target: &Target) -> Result<Stream> {
        self.connect_h2_with(target, &self.net()).await
    }

    /// [`Client::connect_h2`] with one snapshot of the connection options throughout.
    async fn connect_h2_with(&self, target: &Target, net: &Compiled) -> Result<Stream> {
        if !target.is_tls() {
            return Ok(Box::new(self.connect_tcp(target, net).await?));
        }
        let connector = self.connector(true, target, net)?;
        let name = self.server_name_for(target)?;
        let tcp = self.connect_tcp(target, net).await?;
        let refused = || Error::Protocol(format!("{}:{} did not negotiate HTTP/2 (ALPN h2)", target.host, target.port));
        let tls = self.tls_handshake(&connector, tcp, name).await.map_err(|e| match e {
            Error::Tls(m) if m.contains("NoApplicationProtocol") => refused(),
            e => e,
        })?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(refused());
        }
        Ok(Box::new(tls))
    }

    /// Opens a connection to the target, wrapped in TLS for https. The target
    /// must pass the scope guard; the connection goes to an address the guard
    /// checked.
    pub async fn connect(&self, target: &Target) -> Result<Stream> {
        self.connect_with(target, &self.net()).await
    }

    /// [`Client::connect`] with one snapshot of the connection options throughout
    /// (address, route, and certificate all from the same generation).
    async fn connect_with(&self, target: &Target, net: &Compiled) -> Result<Stream> {
        if !target.is_tls() {
            return Ok(Box::new(self.connect_tcp(target, net).await?));
        }
        // A client certificate that can't be loaded, or a server name refused, fails before any
        // connection.
        let connector = self.connector(false, target, net)?;
        let name = self.server_name_for(target)?;
        let tcp = self.connect_tcp(target, net).await?;
        Ok(Box::new(self.tls_handshake(&connector, tcp, name).await?))
    }

    /// The TLS configuration for `target`: with the client certificate its host
    /// pattern asks for, if any.
    fn connector(&self, h2: bool, target: &Target, net: &Compiled) -> Result<TlsConnector> {
        let Some((index, identity)) = net.client_cert(&target.host, target.port) else {
            return Ok(if h2 { self.tls_h2.clone() } else { self.tls.clone() });
        };
        if let Some(e) = &identity.error {
            return Err(Error::Tls(format!("client certificate for {}: {e}", target.host)));
        }
        let key = (net.generation, index, h2);
        if let Some(c) = self.pool.cert_tls.lock().unwrap().get(&key) {
            return Ok(c.clone());
        }
        let alpn: &[u8] = if h2 { b"h2" } else { b"http/1.1" };
        let connector = TlsConnector::from(Arc::new(tls_config(self.opts.verify_tls, alpn, Some(&identity))?));
        self.pool.cert_tls.lock().unwrap().insert(key, connector.clone());
        Ok(connector)
    }

    /// The TLS server name for `target`: its host, or the `--sni` override once the scope
    /// allows it. Checked before the connection opens, so a refused name opens none.
    fn server_name_for(&self, target: &Target) -> Result<ServerName<'static>> {
        self.check_sni(target)?;
        server_name(self.opts.sni.as_deref().unwrap_or(&target.host))
    }

    /// See [`SendOptions::check_sni`].
    pub fn check_sni(&self, target: &Target) -> Result<()> {
        self.opts.check_sni(target)
    }

    async fn tls_handshake(
        &self,
        connector: &TlsConnector,
        tcp: TcpStream,
        name: ServerName<'static>,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        connector.connect(name, tcp).await.map_err(|e| Error::Tls(e.to_string()))
    }

    /// The only place sockets to targets are opened: resolves through the scope
    /// guard and connects only to the addresses it checked, directly or through
    /// the upstream proxy the connection options pick (asked for the checked
    /// address, never the name).
    async fn connect_tcp(&self, target: &Target, net: &Compiled) -> Result<TcpStream> {
        let guard = self.opts.guard.as_ref().ok_or_else(|| {
            Error::OutOfScope("no engagement scope: run `brainproxy engagement start --target HOST ...` first".into())
        })?;
        let addrs = guard.resolve_with(&target.host, target.port, net).await?;
        let tcp = match net.route(&target.host, target.port) {
            Route::Direct => TcpStream::connect(&addrs[..])
                .await
                .map_err(|e| Error::Connect(format!("{}:{}: {e}", target.host, target.port)))?,
            Route::Proxy(proxy) => {
                let proxy_addrs = guard.resolve_proxy(&proxy.host, proxy.port).await?;
                let mut last = None;
                let mut opened = None;
                for addr in &addrs {
                    match proxy.open(&proxy_addrs, *addr).await {
                        Ok(t) => {
                            opened = Some(t);
                            break;
                        }
                        Err(e) => last = Some(e),
                    }
                }
                match (opened, last) {
                    (Some(t), _) => t,
                    (None, Some(e)) => return Err(e),
                    (None, None) => return Err(Error::Connect(format!("{}: no address", target.host))),
                }
            }
        };
        tcp.set_nodelay(true).ok();
        self.pool.opened.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(tcp)
    }
}

/// Reads one response on `c`; with `live`, an event stream's head only, its body left open
/// ([`Conn::live`]).
async fn read_one(c: &mut Conn, method: &str, live: bool) -> Result<Vec<u8>> {
    if !live {
        return c.reader.read_response(&mut c.stream, method).await;
    }
    let (response, framing) = c.reader.read_response_live(&mut c.stream, method).await?;
    c.live = framing;
    Ok(response)
}

/// The final response's status.
fn status(response: &[u8]) -> Option<u16> {
    parse_response_head(final_response(response)).ok().map(|h| h.status)
}

/// The request target from the request line (the Digest `uri`).
fn request_uri(bytes: &[u8]) -> String {
    let (head, _) = crate::http::request::split_head_body(bytes);
    RawRequest::from_bytes(head.to_vec()).head().map(|h| h.target).unwrap_or_else(|_| "/".into())
}

fn with_header(bytes: &[u8], name: &str, value: &str) -> Vec<u8> {
    RawRequest::from_bytes(bytes.to_vec()).set_header(name, value).into_bytes()
}

/// Whether an error on a reused connection means the server had closed it.
fn stale(e: &Error) -> bool {
    match e {
        Error::Protocol(m) => m == "connection closed before any response",
        Error::Io(_) => true,
        _ => false,
    }
}

/// Whether the connection can't be reused after this exchange.
pub fn close_after(request: &[u8], response: &[u8], method: &str) -> bool {
    let req_close = RawRequest::from_bytes(request.to_vec())
        .head()
        .map(|h| h.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close")))
        .unwrap_or(true);
    // More than one message went out (pipelined or smuggled, or a body longer than its
    // Content-Length): the server's other answers may still arrive, and the next request
    // on this connection would read them.
    if req_close || !one_message(request) {
        return true;
    }
    let Ok(h) = parse_response_head(final_response(response)) else { return true };
    h.status == 101
        || cut_short(response, method)
        || h.header("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"))
        || (h.version == "HTTP/1.0" && !h.header("connection").is_some_and(|v| v.eq_ignore_ascii_case("keep-alive")))
        || (h.header("content-length").is_none()
            && !h.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
            && !method.eq_ignore_ascii_case("HEAD")
            && !matches!(h.status, 100..=199 | 204 | 304))
}

/// Whether `request` is exactly one HTTP/1 message: its body is all its framing says.
fn one_message(request: &[u8]) -> bool {
    let (head, body) = crate::http::request::split_head_body(request);
    if !head.ends_with(b"\r\n\r\n") {
        return false;
    }
    let Ok(h) = RawRequest::from_bytes(head.to_vec()).head() else { return false };
    let header = |n: &str| h.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.trim());
    match (header("transfer-encoding"), header("content-length")) {
        (Some(_), Some(_)) => false,
        (Some(te), None) => te.to_ascii_lowercase().ends_with("chunked") && chunked_len(body) == Some(body.len()),
        (None, Some(cl)) => cl.parse::<usize>().is_ok_and(|n| n == body.len()),
        (None, None) => body.is_empty(),
    }
}

/// The length of a complete chunked body (through the last chunk and trailers).
fn chunked_len(body: &[u8]) -> Option<usize> {
    let line = |from: usize| body.get(from..)?.windows(2).position(|w| w == b"\r\n").map(|i| from + i);
    let mut pos = 0;
    loop {
        let end = line(pos)?;
        let size = std::str::from_utf8(&body[pos..end]).ok()?.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        pos = end + 2;
        if size == 0 {
            // Trailer lines, then the empty line.
            loop {
                let end = line(pos)?;
                let empty = end == pos;
                pos = end + 2;
                if empty {
                    return Some(pos);
                }
            }
        }
        pos = pos.checked_add(size)?;
        if body.get(pos..pos + 2)? != b"\r\n" {
            return None;
        }
        pos += 2;
    }
}

/// The final response after any interim 1xx responses.
/// Whether the final response in `resp` to a `method` request has less body than its
/// Content-Length says: the server closed early. Whoever reads it as a whole would wait for the
/// rest on a kept-alive connection.
pub fn cut_short(resp: &[u8], method: &str) -> bool {
    let resp = final_response(resp);
    let Ok(h) = parse_response_head(resp) else { return false };
    if method.eq_ignore_ascii_case("HEAD") || matches!(h.status, 100..=199 | 204 | 304) {
        return false;
    }
    let Some(len) = h.header("content-length").and_then(|v| v.trim().parse::<usize>().ok()) else { return false };
    let (head, body) = crate::http::request::split_head_body(resp);
    !head.is_empty() && body.len() < len
}

pub fn final_response(resp: &[u8]) -> &[u8] {
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

/// Any bidirectional byte stream (plain TCP or TLS).
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type Stream = Box<dyn AsyncStream>;

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS server name as `--sni` (or a target's host) must be: a DNS name or an IP address.
pub fn server_name(name: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(name.to_string())
        .map_err(|e| Error::InvalidInput(format!("bad TLS server name {name:?}: {e}")))
}

/// The server name sent to `target` in place of its host when `sni` overrides it: none over
/// plain HTTP (or ws), none when it is the target's host anyway, and none for an IP address,
/// which can't be a server name, so no SNI is sent then.
pub fn sent_sni(sni: Option<&str>, target: &Target) -> Option<String> {
    sni.filter(|n| target.is_tls() && !n.eq_ignore_ascii_case(&target.host) && n.parse::<std::net::IpAddr>().is_err())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::net::TcpListener;

    use super::*;
    use crate::guard::ScopeSpec;

    #[test]
    fn connections_that_carried_more_than_one_request_are_not_reused() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let ok = |req: &[u8]| !close_after(req, resp, "GET");
        assert!(ok(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"));
        assert!(ok(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nab"));
        assert!(ok(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n"));
        assert!(!ok(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n"));
        assert!(!ok(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nabGET / HTTP/1.1\r\n\r\n"));
        assert!(!ok(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"));
    }

    #[test]
    fn a_host_the_scope_does_not_list_is_foreign() {
        let scope = ScopeSpec { name: None, include: vec!["127.0.0.1".into(), "app.test".into()], exclude: vec![] };
        let opts = SendOptions { guard: Some(Guard::from_specs(vec![scope]).unwrap()), ..Default::default() };
        let target = Target { scheme: "https".into(), host: "127.0.0.1".into(), port: 8443 };
        let foreign = |req: &str| opts.foreign_host(req.as_bytes(), &target);
        // The target's own host, with or without a port, and a name the scope lists aren't.
        assert_eq!(foreign("GET / HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n"), None);
        assert_eq!(foreign("GET / HTTP/1.1\r\nHost: APP.test\r\n\r\nHost: body.test"), None);
        assert_eq!(foreign("GET / HTTP/1.1\r\n\r\n"), None);
        // Any other is, a second Host or an absolute request target too.
        assert_eq!(
            foreign("GET / HTTP/1.1\r\nhost: other-tenant.test:443\r\n\r\n").as_deref(),
            Some("other-tenant.test")
        );
        let lf = opts.foreign_hosts(b"GET / HTTP/1.1\nHost: app.test\nHost: b.test\n\n", &target);
        assert_eq!(lf, ["(a bare LF in the head)", "b.test"]);
        assert_eq!(foreign("GET http://c.test/ HTTP/1.1\r\nHost: app.test\r\n\r\n").as_deref(), Some("c.test"));
        // A value that isn't plainly a host is shown as it is.
        assert_eq!(foreign("GET / HTTP/1.1\r\nHost: app.test/@d.test\r\n\r\n").as_deref(), Some("app.test/@d.test"));
        // So is a request target that isn't a path or `*`, or one the URL parser can't read.
        assert_eq!(foreign("GET .evil.test/ HTTP/1.1\r\nHost: app.test\r\n\r\n").as_deref(), Some(".evil.test/"));
        assert_eq!(foreign("CONNECT e.test:443 HTTP/1.1\r\nHost: app.test\r\n\r\n").as_deref(), Some("e.test"));
        assert_eq!(foreign("GET ws://w.test/ HTTP/1.1\r\n\r\n").as_deref(), Some("ws://w.test/"));
        assert_eq!(foreign("OPTIONS * HTTP/1.1\r\nHost: app.test\r\n\r\n"), None);
        // And a head a lenient server may read otherwise: odd spacing, a tab, a bare CR.
        for odd in
            ["GET  http://e.test/ HTTP/1.1\r\n\r\n", "GET\thttp://e.test/ HTTP/1.1\r\n\r\n", "GET / HTTP/1.1 x\r\n\r\n"]
        {
            assert!(foreign(odd).is_some_and(|h| h.contains("request line")), "{odd:?}");
        }
        let cr = foreign("GET / HTTP/1.1\r\nX: a\rHost: e.test\r\nHost: app.test\r\n\r\n");
        assert_eq!(cr.as_deref(), Some("(a bare CR in the head)"));
        // The client applies the policy to what goes on the wire, and notes what it warned about.
        let refuse = Client::new(SendOptions { host: HostPolicy::Refuse, ..opts.clone() });
        let warn = Client::new(SendOptions { host: HostPolicy::Warn, ..opts.clone() });
        let allow = Client::new(SendOptions { host: HostPolicy::Allow, ..opts.clone() });
        let wire = b"GET / HTTP/1.1\r\nHost: e.test\r\n\r\n";
        assert!(matches!(refuse.check_host(wire, &target), Err(Error::OutOfScope(m)) if m.contains("Host e.test")));
        assert!(
            warn.check_host(wire, &target).is_ok() && warn.clone().first_foreign_host().as_deref() == Some("e.test")
        );
        assert!(allow.check_host(wire, &target).is_ok() && allow.first_foreign_host().is_none());
        // A `\` in an absolute target, which the URL parser reads as `/`.
        let slash = foreign("GET http://app.test\\@e.test/ HTTP/1.1\r\nHost: app.test\r\n\r\n");
        assert_eq!(slash.as_deref(), Some("http://app.test\\@e.test/"));
        // A second request after the body its framing says, but not a body that is just data.
        let second = "GET /b HTTP/1.1\r\nHost: e.test\r\n\r\n";
        for first in [
            "GET /a HTTP/1.1\r\nHost: app.test\r\n\r\n".to_string(),
            "POST /a HTTP/1.1\r\nHost: app.test\r\nContent-Length: 2\r\n\r\nab".to_string(),
            "POST /a HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n".to_string(),
        ] {
            let both = foreign(&format!("{first}{second}"));
            assert_eq!(both.as_deref(), Some("(a second request after the body)"), "{first:?}");
        }
        let data =
            "POST /a HTTP/1.1\r\nHost: app.test\r\nContent-Length: 34\r\n\r\nGET /b HTTP/1.1\r\nHost: e.test\r\n\r\n";
        assert_eq!(foreign(data), None);
        // A method in mixed case still reads as a request.
        let lower =
            "POST /a HTTP/1.1\r\nHost: app.test\r\nContent-Length: 0\r\n\r\nGet /b http/1.1\r\nHost: e.test\r\n\r\n";
        assert_eq!(foreign(lower).as_deref(), Some("(a second request after the body)"));
        // Framing servers may read differently hides one from that check: it counts by itself.
        for framing in ["Content-Length: 47\r\nContent-Length: 0", "Content-Length: 4\r\nTransfer-Encoding: chunked"] {
            let raw = format!("POST /a HTTP/1.1\r\nHost: app.test\r\n{framing}\r\n\r\n0\r\n\r\n");
            assert!(foreign(&raw).is_some_and(|h| h.contains("frame differently")), "{framing}");
        }
        let same = "POST /a HTTP/1.1\r\nHost: app.test\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nab";
        assert_eq!(foreign(same), None);
        // A value a setting puts in requests to come, whatever their target.
        let guard = opts.guard.as_deref();
        assert_eq!(unlisted_host(guard, " app.TEST:8443 "), None);
        assert_eq!(unlisted_host(guard, "127.0.0.1"), None);
        assert_eq!(unlisted_host(guard, ""), None);
        assert_eq!(unlisted_host(guard, "other-tenant.test").as_deref(), Some("other-tenant.test"));
        assert_eq!(unlisted_host(guard, "{{host}}").as_deref(), Some("{{host}}"));
        assert_eq!(unlisted_host(None, "app.test").as_deref(), Some("app.test"));
        // Without a scope nothing is listed.
        let none = SendOptions::default();
        assert_eq!(
            none.foreign_host(b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", &target).as_deref(),
            Some("app.test")
        );
    }

    /// A keep-alive server; with `drop_idle` it closes each connection after one
    /// response without saying so (as servers do with idle connections).
    async fn server(drop_idle: bool) -> (u16, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut reader = WireReader::new();
                    while let Ok(Some(_)) = reader.read_request(&mut s).await {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
                        if drop_idle {
                            return;
                        }
                    }
                });
            }
        });
        (port, accepted)
    }

    fn client() -> Client {
        let scope = ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] };
        Client::new(SendOptions { guard: Some(Guard::from_specs(vec![scope]).unwrap()), ..Default::default() })
    }

    async fn send_n(client: &Client, port: u16, connection: &str, n: usize) {
        let target = Target { scheme: "http".into(), host: "127.0.0.1".into(), port };
        let req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: {connection}\r\n\r\n");
        for _ in 0..n {
            let ex = client.send(&RawRequest::from_bytes(req.clone().into_bytes()), &target).await.unwrap();
            assert!(ex.response.ends_with(b"\r\n\r\nok"));
        }
    }

    #[tokio::test]
    async fn reuses_kept_alive_connections() {
        let (port, accepted) = server(false).await;
        let c = client();
        send_n(&c, port, "keep-alive", 5).await;
        send_n(&c.clone(), port, "keep-alive", 5).await;
        assert_eq!((accepted.load(Ordering::Relaxed), c.connections_opened()), (1, 1));

        // `Connection: close` requests never reuse or return a connection.
        let (port, accepted) = server(false).await;
        send_n(&c, port, "close", 3).await;
        assert_eq!(accepted.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn retries_once_when_a_pooled_connection_was_closed() {
        let (port, accepted) = server(true).await;
        let c = client();
        send_n(&c, port, "keep-alive", 4).await;
        assert_eq!(accepted.load(Ordering::Relaxed), 4);
    }

    /// Answers the first request on each connection, then reads the next and closes
    /// without answering (as if it processed it and then dropped the connection).
    /// Counts the requests it read.
    async fn answer_once_server() -> (u16, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let read = Arc::new(AtomicU64::new(0));
        let count = read.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let count = count.clone();
                tokio::spawn(async move {
                    let mut reader = WireReader::new();
                    for n in 0.. {
                        let Ok(Some(_)) = reader.read_request(&mut s).await else { return };
                        count.fetch_add(1, Ordering::Relaxed);
                        if n > 0 {
                            return;
                        }
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
                    }
                });
            }
        });
        (port, read)
    }

    #[tokio::test]
    async fn only_requests_safe_to_repeat_are_retried() {
        let (port, read) = answer_once_server().await;
        let c = client();
        let target = Target { scheme: "http".into(), host: "127.0.0.1".into(), port };
        let send = |raw: &str| {
            let req = RawRequest::from_bytes(raw.as_bytes().to_vec());
            let (c, target) = (&c, &target);
            async move { c.send(&req, target).await }
        };
        send("GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
        // The POST reached the server once on the pooled connection; it isn't sent again.
        assert!(send("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\nx").await.is_err());
        assert_eq!(read.load(Ordering::Relaxed), 2);
        // A GET in the same spot is retried on a new connection.
        send("GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
        send("GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
        assert_eq!(read.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn a_new_client_does_not_share_the_pool() {
        let (port, accepted) = server(false).await;
        send_n(&client(), port, "keep-alive", 2).await;
        send_n(&client(), port, "keep-alive", 2).await;
        assert_eq!(accepted.load(Ordering::Relaxed), 2);
        // No guard, no connection, pooled or not.
        let target = Target { scheme: "http".into(), host: "127.0.0.1".into(), port };
        let req = RawRequest::from_bytes(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
        assert!(matches!(Client::new(SendOptions::default()).send(&req, &target).await, Err(Error::OutOfScope(_))));
    }
}
