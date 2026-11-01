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
use crate::http::wire::WireReader;

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
}

impl Default for SendOptions {
    fn default() -> Self {
        Self { timeout: Duration::from_secs(30), verify_tls: false, sni: None, guard: None, http2: false }
    }
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
}

#[derive(Clone)]
pub struct Client {
    tls: TlsConnector,
    tls_h2: TlsConnector,
    opts: SendOptions,
    pool: Arc<Pool>,
}

/// A TLS client configuration offering `alpn`, verifying certificates or not, and
/// presenting `identity` when given.
fn tls_config(verify: bool, alpn: &[u8], identity: Option<&ClientIdentity>) -> Result<ClientConfig> {
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
        Ok(Conn { stream, reader: WireReader::new(), reused: false, generation: net.generation })
    }

    pub fn options(&self) -> &SendOptions {
        &self.opts
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
            return Ok(Conn { stream, reader: WireReader::new(), reused: true, generation });
        }
        self.fresh(target).await
    }

    /// Returns a connection to the pool after a complete exchange. Connections
    /// with unread bytes (a desynchronised server) are dropped.
    /// Connections opened with connection options that have since changed are dropped too.
    pub fn checkin(&self, target: &Target, conn: Conn) {
        if !conn.reader.is_empty() || conn.generation != self.net().generation {
            return;
        }
        let mut idle = self.pool.idle.lock().unwrap();
        let list = idle.entry(self.pool_key(target, conn.generation)).or_default();
        if list.len() < POOL_PER_TARGET {
            list.push((conn.stream, Instant::now()));
        }
    }

    /// The bytes to put on the wire: auth placeholders replaced with their values
    /// from the guard's vault. Callers record the original bytes.
    pub fn fill_auth<'a>(&self, bytes: &'a [u8], target: &Target) -> Result<std::borrow::Cow<'a, [u8]>> {
        match &self.opts.guard {
            Some(g) => g.vault.resolve(bytes, target),
            None => Ok(std::borrow::Cow::Borrowed(bytes)),
        }
    }

    pub async fn send(&self, req: &RawRequest, target: &Target) -> Result<Exchange> {
        let method = req.head().map(|h| h.method).unwrap_or_else(|_| "GET".into());
        let started = Instant::now();
        if self.opts.http2 || req.head().is_ok_and(|h| h.version.eq_ignore_ascii_case("HTTP/2")) {
            let filled = self.fill_auth(req.as_bytes(), target)?;
            let response = tokio::time::timeout(self.opts.timeout, self.round_trip_h2_auth(&filled, target, &method))
                .await
                .map_err(|_| Error::Timeout(self.opts.timeout))??;
            return Ok(Exchange {
                target: target.clone(),
                // Recorded with the auth placeholders, not the values sent.
                request: H2Request::from_raw(req.as_bytes(), target)?.recorded,
                response,
                duration_ms: started.elapsed().as_millis() as u64,
            });
        }
        let response = tokio::time::timeout(self.opts.timeout, self.round_trip(req.as_bytes(), target, &method))
            .await
            .map_err(|_| Error::Timeout(self.opts.timeout))??;
        Ok(Exchange {
            target: target.clone(),
            request: req.as_bytes().to_vec(),
            response,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }

    async fn round_trip(&self, bytes: &[u8], target: &Target, method: &str) -> Result<Vec<u8>> {
        let (conn, response) = self.exchange(bytes, target, method).await?;
        if !close_after(bytes, &response, method) {
            self.checkin(target, conn);
        }
        Ok(response)
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
        let bytes = &*self.fill_auth(bytes, target)?;
        match self.platform_cred(target, bytes) {
            Some(cred) => self.exchange_platform(&cred, bytes, target, method).await,
            None => self.exchange_once(bytes, target, method).await,
        }
    }

    async fn exchange_once(&self, bytes: &[u8], target: &Target, method: &str) -> Result<(Conn, Vec<u8>)> {
        let repeatable =
            ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"].iter().any(|m| method.eq_ignore_ascii_case(m));
        let mut c = self.checkout(target, if repeatable { POOL_IDLE } else { POOL_IDLE_UNSAFE }).await?;
        loop {
            let result = async {
                c.stream.write_all(bytes).await?;
                c.stream.flush().await?;
                c.reader.read_response(&mut c.stream, method).await
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
    async fn on_conn(&self, mut c: Conn, bytes: &[u8], method: &str) -> Result<(Conn, Vec<u8>)> {
        c.stream.write_all(bytes).await?;
        c.stream.flush().await?;
        let response = c.reader.read_response(&mut c.stream, method).await?;
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
    ) -> Result<(Conn, Vec<u8>)> {
        let uri = request_uri(bytes);
        let mut sent = bytes.to_vec();
        if let Some(value) = self.learned_header(cred, target, method, &uri)? {
            sent = with_header(bytes, "Authorization", &value);
        }
        let (conn, response) = self.exchange_once(&sent, target, method).await?;
        if status(&response) != Some(401) {
            return Ok((conn, response));
        }
        self.learn(target, None);
        // The next leg goes on this connection if it stays open, else on a new one.
        let next = |conn: Conn, prev: &[u8], prev_resp: &[u8], req: Vec<u8>| {
            let reuse = !close_after(prev, prev_resp, method);
            async move {
                if reuse {
                    self.on_conn(conn, &req, method).await
                } else {
                    drop(conn);
                    let c = self.fresh(target).await?;
                    self.on_conn(c, &req, method).await
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
            return self.on_conn(conn, &auth, method).await;
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
    async fn round_trip_h2_auth(&self, filled: &[u8], target: &Target, method: &str) -> Result<Vec<u8>> {
        let cred = self.platform_cred(target, filled).filter(|c| c.scheme != PlatformScheme::Ntlm);
        let Some(cred) = cred else { return self.round_trip_h2(&H2Request::from_raw(filled, target)?, target).await };
        let uri = request_uri(filled);
        let first = match self.learned_header(&cred, target, method, &uri)? {
            Some(value) => with_header(filled, "Authorization", &value),
            None => filled.to_vec(),
        };
        let response = self.round_trip_h2(&H2Request::from_raw(&first, target)?, target).await?;
        if status(&response) != Some(401) {
            return Ok(response);
        }
        self.learn(target, None);
        let Some((value, learned)) = self.answer(&cred, &response, method, &uri)? else { return Ok(response) };
        let again = with_header(filled, "Authorization", &value);
        let response = self.round_trip_h2(&H2Request::from_raw(&again, target)?, target).await?;
        if status(&response) != Some(401) {
            self.learn(target, Some(learned));
        }
        Ok(response)
    }

    /// Sends on the pooled HTTP/2 connection to `target`, opening one if there
    /// is none. If the pooled connection has gone away (checked before anything
    /// is sent), a new one is opened.
    async fn round_trip_h2(&self, req: &H2Request, target: &Target) -> Result<Vec<u8>> {
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
        let result = crate::http::h2::round_trip(sender, req).await;
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
        let tcp = self.connect_tcp(target, net).await?;
        let refused = || Error::Protocol(format!("{}:{} did not negotiate HTTP/2 (ALPN h2)", target.host, target.port));
        let tls = self.tls_handshake(&connector, tcp, target).await.map_err(|e| match e {
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
        // A client certificate that can't be loaded fails before any connection.
        let connector = self.connector(false, target, net)?;
        let tcp = self.connect_tcp(target, net).await?;
        Ok(Box::new(self.tls_handshake(&connector, tcp, target).await?))
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

    async fn tls_handshake(
        &self,
        connector: &TlsConnector,
        tcp: TcpStream,
        target: &Target,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let name = self.opts.sni.as_deref().unwrap_or(&target.host);
        let server_name = ServerName::try_from(name.to_string())
            .map_err(|e| Error::InvalidInput(format!("bad TLS server name {name:?}: {e}")))?;
        connector.connect(server_name, tcp).await.map_err(|e| Error::Tls(e.to_string()))
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
