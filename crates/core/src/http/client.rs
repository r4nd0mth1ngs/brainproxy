//! A raw HTTP/1.x client: writes the request bytes as-is and reads one response.
//!
//! Connections are kept alive and reused when both the request and the
//! response allow it. The pool belongs to one `Client` (shared by its clones),
//! whose options, guard included, never change; every pooled connection was
//! opened by [`Client::connect`] for the same scheme, host, and port, so reuse
//! never skips a scope decision.

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

use crate::error::{Error, Result};
use crate::guard::Guard;
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
}

impl Default for SendOptions {
    fn default() -> Self {
        Self { timeout: Duration::from_secs(30), verify_tls: false, sni: None, guard: None }
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

/// An open connection with the reader that holds its unread bytes.
pub struct Conn {
    pub stream: Stream,
    pub reader: WireReader,
    /// Whether it came from the pool (so a failure may just mean the server
    /// closed it while idle).
    pub reused: bool,
}

/// Sockets belong to the runtime that opened them (auth logs in on a short-lived
/// one), so the runtime is part of the key.
type PoolKey = (tokio::runtime::Id, String, String, u16);

#[derive(Default)]
struct Pool {
    idle: Mutex<HashMap<PoolKey, Vec<(Stream, Instant)>>>,
    opened: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
pub struct Client {
    tls: TlsConnector,
    opts: SendOptions,
    pool: Arc<Pool>,
}

fn pool_key(target: &Target) -> PoolKey {
    let rt = tokio::runtime::Handle::current().id();
    (rt, target.scheme.to_ascii_lowercase(), target.host.to_ascii_lowercase(), target.port)
}

impl Client {
    pub fn new(opts: SendOptions) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = if opts.verify_tls {
            let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth()
        };
        let mut config = config;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self { tls: TlsConnector::from(Arc::new(config)), opts, pool: Arc::default() }
    }

    /// Connections opened so far (pooled reuse doesn't count).
    pub fn connections_opened(&self) -> u64 {
        self.pool.opened.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// An idle pooled connection to `target`, or a new one from [`Client::connect`].
    pub async fn checkout(&self, target: &Target) -> Result<Conn> {
        let key = pool_key(target);
        let pooled = {
            let mut idle = self.pool.idle.lock().unwrap();
            let list = idle.entry(key).or_default();
            list.retain(|(_, at)| at.elapsed() < POOL_IDLE);
            list.pop()
        };
        if let Some((stream, _)) = pooled {
            return Ok(Conn { stream, reader: WireReader::new(), reused: true });
        }
        Ok(Conn { stream: self.connect(target).await?, reader: WireReader::new(), reused: false })
    }

    /// Returns a connection to the pool after a complete exchange. Connections
    /// with unread bytes (a desynchronised server) are dropped.
    pub fn checkin(&self, target: &Target, conn: Conn) {
        if !conn.reader.is_empty() {
            return;
        }
        let mut idle = self.pool.idle.lock().unwrap();
        let list = idle.entry(pool_key(target)).or_default();
        if list.len() < POOL_PER_TARGET {
            list.push((conn.stream, Instant::now()));
        }
    }

    pub async fn send(&self, req: &RawRequest, target: &Target) -> Result<Exchange> {
        let method = req.head().map(|h| h.method).unwrap_or_else(|_| "GET".into());
        let started = Instant::now();
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
    /// was most likely closed by the server while idle, so the request is
    /// retried once on a new connection. The caller decides whether to
    /// [`Client::checkin`] the connection afterwards.
    pub async fn exchange(&self, bytes: &[u8], target: &Target, method: &str) -> Result<(Conn, Vec<u8>)> {
        let mut c = self.checkout(target).await?;
        loop {
            let result = async {
                c.stream.write_all(bytes).await?;
                c.stream.flush().await?;
                c.reader.read_response(&mut c.stream, method).await
            }
            .await;
            match result {
                Ok(response) => return Ok((c, response)),
                Err(e) if c.reused && c.reader.is_empty() && stale(&e) => {
                    c = Conn { stream: self.connect(target).await?, reader: WireReader::new(), reused: false };
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Opens a connection to the target, wrapped in TLS for https. The target
    /// must pass the scope guard; the connection goes to an address the guard
    /// checked.
    pub async fn connect(&self, target: &Target) -> Result<Stream> {
        let guard = self.opts.guard.as_ref().ok_or_else(|| {
            Error::OutOfScope("no engagement scope: run `brainproxy engagement start --target HOST ...` first".into())
        })?;
        let addrs = guard.resolve(&target.host, target.port).await?;
        let tcp = TcpStream::connect(&addrs[..])
            .await
            .map_err(|e| Error::Connect(format!("{}:{}: {e}", target.host, target.port)))?;
        tcp.set_nodelay(true).ok();
        self.pool.opened.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !target.is_tls() {
            return Ok(Box::new(tcp));
        }
        let name = self.opts.sni.as_deref().unwrap_or(&target.host);
        let server_name = ServerName::try_from(name.to_string())
            .map_err(|e| Error::InvalidInput(format!("bad TLS server name {name:?}: {e}")))?;
        let tls = self.tls.connect(server_name, tcp).await.map_err(|e| Error::Tls(e.to_string()))?;
        Ok(Box::new(tls))
    }
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
    let Ok(h) = parse_response_head(final_response(response)) else { return true };
    req_close
        || h.status == 101
        || h.header("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"))
        || (h.version == "HTTP/1.0" && !h.header("connection").is_some_and(|v| v.eq_ignore_ascii_case("keep-alive")))
        || (h.header("content-length").is_none()
            && !h.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
            && !method.eq_ignore_ascii_case("HEAD")
            && !matches!(h.status, 100..=199 | 204 | 304))
}

/// The final response after any interim 1xx responses.
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
