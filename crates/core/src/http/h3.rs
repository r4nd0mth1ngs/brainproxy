//! HTTP/3 over QUIC, using `quinn` and `h3` on the same rustls + ring as TCP.
//!
//! Containment: quinn never opens a socket or picks an address of its own. The client resolves
//! the destination through the guard ([`crate::guard::Guard::resolve_with`]) as it does for TCP,
//! then gives quinn a [`GuardedUdp`] socket tied to one checked address: a datagram for any other
//! address (a server's preferred address, a stateless reset to a stray sender) is refused before
//! it reaches the network, and datagrams from other addresses are dropped unread. Every
//! connection has an endpoint (and a socket) of its own.
//!
//! Requests are converted like HTTP/2 ones ([`H2Request::from_raw_as`]) and exchanges recorded
//! in the same text form with `HTTP/3` as the version, so history, passive rules and Replay
//! work on them unchanged.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};

use crate::error::{Error, Result};
use crate::http::h2::{response_bytes_as, H2Request};

/// The ALPN token of HTTP/3 (RFC 9114 3.1).
pub const ALPN: &[u8] = b"h3";

/// The sending half of an HTTP/3 connection.
pub type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
/// One request's stream, kept to read an event stream's body as it arrives.
pub type Body = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// A UDP socket that only exchanges datagrams with `peer`, the address the guard checked.
pub(crate) struct GuardedUdp {
    inner: Arc<dyn AsyncUdpSocket>,
    peer: SocketAddr,
}

impl fmt::Debug for GuardedUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedUdp").field("peer", &self.peer).finish()
    }
}

/// The same address, also when one side is written IPv4-mapped (`::ffff:a.b.c.d`).
fn same_addr(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
}

impl AsyncUdpSocket for GuardedUdp {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if !same_addr(transmit.destination, self.peer) {
            // quinn closes a connection whose datagram fails this way, and an endpoint drops it.
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is not the address the scope checked ({})", transmit.destination, self.peer),
            ));
        }
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let n = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        // An empty datagram is skipped: nothing from another address reaches quinn.
        for m in meta.iter_mut().take(n) {
            if !same_addr(m.addr, self.peer) {
                m.len = 0;
            }
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// A client endpoint on a new UDP socket that can only reach `peer`. The only place UDP sockets
/// to targets are opened; `peer` must come from the guard.
pub(crate) fn guarded_endpoint(peer: SocketAddr) -> Result<quinn::Endpoint> {
    let bind: SocketAddr = if peer.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let udp = std::net::UdpSocket::bind(bind).map_err(|e| Error::Connect(format!("UDP socket: {e}")))?;
    let runtime = Arc::new(quinn::TokioRuntime);
    let inner = runtime.wrap_udp_socket(udp).map_err(|e| Error::Connect(format!("UDP socket: {e}")))?;
    let socket = Arc::new(GuardedUdp { inner, peer });
    quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), None, socket, runtime)
        .map_err(|e| Error::Connect(format!("UDP socket: {e}")))
}

/// Largest response header section accepted (decoded), as for an HTTP/1.1 head.
pub const MAX_FIELD_SECTION: u64 = 256 * 1024;

/// Idle time after which an HTTP/3 connection closes (both sides agree on the lower of theirs).
const IDLE: Duration = Duration::from_secs(30);

/// The QUIC client configuration for a rustls configuration offering ALPN `h3`.
pub(crate) fn client_config(tls: rustls::ClientConfig) -> Result<quinn::ClientConfig> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| Error::Tls(format!("QUIC needs TLS 1.3: {e}")))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(IDLE.try_into().expect("30 s fits a QUIC idle timeout")));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// An open HTTP/3 connection: its sender, and the QUIC connection to tell whether it's still up.
#[derive(Clone)]
pub struct Conn {
    pub sender: Sender,
    pub quic: quinn::Connection,
    /// Where the connection went: the target's address, or an Alt-Svc endpoint's.
    pub peer: SocketAddr,
    /// The Alt-Svc endpoint (host and port) it was opened for; none for the target's own.
    pub advertised: Option<(String, u16)>,
}

impl Conn {
    pub fn is_open(&self) -> bool {
        self.quic.close_reason().is_none()
    }
}

/// Opens a QUIC connection to `peer` (an address the guard checked), presenting `server_name`,
/// and starts HTTP/3 on it. The connection's driver runs on its own task until it closes.
/// Fails without sending a request when the handshake fails or doesn't finish within
/// `handshake`: the server may not offer HTTP/3, or UDP may be blocked on the way.
pub(crate) async fn connect(
    peer: SocketAddr,
    server_name: &str,
    config: quinn::ClientConfig,
    handshake: Duration,
) -> Result<Conn> {
    let endpoint = guarded_endpoint(peer)?;
    let connecting =
        endpoint.connect_with(config, peer, server_name).map_err(|e| Error::Connect(format!("QUIC to {peer}: {e}")))?;
    // The handshake and HTTP/3's own setup (its control streams, which a server that grants no
    // stream credit would hold up for ever) together.
    let setup = async {
        let quic = connecting.await.map_err(|e| handshake_error(peer, e))?;
        let mut builder = h3::client::builder();
        // No reserved frames or settings of our own: what goes out is what the request says.
        builder.send_grease(false);
        // Response headers as large as an HTTP/1.1 head may be, not h3's 2^62.
        builder.max_field_section_size(MAX_FIELD_SECTION);
        let (driver, sender) = builder
            .build(h3_quinn::Connection::new(quic.clone()))
            .await
            .map_err(|e| Error::Protocol(format!("HTTP/3 to {peer}: {e}")))?;
        Ok::<_, Error>((quic, driver, sender))
    };
    let (quic, mut driver, sender) = match tokio::time::timeout(handshake, setup).await {
        Err(_) => {
            return Err(Error::Connect(format!(
                "no HTTP/3 connection to {peer} within {} ms (UDP blocked, no HTTP/3 there, or a server that \
                 doesn't let it start)",
                handshake.as_millis()
            )))
        }
        Ok(r) => r?,
    };
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        // The endpoint (and its socket) lives as long as the connection.
        drop(endpoint);
    });
    Ok(Conn { sender, quic, peer, advertised: None })
}

fn handshake_error(peer: SocketAddr, e: quinn::ConnectionError) -> Error {
    let text = e.to_string();
    // TLS alert 120, no_application_protocol (RFC 9001 4.8: QUIC error 0x178).
    if text.contains("error 120") || text.contains("no_application_protocol") || text.contains("0x178") {
        return Error::Protocol(format!("{peer} did not negotiate HTTP/3 (ALPN h3)"));
    }
    match e {
        quinn::ConnectionError::TransportError(_) | quinn::ConnectionError::ConnectionClosed(_) => {
            Error::Tls(format!("QUIC handshake with {peer}: {text}"))
        }
        _ => Error::Connect(format!("QUIC to {peer}: {text}")),
    }
}

pub(crate) fn stream_error(e: h3::error::StreamError) -> Error {
    Error::Protocol(format!("HTTP/3: {e}"))
}

/// Sends one request on `conn` and reads the response, as text with `HTTP/3` as the version.
/// With `live`, an event stream's head is returned and its stream left open to read.
pub async fn round_trip_live(conn: &Conn, req: &H2Request, live: bool) -> Result<(Vec<u8>, Option<Body>)> {
    let mut sender = conn.sender.clone();
    let mut stream = sender.send_request(req.request()).await.map_err(stream_error)?;
    if !req.body.is_empty() {
        stream.send_data(req.body.clone()).await.map_err(stream_error)?;
    }
    stream.finish().await.map_err(stream_error)?;
    // Informational responses (100, 103 Early Hints) come first, each a HEADERS frame of its
    // own; they are kept before the final one, as over HTTP/1.1.
    let mut interim = Vec::new();
    let parts = loop {
        let (parts, ()) = stream.recv_response().await.map_err(stream_error)?.into_parts();
        if !parts.status.is_informational() {
            break parts;
        }
        interim.extend_from_slice(&response_bytes_as(&parts, b"", "HTTP/3"));
        if interim.len() > crate::http::wire::MAX_BODY {
            return Err(Error::Protocol("HTTP/3: too many informational responses".into()));
        }
    };
    if live {
        let head = response_bytes_as(&parts, b"", "HTTP/3");
        if crate::http::parse_response_head(&head).is_ok_and(|h| crate::sse::is_event_stream(&h)) {
            interim.extend_from_slice(&head);
            return Ok((interim, Some(stream)));
        }
    }
    let mut buf = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(stream_error)? {
        while chunk.has_remaining() {
            let piece = chunk.chunk();
            buf.extend_from_slice(piece);
            let n = piece.len();
            chunk.advance(n);
        }
        if buf.len() > crate::http::wire::MAX_BODY {
            return Err(Error::Protocol("HTTP/3 response body over the 64 MB limit".into()));
        }
    }
    interim.extend_from_slice(&response_bytes_as(&parts, &buf, "HTTP/3"));
    Ok((interim, None))
}

/// The next piece of an event stream's body; `None` once it is over.
pub async fn next_piece(body: &mut Body) -> Result<Option<Vec<u8>>> {
    match body.recv_data().await.map_err(stream_error)? {
        None => Ok(None),
        Some(mut chunk) => Ok(Some(chunk.copy_to_bytes(chunk.remaining()).to_vec())),
    }
}

/// An HTTP/3 endpoint a response advertised in its `Alt-Svc` header (RFC 7838).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvc {
    /// The host to connect to; the origin's own when the header gives only a port.
    pub host: String,
    pub port: u16,
    /// How long it may be used (`ma`, 24 hours by default).
    pub max_age: Duration,
}

/// What an `Alt-Svc` value says about HTTP/3: `Some(Some(alt))` for the first `h3` alternative,
/// `Some(None)` for `clear` (forget earlier ones), `None` when it says nothing about `h3`.
/// Draft versions (`h3-29`) aren't spoken, so they don't count.
pub fn parse_alt_svc(value: &str, origin_host: &str) -> Option<Option<AltSvc>> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("clear") {
        return Some(None);
    }
    for alt in split_outside_quotes(value, ',') {
        let mut parts = split_outside_quotes(alt, ';').into_iter();
        let Some((proto, authority)) = parts.next().and_then(|p| p.split_once('=')) else { continue };
        if proto.trim() != "h3" {
            continue;
        }
        let authority = authority.trim().trim_matches('"');
        let Some((host, port)) = authority.rsplit_once(':') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        if port == 0 {
            continue;
        }
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let host = if host.is_empty() { origin_host.to_string() } else { host.to_ascii_lowercase() };
        let mut max_age = Duration::from_secs(86_400);
        for param in parts {
            if let Some((k, v)) = param.split_once('=') {
                if k.trim().eq_ignore_ascii_case("ma") {
                    if let Ok(secs) = v.trim().trim_matches('"').parse::<u64>() {
                        max_age = Duration::from_secs(secs);
                    }
                }
            }
        }
        return Some(Some(AltSvc { host, port, max_age }));
    }
    None
}

fn split_outside_quotes(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut quoted, mut start) = (false, 0);
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            c if c == sep && !quoted => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::guard::{Guard, ScopeSpec};
    use crate::http::{Client, RawRequest, SendOptions, Target};

    #[test]
    fn reads_alt_svc() {
        let alt = |v: &str| parse_alt_svc(v, "app.test");
        let h3 =
            |host: &str, port, secs| Some(Some(AltSvc { host: host.into(), port, max_age: Duration::from_secs(secs) }));
        assert_eq!(alt(r#"h3=":443"; ma=86400, h3-29=":443""#), h3("app.test", 443, 86_400));
        assert_eq!(alt(r#"h3-29=":8443", h3="cdn.test:9443"; ma=60; persist=1"#), h3("cdn.test", 9443, 60));
        assert_eq!(alt(r#"h2="other.test:443", h3="[::1]:4433""#), h3("::1", 4433, 86_400));
        assert_eq!(alt("clear"), Some(None));
        for nothing in [r#"h2=":443""#, r#"h3-29=":443""#, r#"h3=":0""#, r#"h3="nowhere""#, ""] {
            assert_eq!(alt(nothing), None, "{nothing}");
        }
        // A comma inside a quoted value doesn't split it.
        assert_eq!(alt(r#"h2="a,b:1", h3=":444""#), h3("app.test", 444, 86_400));
    }

    /// The rustls server configuration of the test CA for 127.0.0.1, offering `alpn`.
    fn server_tls(alpn: &[&[u8]]) -> rustls::ServerConfig {
        let dir = std::env::temp_dir().join(format!("bp-h3-ca-{}", std::process::id()));
        let (ca, _) = crate::proxy::ca::CertAuthority::load_or_create(&dir).unwrap();
        let mut cfg = (*ca.server_config("127.0.0.1").unwrap()).clone();
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        cfg
    }

    /// An HTTP/3 server on a UDP port of 127.0.0.1 (`port`, or any), offering `alpn`, answering
    /// `<method> <uri> <body>` (with `alt_svc` as its Alt-Svc header if given), an event stream
    /// at `/events`, `103 Early Hints` before the answer at `/hints`, a 300 KB header at `/big`,
    /// and `Alt-Svc: clear` at `/clear`. Returns the port and the connections it accepted.
    pub(crate) async fn h3_server(port: u16, alpn: &[&[u8]], alt_svc: Option<String>) -> (u16, Arc<AtomicU64>) {
        h3_server_with(port, alpn, alt_svc, None).await
    }

    /// [`h3_server`] granting the client `uni` unidirectional streams (QUIC's default when None).
    async fn h3_server_with(
        port: u16,
        alpn: &[&[u8]],
        alt_svc: Option<String>,
        uni: Option<u32>,
    ) -> (u16, Arc<AtomicU64>) {
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls(alpn)).unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        if let Some(n) = uni {
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_uni_streams(n.into());
            config.transport_config(Arc::new(transport));
        }
        let endpoint = quinn::Endpoint::server(config, SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let (count, alt_svc) = (count.clone(), alt_svc.clone());
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    count.fetch_add(1, Ordering::Relaxed);
                    let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                    else {
                        return;
                    };
                    while let Ok(Some(resolver)) = h3.accept().await {
                        let alt_svc = alt_svc.clone();
                        tokio::spawn(async move {
                            let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                            let mut body = Vec::new();
                            while let Ok(Some(mut c)) = stream.recv_data().await {
                                body.extend_from_slice(&c.copy_to_bytes(c.remaining()));
                            }
                            let path = req.uri().path().to_string();
                            let events = path == "/events";
                            if path == "/hints" {
                                let hint =
                                    http::Response::builder().status(103).header("link", "</a.css>; rel=preload");
                                let _ = stream.send_response(hint.body(()).unwrap()).await;
                            }
                            let mut resp = http::Response::builder()
                                .header("content-type", if events { "text/event-stream" } else { "text/plain" });
                            if path == "/big" {
                                resp = resp.header("x-big", "a".repeat(300 * 1024));
                            }
                            if path == "/clear" {
                                resp = resp.header("alt-svc", "clear");
                            } else if let Some(a) = &alt_svc {
                                resp = resp.header("alt-svc", a.as_str());
                            }
                            let _ = stream.send_response(resp.body(()).unwrap()).await;
                            let text = if events {
                                "data: one\n\ndata: two\n\n".to_string()
                            } else {
                                format!("{} {} {}", req.method(), req.uri(), String::from_utf8_lossy(&body))
                            };
                            let _ = stream.send_data(Bytes::from(text)).await;
                            let _ = stream.finish().await;
                        });
                    }
                });
            }
        });
        (port, accepted)
    }

    /// An HTTP/1.1 server over TLS on 127.0.0.1 (`port`, or any) answering `h1 <request line>`
    /// with `alt_svc` as its Alt-Svc header if given. Returns the port and the requests count.
    pub(crate) async fn h1_server(port: u16, alt_svc: Option<String>) -> (u16, Arc<AtomicU64>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls(&[b"http/1.1"])));
        let requests = Arc::new(AtomicU64::new(0));
        let count = requests.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (tls, count, alt_svc) = (tls.clone(), count.clone(), alt_svc.clone());
                tokio::spawn(async move {
                    let Ok(mut s) = tls.accept(tcp).await else { return };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    count.fetch_add(1, Ordering::Relaxed);
                    let line = String::from_utf8_lossy(&buf).lines().next().unwrap_or_default().to_string();
                    let body = format!("h1 {line}");
                    let alt = alt_svc.map(|a| format!("Alt-Svc: {a}\r\n")).unwrap_or_default();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\n{alt}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        (port, requests)
    }

    /// A UDP socket on 127.0.0.1 that counts the datagrams it receives and never answers.
    async fn udp_sink() -> (u16, Arc<AtomicU64>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let got = Arc::new(AtomicU64::new(0));
        let count = got.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while socket.recv_from(&mut buf).await.is_ok() {
                count.fetch_add(1, Ordering::Relaxed);
            }
        });
        (port, got)
    }

    fn client(include: &[String], http3: bool) -> Client {
        let scope = ScopeSpec { name: None, include: include.to_vec(), exclude: vec![] };
        let guard = Guard::from_specs(vec![scope]).unwrap();
        Client::new(SendOptions { guard: Some(guard), http3, ..Default::default() })
    }

    fn target(port: u16) -> Target {
        Target { scheme: "https".into(), host: "127.0.0.1".into(), port }
    }

    fn get(path: &str, port: u16, version: &str) -> RawRequest {
        RawRequest::from_bytes(format!("GET {path} {version}\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes())
    }

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    #[tokio::test]
    async fn sends_over_http3_on_one_connection() {
        let (port, accepted) = h3_server(0, &[ALPN], None).await;
        let c = client(&["127.0.0.1".into()], true);
        for i in 0..3 {
            let raw = format!(
                "POST /p?i={i} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi"
            );
            let ex = c.send(&RawRequest::from_bytes(raw.into_bytes()), &target(port)).await.unwrap();
            assert!(ex.response.starts_with(b"HTTP/3 200\r\n"), "{}", text(&ex.response));
            assert!(ex.response.ends_with(format!("POST https://127.0.0.1:{port}/p?i={i} hi").as_bytes()));
            assert!(ex.request.starts_with(format!("POST /p?i={i} HTTP/3\r\nhost: 127.0.0.1:{port}\r\n").as_bytes()));
            assert!(!text(&ex.request).contains("connection:"), "{}", text(&ex.request));
        }
        assert_eq!((accepted.load(Ordering::Relaxed), c.connections_opened()), (1, 1));
        assert!(c.h3_notes().is_empty());
        // A recorded HTTP/3 request goes back over HTTP/3 without the option.
        let plain = client(&["127.0.0.1".into()], false);
        let ex = plain.send(&get("/again", port, "HTTP/3"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/3 200\r\n"), "{}", text(&ex.response));
        // An event stream is read as it arrives, as over HTTP/1.1 and HTTP/2.
        let ex = c.send(&get("/events", port, "HTTP/1.1"), &target(port)).await.unwrap();
        let read = ex.stream.expect("an event stream");
        assert_eq!(read.events.len(), 2, "{read:?}");
    }

    #[tokio::test]
    async fn falls_back_to_tcp_when_http3_is_not_offered() {
        // TCP and UDP on the same port: HTTP/1.1 over TLS, and a QUIC server without h3.
        let (port, requests) = h1_server(0, None).await;
        let (_, accepted) = h3_server(port, &[b"not-h3"], None).await;
        let c = client(&["127.0.0.1".into()], true);
        let ex = c.send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
        assert!(ex.request.starts_with(b"GET /a HTTP/1.1\r\n"), "{}", text(&ex.request));
        let notes = c.h3_notes();
        assert!(notes[0].contains("did not negotiate HTTP/3") && notes[0].ends_with("sent over TCP"), "{notes:?}");
        // A recorded HTTP/3 request goes over TCP as HTTP/1.1, and the origin isn't tried
        // again for a while.
        let ex = c.send(&get("/b", port, "HTTP/3"), &target(port)).await.unwrap();
        assert!(ex.response.ends_with(b"h1 GET /b HTTP/1.1"), "{}", text(&ex.response));
        assert_eq!(requests.load(Ordering::Relaxed), 2);
        assert_eq!(accepted.load(Ordering::Relaxed), 0);
        // Plain http never tries QUIC.
        let http = Target { scheme: "http".into(), ..target(port) };
        let fresh = client(&["127.0.0.1".into()], true);
        let _ = fresh.send(&get("/c", port, "HTTP/1.1"), &http).await;
        assert!(fresh.h3_notes()[0].contains("HTTP/3 needs https"));
    }

    #[tokio::test]
    async fn falls_back_to_tcp_when_udp_gets_no_answer() {
        let (port, requests) = h1_server(0, None).await;
        // Nothing answers on the UDP port: the handshake times out.
        let c = client(&["127.0.0.1".into()], true);
        let started = std::time::Instant::now();
        let ex = c.send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
        assert!(c.h3_notes()[0].contains("no HTTP/3 connection"), "{:?}", c.h3_notes());
        // The next request doesn't wait for another handshake.
        let again = std::time::Instant::now();
        c.send(&get("/b", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(again.elapsed() < Duration::from_secs(2) && started.elapsed() >= H3_WAIT, "{:?}", again.elapsed());
        assert_eq!(requests.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn concurrent_and_hurried_requests_still_reach_tcp_when_udp_gets_no_answer() {
        let (port, requests) = h1_server(0, None).await;
        // Senders that wait for the same handshake don't each try again once it failed.
        let c = client(&["127.0.0.1".into()], true);
        let started = std::time::Instant::now();
        let sends: Vec<_> = (0..4)
            .map(|i| {
                let c = c.clone();
                tokio::spawn(async move { c.send(&get(&format!("/{i}"), port, "HTTP/1.1"), &target(port)).await })
            })
            .collect();
        for s in sends {
            assert!(s.await.unwrap().unwrap().response.starts_with(b"HTTP/1.1 200"));
        }
        assert!(started.elapsed() < Duration::from_secs(6), "{:?}", started.elapsed());
        // A short timeout leaves time for TCP.
        let scope = ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] };
        let opts = SendOptions {
            guard: Some(Guard::from_specs(vec![scope]).unwrap()),
            http3: true,
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let ex = Client::new(opts).send(&get("/short", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
        assert_eq!(requests.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn a_recorded_http3_request_is_framed_for_http1() {
        let raw = RawRequest::from_bytes(b"POST /x HTTP/3\r\nhost: a.test\r\n\r\na=1".to_vec());
        let tcp = crate::http::client::tcp_form(&raw, false);
        assert_eq!(tcp.as_bytes(), b"POST /x HTTP/1.1\r\nhost: a.test\r\nContent-Length: 3\r\n\r\na=1");
        // HTTP/2 frames the body itself, and a request with framing keeps it.
        assert!(crate::http::client::tcp_form(&raw, true)
            .as_bytes()
            .starts_with(b"POST /x HTTP/2\r\nhost: a.test\r\n\r\n"));
        let framed = RawRequest::from_bytes(b"POST /x HTTP/3\r\ncontent-length: 3\r\n\r\na=1".to_vec());
        assert_eq!(
            crate::http::client::tcp_form(&framed, false).as_bytes(),
            b"POST /x HTTP/1.1\r\ncontent-length: 3\r\n\r\na=1"
        );
        let plain = RawRequest::from_bytes(b"GET / HTTP/1.1\r\n\r\n".to_vec());
        assert!(matches!(crate::http::client::tcp_form(&plain, false), std::borrow::Cow::Borrowed(_)));
    }

    /// The handshake time of the client, for the test above.
    const H3_WAIT: Duration = Duration::from_secs(3);

    #[tokio::test]
    async fn follows_alt_svc_to_an_endpoint_in_scope() {
        let (h3_port, accepted) = h3_server(0, &[ALPN], None).await;
        let (port, requests) = h1_server(0, Some(format!(r#"h3=":{h3_port}"; ma=60"#))).await;
        // A QUIC server without h3 on the TCP port, so the first try fails fast.
        h3_server(port, &[b"not-h3"], None).await;
        let c = client(&["127.0.0.1".into()], true);
        let ex = c.send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
        let ex = c.send(&get("/b", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/3 200\r\n"), "{}", text(&ex.response));
        // The request names the origin; it went to the advertised endpoint.
        assert!(ex.response.ends_with(format!("GET https://127.0.0.1:{port}/b ").as_bytes()));
        assert_eq!((requests.load(Ordering::Relaxed), accepted.load(Ordering::Relaxed)), (1, 1));
    }

    #[tokio::test]
    async fn refuses_http3_destinations_outside_the_scope() {
        // The scope lists the TCP origin's port only. Its Alt-Svc points at another port, where
        // a UDP socket counts what arrives.
        let (sink, got) = udp_sink().await;
        let (port, requests) = h1_server(0, Some(format!(r#"h3=":{sink}""#))).await;
        h3_server(port, &[b"not-h3"], None).await;
        let c = client(&[format!("127.0.0.1:{port}")], true);
        c.send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        let ex = c.send(&get("/b", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
        let notes = c.h3_notes().join("\n");
        assert!(notes.contains(&format!("Alt-Svc endpoint 127.0.0.1:{sink}")) && notes.contains("outside"), "{notes}");
        // A target outside the scope is refused outright, over HTTP/3 as over TCP.
        let err = c.send(&get("/c", sink, "HTTP/1.1"), &target(sink)).await.unwrap_err();
        assert!(matches!(err, crate::Error::OutOfScope(_)), "{err}");
        let err = c.send(&get("/c", sink, "HTTP/3"), &target(sink)).await.unwrap_err();
        assert!(matches!(err, crate::Error::OutOfScope(_)), "{err}");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(got.load(Ordering::Relaxed), 0, "nothing reaches the refused port");
        assert_eq!(requests.load(Ordering::Relaxed), 2);
        // An advertised host the scope doesn't list is refused before any DNS lookup.
        let names = client(&["app.test".into()], true);
        let guard = names.options().guard.clone().unwrap();
        assert!(matches!(guard.resolve("evil.test", 443).await, Err(crate::Error::OutOfScope(_))));
    }

    #[tokio::test]
    async fn informational_responses_come_before_the_answer_and_big_headers_are_refused() {
        let (port, _) = h3_server(0, &[ALPN], None).await;
        let c = client(&["127.0.0.1".into()], true);
        let ex = c.send(&get("/hints", port, "HTTP/1.1"), &target(port)).await.unwrap();
        let t = text(&ex.response);
        assert!(t.starts_with("HTTP/3 103\r\n") && t.contains("\r\n\r\nHTTP/3 200\r\n"), "{t}");
        assert!(t.ends_with(&format!("GET https://127.0.0.1:{port}/hints ")), "{t}");
        let head = crate::http::parse_response_head(crate::http::client::final_response(&ex.response)).unwrap();
        assert_eq!((head.version.as_str(), head.status), ("HTTP/3", 200));
        // A header section larger than an HTTP/1.1 head may be is an error, not a response.
        assert!(c.send(&get("/big", port, "HTTP/1.1"), &target(port)).await.is_err());
    }

    #[tokio::test]
    async fn a_server_that_never_lets_http3_start_leaves_time_for_tcp() {
        let (port, requests) = h1_server(0, None).await;
        // QUIC completes, but HTTP/3 can't open its control stream: no stream credit.
        let (_, accepted) = h3_server_with(port, &[ALPN], None, Some(0)).await;
        let scope = ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] };
        let opts = SendOptions {
            guard: Some(Guard::from_specs(vec![scope]).unwrap()),
            http3: true,
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let c = Client::new(opts);
        let started = std::time::Instant::now();
        let ex = c.send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(c.h3_notes()[0].contains("no HTTP/3 connection"), "{:?}", c.h3_notes());
        assert_eq!((requests.load(Ordering::Relaxed), accepted.load(Ordering::Relaxed)), (1, 1));
    }

    #[tokio::test]
    async fn a_withdrawn_alt_svc_endpoint_is_not_used_again() {
        let (alt, alt_accepted) = h3_server(0, &[ALPN], None).await;
        let (port, _) = h1_server(0, Some(format!(r#"h3=":{alt}""#))).await;
        h3_server(port, &[b"not-h3"], None).await;
        let c = client(&["127.0.0.1".into()], true);
        c.send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        let ex = c.send(&get("/b", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/3 200"), "{}", text(&ex.response));
        // The endpoint withdraws itself: its pooled connection isn't used again.
        let ex = c.send(&get("/clear", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/3 200"), "{}", text(&ex.response));
        let ex = c.send(&get("/d", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
        assert_eq!(alt_accepted.load(Ordering::Relaxed), 1);
        assert!(
            c.h3_notes().iter().any(|n| n.contains(&format!("Alt-Svc endpoint 127.0.0.1:{alt}"))),
            "{:?}",
            c.h3_notes()
        );
    }

    #[tokio::test]
    async fn a_recorded_http3_request_learns_alt_svc_without_the_option() {
        let (alt, accepted) = h3_server(0, &[ALPN], None).await;
        let (port, _) = h1_server(0, Some(format!(r#"h3=":{alt}""#))).await;
        h3_server(port, &[b"not-h3"], None).await;
        let c = client(&["127.0.0.1".into()], false);
        let ex = c.send(&get("/a", port, "HTTP/3"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
        let ex = c.send(&get("/b", port, "HTTP/3"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/3 200"), "{}", text(&ex.response));
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn an_http2_fallback_is_recorded_as_http2() {
        let (port, _) = crate::http::h2::tests::h2_server(Some(vec![b"h2".to_vec()])).await;
        h3_server(port, &[b"not-h3"], None).await;
        let scope = ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] };
        let opts = SendOptions {
            guard: Some(Guard::from_specs(vec![scope]).unwrap()),
            http2: true,
            http3: true,
            ..Default::default()
        };
        let ex = Client::new(opts).send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/2 200"), "{}", text(&ex.response));
        assert!(ex.request.starts_with(b"GET /a HTTP/2\r\n"), "{}", text(&ex.request));
    }

    #[tokio::test]
    async fn advertised_endpoints_the_scope_or_a_proxy_rule_keeps_out_are_not_contacted() {
        use crate::connection::{ConnectionSettings, UpstreamRule};
        // A host the scope doesn't list (with an address scope, its addresses decide).
        let (port, _) = h1_server(0, Some(r#"h3="evil.test:443""#.into())).await;
        h3_server(port, &[b"not-h3"], None).await;
        let c = client(&["127.0.0.1".into()], true);
        c.send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        let ex = c.send(&get("/b", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
        let notes = c.h3_notes().join("\n");
        assert!(notes.contains("Alt-Svc endpoint evil.test:443") && notes.contains("out of scope"), "{notes}");
        // A host in scope that the connection settings send through a proxy.
        let (sink, got) = udp_sink().await;
        let (port, _) = h1_server(0, Some(format!(r#"h3="localhost:{sink}""#))).await;
        h3_server(port, &[b"not-h3"], None).await;
        let c = client(&["127.0.0.1".into(), "localhost".into()], true);
        let rule = UpstreamRule {
            host: "localhost".into(),
            proxy: Some("http://127.0.0.1:1".into()),
            username: None,
            password_env: None,
        };
        let settings = ConnectionSettings { upstream: vec![rule], ..Default::default() };
        c.options().guard.as_ref().unwrap().net.set(settings.compile(vec![]).unwrap());
        c.send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        c.send(&get("/b", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(c.h3_notes().join("\n").contains("goes through an upstream proxy"), "{:?}", c.h3_notes());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(got.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_refused_alt_svc_endpoint_does_not_turn_http3_back_on() {
        // Nothing answers QUIC on the origin's own UDP port (a handshake waits it out), and the
        // endpoint it keeps advertising is out of scope.
        let (port, requests) = h1_server(0, Some(r#"h3="evil.test:443""#.into())).await;
        let c = client(&["127.0.0.1".into()], true);
        // The first request waits for its own address; the second learnt the endpoint, finds
        // it refused, and waits once more.
        c.send(&get("/a", port, "HTTP/1.1"), &target(port)).await.unwrap();
        c.send(&get("/b", port, "HTTP/1.1"), &target(port)).await.unwrap();
        assert!(c.h3_notes().join("\n").contains("Alt-Svc endpoint evil.test:443"), "{:?}", c.h3_notes());
        // The same refused endpoint, advertised again, isn't news: HTTP/3 stays off for the
        // origin rather than costing every request another handshake.
        for path in ["/c", "/d", "/e"] {
            let started = std::time::Instant::now();
            let ex = c.send(&get(path, port, "HTTP/1.1"), &target(port)).await.unwrap();
            assert!(ex.response.starts_with(b"HTTP/1.1 200"), "{}", text(&ex.response));
            assert!(started.elapsed() < Duration::from_secs(1), "{path}: {:?}", started.elapsed());
        }
        assert_eq!(requests.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn host_and_sni_refusals_send_nothing_over_quic() {
        let (port, accepted) = h3_server(0, &[ALPN], None).await;
        let scope = || ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] };
        // As through MCP without --host-header-test.
        let refuse = Client::new(SendOptions {
            guard: Some(Guard::from_specs(vec![scope()]).unwrap()),
            http3: true,
            host: crate::http::client::HostPolicy::Refuse,
            ..Default::default()
        });
        let foreign = RawRequest::from_bytes(b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n".to_vec());
        let err = refuse.send(&foreign, &target(port)).await.unwrap_err();
        assert!(matches!(err, crate::Error::OutOfScope(_)), "{err}");
        let sni = Client::new(SendOptions {
            guard: Some(Guard::from_specs(vec![scope()]).unwrap()),
            http3: true,
            sni: Some("other.test".into()),
            ..Default::default()
        });
        let err = sni.send(&get("/", port, "HTTP/1.1"), &target(port)).await.unwrap_err();
        assert!(matches!(err, crate::Error::OutOfScope(_)), "{err}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(accepted.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn an_upstream_proxy_keeps_requests_on_tcp() {
        use crate::connection::{ConnectionSettings, UpstreamRule};
        // A target the connection settings send through a proxy: nothing goes to it over UDP.
        let (sink, got) = udp_sink().await;
        let c = client(&["127.0.0.1".into()], true);
        let rule = UpstreamRule {
            host: "*".into(),
            proxy: Some("http://127.0.0.1:1".into()),
            username: None,
            password_env: None,
        };
        let settings = ConnectionSettings { upstream: vec![rule], ..Default::default() };
        c.options().guard.as_ref().unwrap().net.set(settings.compile(vec![]).unwrap());
        // The proxy isn't there, so the TCP request fails too.
        assert!(c.send(&get("/", sink, "HTTP/1.1"), &target(sink)).await.is_err());
        assert!(c.h3_notes()[0].contains("upstream proxy"), "{:?}", c.h3_notes());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(got.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn the_socket_only_reaches_the_checked_address() {
        let (allowed, _) = udp_sink().await;
        let (other, got) = udp_sink().await;
        let peer = SocketAddr::from(([127, 0, 0, 1], allowed));
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let inner = quinn::TokioRuntime.wrap_udp_socket(udp).unwrap();
        let guarded = GuardedUdp { inner, peer };
        let datagram = |to: u16| Transmit {
            destination: SocketAddr::from(([127, 0, 0, 1], to)),
            ecn: None,
            contents: b"x",
            segment_size: None,
            src_ip: None,
        };
        let err = guarded.try_send(&datagram(other)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // IPv4-mapped is the same address, and only that one.
        assert!(same_addr(peer, SocketAddr::from(([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1], allowed))));
        assert!(!same_addr(peer, SocketAddr::from(([127, 0, 0, 2], allowed))));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(got.load(Ordering::Relaxed), 0);
    }
}
