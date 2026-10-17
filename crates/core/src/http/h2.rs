//! HTTP/2 over the guarded client, using the `h2` crate: ALPN `h2` for https,
//! prior knowledge (h2c) for http.
//!
//! Requests are written as HTTP/1.x text (like everything else in brainproxy)
//! and converted: the Host header becomes `:authority`, connection-specific
//! headers are dropped, and chunked bodies are de-chunked. Exchanges are
//! recorded in the same text form with `HTTP/2` as the version, so history,
//! passive rules, and `send --http2` work on them unchanged.

use bytes::Bytes;
use h2::client::SendRequest;

use crate::error::{Error, Result};
use crate::http::request::RawRequest;
use crate::http::response::dechunk;
use crate::http::target::Target;

/// Headers that HTTP/2 forbids (RFC 9113 8.2.2); `host` becomes `:authority`.
const DROPPED: &[&str] = &["host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/// A request ready for HTTP/2, and the text form that is recorded for it.
#[derive(Debug, Clone)]
pub struct H2Request {
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: http::HeaderMap,
    pub body: Bytes,
    /// `METHOD path HTTP/2`, `host`, the headers sent, and the body.
    pub recorded: Vec<u8>,
}

impl H2Request {
    /// Converts a raw HTTP/1.x request for sending to `target` over HTTP/2.
    pub fn from_raw(raw: &[u8], target: &Target) -> Result<Self> {
        let req = RawRequest::from_bytes(raw.to_vec());
        let head = req.head()?;
        let unfit = |what: &str| Error::InvalidInput(format!("can't be sent over HTTP/2: {what}"));
        let method = http::Method::from_bytes(head.method.as_bytes()).map_err(|_| unfit("method"))?;
        let path = match head.target.split_once("://") {
            Some((_, rest)) => rest.find('/').map_or("/", |i| &rest[i..]).to_string(),
            None => head.target.clone(),
        };
        let header = |n: &str| head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.trim());
        let authority = header("host").map(str::to_string).unwrap_or_else(|| target.host_header());
        let scheme = if target.is_tls() { "https" } else { "http" };
        let uri: http::Uri =
            format!("{scheme}://{authority}{path}").parse().map_err(|e| unfit(&format!("{authority}{path}: {e}")))?;

        let mut headers = http::HeaderMap::new();
        let mut recorded = format!("{method} {path} HTTP/2\r\nhost: {authority}\r\n");
        for (k, v) in &head.headers {
            let name = k.trim().to_ascii_lowercase();
            if DROPPED.contains(&name.as_str()) || (name == "te" && !v.eq_ignore_ascii_case("trailers")) {
                continue;
            }
            let hn = http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| unfit(&format!("header {k:?}")))?;
            let hv = http::HeaderValue::from_str(v).map_err(|_| unfit(&format!("value of {k:?}")))?;
            headers.append(hn, hv);
            recorded.push_str(&format!("{name}: {v}\r\n"));
        }
        recorded.push_str("\r\n");
        let body = req.split().1;
        let chunked = header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let body = Bytes::from(if chunked { dechunk(body) } else { body.to_vec() });
        let mut recorded = recorded.into_bytes();
        recorded.extend_from_slice(&body);
        Ok(Self { method, uri, headers, body, recorded })
    }

    pub fn request(&self) -> http::Request<()> {
        let mut r = http::Request::new(());
        *r.method_mut() = self.method.clone();
        *r.uri_mut() = self.uri.clone();
        *r.headers_mut() = self.headers.clone();
        r
    }
}

/// The text form of a response: `HTTP/2 <status>`, headers, blank line, body.
pub fn response_bytes(parts: &http::response::Parts, body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/2 {}\r\n", parts.status.as_u16());
    for (k, v) in &parts.headers {
        out.push_str(&format!("{k}: {}\r\n", String::from_utf8_lossy(v.as_bytes())));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

pub(crate) fn h2_error(e: h2::Error) -> Error {
    if e.is_io() {
        if let Some(io) = e.into_io() {
            return Error::Io(io);
        }
        return Error::Protocol("HTTP/2: I/O error".into());
    }
    Error::Protocol(format!("HTTP/2: {e}"))
}

/// An error from setting up HTTP/2 or the first exchange on a new connection,
/// reworded: on http:// targets it usually means the server doesn't speak h2c.
pub(crate) fn setup_error(target: &Target, e: Error) -> Error {
    if matches!(e, Error::OutOfScope(_) | Error::Timeout(_) | Error::Connect(_) | Error::InvalidInput(_)) {
        return e;
    }
    let hint = if target.is_tls() { "" } else { "; http:// targets must accept HTTP/2 prior knowledge (h2c)" };
    Error::Protocol(format!("{}: HTTP/2 failed ({e}){hint}", target.origin()))
}

/// Reads a whole response body, giving flow-control capacity back as it goes.
pub async fn read_response(fut: h2::client::ResponseFuture) -> Result<Vec<u8>> {
    let (parts, mut body) = fut.await.map_err(h2_error)?.into_parts();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_error)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    Ok(response_bytes(&parts, &buf))
}

/// Sends one request on an HTTP/2 connection and reads the response.
pub async fn round_trip(sender: SendRequest<Bytes>, req: &H2Request) -> Result<Vec<u8>> {
    let mut sender = sender.ready().await.map_err(h2_error)?;
    let (fut, mut stream) = sender.send_request(req.request(), req.body.is_empty()).map_err(h2_error)?;
    if !req.body.is_empty() {
        stream.send_data(req.body.clone(), true).map_err(h2_error)?;
    }
    read_response(fut).await
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use tokio::net::TcpListener;

    use super::*;
    use crate::guard::{Guard, ScopeSpec};
    use crate::http::{Client, SendOptions};

    /// An HTTP/2 server answering `<method> <uri> <body>`; with `alpn`, over TLS
    /// offering those protocols. Returns the port and the accepted-connection count.
    pub(crate) async fn h2_server(alpn: Option<Vec<Vec<u8>>>) -> (u16, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let tls = alpn.map(|alpn| {
            let dir = std::env::temp_dir().join(format!("bp-h2-ca-{}-{port}", std::process::id()));
            let (ca, _) = crate::proxy::ca::CertAuthority::load_or_create(&dir).unwrap();
            let mut cfg = (*ca.server_config("127.0.0.1").unwrap()).clone();
            cfg.alpn_protocols = alpn;
            tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
        });
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                let tls = tls.clone();
                tokio::spawn(async move {
                    match tls {
                        Some(a) => {
                            if let Ok(s) = a.accept(tcp).await {
                                serve(s).await
                            }
                        }
                        None => serve(tcp).await,
                    }
                });
            }
        });
        (port, accepted)
    }

    async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: S) {
        let Ok(mut conn) = h2::server::handshake(s).await else { return };
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            tokio::spawn(async move {
                let (parts, mut body) = req.into_parts();
                let mut data = Vec::new();
                while let Some(Ok(c)) = body.data().await {
                    let _ = body.flow_control().release_capacity(c.len());
                    data.extend_from_slice(&c);
                }
                let text = format!("{} {} {}", parts.method, parts.uri, String::from_utf8_lossy(&data));
                let resp = http::Response::builder().header("x-h2", "yes").body(()).unwrap();
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(Bytes::from(text), true);
                }
            });
        }
    }

    pub(crate) fn client(http2: bool) -> Client {
        let scope = ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] };
        let guard = Guard::from_specs(vec![scope]).unwrap();
        Client::new(SendOptions { guard: Some(guard), http2, ..Default::default() })
    }

    #[tokio::test]
    async fn sends_over_h2c_and_tls_on_one_connection() {
        for alpn in [None, Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()])] {
            let tls = alpn.is_some();
            let (port, accepted) = h2_server(alpn).await;
            let scheme = if tls { "https" } else { "http" };
            let target = Target { scheme: scheme.into(), host: "127.0.0.1".into(), port };
            let c = client(true);
            for i in 0..3 {
                let raw = format!("POST /p?i={i} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi");
                let ex = c.send(&RawRequest::from_bytes(raw.into_bytes()), &target).await.unwrap();
                let want = format!("POST {scheme}://127.0.0.1:{port}/p?i={i} hi");
                assert!(ex.response.starts_with(b"HTTP/2 200\r\n"), "{}", String::from_utf8_lossy(&ex.response));
                assert!(ex.response.ends_with(want.as_bytes()), "{}", String::from_utf8_lossy(&ex.response));
                assert!(ex.request.starts_with(format!("POST /p?i={i} HTTP/2\r\n").as_bytes()));
            }
            assert_eq!(accepted.load(Ordering::Relaxed), 1);
            // A recorded HTTP/2 request is re-sent over HTTP/2 without the flag.
            let ex = client(false)
                .send(
                    &RawRequest::from_bytes(
                        format!("GET /again HTTP/2\r\nhost: 127.0.0.1:{port}\r\n\r\n").into_bytes(),
                    ),
                    &target,
                )
                .await
                .unwrap();
            assert!(ex.response.ends_with(format!("GET {scheme}://127.0.0.1:{port}/again ").as_bytes()));
        }
    }

    #[tokio::test]
    async fn refuses_servers_without_h2_alpn() {
        let req = RawRequest::from_bytes(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec());
        // A server that only offers http/1.1, and one that ignores ALPN.
        for alpn in [vec![b"http/1.1".to_vec()], vec![]] {
            let (port, _) = h2_server(Some(alpn)).await;
            let target = Target { scheme: "https".into(), host: "127.0.0.1".into(), port };
            let err = client(true).send(&req, &target).await.unwrap_err();
            assert!(err.to_string().contains("did not negotiate HTTP/2"), "{err}");
        }
        let port = 1;
        // Out of scope stays out of scope over HTTP/2.
        let other = Target { scheme: "https".into(), host: "127.0.0.2".into(), port };
        assert!(matches!(client(true).send(&req, &other).await, Err(Error::OutOfScope(_))));
    }

    #[test]
    fn converts_raw_requests() {
        let t = Target { scheme: "https".into(), host: "a.test".into(), port: 443 };
        let raw = b"POST http://ignored/x?y=1 HTTP/1.1\r\nHost: a.test:8443\r\nConnection: keep-alive\r\nX-A: 1\r\n\
                    Transfer-Encoding: chunked\r\nTE: gzip\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let r = H2Request::from_raw(raw, &t).unwrap();
        assert_eq!(r.uri.to_string(), "https://a.test:8443/x?y=1");
        assert_eq!(r.headers.len(), 1);
        assert_eq!(&r.body[..], b"abc");
        assert_eq!(r.recorded, b"POST /x?y=1 HTTP/2\r\nhost: a.test:8443\r\nx-a: 1\r\n\r\nabc");
        // Line breaks can't be smuggled into an HTTP/2 header value.
        assert!(H2Request::from_raw(b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x01b\r\n\r\n", &t).is_err());
    }

    #[test]
    fn response_text_parses_as_a_response() {
        let mut r = http::Response::new(());
        r.headers_mut().insert("content-type", "text/plain".parse().unwrap());
        let (parts, _) = r.into_parts();
        let bytes = response_bytes(&parts, b"hi");
        let head = crate::http::parse_response_head(&bytes).unwrap();
        assert_eq!((head.version.as_str(), head.status), ("HTTP/2", 200));
        assert_eq!(head.header("content-type"), Some("text/plain"));
    }
}
