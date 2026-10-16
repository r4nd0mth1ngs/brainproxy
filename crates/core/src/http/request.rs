//! Raw HTTP/1.x request handling.
//!
//! Requests are kept as raw bytes so malformed or unusual requests (smuggling,
//! CRLF injection, duplicate headers) survive untouched. Helpers only rewrite
//! the bytes when explicitly asked to.

use serde::Serialize;

use crate::error::{Error, Result};
use crate::http::target::Target;

/// A raw HTTP/1.x request plus a lightweight view of its head.
#[derive(Debug, Clone)]
pub struct RawRequest {
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl RawRequest {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Builds a request in the style of curl: method, absolute URL, headers, body.
    pub fn build(method: &str, url: &str, headers: &[(String, String)], body: &[u8]) -> Result<(Self, Target)> {
        let target = Target::from_url(url)?;
        let parsed = url::Url::parse(url).map_err(|e| Error::InvalidInput(format!("invalid URL {url:?}: {e}")))?;
        let mut path = parsed.path().to_string();
        if let Some(q) = parsed.query() {
            path.push('?');
            path.push_str(q);
        }
        let mut out = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", target.host_header());
        let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
        for (k, v) in headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        if !has("user-agent") {
            out.push_str(concat!("User-Agent: brainproxy/", env!("CARGO_PKG_VERSION"), "\r\n"));
        }
        if !has("accept") {
            out.push_str("Accept: */*\r\n");
        }
        if !body.is_empty() && !has("content-length") {
            out.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        if !has("connection") {
            out.push_str("Connection: close\r\n");
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(body);
        Ok((Self { bytes }, target))
    }

    /// Splits at the end of the header block. Returns (head, body).
    pub fn split(&self) -> (&[u8], &[u8]) {
        split_head_body(&self.bytes)
    }

    pub fn head(&self) -> Result<RequestHead> {
        let (head, _) = self.split();
        parse_request_head(head)
    }

    pub fn body(&self) -> &[u8] {
        self.split().1
    }

    /// Converts bare `\n` line endings in the head to `\r\n`. Request files are
    /// often written by editors or LLMs with Unix line endings. The body is left alone.
    pub fn normalize_line_endings(self) -> Self {
        let (head, body) = split_head_body_lenient(&self.bytes);
        let mut out = Vec::with_capacity(self.bytes.len() + 32);
        let mut prev = 0u8;
        for &b in head {
            if b == b'\n' && prev != b'\r' {
                out.push(b'\r');
            }
            out.push(b);
            prev = b;
        }
        // Make sure the head ends with an empty line.
        if !out.ends_with(b"\r\n\r\n") {
            if out.ends_with(b"\r\n") {
                out.extend_from_slice(b"\r\n");
            } else {
                out.extend_from_slice(b"\r\n\r\n");
            }
        }
        out.extend_from_slice(body);
        Self { bytes: out }
    }

    /// Sets the header, replacing every existing header with the same name
    /// (case-insensitive), or appends it if missing.
    pub fn set_header(self, name: &str, value: &str) -> Self {
        let (head, body) = self.split();
        let head = String::from_utf8_lossy(head).into_owned();
        let mut lines: Vec<&str> = head.trim_end_matches("\r\n").split("\r\n").collect();
        let new_line = format!("{name}: {value}");
        let mut replaced = false;
        let mut i = 1;
        while i < lines.len() {
            let is_match = lines[i].split_once(':').map(|(k, _)| k.trim().eq_ignore_ascii_case(name)).unwrap_or(false);
            if is_match {
                if replaced {
                    lines.remove(i);
                    continue;
                }
                lines[i] = &new_line;
                replaced = true;
            }
            i += 1;
        }
        if !replaced {
            lines.push(&new_line);
        }
        let mut out = lines.join("\r\n").into_bytes();
        out.extend_from_slice(b"\r\n\r\n");
        out.extend_from_slice(body);
        Self { bytes: out }
    }

    pub fn remove_header(self, name: &str) -> Self {
        let (head, body) = self.split();
        let head = String::from_utf8_lossy(head).into_owned();
        let lines: Vec<&str> = head
            .trim_end_matches("\r\n")
            .split("\r\n")
            .enumerate()
            .filter(|(i, l)| {
                *i == 0 || !l.split_once(':').map(|(k, _)| k.trim().eq_ignore_ascii_case(name)).unwrap_or(false)
            })
            .map(|(_, l)| l)
            .collect();
        let mut out = lines.join("\r\n").into_bytes();
        out.extend_from_slice(b"\r\n\r\n");
        out.extend_from_slice(body);
        Self { bytes: out }
    }

    /// Rewrites `Content-Length` to the actual body length, like Burp's
    /// "Update Content-Length". Only touches requests that already have the header
    /// or have a non-empty body, and never touches chunked requests.
    pub fn update_content_length(self) -> Self {
        let Ok(head) = self.head() else { return self };
        let header = |n: &str| head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n));
        if header("transfer-encoding").is_some() {
            return self;
        }
        let len = self.body().len();
        match header("content-length") {
            Some((_, v)) if v.trim() == len.to_string() => self,
            Some(_) => self.set_header("Content-Length", &len.to_string()),
            None if len > 0 => self.set_header("Content-Length", &len.to_string()),
            None => self,
        }
    }

    /// Works out where to send this request: absolute-form request target first,
    /// then the Host header with the given default scheme.
    pub fn infer_target(&self, default_scheme: &str) -> Result<Target> {
        let head = self.head()?;
        if head.target.starts_with("http://") || head.target.starts_with("https://") {
            return Target::from_url(&head.target);
        }
        let host = head
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.trim().to_string())
            .ok_or_else(|| Error::InvalidInput("request has no Host header; pass --target".into()))?;
        Target::from_url(&format!("{default_scheme}://{host}"))
    }
}

/// Splits a message at the first `\r\n\r\n`. Without one, the whole input is head.
pub fn split_head_body(bytes: &[u8]) -> (&[u8], &[u8]) {
    match find(bytes, b"\r\n\r\n") {
        Some(i) => (&bytes[..i + 4], &bytes[i + 4..]),
        None => (bytes, &[]),
    }
}

/// Like [`split_head_body`] but also accepts `\n\n` as the separator.
fn split_head_body_lenient(bytes: &[u8]) -> (&[u8], &[u8]) {
    let crlf = find(bytes, b"\r\n\r\n").map(|i| (i, 4));
    let lf = find(bytes, b"\n\n").map(|i| (i, 2));
    let best = match (crlf, lf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, b) => a.or(b),
    };
    match best {
        Some((i, n)) => (&bytes[..i + n], &bytes[i + n..]),
        None => (bytes, &[]),
    }
}

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_request_head(head: &[u8]) -> Result<RequestHead> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.splitn(3, ' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v)) if !m.is_empty() => (m, t, v),
        (Some(m), Some(t), None) if !m.is_empty() => (m, t, ""),
        _ => return Err(Error::InvalidInput(format!("bad request line: {request_line:?}"))),
    };
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.to_string(), v.trim_start().to_string())))
        .collect();
    Ok(RequestHead { method: method.to_string(), target: target.to_string(), version: version.to_string(), headers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_lf_and_updates_length() {
        let req = RawRequest::from_bytes(b"POST /x HTTP/1.1\nHost: a.test\nContent-Length: 1\n\nhello".to_vec())
            .normalize_line_endings()
            .update_content_length();
        assert_eq!(req.as_bytes(), b"POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n\r\nhello");
    }

    #[test]
    fn normalizes_head_without_blank_line() {
        let req = RawRequest::from_bytes(b"GET / HTTP/1.1\nHost: a.test\n".to_vec()).normalize_line_endings();
        assert_eq!(req.as_bytes(), b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n");
    }

    #[test]
    fn set_header_replaces_duplicates() {
        let req = RawRequest::from_bytes(b"GET / HTTP/1.1\r\nX-A: 1\r\nHost: h\r\nx-a: 2\r\n\r\n".to_vec())
            .set_header("X-A", "3");
        assert_eq!(req.as_bytes(), b"GET / HTTP/1.1\r\nX-A: 3\r\nHost: h\r\n\r\n");
    }

    #[test]
    fn infers_target_from_host_and_absolute_form() {
        let req = RawRequest::from_bytes(b"GET / HTTP/1.1\r\nHost: example.test:8443\r\n\r\n".to_vec());
        let t = req.infer_target("https").unwrap();
        assert_eq!((t.scheme.as_str(), t.host.as_str(), t.port), ("https", "example.test", 8443));

        let req = RawRequest::from_bytes(b"GET http://a.test/x HTTP/1.1\r\n\r\n".to_vec());
        let t = req.infer_target("https").unwrap();
        assert_eq!((t.scheme.as_str(), t.port), ("http", 80));
    }

    #[test]
    fn build_creates_valid_request() {
        let (req, target) =
            RawRequest::build("POST", "http://a.test:81/p?q=1", &[("X-T".into(), "v".into())], b"abc").unwrap();
        let head = req.head().unwrap();
        assert_eq!(head.target, "/p?q=1");
        assert_eq!(target.port, 81);
        assert!(head.headers.contains(&("Host".into(), "a.test:81".into())));
        assert!(head.headers.contains(&("Content-Length".into(), "3".into())));
        assert_eq!(req.body(), b"abc");
    }
}
