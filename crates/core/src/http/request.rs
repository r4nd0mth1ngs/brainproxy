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
        let parsed = url::Url::parse(url).map_err(|e| {
            let hint = if url.contains("://") {
                String::new()
            } else {
                format!("; add the scheme: http://{url} or https://{url}")
            };
            Error::InvalidInput(format!("invalid URL {url:?}: {e}{hint}"))
        })?;
        let mut path = parsed.path().to_string();
        if let Some(q) = parsed.query() {
            path.push('?');
            path.push_str(q);
        }
        for (k, v) in headers {
            check_header(k, v)?;
        }
        let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
        // A Host header given takes the place of the target's, first, rather than adding a second.
        let host = |(k, _): &&(String, String)| k.eq_ignore_ascii_case("host");
        let mut out = format!("{method} {path} HTTP/1.1\r\n");
        if !has("host") {
            out.push_str(&format!("Host: {}\r\n", target.host_header()));
        }
        for (k, v) in headers.iter().filter(host).chain(headers.iter().filter(|h| !host(h))) {
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
    /// (case-insensitive), or appends it if missing. Other lines keep their bytes.
    pub fn set_header(self, name: &str, value: &str) -> Self {
        let (head, body) = self.split();
        let new_line = format!("{name}: {value}");
        let mut lines: Vec<&[u8]> = Vec::new();
        let mut replaced = false;
        for (i, line) in head_lines(head).into_iter().enumerate() {
            if i > 0 && is_header(line, name) {
                if !replaced {
                    lines.push(new_line.as_bytes());
                    replaced = true;
                }
            } else {
                lines.push(line);
            }
        }
        if !replaced {
            lines.push(new_line.as_bytes());
        }
        Self { bytes: join_head(&lines, body) }
    }

    pub fn remove_header(self, name: &str) -> Self {
        let (head, body) = self.split();
        let lines: Vec<&[u8]> = head_lines(head)
            .into_iter()
            .enumerate()
            .filter(|(i, l)| *i == 0 || !is_header(l, name))
            .map(|(_, l)| l)
            .collect();
        Self { bytes: join_head(&lines, body) }
    }

    /// Rewrites `Content-Length` to the actual body length, like other proxy tools'
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

/// Refuses a header name or value given as input (`-H`, a profile's, a collection's) that holds
/// a CR, LF or NUL: written into a request, a line break would start another header (a Host,
/// say). A name must also be non-empty and hold no colon or space.
pub fn check_header(name: &str, value: &str) -> Result<()> {
    let breaks = |s: &str| s.contains(['\r', '\n', '\0']);
    if breaks(name) || breaks(value) {
        return Err(Error::InvalidInput(format!("header {name:?}: a name or value can't hold a line break or NUL")));
    }
    if name.trim().is_empty() || name.contains([':', ' ', '\t']) {
        return Err(Error::InvalidInput(format!("bad header name {name:?}")));
    }
    Ok(())
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

/// The lines of a request head, without the blank line that ends it.
fn head_lines(head: &[u8]) -> Vec<&[u8]> {
    let mut h = head;
    while let Some(rest) = h.strip_suffix(b"\r\n") {
        h = rest;
    }
    let mut lines = Vec::new();
    while let Some(i) = h.windows(2).position(|w| w == b"\r\n") {
        lines.push(&h[..i]);
        h = &h[i + 2..];
    }
    lines.push(h);
    lines
}

/// Whether a head line is the header `name` (case-insensitive).
fn is_header(line: &[u8], name: &str) -> bool {
    line.iter().position(|&b| b == b':').is_some_and(|i| line[..i].trim_ascii().eq_ignore_ascii_case(name.as_bytes()))
}

fn join_head(lines: &[&[u8]], body: &[u8]) -> Vec<u8> {
    let mut out = lines.join(&b"\r\n"[..]);
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// The origin-form target (`/path?query`) of an absolute-form one, given what follows its
/// `scheme://`. The authority ends at the first `/`, `?` or `#` (RFC 3986 3.2), so
/// `a.test?next=http://b.test/x` is `/?next=http://b.test/x`, not `//b.test/x`, and
/// `a.test?id=1` keeps its query.
pub fn origin_form(after_scheme: &str) -> String {
    match after_scheme.find(['/', '?', '#']).map(|i| (i, after_scheme.as_bytes()[i])) {
        Some((i, b'/')) => after_scheme[i..].to_string(),
        Some((i, b'?')) => format!("/{}", &after_scheme[i..]),
        _ => "/".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_form_ends_the_authority_at_a_path_query_or_fragment() {
        assert_eq!(origin_form("a.test/x?y=1"), "/x?y=1");
        assert_eq!(origin_form("a.test?id=1"), "/?id=1");
        assert_eq!(origin_form("a.test?next=http://b.test/x"), "/?next=http://b.test/x");
        assert_eq!(origin_form("a.test:8080"), "/");
        assert_eq!(origin_form("a.test#top"), "/");
        assert_eq!(origin_form("[::1]:8080/p"), "/p");
    }

    #[test]
    fn header_edits_keep_other_bytes() {
        let req = RawRequest::from_bytes(
            b"POST / HTTP/1.1\r\nX-T: X\xffY\r\ncontent-length: 1\r\nContent-Length: 9\r\n\r\nabc".to_vec(),
        );
        let out = req.update_content_length().into_bytes();
        assert_eq!(out, b"POST / HTTP/1.1\r\nX-T: X\xffY\r\nContent-Length: 3\r\n\r\nabc");
        let out = RawRequest::from_bytes(out).remove_header("x-t").into_bytes();
        assert_eq!(out, b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc");
    }

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

    #[test]
    fn build_without_scheme_says_how_to_fix() {
        let e = RawRequest::build("GET", "10.0.0.5:8100", &[], b"").unwrap_err().to_string();
        assert!(e.contains("add the scheme: http://10.0.0.5:8100"), "{e}");
    }
}
