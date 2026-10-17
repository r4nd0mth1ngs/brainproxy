//! Turns a raw request/response pair into the parsed, queryable fields stored
//! in the capture database: URL parts, headers as JSON, decoded bodies, title.

use std::io::Read;

use crate::http::request::split_head_body;
use crate::http::{dechunk, parse_response_head, RawRequest, Target};

/// Decompressed bodies larger than this are cut off, to survive compression bombs.
const MAX_DECODED_BODY: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct Capture {
    pub source: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub url: String,
    pub path: String,
    pub query: Option<String>,
    pub req_headers: String,
    pub req_content_type: Option<String>,
    pub req_body: Vec<u8>,
    pub req_body_text: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub resp_headers: Option<String>,
    pub resp_content_type: Option<String>,
    pub resp_body: Option<Vec<u8>>,
    pub resp_body_text: Option<String>,
    pub title: Option<String>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

impl Capture {
    pub fn new(
        source: &str,
        target: &Target,
        request: &[u8],
        response: Option<&[u8]>,
        duration_ms: Option<i64>,
        error: Option<&str>,
    ) -> Self {
        let raw = RawRequest::from_bytes(request.to_vec());
        let head = raw.head().ok();
        let (method, req_target, req_headers) =
            head.map(|h| (h.method, h.target, h.headers)).unwrap_or_else(|| (String::new(), String::new(), Vec::new()));

        // Absolute-form targets carry their own origin (origin-form ones start
        // with `/` and may carry URLs in the query: `/fetch?url=http://x/y`).
        let path_and_query = match req_target.find("://").filter(|_| !req_target.starts_with('/')) {
            Some(i) => req_target[i + 3..].find('/').map(|j| req_target[i + 3 + j..].to_string()).unwrap_or("/".into()),
            None => req_target.clone(),
        };
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (path_and_query.clone(), None),
        };

        let req_body = decode_body(&req_headers, raw.body());
        let mut c = Capture {
            source: source.to_string(),
            scheme: target.scheme.clone(),
            host: target.host.clone(),
            port: target.port,
            method,
            url: format!("{}{}", target.origin(), path_and_query),
            path,
            query,
            req_content_type: header(&req_headers, "content-type").map(str::to_string),
            req_headers: headers_json(&req_headers),
            req_body_text: text(&req_body),
            req_body,
            duration_ms,
            error: error.map(str::to_string),
            request: request.to_vec(),
            ..Default::default()
        };

        if let Some(response) = response {
            c.response = response.to_vec();
            // Skip interim 1xx responses to reach the final one.
            let mut rest = response;
            while let Ok(h) = parse_response_head(rest) {
                if (100..200).contains(&h.status) && h.status != 101 {
                    rest = split_head_body(rest).1;
                    continue;
                }
                break;
            }
            if let Ok(head) = parse_response_head(rest) {
                let body = decode_body(&head.headers, split_head_body(rest).1);
                c.status = Some(head.status);
                c.reason = Some(head.reason.clone());
                c.resp_content_type = header(&head.headers, "content-type").map(str::to_string);
                c.resp_headers = Some(headers_json(&head.headers));
                c.resp_body_text = text(&body);
                c.title = c.resp_body_text.as_deref().and_then(html_title);
                c.resp_body = Some(body);
            }
        }
        c
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn headers_json(headers: &[(String, String)]) -> String {
    serde_json::to_string(&headers.iter().map(|(k, v)| [k, v]).collect::<Vec<_>>()).unwrap_or_else(|_| "[]".into())
}

fn text(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    std::str::from_utf8(body).ok().map(str::to_string)
}

/// Removes chunked framing and content encoding (gzip, deflate, br). If decoding
/// fails, returns the bytes as they were.
pub fn decode_body(headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let has = |name: &str, token: &str| header(headers, name).map(|v| v.to_ascii_lowercase().contains(token));
    let mut out = if has("transfer-encoding", "chunked").unwrap_or(false) { dechunk(body) } else { body.to_vec() };
    if let Some(enc) = header(headers, "content-encoding") {
        for coding in enc.split(',').rev().map(|c| c.trim().to_ascii_lowercase()) {
            let decoded = match coding.as_str() {
                "gzip" | "x-gzip" => read_limited(flate2::read::MultiGzDecoder::new(&out[..])),
                "deflate" => read_limited(flate2::read::ZlibDecoder::new(&out[..]))
                    .or_else(|| read_limited(flate2::read::DeflateDecoder::new(&out[..]))),
                "br" => read_limited(brotli_decompressor::Decompressor::new(&out[..], 4096)),
                _ => None,
            };
            match decoded {
                Some(d) => out = d,
                None => break,
            }
        }
    }
    out
}

fn read_limited(r: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    r.take(MAX_DECODED_BODY).read_to_end(&mut out).ok().map(|_| out)
}

fn html_title(body: &str) -> Option<String> {
    let lower = body.get(..body.len().min(256 * 1024))?.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let open_end = start + lower[start..].find('>')? + 1;
    let close = open_end + lower[open_end..].find("</title")?;
    let title = body.get(open_end..close)?.split_whitespace().collect::<Vec<_>>().join(" ");
    (!title.is_empty()).then_some(title)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_exchange() {
        let target = Target::from_url("https://a.test").unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"<html><TITLE>\n Admin  Panel </title></html>").unwrap();
        let body = gz.finish().unwrap();
        let mut resp = format!(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(&body);
        let req = b"POST /login?next=%2F HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nu=admin";

        let c = Capture::new("send", &target, req, Some(&resp), Some(5), None);
        assert_eq!(c.url, "https://a.test/login?next=%2F");
        assert_eq!((c.path.as_str(), c.query.as_deref()), ("/login", Some("next=%2F")));
        assert_eq!(c.req_body_text.as_deref(), Some("u=admin"));
        assert_eq!(c.status, Some(200));
        assert_eq!(c.title.as_deref(), Some("Admin Panel"));
        assert!(c.resp_headers.unwrap().contains(r#"["Content-Type","text/html"]"#));
    }

    #[test]
    fn absolute_form_and_failure() {
        let target = Target::from_url("http://b.test:8080").unwrap();
        let c =
            Capture::new("proxy", &target, b"GET http://b.test:8080/x?y HTTP/1.1\r\n\r\n", None, None, Some("boom"));
        assert_eq!(c.url, "http://b.test:8080/x?y");
        let q = Capture::new("scan", &target, b"GET /f?u=http://o.test/a HTTP/1.1\r\n\r\n", None, None, None);
        assert_eq!(q.url, "http://b.test:8080/f?u=http://o.test/a");
        assert_eq!(c.status, None);
        assert_eq!(c.error.as_deref(), Some("boom"));
    }
}
