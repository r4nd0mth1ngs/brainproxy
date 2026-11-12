//! Reading and parsing raw HTTP/1.x responses.

use serde::Serialize;
use tokio::io::AsyncRead;

use crate::error::{Error, Result};
use crate::http::request::{find, split_head_body};
use crate::http::wire::WireReader;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ResponseHead {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Parses the head of a raw response (everything up to the blank line).
pub fn parse_response_head(raw: &[u8]) -> Result<ResponseHead> {
    let (head, _) = split_head_body(raw);
    // HTTP/2 and HTTP/3 exchanges are recorded as `HTTP/2 <status>` and `HTTP/3 <status>`
    // (see http::h2 and http::h3).
    let multiplexed = [b"HTTP/2 ".as_slice(), b"HTTP/3 "].into_iter().find(|v| head.starts_with(v));
    let h2 = multiplexed.is_some();
    let rewritten;
    let head = if h2 {
        rewritten = [b"HTTP/1.1 ".as_slice(), &head[7..]].concat();
        &rewritten[..]
    } else {
        head
    };
    let mut headers = [httparse::EMPTY_HEADER; 256];
    let mut resp = httparse::Response::new(&mut headers);
    // Read what browsers and curl read (RFC 9112 5.2: a folded line is part of the value):
    // `Name : value`, folded lines, and header lines that aren't valid are skipped.
    let lenient = httparse::ParserConfig::default()
        .allow_obsolete_multiline_headers_in_responses(true)
        .allow_spaces_after_header_name_in_responses(true)
        .ignore_invalid_headers_in_responses(true)
        .clone();
    match lenient.parse_response(&mut resp, head) {
        Ok(httparse::Status::Complete(_)) => {}
        // Partial leaves `headers` at its full length of empty slots, so it must not pass.
        Ok(httparse::Status::Partial) => return Err(Error::Protocol("incomplete response head".into())),
        Err(e) => return Err(Error::Protocol(format!("bad response head: {e}"))),
    }
    Ok(ResponseHead {
        version: match multiplexed {
            Some(v) => String::from_utf8_lossy(&v[..6]).into_owned(),
            None => format!("HTTP/1.{}", resp.version.unwrap_or(1)),
        },
        status: resp.code.unwrap_or(0),
        reason: resp.reason.unwrap_or("").to_string(),
        headers: resp
            .headers
            .iter()
            .map(|h| {
                let value = String::from_utf8_lossy(h.value);
                // A folded value's line breaks become spaces.
                let value =
                    if value.contains(['\r', '\n']) { value.replace(['\r', '\n'], " ") } else { value.into_owned() };
                (h.name.to_string(), value)
            })
            .collect(),
    })
}

/// Reads one complete response from `stream`, returning the bytes exactly as
/// received (chunked framing included). Interim 1xx responses are kept in the
/// output and skipped over.
pub async fn read_response<S: AsyncRead + Unpin>(stream: &mut S, request_method: &str) -> Result<Vec<u8>> {
    WireReader::new().read_response(stream, request_method).await
}

/// Removes chunked framing from a body. Returns the input unchanged if it
/// isn't valid chunked encoding.
pub fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut pos = 0;
    while let Some(i) = find(&body[pos..], b"\r\n") {
        let size_str = String::from_utf8_lossy(&body[pos..pos + i]);
        let Ok(size) = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16) else {
            return body.to_vec();
        };
        pos += i + 2;
        if size == 0 {
            return out;
        }
        // `size` comes from the peer: compare without adding, so it can't wrap.
        if size > body.len() - pos {
            return body.to_vec();
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos = (pos + size + 2).min(body.len());
    }
    if out.is_empty() {
        body.to_vec()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odd_header_lines_are_read_not_rejected() {
        let h = parse_response_head(
            b"HTTP/1.1 200 OK\r\nX-A: 1\r\n  folded\r\nServer : x\r\nX-Bad: a\x01b\r\nContent-Length: 2\r\n\r\nok",
        )
        .unwrap();
        assert_eq!(
            h.header("x-a").map(|v| v.split_whitespace().collect::<Vec<_>>().join(" ")),
            Some("1 folded".into())
        );
        assert_eq!(h.header("server"), Some("x"));
        assert_eq!(h.header("content-length"), Some("2"));
    }

    #[tokio::test]
    async fn reads_content_length() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA".to_vec();
        let out = read_response(&mut data.as_slice(), "GET").await.unwrap();
        assert_eq!(out, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    }

    #[tokio::test]
    async fn reads_chunked_and_skips_100() {
        let data = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\nJUNK".to_vec();
        let out = read_response(&mut data.as_slice(), "POST").await.unwrap();
        assert!(out.ends_with(b"0\r\n\r\n"));
        let (_, body) = split_head_body(&out[find(&out, b"HTTP/1.1 200").unwrap()..]);
        assert_eq!(dechunk(body), b"abcde");
    }

    #[test]
    fn dechunk_survives_overflowing_sizes() {
        for size in ["ffffffffffffffec", "fffffffffffffff3"] {
            let body = format!("{size}\r\nAAAAAAAAAAAAAAAAAAAA\r\n0\r\n\r\n").into_bytes();
            assert_eq!(dechunk(&body), body);
        }
        assert_eq!(dechunk(b"3\r\nabc"), b"abc");
    }

    #[tokio::test]
    async fn head_request_has_no_body() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n".to_vec();
        let out = read_response(&mut data.as_slice(), "HEAD").await.unwrap();
        assert_eq!(out.len(), data.len());
    }

    #[tokio::test]
    async fn reads_to_eof_without_length() {
        let data = b"HTTP/1.0 200 OK\r\n\r\nall of it".to_vec();
        let out = read_response(&mut data.as_slice(), "GET").await.unwrap();
        assert_eq!(out, data);
    }
}
