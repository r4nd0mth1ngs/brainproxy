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
    let mut headers = [httparse::EMPTY_HEADER; 256];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(head) {
        Ok(_) => {}
        Err(e) => return Err(Error::Protocol(format!("bad response head: {e}"))),
    }
    Ok(ResponseHead {
        version: format!("HTTP/1.{}", resp.version.unwrap_or(1)),
        status: resp.code.unwrap_or(0),
        reason: resp.reason.unwrap_or("").to_string(),
        headers: resp
            .headers
            .iter()
            .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
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
        if pos + size > body.len() {
            return body.to_vec();
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size + 2;
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
