//! Reading and parsing raw HTTP/1.x responses.

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};
use crate::http::request::{find, split_head_body};

const MAX_HEAD: usize = 256 * 1024;

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
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut start = 0;
    loop {
        let head_end = read_until_head_end(stream, &mut buf, start).await?;
        let head = parse_response_head(&buf[start..head_end])?;
        if (100..200).contains(&head.status) && head.status != 101 {
            start = head_end;
            continue;
        }
        let no_body = request_method.eq_ignore_ascii_case("HEAD")
            || head.status == 204
            || head.status == 304
            || head.status == 101
            || (request_method.eq_ignore_ascii_case("CONNECT") && (200..300).contains(&head.status));
        if no_body {
            buf.truncate(head_end);
            return Ok(buf);
        }
        let chunked =
            head.header("transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false);
        if chunked {
            read_chunked(stream, &mut buf, head_end).await?;
        } else if let Some(len) = head.header("content-length").and_then(|v| v.trim().parse::<usize>().ok()) {
            let want = head_end + len;
            while buf.len() < want {
                if read_more(stream, &mut buf).await? == 0 {
                    break; // Truncated; return what we have.
                }
            }
            buf.truncate(want.min(buf.len()));
        } else {
            while read_more(stream, &mut buf).await? > 0 {}
        }
        return Ok(buf);
    }
}

async fn read_more<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> Result<usize> {
    let mut chunk = [0u8; 16 * 1024];
    let n = match stream.read(&mut chunk).await {
        Ok(n) => n,
        // Many servers close TLS without close_notify; treat it as EOF.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
        Err(e) => return Err(e.into()),
    };
    buf.extend_from_slice(&chunk[..n]);
    Ok(n)
}

async fn read_until_head_end<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>, start: usize) -> Result<usize> {
    loop {
        if let Some(i) = find(&buf[start..], b"\r\n\r\n") {
            return Ok(start + i + 4);
        }
        if buf.len() - start > MAX_HEAD {
            return Err(Error::Protocol("response head too large".into()));
        }
        if read_more(stream, buf).await? == 0 {
            return Err(if buf.len() == start {
                Error::Protocol("connection closed before any response".into())
            } else {
                Error::Protocol("connection closed inside response head".into())
            });
        }
    }
}

async fn read_chunked<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>, body_start: usize) -> Result<()> {
    let mut pos = body_start;
    loop {
        // Chunk size line.
        let line_end = loop {
            if let Some(i) = find(&buf[pos..], b"\r\n") {
                break pos + i;
            }
            if read_more(stream, buf).await? == 0 {
                return Ok(());
            }
        };
        let size_str = String::from_utf8_lossy(&buf[pos..line_end]);
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_hex, 16).map_err(|_| Error::Protocol(format!("bad chunk size {size_hex:?}")))?;
        pos = line_end + 2;
        if size == 0 {
            // Trailers end with an empty line.
            loop {
                if buf[pos..].starts_with(b"\r\n") {
                    buf.truncate(pos + 2);
                    return Ok(());
                }
                if let Some(i) = find(&buf[pos..], b"\r\n\r\n") {
                    buf.truncate(pos + i + 4);
                    return Ok(());
                }
                if read_more(stream, buf).await? == 0 {
                    return Ok(());
                }
            }
        }
        let want = pos + size + 2;
        while buf.len() < want {
            if read_more(stream, buf).await? == 0 {
                return Ok(());
            }
        }
        pos = want;
    }
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
