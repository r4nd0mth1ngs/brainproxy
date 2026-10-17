//! Reading whole HTTP/1.x messages off a stream, keeping raw bytes intact.
//!
//! [`WireReader`] keeps any bytes read past the end of a message, so it can be
//! reused across keep-alive requests and handed off when a connection upgrades.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};
use crate::http::request::{find, RawRequest};
use crate::http::response::parse_response_head;

const MAX_HEAD: usize = 256 * 1024;
const READ_CHUNK: usize = 16 * 1024;

#[derive(Default)]
pub struct WireReader {
    buf: Vec<u8>,
}

enum Framing {
    None,
    Length(usize),
    Chunked,
    UntilClose,
}

impl WireReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether no unread bytes are buffered.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Bytes read past the last message (e.g. the start of a WebSocket stream).
    pub fn into_leftover(self) -> Vec<u8> {
        self.buf
    }

    /// Reads one request. Returns `None` if the peer closed the connection before
    /// sending anything, which is the normal end of a keep-alive connection.
    pub async fn read_request<S: AsyncRead + Unpin>(&mut self, s: &mut S) -> Result<Option<Vec<u8>>> {
        // Tolerate stray CRLFs between keep-alive requests.
        loop {
            while self.buf.starts_with(b"\r\n") {
                self.buf.drain(..2);
            }
            if !self.buf.is_empty() && !self.buf.starts_with(b"\r") {
                break;
            }
            if self.fill(s).await? == 0 {
                return Ok(None);
            }
        }
        let head_end = self.head_end(s, 0).await?;
        let head = RawRequest::from_bytes(self.buf[..head_end].to_vec()).head()?;
        let header = |n: &str| head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str());
        let framing = if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            Framing::Chunked
        } else if let Some(len) = header("content-length") {
            Framing::Length(len.trim().parse().map_err(|_| Error::Protocol(format!("bad Content-Length {len:?}")))?)
        } else {
            Framing::None
        };
        let end = self.body_end(s, head_end, framing).await?;
        Ok(Some(self.buf.drain(..end).collect()))
    }

    /// Reads the head of a request without consuming it, for decisions (such as
    /// `Expect: 100-continue`) that must happen before the body arrives.
    pub async fn peek_request_head<S: AsyncRead + Unpin>(&mut self, s: &mut S) -> Result<Option<Vec<u8>>> {
        loop {
            while self.buf.starts_with(b"\r\n") {
                self.buf.drain(..2);
            }
            if !self.buf.is_empty() && !self.buf.starts_with(b"\r") {
                break;
            }
            if self.fill(s).await? == 0 {
                return Ok(None);
            }
        }
        let end = self.head_end(s, 0).await?;
        Ok(Some(self.buf[..end].to_vec()))
    }

    /// Reads one complete response, exactly as received. Interim 1xx responses
    /// (other than 101) are kept in the output and read past.
    pub async fn read_response<S: AsyncRead + Unpin>(&mut self, s: &mut S, request_method: &str) -> Result<Vec<u8>> {
        let mut start = 0;
        loop {
            let head_end = self.head_end(s, start).await.map_err(|e| match e {
                Error::Protocol(m) if m == "connection closed" && start == 0 && self.buf.is_empty() => {
                    Error::Protocol("connection closed before any response".into())
                }
                other => other,
            })?;
            let head = parse_response_head(&self.buf[start..head_end])?;
            if (100..200).contains(&head.status) && head.status != 101 {
                start = head_end;
                continue;
            }
            let method = request_method.to_ascii_uppercase();
            let framing = if method == "HEAD"
                || matches!(head.status, 101 | 204 | 304)
                || (method == "CONNECT" && (200..300).contains(&head.status))
            {
                Framing::None
            } else if head.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
                Framing::Chunked
            } else if let Some(len) = head.header("content-length").and_then(|v| v.trim().parse().ok()) {
                Framing::Length(len)
            } else {
                Framing::UntilClose
            };
            let end = self.body_end(s, head_end, framing).await?;
            return Ok(self.buf.drain(..end).collect());
        }
    }

    async fn fill<S: AsyncRead + Unpin>(&mut self, s: &mut S) -> Result<usize> {
        let old = self.buf.len();
        self.buf.resize(old + READ_CHUNK, 0);
        let n = match s.read(&mut self.buf[old..]).await {
            Ok(n) => n,
            // Many servers close TLS without close_notify; treat it as EOF.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => {
                self.buf.truncate(old);
                return Err(e.into());
            }
        };
        self.buf.truncate(old + n);
        Ok(n)
    }

    async fn head_end<S: AsyncRead + Unpin>(&mut self, s: &mut S, start: usize) -> Result<usize> {
        let mut searched = start;
        loop {
            if let Some(i) = find(&self.buf[searched..], b"\r\n\r\n") {
                return Ok(searched + i + 4);
            }
            searched = self.buf.len().saturating_sub(3).max(start);
            if self.buf.len() - start > MAX_HEAD {
                return Err(Error::Protocol("message head too large".into()));
            }
            if self.fill(s).await? == 0 {
                return Err(Error::Protocol(if self.buf.len() == start {
                    "connection closed".into()
                } else {
                    "connection closed inside message head".into()
                }));
            }
        }
    }

    /// Returns the end offset of the body starting at `body_start`. A body cut
    /// short by EOF ends where the data ends.
    async fn body_end<S: AsyncRead + Unpin>(
        &mut self,
        s: &mut S,
        body_start: usize,
        framing: Framing,
    ) -> Result<usize> {
        match framing {
            Framing::None => Ok(body_start),
            Framing::Length(len) => {
                let want = body_start + len;
                while self.buf.len() < want {
                    if self.fill(s).await? == 0 {
                        return Ok(self.buf.len());
                    }
                }
                Ok(want)
            }
            Framing::UntilClose => {
                while self.fill(s).await? > 0 {}
                Ok(self.buf.len())
            }
            Framing::Chunked => self.chunked_end(s, body_start).await,
        }
    }

    async fn chunked_end<S: AsyncRead + Unpin>(&mut self, s: &mut S, mut pos: usize) -> Result<usize> {
        loop {
            let line_end = loop {
                if let Some(i) = find(&self.buf[pos..], b"\r\n") {
                    break pos + i;
                }
                if self.fill(s).await? == 0 {
                    return Ok(self.buf.len());
                }
            };
            let line = String::from_utf8_lossy(&self.buf[pos..line_end]).into_owned();
            let size_hex = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16)
                .map_err(|_| Error::Protocol(format!("bad chunk size {size_hex:?}")))?;
            pos = line_end + 2;
            if size == 0 {
                // Optional trailers, then an empty line.
                loop {
                    if self.buf.len() >= pos + 2 && self.buf[pos..].starts_with(b"\r\n") {
                        return Ok(pos + 2);
                    }
                    if let Some(i) = find(&self.buf[pos..], b"\r\n\r\n") {
                        return Ok(pos + i + 4);
                    }
                    if self.fill(s).await? == 0 {
                        return Ok(self.buf.len());
                    }
                }
            }
            let want = pos + size + 2;
            while self.buf.len() < want {
                if self.fill(s).await? == 0 {
                    return Ok(self.buf.len());
                }
            }
            pos = want;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_pipelined_requests() {
        let data = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nPOST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc\
            PUT /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n"
            .to_vec();
        let mut s = data.as_slice();
        let mut r = WireReader::new();
        let a = r.read_request(&mut s).await.unwrap().unwrap();
        assert!(a.starts_with(b"GET /a") && a.ends_with(b"\r\n\r\n"));
        let b = r.read_request(&mut s).await.unwrap().unwrap();
        assert!(b.ends_with(b"\r\n\r\nabc"));
        let c = r.read_request(&mut s).await.unwrap().unwrap();
        assert!(c.ends_with(b"0\r\n\r\n"));
        assert!(r.read_request(&mut s).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn keeps_leftover_after_upgrade() {
        let data = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x02hi".to_vec();
        let mut r = WireReader::new();
        let resp = r.read_response(&mut data.as_slice(), "GET").await.unwrap();
        assert!(resp.ends_with(b"\r\n\r\n"));
        assert_eq!(r.into_leftover(), b"\x81\x02hi");
    }
}
