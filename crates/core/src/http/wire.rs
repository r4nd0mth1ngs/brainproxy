//! Reading whole HTTP/1.x messages off a stream, keeping raw bytes intact.
//!
//! [`WireReader`] keeps any bytes read past the end of a message, so it can be
//! reused across keep-alive requests and handed off when a connection upgrades.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};
use crate::http::request::{find, RawRequest};
use crate::http::response::parse_response_head;

const MAX_HEAD: usize = 256 * 1024;
/// Largest message body buffered (HTTP/1 framing included, HTTP/2 data).
/// Anything bigger fails with a protocol error instead of eating memory.
pub const MAX_BODY: usize = 64 * 1024 * 1024;
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

/// How the rest of a response left open is framed: where [`WireReader::next_piece`] is in it.
#[derive(Debug)]
pub enum LiveFraming {
    /// Body bytes still to come.
    Length(usize),
    Chunked(ChunkState),
    UntilClose,
    /// The body is over, or the connection closed inside it.
    Done,
}

/// Where a chunked body left open stands.
#[derive(Debug)]
pub enum ChunkState {
    /// At a chunk's size line.
    Size,
    /// Inside a chunk, with this many data bytes to go.
    Data(usize),
    /// At the line break that ends a chunk's data.
    DataEnd,
    /// After the last chunk: trailer lines, then an empty line.
    Trailers,
}

/// A piece of a body read as it arrives.
#[derive(Debug, Default)]
pub struct Piece {
    /// The bytes as received, chunk framing included.
    pub wire: Vec<u8>,
    /// The content they carry when that differs (a chunked body's data).
    data: Option<Vec<u8>>,
    /// Whether the body so far ends where it could be cut and still be read: not inside a chunk.
    pub boundary: bool,
}

impl Piece {
    /// A piece whose bytes are its content (no chunk framing).
    pub fn plain(wire: Vec<u8>) -> Self {
        Self { wire, data: None, boundary: true }
    }

    /// The content the piece carries, chunk framing removed.
    pub fn data(&self) -> &[u8] {
        self.data.as_deref().unwrap_or(&self.wire)
    }
}

/// Longest chunk size line (with its extensions) or trailer line of a body read as it arrives.
const MAX_CHUNK_LINE: usize = 16 * 1024;

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
        Ok(self.read_response_with(s, request_method, false).await?.0)
    }

    /// [`Self::read_response`], except that an event stream ([`crate::sse::is_event_stream`])
    /// is left open: its head is returned (interim responses included) with how its body is
    /// framed, for [`Self::next_piece`] to read as it arrives. A whole response waits for a
    /// body that may never end.
    pub async fn read_response_live<S: AsyncRead + Unpin>(
        &mut self,
        s: &mut S,
        request_method: &str,
    ) -> Result<(Vec<u8>, Option<LiveFraming>)> {
        self.read_response_with(s, request_method, true).await
    }

    async fn read_response_with<S: AsyncRead + Unpin>(
        &mut self,
        s: &mut S,
        request_method: &str,
        live: bool,
    ) -> Result<(Vec<u8>, Option<LiveFraming>)> {
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
            if live && crate::sse::is_event_stream(&head) {
                let open = match framing {
                    Framing::None => None,
                    Framing::Length(n) => Some(LiveFraming::Length(n)),
                    Framing::Chunked => Some(LiveFraming::Chunked(ChunkState::Size)),
                    Framing::UntilClose => Some(LiveFraming::UntilClose),
                };
                if open.is_some() {
                    return Ok((self.buf.drain(..head_end).collect(), open));
                }
            }
            let end = self.body_end(s, head_end, framing).await?;
            return Ok((self.buf.drain(..end).collect(), None));
        }
    }

    /// The next piece of a body left open by [`Self::read_response_live`], as soon as any of
    /// it has arrived; `None` once the body is over or the connection closed.
    pub async fn next_piece<S: AsyncRead + Unpin>(
        &mut self,
        s: &mut S,
        framing: &mut LiveFraming,
    ) -> Result<Option<Piece>> {
        loop {
            if let Some(piece) = self.take_piece(framing)? {
                return Ok(Some(piece));
            }
            if matches!(framing, LiveFraming::Done) {
                return Ok(None);
            }
            if self.fill(s).await? == 0 {
                *framing = LiveFraming::Done;
                return Ok(None);
            }
        }
    }

    /// What of the body is buffered already, taken out of the buffer; `None` when that is nothing.
    fn take_piece(&mut self, framing: &mut LiveFraming) -> Result<Option<Piece>> {
        match framing {
            LiveFraming::Done => Ok(None),
            LiveFraming::Length(0) => {
                *framing = LiveFraming::Done;
                Ok(None)
            }
            LiveFraming::Length(left) => {
                let n = (*left).min(self.buf.len());
                *left -= n;
                if *left == 0 {
                    *framing = LiveFraming::Done;
                }
                Ok((n > 0).then(|| Piece::plain(self.buf.drain(..n).collect())))
            }
            LiveFraming::UntilClose => Ok((!self.buf.is_empty()).then(|| Piece::plain(std::mem::take(&mut self.buf)))),
            LiveFraming::Chunked(state) => {
                let (mut pos, mut data, mut done) = (0, Vec::new(), false);
                let bad = |what: &str| Error::Protocol(format!("bad chunked body: {what}"));
                loop {
                    let rest = &self.buf[pos..];
                    match state {
                        ChunkState::Size => {
                            let Some(i) = find(rest, b"\r\n") else {
                                if rest.len() > MAX_CHUNK_LINE {
                                    return Err(bad("chunk size line too long"));
                                }
                                break;
                            };
                            let line = String::from_utf8_lossy(&rest[..i]);
                            let size_hex = line.split(';').next().unwrap_or("").trim();
                            let size = usize::from_str_radix(size_hex, 16)
                                .map_err(|_| bad(&format!("chunk size {size_hex:?}")))?;
                            pos += i + 2;
                            *state = if size == 0 { ChunkState::Trailers } else { ChunkState::Data(size) };
                        }
                        ChunkState::Data(left) => {
                            let n = (*left).min(rest.len());
                            if n == 0 {
                                break;
                            }
                            data.extend_from_slice(&rest[..n]);
                            pos += n;
                            *left -= n;
                            if *left == 0 {
                                *state = ChunkState::DataEnd;
                            }
                        }
                        ChunkState::DataEnd => {
                            if rest.len() < 2 {
                                break;
                            }
                            if !rest.starts_with(b"\r\n") {
                                return Err(bad("no line break after a chunk"));
                            }
                            pos += 2;
                            *state = ChunkState::Size;
                        }
                        ChunkState::Trailers => {
                            let Some(i) = find(rest, b"\r\n") else {
                                if rest.len() > MAX_CHUNK_LINE {
                                    return Err(bad("trailer line too long"));
                                }
                                break;
                            };
                            pos += i + 2;
                            if i == 0 {
                                done = true;
                                break;
                            }
                        }
                    }
                }
                let boundary = done || matches!(state, ChunkState::Size);
                if done {
                    *framing = LiveFraming::Done;
                }
                Ok((pos > 0).then(|| Piece { wire: self.buf.drain(..pos).collect(), data: Some(data), boundary }))
            }
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

    /// [`Self::fill`] for body bytes: fails once the buffer passes `limit`.
    async fn fill_body<S: AsyncRead + Unpin>(&mut self, s: &mut S, limit: usize) -> Result<usize> {
        if self.buf.len() > limit {
            return Err(too_large());
        }
        self.fill(s).await
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
        let limit = body_start + MAX_BODY;
        match framing {
            Framing::None => Ok(body_start),
            Framing::Length(len) => {
                if len > MAX_BODY {
                    return Err(too_large());
                }
                let want = body_start + len;
                while self.buf.len() < want {
                    if self.fill_body(s, limit).await? == 0 {
                        return Ok(self.buf.len());
                    }
                }
                Ok(want)
            }
            Framing::UntilClose => {
                while self.fill_body(s, limit).await? > 0 {}
                Ok(self.buf.len())
            }
            Framing::Chunked => self.chunked_end(s, body_start, limit).await,
        }
    }

    async fn chunked_end<S: AsyncRead + Unpin>(&mut self, s: &mut S, mut pos: usize, limit: usize) -> Result<usize> {
        loop {
            let line_end = loop {
                if let Some(i) = find(&self.buf[pos..], b"\r\n") {
                    break pos + i;
                }
                if self.fill_body(s, limit).await? == 0 {
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
                    if self.fill_body(s, limit).await? == 0 {
                        return Ok(self.buf.len());
                    }
                }
            }
            // `pos` is within the buffer and `size` is capped, so this can't overflow.
            if size > MAX_BODY || pos + size + 2 > limit {
                return Err(too_large());
            }
            let want = pos + size + 2;
            while self.buf.len() < want {
                if self.fill_body(s, limit).await? == 0 {
                    return Ok(self.buf.len());
                }
            }
            pos = want;
        }
    }
}

fn too_large() -> Error {
    Error::Protocol(format!("message body over the {} MB limit", MAX_BODY / (1024 * 1024)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_oversized_bodies() {
        // Chunk sizes that wrap `usize` arithmetic used to hang or panic.
        for size in ["ffffffffffffffec", "fffffffffffffff3", "4000001"] {
            let data = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nAAAA\r\n0\r\n\r\n");
            let err = WireReader::new().read_response(&mut data.as_bytes(), "GET").await.unwrap_err();
            assert!(err.to_string().contains("limit"), "{size}: {err}");
        }
        let data = b"POST / HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\nabc".to_vec();
        assert!(WireReader::new().read_request(&mut data.as_slice()).await.is_err());
        // A body with no framing that never ends stops at the cap.
        let head = b"HTTP/1.1 200 OK\r\n\r\n".as_slice();
        let mut endless = tokio::io::AsyncReadExt::chain(head, tokio::io::repeat(b'A'));
        let err = WireReader::new().read_response(&mut endless, "GET").await.unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }

    /// A reader that hands out `data` a few bytes at a time, as a slow connection does.
    struct Trickle<'a>(&'a [u8], usize);

    impl AsyncRead for Trickle<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let n = self.1.min(self.0.len()).min(buf.remaining());
            buf.put_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn an_event_stream_is_left_open_and_read_in_pieces() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n";
        let chunked =
            format!("{head}Transfer-Encoding: chunked\r\n\r\n8\r\ndata: a\n\r\n1;x=y\r\n\n\r\n0\r\nT: 1\r\n\r\nNEXT");
        let until_close = format!("{head}\r\ndata: a\n\n");
        let length = format!("{head}Content-Length: 9\r\n\r\ndata: a\n\nNEXT");
        for (raw, body_wire, rest) in [
            (&chunked, "8\r\ndata: a\n\r\n1;x=y\r\n\n\r\n0\r\nT: 1\r\n\r\n", "NEXT"),
            (&until_close, "data: a\n\n", ""),
            (&length, "data: a\n\n", "NEXT"),
        ] {
            // However the bytes arrive, the pieces add up to the body and nothing else.
            for step in [1, 3, 7, 4096] {
                let mut s = Trickle(raw.as_bytes(), step);
                let mut r = WireReader::new();
                let (got_head, framing) = r.read_response_live(&mut s, "GET").await.unwrap();
                assert!(got_head.ends_with(b"\r\n\r\n") && got_head.starts_with(b"HTTP/1.1 200"));
                let mut framing = framing.expect("an event stream is left open");
                let (mut wire, mut data) = (Vec::new(), Vec::new());
                while let Some(p) = r.next_piece(&mut s, &mut framing).await.unwrap() {
                    wire.extend_from_slice(&p.wire);
                    data.extend_from_slice(p.data());
                    // A cut at a boundary leaves a body that still reads as chunked.
                    if p.boundary && raw == &chunked {
                        assert!(crate::http::dechunk(&wire).len() <= data.len(), "step {step}");
                    }
                }
                assert_eq!(String::from_utf8_lossy(&wire), body_wire, "step {step}");
                assert_eq!(data, b"data: a\n\n", "step {step}");
                let mut left = r.into_leftover();
                tokio::io::AsyncReadExt::read_to_end(&mut s, &mut left).await.unwrap();
                assert_eq!(String::from_utf8_lossy(&left), rest, "step {step}");
            }
        }
        // Anything else is read whole, as before; so is an event stream nobody asked to leave open.
        let json = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let (whole, open) = WireReader::new().read_response_live(&mut json.as_slice(), "GET").await.unwrap();
        assert!(open.is_none() && whole.ends_with(b"{}"));
        let whole = WireReader::new().read_response(&mut until_close.as_bytes(), "GET").await.unwrap();
        assert!(whole.ends_with(b"data: a\n\n"));
        // A HEAD's answer has no body to wait for.
        let (_, open) = WireReader::new().read_response_live(&mut until_close.as_bytes(), "HEAD").await.unwrap();
        assert!(open.is_none());
        // A chunk size that isn't one ends the stream with an error, not a hang.
        let bad = format!("{head}Transfer-Encoding: chunked\r\n\r\nzz\r\n");
        let mut s = bad.as_bytes();
        let mut r = WireReader::new();
        let (_, framing) = r.read_response_live(&mut s, "GET").await.unwrap();
        assert!(r.next_piece(&mut s, &mut framing.unwrap()).await.is_err());
    }

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
