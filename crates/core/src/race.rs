//! Race-condition sending.
//!
//! - [`last_byte_sync`] (HTTP/1.1, any server): open every connection (TLS
//!   included) and send all but the final byte of each request, then release
//!   the final bytes together so the server receives the requests at nearly the
//!   same moment.
//! - [`single_packet`] (HTTP/2): the single-packet attack. All requests go on
//!   one connection; each is sent except its final DATA frame (an empty frame
//!   for requests without a body), a PING round trip makes sure all of that
//!   has arrived, then the final frames are written together in one write, so
//!   they reach the server in one TCP packet and network jitter can't separate
//!   them.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::{Error, Result};
use crate::http::h2::{h2_error, read_response, setup_error, H2Request};
use crate::http::{Client, Exchange, Stream, Target, WireReader};

/// Requests that fit one packet comfortably (final frames are 9-10 bytes each).
pub const SINGLE_PACKET_MAX: usize = 100;

/// Sends `requests` concurrently. Results are in the same order as `requests`;
/// `duration_ms` is measured from the moment the final bytes were released.
pub async fn last_byte_sync(client: &Client, target: &Target, requests: Vec<Vec<u8>>) -> Vec<Result<Exchange>> {
    let timeout = client.options().timeout;
    // What goes on the wire has auth placeholders filled; `requests` stays as recorded.
    let mut wire: Vec<Vec<u8>> = Vec::with_capacity(requests.len());
    for r in &requests {
        match client.fill_auth(r, target).await {
            Ok(w) => wire.push(w.into_owned()),
            Err(e) => return requests.iter().map(|_| Err(Error::InvalidInput(e.to_string()))).collect(),
        }
    }
    // 1. Connect everything up front.
    let mut connects = Vec::new();
    for _ in &requests {
        let (client, target) = (client.clone(), target.clone());
        connects.push(tokio::spawn(async move {
            tokio::time::timeout(timeout, client.connect(&target)).await.map_err(|_| Error::Timeout(timeout))?
        }));
    }
    let mut streams = Vec::new();
    for c in connects {
        streams.push(c.await.map_err(|e| Error::Protocol(e.to_string())).and_then(|r| r));
    }

    // 2. Send everything except the last byte.
    for (stream, req) in streams.iter_mut().zip(&wire) {
        if let Ok(s) = stream {
            let body = &req[..req.len().saturating_sub(1)];
            let write = async {
                s.write_all(body).await?;
                s.flush().await
            };
            match tokio::time::timeout(timeout, write).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => *stream = Err(e.into()),
                Err(_) => *stream = Err(Error::Timeout(timeout)),
            }
        }
    }

    // 3. Release the last bytes back to back.
    let released = Instant::now();
    for (stream, req) in streams.iter_mut().zip(&wire) {
        if let Ok(s) = stream {
            if let Err(e) = async {
                s.write_all(&req[req.len().saturating_sub(1)..]).await?;
                s.flush().await
            }
            .await
            {
                *stream = Err(e.into());
            }
        }
    }

    // 4. Read the responses concurrently.
    let mut reads = Vec::new();
    for (stream, req) in streams.into_iter().zip(requests) {
        let target = target.clone();
        reads.push(tokio::spawn(async move {
            let mut s = stream?;
            let method = crate::http::RawRequest::from_bytes(req.clone()).head().map(|h| h.method).unwrap_or_default();
            let response = tokio::time::timeout(timeout, WireReader::new().read_response(&mut s, &method))
                .await
                .map_err(|_| Error::Timeout(timeout))??;
            Ok(Exchange { target, request: req, response, duration_ms: released.elapsed().as_millis() as u64 })
        }));
    }
    let mut out = Vec::new();
    for r in reads {
        out.push(r.await.map_err(|e| Error::Protocol(e.to_string())).and_then(|r| r));
    }
    out
}

/// The outcome of a single-packet race.
pub struct SinglePacket {
    /// One result per request, in order.
    pub results: Vec<Result<Exchange>>,
    /// Final frames that went out in the single write; fewer than the number of
    /// requests means some were sent separately (they weren't all queued
    /// within two seconds).
    pub synced: usize,
}

/// Sends `requests` with the HTTP/2 single-packet attack. `duration_ms` is
/// measured from the release of the final frames. An error means nothing was sent (bad
/// requests); once connecting starts, a failure comes back as each request's result.
pub async fn single_packet(client: &Client, target: &Target, requests: Vec<Vec<u8>>) -> Result<SinglePacket> {
    if requests.is_empty() || requests.len() > SINGLE_PACKET_MAX {
        return Err(Error::InvalidInput(format!("single-packet races take 1 to {SINGLE_PACKET_MAX} requests")));
    }
    let mut converted: Vec<H2Request> = Vec::with_capacity(requests.len());
    for r in &requests {
        converted.push(H2Request::from_raw(&client.fill_auth(r, target).await?, target)?);
    }
    // Recorded with the auth placeholders, not the values sent.
    let recorded: Vec<Vec<u8>> =
        requests.iter().map(|r| H2Request::from_raw(r, target).map(|h| h.recorded)).collect::<Result<_>>()?;
    // From here on, requests may be on the wire: a failure is every request's result, so
    // each copy is recorded with it.
    let failed = |e: Error| {
        let results = (0..requests.len()).map(|_| Err(e.duplicate())).collect();
        Ok(SinglePacket { results, synced: 0 })
    };
    // Kept until the responses are read: dropping every sender closes the connection.
    // The timeout also covers servers allowing fewer concurrent streams than requests.
    let timeout = client.options().timeout;
    let (_sender, pending, state) = match tokio::time::timeout(timeout, send_all_but_last(client, target, &converted))
        .await
        .map_err(|_| Error::Timeout(timeout))
        .and_then(|r| r.map_err(|e| setup_error(target, e)))
    {
        Ok(v) => v,
        Err(e) => return failed(e),
    };

    // 3. Hold writes, queue the final frames, release them in one write.
    state.lock().unwrap().held = Some(Vec::new());
    let mut futures = Vec::new();
    for (fut, mut stream, last) in pending {
        if let Err(e) = stream.send_data(last, true) {
            return failed(h2_error(e));
        }
        futures.push(fut);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while end_streams(state.lock().unwrap().held.as_deref().unwrap_or_default()) < futures.len()
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let synced = end_streams(state.lock().unwrap().held.as_deref().unwrap_or_default());
    let released = Instant::now();
    Gate::open(&state);

    // 4. Read the responses.
    let mut reads = Vec::new();
    for (fut, request) in futures.into_iter().zip(recorded) {
        let target = target.clone();
        reads.push(tokio::spawn(async move {
            let response =
                tokio::time::timeout(timeout, read_response(fut)).await.map_err(|_| Error::Timeout(timeout))??;
            Ok(Exchange { target, request, response, duration_ms: released.elapsed().as_millis() as u64 })
        }));
    }
    let mut out = Vec::new();
    for r in reads {
        out.push(r.await.map_err(|e| Error::Protocol(e.to_string())).and_then(|r| r));
    }
    Ok(SinglePacket { results: out, synced })
}

type Pending = Vec<(h2::client::ResponseFuture, h2::SendStream<Bytes>, Bytes)>;

/// Steps 1 and 2 of [`single_packet`]: a gated HTTP/2 connection with every
/// request sent except its final frame, confirmed by a PING round trip.
async fn send_all_but_last(
    client: &Client,
    target: &Target,
    converted: &[H2Request],
) -> Result<(h2::client::SendRequest<Bytes>, Pending, Arc<Mutex<GateState>>)> {
    let gate = Gate::new(client.connect_h2(target).await?);
    let state = gate.state.clone();
    let mut builder = h2::client::Builder::new();
    builder.max_concurrent_reset_streams(SINGLE_PACKET_MAX);
    let (mut sender, mut conn) = builder.handshake::<_, Bytes>(gate).await.map_err(h2_error)?;
    let mut ping = conn.ping_pong().ok_or_else(|| Error::Protocol("HTTP/2 ping unavailable".into()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // 1. Everything but the final frame of each request.
    let mut pending = Vec::new();
    for req in converted {
        sender = sender.ready().await.map_err(h2_error)?;
        let (fut, mut stream) = sender.send_request(req.request(), false).map_err(h2_error)?;
        let split = req.body.len().saturating_sub(1);
        if split > 0 {
            stream.send_data(req.body.slice(..split), false).map_err(h2_error)?;
        }
        pending.push((fut, stream, req.body.slice(split..)));
    }
    // 2. A PING round trip: the server has everything sent so far.
    ping.ping(h2::Ping::opaque()).await.map_err(h2_error)?;

    Ok((sender, pending, state))
}

/// Counts DATA frames with END_STREAM in a buffer of whole HTTP/2 frames.
fn end_streams(buf: &[u8]) -> usize {
    let (mut i, mut n) = (0, 0);
    while i + 9 <= buf.len() {
        let len = u32::from_be_bytes([0, buf[i], buf[i + 1], buf[i + 2]]) as usize;
        if buf[i + 3] == 0 && buf[i + 4] & 1 == 1 {
            n += 1;
        }
        i += 9 + len;
    }
    n
}

#[derive(Default)]
struct GateState {
    /// While `Some`, writes are collected here instead of being sent.
    held: Option<Vec<u8>>,
    /// Released bytes not yet written to the stream.
    out: Vec<u8>,
    waker: Option<Waker>,
}

/// A stream whose writes can be held back and then released in one write.
struct Gate {
    inner: Stream,
    state: Arc<Mutex<GateState>>,
}

impl Gate {
    fn new(inner: Stream) -> Self {
        Self { inner, state: Arc::default() }
    }

    /// Moves the held bytes out for sending and wakes the connection task.
    fn open(state: &Mutex<GateState>) {
        let mut s = state.lock().unwrap();
        if let Some(held) = s.held.take() {
            s.out = held;
        }
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }

    /// Writes released bytes; `Ready(Ok)` once none are left.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut s = self.state.lock().unwrap();
        while !s.out.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &s.out) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    s.out.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Gate {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Gate {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        {
            let mut s = self.state.lock().unwrap();
            if let Some(held) = s.held.as_mut() {
                held.extend_from_slice(data);
                return Poll::Ready(Ok(data.len()));
            }
        }
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_write(cx, data),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let mut s = self.state.lock().unwrap();
            if s.held.is_some() {
                // Wait for the release; `open` wakes this task.
                s.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A new race id: a random UUID (version 4), tagged on every row the race records.
pub fn new_race_id() -> Result<String> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut b).map_err(|_| Error::InvalidInput("no random bytes".into()))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    Ok(format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

/// The tags on request `pos` (from 0) of a race of `n`: which race it was (`race:ID`), how it
/// was synchronised (`race-sync:last-byte` or `race-sync:single-packet`), its position
/// (`race-pos:3/20`), and `race-partial` when not every final frame went out together.
pub fn row_tags(race_id: &str, sync: &str, partial: bool, pos: usize, n: usize) -> Vec<String> {
    let mut tags = vec![format!("race:{race_id}"), format!("race-sync:{sync}"), format!("race-pos:{}/{n}", pos + 1)];
    if partial {
        tags.push("race-partial".into());
    }
    tags
}

/// Raises the soft limit on open files to the hard limit. A last-byte race holds a connection
/// per request, and an app started from Finder or the Dock on macOS gets a soft limit of 256.
/// Best effort: the limit stays as it was if it can't be raised.
#[cfg(unix)]
pub fn raise_fd_limit() {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit and setrlimit only read or write the struct passed in.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 || lim.rlim_cur >= lim.rlim_max {
        return;
    }
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &libc::rlimit { rlim_cur: lim.rlim_max, ..lim }) } == 0 {
        return;
    }
    // macOS refuses a soft limit above kern.maxfilesperproc, which an unlimited hard limit is;
    // OPEN_MAX (10240) is always accepted.
    let capped = lim.rlim_max.min(10240);
    if capped > lim.rlim_cur {
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &libc::rlimit { rlim_cur: capped, ..lim }) };
    }
}

#[cfg(not(unix))]
pub fn raise_fd_limit() {}

/// The soft limit on open files and how many are open now, or None where there's no such
/// limit to run into.
#[cfg(unix)]
pub fn fd_usage() -> Option<(usize, usize)> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit only writes the struct passed in.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 || lim.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    let open = std::fs::read_dir("/dev/fd").map(|d| d.count()).unwrap_or(0);
    Some((usize::try_from(lim.rlim_cur).unwrap_or(usize::MAX), open))
}

#[cfg(not(unix))]
pub fn fd_usage() -> Option<(usize, usize)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::h2::tests::{client, h2_server};

    #[test]
    fn counts_final_data_frames() {
        let mut buf = vec![0, 0, 1, 0, 1, 0, 0, 0, 1, b'x']; // DATA, END_STREAM, 1 byte
        buf.extend([0, 0, 0, 0, 1, 0, 0, 0, 3]); // empty DATA, END_STREAM
        buf.extend([0, 0, 0, 0, 0, 0, 0, 0, 5]); // DATA without END_STREAM
        buf.extend([0, 0, 0, 1, 1, 0, 0, 0, 7]); // HEADERS with END_STREAM
        assert_eq!(end_streams(&buf), 2);
    }

    #[test]
    fn race_ids_and_tags() {
        let id = new_race_id().unwrap();
        assert_eq!((id.len(), id.matches('-').count(), &id[14..15]), (36, 4, "4"), "{id}");
        assert_ne!(id, new_race_id().unwrap());
        assert_eq!(row_tags("x", "last-byte", false, 0, 20), ["race:x", "race-sync:last-byte", "race-pos:1/20"]);
        assert_eq!(
            row_tags("x", "single-packet", true, 19, 20),
            ["race:x", "race-sync:single-packet", "race-pos:20/20", "race-partial"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn fd_limit_is_raised_and_read() {
        raise_fd_limit();
        let (limit, open) = fd_usage().unwrap();
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        assert!(lim.rlim_cur == lim.rlim_max || lim.rlim_cur >= 10240, "{} of {}", lim.rlim_cur, lim.rlim_max);
        assert!(open >= 3 && open < limit, "{open} of {limit}");
    }

    #[tokio::test]
    async fn last_byte_sync_times_out() {
        // A server that accepts and never replies.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let opts = crate::http::SendOptions { timeout: Duration::from_millis(300), ..client(false).options().clone() };
        let client = Client::new(opts);
        let target = Target { scheme: "http".into(), host: "127.0.0.1".into(), port };
        let req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes();
        let results = tokio::time::timeout(Duration::from_secs(5), last_byte_sync(&client, &target, vec![req; 2]))
            .await
            .expect("race ignored the client timeout");
        assert!(results.iter().all(|r| matches!(r, Err(Error::Timeout(_)))));
    }

    #[tokio::test]
    async fn a_failed_single_packet_race_fails_every_request() {
        // A server that answers HTTP/2 prior knowledge with HTTP/1.1 and hangs up.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
            }
        });
        let target = Target { scheme: "http".into(), host: "127.0.0.1".into(), port };
        let req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes();
        let run = single_packet(&client(false), &target, vec![req.clone(); 3]).await.unwrap();
        assert_eq!((run.results.len(), run.synced), (3, 0));
        assert!(
            run.results.iter().all(|r| matches!(r, Err(Error::Protocol(_)))),
            "{:?}",
            run.results[0].as_ref().err()
        );
        // Requests that can't be sent at all are still one error.
        assert!(single_packet(&client(false), &target, vec![req; SINGLE_PACKET_MAX + 1]).await.is_err());
    }

    #[tokio::test]
    async fn single_packet_race_over_h2() {
        for alpn in [None, Some(vec![b"h2".to_vec()])] {
            let tls = alpn.is_some();
            let (port, accepted) = h2_server(alpn).await;
            let scheme = if tls { "https" } else { "http" };
            let target = Target { scheme: scheme.into(), host: "127.0.0.1".into(), port };
            let get = format!("GET /r HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes();
            let post =
                format!("POST /r HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 5\r\n\r\nhello").into_bytes();
            let mut reqs = vec![get; 10];
            reqs.extend(vec![post; 10]);
            let run = single_packet(&client(false), &target, reqs).await.unwrap();
            assert_eq!((run.results.len(), run.synced), (20, 20));
            for (i, r) in run.results.iter().enumerate() {
                let r = r.as_ref().unwrap();
                let want = if i < 10 { "GET " } else { "POST " };
                assert!(r.response.starts_with(b"HTTP/2 200"));
                let body = String::from_utf8_lossy(&r.response);
                assert!(body.contains(want) && (i < 10 || body.ends_with("/r hello")), "{body}");
            }
            assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 1);
        }
    }
}
