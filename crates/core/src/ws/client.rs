//! A WebSocket client for replay (`ws send`): sends a handshake through the scope-guarded
//! HTTP client, then messages, and collects what comes back for a while.

use std::time::{Duration, Instant};

use regex::bytes::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::http::client::Conn;
use crate::http::{parse_response_head, Client, RawRequest, Target};
use crate::ws::{
    accept_key, close_payload, encode_frame, is_upgrade_response, new_key, parse_frame, random_mask, Assembler,
    Deflate, Direction, Message, MAX_MESSAGE, OP_CLOSE, OP_PING, OP_PONG,
};

/// How long to wait for the server's close frame after sending ours.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// Prepares a handshake to replay: a new `Sec-WebSocket-Key`, and the upgrade headers
/// added if they are missing. Everything else is kept as given.
pub fn handshake(request: RawRequest) -> RawRequest {
    let head = request.head().ok();
    let has = |n: &str| head.as_ref().is_some_and(|h| h.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n)));
    let mut req = request.clone();
    if !has("upgrade") {
        req = req.set_header("Upgrade", "websocket");
    }
    if !head.as_ref().is_some_and(|h| {
        h.headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.to_ascii_lowercase().contains("upgrade"))
    }) {
        req = req.set_header("Connection", "Upgrade");
    }
    if !has("sec-websocket-version") {
        req = req.set_header("Sec-WebSocket-Version", "13");
    }
    req.set_header("Sec-WebSocket-Key", &new_key())
}

/// An open connection: the 101 response and what is needed to talk on it.
pub struct Opened {
    pub response: Vec<u8>,
    pub duration_ms: u64,
    /// The server's `Sec-WebSocket-Accept` matches the key sent.
    pub accept_ok: bool,
    conn: Conn,
    deflate: Deflate,
}

/// Sends the handshake. A response other than 101 comes back as `Err((response, ...))`
/// so it can be recorded and shown.
pub async fn open(
    client: &Client,
    target: &Target,
    request: &RawRequest,
) -> Result<std::result::Result<Opened, (Vec<u8>, u64)>> {
    let started = Instant::now();
    let timeout = client.options().timeout;
    let (conn, response) = tokio::time::timeout(timeout, client.exchange(request.as_bytes(), target, "GET"))
        .await
        .map_err(|_| Error::Timeout(timeout))??;
    let duration_ms = started.elapsed().as_millis() as u64;
    // After any 1xx interim responses (103 Early Hints).
    let head = parse_response_head(crate::http::client::final_response(&response))?;
    if !is_upgrade_response(&head) {
        return Ok(Err((response, duration_ms)));
    }
    let key = request.head().ok().and_then(|h| {
        h.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key")).map(|(_, v)| v.clone())
    });
    let accept_ok =
        key.is_some_and(|k| head.header("sec-websocket-accept").is_some_and(|a| a.trim() == accept_key(&k)));
    let deflate = Deflate::from_response(&head);
    Ok(Ok(Opened { response, duration_ms, accept_ok, conn, deflate }))
}

pub struct Options {
    /// How long to keep listening after the last message is sent.
    pub wait: Duration,
    /// Stop as soon as a received data message matches.
    pub until: Option<Regex>,
    /// Stop after receiving this many data messages.
    pub max_messages: usize,
    /// How long sending the messages may take.
    pub write_timeout: Duration,
}

/// One message sent or received, with the time since the connection opened.
#[derive(Debug, Clone)]
pub struct Event {
    pub direction: Direction,
    pub message: Message,
    pub elapsed_ms: u64,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub events: Vec<Event>,
    /// Why listening stopped: `until`, `max-messages`, `wait`, `closed` (by the server),
    /// or `disconnected`.
    pub stopped: &'static str,
    pub close_code: Option<u16>,
    pub close_reason: Option<String>,
    pub error: Option<String>,
}

/// Sends `messages` (opcode, payload) in order while reading what arrives (a server that
/// answers as it goes can't block the sending), answers pings, and records everything until a
/// stop condition, then closes the connection.
pub async fn talk(opened: Opened, messages: &[(u8, Vec<u8>)], opts: &Options) -> Outcome {
    talk_watched(opened, messages, opts, |_| {}).await
}

/// [`talk`], calling `watch` with each event as it happens: a message to the server when it
/// is queued to be written (the ones given are all queued at the start, so a connection that
/// drops early may not have sent the last of them), one from the server as it arrives. A
/// caller can record as it goes, so what was sent is on record even if it never gets the
/// outcome. `watch` runs on the reading task: it mustn't block.
pub async fn talk_watched(
    opened: Opened,
    messages: &[(u8, Vec<u8>)],
    opts: &Options,
    mut watch: impl FnMut(&Event),
) -> Outcome {
    let started = Instant::now();
    let Opened { conn: Conn { stream, reader, .. }, deflate, .. } = opened;
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut out = Outcome { stopped: "wait", ..Default::default() };
    let elapsed = |s: Instant| s.elapsed().as_millis() as u64;
    let mut push = |out: &mut Outcome, direction: Direction, message: Message| {
        let e = Event { direction, message, elapsed_ms: elapsed(started) };
        watch(&e);
        out.events.push(e);
    };

    // The writer sends the messages, says when they are all out, then whatever the reader
    // queues (pongs, the close) until the reader is done.
    let (queue, mut queued) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (all_sent, mut all_sent_rx) = tokio::sync::oneshot::channel::<()>();
    let first: Vec<Vec<u8>> =
        messages.iter().map(|(op, p)| encode_frame(true, 0, *op, p, Some(random_mask()))).collect();
    for (opcode, payload) in messages {
        push(&mut out, Direction::ToServer, Message::new(*opcode, payload.clone()));
    }
    let writer = async move {
        for frame in first {
            wr.write_all(&frame).await?;
        }
        wr.flush().await?;
        let _ = all_sent.send(());
        while let Some(frame) = queued.recv().await {
            wr.write_all(&frame).await?;
            wr.flush().await?;
        }
        wr.shutdown().await
    };

    let reader = async {
        let mut buf = reader.into_leftover();
        let mut assembler = Assembler::new(deflate, Direction::ToClient, MAX_MESSAGE);
        let mut writing = true;
        // Until the messages are out, the deadline bounds a stalled send.
        let mut deadline = Instant::now() + opts.write_timeout;
        let mut received = 0;
        let mut closing = false;
        let mut close_sent = false;
        let mut chunk = vec![0u8; 64 * 1024];
        'read: loop {
            loop {
                let (frame, n) = match parse_frame(&buf, MAX_MESSAGE) {
                    Ok(Some(f)) => f,
                    Ok(None) => break,
                    Err(e) => {
                        out.error = Some(e.to_string());
                        break 'read;
                    }
                };
                buf.drain(..n);
                let m = match assembler.push(&frame) {
                    Ok(Some(m)) => m,
                    Ok(None) => continue,
                    Err(e) => {
                        out.error = Some(e.to_string());
                        break 'read;
                    }
                };
                push(&mut out, Direction::ToClient, m.clone());
                match m.opcode {
                    OP_PING => {
                        if queue.send(encode_frame(true, 0, OP_PONG, &m.payload, Some(random_mask()))).is_ok() {
                            push(&mut out, Direction::ToServer, Message::new(OP_PONG, m.payload.clone()));
                        }
                    }
                    OP_CLOSE => {
                        let (code, reason) = m.close_info();
                        out.close_code = code;
                        out.close_reason = reason;
                        if !close_sent {
                            // Echo the code (RFC 6455 5.5.1) and stop.
                            out.stopped = "closed";
                            let payload = code.map(|c| c.to_be_bytes().to_vec()).unwrap_or_default();
                            if queue.send(encode_frame(true, 0, OP_CLOSE, &payload, Some(random_mask()))).is_ok() {
                                push(&mut out, Direction::ToServer, Message::new(OP_CLOSE, payload));
                            }
                        }
                        break 'read;
                    }
                    _ if m.is_data() && !closing => {
                        received += 1;
                        if opts.until.as_ref().is_some_and(|re| re.is_match(&m.payload)) {
                            out.stopped = "until";
                        } else if received >= opts.max_messages {
                            out.stopped = "max-messages";
                        }
                        closing = out.stopped != "wait";
                    }
                    _ => {}
                }
            }
            if closing && !close_sent {
                // Done listening: say goodbye and wait briefly for the server's close.
                close_sent = true;
                let payload = close_payload(1000, "");
                if queue.send(encode_frame(true, 0, OP_CLOSE, &payload, Some(random_mask()))).is_ok() {
                    push(&mut out, Direction::ToServer, Message::new(OP_CLOSE, payload));
                }
                deadline = Instant::now() + CLOSE_WAIT;
            }
            tokio::select! {
                done = &mut all_sent_rx, if writing => {
                    writing = false;
                    if done.is_err() {
                        // The writer failed; its error is reported below.
                        out.stopped = "disconnected";
                        break;
                    }
                    if !close_sent {
                        deadline = Instant::now() + opts.wait;
                    }
                }
                read = tokio::time::timeout_at(deadline.into(), rd.read(&mut chunk)) => match read {
                    Ok(Ok(0)) => {
                        if !closing {
                            out.stopped = "disconnected";
                        }
                        break;
                    }
                    Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                    Ok(Err(e)) => {
                        out.error = Some(e.to_string());
                        if !closing {
                            out.stopped = "disconnected";
                        }
                        break;
                    }
                    Err(_) if close_sent => break,
                    Err(_) if writing => {
                        out.error = Some(format!("the messages weren't all sent within {:?}", opts.write_timeout));
                        out.stopped = "disconnected";
                        break;
                    }
                    // Time is up: close (above), then wait a moment for the server's answer.
                    Err(_) => closing = true,
                },
            }
        }
        drop(queue);
    };

    tokio::pin!(writer);
    let mut written = None;
    tokio::select! {
        _ = reader => {}
        // The writer only ends first when writing failed: stop there.
        w = &mut writer => written = Some(w),
    }
    let written = match written {
        Some(w) => Some(w),
        None => tokio::time::timeout(CLOSE_WAIT, &mut writer).await.ok(),
    };
    if let Some(Err(e)) = written {
        out.error.get_or_insert_with(|| e.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::WireReader;
    use crate::ws::{OP_BINARY, OP_TEXT};

    /// An echo server on the other end of `server`: each message comes back as it was.
    async fn echo(mut server: tokio::io::DuplexStream) {
        let mut buf = Vec::new();
        let mut a = Assembler::new(Deflate::default(), Direction::ToServer, MAX_MESSAGE);
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            while let Some((f, n)) = parse_frame(&buf, MAX_MESSAGE).unwrap() {
                buf.drain(..n);
                if let Some(m) = a.push(&f).unwrap() {
                    let close = m.opcode == OP_CLOSE;
                    server.write_all(&encode_frame(true, 0, m.opcode, &m.payload, None)).await.unwrap();
                    if close {
                        return;
                    }
                }
            }
            match server.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn opened(stream: tokio::io::DuplexStream) -> Opened {
        let conn = Conn { stream: Box::new(stream), reader: WireReader::new(), reused: false, generation: 0 };
        Opened { response: Vec::new(), duration_ms: 0, accept_ok: true, conn, deflate: Deflate::default() }
    }

    #[tokio::test]
    async fn replies_are_read_while_large_messages_are_sent() {
        // Small pipes: an echo server blocks on its replies long before all messages are sent,
        // so sending everything before reading would stall both sides.
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(echo(server));
        let messages: Vec<(u8, Vec<u8>)> = (0..8u8).map(|i| (OP_BINARY, vec![i; 256 * 1024])).collect();
        let opts = Options {
            wait: Duration::from_secs(5),
            until: None,
            max_messages: 8,
            write_timeout: Duration::from_secs(10),
        };
        let out = tokio::time::timeout(Duration::from_secs(20), talk(opened(client), &messages, &opts)).await.unwrap();
        assert_eq!((out.stopped, out.error.as_deref()), ("max-messages", None));
        let got: Vec<_> =
            out.events.iter().filter(|e| e.direction == Direction::ToClient && e.message.is_data()).collect();
        assert_eq!(got.len(), 8);
        assert!(got.iter().enumerate().all(|(i, e)| e.message.payload == vec![i as u8; 256 * 1024]));
        // We closed; the server's answering close still gives the code.
        assert_eq!(out.close_code, Some(1000));
    }

    #[tokio::test]
    async fn the_wait_window_starts_after_sending() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(echo(server));
        let opts = Options {
            wait: Duration::from_millis(200),
            until: None,
            max_messages: 100,
            write_timeout: Duration::from_secs(10),
        };
        let out = talk(opened(client), &[(OP_TEXT, b"hi".to_vec())], &opts).await;
        assert_eq!(out.stopped, "wait");
        assert!(out.events.iter().any(|e| e.direction == Direction::ToClient && e.message.payload == b"hi"));
        assert_eq!(out.close_code, Some(1000));
    }
}
