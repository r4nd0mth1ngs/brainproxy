//! Server-sent events (`text/event-stream`, the WHATWG HTML "server-sent events" format): a
//! response whose body is a series of events that may never end. Such a response isn't read
//! whole: the proxy relays it to the client as it arrives, and a sender reads it for a bounded
//! time ([`read`]). Either way a [`Recorder`] keeps what one stream may store, its body as
//! received and its events as parsed ([`Parser`]), and the project database lists them ([`db`]).

pub mod db;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::http::client::LiveBody;
use crate::http::wire::Piece;
use crate::http::ResponseHead;

/// The most body bytes one stream may store, as received and (when it is compressed) as
/// decoded. A stream that passes it is relayed on, unrecorded, and marked truncated.
pub const MAX_STREAM_BYTES: usize = 4 * 1024 * 1024;
/// The most events one stream may store.
pub const MAX_STREAM_EVENTS: usize = 10_000;

/// Whether a response is an event stream to read as it arrives: a 2xx whose Content-Type is
/// `text/event-stream`. Browsers hand only a 200 to an `EventSource`, but other clients
/// (`fetch`, API libraries) read any such body as a stream.
pub fn is_event_stream(head: &ResponseHead) -> bool {
    (200..300).contains(&head.status)
        && head.status != 204
        && head
            .header("content-type")
            .is_some_and(|v| v.split(';').next().unwrap_or_default().trim().eq_ignore_ascii_case("text/event-stream"))
}

/// One event: a block of field lines ended by a blank line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    /// UTC time its last line arrived.
    pub time: String,
    /// The `event` field: the event's type, `message` when the block names none.
    pub event: String,
    /// The `id` field, when the block has one.
    pub event_id: Option<String>,
    /// The `data` lines joined with line breaks; `None` for a block without one, which a
    /// browser dispatches no event for (it still takes the block's `id` and `retry`).
    pub data: Option<String>,
    /// The `retry` field: milliseconds the client waits before it reconnects.
    pub retry: Option<u64>,
}

/// Parses an event stream as its bytes arrive. Comment lines (`: keep-alive`) and blocks with
/// no `event`, `id`, `data` or `retry` line give no event; neither does a block the stream
/// ends inside.
#[derive(Debug, Default)]
pub struct Parser {
    /// The line being read.
    line: Vec<u8>,
    /// Whether anything has been fed yet (a byte order mark is only skipped at the start).
    started: bool,
    /// The last byte was a CR: a LF that follows belongs to the same line break.
    after_cr: bool,
    event: Option<String>,
    id: Option<String>,
    data: Option<String>,
    retry: Option<u64>,
}

impl Parser {
    /// Takes the next bytes of the stream; returns the events they complete.
    pub fn feed(&mut self, mut bytes: &[u8]) -> Vec<Event> {
        let mut out = Vec::new();
        // The byte order mark is three bytes that may arrive apart: keep them until they can be told.
        if !self.started {
            self.line.extend_from_slice(bytes);
            const BOM: &[u8] = b"\xEF\xBB\xBF";
            if self.line.len() < BOM.len() && BOM.starts_with(&self.line) {
                return out;
            }
            self.started = true;
            let held = std::mem::take(&mut self.line);
            let start = if held.starts_with(BOM) { BOM.len() } else { 0 };
            self.lines(&held[start..], &mut out);
            return out;
        }
        // Only the byte right after a CR can be the LF of its line break.
        if self.after_cr && !bytes.is_empty() {
            if bytes[0] == b'\n' {
                bytes = &bytes[1..];
            }
            self.after_cr = false;
        }
        self.lines(bytes, &mut out);
        out
    }

    fn lines(&mut self, bytes: &[u8], out: &mut Vec<Event>) {
        let mut rest = bytes;
        while let Some(i) = rest.iter().position(|b| matches!(b, b'\r' | b'\n')) {
            self.line.extend_from_slice(&rest[..i]);
            let crlf = rest[i] == b'\r' && rest.get(i + 1) == Some(&b'\n');
            // A CR at the very end may be half of a CRLF whose LF comes next.
            self.after_cr = rest[i] == b'\r' && i + 1 == rest.len();
            rest = &rest[i + 1 + usize::from(crlf)..];
            let line = std::mem::take(&mut self.line);
            if let Some(e) = self.end_line(&line) {
                out.push(e);
            }
        }
        self.line.extend_from_slice(rest);
    }

    /// One whole line: a field of the block being read, or the blank line that ends it.
    fn end_line(&mut self, line: &[u8]) -> Option<Event> {
        if line.is_empty() {
            let (event, event_id, data, retry) =
                (self.event.take(), self.id.take(), self.data.take(), self.retry.take());
            if event.is_none() && event_id.is_none() && data.is_none() && retry.is_none() {
                return None;
            }
            return Some(Event {
                time: crate::ws::now_iso(),
                event: event.filter(|e| !e.is_empty()).unwrap_or_else(|| "message".into()),
                event_id,
                data,
                retry,
            });
        }
        let line = String::from_utf8_lossy(line);
        let (field, value) = match line.split_once(':') {
            // A comment.
            Some(("", _)) => return None,
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (&*line, ""),
        };
        match field {
            "event" => self.event = Some(value.to_string()),
            "data" => match &mut self.data {
                Some(d) => {
                    d.push('\n');
                    d.push_str(value);
                }
                None => self.data = Some(value.to_string()),
            },
            // An id with a NUL is ignored, as the format says.
            "id" if !value.contains('\0') => self.id = Some(value.to_string()),
            "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                self.retry = value.parse().ok().or(self.retry)
            }
            _ => {}
        }
        None
    }
}

/// A stream's decoded bytes not parsed yet, and how many more it may decode.
#[derive(Default)]
struct Decoded {
    buf: Vec<u8>,
    left: usize,
    /// The coding gave more than `left`: the stream is over the cap.
    over: bool,
}

/// Where decoded bytes go: no further than the cap, so a small compressed piece can't fill memory.
struct Sink(Arc<Mutex<Decoded>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut out = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if buf.len() > out.left {
            out.over = true;
            return Err(std::io::Error::other("over the stream cap"));
        }
        out.left -= buf.len();
        out.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Removes a stream's content coding as its bytes arrive.
enum Decoder {
    Gzip(flate2::write::MultiGzDecoder<Sink>),
    /// `deflate`: a zlib stream, or a bare deflate one from servers that get it wrong. Told
    /// apart by the first byte.
    Deflate(Option<Sink>),
    Zlib(flate2::write::ZlibDecoder<Sink>),
    Raw(flate2::write::DeflateDecoder<Sink>),
    Brotli(Box<brotli_decompressor::DecompressorWriter<Sink>>),
}

impl Decoder {
    fn feed(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if let (Decoder::Deflate(sink), Some(first)) = (&mut *self, bytes.first()) {
            let sink = sink.take().expect("replaced at the first byte");
            // A zlib header's first byte says deflate with a window of up to 32K: 0x?8.
            *self = if first & 0x0f == 8 {
                Decoder::Zlib(flate2::write::ZlibDecoder::new(sink))
            } else {
                Decoder::Raw(flate2::write::DeflateDecoder::new(sink))
            };
        }
        match self {
            Decoder::Gzip(d) => d.write_all(bytes).and_then(|_| d.flush()),
            Decoder::Zlib(d) => d.write_all(bytes).and_then(|_| d.flush()),
            Decoder::Raw(d) => d.write_all(bytes).and_then(|_| d.flush()),
            Decoder::Brotli(d) => d.write_all(bytes).and_then(|_| d.flush()),
            Decoder::Deflate(_) => Ok(()),
        }
    }
}

/// What is kept of one stream: its body as received, up to [`MAX_STREAM_BYTES`], and the
/// events parsed from it, up to [`MAX_STREAM_EVENTS`]. Past either, nothing more is kept.
pub struct Recorder {
    parser: Parser,
    decoder: Option<Decoder>,
    decoded: Arc<Mutex<Decoded>>,
    body: Vec<u8>,
    /// The body's length at the last point it could be cut and still be read (see [`Piece::boundary`]).
    clean: usize,
    events: usize,
    truncated: bool,
    note: Option<String>,
}

impl Recorder {
    /// A recorder for the stream `head` opens.
    pub fn new(head: &ResponseHead) -> Self {
        let decoded = Arc::new(Mutex::new(Decoded { left: MAX_STREAM_BYTES, ..Default::default() }));
        let sink = || Sink(decoded.clone());
        let coding = head.header("content-encoding").map(|v| v.trim().to_ascii_lowercase()).unwrap_or_default();
        let mut note = None;
        let decoder = match coding.as_str() {
            "" | "identity" => None,
            "gzip" | "x-gzip" => Some(Decoder::Gzip(flate2::write::MultiGzDecoder::new(sink()))),
            "deflate" => Some(Decoder::Deflate(Some(sink()))),
            "br" => Some(Decoder::Brotli(Box::new(brotli_decompressor::DecompressorWriter::new(sink(), 4096)))),
            other => {
                note = Some(format!("events not parsed: Content-Encoding {other} isn't decoded as it arrives"));
                None
            }
        };
        Self {
            parser: Parser::default(),
            decoder,
            decoded,
            body: Vec::new(),
            clean: 0,
            events: 0,
            truncated: false,
            // Without a decoder for its coding the body is kept, and no events are parsed.
            note,
        }
    }

    /// Takes the next piece of the body; returns the events it completes. Nothing once the
    /// stream is over a cap.
    pub fn push(&mut self, piece: &Piece) -> Vec<Event> {
        if self.truncated {
            return Vec::new();
        }
        if self.body.len() + piece.wire.len() > MAX_STREAM_BYTES {
            return self.cut(format!("recording stopped at the {} MiB a stream may store", MAX_STREAM_BYTES >> 20));
        }
        let before = (self.body.len(), self.clean);
        self.body.extend_from_slice(&piece.wire);
        if piece.boundary {
            self.clean = self.body.len();
        }
        if self.note.is_some() {
            return Vec::new();
        }
        let decoded;
        let data = match &mut self.decoder {
            None => piece.data(),
            Some(d) => {
                let fed = d.feed(piece.data());
                let mut out = self.decoded.lock().unwrap_or_else(|e| e.into_inner());
                decoded = std::mem::take(&mut out.buf);
                if let Err(e) = fed {
                    let over = out.over;
                    drop(out);
                    return if over {
                        // Without the piece that went over: what is kept decodes to no more
                        // than a stream may store, also for whoever decodes the row later.
                        self.body.truncate(before.0);
                        self.clean = before.1;
                        self.cut(format!(
                            "recording stopped at the {} MiB a stream may store, decoded",
                            MAX_STREAM_BYTES >> 20
                        ))
                    } else {
                        // What arrived is kept; its events can't be read.
                        self.note = Some(format!("events not parsed past a decoding error: {e}"));
                        Vec::new()
                    };
                }
                &decoded[..]
            }
        };
        let mut events = self.parser.feed(data);
        if self.events + events.len() >= MAX_STREAM_EVENTS {
            events.truncate(MAX_STREAM_EVENTS - self.events);
            self.events = MAX_STREAM_EVENTS;
            self.cut(format!("recording stopped at the {MAX_STREAM_EVENTS} events a stream may store"));
            return events;
        }
        self.events += events.len();
        events
    }

    /// Stops the recording here, marked truncated, `why` as its note: the stream went over a
    /// cap (its own, or the one its recorder's owner keeps over all its streams).
    pub fn cut(&mut self, why: String) -> Vec<Event> {
        self.truncated = true;
        // Not inside a chunk: the body kept still reads as chunked.
        self.body.truncate(self.clean);
        self.note = Some(why);
        Vec::new()
    }

    /// The body kept so far, as received.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The body kept, taken out, for the row of a stream whose recording is over.
    pub fn take_body(&mut self) -> Vec<u8> {
        self.clean = 0;
        std::mem::take(&mut self.body)
    }

    /// Whether the stream went over a cap, so not all of it is kept.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Why not all of the stream is kept or parsed, if so.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// Events kept so far.
    pub fn events(&self) -> usize {
        self.events
    }
}

/// How long and how much of an event stream a sender reads before it stops (`send
/// --stream-wait`, `--max-events`). Every sender has one, so none waits on a stream that
/// never ends: a scan or a crawl that meets one gets what arrived in this time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StreamLimits {
    /// The longest to read for, from the response's head.
    pub wait: Duration,
    /// Stop once this many events have arrived. Events that arrive together with the last
    /// one are read too.
    pub max_events: usize,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self { wait: Duration::from_secs(5), max_events: 100 }
    }
}

/// Why reading a stream stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stopped {
    /// The server ended the response, or closed the connection.
    Closed,
    /// [`StreamLimits::wait`] passed.
    Wait,
    /// [`StreamLimits::max_events`] arrived.
    MaxEvents,
    /// The stream went over what one may store.
    Cap,
    /// Reading failed.
    Error,
}

impl Stopped {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Wait => "wait",
            Self::MaxEvents => "max-events",
            Self::Cap => "cap",
            Self::Error => "error",
        }
    }
}

/// What a sender read of an event stream; the exchange's response holds the body.
#[derive(Debug, Clone)]
pub struct StreamRead {
    /// UTC time reading started: when the response's head had arrived.
    pub opened: String,
    /// The events that arrived, those that came with the last one included: every event in
    /// the body is here.
    pub events: Vec<Event>,
    pub stopped: Stopped,
    /// Not all of the stream is kept: it went over a cap.
    pub truncated: bool,
    /// Why reading stopped early or events are missing, when there is something to say.
    pub note: Option<String>,
}

/// Reads the stream `head` opens from `body` until it ends or `limits` say stop. Returns the
/// body as received (to follow the head in the recorded response) and what was read.
pub async fn read(head: &ResponseHead, body: &mut LiveBody, limits: &StreamLimits) -> (Vec<u8>, StreamRead) {
    let mut recorder = Recorder::new(head);
    let mut events = Vec::new();
    let opened = crate::ws::now_iso();
    let deadline = tokio::time::Instant::now() + limits.wait;
    let mut error = None;
    let stopped = loop {
        if events.len() >= limits.max_events {
            break Stopped::MaxEvents;
        }
        match tokio::time::timeout_at(deadline, body.next()).await {
            Err(_) => break Stopped::Wait,
            Ok(Ok(None)) => break Stopped::Closed,
            Ok(Err(e)) => {
                error = Some(e.to_string());
                break Stopped::Error;
            }
            Ok(Ok(Some(piece))) => {
                events.extend(recorder.push(&piece));
                if recorder.truncated() {
                    break Stopped::Cap;
                }
            }
        }
    };
    let note = match (error, recorder.note()) {
        (Some(e), Some(n)) => Some(format!("{e}; {n}")),
        (e, n) => e.or(n.map(str::to_string)),
    };
    let read = StreamRead { opened, events, stopped, truncated: recorder.truncated(), note };
    (recorder.body, read)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(extra: &str) -> ResponseHead {
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{extra}\r\n");
        crate::http::parse_response_head(raw.as_bytes()).unwrap()
    }

    /// An event's type, id, data and retry.
    type Fields<'a> = (&'a str, Option<&'a str>, Option<&'a str>, Option<u64>);

    fn fields(e: &Event) -> Fields<'_> {
        (e.event.as_str(), e.event_id.as_deref(), e.data.as_deref(), e.retry)
    }

    #[test]
    fn tells_an_event_stream_by_its_content_type() {
        let parse = |raw: &str| crate::http::parse_response_head(raw.as_bytes()).unwrap();
        assert!(is_event_stream(&head("")));
        assert!(is_event_stream(&parse("HTTP/2 200\r\ncontent-type: Text/Event-Stream; charset=utf-8\r\n\r\n")));
        assert!(!is_event_stream(&parse("HTTP/1.1 200 OK\r\nContent-Type: text/event-streams\r\n\r\n")));
        assert!(!is_event_stream(&parse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")));
        assert!(!is_event_stream(&parse("HTTP/1.1 401 No\r\nContent-Type: text/event-stream\r\n\r\n")));
        assert!(!is_event_stream(&parse("HTTP/1.1 204 No Content\r\nContent-Type: text/event-stream\r\n\r\n")));
        assert!(!is_event_stream(&parse("HTTP/1.1 200 OK\r\n\r\n")));
    }

    #[test]
    fn parses_events_as_the_format_says() {
        let stream = "\u{feff}: a comment\n\ndata: first\n\nevent: update\nid: 7\ndata: {\"a\":1}\ndata:two\nretry: 3000\n\n\
                      data\n\nid\nevent:\ndata:  spaced\n\nretry: soon\nid: a\0b\nunknown: x\n\nretry: 10\n\ndata: unfinished\n";
        let want: Vec<Fields> = vec![
            ("message", None, Some("first"), None),
            ("update", Some("7"), Some("{\"a\":1}\ntwo"), Some(3000)),
            // A `data` line with no colon is an empty line of data.
            ("message", None, Some(""), None),
            // An empty `id` resets the last event id; an empty `event` is `message`; one space goes.
            ("message", Some(""), Some(" spaced"), None),
            // The block before this one (a bad retry, an id with a NUL, an unknown field) set
            // nothing: no event. One with only a retry is kept, with no data.
            ("message", None, None, Some(10)),
        ];
        // Whole, byte by byte, and with every line ending the format allows.
        for ending in ["\n", "\r\n", "\r"] {
            let text = stream.replace('\n', ending);
            for step in [text.len(), 1, 2, 5] {
                let mut p = Parser::default();
                let got: Vec<Event> = text.as_bytes().chunks(step).flat_map(|c| p.feed(c)).collect();
                let got: Vec<_> = got.iter().map(fields).collect();
                assert_eq!(got, want, "ending {ending:?} step {step}");
            }
        }
        // A CRLF split over two pieces is one line break, and the LF after it is another.
        let mut p = Parser::default();
        let got: Vec<Event> =
            [&b"data: a\r"[..], b"\n", b"\n", b"data: b\n\n"].into_iter().flat_map(|c| p.feed(c)).collect();
        assert_eq!(got.iter().map(|e| e.data.as_deref()).collect::<Vec<_>>(), [Some("a"), Some("b")]);
        // Text that isn't UTF-8 is kept, with the bad bytes replaced.
        let mut p = Parser::default();
        assert_eq!(p.feed(b"data: a\xffb\n\n")[0].data.as_deref(), Some("a\u{fffd}b"));
    }

    #[test]
    fn a_recorder_keeps_the_body_and_stops_at_the_caps() {
        let mut r = Recorder::new(&head(""));
        assert_eq!(r.push(&Piece::plain(b"data: a\n\ndata: b".to_vec())).len(), 1);
        assert_eq!(r.push(&Piece::plain(b"\n\n".to_vec())).len(), 1);
        assert_eq!((r.body(), r.events(), r.truncated()), (b"data: a\n\ndata: b\n\n".as_slice(), 2, false));

        // The event cap: the events up to it are kept, the rest of the stream isn't.
        let mut r = Recorder::new(&head(""));
        let many = "data: x\n\n".repeat(MAX_STREAM_EVENTS + 5);
        assert_eq!(r.push(&Piece::plain(many.into_bytes())).len(), MAX_STREAM_EVENTS);
        assert!(r.truncated() && r.note().unwrap().contains("events"));
        let kept = r.body().len();
        assert!(r.push(&Piece::plain(b"data: more\n\n".to_vec())).is_empty());
        assert_eq!(r.body().len(), kept);

        // The byte cap: a piece that would pass it isn't kept, and the body ends at a boundary.
        let mut r = Recorder::new(&head(""));
        let half = vec![b':'; MAX_STREAM_BYTES / 2];
        r.push(&Piece::plain(half.clone()));
        let mut inside = Piece::plain(half[..100].to_vec());
        inside.boundary = false;
        r.push(&inside);
        assert!(r.push(&Piece::plain(half.clone())).is_empty());
        assert!(r.truncated() && r.note().unwrap().contains("MiB"));
        assert_eq!(r.body().len(), MAX_STREAM_BYTES / 2);
    }

    #[test]
    fn a_compressed_stream_is_decoded_as_it_arrives() {
        let text = b"data: one\n\ndata: two\n\n";
        let gzip = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&text[..11]).unwrap();
            // As a server does after each event, so the client can read it at once.
            e.flush().unwrap();
            let first = e.get_ref().len();
            e.write_all(&text[11..]).unwrap();
            (e.finish().unwrap(), first)
        };
        let zlib = {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(text).unwrap();
            (e.finish().unwrap(), 0)
        };
        let raw = {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(text).unwrap();
            (e.finish().unwrap(), 0)
        };
        for (coding, (bytes, first)) in [("gzip", gzip), ("deflate", zlib), ("deflate", raw)] {
            let mut r = Recorder::new(&head(&format!("Content-Encoding: {coding}\r\n")));
            let mut events = r.push(&Piece::plain(bytes[..first].to_vec()));
            if first > 0 {
                // The first event is out before the second is sent.
                assert_eq!(events.len(), 1, "{coding}");
            }
            events.extend(r.push(&Piece::plain(bytes[first..].to_vec())));
            let data: Vec<_> = events.iter().map(|e| e.data.as_deref().unwrap()).collect();
            assert_eq!(data, ["one", "two"], "{coding}");
            // The body kept is the body received.
            assert_eq!(r.body(), &bytes[..], "{coding}");
        }
        // However the bytes arrive: a header split over two reads, a byte at a time.
        let whole = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(text).unwrap();
            e.finish().unwrap()
        };
        // Brotli of the same text, flushed after the first event (made with the reference encoder).
        let br: &[u8] = &[
            11, 5, 128, 100, 97, 116, 97, 58, 32, 111, 110, 101, 10, 10, 161, 0, 128, 95, 90, 225, 141, 238, 78, 17,
            162, 74, 4, 96, 11,
        ];
        for (coding, bytes) in [("gzip", &whole[..]), ("br", br)] {
            for step in [1, 3, bytes.len()] {
                let mut r = Recorder::new(&head(&format!("Content-Encoding: {coding}\r\n")));
                let events: Vec<Event> = bytes.chunks(step).flat_map(|c| r.push(&Piece::plain(c.to_vec()))).collect();
                let data: Vec<_> = events.iter().map(|e| e.data.as_deref().unwrap()).collect();
                assert_eq!((data, r.note()), (vec!["one", "two"], None), "{coding} step {step}");
            }
        }
        // Brotli's first event is out at its flush too.
        let mut r = Recorder::new(&head("Content-Encoding: br\r\n"));
        assert_eq!(r.push(&Piece::plain(br[..14].to_vec())).len(), 1);
        // A coding that isn't decoded: the body is kept, and the stream says why it has no events.
        let mut r = Recorder::new(&head("Content-Encoding: zstd\r\n"));
        assert!(r.push(&Piece::plain(b"\x28\xb5\x2f\xfd".to_vec())).is_empty());
        assert!(r.note().unwrap().contains("zstd") && r.body().len() == 4 && !r.truncated());
        // Bytes that aren't the coding they claim.
        let mut r = Recorder::new(&head("Content-Encoding: gzip\r\n"));
        assert!(r.push(&Piece::plain(b"data: plain\n\n".to_vec())).is_empty());
        assert!(r.note().unwrap().contains("decoding error"));
        // A small piece that decodes to more than a stream may store stops the recording.
        let mut bomb = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        bomb.write_all(&vec![b'a'; MAX_STREAM_BYTES + 1024]).unwrap();
        let mut r = Recorder::new(&head("Content-Encoding: gzip\r\n"));
        let bomb = bomb.finish().unwrap();
        assert!(r.push(&Piece::plain(bomb[..20].to_vec())).is_empty());
        r.push(&Piece::plain(bomb[20..].to_vec()));
        assert!(r.truncated() && r.note().unwrap().contains("decoded"));
        // The piece that went over isn't kept, so the row's body can't decode to more either.
        assert_eq!(r.body(), &bomb[..20]);
        let headers = vec![("Content-Encoding".to_string(), "gzip".to_string())];
        assert!(crate::capture::decode_body(&headers, r.body()).len() <= MAX_STREAM_BYTES);
    }
}
