//! WebSockets (RFC 6455): frames, messages reassembled from fragments, permessage-deflate
//! (RFC 7692), and the handshake. The proxy relays upgraded connections through
//! [`relay`] (recording every message, holding some for intercept); `ws send` opens its own
//! connections with [`client`]. Messages are stored in the project database ([`db`]).

pub mod client;
pub mod db;
pub mod relay;

use base64::Engine;
use flate2::{Decompress, FlushDecompress, Status};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::http::ResponseHead;

pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// Largest frame, and largest (decompressed) message, recorded or held. A message can exist
/// in several copies on its way through (read buffer, reassembly, raw frames, inflated
/// payload, recorder queue), so this also bounds peak memory per connection. A direction that
/// goes over it is relayed byte for byte from then on, unrecorded.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// The permessage-deflate tail every compressed message has removed (RFC 7692 7.2.1).
const DEFLATE_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// Which way a message went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    ToServer,
    ToClient,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToServer => "to-server",
            Self::ToClient => "to-client",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "to-server" => Ok(Self::ToServer),
            "to-client" => Ok(Self::ToClient),
            _ => Err(Error::InvalidInput(format!("direction {s:?}: use to-server or to-client"))),
        }
    }

    /// The intercept queue's direction for a message going this way.
    pub fn intercept_direction(self) -> &'static str {
        match self {
            Self::ToServer => "ws-to-server",
            Self::ToClient => "ws-to-client",
        }
    }
}

pub fn opcode_name(op: u8) -> &'static str {
    match op {
        OP_CONTINUATION => "continuation",
        OP_TEXT => "text",
        OP_BINARY => "binary",
        OP_CLOSE => "close",
        OP_PING => "ping",
        OP_PONG => "pong",
        _ => "reserved",
    }
}

pub fn opcode_from_name(name: &str) -> Result<u8> {
    match name {
        "text" => Ok(OP_TEXT),
        "binary" => Ok(OP_BINARY),
        "close" => Ok(OP_CLOSE),
        "ping" => Ok(OP_PING),
        "pong" => Ok(OP_PONG),
        _ => Err(Error::InvalidInput(format!("opcode {name:?}: use text, binary, close, ping, or pong"))),
    }
}

/// One frame with its payload unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    /// RSV1..RSV3 as the frame carries them (0x4 = RSV1, set on compressed messages).
    pub rsv: u8,
    pub opcode: u8,
    pub mask: Option<[u8; 4]>,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn is_control(&self) -> bool {
        self.opcode & 0x8 != 0
    }
}

/// Parses one frame from the start of `buf`. `Ok(None)` means more bytes are needed;
/// otherwise returns the frame and how many bytes it took. Fails on frames RFC 6455
/// forbids (reserved opcodes, fragmented or long control frames) and on frames whose
/// payload is over `max_payload`, as soon as the header says so.
pub fn parse_frame(buf: &[u8], max_payload: usize) -> Result<Option<(Frame, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (b0, b1) = (buf[0], buf[1]);
    let fin = b0 & 0x80 != 0;
    let rsv = (b0 >> 4) & 0x7;
    let opcode = b0 & 0x0f;
    let masked = b1 & 0x80 != 0;
    if matches!(opcode, 0x3..=0x7 | 0xB..=0xF) {
        return Err(Error::Protocol(format!("WebSocket frame with reserved opcode {opcode:#x}")));
    }
    let mut pos = 2;
    let len = match b1 & 0x7f {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            pos = 4;
            u16::from_be_bytes([buf[2], buf[3]]) as u64
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            pos = 10;
            let n = u64::from_be_bytes(buf[2..10].try_into().unwrap());
            if n >> 63 != 0 {
                return Err(Error::Protocol("WebSocket frame length has its top bit set".into()));
            }
            n
        }
        n => n as u64,
    };
    if opcode & 0x8 != 0 && (!fin || len > 125) {
        return Err(Error::Protocol("WebSocket control frame fragmented or over 125 bytes".into()));
    }
    if len > max_payload as u64 {
        return Err(Error::Protocol(format!("WebSocket frame of {len} bytes is over the {max_payload}-byte limit")));
    }
    let mask = if masked {
        if buf.len() < pos + 4 {
            return Ok(None);
        }
        let m = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
        pos += 4;
        Some(m)
    } else {
        None
    };
    let end = pos + len as usize;
    if buf.len() < end {
        return Ok(None);
    }
    let mut payload = buf[pos..end].to_vec();
    if let Some(m) = mask {
        apply_mask(&mut payload, m);
    }
    Ok(Some((Frame { fin, rsv, opcode, mask, payload }, end)))
}

fn apply_mask(data: &mut [u8], mask: [u8; 4]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
}

/// Encodes one frame; `mask` masks the payload (frames from a client must be masked).
pub fn encode_frame(fin: bool, rsv: u8, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(((fin as u8) << 7) | ((rsv & 0x7) << 4) | (opcode & 0x0f));
    let m = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(m | n as u8),
        n if n <= u16::MAX as usize => {
            out.push(m | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(m | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(k) => {
            out.extend_from_slice(&k);
            let start = out.len();
            out.extend_from_slice(payload);
            apply_mask(&mut out[start..], k);
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// A fresh random masking key.
pub fn random_mask() -> [u8; 4] {
    let mut k = [0u8; 4];
    getrandom::fill(&mut k).expect("system random number generator");
    k
}

/// A whole message: a data message reassembled from its fragments (and decompressed), or
/// a control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub opcode: u8,
    pub payload: Vec<u8>,
    /// Sent compressed (permessage-deflate); `payload` is the decompressed form.
    pub compressed: bool,
    pub fragments: u32,
    /// UTC time the last frame arrived (ISO-8601).
    pub time: String,
}

impl Message {
    pub fn new(opcode: u8, payload: Vec<u8>) -> Self {
        Self { opcode, payload, compressed: false, fragments: 1, time: now_iso() }
    }

    pub fn is_data(&self) -> bool {
        matches!(self.opcode, OP_TEXT | OP_BINARY)
    }

    /// Status code and reason of a close message.
    pub fn close_info(&self) -> (Option<u16>, Option<String>) {
        if self.opcode != OP_CLOSE || self.payload.len() < 2 {
            return (None, None);
        }
        let code = u16::from_be_bytes([self.payload[0], self.payload[1]]);
        let reason = String::from_utf8_lossy(&self.payload[2..]).into_owned();
        (Some(code), (!reason.is_empty()).then_some(reason))
    }
}

/// A close frame payload: status code and reason.
pub fn close_payload(code: u16, reason: &str) -> Vec<u8> {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(reason.as_bytes());
    p
}

/// permessage-deflate as negotiated by the handshake response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Deflate {
    pub enabled: bool,
    /// The server resets its compressor after every message.
    pub server_no_context_takeover: bool,
    /// The client resets its compressor after every message.
    pub client_no_context_takeover: bool,
}

impl Deflate {
    /// Reads the server's `Sec-WebSocket-Extensions` answer.
    pub fn from_response(head: &ResponseHead) -> Self {
        let mut d = Self::default();
        for (_, value) in head.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-extensions")) {
            for ext in value.split(',') {
                let mut params = ext.split(';').map(str::trim);
                if !params.next().is_some_and(|n| n.eq_ignore_ascii_case("permessage-deflate")) {
                    continue;
                }
                d.enabled = true;
                for p in params {
                    let name = p.split('=').next().unwrap_or("").trim();
                    if name.eq_ignore_ascii_case("server_no_context_takeover") {
                        d.server_no_context_takeover = true;
                    } else if name.eq_ignore_ascii_case("client_no_context_takeover") {
                        d.client_no_context_takeover = true;
                    }
                }
            }
        }
        d
    }

    /// Whether the sender in `dir` keeps its compression window between messages (so later
    /// messages may refer back to earlier ones).
    pub fn takeover(&self, dir: Direction) -> bool {
        self.enabled
            && !match dir {
                Direction::ToServer => self.client_no_context_takeover,
                Direction::ToClient => self.server_no_context_takeover,
            }
    }
}

/// Reassembles the messages one side sends: fragments joined, compressed messages
/// inflated with the sender's window kept between messages as negotiated.
pub struct Assembler {
    deflate: Deflate,
    takeover: bool,
    inflater: Decompress,
    partial: Option<(u8, bool, Vec<u8>, u32)>,
    max_message: usize,
}

impl Assembler {
    pub fn new(deflate: Deflate, dir: Direction, max_message: usize) -> Self {
        Self { deflate, takeover: deflate.takeover(dir), inflater: Decompress::new(false), partial: None, max_message }
    }

    /// Whether a data message is being reassembled.
    pub fn in_message(&self) -> bool {
        self.partial.is_some()
    }

    /// Takes one frame; returns a message when one is complete. Control frames are
    /// complete messages on their own, also between the fragments of a data message.
    pub fn push(&mut self, f: &Frame) -> Result<Option<Message>> {
        if f.is_control() {
            if f.rsv != 0 {
                return Err(Error::Protocol("WebSocket control frame with RSV bits set".into()));
            }
            return Ok(Some(Message::new(f.opcode, f.payload.clone())));
        }
        let compressed_bit = f.rsv & 0x4 != 0;
        if f.rsv & 0x3 != 0 || (compressed_bit && !self.deflate.enabled) {
            return Err(Error::Protocol("WebSocket frame with RSV bits no extension negotiated".into()));
        }
        match (f.opcode, self.partial.as_mut()) {
            (OP_CONTINUATION, None) => {
                return Err(Error::Protocol("WebSocket continuation frame outside a message".into()))
            }
            (OP_CONTINUATION, Some(p)) => {
                if compressed_bit {
                    return Err(Error::Protocol("WebSocket continuation frame with RSV1 set".into()));
                }
                p.2.extend_from_slice(&f.payload);
                p.3 += 1;
            }
            (_, Some(_)) => return Err(Error::Protocol("WebSocket data frame inside an unfinished message".into())),
            (op, None) => self.partial = Some((op, compressed_bit, f.payload.clone(), 1)),
        }
        if self.partial.as_ref().is_some_and(|p| p.2.len() > self.max_message) {
            return Err(Error::Protocol(format!("WebSocket message over the {}-byte limit", self.max_message)));
        }
        if !f.fin {
            return Ok(None);
        }
        let (opcode, compressed, data, fragments) = self.partial.take().unwrap();
        let payload = if compressed { self.inflate(&data)? } else { data };
        Ok(Some(Message { opcode, payload, compressed, fragments, time: now_iso() }))
    }

    fn inflate(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.takeover {
            self.inflater.reset(false);
        }
        let mut input = data.to_vec();
        input.extend_from_slice(&DEFLATE_TAIL);
        let mut out = Vec::with_capacity(data.len() * 3 + 64);
        let mut pos = 0;
        loop {
            out.reserve(32 * 1024);
            let (in0, out0) = (self.inflater.total_in(), self.inflater.total_out());
            let status = self
                .inflater
                .decompress_vec(&input[pos..], &mut out, FlushDecompress::Sync)
                .map_err(|e| Error::Protocol(format!("WebSocket message doesn't inflate: {e}")))?;
            pos += (self.inflater.total_in() - in0) as usize;
            if out.len() > self.max_message {
                return Err(Error::Protocol(format!(
                    "WebSocket message inflates past the {}-byte limit",
                    self.max_message
                )));
            }
            if status == Status::StreamEnd {
                // The sender ended the deflate stream (final block): the next message starts a new one.
                self.inflater.reset(false);
                break;
            }
            let progressed = self.inflater.total_in() != in0 || self.inflater.total_out() != out0;
            if (pos >= input.len() && out.len() < out.capacity()) || !progressed {
                break;
            }
        }
        Ok(out)
    }
}

/// Whether a response accepts a WebSocket upgrade (101 with `Upgrade: websocket`).
pub fn is_upgrade_response(head: &ResponseHead) -> bool {
    head.status == 101 && head.header("upgrade").is_some_and(|v| v.to_ascii_lowercase().contains("websocket"))
}

/// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key`.
pub fn accept_key(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.trim().as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// A new random `Sec-WebSocket-Key`.
pub fn new_key() -> String {
    let mut k = [0u8; 16];
    getrandom::fill(&mut k).expect("system random number generator");
    base64::engine::general_purpose::STANDARD.encode(k)
}

/// The ws:// or wss:// form of an upgrade request's http(s):// URL (path and query kept).
pub fn ws_url(http_url: &str) -> String {
    if let Some(rest) = http_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = http_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        http_url.to_string()
    }
}

/// The current UTC time as stored in the database (`2026-01-31T12:00:00.000Z`).
pub fn now_iso() -> String {
    let t = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn deflate_msg(c: &mut Compress, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 64);
        c.compress_vec(data, &mut out, FlushCompress::Sync).unwrap();
        assert!(out.ends_with(&DEFLATE_TAIL));
        out.truncate(out.len() - 4);
        out
    }

    fn head(ext: &str) -> ResponseHead {
        crate::http::parse_response_head(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: {ext}\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn frames_round_trip_masked_and_long() {
        for len in [0, 5, 125, 126, 65535, 65536, 70000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            for mask in [None, Some([1, 2, 3, 4])] {
                let bytes = encode_frame(true, 0, OP_BINARY, &payload, mask);
                // Every prefix is incomplete, never an error.
                for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
                    assert!(parse_frame(&bytes[..cut], MAX_MESSAGE).unwrap().is_none(), "len {len} cut {cut}");
                }
                let (f, n) = parse_frame(&bytes, MAX_MESSAGE).unwrap().unwrap();
                assert_eq!(n, bytes.len());
                assert_eq!((f.fin, f.opcode, f.mask, f.payload.len()), (true, OP_BINARY, mask, len));
                assert_eq!(f.payload, payload);
            }
        }
    }

    #[test]
    fn rfc_examples_parse() {
        // RFC 6455 5.7: a single-frame masked text message "Hello".
        let (f, _) =
            parse_frame(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58], 100).unwrap().unwrap();
        assert_eq!(f.payload, b"Hello");
        // A fragmented unmasked text message "Hel" + "lo".
        let mut a = Assembler::new(Deflate::default(), Direction::ToClient, 100);
        let (f1, n1) = parse_frame(&[0x01, 0x03, 0x48, 0x65, 0x6c, 0x00], 100).unwrap().unwrap();
        assert_eq!(n1, 5);
        assert_eq!(a.push(&f1).unwrap(), None);
        // A ping between the fragments is a message of its own.
        let ping = a.push(&parse_frame(&[0x89, 0x05, b'H', b'e', b'l', b'l', b'o'], 100).unwrap().unwrap().0);
        assert_eq!(ping.unwrap().unwrap().opcode, OP_PING);
        let (f2, _) = parse_frame(&[0x80, 0x02, 0x6c, 0x6f], 100).unwrap().unwrap();
        let m = a.push(&f2).unwrap().unwrap();
        assert_eq!((m.opcode, m.payload.as_slice(), m.fragments), (OP_TEXT, &b"Hello"[..], 2));
    }

    #[test]
    fn bad_frames_are_refused() {
        assert!(parse_frame(&[0x83, 0x00], 100).is_err(), "reserved opcode");
        assert!(parse_frame(&[0x09, 0x00], 100).is_err(), "fragmented ping");
        assert!(parse_frame(&[0x89, 126, 0, 200], 1000).is_err(), "long ping");
        assert!(parse_frame(&[0x82, 126, 0x10, 0x00], 100).is_err(), "over the limit, known from the header");
        let mut a = Assembler::new(Deflate::default(), Direction::ToServer, 100);
        assert!(a.push(&Frame { fin: true, rsv: 0, opcode: 0, mask: None, payload: vec![] }).is_err());
        assert!(a.push(&Frame { fin: true, rsv: 4, opcode: 1, mask: None, payload: vec![] }).is_err());
        a.push(&Frame { fin: false, rsv: 0, opcode: 1, mask: None, payload: vec![] }).unwrap();
        assert!(a.push(&Frame { fin: true, rsv: 0, opcode: 1, mask: None, payload: vec![] }).is_err());
    }

    #[test]
    fn close_frames_carry_code_and_reason() {
        let m = Message::new(OP_CLOSE, close_payload(1008, "policy"));
        assert_eq!(m.close_info(), (Some(1008), Some("policy".into())));
        assert_eq!(Message::new(OP_CLOSE, vec![]).close_info(), (None, None));
    }

    #[test]
    fn negotiated_deflate_is_read() {
        let d =
            Deflate::from_response(&head("permessage-deflate; client_max_window_bits=15; server_no_context_takeover"));
        assert!(d.enabled && d.server_no_context_takeover && !d.client_no_context_takeover);
        assert!(d.takeover(Direction::ToServer) && !d.takeover(Direction::ToClient));
        assert!(!Deflate::from_response(&head("x-webkit-deflate-frame")).enabled);
    }

    #[test]
    fn compressed_messages_inflate_with_context_takeover() {
        let d = Deflate::from_response(&head("permessage-deflate"));
        let mut a = Assembler::new(d, Direction::ToClient, MAX_MESSAGE);
        let mut c = Compress::new(Compression::default(), false);
        let text = b"hello hello hello websocket world";
        // The second copy refers back into the first message's window.
        for _ in 0..2 {
            let data = deflate_msg(&mut c, text);
            let m = a.push(&Frame { fin: true, rsv: 4, opcode: OP_TEXT, mask: None, payload: data }).unwrap().unwrap();
            assert!(m.compressed);
            assert_eq!(m.payload, text);
        }
        // Fragmented: RSV1 on the first frame only.
        let data = deflate_msg(&mut c, b"fragmented and compressed");
        let (x, y) = data.split_at(data.len() / 2);
        assert!(a
            .push(&Frame { fin: false, rsv: 4, opcode: OP_TEXT, mask: None, payload: x.to_vec() })
            .unwrap()
            .is_none());
        let m = a.push(&Frame { fin: true, rsv: 0, opcode: 0, mask: None, payload: y.to_vec() }).unwrap().unwrap();
        assert_eq!(m.payload, b"fragmented and compressed");
        // An uncompressed message in between is fine (RSV1 clear).
        let m = a.push(&Frame { fin: true, rsv: 0, opcode: OP_TEXT, mask: None, payload: b"plain".to_vec() }).unwrap();
        assert!(!m.unwrap().compressed);
    }

    #[test]
    fn compressed_messages_inflate_without_context_takeover() {
        let d = Deflate::from_response(&head("permessage-deflate; server_no_context_takeover"));
        let mut a = Assembler::new(d, Direction::ToClient, MAX_MESSAGE);
        for word in ["first message", "second message"] {
            let mut c = Compress::new(Compression::default(), false);
            let data = deflate_msg(&mut c, word.as_bytes());
            let m = a.push(&Frame { fin: true, rsv: 4, opcode: OP_TEXT, mask: None, payload: data }).unwrap();
            assert_eq!(m.unwrap().payload, word.as_bytes());
        }
    }

    #[test]
    fn inflation_is_bounded() {
        let d = Deflate::from_response(&head("permessage-deflate"));
        let mut a = Assembler::new(d, Direction::ToClient, 1000);
        let mut c = Compress::new(Compression::default(), false);
        let data = deflate_msg(&mut c, &vec![b'a'; 100_000]);
        assert!(data.len() < 1000);
        let e = a.push(&Frame { fin: true, rsv: 4, opcode: OP_TEXT, mask: None, payload: data }).unwrap_err();
        assert!(e.to_string().contains("limit"), "{e}");
    }

    #[test]
    fn accept_key_matches_rfc() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(ws_url("https://a.test/chat?x=1"), "wss://a.test/chat?x=1");
    }
}
