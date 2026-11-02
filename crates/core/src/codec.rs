//! Encoders, decoders, and hashes (the Decoder tool).

use std::io::Read;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use md5::Md5;
use percent_encoding::{percent_decode, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

/// Characters left alone by `url` encoding: RFC 3986 unreserved.
const URL_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

pub const ENCODINGS: &[&str] = &["base64", "base64url", "url", "url-all", "hex", "html", "gzip", "zlib", "deflate"];
pub const DECODINGS: &[&str] =
    &["base64", "base64url", "url", "hex", "html", "jwt", "gzip", "zlib", "deflate", "brotli", "auto"];
pub const HASHES: &[&str] = &["md5", "sha1", "sha256", "sha512"];

/// Most bytes a decompression may produce, so a small "bomb" can't fill memory.
pub const MAX_INFLATED: u64 = 16 * 1024 * 1024;

/// Most decodings `auto` stacks before it stops.
pub const SMART_DEPTH: usize = 8;

pub fn encode(kind: &str, input: &[u8]) -> Result<Vec<u8>> {
    Ok(match kind {
        "base64" => STANDARD.encode(input).into_bytes(),
        "base64url" => URL_SAFE_NO_PAD.encode(input).into_bytes(),
        "url" => match std::str::from_utf8(input) {
            Ok(s) => utf8_percent_encode(s, URL_COMPONENT).to_string().into_bytes(),
            Err(_) => percent_all(input, URL_COMPONENT),
        },
        // Percent-encodes every byte, like "URL-encode all characters".
        "url-all" => input.iter().flat_map(|b| format!("%{b:02X}").into_bytes()).collect(),
        "hex" => hex::encode(input).into_bytes(),
        "html" => html_encode(input),
        "gzip" => compress(flate2::read::GzEncoder::new(input, flate2::Compression::default()))?,
        "zlib" => compress(flate2::read::ZlibEncoder::new(input, flate2::Compression::default()))?,
        // Raw DEFLATE (RFC 1951): no header or checksum.
        "deflate" => compress(flate2::read::DeflateEncoder::new(input, flate2::Compression::default()))?,
        other => return Err(unknown("encoding", other, ENCODINGS)),
    })
}

/// Percent-encodes only what isn't valid in a URL (space, quotes, <>, #, `, {}, |, \, ^,
/// control and non-ASCII bytes, a '%' not starting an escape) and keeps the characters that
/// give a URL or form body its structure (/ ? & = ; and existing %XX). Idempotent.
pub fn encode_loose(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (i, &b) in input.iter().enumerate() {
        let escape = b == b'%' && input.get(i + 1..i + 3).is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit));
        let safe = b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?[]".contains(&b);
        if safe || escape {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

pub fn decode(kind: &str, input: &[u8]) -> Result<Vec<u8>> {
    let trimmed = trim_ascii(input);
    Ok(match kind {
        "base64" => {
            let s: Vec<u8> = trimmed.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
            STANDARD
                .decode(&s)
                .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&s))
                .or_else(|_| URL_SAFE_NO_PAD.decode(s.iter().copied().filter(|&b| b != b'=').collect::<Vec<_>>()))
                .map_err(|e| Error::InvalidInput(format!("base64: {e}")))?
        }
        "base64url" => URL_SAFE_NO_PAD
            .decode(trimmed.iter().copied().filter(|&b| b != b'=').collect::<Vec<_>>())
            .map_err(|e| Error::InvalidInput(format!("base64url: {e}")))?,
        "url" => {
            let plus_as_space: Vec<u8> = input.iter().map(|&b| if b == b'+' { b' ' } else { b }).collect();
            percent_decode(&plus_as_space).collect()
        }
        "hex" => {
            let s: Vec<u8> = trimmed.iter().copied().filter(|b| !b.is_ascii_whitespace() && *b != b':').collect();
            let s = s.strip_prefix(b"0x").unwrap_or(&s);
            hex::decode(s).map_err(|e| Error::InvalidInput(format!("hex: {e}")))?
        }
        "html" => html_decode(&String::from_utf8_lossy(input)).into_bytes(),
        "jwt" => serde_json::to_vec_pretty(&decode_jwt(&String::from_utf8_lossy(trimmed))?)
            .map_err(|e| Error::InvalidInput(e.to_string()))?,
        // Compressed data is binary: use the input as given, untrimmed.
        "gzip" => inflate("gzip", flate2::read::MultiGzDecoder::new(input))?,
        "zlib" => inflate("zlib", flate2::read::ZlibDecoder::new(input))?,
        // Raw DEFLATE, or zlib-wrapped as HTTP's Content-Encoding: deflate usually is. With a
        // zlib header, the zlib error (such as the size limit) is the one worth reporting.
        "deflate" => inflate("zlib", flate2::read::ZlibDecoder::new(input)).or_else(|e| {
            if zlib_header(input) {
                Err(e)
            } else {
                inflate("deflate", flate2::read::DeflateDecoder::new(input))
            }
        })?,
        "brotli" => inflate("brotli", brotli_decompressor::Decompressor::new(input, 4096))?,
        "auto" => smart_decode(input).output,
        other => return Err(unknown("decoding", other, DECODINGS)),
    })
}

pub fn hash(kind: &str, input: &[u8]) -> Result<String> {
    Ok(match kind {
        "md5" => hex::encode(Md5::digest(input)),
        "sha1" => hex::encode(Sha1::digest(input)),
        "sha256" => hex::encode(Sha256::digest(input)),
        "sha512" => hex::encode(Sha512::digest(input)),
        other => return Err(unknown("hash", other, HASHES)),
    })
}

/// Splits a JWT into its decoded header and payload. The signature is not verified.
pub fn decode_jwt(token: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() < 2 {
        return Err(Error::InvalidInput("JWT must have at least two dot-separated parts".into()));
    }
    let part = |i: usize, name: &str| -> Result<serde_json::Value> {
        let raw = URL_SAFE_NO_PAD
            .decode(parts[i].trim_end_matches('='))
            .map_err(|e| Error::InvalidInput(format!("JWT {name}: {e}")))?;
        serde_json::from_slice(&raw).map_err(|e| Error::InvalidInput(format!("JWT {name} is not JSON: {e}")))
    };
    Ok(serde_json::json!({
        "header": part(0, "header")?,
        "payload": part(1, "payload")?,
        "signature": parts.get(2).copied().unwrap_or(""),
    }))
}

/// What `smart_decode` found: the decodings it applied, in order, and the result.
#[derive(Debug, PartialEq)]
pub struct Smart {
    pub steps: Vec<&'static str>,
    pub output: Vec<u8>,
}

/// Detects and applies decodings until none applies, up to `SMART_DEPTH` steps. Each step
/// is a `decode` kind, so running the steps one by one gives the same output. Base64 and
/// hex count only when the whole input is one and it decodes to readable text or
/// compressed data, so plain words that happen to be valid base64 or hex are left alone.
pub fn smart_decode(input: &[u8]) -> Smart {
    let mut steps = Vec::new();
    let mut value = input.to_vec();
    while steps.len() < SMART_DEPTH {
        let Some((kind, next)) = smart_step(&value) else { break };
        steps.push(kind);
        value = next;
        // A JWT decodes to JSON: nothing further to undo.
        if kind == "jwt" {
            break;
        }
    }
    Smart { steps, output: value }
}

/// The first decoding that applies to `v`, and its output.
fn smart_step(v: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    let attempt =
        |kind: &'static str| decode(kind, v).ok().filter(|out| !out.is_empty() && out != v).map(|out| (kind, out));
    // Escapes count when they decode to text; base64 and hex need more (see looks_decoded).
    let text_out = |found: &(&'static str, Vec<u8>)| compressed(&found.1) || is_text(&found.1);
    let decoded_out = |found: &(&'static str, Vec<u8>)| looks_decoded(&found.1);
    if v.starts_with(&[0x1f, 0x8b]) {
        return attempt("gzip");
    }
    if zlib_header(v) {
        if let Some(found) = attempt("zlib") {
            return Some(found);
        }
    }
    let text = std::str::from_utf8(v).ok()?.trim();
    if looks_like_jwt(text) {
        return attempt("jwt");
    }
    if has_percent_escape(text) {
        if let Some(found) = attempt("url").filter(text_out) {
            return Some(found);
        }
    }
    if text.contains('&') {
        if let Some(found) = attempt("html").filter(text_out) {
            return Some(found);
        }
    }
    if looks_like_hex(text) {
        if let Some(found) = attempt("hex").filter(decoded_out) {
            return Some(found);
        }
    }
    attempt(looks_like_base64(text)?).filter(decoded_out)
}

/// A zlib stream header (RFC 1950): the deflate method, a window size zlib allows, no
/// preset dictionary, and valid check bits.
fn zlib_header(v: &[u8]) -> bool {
    match v {
        [cmf, flg, ..] => {
            cmf & 0x0f == 8 && cmf >> 4 <= 7 && flg & 0x20 == 0 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0
        }
        _ => false,
    }
}

fn looks_like_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    let b64url = |p: &&str| p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    (2..=3).contains(&parts.len()) && parts[0].starts_with("eyJ") && parts.iter().all(b64url)
}

fn has_percent_escape(s: &str) -> bool {
    s.as_bytes().windows(3).any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}

/// Hex with both a digit and a letter, so words like "deadbeef" and numbers like
/// "20240101" stay as they are: eight bytes or more, or four or more marked as hex by a
/// "0x" prefix or by spaces or colons between bytes.
fn looks_like_hex(s: &str) -> bool {
    let (marked, s) = s.strip_prefix("0x").map_or((false, s), |rest| (true, rest));
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b':').collect();
    let marked = marked || digits.len() < s.len();
    digits.len() >= if marked { 8 } else { 16 }
        && digits.len().is_multiple_of(2)
        && digits.iter().all(u8::is_ascii_hexdigit)
        && digits.iter().any(u8::is_ascii_digit)
        && digits.iter().any(u8::is_ascii_alphabetic)
}

/// The base64 kind `s` is written in, if it is one run of at least eight base64
/// characters (line breaks allowed, not spaces) with padding only at the end.
fn looks_like_base64(s: &str) -> Option<&'static str> {
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'\r' && b != b'\n').collect();
    let (body, pad) = s.split_at(s.iter().position(|&b| b == b'=').unwrap_or(s.len()));
    let standard = body.iter().any(|&b| b == b'+' || b == b'/');
    let url_safe = body.iter().any(|&b| b == b'-' || b == b'_');
    // Short words and passwords ("Michelle", "Sydney01") are valid base64 too: below 16
    // characters, ask for padding, a symbol, or two capitals, two small letters, and a digit.
    let count = |f: fn(&u8) -> bool| body.iter().filter(|b| f(b)).count();
    let mixed =
        count(u8::is_ascii_uppercase) >= 2 && count(u8::is_ascii_lowercase) >= 2 && count(u8::is_ascii_digit) >= 1;
    let ok = s.len() >= 8
        && (s.len() >= 16 || !pad.is_empty() || standard || url_safe || mixed)
        && body.len() % 4 != 1
        && pad.len() <= 2
        && pad.iter().all(|&b| b == b'=')
        && body.iter().all(|&b| b.is_ascii_alphanumeric() || b"+/-_".contains(&b))
        && !(standard && url_safe);
    ok.then_some(if url_safe { "base64url" } else { "base64" })
}

fn compressed(v: &[u8]) -> bool {
    v.starts_with(&[0x1f, 0x8b]) || zlib_header(v)
}

/// UTF-8 with no control characters but tabs and line breaks.
fn is_text(v: &[u8]) -> bool {
    std::str::from_utf8(v).is_ok_and(|s| s.chars().all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r')))
}

/// Whether base64 or hex output looks like progress: compressed data to unpack, JSON, or
/// printable ASCII. Under 12 bytes, chance printable output is common, so short text must
/// also be at least half letters, digits, and spaces.
fn looks_decoded(v: &[u8]) -> bool {
    if compressed(v) {
        return true;
    }
    if !v.iter().all(|&b| b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\n' | b'\r')) {
        return false;
    }
    let wordy = v.iter().filter(|&&b| b.is_ascii_alphanumeric() || b == b' ').count();
    wordy > 0 && (v.len() >= 12 || wordy * 2 >= v.len())
        || serde_json::from_slice::<serde_json::Value>(v).is_ok_and(|j| j.is_object() || j.is_array())
}

fn compress(mut encoder: impl Read) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encoder.read_to_end(&mut out)?;
    Ok(out)
}

/// Reads a decompressor to the end, refusing output over `MAX_INFLATED`.
fn inflate(name: &str, decoder: impl Read) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    decoder.take(MAX_INFLATED + 1).read_to_end(&mut out).map_err(|e| Error::InvalidInput(format!("{name}: {e}")))?;
    if out.len() as u64 > MAX_INFLATED {
        return Err(Error::InvalidInput(format!(
            "{name}: output is over the {} MB limit (a decompression bomb?)",
            MAX_INFLATED / (1024 * 1024)
        )));
    }
    Ok(out)
}

fn percent_all(input: &[u8], set: &'static AsciiSet) -> Vec<u8> {
    percent_encoding::percent_encode(input, set).to_string().into_bytes()
}

fn html_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&#x27;"),
            _ => out.push(b),
        }
    }
    out
}

fn html_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest.find(';').filter(|&semi| semi <= 12).and_then(|semi| {
            let entity = &rest[1..semi];
            let ch = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                "hellip" => Some('…'),
                _ => entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .and_then(char::from_u32),
            };
            ch.map(|c| (c, semi))
        });
        match decoded {
            Some((c, semi)) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn trim_ascii(input: &[u8]) -> &[u8] {
    let start = input.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(input.len());
    let end = input.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |i| i + 1);
    &input[start..end]
}

fn unknown(what: &str, name: &str, valid: &[&str]) -> Error {
    Error::InvalidInput(format!("unknown {what} {name:?}; valid: {}", valid.join(", ")))
}

#[cfg(test)]
mod tests {

    #[test]
    fn encode_loose_keeps_structure() {
        assert_eq!(encode_loose(b"x' OR \"1\"=1 <b>#&a=%41%zz"), b"x'%20OR%20%221%22=1%20%3Cb%3E%23&a=%41%25zz");
        assert_eq!(encode_loose("é".as_bytes()), b"%C3%A9");
        let once = encode_loose(b"a b");
        assert_eq!(encode_loose(&once), once);
    }

    use super::*;

    #[test]
    fn round_trips() {
        for kind in ["base64", "base64url", "url", "hex", "html"] {
            let input = "a b&c<d>\"'é/?=+".as_bytes();
            let enc = encode(kind, input).unwrap();
            assert_eq!(decode(kind, &enc).unwrap(), input, "{kind}");
        }
        assert_eq!(encode("url-all", b"ab").unwrap(), b"%61%62");
        assert_eq!(decode("url", b"%61+b").unwrap(), b"a b");
    }

    #[test]
    fn html_entities() {
        assert_eq!(html_decode("&lt;&#x41;&#66;&bogus;&"), "<AB&bogus;&");
    }

    #[test]
    fn hashes() {
        assert_eq!(hash("md5", b"abc").unwrap(), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hash("sha256", b"abc").unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn jwt() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig";
        let v = decode_jwt(token).unwrap();
        assert_eq!(v["header"]["alg"], "HS256");
        assert_eq!(v["payload"]["sub"], "1");
    }

    #[test]
    fn compression_round_trips() {
        let input = "{\"user\":\"admin\"} \n".repeat(20);
        for kind in ["gzip", "zlib", "deflate"] {
            let enc = encode(kind, input.as_bytes()).unwrap();
            assert!(enc.len() < input.len(), "{kind}");
            assert_eq!(decode(kind, &enc).unwrap(), input.as_bytes(), "{kind}");
        }
        assert_eq!(&encode("gzip", b"x").unwrap()[..2], [0x1f, 0x8b]);
        // "deflate" also takes the zlib-wrapped form HTTP servers send.
        assert_eq!(decode("deflate", &encode("zlib", b"abc").unwrap()).unwrap(), b"abc");
        // A stored (uncompressed) brotli meta-block holding "hello".
        assert_eq!(decode("brotli", b"\x0b\x02\x80hello\x03").unwrap(), b"hello");
    }

    #[test]
    fn compression_errors() {
        for kind in ["gzip", "zlib", "brotli"] {
            let err = decode(kind, b"not compressed at all").unwrap_err().to_string();
            assert!(err.contains(kind), "{kind}: {err}");
        }
        let bomb = encode("gzip", &vec![0u8; MAX_INFLATED as usize + 1]).unwrap();
        assert!(bomb.len() < 64 * 1024);
        let err = decode("gzip", &bomb).unwrap_err().to_string();
        assert!(err.contains("16 MB limit"), "{err}");
        assert_eq!(decode("gzip", &encode("gzip", &vec![0u8; MAX_INFLATED as usize]).unwrap()).unwrap().len(), 1 << 24);
        let bomb = encode("zlib", &vec![0u8; MAX_INFLATED as usize + 1]).unwrap();
        let err = decode("deflate", &bomb).unwrap_err().to_string();
        assert!(err.contains("zlib: output is over the 16 MB limit"), "{err}");
    }

    #[test]
    fn smart_decode_unwraps_layers() {
        let json = br#"{"user":"admin","role":"staff"}"#;
        let layered = encode("url", &encode("base64", &encode("gzip", json).unwrap()).unwrap()).unwrap();
        let s = smart_decode(&layered);
        assert_eq!(s.steps, ["url", "base64", "gzip"]);
        assert_eq!(s.output, json);
        // Running the steps one by one gives the same result.
        let replay = s.steps.iter().fold(layered.clone(), |v, k| decode(k, &v).unwrap());
        assert_eq!(replay, s.output);
        assert_eq!(decode("auto", &layered).unwrap(), json);

        let cases: &[(&[u8], &[&str], &[u8])] = &[
            (b"SGVsbG8sIHdvcmxkIQ==", &["base64"], b"Hello, world!"),
            (b"PD94bWw-PHg-YTwveD4_", &["base64url"], b"<?xml><x>a</x>?"),
            (b"48656c6c6f2c20776f726c6421", &["hex"], b"Hello, world!"),
            (b"0x48:65:6c:6c:6f:21", &["hex"], b"Hello!"),
            (b"%3Cscript%3Ealert(1)%3C%2Fscript%3E", &["url"], b"<script>alert(1)</script>"),
            (b"&lt;b&gt;bold&#x3C;/b&#62;", &["html"], b"<b>bold</b>"),
            (b"JTNDYiUzRWhpJTNDJTJGYiUzRQ==", &["base64", "url"], b"<b>hi</b>"),
        ];
        for (input, steps, output) in cases {
            let s = smart_decode(input);
            assert_eq!(s.steps, *steps, "{}", String::from_utf8_lossy(input));
            assert_eq!(s.output, *output, "{}", String::from_utf8_lossy(input));
        }

        let zlib_hex = encode("hex", &encode("zlib", b"secret=1").unwrap()).unwrap();
        assert_eq!(smart_decode(&zlib_hex), Smart { steps: vec!["hex", "zlib"], output: b"secret=1".to_vec() });

        let s = smart_decode(b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln");
        assert_eq!(s.steps, ["jwt"]);
        let v: serde_json::Value = serde_json::from_slice(&s.output).unwrap();
        assert_eq!(v["payload"]["sub"], "1");
    }

    #[test]
    fn smart_decode_leaves_plain_text_alone() {
        let plain = [
            "password",
            "username",
            "Administrator",
            "deadbeef",
            "cafebabe",
            "decade",
            "facade12",
            "20240101",
            "1234567890",
            "12345678",
            "abcdef0123",
            "test1234",
            "Hello",
            "hello world",
            "localhost",
            "JavaScript",
            "application",
            "Authorization",
            "keepalive",
            "superuser",
            "qwertyuiop",
            "letmein1",
            "Passw0rd",
            "admin123",
            "id=1&page=2",
            "AT&T rocks",
            "100% sure",
            "{\"a\":1}",
            "SELECT * FROM users",
            "/api/v1/users",
            "eyJ",
            "aGVsbG8",
            "x^plain text",
            "Sydney01",
            "R2d2c3po",
            "7777777a",
            "5a5a5a5a",
            "!@#$%12345",
            "100%devil",
            "isAdminUser",
            "McDonald",
            "circumstantially",
            "userName",
        ];
        for word in plain {
            let s = smart_decode(word.as_bytes());
            assert!(s.steps.is_empty(), "{word:?} decoded as {:?}", s.steps);
            assert_eq!(s.output, word.as_bytes());
        }
        // Binary input that isn't compressed stays as it is too.
        assert!(smart_decode(&[0xff, 0x00, 0x13, 0x37]).steps.is_empty());
    }

    #[test]
    fn smart_decode_stops_at_depth() {
        let mut v = b"deep secret value".to_vec();
        for _ in 0..SMART_DEPTH + 2 {
            v = encode("base64", &v).unwrap();
        }
        let s = smart_decode(&v);
        assert_eq!(s.steps.len(), SMART_DEPTH);
        assert!(s.steps.iter().all(|k| *k == "base64"));
    }
}
