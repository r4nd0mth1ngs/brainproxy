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
    &["base64", "base64url", "url", "percent", "hex", "html", "jwt", "gzip", "zlib", "deflate", "brotli", "auto"];
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
        // %XX escapes only: a '+' stays a '+', as in paths, cookies, and headers.
        "percent" => percent_decode(input).collect(),
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
        // Raw DEFLATE, or zlib-wrapped as HTTP's Content-Encoding: deflate usually is. A raw
        // stream can start with bytes that pass as a zlib header, so raw is tried whenever
        // zlib fails, except at the size limit. If both fail, a zlib header means the zlib
        // error is the one worth reporting.
        "deflate" => match read_inflated(flate2::read::ZlibDecoder::new(input)) {
            Ok(out) => out,
            Err(zlib @ Inflate::TooBig) => return Err(zlib.error("zlib")),
            Err(zlib) => match read_inflated(flate2::read::DeflateDecoder::new(input)) {
                Ok(out) => out,
                Err(raw @ Inflate::TooBig) => return Err(raw.error("deflate")),
                Err(_) if zlib_header(input) => return Err(zlib.error("zlib")),
                Err(raw) => return Err(raw.error("deflate")),
            },
        },
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
    // Only the syntax counts here, not what the base64 holds: if it holds binary, reading
    // the '+' as a space would turn base64 into neither base64 nor text.
    let base64_inside = |found: &(&'static str, Vec<u8>)| {
        std::str::from_utf8(&found.1).ok().and_then(|s| looks_like_base64(s.trim())) == Some("base64")
            && decode("base64", &found.1).is_ok()
    };
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
        // '+' means a space only in form data. Base64 in a cookie or header often has a raw
        // '+' and only its '=' escaped: undo the escapes and keep the '+', even when the
        // base64 itself goes no further.
        if text.contains('+') {
            if let Some(found) = attempt("percent").filter(base64_inside) {
                return Some(found);
            }
        }
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

/// Whether `v` is a gzip or zlib stream that unpacks, or would but for `MAX_INFLATED` (a
/// bomb is still compressed data). The first bytes alone aren't enough: about 1 in 2000
/// random byte pairs is a valid zlib header, so random IDs would decode to garbage.
fn compressed(v: &[u8]) -> bool {
    let unpacks = |r: &mut dyn Read| std::io::copy(&mut r.take(MAX_INFLATED + 1), &mut std::io::sink()).is_ok();
    (v.starts_with(&[0x1f, 0x8b]) && unpacks(&mut flate2::read::MultiGzDecoder::new(v)))
        || (zlib_header(v) && unpacks(&mut flate2::read::ZlibDecoder::new(v)))
}

/// UTF-8 with no control characters but tabs and line breaks.
fn is_text(v: &[u8]) -> bool {
    std::str::from_utf8(v).is_ok_and(|s| s.chars().all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r')))
}

/// Whether base64 or hex output looks like progress: compressed data to unpack, printable
/// ASCII, or a JSON object or array (UTF-8, so non-ASCII strings count).
fn looks_decoded(v: &[u8]) -> bool {
    // JSON last: the ASCII check reads the bytes once, while parsing walks the whole tree.
    compressed(v) || printable_ascii(v) || json_container(v)
}

/// Printable ASCII. Under 12 bytes, chance printable output is common, so short text must
/// also be at least half letters, digits, and spaces.
fn printable_ascii(v: &[u8]) -> bool {
    if !v.iter().all(|&b| b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\n' | b'\r')) {
        return false;
    }
    let wordy = v.iter().filter(|&&b| b.is_ascii_alphanumeric() || b == b' ').count();
    wordy > 0 && (v.len() >= 12 || wordy * 2 >= v.len())
}

/// A JSON object or array, checked without building it (decoded output can be megabytes).
fn json_container(v: &[u8]) -> bool {
    matches!(v.iter().find(|b| !b.is_ascii_whitespace()), Some(b'{' | b'['))
        && serde_json::from_slice::<serde::de::IgnoredAny>(v).is_ok()
}

fn compress(mut encoder: impl Read) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encoder.read_to_end(&mut out)?;
    Ok(out)
}

/// Reads a decompressor to the end, refusing output over `MAX_INFLATED`.
fn inflate(name: &str, decoder: impl Read) -> Result<Vec<u8>> {
    read_inflated(decoder).map_err(|e| e.error(name))
}

/// Why a decompression failed: bad data, or output over `MAX_INFLATED`.
enum Inflate {
    Bad(std::io::Error),
    TooBig,
}

impl Inflate {
    fn error(self, name: &str) -> Error {
        Error::InvalidInput(match self {
            Inflate::Bad(e) => format!("{name}: {e}"),
            Inflate::TooBig => {
                format!("{name}: output is over the {} MB limit (a decompression bomb?)", MAX_INFLATED / (1024 * 1024))
            }
        })
    }
}

fn read_inflated(decoder: impl Read) -> std::result::Result<Vec<u8>, Inflate> {
    let mut out = Vec::new();
    decoder.take(MAX_INFLATED + 1).read_to_end(&mut out).map_err(Inflate::Bad)?;
    if out.len() as u64 > MAX_INFLATED {
        return Err(Inflate::TooBig);
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
        assert_eq!(decode("percent", b"%61+b%2B").unwrap(), b"a+b+");
        assert_eq!(decode("percent", &encode("url", "a b/é".as_bytes()).unwrap()).unwrap(), "a b/é".as_bytes());
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
            // Decode to bytes that start like a zlib header but don't unpack.
            "789c00112233445566778899aabbccdd",
            "SMdYmAPoi73dreeA",
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

    /// Runs `steps` one decode at a time, as the Codec view does with what `auto` found.
    fn replay(input: &[u8], steps: &[&str]) -> Vec<u8> {
        steps.iter().fold(input.to_vec(), |v, k| decode(k, &v).unwrap())
    }

    #[test]
    fn compression_edge_cases() {
        let all: Vec<u8> = (0..=255).collect();
        for kind in ["gzip", "zlib", "deflate"] {
            assert_eq!(decode(kind, &encode(kind, b"").unwrap()).unwrap(), b"", "{kind}");
            assert_eq!(decode(kind, &encode(kind, &all).unwrap()).unwrap(), all, "{kind}");
            let enc = encode(kind, b"hello hello hello").unwrap();
            let err = decode(kind, &enc[..enc.len() / 2]).unwrap_err().to_string();
            assert!(err.contains(&format!("{kind}: ")), "{kind}: {err}");
        }
        // Empty input is an error, not empty output.
        for kind in ["gzip", "zlib", "deflate", "brotli"] {
            let err = decode(kind, b"").unwrap_err().to_string();
            assert!(err.contains(&format!("{kind}: ")), "{kind}: {err}");
        }
        assert!(decode("deflate", b"not compressed at all").unwrap_err().to_string().contains("deflate: "));
        // Compressed input isn't trimmed: a zlib stream whose checksum ends in a whitespace
        // byte still decodes.
        let (plain, enc) = (0..10_000)
            .map(|i| format!("x{i}"))
            .map(|p| (encode("zlib", p.as_bytes()).unwrap(), p))
            .find(|(e, _)| e.last().unwrap().is_ascii_whitespace())
            .map(|(e, p)| (p, e))
            .unwrap();
        assert_eq!(decode("zlib", &enc).unwrap(), plain.as_bytes());
        assert_eq!(decode("deflate", &enc).unwrap(), plain.as_bytes());
        // gzip members back to back decode as one body.
        let mut two = encode("gzip", b"ab").unwrap();
        two.extend(encode("gzip", b"cd").unwrap());
        assert_eq!(decode("gzip", &two).unwrap(), b"abcd");
        // Made with Python's brotli module: "hello" four times.
        let brotli = hex::decode("1b1600f88d946ede445586966c206f214f1ce038").unwrap();
        assert_eq!(decode("brotli", &brotli).unwrap(), b"hello hello hello hello");
        assert!(decode("brotli", b"\x0b\x02\x80hel").unwrap_err().to_string().contains("brotli: "));
    }

    #[test]
    fn every_decompressor_is_capped() {
        let over = vec![0u8; MAX_INFLATED as usize + 1];
        for kind in ["zlib", "deflate"] {
            let bomb = encode(kind, &over).unwrap();
            assert!(bomb.len() < 64 * 1024, "{kind}");
            let err = decode(kind, &bomb).unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)), "{kind}");
            assert!(err.to_string().contains(&format!("{kind}: output is over the 16 MB limit")), "{kind}: {err}");
            assert_eq!(decode(kind, &encode(kind, &over[1..]).unwrap()).unwrap().len(), 1 << 24, "{kind}");
        }
        // Made with Python's brotli module: 16 MiB + 1 zero bytes in 32 bytes, then exactly 16 MiB.
        let bomb = hex::decode("cbffff3ff82700e2b14020f7fe8fffff7ff04f00c4611180eefd1f0000020003").unwrap();
        let err = decode("brotli", &bomb).unwrap_err().to_string();
        assert!(err.contains("brotli: output is over the 16 MB limit"), "{err}");
        let limit = hex::decode("cbffff3ff82700e2b14020f7fe8fffff7ff04f00c4611180eefddf").unwrap();
        assert_eq!(decode("brotli", &limit).unwrap().len(), 1 << 24);
    }

    #[test]
    fn codec_kind_lists_match() {
        // brotli only decodes, and `auto` is a decode kind only.
        for kind in ["brotli", "auto"] {
            let err = encode(kind, b"x").unwrap_err().to_string();
            assert!(err.contains(&format!("unknown encoding {kind:?}")) && err.contains("deflate"), "{err}");
        }
        let err = decode("zstd", b"x").unwrap_err().to_string();
        assert!(err.contains("brotli, auto"), "{err}");
        for kind in ENCODINGS.iter().filter(|k| **k != "url-all") {
            assert!(DECODINGS.contains(kind), "{kind}");
        }
    }

    #[test]
    fn smart_decode_steps_replay() {
        let gzip = encode("gzip", b"{\"id\":7}").unwrap();
        let wrapped: Vec<u8> = encode("base64", "The quick brown fox jumps over the lazy dog. ".repeat(10).as_bytes())
            .unwrap()
            .chunks(76)
            .collect::<Vec<_>>()
            .join(&b"\r\n"[..]);
        let cases: &[(&[u8], &[&str], &[u8])] = &[
            // A form value: '+' is a space once there is an escape to undo.
            (b"q=hello+world&x=%2F", &["url"], b"q=hello world&x=/"),
            // Base64 with a raw '+' and an escaped '=', as cookies often carry it.
            (b"SGk+dGhlcmU%3D", &["percent", "base64"], b"Hi>there"),
            (b"a+b%3D", &["url"], b"a b="),
            (b"%253Cb%253E", &["url", "url"], b"<b>"),
            (b"%E2%9C%93", &["url"], "\u{2713}".as_bytes()),
            (b"&amp;lt;b&amp;gt;", &["html", "html"], b"<b>"),
            (b"Tom &amp; Jerry", &["html"], b"Tom & Jerry"),
            (b"&#x1F600;", &["html"], "\u{1F600}".as_bytes()),
            // Pasted or piped with a line break at the end.
            (b"SGVsbG8sIHdvcmxkIQ==\n", &["base64"], b"Hello, world!"),
            (b"  dGVzdA==  ", &["base64"], b"test"),
            // Starts like a JWT, but one part only: plain base64 JSON.
            (b"eyJhIjoxfQ==", &["base64"], b"{\"a\":1}"),
            (b"48 65 6c 6c 6f 2c 20 77 6f 72 6c 64", &["hex"], b"Hello, world"),
            (&gzip, &["gzip"], b"{\"id\":7}"),
        ];
        for (input, steps, output) in cases {
            let s = smart_decode(input);
            assert_eq!(s.steps, *steps, "{}", String::from_utf8_lossy(input));
            assert_eq!(s.output, *output, "{}", String::from_utf8_lossy(input));
            assert_eq!(replay(input, &s.steps), s.output, "{}", String::from_utf8_lossy(input));
            assert_eq!(decode("auto", input).unwrap(), s.output);
        }
        let s = smart_decode(&wrapped);
        assert_eq!(s.steps, ["base64"]);
        assert!(s.output.starts_with(b"The quick brown fox"));

        // The magic bytes are enough: gzip is unpacked even when what it holds is binary.
        let s = smart_decode(&encode("base64url", &encode("gzip", &[0xff, 0x00, 0xfe]).unwrap()).unwrap());
        assert_eq!(s.steps.last(), Some(&"gzip"));
        assert_eq!(s.output, [0xff, 0x00, 0xfe]);
    }

    #[test]
    fn deflate_tries_raw_after_zlib() {
        // A raw stored block whose first bytes pass as a zlib header (78 9c): 156 bytes of
        // 'A', then an empty final block.
        let mut raw = vec![0x78, 0x9c, 0x00, 0x63, 0xff];
        raw.extend([b'A'; 156]);
        raw.extend([0x01, 0x00, 0x00, 0xff, 0xff]);
        assert!(zlib_header(&raw));
        assert!(decode("zlib", &raw).is_err());
        assert_eq!(decode("deflate", &raw).unwrap(), [b'A'; 156]);
        // When neither reads it, a zlib header still gets the zlib error.
        let err = decode("deflate", &raw[..40]).unwrap_err().to_string();
        assert!(err.contains("zlib: corrupt"), "{err}");
    }

    #[test]
    fn smart_decode_keeps_plus_in_binary_base64() {
        // Base64 of an emoji: binary, so it stops there, but its '+' isn't read as a space.
        let s = smart_decode(b"8J+YgA%3D%3D");
        assert_eq!((s.steps, s.output), (vec!["percent"], b"8J+YgA==".to_vec()));
        assert_eq!(decode("auto", b"8J+YgA%3D%3D").unwrap(), b"8J+YgA==");
        // Not base64: a form value, with '+' as a space.
        assert_eq!(smart_decode(b"hello+world%21").output, b"hello world!");
    }

    #[test]
    fn smart_decode_json_with_non_ascii() {
        let s = smart_decode(b"eyJuYW1lIjoiSm9zw6kifQ==");
        assert_eq!(s.steps, ["base64"]);
        assert_eq!(s.output, r#"{"name":"José"}"#.as_bytes());
        let hex = encode("hex", r#"["café"]"#.as_bytes()).unwrap();
        assert_eq!(smart_decode(&hex).output, r#"["café"]"#.as_bytes());
        // Short JSON the ASCII check finds too sparse still counts.
        assert!(looks_decoded(b"[1]") && !printable_ascii(b"[1]"));
    }

    #[test]
    fn looks_decoded_tries_ascii_before_json() {
        // ASCII JSON passes the ASCII check, so looks_decoded never parses it.
        let big = format!("[{}0]", "0,".repeat(100_000));
        assert!(printable_ascii(big.as_bytes()) && looks_decoded(big.as_bytes()));
        // The JSON fallback takes objects and arrays only, whole, and with any UTF-8 inside.
        assert!(json_container(r#" {"name":"José"}"#.as_bytes()) && !printable_ascii(r#"{"name":"José"}"#.as_bytes()));
        assert!(json_container("[\"café\"]\n".as_bytes()));
        assert!(!json_container(b"12"));
        for not in [r#""José""#, r#"{"name":"José"} x"#, r#"{"name":"José""#, "José"] {
            assert!(!json_container(not.as_bytes()) && !looks_decoded(not.as_bytes()), "{not}");
        }
    }

    #[test]
    fn smart_decode_jwt() {
        // Unsigned tokens (alg none), with or without the trailing dot.
        for token in ["eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0"] {
            let s = smart_decode(token.as_bytes());
            assert_eq!(s.steps, ["jwt"], "{token}");
            let v: serde_json::Value = serde_json::from_slice(&s.output).unwrap();
            assert_eq!((v["header"]["alg"].as_str(), v["signature"].as_str()), (Some("none"), Some("")));
        }
        // The payload holds base64, but a JWT is the last step: its output is JSON to read.
        let payload = encode("base64url", br#"{"data":"SGVsbG8sIHdvcmxkIQ=="}"#).unwrap();
        let token = format!("eyJhbGciOiJIUzI1NiJ9.{}.c2ln", String::from_utf8(payload).unwrap());
        let s = smart_decode(token.as_bytes());
        assert_eq!(s.steps, ["jwt"]);
        assert!(String::from_utf8(s.output).unwrap().contains("SGVsbG8sIHdvcmxkIQ=="));
        // Shaped like a JWT, but the header isn't JSON: nothing is guessed instead.
        assert!(smart_decode(b"eyJhbGci.e30.x").steps.is_empty());
    }

    #[test]
    fn smart_decode_leaves_ids_and_secrets_alone() {
        let plain = [
            // Hashes, IDs, and addresses: valid hex or base64 that decodes to binary.
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "a9993e364706816aba3e25717850c26c9cd0d89d",
            "550e8400-e29b-41d4-a716-446655440000",
            "00:1a:2b:3c:4d:5e",
            "fe80::1",
            "0xCAFE1234",
            "2024-01-01T00:00:00Z",
            "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
            // Token-shaped strings stay exactly as given.
            "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "AKIAIOSFODNN7EXAMPLE",
            concat!("sk_", "test_4eC39HqLyjWDarjtT1zdp7dc"),
            // Identifiers and passwords with capitals and digits.
            "HelloWorld2024",
            "ThisIsATest123",
            "getUserById2",
            "MyPassword1",
            "AbCd1234",
            "Summer2024!",
            "Base64Encoded",
            "Kubernetes",
            // Hex with no letters is a number.
            "41 42 43 44",
            "4142434445464748",
            // Escapes that would give binary or control characters.
            "%ff%fe",
            "%00",
            "a%00b",
            "&#0;",
            "&#55296;",
            // Nothing to undo, or not one alphabet.
            "a+b",
            "a & b",
            "QUJD+-_/",
            "dGVzdA",
            "AAAAAAAA",
            "++++++++",
            "________",
            "",
            "   ",
            "\n",
        ];
        for word in plain {
            let s = smart_decode(word.as_bytes());
            assert!(s.steps.is_empty(), "{word:?} decoded as {:?}", s.steps);
            assert_eq!(s.output, word.as_bytes());
        }
    }

    #[test]
    fn smart_decode_stops_at_bad_or_huge_compression() {
        // gzip's magic bytes, then nothing usable.
        assert_eq!(smart_decode(&[0x1f, 0x8b, 0x08]), Smart { steps: vec![], output: vec![0x1f, 0x8b, 0x08] });
        // A bomb isn't unpacked: auto stops before it, with the compressed bytes as output.
        let bomb = encode("gzip", &vec![0u8; MAX_INFLATED as usize + 1]).unwrap();
        assert!(smart_decode(&bomb).steps.is_empty());
        let s = smart_decode(&encode("base64", &bomb).unwrap());
        assert_eq!((s.steps, s.output), (vec!["base64"], bomb));
        // Raw deflate has no magic bytes, so it is never guessed.
        let raw = encode("base64", &encode("deflate", b"hello hello hello").unwrap()).unwrap();
        assert!(smart_decode(&raw).steps.is_empty());
    }

    #[test]
    fn smart_decode_depth_counts_every_kind() {
        let mut v = b"<b>".to_vec();
        for _ in 0..SMART_DEPTH + 2 {
            v = encode("url-all", &v).unwrap();
        }
        let s = smart_decode(&v);
        assert_eq!(s.steps, ["url"; SMART_DEPTH]);
        assert!(s.output.starts_with(b"%25"), "{}", String::from_utf8_lossy(&s.output));
        assert_eq!(replay(&v, &s.steps), s.output);
        // A second run picks up where the first stopped.
        assert_eq!(smart_decode(&s.output).output, b"<b>");
    }
}
