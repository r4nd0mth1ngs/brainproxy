//! Encoders, decoders, and hashes (the Decoder tool).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use md5::Md5;
use percent_encoding::{percent_decode, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

/// Characters left alone by `url` encoding: RFC 3986 unreserved.
const URL_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

pub const ENCODINGS: &[&str] = &["base64", "base64url", "url", "url-all", "hex", "html"];
pub const DECODINGS: &[&str] = &["base64", "base64url", "url", "hex", "html", "jwt"];
pub const HASHES: &[&str] = &["md5", "sha1", "sha256", "sha512"];

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
        other => return Err(unknown("encoding", other, ENCODINGS)),
    })
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
}
