//! Small helpers shared by the header rules (ZAP core semantics that the
//! generic `Message` API does not model exactly).

use std::sync::LazyLock;

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;

use crate::scan::passive::util::{tags, Tag};
use crate::scan::Message;

/// ZAP `getHeaderValues(name)`: every value of `name` (case-insensitive), trimmed.
pub fn header_values<'a>(msg: &'a Message, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    msg.resp_headers_named(name).map(str::trim)
}

/// ZAP `getHeader(name)`: the first value, trimmed.
pub fn header_first<'a>(msg: &'a Message, name: &str) -> Option<&'a str> {
    msg.resp_header(name).map(str::trim)
}

/// Response header lines as ZAP's `HttpHeader.toString()` renders them ("Name: value").
pub fn header_lines(msg: &Message) -> impl Iterator<Item = String> + '_ {
    msg.resp_headers.iter().map(|(k, v)| format!("{k}: {}", v.trim()))
}

/// The response header block without the status line, lines joined with CRLF
/// (ZAP `getHeadersAsString()`).
pub fn headers_block(msg: &Message) -> String {
    let mut s = String::new();
    for line in header_lines(msg) {
        s.push_str(&line);
        s.push_str("\r\n");
    }
    s
}

/// First header line starting with `prefix` (case-insensitive), whole line.
pub fn first_line_with_prefix(msg: &Message, prefix: &str) -> Option<String> {
    header_lines(msg).find(|l| starts_with_ci(l, prefix))
}

/// ZAP's `getHeaderField`: the `prefix` part, in the response's spelling, of the
/// first header line starting with it.
pub fn header_name_as_spelled(msg: &Message, prefix: &str) -> Option<String> {
    msg.resp_headers.iter().find(|(k, _)| starts_with_ci(k, prefix)).map(|(k, _)| k[..prefix.len()].to_string())
}

pub fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// ZAP `HttpHeader.isText()`: Content-Type mentions text, html, xml, json or javascript.
pub fn zap_is_text(msg: &Message) -> bool {
    let ct = msg.content_type();
    ["text", "html", "xml", "json", "javascript"].iter().any(|t| ct.contains(t))
}

pub fn is_redirect(status: u16) -> bool {
    (300..=399).contains(&status)
}

pub fn is_error(status: u16) -> bool {
    (400..=599).contains(&status)
}

/// `<meta>` elements of the body. Cheap pre-check so non-HTML bodies are not tokenized.
pub fn meta_tags(body: &str) -> Vec<Tag> {
    if !body.as_bytes().windows(5).any(|w| w.eq_ignore_ascii_case(b"<meta")) {
        return Vec::new();
    }
    tags(body).into_iter().filter(|t| t.name == "meta").collect()
}

/// First `<meta>` whose http-equiv equals `name` (case-insensitive).
pub fn meta_http_equiv(body: &str, name: &str) -> Option<Tag> {
    meta_tags(body).into_iter().find(|t| t.attr("http-equiv").is_some_and(|v| v.eq_ignore_ascii_case(name)))
}

/// java.util.Base64.getDecoder(): standard alphabet, padding optional, no whitespace.
pub fn java_base64_decode(s: &str) -> Option<Vec<u8>> {
    static ENGINE: LazyLock<GeneralPurpose> = LazyLock::new(|| {
        GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new()
                .with_decode_padding_mode(DecodePaddingMode::Indifferent)
                .with_decode_allow_trailing_bits(true),
        )
    });
    ENGINE.decode(s).ok()
}

/// java.text.MessageFormat rendering of an integer (en locale grouping, e.g. 1,234).
pub fn fmt_int(n: impl Into<i128>) -> String {
    let n: i128 = n.into();
    let digits = n.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if n < 0 {
        out.push('-');
    }
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(fmt_int(1234567), "1,234,567");
        assert_eq!(fmt_int(12), "12");
        assert_eq!(fmt_int(-1000), "-1,000");
        assert_eq!(java_base64_decode("aGk"), Some(b"hi".to_vec()));
        assert_eq!(java_base64_decode("aGk="), Some(b"hi".to_vec()));
        assert_eq!(java_base64_decode("a-_k"), None);
        assert!(starts_with_ci("x-powered-BY: a", "X-Powered-By"));
    }
}
