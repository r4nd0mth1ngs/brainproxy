//! Shared helpers for the response-body content rules: ZAP's content-type
//! predicates (HttpHeader / ResourceIdentificationUtils semantics), Jericho-like
//! element source extraction, URL host checks and the Luhn check.

use crate::scan::passive::util::{find_ci, url_host, Tag};
use crate::scan::Message;

/// ZAP HttpHeader.isText(): a Content-Type is present and mentions text, html,
/// xml, json, javascript or x-www-form-urlencoded.
pub fn is_text(msg: &Message) -> bool {
    let ct = msg.content_type();
    ["text", "html", "xml", "json", "javascript", "x-www-form-urlencoded"].iter().any(|t| ct.contains(t))
}

fn path_ends_with(msg: &Message, exts: &[&str]) -> bool {
    let p = msg.path.to_ascii_lowercase();
    exts.iter().any(|e| p.ends_with(e))
}

/// ResourceIdentificationUtils.isJavaScript: by Content-Type or a `.js` path.
pub fn is_javascript(msg: &Message) -> bool {
    msg.is_javascript() || path_ends_with(msg, &[".js"])
}

/// ResourceIdentificationUtils.isCss: by Content-Type or a `.css` path.
pub fn is_css(msg: &Message) -> bool {
    msg.is_css() || path_ends_with(msg, &[".css"])
}

/// ResourceIdentificationUtils.isFont: by Content-Type or a font extension.
pub fn is_font(msg: &Message) -> bool {
    msg.content_type().contains("font") || path_ends_with(msg, &[".woff", ".woff2", ".ttf", ".otf", ".eot"])
}

/// ResourceIdentificationUtils.isImage: by Content-Type or an image extension.
pub fn is_image(msg: &Message) -> bool {
    msg.is_image()
        || path_ends_with(
            msg,
            &[".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".tif", ".tiff", ".avif"],
        )
}

const VOID_ELEMENTS: &[&str] =
    &["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"];

/// Finds `<name` / `</name` (case-insensitive) followed by a tag-name terminator.
fn find_tag_ci(html: &str, prefix: &str, from: usize) -> Option<usize> {
    let mut i = from;
    while let Some(p) = find_ci(html, prefix, i) {
        match html.as_bytes().get(p + prefix.len()) {
            Some(c) if c.is_ascii_alphanumeric() || *c == b'-' || *c == b':' => i = p + 1,
            _ => return Some(p),
        }
    }
    None
}

/// Byte ranges of an element: (content start, content end, element end).
/// Approximates Jericho: void elements (and elements whose end tag is missing)
/// are just their start tag.
pub fn element_bounds(html: &str, tag: &Tag) -> (usize, usize, usize) {
    if VOID_ELEMENTS.contains(&tag.name.as_str()) || (html[tag.start..tag.end].ends_with("/>") && tag.name != "script")
    {
        return (tag.end, tag.end, tag.end);
    }
    let close = format!("</{}", tag.name);
    let Some(c) = find_tag_ci(html, &close, tag.end) else {
        return (tag.end, tag.end, tag.end);
    };
    // Raw-text elements cannot nest; for the rest an earlier sibling start tag
    // means this one has no end tag of its own.
    if tag.name != "script" && tag.name != "style" {
        if let Some(o) = find_tag_ci(html, &format!("<{}", tag.name), tag.end) {
            if o < c {
                return (tag.end, tag.end, tag.end);
            }
        }
    }
    let end = html[c..].find('>').map(|e| c + e + 1).unwrap_or(html.len());
    (tag.end, c, end)
}

/// Jericho Element.toString(): start tag through end tag.
pub fn element_source<'a>(html: &'a str, tag: &Tag) -> &'a str {
    &html[tag.start..element_bounds(html, tag).2]
}

/// Jericho Element.getContent(): the text between start and end tag.
pub fn element_content<'a>(html: &'a str, tag: &Tag) -> &'a str {
    let (s, e, _) = element_bounds(html, tag);
    &html[s..e]
}

/// commons-httpclient `URI(s, true)` rejects unescaped characters that are
/// illegal in a URI and malformed percent escapes.
pub fn uri_has_illegal_chars(s: &str) -> bool {
    let b = s.as_bytes();
    b.iter().enumerate().any(|(i, &c)| {
        c <= b' '
            || c == 0x7f
            || b"\"<>\\^`{|}".contains(&c)
            || (c == b'%'
                && !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit)))
    })
}

/// ZAP's isScriptFromOtherDomain / isLinkFromOtherDomain (without contexts): the
/// URL is absolute or protocol-relative and names a host other than the page's.
pub fn is_other_domain(page_host: &str, url: &str) -> bool {
    if !url.starts_with("//") && (url.starts_with('/') || url.starts_with("./") || url.starts_with("../")) {
        return false;
    }
    if uri_has_illegal_chars(url) {
        return false;
    }
    url_host(url).is_some_and(|h| !h.trim_start_matches('[').trim_end_matches(']').eq_ignore_ascii_case(page_host))
}

/// Standard Luhn check over a string of ASCII digits.
pub fn is_valid_luhn(digits: &str) -> bool {
    let mut sum = 0u32;
    for (i, c) in digits.bytes().rev().enumerate() {
        if !c.is_ascii_digit() {
            return false;
        }
        let mut d = u32::from(c - b'0');
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    !digits.is_empty() && sum.is_multiple_of(10)
}

/// Decodes the five predefined XML entities and numeric character references.
pub fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let decoded = rest.find(';').filter(|&e| e <= 10).and_then(|e| {
            let ent = &rest[1..e];
            let c = match ent {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => ent
                    .strip_prefix("#x")
                    .map(|h| u32::from_str_radix(h, 16).ok())
                    .unwrap_or_else(|| ent.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .and_then(char::from_u32),
            }?;
            Some((c, e + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
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

/// The text of a data file with `#` comment lines and blank lines removed, trimmed.
pub fn data_lines(text: &'static str) -> impl Iterator<Item = &'static str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// ZAP's `getHeadersAsString()`: "Name: value\r\n" per header.
pub fn headers_as_string(headers: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in headers {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push_str("\r\n");
    }
    s
}

/// Byte offset `n` characters before `i` (or 0).
pub fn chars_back(s: &str, i: usize, n: usize) -> usize {
    s[..i].char_indices().rev().nth(n.saturating_sub(1)).map(|(p, _)| p).unwrap_or(0)
}

/// Byte offset `n` characters after `i` (or the end).
pub fn chars_forward(s: &str, i: usize, n: usize) -> usize {
    s[i..].char_indices().nth(n).map(|(p, _)| i + p).unwrap_or(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::tags;

    #[test]
    fn element_helpers() {
        let html = "<div><a href=x>one<b>2</b></a><a>no end<A href=y>z</A><link rel=x></div>";
        let t = tags(html);
        let a: Vec<&Tag> = t.iter().filter(|t| t.name == "a").collect();
        assert_eq!(element_source(html, a[0]), "<a href=x>one<b>2</b></a>");
        assert_eq!(element_content(html, a[0]), "one<b>2</b>");
        assert_eq!(element_source(html, a[1]), "<a>");
        assert_eq!(element_source(html, a[2]), "<A href=y>z</A>");
        let link = t.iter().find(|t| t.name == "link").unwrap();
        assert_eq!(element_source(html, link), "<link rel=x>");
    }

    #[test]
    fn misc_helpers() {
        assert!(is_valid_luhn("4716186978544330"));
        assert!(!is_valid_luhn("4716186978544331"));
        assert_eq!(xml_unescape("&lt;b&gt; &amp;quot; &#65;&x"), "<b> &quot; A&x");
        assert!(is_other_domain("a.test", "https://b.test/x.js"));
        assert!(is_other_domain("a.test", "//b.test/x.js"));
        assert!(!is_other_domain("a.test", "https://A.test/x.js"));
        assert!(!is_other_domain("a.test", "/x.js"));
        assert!(!is_other_domain("a.test", "js/x.js"));
        assert!(!is_other_domain("a.test", "https://b.test/a b.js"));
        assert_eq!(chars_back("aébc", 4, 2), 1);
        assert_eq!(chars_forward("aébc", 0, 2), 3);
    }
}
