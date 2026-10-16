//! Helpers shared by the ported cookie, parameter, reflection and form rules.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::scan::passive::util::{find_ci, Tag};
use crate::scan::Message;

/// ZAP's `TreeSet<HtmlParameter>` of form plus URL parameters: deduplicated,
/// form parameters first, then URL parameters, each sorted by name and value.
pub fn request_params(msg: &Message) -> Vec<(String, String)> {
    let mut p = sorted_dedup(msg.form_params());
    p.extend(sorted_dedup(msg.query_params()));
    p
}

/// ZAP's `msg.getUrlParams()`: query parameters, deduplicated and sorted.
pub fn url_params(msg: &Message) -> Vec<(String, String)> {
    sorted_dedup(msg.query_params())
}

fn sorted_dedup(mut v: Vec<(String, String)>) -> Vec<(String, String)> {
    v.sort();
    v.dedup();
    v
}

/// The request method's ZAP intro text selector: Some(true) for GET, Some(false) for POST.
pub fn is_get(msg: &Message) -> Option<bool> {
    if msg.method.eq_ignore_ascii_case("GET") {
        Some(true)
    } else if msg.method.eq_ignore_ascii_case("POST") {
        Some(false)
    } else {
        None
    }
}

/// ZAP's `getHelper().isPage200(msg)` without custom-page definitions.
pub fn is_page_200(msg: &Message) -> bool {
    msg.status == 200
}

/// The `isResponseHTML` helper several ZAP rules carry: the first Content-Type
/// header contains (case-sensitively) text/html or application/xhtml.
pub fn is_response_html(msg: &Message) -> bool {
    msg.resp_header("content-type").is_some_and(|ct| ct.contains("text/html") || ct.contains("application/xhtml"))
}

/// Java `String.equalsIgnoreCase`.
pub fn eq_ic(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b) || (!(a.is_ascii() && b.is_ascii()) && a.to_lowercase() == b.to_lowercase())
}

/// The authority (`[userinfo@]host[:port]`) of an absolute URL as written, if any.
pub fn url_authority(url: &str) -> Option<&str> {
    let rest = &url[url.find("://")? + 3..];
    let a = rest.split(['/', '?', '#']).next().unwrap_or("");
    (!a.is_empty()).then_some(a)
}

/// The parts of `new java.net.URI(s).toURL()` the rules use.
#[derive(Debug, PartialEq)]
pub struct JavaUrl<'a> {
    /// Lower-cased scheme.
    pub protocol: String,
    pub authority: Option<&'a str>,
    pub query: Option<&'a str>,
}

/// Approximates `new java.net.URI(s).toURL()`: None where Java would throw
/// (illegal characters, bad escapes, bad scheme, or no URL handler for the scheme).
pub fn java_url(s: &str) -> Option<JavaUrl<'_>> {
    let colon = s.find(':')?;
    let scheme = &s[..colon];
    let mut sc = scheme.chars();
    if !sc.next().is_some_and(|c| c.is_ascii_alphabetic())
        || !sc.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        return None;
    }
    let protocol = scheme.to_ascii_lowercase();
    if !["http", "https", "ftp", "file", "jar", "mailto", "jrt"].contains(&protocol.as_str()) {
        return None;
    }
    let rest = &s[colon + 1..];
    let (authority, after) = match rest.strip_prefix("//") {
        Some(r) => {
            let end = r.find(['/', '?', '#']).unwrap_or(r.len());
            (Some(&r[..end]).filter(|a| !a.is_empty()), &r[end..])
        }
        None => (None, rest),
    };
    // Character validity: Java's URI parser rejects these anywhere.
    let b = s.as_bytes();
    for (i, c) in s.char_indices() {
        let bad = c.is_whitespace()
            || c.is_control()
            || "\"<>\\^`{|}".contains(c)
            || (c == '%'
                && !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit)));
        if bad {
            return None;
        }
    }
    // Brackets are only legal around an IPv6 host; a second '#' is never legal.
    if after.contains(['[', ']']) || after.matches('#').count() > 1 {
        return None;
    }
    if let Some(a) = authority {
        let host = a.rsplit('@').next().unwrap_or(a);
        if host.contains(['[', ']']) && !host.starts_with('[') {
            return None;
        }
    }
    let no_frag = after.split('#').next().unwrap_or("");
    let query = no_frag.find('?').map(|q| &no_frag[q + 1..]);
    if authority.is_none() && !rest.starts_with('/') {
        // Opaque URI (e.g. mailto:x): no authority or query.
        return Some(JavaUrl { protocol, authority: None, query: None });
    }
    Some(JavaUrl { protocol, authority, query })
}

const VOID_ELEMENTS: [&str; 19] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr",
    "basefont", "frame", "isindex", "keygen", "command",
];

/// Approximates Jericho's `getParentElement() != null` for `tags[idx]`: some
/// non-void element opened before it is still open (more start than end tags).
pub fn has_parent_element(html: &str, tags: &[Tag], idx: usize) -> bool {
    let start = tags[idx].start;
    let mut open: HashMap<&str, i32> = HashMap::new();
    for t in &tags[..idx] {
        if !VOID_ELEMENTS.contains(&t.name.as_str()) && !html[t.start..t.end].ends_with("/>") {
            *open.entry(t.name.as_str()).or_default() += 1;
        }
    }
    if open.is_empty() {
        return false;
    }
    let before = &html[..start];
    let mut i = 0;
    while let Some(off) = before[i..].find("</") {
        let s = i + off + 2;
        let len = before[s..].bytes().take_while(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b':').count();
        if len > 0 {
            let name = before[s..s + len].to_ascii_lowercase();
            if let Some(n) = open.get_mut(name.as_str()) {
                *n -= 1;
            }
        }
        i = s;
    }
    open.values().any(|n| *n > 0)
}

/// Byte offset just past the end of the element started by `tag` (its first
/// matching end tag), or just past the start tag when there is no end tag.
pub fn element_end(html: &str, tag: &Tag) -> usize {
    let close = format!("</{}", tag.name);
    match find_ci(html, &close, tag.end) {
        Some(p) => html[p..].find('>').map(|e| p + e + 1).unwrap_or(html.len()),
        None => tag.end,
    }
}

/// The charset parameter of the response Content-Type header (ZAP `getCharset()`).
pub fn response_charset(msg: &Message) -> Option<&str> {
    let ct = msg.resp_header("content-type")?;
    let i = find_ci(ct, "charset", 0)? + "charset".len();
    let rest = ct[i..].trim_start_matches(' ').strip_prefix('=')?.trim_start_matches(' ');
    let rest = rest.trim_start_matches(['"', '\'']);
    let end = rest.find(|c: char| c == ';' || c == '"' || c == '\'' || c.is_whitespace()).unwrap_or(rest.len());
    let cs = &rest[..end];
    (!cs.is_empty()).then_some(cs)
}

/// Default contents of ZAP's URL-information-disclosure-messages.txt.
pub const SENSITIVE_STRINGS: [&str; 10] =
    ["user", "username", "pass", "password", "pwd", "token", "ticket", "session", "jsessionid", "sessionid"];

pub static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b").unwrap());
pub static CREDIT_CARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?-u)\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35[0-9]{3})[0-9]{11})\b",
    )
    .unwrap()
});
pub static SSN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u)\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b").unwrap());

/// Standard Luhn (mod 10) check over the digits of `s`.
pub fn is_valid_luhn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.is_empty() {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::tags;

    #[test]
    fn java_url_parts() {
        let u = java_url("HTTP://u@a.test:8080/p?q=1/2#f").unwrap();
        assert_eq!(u.protocol, "http");
        assert_eq!(u.authority, Some("u@a.test:8080"));
        assert_eq!(u.query, Some("q=1/2"));
        assert!(java_url("http://a.test/a b").is_none());
        assert!(java_url("http://a.test/%zz").is_none());
        assert!(java_url("foo://a.test/").is_none());
        assert_eq!(java_url("https://a.test").unwrap().query, None);
    }

    #[test]
    fn parent_elements() {
        let html = "<form method=post></form><html><body><form method=post></form></body></html>";
        let t = tags(html);
        assert!(!has_parent_element(html, &t, 0));
        assert!(has_parent_element(html, &t, 3));
        let closed = "<div></div><form>";
        assert!(!has_parent_element(closed, &tags(closed), 1));
        assert_eq!(element_end(html, &t[0]), "<form method=post></form>".len());
    }

    #[test]
    fn luhn_and_charset() {
        assert!(is_valid_luhn("4111111111111111"));
        assert!(!is_valid_luhn("4111111111111112"));
        let m = crate::scan::passive::util::testing::msg("http://a.test/")
            .header("Content-Type", "text/html; Charset=\"UTF-7\"")
            .build();
        assert_eq!(response_charset(&m), Some("UTF-7"));
    }
}
