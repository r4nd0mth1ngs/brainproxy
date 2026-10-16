// Helpers are adopted rule by rule as the ZAP ports land.
#![allow(dead_code)]

//! Lenient HTML helpers for passive rules: start tags with attributes, comments,
//! and script contents. Good enough for scanning arbitrary (often broken) pages
//! without a full DOM.

#[derive(Debug, Clone)]
pub struct Tag {
    /// Lower-case element name.
    pub name: String,
    /// Attributes with lower-case names, in source order. Values are unquoted
    /// and HTML-entity-decoded for the common entities.
    pub attrs: Vec<(String, String)>,
    /// Byte offset of `<` in the document.
    pub start: usize,
    /// Byte offset just past `>`.
    pub end: usize,
}

impl Tag {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn has(&self, name: &str) -> bool {
        self.attrs.iter().any(|(k, _)| k == name)
    }
}

/// All start tags in the document (comments, doctypes, and end tags skipped;
/// script/style contents are not parsed as tags).
pub fn tags(html: &str) -> Vec<Tag> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = memchr(b'<', &b[i..]) {
        let start = i + off;
        let rest = &html[start..];
        if rest.starts_with("<!--") {
            i = match rest.find("-->") {
                Some(e) => start + e + 3,
                None => b.len(),
            };
            continue;
        }
        if rest.starts_with("<!") || rest.starts_with("<?") || rest.starts_with("</") {
            i = match rest.find('>') {
                Some(e) => start + e + 1,
                None => b.len(),
            };
            continue;
        }
        let name_len = rest[1..].bytes().take_while(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b':').count();
        if name_len == 0 {
            i = start + 1;
            continue;
        }
        let name = rest[1..1 + name_len].to_ascii_lowercase();
        let (attrs, end) = parse_attrs(html, start + 1 + name_len);
        out.push(Tag { name: name.clone(), attrs, start, end });
        i = end;
        // Skip raw-text element bodies.
        if name == "script" || name == "style" || name == "textarea" || name == "title" {
            let close = format!("</{name}");
            i = find_ci(html, &close, i).unwrap_or(b.len());
        }
    }
    out
}

fn parse_attrs(html: &str, mut i: usize) -> (Vec<(String, String)>, usize) {
    let b = html.as_bytes();
    let mut attrs = Vec::new();
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            return (attrs, b.len());
        }
        if b[i] == b'>' {
            return (attrs, i + 1);
        }
        let ns = i;
        while i < b.len()
            && !b[i].is_ascii_whitespace()
            && b[i] != b'='
            && b[i] != b'>'
            && !(b[i] == b'/' && b.get(i + 1) == Some(&b'>'))
        {
            i += 1;
        }
        let name = html[ns..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let vs = i + 1;
                let ve = memchr(q, &b[vs..]).map(|o| vs + o).unwrap_or(b.len());
                value = decode_entities(&html[vs..ve]);
                i = (ve + 1).min(b.len());
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                value = decode_entities(&html[vs..i]);
            }
        }
        if !name.is_empty() {
            attrs.push((name, value));
        }
    }
}

/// Text of every `<!-- comment -->`.
pub fn comments(html: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(s) = html[i..].find("<!--") {
        let start = i + s + 4;
        match html[start..].find("-->") {
            Some(e) => {
                out.push(&html[start..start + e]);
                i = start + e + 3;
            }
            None => {
                out.push(&html[start..]);
                break;
            }
        }
    }
    out
}

/// Contents of every inline `<script>` element.
pub fn scripts(html: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for t in tags(html).iter().filter(|t| t.name == "script") {
        let end = find_ci(html, "</script", t.end).unwrap_or(html.len());
        out.push(&html[t.end..end]);
    }
    out
}

pub fn find_ci(hay: &str, needle: &str, from: usize) -> Option<usize> {
    let h = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || from >= h.len() {
        return None;
    }
    h[from..].windows(n.len()).position(|w| w.eq_ignore_ascii_case(n)).map(|p| from + p)
}

fn memchr(c: u8, b: &[u8]) -> Option<usize> {
    b.iter().position(|&x| x == c)
}

pub fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    String::from_utf8(crate::codec::decode("html", s.as_bytes()).unwrap_or_else(|_| s.as_bytes().to_vec()))
        .unwrap_or_else(|_| s.to_string())
}

/// The host of an absolute or protocol-relative URL, lower-cased.
pub fn url_host(url: &str) -> Option<String> {
    let rest = if let Some(r) = url.strip_prefix("//") {
        r
    } else {
        let (scheme, r) = url.split_once("://")?;
        if !scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
            return None;
        }
        r
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = if host_port.starts_with('[') {
        host_port.split(']').next().map(|h| format!("{h}]"))?
    } else {
        host_port.split(':').next()?.to_string()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_lenient_html() {
        let html = r#"<!DOCTYPE html><html><!-- secret: todo --><a HREF='/x?a=1&amp;b=2' target=_blank>x</a>
            <script src="https://cdn.test/a.js"></script><script>var a = "<b>";</script><img src=x.png alt>"#;
        let t = tags(html);
        let names: Vec<&str> = t.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["html", "a", "script", "script", "img"]);
        assert_eq!(t[1].attr("href"), Some("/x?a=1&b=2"));
        assert_eq!(t[1].attr("target"), Some("_blank"));
        assert!(t[4].has("alt"));
        assert_eq!(comments(html), [" secret: todo "]);
        assert_eq!(scripts(html), ["", "var a = \"<b>\";"]);
        assert_eq!(url_host("https://user@CDN.test:8443/x"), Some("cdn.test".into()));
        assert_eq!(url_host("//other.test/x"), Some("other.test".into()));
        assert_eq!(url_host("/relative"), None);
    }
}

/// Parses an HTTP date (RFC 1123 `Thu, 01 Jan 1970 00:00:00 GMT`, the Netscape
/// cookie form `Thu, 01-Jan-1970 00:00:00 GMT`, or RFC 850) to Unix seconds.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let s = s.trim();
    let rest = s.split_once(',').map(|(_, r)| r).unwrap_or(s).trim();
    let rest = rest.replace('-', " ");
    let mut it = rest.split_whitespace();
    let day: i64 = it.next()?.parse().ok()?;
    let month = match it.next()?.to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let mut year: i64 = it.next()?.parse().ok()?;
    if year < 100 {
        year += if year < 70 { 2000 } else { 1900 };
    }
    let mut hms = it.next()?.split(':').map(|p| p.parse::<i64>().ok());
    let (h, m, sec) = (hms.next()??, hms.next()??, hms.next()??);
    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + m * 60 + sec)
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// ZAP CookieUtils.isExpired: the Expires attribute parses to a time in the past.
pub fn cookie_expired(c: &crate::scan::message::SetCookie) -> bool {
    c.attr("expires").and_then(parse_http_date).is_some_and(|t| t < now_unix())
}

/// ZAP CookieUtils.getSetCookiePlusName: "<header name as sent>: <cookie name>".
pub fn set_cookie_evidence(msg: &crate::scan::Message, raw_value: &str, name: &str) -> String {
    let header = msg
        .resp_headers
        .iter()
        .find(|(k, v)| {
            v == raw_value && (k.eq_ignore_ascii_case("set-cookie") || k.eq_ignore_ascii_case("set-cookie2"))
        })
        .map(|(k, _)| k.as_str())
        .unwrap_or("Set-Cookie");
    format!("{header}: {name}")
}

/// All Set-Cookie then Set-Cookie2 values, in order (ZAP order).
pub fn set_cookie_values(msg: &crate::scan::Message) -> Vec<&str> {
    msg.resp_headers_named("set-cookie").chain(msg.resp_headers_named("set-cookie2")).collect()
}

#[cfg(test)]
pub mod testing {
    //! Builders for rule unit tests.
    use crate::scan::{Finding, Message, PassiveRule};

    pub struct M {
        pub url: String,
        pub method: String,
        pub req_headers: Vec<(String, String)>,
        pub req_body: Vec<u8>,
        pub status: u16,
        pub resp_headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    /// A GET for `url` answered 200 with no headers and an empty body.
    pub fn msg(url: &str) -> M {
        M {
            url: url.into(),
            method: "GET".into(),
            req_headers: vec![],
            req_body: vec![],
            status: 200,
            resp_headers: vec![],
            body: vec![],
        }
    }

    impl M {
        pub fn method(mut self, m: &str) -> Self {
            self.method = m.into();
            self
        }
        pub fn req_header(mut self, k: &str, v: &str) -> Self {
            self.req_headers.push((k.into(), v.into()));
            self
        }
        pub fn req_body(mut self, b: &str) -> Self {
            self.req_body = b.as_bytes().to_vec();
            self
        }
        pub fn status(mut self, s: u16) -> Self {
            self.status = s;
            self
        }
        pub fn header(mut self, k: &str, v: &str) -> Self {
            self.resp_headers.push((k.into(), v.into()));
            self
        }
        pub fn html(self, body: &str) -> Self {
            self.header("Content-Type", "text/html; charset=utf-8").body(body)
        }
        pub fn body(mut self, b: &str) -> Self {
            self.body = b.as_bytes().to_vec();
            self
        }
        pub fn build(self) -> Message {
            let target = crate::http::Target::from_url(&self.url).unwrap();
            let after = &self.url[self.url.find("://").map(|i| i + 3).unwrap_or(0)..];
            let pq = after.find('/').map(|i| &after[i..]).unwrap_or("/");
            let (path, query) = match pq.split_once('?') {
                Some((p, q)) => (p.to_string(), Some(q.to_string())),
                None => (pq.to_string(), None),
            };
            Message::new(
                1,
                self.method,
                self.url.clone(),
                target.scheme.clone(),
                target.host.clone(),
                target.port,
                path,
                query,
                self.req_headers,
                self.req_body,
                self.status,
                self.resp_headers,
                self.body,
            )
        }
        /// Runs `rule` on the message.
        pub fn scan(self, rule: &dyn PassiveRule) -> Vec<Finding> {
            let m = self.build();
            let mut out = Vec::new();
            rule.scan(&m, &mut out);
            out
        }
    }
}
