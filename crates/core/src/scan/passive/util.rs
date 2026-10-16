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
