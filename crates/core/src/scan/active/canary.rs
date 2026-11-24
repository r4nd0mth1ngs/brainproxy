//! Helpers for rules that put a made-up host into a request header and look for it where the
//! application builds URLs from it (Host header injection, and the header tests that follow it):
//!
//! - [`canary`]: a random host name under `.invalid`, which never resolves (RFC 6761), so a
//!   reflected value can only have come from the request and nothing ever connects to it;
//! - [`reflected_in_link_context`]: whether a response uses that host as the host of a URL it
//!   hands the browser (a redirect, a link, a form action, a `<base>`, a script or stylesheet);
//! - [`cache_buster`] and [`bust`]: a random query parameter for every attack request, so a
//!   cache in front of the site keys the attack on a URL nobody else asks for, and a poisoned
//!   answer can only ever reach the scan.

use std::sync::Arc;

use super::rules::params::common::{is_html, HtmlContextAnalyser};
use super::{rand_u64, Response};

/// A fresh random host name, `bp<16 hex digits>.invalid`.
pub fn canary() -> String {
    format!("bp{:016x}.invalid", rand_u64())
}

/// A fresh random query parameter, `name=value`, to append to an attack's request target.
pub fn cache_buster() -> String {
    format!("bp{:08x}={:08x}", rand_u64() as u32, rand_u64() as u32)
}

/// `request` with a fresh [`cache_buster`] appended to its request target's query (also an
/// absolute-form one). A target of `*`, or a head that can't be read, is left as it is.
pub fn bust(request: &[u8]) -> Vec<u8> {
    let line_end = request.iter().position(|&b| b == b'\n').unwrap_or(request.len());
    let Ok(line) = std::str::from_utf8(&request[..line_end]) else { return request.to_vec() };
    let mut parts = line.splitn(3, ' ');
    let (Some(method), Some(target), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return request.to_vec();
    };
    if target == "*" || target.is_empty() {
        return request.to_vec();
    }
    let sep = if target.contains('?') { '&' } else { '?' };
    let mut out = format!("{method} {target}{sep}{} {rest}", cache_buster()).into_bytes();
    out.extend_from_slice(&request[line_end..]);
    out
}

/// Headers whose value is a URL the client follows or loads.
const URL_HEADERS: &[&str] = &["location", "content-location", "refresh", "link"];

/// Where `resp` uses `host` as the host of a URL it gives the browser: a `Location` (or
/// `Content-Location`, `Refresh`, `Link`) header, or in an HTML page a URL attribute such as a
/// link's `href`, a form's `action`, `<base href>`, a script's `src` or a stylesheet's `href`,
/// and a meta refresh. Outside HTML (a JSON answer, a script), an absolute URL anywhere in the
/// body counts, also with its slashes escaped (`https:\/\/`). Returns the value that holds it,
/// as evidence.
///
/// The host has to stand as a URL's host (`//host` followed by its end, a port, a path, a
/// query or a fragment): a page that only echoes the header's text, such as a debug page
/// listing the request headers, isn't building links from it.
pub fn reflected_in_link_context(resp: &Response, host: &str) -> Option<String> {
    for (name, value) in &resp.headers {
        if URL_HEADERS.iter().any(|h| name.eq_ignore_ascii_case(h)) && has_host(value, host) {
            return Some(format!("{name}: {value}"));
        }
    }
    let body = resp.body_str();
    if !body.to_ascii_lowercase().contains(&host.to_ascii_lowercase()) {
        return None;
    }
    if !is_html(resp) {
        let unescaped = body.replace("\\/", "/");
        return url_around(&unescaped, host);
    }
    let analyser = HtmlContextAnalyser::new(Arc::new(resp.clone()));
    analyser.contexts(host, None, 0, false).into_iter().find_map(|ctx| {
        let attr = ctx.tag_attribute.as_deref()?;
        let value = ctx.tag_attribute_value.as_deref()?;
        let in_meta = ctx.parent_tags.last().is_some_and(|t| t == "meta") && attr.eq_ignore_ascii_case("content");
        let url_attr =
            ctx.in_url_attribute || in_meta || ["srcset", "formaction"].iter().any(|a| attr.eq_ignore_ascii_case(a));
        (url_attr && has_host(value, host)).then(|| format!("{attr}=\"{value}\""))
    })
}

/// Whether `text` holds a URL whose host is `host` (case-insensitive).
fn has_host(text: &str, host: &str) -> bool {
    url_around(text, host).is_some()
}

/// The first URL in `text` whose host is `host`: `//host` (after a scheme or as a
/// scheme-relative URL), then the URL's end, a port, a path, a query or a fragment.
fn url_around(text: &str, host: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let needle = format!("//{}", host.to_ascii_lowercase());
    let mut from = 0;
    while let Some(i) = lower.get(from..)?.find(&needle) {
        let start = from + i;
        let end = start + needle.len();
        let next = lower.as_bytes().get(end).copied();
        if next.is_none_or(|b| {
            matches!(b, b':' | b'/' | b'?' | b'#' | b'"' | b'\'' | b'>' | b'<' | b';' | b',' | b')')
                || b.is_ascii_whitespace()
        }) {
            // From the scheme (letters before `//`, and its `:`) to the URL's end.
            let begin = lower[..start]
                .strip_suffix(':')
                .map(|s| s.len() - s.bytes().rev().take_while(|b| b.is_ascii_alphanumeric()).count())
                .unwrap_or(start);
            let stop = lower[end..]
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>'))
                .map_or(lower.len(), |j| end + j);
            return text.get(begin..stop).map(str::to_string);
        }
        from = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(head: &str, body: &str) -> Response {
        let raw = format!("HTTP/1.1 200 OK\r\n{head}Content-Length: {}\r\n\r\n{body}", body.len());
        Response::parse(Vec::new(), raw.into_bytes(), std::time::Duration::ZERO).unwrap()
    }

    #[test]
    fn a_canary_is_a_fresh_invalid_host() {
        let (a, b) = (canary(), canary());
        assert!(a.starts_with("bp") && a.ends_with(".invalid") && a.len() == 2 + 16 + 8, "{a}");
        assert_ne!(a, b);
    }

    #[test]
    fn a_buster_is_added_to_the_query() {
        let busted = |r: &str| String::from_utf8(bust(r.as_bytes())).unwrap();
        let a = busted("GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(a.starts_with("GET /a?bp") && a.ends_with(" HTTP/1.1\r\nHost: x\r\n\r\n"), "{a}");
        let b = busted("POST http://x/a?q=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nz");
        assert!(b.starts_with("POST http://x/a?q=1&bp") && b.ends_with("\r\n\r\nz"), "{b}");
        assert_eq!(busted("OPTIONS * HTTP/1.1\r\n\r\n"), "OPTIONS * HTTP/1.1\r\n\r\n");
        assert_ne!(cache_buster(), cache_buster());
    }

    #[test]
    fn a_host_counts_only_where_a_url_names_it() {
        let h = "bp0123456789abcdef.invalid";
        // A redirect, and the links, form, base, script and stylesheet of a page.
        let loc = resp(&format!("Location: https://{h}/reset?t=1\r\n"), "");
        assert_eq!(reflected_in_link_context(&loc, h).unwrap(), format!("Location: https://{h}/reset?t=1"));
        for tag in [
            format!("<a href=\"http://{h}/x\">x</a>"),
            format!("<form action=\"https://{h}:8443/login\" method=post></form>"),
            format!("<base href=\"//{h}/\">"),
            format!("<script src=\"https://{h}/app.js\"></script>"),
            format!("<link rel=stylesheet href='https://{h}/s.css'>"),
            format!("<meta http-equiv=refresh content=\"0;url=http://{h}/\">"),
        ] {
            let page = resp("Content-Type: text/html\r\n", &format!("<html><head>{tag}</head><body>hi</body></html>"));
            assert!(reflected_in_link_context(&page, h).is_some(), "{tag}");
        }
        // A JSON answer's link, slashes escaped or not.
        let json = resp("Content-Type: application/json\r\n", &format!("{{\"link\":\"https:\\/\\/{h}\\/r?t=1\"}}"));
        assert_eq!(reflected_in_link_context(&json, h).unwrap(), format!("https://{h}/r?t=1"));
        // Text echoed, a relative link that only carries it, or a longer host: not a URL's host.
        for body in [
            format!("<html><body><p>X-Forwarded-Host: {h}</p></body></html>"),
            format!("<html><body><a href=\"/search?q={h}\">s</a></body></html>"),
            format!("<html><body><a href=\"http://{h}.evil.test/\">s</a></body></html>"),
            format!("<html><body><p>see http://{h}/ here</p></body></html>"),
        ] {
            let page = resp("Content-Type: text/html\r\n", &body);
            assert_eq!(reflected_in_link_context(&page, h), None, "{body}");
        }
        assert_eq!(reflected_in_link_context(&resp(&format!("X-Echo: http://{h}/\r\n"), ""), h), None);
    }
}
