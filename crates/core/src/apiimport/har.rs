//! HAR 1.2 files (as Chrome, Firefox, Burp, ZAP and others export them) to requests: one per
//! entry, as it was recorded, for `import api` and `scan active --api`.
//!
//! Only the requests are read. Responses are ignored apart from their content type, which
//! helps tell a static asset: each request is sent again, and the live answer is what gets
//! recorded. Entries that aren't HTTP requests (WebSocket handshakes, `data:` and `blob:`
//! URLs), static assets (unless kept) and repeats of an earlier request are left out and
//! counted in a warning. Credentials are taken out later, as for every format, by
//! `api::harden`.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::Value;

use super::values::{self, Part, MULTIPART_BOUNDARY};
use super::{rebase, shown_url, ApiRequest, Built};
use crate::error::{Error, Result};

/// Largest HAR file accepted: larger than other documents, as a HAR often holds every
/// response body too (which is skipped, not kept).
pub const MAX_HAR: usize = 256 << 20;

#[derive(Debug, Default, Clone)]
pub struct Options {
    /// Replaces the scheme/host/port of every request; a path is put in front.
    pub base_url: Option<String>,
    /// Keep scripts, styles, images, fonts and media.
    pub keep_static: bool,
}

/// What the file says made it, for the preview's title.
#[derive(Debug, Default, Clone)]
pub struct Creator {
    pub name: Option<String>,
    pub version: Option<String>,
}

// Only what a request needs is read: a response's body, often most of the file, is skipped
// by the parser without being kept.
#[derive(Deserialize)]
struct Har {
    log: Log,
}

/// A field written as `null` (`"cookies": null`, `"response": null` for an aborted request)
/// reads as its default, so one odd entry doesn't fail the whole file.
fn or_default<'de, D: serde::Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> std::result::Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Log {
    #[serde(deserialize_with = "or_default")]
    creator: Named,
    #[serde(deserialize_with = "or_default")]
    browser: Named,
    #[serde(deserialize_with = "or_default")]
    entries: Vec<Entry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Named {
    name: Value,
    version: Value,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    #[serde(deserialize_with = "or_default")]
    request: Request,
    #[serde(deserialize_with = "or_default")]
    response: Response,
    /// Chrome's: document, xhr, fetch, script, stylesheet, image, font, websocket, ...
    #[serde(rename = "_resourceType")]
    resource_type: Value,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Request {
    method: Value,
    url: Value,
    #[serde(deserialize_with = "or_default")]
    headers: Vec<Pair>,
    #[serde(deserialize_with = "or_default")]
    cookies: Vec<Pair>,
    #[serde(rename = "queryString", deserialize_with = "or_default")]
    query: Vec<Pair>,
    #[serde(rename = "postData")]
    post: Option<PostData>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Pair {
    name: Value,
    value: Value,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PostData {
    #[serde(rename = "mimeType")]
    mime: Value,
    text: Value,
    #[serde(deserialize_with = "or_default")]
    params: Vec<Param>,
    /// Not in HAR 1.2: how a binary body's `text` is written, as `history export` writes it.
    #[serde(rename = "_encoding")]
    encoding: Value,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Param {
    name: Value,
    value: Value,
    #[serde(rename = "fileName")]
    file_name: Value,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    #[serde(deserialize_with = "or_default")]
    content: Content,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Content {
    #[serde(rename = "mimeType")]
    mime: Value,
}

/// Request headers not taken from the file: the URL gives the host, the length is worked
/// out again, a connection's own headers belong to the browser's connection, an encoding the
/// client may not decode (zstd) would only get in the way of a scan, the body is the decoded
/// one (as HAR files record it), and HTTP/2's pseudo-headers (`:path`) are dropped too.
const NOT_REPLAYED: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "upgrade",
    "accept-encoding",
    "content-encoding",
];

/// A read's cache validators, which would get a 304 with no body. A write's preconditions
/// (`If-Match`, `If-Unmodified-Since`, `If-None-Match: *`) are kept: without them a stale
/// recording could overwrite newer data instead of failing with 412.
const READ_CONDITIONALS: &[&str] =
    &["if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "if-range"];

/// Chrome's resource types for what a page loads to show itself.
const STATIC_TYPES: &[&str] = &["stylesheet", "script", "image", "font", "media", "manifest", "texttrack"];

const STATIC_EXTENSIONS: &[&str] = &[
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp", "woff", "woff2",
    "ttf", "otf", "eot", "mp4", "webm", "mp3", "ogg", "wav", "m4a", "mov",
];

fn text(v: &Value) -> String {
    values::scalar(v)
}

/// Just the shape of a HAR file, every entry skipped unread.
#[derive(Deserialize)]
#[allow(dead_code)] // Only its shape is checked.
struct Probe {
    log: ProbeLog,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ProbeLog {
    entries: Vec<serde::de::IgnoredAny>,
}

/// Whether `text` is a HAR file: `{"log": {"entries": [...]}}`, its entries skipped rather than
/// read, as [`build`] reads them next.
pub fn is_har(text: &str) -> bool {
    let t = text.trim_start_matches('\u{feff}').trim_start();
    text.len() <= MAX_HAR && text.contains("\"entries\"") && serde_json::from_str::<Probe>(t).is_ok()
}

fn parse(text: &str) -> Result<Har> {
    if text.len() > MAX_HAR {
        return Err(Error::InvalidInput(format!("the HAR file is larger than {} MiB", MAX_HAR >> 20)));
    }
    let t = text.trim_start_matches('\u{feff}').trim_start();
    serde_json::from_str(t).map_err(|e| {
        // Where it stopped, never the text there: a HAR holds cookies.
        Error::InvalidInput(format!("not a valid HAR file (line {}, column {})", e.line(), e.column()))
    })
}

/// The file's requests, in order, and who made the file. Never guarded-free: this is only
/// for `import api`'s rules.
pub fn build(document: &str, opts: &Options) -> Result<(Built, Creator)> {
    let har = parse(document)?;
    let made_by = if text_of(&har.log.browser.name).is_some() { &har.log.browser } else { &har.log.creator };
    let creator = Creator { name: text_of(&made_by.name), version: text_of(&made_by.version) };
    let mut out = Built::default();
    let (mut static_assets, mut repeats, mut not_http, mut websockets) = (0, 0, 0, 0);
    let mut seen = HashSet::new();
    for (i, e) in har.log.entries.iter().enumerate() {
        let r = &e.request;
        let method = text(&r.method).trim().to_ascii_uppercase();
        let raw_url = text(&r.url);
        let scheme = raw_url.split_once(':').map(|(s, _)| s.to_ascii_lowercase()).unwrap_or_default();
        let upgrade = r.headers.iter().any(|h| {
            text(&h.name).eq_ignore_ascii_case("upgrade") && text(&h.value).to_ascii_lowercase().contains("websocket")
        });
        if upgrade
            || matches!(scheme.as_str(), "ws" | "wss")
            || text(&e.resource_type).eq_ignore_ascii_case("websocket")
        {
            websockets += 1;
            continue;
        }
        if !matches!(scheme.as_str(), "http" | "https") {
            not_http += 1;
            continue;
        }
        let name = format!("{method} {}", shown_url(&raw_url));
        let label = format!("entry {i}: {name}");
        if !opts.keep_static && is_static(&method, &raw_url, &text(&e.resource_type), &text(&e.response.content.mime)) {
            static_assets += 1;
            continue;
        }
        let req = match request(name, &method, &raw_url, r, opts) {
            Ok(req) => req,
            Err(err) => {
                out.fail(true, label, &err);
                continue;
            }
        };
        // Accept too: the same URL may answer a page and its API (`Accept: application/json`).
        let header = |n: &str| req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
        let key = (
            req.method.clone(),
            req.url.clone(),
            header("content-type").unwrap_or_default(),
            header("accept").unwrap_or_default(),
            crate::fetch::sha256_hex(&req.body),
        );
        if !seen.insert(key) {
            repeats += 1;
            continue;
        }
        out.keep(true, label, req);
    }
    if har.log.entries.is_empty() {
        out.warn("the HAR file has no entries".into());
    }
    if static_assets > 0 {
        out.warn(format!(
            "left out {static_assets} static asset(s) (scripts, styles, images, fonts, media); --keep-static keeps them"
        ));
    }
    if repeats > 0 {
        out.warn(format!(
            "left out {repeats} repeated request(s): the same method, URL, Accept and body as an earlier entry"
        ));
    }
    if websockets > 0 {
        out.warn(format!("left out {websockets} WebSocket handshake(s); `ws send --from` replays a connection"));
    }
    if not_http > 0 {
        out.warn(format!("left out {not_http} entr(ies) whose URL isn't http(s) (data:, blob:, extensions)"));
    }
    Ok((out, creator))
}

fn text_of(v: &Value) -> Option<String> {
    Some(text(v)).filter(|s| !s.trim().is_empty())
}

fn is_static(method: &str, url: &str, resource_type: &str, mime: &str) -> bool {
    if !matches!(method, "GET" | "HEAD") {
        return false;
    }
    if STATIC_TYPES.contains(&resource_type.to_ascii_lowercase().as_str()) {
        return true;
    }
    let mime = mime.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    if ["image/", "font/", "video/", "audio/"].iter().any(|p| mime.starts_with(p))
        || mime == "text/css"
        || mime.contains("javascript")
        || mime.starts_with("application/font")
        || mime.starts_with("application/x-font")
    {
        return true;
    }
    let path = url.split(['?', '#']).next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();
    last.rsplit_once('.').is_some_and(|(_, ext)| STATIC_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

fn request(name: String, method: &str, raw_url: &str, r: &Request, opts: &Options) -> Result<ApiRequest> {
    let mut url = raw_url.to_string();
    // Some tools give the query only as `queryString`.
    let query: Vec<(String, String)> = r.query.iter().map(|q| (text(&q.name), text(&q.value))).collect();
    if !url.contains('?') && !query.is_empty() {
        url = format!("{url}?{}", String::from_utf8_lossy(&values::form(&query)));
    }
    if let Some(b) = &opts.base_url {
        url = rebase(&url, b)?;
    }
    url::Url::parse(&url).map_err(|e| Error::InvalidInput(format!("invalid URL {:?}: {e}", shown_url(&url))))?;
    let mut headers: Vec<(String, String)> = r
        .headers
        .iter()
        .map(|h| (text(&h.name).trim().to_string(), text(&h.value)))
        .filter(|(k, _)| !k.is_empty() && !k.starts_with(':'))
        .filter(|(k, _)| !NOT_REPLAYED.contains(&k.to_ascii_lowercase().as_str()))
        .filter(|(k, _)| {
            !matches!(method, "GET" | "HEAD") || !READ_CONDITIONALS.contains(&k.to_ascii_lowercase().as_str())
        })
        .collect();
    let has = |hs: &[(String, String)], n: &str| hs.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    // A sanitized or hand-made HAR may list the cookies without the header.
    if !has(&headers, "cookie") && !r.cookies.is_empty() {
        let jar: Vec<String> = r.cookies.iter().map(|c| format!("{}={}", text(&c.name), text(&c.value))).collect();
        headers.push(("Cookie".into(), jar.join("; ")));
    }
    let mut body = Vec::new();
    if let Some(p) = &r.post {
        let mime = text(&p.mime);
        let given = text(&p.text);
        if !given.is_empty() && text(&p.encoding).eq_ignore_ascii_case("base64") {
            use base64::Engine;
            body = base64::engine::general_purpose::STANDARD
                .decode(given.trim())
                .map_err(|_| Error::InvalidInput("its base64 body doesn't decode".into()))?;
        } else if !given.is_empty() {
            body = given.into_bytes();
        } else if !p.params.is_empty() {
            if mime.to_ascii_lowercase().contains("multipart/") {
                // A file's content isn't in the HAR: a stand-in goes in its place.
                let parts: Vec<Part> = p
                    .params
                    .iter()
                    .map(|q| match text_of(&q.file_name) {
                        Some(f) => Part { name: text(&q.name), value: "test".into(), file: Some(f) },
                        None => Part { name: text(&q.name), value: text(&q.value), file: None },
                    })
                    .collect();
                body = values::multipart(&parts);
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
                headers.push(("Content-Type".into(), format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}")));
            } else {
                let fields: Vec<(String, String)> = p.params.iter().map(|q| (text(&q.name), text(&q.value))).collect();
                body = values::form(&fields);
                // Fields alone are a form, whatever type the file gives (or none).
                if !has(&headers, "content-type") && !mime.to_ascii_lowercase().contains("form") {
                    headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
                }
            }
        }
        // A text body the file gives no type for goes without one, rather than a guessed one.
        if !body.is_empty() && !has(&headers, "content-type") && !mime.is_empty() {
            headers.push(("Content-Type".into(), mime));
        }
    }
    Ok(ApiRequest { name, method: method.into(), url, headers, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// As Chrome's DevTools exports it: HTTP/2 pseudo-headers, lower-case names, the
    /// resource type, cookies in both the header and the list, and response bodies.
    fn chrome() -> String {
        json!({"log": {
        "version": "1.2",
        "creator": {"name": "WebInspector", "version": "537.36"},
        "pages": [{"id": "page_1", "title": "https://app.test/"}],
        "entries": [
            {"_resourceType": "document", "request": {
                "method": "GET", "url": "https://app.test/account?tab=1", "httpVersion": "http/2.0",
                "headers": [
                    {"name": ":authority", "value": "app.test"}, {"name": ":method", "value": "GET"},
                    {"name": ":path", "value": "/account?tab=1"}, {"name": ":scheme", "value": "https"},
                    {"name": "accept", "value": "text/html"}, {"name": "accept-encoding", "value": "gzip, br, zstd"},
                    {"name": "cookie", "value": "sid=CHROMESECRET1; theme=dark"},
                    {"name": "if-none-match", "value": "\"abc\""}],
                "queryString": [{"name": "tab", "value": "1"}],
                "cookies": [{"name": "sid", "value": "CHROMESECRET1", "httpOnly": true}],
                "headersSize": -1, "bodySize": 0},
              "response": {"status": 200, "content": {"size": 5, "mimeType": "text/html", "text": "<html>"}}},
            {"_resourceType": "script", "request": {"method": "GET", "url": "https://app.test/app.js",
                "headers": [], "cookies": [], "queryString": []},
              "response": {"status": 200, "content": {"mimeType": "application/javascript", "text": "x()"}}},
            {"_resourceType": "image", "request": {"method": "GET", "url": "https://cdn.test/logo",
                "headers": [], "cookies": [], "queryString": []},
              "response": {"status": 200, "content": {"mimeType": "image/png", "encoding": "base64", "text": "iVBOR"}}},
            {"_resourceType": "fetch", "request": {"method": "POST", "url": "https://app.test/api/orders",
                "headers": [{"name": "content-type", "value": "application/json"},
                    {"name": "authorization", "value": "Bearer CHROMESECRET2"},
                    {"name": "content-length", "value": "11"}],
                "cookies": [], "queryString": [],
                "postData": {"mimeType": "application/json", "text": "{\"qty\": 2}"}},
              "response": {"status": 201, "content": {"mimeType": "application/json", "text": "{}"}}},
            {"_resourceType": "fetch", "request": {"method": "POST", "url": "https://app.test/api/orders",
                "headers": [{"name": "content-type", "value": "application/json"}],
                "cookies": [], "queryString": [],
                "postData": {"mimeType": "application/json", "text": "{\"qty\": 2}"}},
              "response": {"status": 201, "content": {"mimeType": "application/json"}}},
            {"_resourceType": "websocket", "request": {"method": "GET", "url": "wss://app.test/live",
                "headers": [], "cookies": [], "queryString": []}, "response": {"status": 101, "content": {}}},
            {"_resourceType": "image", "request": {"method": "GET", "url": "data:image/png;base64,AAAA",
                "headers": [], "cookies": [], "queryString": []}, "response": {"status": 200, "content": {}}},
            {"_resourceType": "fetch", "request": {"method": "DELETE", "url": "https://app.test/api/orders/7",
                "headers": [], "cookies": [], "queryString": []}, "response": {"status": 204, "content": {}}}
        ]}})
        .to_string()
    }

    /// As Firefox saves it: `browser` beside `creator`, HTTP/1.1 header case and a Host
    /// header, no resource type, and form and multipart bodies as `params`.
    fn firefox() -> String {
        json!({"log": {
            "version": "1.2",
            "creator": {"name": "Firefox", "version": "133.0"},
            "browser": {"name": "Firefox", "version": "133.0"},
            "entries": [
                {"pageref": "page_1", "startedDateTime": "2026-11-01T10:00:00.000+00:00", "request": {
                    "bodySize": 27, "method": "POST", "url": "http://app.test/login", "httpVersion": "HTTP/1.1",
                    "headers": [{"name": "Host", "value": "app.test"},
                        {"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
                        {"name": "Cookie", "value": "PHPSESSID=FOXSECRET1"},
                        {"name": "Connection", "value": "keep-alive"}],
                    "cookies": [{"name": "PHPSESSID", "value": "FOXSECRET1"}],
                    "queryString": [],
                    "postData": {"mimeType": "application/x-www-form-urlencoded",
                        "params": [{"name": "user", "value": "alice"}, {"name": "password", "value": "FOXSECRET2"}],
                        "text": ""}},
                  "response": {"status": 302, "content": {"mimeType": "text/html; charset=UTF-8", "size": 0}}},
                {"request": {"method": "POST", "url": "http://app.test/upload",
                    "headers": [{"name": "Content-Type", "value": "multipart/form-data; boundary=---------------------------1"}],
                    "cookies": [], "queryString": [],
                    "postData": {"mimeType": "multipart/form-data; boundary=---------------------------1",
                        "params": [{"name": "title", "value": "cv"}, {"name": "file", "fileName": "cv.pdf", "contentType": "application/pdf"}]}},
                  "response": {"status": 200, "content": {"mimeType": "application/json"}}},
                {"request": {"method": "GET", "url": "http://app.test/search",
                    "headers": [{"name": "Accept", "value": "*/*"}], "cookies": [],
                    "queryString": [{"name": "q", "value": "shoes"}]},
                  "response": {"status": 200, "content": {"mimeType": "application/json"}}},
                {"request": {"method": "GET", "url": "http://app.test/static/site.css?v=3",
                    "headers": [], "cookies": [], "queryString": [{"name": "v", "value": "3"}]},
                  "response": {"status": 200, "content": {"mimeType": "text/css"}}}
            ]}})
        .to_string()
    }

    #[test]
    fn chrome_entries_become_requests() {
        let (b, creator) = build(&chrome(), &Options::default()).unwrap();
        assert_eq!(creator.name.as_deref(), Some("WebInspector"));
        let got: Vec<(String, String)> = b.requests.iter().map(|r| (r.method.clone(), r.url.clone())).collect();
        assert_eq!(
            got,
            vec![
                ("GET".into(), "https://app.test/account?tab=1".into()),
                ("POST".into(), "https://app.test/api/orders".into()),
                ("DELETE".into(), "https://app.test/api/orders/7".into()),
            ]
        );
        let page = &b.requests[0];
        let names: Vec<&str> = page.headers.iter().map(|(k, _)| k.as_str()).collect();
        // No pseudo-headers, encodings or conditionals; the cookie header as recorded (harden takes it out).
        assert_eq!(names, ["accept", "cookie"], "{:?}", page.headers);
        let post = &b.requests[1];
        assert_eq!(post.body, b"{\"qty\": 2}");
        assert!(!post.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")));
        assert_eq!(post.name, "POST https://app.test/api/orders");
        let w = b.warnings.join("\n");
        for want in ["2 static asset", "1 repeated request", "1 WebSocket", "1 entr(ies) whose URL isn't http(s)"] {
            assert!(w.contains(want), "{want}: {w}");
        }
        assert!(!w.contains("SECRET") && !w.contains("AAAA"), "{w}");
    }

    #[test]
    fn firefox_params_become_bodies() {
        let (b, creator) = build(&firefox(), &Options::default()).unwrap();
        assert_eq!((creator.name.as_deref(), creator.version.as_deref()), (Some("Firefox"), Some("133.0")));
        assert_eq!(b.requests.len(), 3, "{:?}", b.requests);
        let login = &b.requests[0];
        assert_eq!(String::from_utf8_lossy(&login.body), "user=alice&password=FOXSECRET2");
        assert!(!login
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("connection")));
        let upload = &b.requests[1];
        let body = String::from_utf8_lossy(&upload.body);
        assert!(body.contains("name=\"title\"\r\n\r\ncv") && body.contains("filename=\"cv.pdf\""), "{body}");
        let ct = upload.headers.iter().find(|(k, _)| k == "Content-Type").unwrap();
        assert!(ct.1.contains(MULTIPART_BOUNDARY), "{ct:?}");
        assert_eq!(b.requests[2].url, "http://app.test/search?q=shoes");
        assert!(b.warnings.iter().any(|w| w.contains("1 static asset")), "{:?}", b.warnings);
    }

    #[test]
    fn static_assets_can_be_kept_and_urls_rebased() {
        let opts = Options { keep_static: true, base_url: Some("http://staging.test:8080".into()) };
        let (b, _) = build(&firefox(), &opts).unwrap();
        assert_eq!(b.requests.len(), 4);
        assert_eq!(b.requests[3].url, "http://staging.test:8080/static/site.css?v=3");
        assert!(!b.warnings.iter().any(|w| w.contains("static")));
    }

    #[test]
    fn cookies_without_a_header_and_queries_without_a_url() {
        let doc = json!({"log": {"entries": [{"request": {"method": "get", "url": "https://a.test/x",
            "cookies": [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}],
            "queryString": [{"name": "k", "value": "v w"}]}}]}})
        .to_string();
        let (b, _) = build(&doc, &Options::default()).unwrap();
        let r = &b.requests[0];
        assert_eq!((r.method.as_str(), r.url.as_str()), ("GET", "https://a.test/x?k=v+w"));
        assert_eq!(r.headers, vec![("Cookie".to_string(), "a=1; b=2".to_string())]);
    }

    #[test]
    fn null_fields_read_as_empty() {
        let doc = json!({"log": {"creator": null, "entries": [
            {"request": {"method": "POST", "url": "https://a.test/x", "headers": null, "cookies": null,
                "queryString": null, "postData": {"mimeType": null, "text": "{\"a\":1}", "params": null}},
             "response": null},
            {"request": {"method": "GET", "url": "https://a.test/y"}, "response": {"content": null}}]}})
        .to_string();
        assert!(is_har(&doc));
        let (b, _) = build(&doc, &Options::default()).unwrap();
        assert_eq!(b.requests.len(), 2, "{:?}", b.skipped);
        // A text body without a type goes without one, not as a guessed form.
        assert_eq!((b.requests[0].body.as_slice(), b.requests[0].headers.len()), (&b"{\"a\":1}"[..], 0));
    }

    #[test]
    fn fields_alone_are_a_form_and_accept_tells_requests_apart() {
        let doc = json!({"log": {"entries": [
            {"request": {"method": "POST", "url": "https://a.test/f", "postData": {"params": [{"name": "a", "value": "1"}]}}},
            {"request": {"method": "GET", "url": "https://a.test/orders", "headers": [{"name": "Accept", "value": "text/html"}]}},
            {"request": {"method": "GET", "url": "https://a.test/orders", "headers": [{"name": "Accept", "value": "application/json"}]}},
            {"request": {"method": "GET", "url": "https://a.test/orders", "headers": [{"name": "Accept", "value": "application/json"}, {"name": "X-Trace", "value": "2"}]}}]}})
        .to_string();
        let (b, _) = build(&doc, &Options::default()).unwrap();
        let form = &b.requests[0];
        assert_eq!(form.body, b"a=1");
        assert_eq!(form.headers, vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]);
        assert_eq!(b.requests.len(), 3, "the page and its JSON are both kept, the repeat isn't");
        assert!(b.warnings.iter().any(|w| w.contains("1 repeated request")), "{:?}", b.warnings);
    }

    #[test]
    fn writes_keep_their_preconditions_and_base64_bodies_are_decoded() {
        let doc = json!({"log": {"entries": [
            {"request": {"method": "PUT", "url": "https://a.test/doc/1", "headers": [
                {"name": "If-Match", "value": "\"v3\""}, {"name": "If-None-Match", "value": "*"},
                {"name": "Content-Encoding", "value": "gzip"}, {"name": "Content-Type", "value": "application/octet-stream"}],
                "postData": {"mimeType": "application/octet-stream", "text": "//4=", "_encoding": "base64"}}},
            {"request": {"method": "GET", "url": "https://a.test/doc/1", "headers": [{"name": "If-Match", "value": "\"v3\""}]}},
            {"request": {"method": "POST", "url": "https://a.test/bad", "postData": {"text": "!!", "_encoding": "base64"}}}]}})
        .to_string();
        let (b, _) = build(&doc, &Options::default()).unwrap();
        let put = &b.requests[0];
        let names: Vec<&str> = put.headers.iter().map(|(k, _)| k.as_str()).collect();
        // The body is the decoded one, so its encoding header would lie about it.
        assert_eq!(names, ["If-Match", "If-None-Match", "Content-Type"]);
        assert_eq!(put.body, [0xff, 0xfe]);
        assert!(b.requests[1].headers.is_empty(), "{:?}", b.requests[1].headers);
        assert_eq!(b.skipped.len(), 1, "{:?}", b.skipped);
        assert!(b.skipped[0].reason.contains("base64"), "{:?}", b.skipped);
    }

    #[test]
    fn broken_files_say_where_not_what() {
        let e =
            build("{\"log\": {\"entries\": [{\"request\": SECRET}]}}", &Options::default()).unwrap_err().to_string();
        assert!(e.contains("line 1") && !e.contains("SECRET"), "{e}");
        assert!(is_har(&chrome()) && !is_har("{\"openapi\": \"3.0.0\", \"entries\": 1}"));
        let (b, _) = build("{\"log\": {\"version\": \"1.2\", \"entries\": []}}", &Options::default()).unwrap();
        assert!(b.requests.is_empty() && b.warnings[0].contains("no entries"));
    }
}
