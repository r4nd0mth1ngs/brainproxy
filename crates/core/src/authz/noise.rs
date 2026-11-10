//! Requests not worth testing for access control, because whatever comes back says nothing
//! about who may see what: static assets (served to everyone), HEAD and OPTIONS (no body to
//! compare), and paths the user chose to skip, by default well-known public files such as
//! `robots.txt` and health checks. Runs and live testing leave them out unless asked, and
//! `authz matrix` hides them from runs that tested them anyway.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::http::RawRequest;

/// Setting key of the project's saved skip paths ([`SavedSkips`]).
pub const SKIP_KEY: &str = "authz_skip";

/// Methods whose responses have no body to compare: always inconclusive or enforced, never a
/// bypass. Left out unless `--include-methods` names them.
pub const NO_BODY_METHODS: &[&str] = &["HEAD", "OPTIONS"];

/// Saved skip paths of a new project: files that are public by design.
pub const DEFAULT_SKIP_PATHS: &[&str] = &[
    "/robots.txt$",
    "/sitemap.xml$",
    "/sitemap_index.xml$",
    "/favicon.ico$",
    "/.well-known/",
    "/manifest.json$",
    "/site.webmanifest$",
    "/manifest.webmanifest$",
    "/browserconfig.xml$",
    "/crossdomain.xml$",
    "/clientaccesspolicy.xml$",
    "/humans.txt$",
    "/ads.txt$",
    "*/health$",
    "*/healthz$",
    "*/ping$",
];

/// How a skip path is written, for help texts and errors.
pub const SKIP_SYNTAX: &str = "a path (/static/) or URL (https://cdn.example.com/) it starts with; * matches any \
    characters, a trailing $ means it ends there, and case doesn't matter. A path matches without the query \
    string unless the pattern has a ?";

/// Content types of static assets, by prefix and in full.
const STATIC_TYPE_PREFIXES: &[&str] =
    &["image/", "font/", "audio/", "video/", "application/font", "application/x-font"];
const STATIC_TYPES: &[&str] = &[
    "text/css",
    "text/javascript",
    "text/ecmascript",
    "text/x-javascript",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/wasm",
    "application/vnd.ms-fontobject",
];
/// Extensions of static assets, counted when the response doesn't say what it is.
const STATIC_EXTENSIONS: &[&str] = &[
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "woff", "woff2",
    "ttf", "otf", "eot", "mp3", "mp4", "webm", "wasm",
];
/// `Sec-Fetch-Dest` values a browser sends for subresources that aren't data.
const STATIC_DESTS: &[&str] = &[
    "image",
    "style",
    "script",
    "font",
    "audio",
    "video",
    "track",
    "manifest",
    "worker",
    "sharedworker",
    "serviceworker",
    "audioworklet",
    "paintworklet",
    "xslt",
];

/// Why a request and its response are a static asset, or None. The response's Content-Type
/// decides first: a stylesheet, script, image, font, audio or video type is one, and an HTML,
/// JSON or XML response never is, whatever its path. Otherwise the browser's `Sec-Fetch-Dest`
/// (image, style, script, font, ...) or, when the response has no useful type, the path's
/// extension says so. A source map (`.map`) is one even when served as JSON.
pub fn static_asset(content_type: Option<&str>, path: &str, fetch_dest: Option<&str>) -> Option<String> {
    let kind = content_type.unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if STATIC_TYPES.contains(&kind.as_str()) || STATIC_TYPE_PREFIXES.iter().any(|p| kind.starts_with(p)) {
        return Some(format!("Content-Type {kind}"));
    }
    let untyped = kind.is_empty() || kind == "application/octet-stream" || kind == "binary/octet-stream";
    let ext = extension(path);
    if ext.as_deref() == Some("map") && (untyped || kind.contains("json")) {
        return Some("source map".into());
    }
    if kind.contains("html") || kind.contains("json") || kind.contains("xml") {
        return None;
    }
    if let Some(d) = fetch_dest.map(|d| d.trim().to_ascii_lowercase()).filter(|d| STATIC_DESTS.contains(&d.as_str())) {
        return Some(format!("Sec-Fetch-Dest {d}"));
    }
    match ext {
        Some(ext) if untyped && STATIC_EXTENSIONS.contains(&ext.as_str()) => Some(format!("extension .{ext}")),
        _ => None,
    }
}

/// The lowercase extension of a path's last segment, without its query.
fn extension(path: &str) -> Option<String> {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let name = path.rsplit('/').next()?;
    name.rsplit_once('.').map(|(_, ext)| ext.to_ascii_lowercase()).filter(|e| !e.is_empty())
}

/// The request's `Sec-Fetch-Dest` header, if any.
pub fn fetch_dest(request: &[u8]) -> Option<String> {
    let head = RawRequest::from_bytes(request.to_vec()).head().ok()?;
    head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-dest")).map(|(_, v)| v.trim().to_string())
}

/// Whether `method` has no body to compare and isn't opted in to by `included`
/// (`--include-methods`, where `all` names every method).
pub fn no_body_method(method: &str, included: &[String]) -> bool {
    NO_BODY_METHODS.iter().any(|m| m.eq_ignore_ascii_case(method))
        && !included.iter().any(|i| i.eq_ignore_ascii_case("all") || i.eq_ignore_ascii_case(method))
}

/// The project's saved skip paths, applied to every run and to live testing unless a run says
/// otherwise, and to what `authz matrix` shows. Unset, they are [`DEFAULT_SKIP_PATHS`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SavedSkips {
    #[serde(default)]
    pub paths: Vec<String>,
}

impl Default for SavedSkips {
    fn default() -> Self {
        SavedSkips { paths: DEFAULT_SKIP_PATHS.iter().map(|p| p.to_string()).collect() }
    }
}

/// One skip path, compiled.
#[derive(Debug, Clone)]
struct PathSkip {
    raw: String,
    re: Regex,
    /// Matched against the whole URL (the pattern has a scheme).
    url: bool,
    /// Matched against the path with its query string.
    query: bool,
}

impl PathSkip {
    fn new(pattern: &str) -> Result<PathSkip> {
        let raw = pattern.trim();
        let bad = |why: &str| Error::InvalidInput(format!("skip path {raw:?}: {why}; write {SKIP_SYNTAX}"));
        if raw.is_empty() {
            return Err(bad("empty"));
        }
        // A path may hold a URL in its query (`/fetch?url=https://...`): only a pattern that
        // starts with a scheme is a URL.
        let url = !raw.starts_with('/') && !raw.starts_with('*') && absolute(raw).is_some();
        if !url && !raw.starts_with('/') && !raw.starts_with('*') {
            return Err(bad("start it with / or *, or give a URL"));
        }
        let (body, end) = match raw.strip_suffix('$') {
            Some(b) => (b, true),
            None => (raw, false),
        };
        let glob = regex::escape(body).replace(r"\*", ".*");
        let src = format!("^{glob}{}", if end { "$" } else { "" });
        let re = RegexBuilder::new(&src).case_insensitive(true).build().map_err(|e| bad(&e.to_string()))?;
        Ok(PathSkip { raw: raw.to_string(), re, url, query: url || body.contains('?') })
    }

    fn matches(&self, url: &str, path: &str, path_query: &str) -> bool {
        self.re.is_match(if self.url {
            url
        } else if self.query {
            path_query
        } else {
            path
        })
    }
}

/// Skip paths ready to match URLs.
#[derive(Debug, Clone, Default)]
pub struct PathSkips(Vec<PathSkip>);

impl PathSkips {
    /// Fails naming the first pattern that isn't a valid skip path.
    pub fn compile<'a>(patterns: impl IntoIterator<Item = &'a String>) -> Result<PathSkips> {
        Ok(PathSkips(patterns.into_iter().map(|p| PathSkip::new(p)).collect::<Result<_>>()?))
    }

    /// The patterns of both.
    pub fn with(mut self, other: &PathSkips) -> PathSkips {
        self.0.extend(other.0.iter().cloned());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The first pattern `url` (absolute, or a path) matches.
    pub fn matching(&self, url: &str) -> Option<&str> {
        if self.0.is_empty() {
            return None;
        }
        let url = url.split('#').next().unwrap_or("");
        let path_query = url_path(url);
        let path = path_query.split('?').next().unwrap_or("/");
        self.0.iter().find(|s| s.matches(url, path, path_query)).map(|s| s.raw.as_str())
    }
}

/// The path (and query) of a URL, absolute or not: an absolute one without its origin, and
/// `/` when it has no path. A `://` in a path's query (`/logout?next=https://...`) doesn't make
/// it absolute.
pub fn url_path(url: &str) -> &str {
    match absolute(url) {
        Some(rest) => rest.find(['/', '?']).map_or("/", |i| &rest[i..]),
        None => url,
    }
}

/// What follows `scheme://` when `text` starts with a scheme (letters, digits, `+`, `-`, `.`).
fn absolute(text: &str) -> Option<&str> {
    let (scheme, rest) = text.split_once("://")?;
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then_some(rest)
}

/// Checks patterns before they are saved or used; returns them trimmed, without repeats.
pub fn check_skip_paths<'a>(patterns: impl IntoIterator<Item = &'a String>) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for p in patterns {
        PathSkip::new(p)?;
        let p = p.trim().to_string();
        if !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_assets_by_type_destination_or_extension() {
        assert!(static_asset(Some("text/javascript; charset=utf-8"), "/app", None).is_some());
        assert!(static_asset(Some("IMAGE/PNG"), "/avatar", None).is_some());
        assert!(static_asset(Some("font/woff2"), "/f", None).is_some());
        assert!(static_asset(Some("text/css"), "/api/theme", None).is_some());
        assert!(static_asset(None, "/static/app.min.JS", None).is_some());
        assert!(static_asset(Some("application/octet-stream"), "/a/b.woff2", None).is_some());
        assert!(static_asset(Some("application/json"), "/static/app.js.map", None).is_some(), "a source map");
        assert!(static_asset(None, "/static/app.css.map?v=2", None).is_some());
        // The response's type wins over the extension and the destination.
        assert!(static_asset(Some("application/json"), "/api/orders/1", None).is_none());
        assert!(static_asset(Some("application/json"), "/api/users.js", None).is_none());
        assert!(static_asset(Some("text/html"), "/report.png", None).is_none());
        assert!(static_asset(Some("application/json"), "/api/avatar", Some("image")).is_none());
        assert!(static_asset(None, "/api/orders/1", None).is_none());
        assert!(static_asset(None, "/v1.2/orders", None).is_none());
        assert!(static_asset(Some("text/plain"), "/a.js", None).is_none(), "a typed response isn't judged by name");
        // The browser's own label for what it fetched.
        assert_eq!(static_asset(Some("text/plain"), "/theme", Some("Style")).as_deref(), Some("Sec-Fetch-Dest style"));
        assert!(static_asset(None, "/avatar/17", Some("image")).is_some());
        assert!(static_asset(None, "/api/orders/1", Some("empty")).is_none());
        assert!(static_asset(None, "/page", Some("document")).is_none());
    }

    #[test]
    fn fetch_dest_and_methods() {
        let req = b"GET /a HTTP/1.1\r\nHost: a.test\r\nsec-fetch-dest: image\r\n\r\n";
        assert_eq!(fetch_dest(req).as_deref(), Some("image"));
        assert_eq!(fetch_dest(b"GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n"), None);
        assert!(no_body_method("head", &[]));
        assert!(no_body_method("OPTIONS", &["POST".into()]));
        assert!(!no_body_method("HEAD", &["head".into()]));
        assert!(!no_body_method("OPTIONS", &["all".into()]));
        assert!(!no_body_method("GET", &[]));
    }

    fn skips(patterns: &[&str]) -> PathSkips {
        PathSkips::compile(&patterns.iter().map(|p| p.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn skip_paths_are_prefixes_with_wildcards() {
        let s = skips(&["/static/", "*/health$", "/robots.txt$", "https://cdn.a.test/", "/search?q=*&page="]);
        assert_eq!(s.matching("https://a.test/static/x/y.png"), Some("/static/"));
        assert_eq!(s.matching("https://a.test/STATIC/x"), Some("/static/"), "case doesn't matter");
        assert_eq!(s.matching("http://a.test/health"), Some("*/health$"));
        assert_eq!(s.matching("http://a.test/api/v1/health?full=1"), Some("*/health$"), "the query isn't the path");
        assert_eq!(s.matching("http://a.test/healthcare/patients/1"), None, "$ ends it");
        assert_eq!(s.matching("http://a.test/robots.txt"), Some("/robots.txt$"));
        assert_eq!(s.matching("https://cdn.a.test/lib.js?v=1"), Some("https://cdn.a.test/"));
        assert_eq!(s.matching("https://app.a.test/lib.js"), None);
        assert_eq!(s.matching("http://a.test/search?q=x&page=2"), Some("/search?q=*&page="));
        assert_eq!(s.matching("http://a.test/search?page=2"), None);
        assert_eq!(s.matching("/static/a.css"), Some("/static/"), "a bare path");
        assert_eq!(s.matching("http://a.test"), None);
        // A URL in the query is part of the path's query, both in the pattern and the request.
        let q = skips(&["/fetch?url=https://example.test/", "/logout$"]);
        assert_eq!(
            q.matching("http://a.test/fetch?url=https://example.test/x"),
            Some("/fetch?url=https://example.test/")
        );
        assert_eq!(q.matching("/logout?next=https://example.test/"), Some("/logout$"));
        assert_eq!(url_path("/logout?next=https://example.test/"), "/logout?next=https://example.test/");
        assert_eq!(url_path("http://a.test?x=https://b.test/"), "?x=https://b.test/");
        // The default list.
        let d = PathSkips::compile(&SavedSkips::default().paths).unwrap();
        for public in ["/robots.txt", "/.well-known/openid-configuration", "/api/healthz", "/favicon.ico"] {
            assert!(d.matching(&format!("https://a.test{public}")).is_some(), "{public}");
        }
        for private in ["/api/orders/1", "/metrics", "/actuator/env", "/health/details", "/robots.txt.bak"] {
            assert!(d.matching(&format!("https://a.test{private}")).is_none(), "{private}");
        }
    }

    #[test]
    fn bad_skip_paths_are_refused() {
        for bad in ["", "  ", "robots.txt", "api/*"] {
            let e = check_skip_paths(&[bad.to_string()]).unwrap_err().to_string();
            assert!(e.contains("skip path"), "{e}");
        }
        let ok = check_skip_paths(&[" /a ".to_string(), "/a".to_string(), "*.pdf$".to_string()]).unwrap();
        assert_eq!(ok, vec!["/a".to_string(), "*.pdf$".to_string()]);
    }
}
