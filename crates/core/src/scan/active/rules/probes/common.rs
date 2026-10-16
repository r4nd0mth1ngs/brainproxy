//! Helpers shared by the page and host probe rules: request rewriting, ZAP's
//! isPage200/isSuccess checks, commonlib's ComparableResponse and TimingUtils, and
//! small stand-ins for the Jericho HTML parser and renderer.
//!
//! ComparableResponse and TimingUtils are ported from ZAP commonlib (Apache
//! License 2.0).

use std::future::Future;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

use crate::http::RawRequest;
use crate::scan::active::rules::env_file::testable_path;
use crate::scan::active::{Cx, Response};

/// commonlib AbstractAppFilePlugin.scan up to the status check: GETs `filename`
/// in the base request's directory once per run (ZAP tracks this in its Kb) and
/// returns the response when it is a 200. The LOW-threshold 401/403 alert is not
/// raised at the MEDIUM threshold, so it is not ported.
pub(super) async fn app_file_probe(cx: &Cx, rule_id: u32, filename: &str) -> Option<Response> {
    let path = testable_path(&cx.base().path, filename);
    if cx.stopped() || !cx.once(&format!("{rule_id}|{}{path}", cx.target().origin())) {
        return None;
    }
    let resp = cx.send(cx.request_for("GET", &path)).await.ok()?;
    (resp.status == 200).then_some(resp)
}

/// commonlib AbstractHostFilePlugin.scan up to the status check: GETs `path` at
/// the host root and returns the response when it is a 2xx.
pub(super) async fn host_file_probe(cx: &Cx, path: &str) -> Option<Response> {
    if cx.stopped() {
        return None;
    }
    let resp = cx.send(cx.request_for("GET", path)).await.ok()?;
    is_success(&resp).then_some(resp)
}

/// ZAP `isSuccess`: a 2xx status.
pub(super) fn is_success(resp: &Response) -> bool {
    (200..300).contains(&resp.status)
}

/// ZAP `isPage200`: a 200 that is not this host's soft-404 page.
pub(super) async fn is_page_200(cx: &Cx, resp: &Response) -> bool {
    resp.status == 200 && !cx.not_found(resp).await
}

/// The base request's path and query as sent.
pub(super) fn base_path_query(cx: &Cx) -> String {
    let base = cx.base();
    match &base.query {
        Some(q) => format!("{}?{q}", base.path),
        None => base.path.clone(),
    }
}

/// The base request path, "/" when empty.
pub(super) fn base_path(cx: &Cx) -> String {
    let p = &cx.base().path;
    if p.is_empty() {
        "/".into()
    } else {
        p.clone()
    }
}

/// `raw` with a new request line (method and target); headers and body are kept
/// (ZAP `getNewMsg()` followed by `setMethod`/`setURI`).
pub(super) fn with_request_line(raw: &[u8], method: &str, target: &str) -> Vec<u8> {
    let line_end = raw.windows(2).position(|w| w == b"\r\n").unwrap_or(raw.len());
    let line = String::from_utf8_lossy(&raw[..line_end]);
    let version = line.rsplit(' ').next().filter(|v| v.starts_with("HTTP/")).unwrap_or("HTTP/1.1");
    let mut out = format!("{method} {target} {version}").into_bytes();
    out.extend_from_slice(&raw[line_end..]);
    out
}

/// `raw` with its body replaced and Content-Length set to match.
pub(super) fn with_body(raw: Vec<u8>, body: &[u8]) -> Vec<u8> {
    let req = RawRequest::from_bytes(raw).remove_header("Transfer-Encoding");
    let mut bytes = req.split().0.to_vec();
    bytes.extend_from_slice(body);
    RawRequest::from_bytes(bytes).set_header("Content-Length", &body.len().to_string()).into_bytes()
}

/// A new request without the base request's headers (ZAP `new HttpMessage(uri)`):
/// only Host, the base User-Agent and, with a body, Content-Length.
pub(super) fn fresh_request(cx: &Cx, method: &str, path_and_query: &str, body: &[u8]) -> Vec<u8> {
    let version = String::from_utf8_lossy(cx.base_request().split(|&b| b == b'\n').next().unwrap_or_default())
        .trim_end()
        .rsplit(' ')
        .next()
        .filter(|v| v.starts_with("HTTP/"))
        .unwrap_or("HTTP/1.1")
        .to_string();
    let mut out = format!("{method} {path_and_query} {version}\r\nHost: {}\r\n", cx.target().host_header());
    if let Some(ua) = cx.base().req_header("user-agent") {
        out.push_str(&format!("User-Agent: {ua}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// The request line of the request that produced `resp` (ZAP's request prime header).
pub(super) fn request_line(resp: &Response) -> String {
    let end = resp.request.windows(2).position(|w| w == b"\r\n").unwrap_or(resp.request.len());
    String::from_utf8_lossy(&resp.request[..end]).into_owned()
}

/// A stand-in exchange for findings raised without a response (timeouts,
/// connection failures): the attack request and an empty response.
pub(super) fn no_response(cx: &Cx, request: Vec<u8>, duration: Duration) -> Response {
    let mut r = cx.base_response().clone();
    r.request = request;
    r.raw = Vec::new();
    r.duration = duration;
    r
}

/// ZAP `HttpHeader.isText()`-style check on a Content-Type value.
pub(super) fn is_text_type(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.starts_with("text/")
        || ct.contains("html")
        || ct.contains("xml")
        || ct.contains("json")
        || ct.contains("javascript")
        || ct.contains("ecmascript")
}

/// Number of pieces Java's `String.split(regex)` returns (trailing empty strings
/// removed; an empty input gives one piece).
pub(super) fn java_split_count(s: &str, re: &Regex) -> usize {
    if s.is_empty() {
        return 1;
    }
    let parts: Vec<&str> = re.split(s).collect();
    let mut n = parts.len();
    while n > 0 && parts[n - 1].is_empty() {
        n -= 1;
    }
    n
}

/// Non-overlapping occurrences (commons-lang `StringUtils.countMatches`; 0 for an empty needle).
fn count_matches(hay: &str, needle: &str) -> usize {
    if needle.is_empty() {
        0
    } else {
        hay.matches(needle).count()
    }
}

/// Basic HTML escaping (commons-text `escapeHtml4` for ASCII input).
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// ---------------------------------------------------------------------------
// ComparableResponse (commonlib), heuristics from Backslash Powered Scanner.

const STATUS_CODE_WEIGHT: f32 = 1.0;
const HEADERS_WEIGHT: f32 = 0.15;
const HTML_STRUCTURE_WEIGHT: f32 = 0.5;
const NUMBER_LINES_WEIGHT: f32 = 0.25;
const NUMBER_WORDS_WEIGHT: f32 = 0.5;
const REFLECTION_WEIGHT: f32 = 0.5;
const RELEVANT_KEYWORDS_WEIGHT: f32 = 0.5;
const DYNAMIC_HEADERS: [&str; 2] = ["Expires", "Date"];
const RELEVANT_KEYWORDS: [&str; 9] =
    ["error", "problem", "unexpected", "template", "line", "syntax", "warning", "unknown", "token"];

static CRLF_SPLIT: LazyLock<Regex> = LazyLock::new(|| Regex::new("\r\n|\r|\n").unwrap());
static WORD_SPLIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

/// One response reduced to what the similarity heuristics compare.
pub(super) struct ComparableResponse {
    status: u16,
    body: String,
    /// Case-insensitive map: first-seen name, last value.
    headers: Vec<(String, String)>,
    value_sent: String,
    paths: Option<(Vec<(String, usize)>, usize)>,
}

impl ComparableResponse {
    pub(super) fn new(status: u16, body: &str, headers: &[(String, String)], value_sent: &str) -> Self {
        let mut map: Vec<(String, String)> = Vec::new();
        for (k, v) in headers {
            match map.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(k)) {
                Some(e) => e.1 = v.clone(),
                None => map.push((k.clone(), v.clone())),
            }
        }
        let mut r =
            Self { status, body: body.to_string(), headers: map, value_sent: value_sent.to_string(), paths: None };
        r.paths = Some(r.all_paths());
        r
    }

    /// From a response, with its headers (ZAP `new ComparableResponse(msg, valueSent)`).
    pub(super) fn from_response(resp: &Response, value_sent: &str) -> Self {
        Self::new(resp.status, resp.body_str(), &resp.headers, value_sent)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn content_type(&self) -> Option<String> {
        self.header("Content-Type").map(|v| v.to_lowercase().split(';').next().unwrap_or("").to_string())
    }

    /// 0 means very different, 1 very similar.
    pub(super) fn compare_with(&self, other: &Self) -> f32 {
        let mut total = 1f32;
        total *= status_code_heuristic(self, other) * STATUS_CODE_WEIGHT + (1.0 - STATUS_CODE_WEIGHT);
        if total == 0.0 {
            return 0.0;
        }
        total *= body_structure_heuristic(self, other) * HTML_STRUCTURE_WEIGHT + (1.0 - HTML_STRUCTURE_WEIGHT);
        total *= headers_heuristic(self, other) * HEADERS_WEIGHT + (1.0 - HEADERS_WEIGHT);
        total *= line_count_heuristic(self, other) * NUMBER_LINES_WEIGHT + (1.0 - NUMBER_LINES_WEIGHT);
        total *= word_count_heuristic(self, other) * NUMBER_WORDS_WEIGHT + (1.0 - NUMBER_WORDS_WEIGHT);
        total *= reflection_heuristic(self, other) * REFLECTION_WEIGHT + (1.0 - REFLECTION_WEIGHT);
        total *= keywords_heuristic(self, other) * RELEVANT_KEYWORDS_WEIGHT + (1.0 - RELEVANT_KEYWORDS_WEIGHT);
        total
    }

    fn all_paths(&self) -> (Vec<(String, usize)>, usize) {
        let mut counts: Vec<(String, usize)> = Vec::new();
        let mut n = 0;
        let Some(ct) = self.content_type() else { return (counts, 0) };
        let mut add = |p: String| {
            n += 1;
            match counts.iter_mut().find(|(k, _)| *k == p) {
                Some(e) => e.1 += 1,
                None => counts.push((p, 1)),
            }
        };
        if ct.contains("text/html") {
            for p in html_element_paths(&self.body) {
                add(p);
            }
        }
        if ct.contains("json") {
            let value = serde_json::from_str::<serde_json::Value>(&self.body)
                .ok()
                .filter(|v| v.is_object() || v.is_array())
                .unwrap_or(serde_json::Value::Null);
            for p in json_paths(&value) {
                add(p);
            }
        }
        (counts, n)
    }
}

fn ratio(a: f32, b: f32) -> f32 {
    if a > b {
        b / a
    } else if a < b {
        a / b
    } else {
        1.0
    }
}

fn status_code_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    if a.status != b.status {
        0.0
    } else {
        1.0
    }
}

fn keywords_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    let (la, lb) = (a.body.to_lowercase(), b.body.to_lowercase());
    let (mut na, mut nb) = (0f32, 0f32);
    for k in RELEVANT_KEYWORDS {
        if k.eq_ignore_ascii_case(&a.value_sent) || k.eq_ignore_ascii_case(&b.value_sent) {
            continue;
        }
        na += count_matches(&la, k) as f32;
        nb += count_matches(&lb, k) as f32;
    }
    ratio(na, nb)
}

fn reflection_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    let (v1, v2) = (a.value_sent.as_str(), b.value_sent.as_str());
    let (e1, e2) = (escape_html(v1), escape_html(v2));
    let (mut body1, mut body2) = (a.body.clone(), b.body.clone());
    let n11 = count_matches(&body1, v1) + count_matches(&body1, &e1);
    let n22 = count_matches(&body2, v2) + count_matches(&body2, &e2);
    if v2.contains(v1) && !v2.is_empty() {
        body2 = body2.replace(v2, "");
    }
    let mut n12 = count_matches(&body2, v1);
    if e1 != v1 {
        n12 += count_matches(&body2, &e1);
    }
    if v1.contains(v2) && !v1.is_empty() {
        body1 = body1.replace(v1, "");
    }
    let mut n21 = count_matches(&body1, v2);
    if e2 != v2 {
        n21 += count_matches(&body1, &e2);
    }
    let p1 = 1.0 + (n11 as f32 - n12 as f32).abs();
    let p2 = 1.0 + (n21 as f32 - n22 as f32).abs();
    ratio(p1, p2)
}

fn word_count_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    ratio(java_split_count(&a.body, &WORD_SPLIT) as f32, java_split_count(&b.body, &WORD_SPLIT) as f32)
}

fn line_count_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    ratio(java_split_count(&a.body, &CRLF_SPLIT) as f32, java_split_count(&b.body, &CRLF_SPLIT) as f32)
}

fn headers_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    if a.headers.is_empty() && b.headers.is_empty() {
        return 1.0;
    }
    if a.headers.is_empty() || b.headers.is_empty() {
        return 0.0;
    }
    let (larger, smaller) = if b.headers.len() > a.headers.len() { (b, a) } else { (a, b) };
    let mut number = a.headers.len().max(b.headers.len()) as f32;
    let mut equal = 0f32;
    for (k, v) in &larger.headers {
        // ZAP compares the stored key case-sensitively against "Expires"/"Date".
        if DYNAMIC_HEADERS.contains(&k.as_str()) {
            number -= 1.0;
            continue;
        }
        if smaller.header(k) == Some(v.as_str()) {
            equal += 1.0;
        }
    }
    equal / number
}

fn body_structure_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    match (a.content_type(), b.content_type()) {
        (Some(ca), Some(cb)) => {
            if ca != cb {
                return 0.0;
            }
            if ca.contains("text/html") || ca.contains("json") {
                let (pa, na) = a.paths.as_ref().map(|(p, n)| (p, *n)).unwrap();
                let (pb, nb) = b.paths.as_ref().map(|(p, n)| (p, *n)).unwrap();
                if na == 0 && nb == 0 {
                    return 1.0;
                }
                if na == 0 || nb == 0 {
                    return 0.0;
                }
                let common: usize =
                    pa.iter().filter(|(k, c)| pb.iter().any(|(k2, c2)| k2 == k && c2 == c)).map(|(_, c)| *c).sum();
                let f1 = common as f32 / na as f32;
                let f2 = common as f32 / nb as f32;
                return (f1 + f2) / 2.0;
            }
            1.0
        }
        (None, None) => 1.0,
        _ => 0.0,
    }
}

fn json_paths(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    match v {
        serde_json::Value::Object(m) => {
            for (k, child) in m {
                for p in json_paths(child) {
                    out.push(p + k);
                }
            }
        }
        serde_json::Value::Array(a) => {
            for child in a {
                out.extend(json_paths(child));
            }
        }
        _ => {}
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

// ---------------------------------------------------------------------------
// Minimal HTML element tree (stand-in for Jericho's element hierarchy).

const VOID_ELEMENTS: [&str; 16] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr",
    "keygen", "command",
];

struct Node {
    name: String,
    children: Vec<usize>,
}

/// Element tree of an HTML document: (nodes, top-level node indexes).
fn html_tree(body: &str) -> (Vec<Node>, Vec<usize>) {
    let mut nodes: Vec<Node> = Vec::new();
    let mut roots = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let lower = body.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut i = 0;
    while let Some(off) = lower[i..].find('<') {
        i += off;
        if lower[i..].starts_with("<!--") {
            i = lower[i + 4..].find("-->").map(|e| i + 4 + e + 3).unwrap_or(b.len());
            continue;
        }
        if lower[i..].starts_with("<!") || lower[i..].starts_with("<?") {
            i = lower[i..].find('>').map(|e| i + e + 1).unwrap_or(b.len());
            continue;
        }
        let closing = b.get(i + 1) == Some(&b'/');
        let start = if closing { i + 2 } else { i + 1 };
        let mut end = start;
        while end < b.len() && (b[end].is_ascii_alphanumeric() || b[end] == b'-' || b[end] == b':' || b[end] == b'_') {
            end += 1;
        }
        if end == start || !b[start].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let name = lower[start..end].to_string();
        let tag_end = lower[end..].find('>').map(|e| end + e).unwrap_or(b.len());
        i = (tag_end + 1).min(b.len());
        if closing {
            if let Some(pos) = stack.iter().rposition(|&n| nodes[n].name == name) {
                stack.truncate(pos);
            }
            continue;
        }
        let idx = nodes.len();
        nodes.push(Node { name: name.clone(), children: Vec::new() });
        match stack.last() {
            Some(&parent) => nodes[parent].children.push(idx),
            None => roots.push(idx),
        }
        let self_closing = tag_end > end && b[tag_end - 1] == b'/';
        if VOID_ELEMENTS.contains(&name.as_str()) || self_closing {
            continue;
        }
        if name == "script" || name == "style" {
            let close = format!("</{name}");
            i = lower[i..].find(&close).map(|e| i + e).unwrap_or(b.len());
            continue;
        }
        stack.push(idx);
    }
    (nodes, roots)
}

/// All leaf-to-element paths of the document's elements (ComparableResponse.getAllPaths).
pub(super) fn html_element_paths(body: &str) -> Vec<String> {
    fn paths(nodes: &[Node], n: usize) -> Vec<String> {
        let mut out = Vec::new();
        for &c in &nodes[n].children {
            for p in paths(nodes, c) {
                out.push(p + &nodes[n].name);
            }
        }
        if out.is_empty() {
            out.push(nodes[n].name.clone());
        }
        out
    }
    let (nodes, roots) = html_tree(body);
    roots.iter().flat_map(|&r| paths(&nodes, r)).collect()
}

/// Whether the document has an `<html>` element (Jericho `getFirstElement(HTML)`).
pub(super) fn has_html_element(body: &str) -> bool {
    static HTML: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<html[\s>/]").unwrap());
    HTML.is_match(body) || body.to_ascii_lowercase().ends_with("<html")
}

/// Text rendering of HTML (stand-in for Jericho's Renderer): tags removed,
/// `<br>` and block ends as new lines, script/style dropped, entities decoded.
pub(super) fn render_html_text(body: &str) -> String {
    static TAG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)<script\b.*?</script\s*>|<style\b.*?</style\s*>|<!--.*?-->|<(/?)([a-z][a-z0-9]*)\b[^>]*>")
            .unwrap()
    });
    const BLOCKS: [&str; 12] = ["br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre"];
    let mut out = String::with_capacity(body.len());
    let mut last = 0;
    for m in TAG.captures_iter(body) {
        let all = m.get(0).unwrap();
        out.push_str(&body[last..all.start()]);
        last = all.end();
        if let Some(name) = m.get(2) {
            let name = name.as_str().to_ascii_lowercase();
            if BLOCKS.contains(&name.as_str()) && (name == "br" || !m[1].is_empty()) {
                out.push('\n');
            }
        }
    }
    out.push_str(&body[last..]);
    decode_entities(&out)
}

/// Decodes the common named entities and numeric character references.
pub(super) fn decode_entities(s: &str) -> String {
    static ENTITY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"&(#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});").unwrap());
    ENTITY
        .replace_all(s, |c: &regex::Captures| {
            let e = &c[1];
            let ch = if let Some(hex) = e.strip_prefix("#x").or_else(|| e.strip_prefix("#X")) {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else if let Some(dec) = e.strip_prefix('#') {
                dec.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                match e {
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "amp" => Some('&'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "nbsp" => Some(' '),
                    _ => None,
                }
            };
            ch.map(String::from).unwrap_or_else(|| c[0].to_string())
        })
        .into_owned()
}

// ---------------------------------------------------------------------------
// TimingUtils / OnlineSimpleLinearRegression (commonlib).

#[derive(Debug, Default)]
pub(super) struct Regression {
    count: f64,
    x_sum: f64,
    y_sum: f64,
    x_var_n: f64,
    y_var_n: f64,
    cov_n: f64,
    slope: f64,
    correlation: f64,
}

impl Regression {
    pub(super) fn new() -> Self {
        Self { slope: 1.0, correlation: 1.0, ..Default::default() }
    }

    pub(super) fn add_point(&mut self, x: f64, y: f64) {
        let x_adj = x - self.x_sum / self.count;
        let y_adj = y - self.y_sum / self.count;
        self.count += 1.0;
        self.x_sum += x;
        self.y_sum += y;
        if x_adj.is_nan() {
            return;
        }
        let x_res = x - self.x_sum / self.count;
        let y_res = y - self.y_sum / self.count;
        self.x_var_n += x_res * x_adj;
        self.y_var_n += y_res * y_adj;
        self.cov_n += x_res * y_adj;
        self.slope = self.cov_n / self.x_var_n;
        self.correlation = self.slope * (self.x_var_n / self.y_var_n).sqrt();
        self.correlation *= self.correlation;
        if self.correlation.is_nan() {
            self.correlation = 1.0;
        }
    }

    pub(super) fn within_confidence(&self, correlation_error: f64, expected_slope: f64, slope_error: f64) -> bool {
        self.correlation > 1.0 - correlation_error && (expected_slope - self.slope).abs() < slope_error
    }
}

/// TimingUtils.checkTimingDependence: sends pairs of high/low delay requests and
/// checks that the response time follows the requested delay. `send` returns the
/// response time in seconds, or None when the request failed (which ends the check).
pub(super) async fn check_timing_dependence<F, Fut>(
    requests_limit: usize,
    high_sleep_secs: u32,
    mut send: F,
    correlation_error: f64,
    slope_error: f64,
) -> bool
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Option<f64>>,
{
    let mut regression = Regression::new();
    let mut left = requests_limit as i64;
    while left > 0 {
        for delay in [high_sleep_secs, 1] {
            let Some(y) = send(delay).await else { return false };
            if y < delay as f64 {
                return false;
            }
            regression.add_point(delay as f64, y);
            if !regression.within_confidence(0.3, 1.0, 0.5) {
                return false;
            }
        }
        left -= 2;
    }
    regression.within_confidence(correlation_error, 1.0, slope_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_split_counts() {
        assert_eq!(java_split_count("", &WORD_SPLIT), 1);
        assert_eq!(java_split_count("a b  c", &WORD_SPLIT), 3);
        assert_eq!(java_split_count(" a b", &WORD_SPLIT), 3);
        assert_eq!(java_split_count("a\n\n", &CRLF_SPLIT), 1);
        assert_eq!(java_split_count("a\r\nb\rc\nd", &CRLF_SPLIT), 4);
    }

    #[test]
    fn comparable_identical_and_different() {
        let h = vec![("Content-Type".to_string(), "text/html".to_string())];
        let a = ComparableResponse::new(200, "<html><body><p>hi</p></body></html>", &h, "");
        let b = ComparableResponse::new(200, "<html><body><p>hi</p></body></html>", &h, "");
        assert_eq!(a.compare_with(&b), 1.0);
        let c = ComparableResponse::new(404, "<html><body><p>hi</p></body></html>", &h, "");
        assert_eq!(a.compare_with(&c), 0.0);
        let d = ComparableResponse::new(200, "[core]\n\trepositoryformatversion = 0\n", &[], "");
        assert!(a.compare_with(&d) < 0.9);
    }

    #[test]
    fn html_paths() {
        let paths =
            html_element_paths("<!DOCTYPE html><html><head><title>x</title></head><body><br><p>a</p></body></html>");
        assert_eq!(paths, vec!["titleheadhtml", "brbodyhtml", "pbodyhtml"]);
        assert!(has_html_element("<HTML lang=en>"));
        assert!(!has_html_element("<htmlx>"));
    }

    #[test]
    fn json_path_counts() {
        let v: serde_json::Value = serde_json::from_str(r#"{"a":{"b":1},"c":[1,2]}"#).unwrap();
        assert_eq!(json_paths(&v), vec!["ba", "c", "c"]);
        let r = ComparableResponse::new(200, "not json", &[("Content-Type".into(), "application/json".into())], "");
        assert_eq!(r.paths.as_ref().unwrap().1, 1);
    }

    #[test]
    fn renders_html() {
        let html = "<code><span>&lt;?php&nbsp;echo&nbsp;1;<br />?&gt;</span></code>";
        assert_eq!(render_html_text(html), "<?php echo 1;\n?>");
        assert_eq!(decode_entities("&#65;&#x42;&unknown;"), "AB&unknown;");
    }

    #[test]
    fn request_rewrites() {
        let raw = b"POST /a?b=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc".to_vec();
        let r = with_request_line(&raw, "GET", "/z");
        assert_eq!(r, b"GET /z HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc");
        let r = with_body(raw, b"hello");
        assert_eq!(r, b"POST /a?b=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello");
    }

    #[test]
    fn regression_confidence() {
        let mut r = Regression::new();
        for (x, y) in [(5.0, 5.1), (1.0, 1.05), (5.0, 5.08), (1.0, 1.1)] {
            r.add_point(x, y);
        }
        assert!(r.within_confidence(0.15, 1.0, 0.3));
        let mut r = Regression::new();
        for (x, y) in [(5.0, 5.1), (1.0, 5.0)] {
            r.add_point(x, y);
        }
        assert!(!r.within_confidence(0.3, 1.0, 0.5));
    }

    #[tokio::test]
    async fn timing_dependence() {
        // A server that sleeps as asked.
        assert!(check_timing_dependence(4, 5, |d| async move { Some(d as f64 + 0.05) }, 0.15, 0.3).await);
        // A fast server stops after the first request.
        let mut sent = 0;
        let fast = check_timing_dependence(
            4,
            5,
            |_| {
                sent += 1;
                async { Some(0.1) }
            },
            0.15,
            0.3,
        )
        .await;
        assert!(!fast);
        assert_eq!(sent, 1);
    }
}
