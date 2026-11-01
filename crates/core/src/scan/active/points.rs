//! Insertion points: the places in a request where a rule can put a value
//! (ZAP "variants"). Query and form parameters, JSON and XML values and multipart
//! fields are used by default; cookies, selected headers and URL path segments are
//! opt-in, like ZAP's defaults.

use std::ops::Range;

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Serialize;
use serde_json::Value;

use crate::http::request::{find, split_head_body};
use crate::http::RawRequest;
use crate::scan::message::url_decode;
use crate::scan::passive::util::decode_entities;

/// Everything but RFC 3986 unreserved characters is escaped in a path segment.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// File extensions of static assets: one file per directory is enough to attack.
const ASSET_EXT: &[&str] = &[
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "woff", "woff2",
    "ttf", "otf", "eot", "mp3", "mp4", "webm", "wasm",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PointKind {
    Query,
    Form,
    Json,
    Cookie,
    Header,
    Multipart,
    Xml,
    Path,
}

#[derive(Debug, Clone, PartialEq)]
enum Loc {
    /// Index of the name=value pair in the query or form body.
    Pair(usize),
    Json(Vec<JsonKey>),
    Cookie(usize),
    Header(String),
    /// Byte range of the value in the body.
    Body(Range<usize>),
    /// Byte range of a multipart file name in the body.
    FileName(Range<usize>),
    /// Index of the segment in the path split on `/`.
    Segment(usize),
}

#[derive(Debug, Clone, PartialEq)]
enum JsonKey {
    Field(String),
    Index(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub struct InsertionPoint {
    pub kind: PointKind,
    /// Parameter name (decoded); for JSON, a path like `user.tags[0]`; for XML, one
    /// like `order.item[1].@id`; for a multipart file, `field.filename`; for a URL
    /// path, `path[1]` (the segment's position).
    pub name: String,
    /// Original value (decoded).
    pub value: String,
    loc: Loc,
}

impl InsertionPoint {
    /// The name a session rule knows this parameter by: JSON values go by their last key.
    pub(crate) fn session_name(&self) -> &str {
        match self.kind {
            PointKind::Json => self.name.rsplit('.').next().unwrap_or(&self.name),
            _ => &self.name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PointOptions {
    pub query: bool,
    pub form: bool,
    pub json: bool,
    pub multipart: bool,
    pub xml: bool,
    pub path: bool,
    pub cookies: bool,
    /// Header names to inject into (e.g. User-Agent, Referer).
    pub headers: Vec<String>,
}

impl Default for PointOptions {
    fn default() -> Self {
        Self {
            query: true,
            form: true,
            json: true,
            multipart: true,
            xml: true,
            path: false,
            cookies: false,
            headers: Vec::new(),
        }
    }
}

fn split_target(head: &str) -> (&str, &str, &str) {
    // "METHOD target VERSION"
    let line = head.split("\r\n").next().unwrap_or("");
    let mut it = line.splitn(3, ' ');
    (it.next().unwrap_or(""), it.next().unwrap_or(""), it.next().unwrap_or(""))
}

fn pairs(s: &str) -> Vec<(&str, &str)> {
    s.split('&').map(|p| p.split_once('=').unwrap_or((p, ""))).collect()
}

fn content_type(raw: &[u8]) -> String {
    RawRequest::from_bytes(raw.to_vec())
        .head()
        .ok()
        .and_then(|h| h.headers.into_iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v))
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// The path of a request target, as a byte range: after any scheme and authority,
/// up to the query.
fn path_range(target: &str) -> Range<usize> {
    let end = target.find('?').unwrap_or(target.len());
    let start = match target[..end].find("://").filter(|_| !target.starts_with('/')) {
        Some(i) => target[i + 3..end].find('/').map_or(end, |p| i + 3 + p),
        None => 0,
    };
    start..end
}

/// Whether a path segment looks like a generated value rather than part of the route:
/// a number, a UUID or a long hex ID.
fn is_id_segment(seg: &str) -> bool {
    let hex_run = |s: &str, len: usize| s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit());
    let uuid = seg.len() == 36 && {
        let groups: Vec<&str> = seg.split('-').collect();
        groups.len() == 5 && groups.iter().zip([8, 4, 4, 4, 12]).all(|(g, len)| hex_run(g, len))
    };
    let number = !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit());
    number || uuid || (seg.len() >= 16 && hex_run(seg, seg.len()))
}

/// Whether a request target names a static asset, by the extension of its last segment.
/// Documents and archives don't count: `/files/report.pdf` is often a parameter.
fn is_asset(target: &str) -> bool {
    let path = &target[path_range(target)];
    let file = path.rsplit('/').next().unwrap_or("");
    file.rsplit_once('.').is_some_and(|(_, ext)| ASSET_EXT.iter().any(|a| ext.eq_ignore_ascii_case(a)))
}

/// The route of a request target's path: IDs and an asset's file name are replaced,
/// so `/users/1` and `/users/2` are one route, and so are `/js/a.js` and `/js/b.js`.
pub fn route(target: &str) -> String {
    let path = &target[path_range(target)];
    let mut segments: Vec<&str> = path.split('/').map(|seg| if is_id_segment(seg) { "{id}" } else { seg }).collect();
    if let Some(file) = segments.last_mut().filter(|_| is_asset(target)) {
        *file = "{asset}";
    }
    segments.join("/")
}

/// The route up to a fixed URL path segment, for attacking it once per origin and method; None for
/// other points. `/api` under `/api/users` is the same place as under `/api/orders`, while
/// an ID isn't fixed: its one target per route (see `route`) already limits it.
pub(crate) fn fixed_segment(raw: &[u8], point: &InsertionPoint) -> Option<String> {
    let Loc::Segment(i) = point.loc else { return None };
    let head = String::from_utf8_lossy(split_head_body(raw).0).into_owned();
    let (_, target, _) = split_target(&head);
    let path = &target[path_range(target)];
    let seg = path.split('/').nth(i)?;
    if is_id_segment(seg) {
        return None;
    }
    let prefix = path.split('/').take(i + 1).collect::<Vec<_>>().join("/");
    Some(route(&prefix))
}

/// All insertion points of a raw request.
pub fn points(raw: &[u8], opts: &PointOptions) -> Vec<InsertionPoint> {
    let mut out = Vec::new();
    let (head, body) = split_head_body(raw);
    let head = String::from_utf8_lossy(head);
    let (_, target, _) = split_target(&head);
    if opts.query {
        if let Some((_, q)) = target.split_once('?') {
            for (i, (k, v)) in pairs(q).into_iter().enumerate() {
                if !k.is_empty() {
                    out.push(InsertionPoint {
                        kind: PointKind::Query,
                        name: url_decode(k),
                        value: url_decode(v),
                        loc: Loc::Pair(i),
                    });
                }
            }
        }
    }
    if opts.path {
        let path = &target[path_range(target)];
        if path.starts_with('/') {
            for (i, seg) in path.split('/').enumerate().filter(|(_, seg)| !seg.is_empty()) {
                out.push(InsertionPoint {
                    kind: PointKind::Path,
                    name: format!("path[{}]", i - 1),
                    value: percent_decode_str(seg).decode_utf8_lossy().into_owned(),
                    loc: Loc::Segment(i),
                });
            }
        }
    }
    let ct = content_type(raw);
    if opts.form && ct.contains("application/x-www-form-urlencoded") {
        let b = String::from_utf8_lossy(body);
        for (i, (k, v)) in pairs(&b).into_iter().enumerate() {
            if !k.is_empty() {
                out.push(InsertionPoint {
                    kind: PointKind::Form,
                    name: url_decode(k),
                    value: url_decode(v),
                    loc: Loc::Pair(i),
                });
            }
        }
    }
    if opts.json && ct.contains("json") {
        if let Ok(v) = serde_json::from_slice::<Value>(body) {
            json_leaves(&v, &mut Vec::new(), &mut out);
        }
    }
    if opts.multipart {
        let body_start = raw.len() - body.len();
        let range = |r: &Range<usize>| r.start - body_start..r.end - body_start;
        for part in multipart_parts(raw) {
            let text = |r: &Range<usize>| String::from_utf8_lossy(&raw[r.clone()]).into_owned();
            match &part.filename {
                Some(file) => out.push(InsertionPoint {
                    kind: PointKind::Multipart,
                    name: format!("{}.filename", part.name),
                    value: if raw[..file.start].ends_with(b"\"") { unquote(&text(file)) } else { text(file) },
                    loc: Loc::FileName(range(file)),
                }),
                None => out.push(InsertionPoint {
                    kind: PointKind::Multipart,
                    value: text(&part.value),
                    loc: Loc::Body(range(&part.value)),
                    name: part.name,
                }),
            }
        }
    }
    if opts.xml && ct.contains("xml") {
        for (name, value, range) in xml_values(body).unwrap_or_default() {
            out.push(InsertionPoint { kind: PointKind::Xml, name, value, loc: Loc::Body(range) });
        }
    }
    let req = RawRequest::from_bytes(raw.to_vec());
    if let Ok(h) = req.head() {
        if opts.cookies {
            let mut idx = 0;
            for (_, v) in h.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
                for c in v.split(';') {
                    let (k, val) = c.split_once('=').unwrap_or((c, ""));
                    if !k.trim().is_empty() {
                        out.push(InsertionPoint {
                            kind: PointKind::Cookie,
                            name: k.trim().to_string(),
                            value: val.trim().to_string(),
                            loc: Loc::Cookie(idx),
                        });
                    }
                    idx += 1;
                }
            }
        }
        for name in &opts.headers {
            let value = h
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            out.push(InsertionPoint {
                kind: PointKind::Header,
                name: name.clone(),
                value,
                loc: Loc::Header(name.clone()),
            });
        }
    }
    out
}

fn json_leaves(v: &Value, path: &mut Vec<JsonKey>, out: &mut Vec<InsertionPoint>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                path.push(JsonKey::Field(k.clone()));
                json_leaves(child, path, out);
                path.pop();
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                path.push(JsonKey::Index(i));
                json_leaves(child, path, out);
                path.pop();
            }
        }
        leaf => {
            let value = match leaf {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            out.push(InsertionPoint {
                kind: PointKind::Json,
                name: json_path(path),
                value,
                loc: Loc::Json(path.clone()),
            });
        }
    }
}

fn json_path(path: &[JsonKey]) -> String {
    let mut s = String::new();
    for k in path {
        match k {
            JsonKey::Field(f) => {
                if !s.is_empty() {
                    s.push('.');
                }
                s.push_str(f);
            }
            JsonKey::Index(i) => s.push_str(&format!("[{i}]")),
        }
    }
    s
}

/// A part of a multipart/form-data body, with byte ranges in the whole request.
pub(crate) struct MultipartPart {
    pub name: String,
    pub filename: Option<Range<usize>>,
    pub value: Range<usize>,
    /// The whole part, from its delimiter up to the next one.
    pub span: Range<usize>,
}

/// The named parts of a multipart/form-data request.
pub(crate) fn multipart_parts(raw: &[u8]) -> Vec<MultipartPart> {
    let boundary = RawRequest::from_bytes(raw.to_vec()).head().ok().and_then(|h| {
        let ct = h.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type"))?.1.clone();
        if !ct.to_ascii_lowercase().starts_with("multipart/form-data") {
            return None;
        }
        ct.split(';').find_map(|p| p.trim().strip_prefix("boundary=").map(|b| b.trim_matches('"').to_string()))
    });
    let Some(boundary) = boundary.filter(|b| !b.is_empty()) else { return vec![] };
    let body_start = split_head_body(raw).0.len();
    let delim = format!("--{boundary}").into_bytes();
    // Where each delimiter starts, in `raw`.
    let mut marks = Vec::new();
    let mut at = body_start;
    while let Some(i) = find(&raw[at..], &delim) {
        let mark = at + i;
        at = mark + delim.len();
        // A delimiter is a whole line: anything else is field data that looks like one.
        let closing = raw[at..].starts_with(b"--");
        let rest = &raw[at + if closing { 2 } else { 0 }..];
        let padding = rest.iter().take_while(|b| matches!(b, b' ' | b'\t')).count();
        let line_end = rest[padding..].starts_with(b"\r\n") || (closing && rest.len() == padding);
        if line_end && (mark == body_start || raw[..mark].ends_with(b"\r\n")) {
            marks.push(mark);
            // What follows the closing delimiter is not part of the form.
            if closing {
                break;
            }
        }
    }
    let mut out = Vec::new();
    for pair in marks.windows(2) {
        let (start, end) = (pair[0] + delim.len(), pair[1]);
        let part = &raw[start..end];
        let Some(h) = find(part, b"\r\n\r\n") else { continue };
        let mut line_start = start;
        let disposition = part[..h].split(|&b| b == b'\n').find_map(|line| {
            let at = line_start;
            line_start += line.len() + 1;
            let lower = line.to_ascii_lowercase();
            lower.starts_with(b"content-disposition").then_some((at, line))
        });
        let Some((at, line)) = disposition else { continue };
        let params = disposition_params(line);
        let param = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, r)| r.start + at..r.end + at);
        let Some(name) = param("name") else { continue };
        // The value runs to the CRLF before the next delimiter.
        let value_end = if part.ends_with(b"\r\n") { end - 2 } else { end };
        out.push(MultipartPart {
            name: String::from_utf8_lossy(&raw[name]).into_owned(),
            filename: param("filename"),
            value: start + h + 4..value_end.max(start + h + 4),
            span: pair[0]..end,
        });
    }
    out
}

/// The parameters of a Content-Disposition line: lower-case name and the byte range
/// of the value in `line`, without its quotes.
fn disposition_params(line: &[u8]) -> Vec<(String, Range<usize>)> {
    let mut out = Vec::new();
    let mut i = line.iter().position(|&b| b == b';').unwrap_or(line.len());
    while i < line.len() {
        i += 1;
        let key_start = i;
        while i < line.len() && line[i] != b'=' && line[i] != b';' {
            i += 1;
        }
        if line.get(i) != Some(&b'=') {
            continue;
        }
        let key = String::from_utf8_lossy(&line[key_start..i]).trim().to_ascii_lowercase();
        i += 1;
        while matches!(line.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        let range = if line.get(i) == Some(&b'"') {
            let start = i + 1;
            i = start;
            while i < line.len() && line[i] != b'"' {
                i += if line[i] == b'\\' { 2 } else { 1 };
            }
            i = i.min(line.len());
            start..i
        } else {
            let start = i;
            while i < line.len() && line[i] != b';' && line[i] != b'\r' {
                i += 1;
            }
            let len = line[start..i].iter().rposition(|b| !matches!(b, b' ' | b'\t')).map_or(0, |p| p + 1);
            start..start + len
        };
        out.push((key, range));
        while i < line.len() && line[i] != b';' {
            i += 1;
        }
    }
    out
}

/// The values of an XML document: leaf element text and attributes (namespace
/// declarations aside), each with its dotted name, decoded value and byte range.
/// `None` for anything malformed, so that other text sent as XML yields no points.
fn xml_values(body: &[u8]) -> Option<Vec<(String, String, Range<usize>)>> {
    let s = std::str::from_utf8(body).ok()?;
    if !s.strip_prefix('\u{feff}').unwrap_or(s).trim_start().starts_with('<') {
        return None;
    }
    let mut out: Vec<(String, String, Range<usize>)> = Vec::new();
    let mut stack: Vec<&str> = Vec::new();
    let mut seen_root = false;
    let mut i = 0;
    while let Some(off) = s[i..].find('<') {
        let at = i + off;
        let rest = &s[at..];
        let skip_to = [("<?", "?>"), ("<!--", "-->"), ("<![CDATA[", "]]>")]
            .into_iter()
            .find_map(|(open, close)| rest.starts_with(open).then_some(close));
        if let Some(close) = skip_to {
            i = at + rest.find(close)? + close.len();
        } else if rest.starts_with("<!") {
            i = at + doctype_len(rest)?;
        } else if let Some(end_tag) = rest.strip_prefix("</") {
            let gt = end_tag.find('>')?;
            if stack.pop() != Some(end_tag[..gt].trim_end()) {
                return None;
            }
            i = at + 2 + gt + 1;
        } else {
            if stack.is_empty() && seen_root {
                return None;
            }
            seen_root = true;
            let name_end = rest[1..].find(|c: char| c.is_whitespace() || c == '/' || c == '>')? + 1;
            if name_end == 1 {
                return None;
            }
            stack.push(&rest[1..name_end]);
            let mut j = at + name_end;
            let self_closing = loop {
                j += s[j..].find(|c: char| !c.is_whitespace())?;
                if s[j..].starts_with("/>") {
                    j += 2;
                    break true;
                }
                if s[j..].starts_with('>') {
                    j += 1;
                    break false;
                }
                let eq = j + s[j..].find('=')?;
                let attr = s[j..eq].trim_end();
                let quote_at = eq + 1 + s[eq + 1..].find(|c: char| !c.is_whitespace())?;
                let quote = s[quote_at..].chars().next().filter(|c| matches!(c, '"' | '\''))?;
                let value_at = quote_at + 1;
                let value_end = value_at + s[value_at..].find(quote)?;
                if attr != "xmlns" && !attr.starts_with("xmlns:") {
                    let name = format!("{}.@{attr}", stack.join("."));
                    out.push((name, decode_entities(&s[value_at..value_end]), value_at..value_end));
                }
                j = value_end + 1;
            };
            if self_closing {
                stack.pop();
            } else if let Some((value, range)) = xml_leaf_text(s, j) {
                out.push((stack.join("."), value, range));
            }
            i = j;
        }
    }
    if !seen_root || !stack.is_empty() {
        return None;
    }
    // Repeated names are told apart by position, as JSON array items are.
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (name, _, _) in &mut out {
        let n = seen.entry(name.clone()).or_default();
        if *n > 0 {
            name.push_str(&format!("[{n}]"));
        }
        *n += 1;
    }
    Some(out)
}

/// The length of the DOCTYPE at the start of `s`, internal subset included.
fn doctype_len(s: &str) -> Option<usize> {
    let mut in_subset = false;
    for (i, c) in s.char_indices() {
        match c {
            '[' => in_subset = true,
            ']' => in_subset = false,
            '>' if !in_subset => return Some(i + 1),
            _ => {}
        }
    }
    None
}

/// The text of the element whose content starts at `start`, when that is all it
/// holds: plain text or one CDATA section (whose markers are part of the range).
fn xml_leaf_text(s: &str, start: usize) -> Option<(String, Range<usize>)> {
    let lt = start + s[start..].find('<')?;
    if s[lt..].starts_with("</") {
        return Some((decode_entities(&s[start..lt]), start..lt));
    }
    let inner = s[lt..].strip_prefix("<![CDATA[").filter(|_| s[start..lt].trim().is_empty())?;
    let close = inner.find("]]>")?;
    let end = lt + "<![CDATA[".len() + close + "]]>".len();
    s[end..].starts_with("</").then(|| (inner[..close].to_string(), lt..end))
}

fn xml_encode(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// Keeps a value inside one multipart file name: quotes and line ends the way browsers
/// escape them, and quotes added when the original had none, for `;` and spaces.
fn filename_encode(s: &str, quoted: bool) -> String {
    let s = s.replace('\\', "\\\\").replace('"', "%22").replace('\r', "%0D").replace('\n', "%0A");
    if quoted {
        s
    } else {
        format!("\"{s}\"")
    }
}

/// A quoted-string's content with its `\\x` pairs resolved.
fn unquote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        out.push(if c == '\\' { chars.next().unwrap_or(c) } else { c });
    }
    out
}

/// The request without the multipart part holding `point`.
pub(crate) fn remove_multipart_part(raw: &[u8], point: &InsertionPoint) -> Vec<u8> {
    let (Loc::Body(range) | Loc::FileName(range)) = &point.loc else { return raw.to_vec() };
    let at = split_head_body(raw).0.len() + range.start;
    let Some(part) = multipart_parts(raw).into_iter().find(|p| p.span.contains(&at)) else { return raw.to_vec() };
    let mut out = raw.to_vec();
    out.drain(part.span);
    RawRequest::from_bytes(out).update_content_length().into_bytes()
}

/// Form/query encoding (ZAP uses URLEncoder: space as '+').
pub fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// The request with `point` set to `value`. With `encode`, the value is escaped
/// for its context (URL-encoded in query/form/path, JSON-escaped in JSON, entities
/// in XML, `;`/`,`/space escaped in cookies, quotes and line ends in a multipart file
/// name; a multipart field takes any bytes); without it, it is inserted as-is (JSON
/// still gets a valid string). Content-Length is updated.
pub fn inject(raw: &[u8], point: &InsertionPoint, value: &str, encode: bool) -> Vec<u8> {
    let (raw_head, body) = split_head_body(raw);
    let head = String::from_utf8_lossy(raw_head).into_owned();
    let out = match (&point.kind, &point.loc) {
        (PointKind::Query, Loc::Pair(i)) => {
            let (method, target, version) = split_target(&head);
            let Some((path, q)) = target.split_once('?') else { return raw.to_vec() };
            let new_q = replace_pair(q, *i, &if encode { form_encode(value) } else { value.to_string() });
            let line_end = find(raw, b"\r\n").unwrap_or(raw.len());
            let mut out = format!("{method} {path}?{new_q} {version}").into_bytes();
            out.extend_from_slice(&raw[line_end..]);
            out
        }
        (PointKind::Form, Loc::Pair(i)) => {
            let b = String::from_utf8_lossy(body);
            let new_b = replace_pair(&b, *i, &if encode { form_encode(value) } else { value.to_string() });
            [head.as_bytes(), new_b.as_bytes()].concat()
        }
        (PointKind::Json, Loc::Json(path)) => {
            let Ok(mut v) = serde_json::from_slice::<Value>(body) else { return raw.to_vec() };
            if let Some(slot) = json_slot(&mut v, path) {
                *slot = Value::String(value.to_string());
            }
            [head.as_bytes(), serde_json::to_string(&v).unwrap_or_default().as_bytes()].concat()
        }
        (PointKind::Cookie, Loc::Cookie(idx)) => {
            let encoded = if encode { cookie_encode(value) } else { value.to_string() };
            let mut n = 0;
            let lines: Vec<String> = head
                .trim_end_matches("\r\n")
                .split("\r\n")
                .map(|line| {
                    let Some((k, v)) = line.split_once(':') else { return line.to_string() };
                    if !k.trim().eq_ignore_ascii_case("cookie") {
                        return line.to_string();
                    }
                    let parts: Vec<String> = v
                        .split(';')
                        .map(|c| {
                            let this = n;
                            n += 1;
                            if this == *idx {
                                let name = c.split_once('=').map(|(k, _)| k).unwrap_or(c).trim();
                                format!("{name}={encoded}")
                            } else {
                                c.trim().to_string()
                            }
                        })
                        .collect();
                    format!("{k}: {}", parts.join("; "))
                })
                .collect();
            [lines.join("\r\n").as_bytes(), b"\r\n\r\n", body].concat()
        }
        (PointKind::Header, Loc::Header(name)) => {
            return RawRequest::from_bytes(raw.to_vec()).set_header(name, value).into_bytes();
        }
        (PointKind::Path, Loc::Segment(i)) => {
            let (method, target, version) = split_target(&head);
            let range = path_range(target);
            let encoded = if encode { utf8_percent_encode(value, PATH_SEGMENT).to_string() } else { value.to_string() };
            let path = target[range.clone()]
                .split('/')
                .enumerate()
                .map(|(n, seg)| if n == *i { encoded.as_str() } else { seg })
                .collect::<Vec<_>>()
                .join("/");
            let line_end = find(raw, b"\r\n").unwrap_or(raw.len());
            let mut out =
                format!("{method} {}{path}{} {version}", &target[..range.start], &target[range.end..]).into_bytes();
            out.extend_from_slice(&raw[line_end..]);
            out
        }
        (kind, Loc::Body(range) | Loc::FileName(range)) if body.get(range.clone()).is_some() => {
            let escaped = match (&point.loc, kind) {
                _ if !encode => value.to_string(),
                (Loc::FileName(_), _) => filename_encode(value, body[..range.start].ends_with(b"\"")),
                (_, PointKind::Xml) => xml_encode(value),
                _ => value.to_string(),
            };
            [raw_head, &body[..range.start], escaped.as_bytes(), &body[range.end..]].concat()
        }
        _ => raw.to_vec(),
    };
    RawRequest::from_bytes(out).update_content_length().into_bytes()
}

fn replace_pair(s: &str, index: usize, raw_value: &str) -> String {
    s.split('&')
        .enumerate()
        .map(|(i, p)| {
            if i == index {
                let name = p.split_once('=').map(|(k, _)| k).unwrap_or(p);
                format!("{name}={raw_value}")
            } else {
                p.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn json_slot<'a>(v: &'a mut Value, path: &[JsonKey]) -> Option<&'a mut Value> {
    let mut cur = v;
    for k in path {
        cur = match k {
            JsonKey::Field(f) => cur.get_mut(f.as_str())?,
            JsonKey::Index(i) => cur.get_mut(*i)?,
        };
    }
    Some(cur)
}

fn cookie_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ';' | ',' | ' ' | '"' | '\\' | '%' | '\r' | '\n' => out.push_str(&format!("%{:02X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(b: Vec<u8>) -> String {
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn query_and_form() {
        let raw = b"POST /p?a=1&b=x%20y HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nc=3&d=4";
        let pts = points(raw, &PointOptions::default());
        let names: Vec<(&PointKind, &str, &str)> =
            pts.iter().map(|p| (&p.kind, p.name.as_str(), p.value.as_str())).collect();
        assert_eq!(
            names,
            [
                (&PointKind::Query, "a", "1"),
                (&PointKind::Query, "b", "x y"),
                (&PointKind::Form, "c", "3"),
                (&PointKind::Form, "d", "4")
            ]
        );
        let out = s(inject(raw, &pts[1], "<x y>&", true));
        assert!(out.starts_with("POST /p?a=1&b=%3Cx+y%3E%26 HTTP/1.1\r\n"), "{out}");
        let out = s(inject(raw, &pts[3], "4' OR '1", true));
        assert!(out.ends_with("\r\n\r\nc=3&d=4%27+OR+%271"), "{out}");
        assert!(out.contains("Content-Length: 18\r\n"), "{out}");
        let out = s(inject(raw, &pts[0], "a b", false));
        assert!(out.starts_with("POST /p?a=a b&b=x%20y"), "{out}");
    }

    #[test]
    fn multipart_fields_and_file_names() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--b\r\nContent-Disposition: form-data; name=\"up\"; filename=\"x;y.png\"\r\nContent-Type: image/png\r\n\r\nDATA\r\n--b--\r\n";
        let raw = format!(
            "POST /u HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let pts = points(&raw, &PointOptions::default());
        let names: Vec<(&str, &str)> = pts.iter().map(|p| (p.name.as_str(), p.value.as_str())).collect();
        assert_eq!(names, [("a", "one"), ("up.filename", "x;y.png")]);
        let out = s(inject(&raw, &pts[0], "<two>", true));
        assert!(out.contains("name=\"a\"\r\n\r\n<two>\r\n--b"), "{out}");
        assert!(out.contains(&format!("Content-Length: {}\r\n", body.len() + 2)), "{out}");
        let out = s(inject(&raw, &pts[1], "../\"e", true));
        assert!(out.contains("filename=\"../%22e\"\r\n") && out.contains("\r\n\r\nDATA\r\n"), "{out}");
        // Binary file content survives an injection in another part.
        let mut bin = raw.clone();
        let at = find(&bin, b"DATA").unwrap();
        bin[at] = 0xff;
        let pts = points(&bin, &PointOptions::default());
        assert!(find(&inject(&bin, &pts[0], "z", true), &[0xff, b'A', b'T', b'A']).is_some());
        let off = PointOptions { multipart: false, ..Default::default() };
        assert!(points(&raw, &off).is_empty());
    }

    fn multipart(body: &str) -> Vec<u8> {
        format!(
            "POST /u HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn multipart_delimiters_are_whole_lines() {
        let raw =
            multipart("--b\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\nbefore--bafter\r\n--bx\r\n--b--\r\n");
        let pts = points(&raw, &PointOptions::default());
        assert_eq!(pts.iter().map(|p| p.value.as_str()).collect::<Vec<_>>(), ["before--bafter\r\n--bx"]);
        assert!(s(inject(&raw, &pts[0], "P", true)).ends_with("\r\n\r\nP\r\n--b--\r\n"));
    }

    #[test]
    fn multipart_stops_at_the_closing_delimiter() {
        let part = "--b\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\n";
        let raw = multipart(&format!("{part}x\r\n--b--suffix\r\ny\r\n--b--"));
        let pts = points(&raw, &PointOptions::default());
        assert_eq!(pts.iter().map(|p| p.value.as_str()).collect::<Vec<_>>(), ["x\r\n--b--suffix\r\ny"]);
        let ghost = part.replace("\"n\"", "\"ghost\"");
        let raw = multipart(&format!("{part}x\r\n--b--\r\n{ghost}y\r\n--b--\r\n"));
        let pts = points(&raw, &PointOptions::default());
        assert_eq!(pts.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["n"]);
    }

    #[test]
    fn multipart_file_name_value_is_decoded() {
        let raw = multipart(
            "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a\\\\b.txt\"\r\n\r\nd\r\n--b--\r\n",
        );
        let pts = points(&raw, &PointOptions::default());
        assert_eq!(pts[0].value, "a\\b.txt");
        assert_eq!(inject(&raw, &pts[0], &pts[0].value, true), raw, "re-sending the value changes nothing");
    }

    #[test]
    fn multipart_unquoted_parameters() {
        let raw = multipart("--b\r\nContent-Disposition: form-data; name=\tcsrf ;filename=x \r\n\r\nd\r\n--b--\r\n");
        let pts = points(&raw, &PointOptions::default());
        assert_eq!(pts[0].name, "csrf.filename");
        assert_eq!(pts[0].value, "x");
        // A value with a `;` stays one file name.
        let out = s(inject(&raw, &pts[0], "a;b", true));
        assert!(out.contains("filename=\"a;b\" \r\n"), "{out}");
    }

    #[test]
    fn multipart_file_name_keeps_its_closing_quote() {
        let raw = multipart("--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\nd\r\n--b--\r\n");
        let pts = points(&raw, &PointOptions::default());
        let out = s(inject(&raw, &pts[0], "a\\", true));
        assert!(out.contains(r#"filename="a\\""#), "{out}");
    }

    #[test]
    fn removes_a_whole_multipart_part() {
        let raw = multipart("--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n\r\n--b\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\n2\r\n--b--\r\n");
        let pts = points(&raw, &PointOptions::default());
        let out = remove_multipart_part(&raw, &pts[0]);
        let left = points(&out, &PointOptions::default());
        assert_eq!(left.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["c"]);
        let body = "--b\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\n2\r\n--b--\r\n";
        assert!(s(out).contains(&format!("Content-Length: {}\r\n", body.len())));
    }

    #[test]
    fn body_injection_keeps_header_bytes() {
        let raw = b"POST /x HTTP/1.1\r\nHost: h\r\nX-Token: \xff\r\nContent-Type: text/xml\r\nContent-Length: 8\r\n\r\n<a>1</a>";
        let pts = points(raw, &PointOptions::default());
        assert!(find(&inject(raw, &pts[0], "2", true), b"X-Token: \xff\r\n").is_some());
    }

    #[test]
    fn session_names() {
        let raw = multipart("--b\r\nContent-Disposition: form-data; name=\"csrf.token\"\r\n\r\n1\r\n--b--\r\n");
        assert_eq!(points(&raw, &PointOptions::default())[0].session_name(), "csrf.token");
        let json = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"u\":{\"id\":1}}";
        assert_eq!(points(json, &PointOptions::default())[0].session_name(), "id");
    }

    #[test]
    fn xml_values_and_attributes() {
        let body = r#"<?xml version="1.0"?><!DOCTYPE o [<!ENTITY e "x">]><o xmlns:m="urn:m" id='7'><!-- c --><m:n>a &amp; b</m:n><i>1</i><i>2</i><c><![CDATA[<raw>]]></c><e/><mixed>t<b/></mixed></o>"#;
        let raw = format!(
            "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let pts = points(&raw, &PointOptions::default());
        let names: Vec<(&str, &str)> = pts.iter().map(|p| (p.name.as_str(), p.value.as_str())).collect();
        assert_eq!(names, [("o.@id", "7"), ("o.m:n", "a & b"), ("o.i", "1"), ("o.i[1]", "2"), ("o.c", "<raw>")]);
        let out = s(inject(&raw, &pts[1], "<'x'>", true));
        assert!(out.contains("<m:n>&lt;&apos;x&apos;&gt;</m:n>"), "{out}");
        let out = s(inject(&raw, &pts[0], "\"", true));
        assert!(out.contains("id='&quot;'"), "{out}");
        let out = s(inject(&raw, &pts[3], "<!ENTITY>", false));
        assert!(out.contains("<i>1</i><i><!ENTITY></i>"), "{out}");
        let out = s(inject(&raw, &pts[4], "<q>", true));
        assert!(out.contains("<c>&lt;q&gt;</c>"), "{out}");
    }

    #[test]
    fn xml_after_a_byte_order_mark() {
        let raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/xml\r\n\r\n\u{feff}<note>hi</note>";
        let pts = points(raw.as_bytes(), &PointOptions::default());
        assert_eq!(pts[0].value, "hi");
        assert!(s(inject(raw.as_bytes(), &pts[0], "z", true)).ends_with("\u{feff}<note>z</note>"));
    }

    #[test]
    fn malformed_xml_has_no_points() {
        for body in ["not xml", "<a><b></a></b>", "<a>", "<a b=c></a>", "<a/><b/>", "<a><![CDATA[x</a>", ""] {
            let raw = format!("POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: text/xml\r\n\r\n{body}").into_bytes();
            assert!(points(&raw, &PointOptions::default()).is_empty(), "{body}");
        }
    }

    #[test]
    fn url_path_segments() {
        let opts = PointOptions { path: true, ..Default::default() };
        let raw = b"GET /api/users%20x/42?a=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(points(raw, &PointOptions::default()).iter().all(|p| p.kind != PointKind::Path), "opt-in");
        let pts: Vec<_> = points(raw, &opts).into_iter().filter(|p| p.kind == PointKind::Path).collect();
        let names: Vec<(&str, &str)> = pts.iter().map(|p| (p.name.as_str(), p.value.as_str())).collect();
        assert_eq!(names, [("path[0]", "api"), ("path[1]", "users x"), ("path[2]", "42")]);
        let out = s(inject(raw, &pts[2], "1 /'", true));
        assert!(out.starts_with("GET /api/users%20x/1%20%2F%27?a=1 HTTP/1.1\r\n"), "{out}");
        let out = s(inject(raw, &pts[0], "../x", false));
        assert!(out.starts_with("GET /../x/users%20x/42?a=1 HTTP/1.1\r\n"), "{out}");
        // An absolute target keeps its origin, whose name is no segment.
        let abs = b"GET http://h.example/a/b HTTP/1.1\r\nHost: h.example\r\n\r\n";
        let pts = points(abs, &opts);
        assert_eq!(pts.iter().map(|p| p.value.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        assert!(s(inject(abs, &pts[1], "z", true)).starts_with("GET http://h.example/a/z HTTP/1.1\r\n"));
        // A URL in the query or the path is no origin.
        let q = b"GET /users/42?next=http://h.example/d HTTP/1.1\r\nHost: h\r\n\r\n";
        let pts: Vec<_> = points(q, &opts).into_iter().filter(|p| p.kind == PointKind::Path).collect();
        assert_eq!(pts.iter().map(|p| p.value.as_str()).collect::<Vec<_>>(), ["users", "42"]);
        assert!(s(inject(q, &pts[1], "z", true)).starts_with("GET /users/z?next=http://h.example/d "));
        let p = b"GET /go/http://h.example/d HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(points(p, &opts).len(), 4);
        assert!(points(b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n", &opts).is_empty());
    }

    #[test]
    fn id_segments() {
        for id in ["1", "007", "550e8400-e29b-41d4-a716-446655440000", "507f1f77bcf86cd799439011", "ABCDEF0123456789"] {
            assert!(is_id_segment(id), "{id}");
        }
        for seg in ["", "v1", "users", "abc123", "deadbeef", "550e8400-e29b-41d4-a716", "1.5", "42%27", "2fa"] {
            assert!(!is_id_segment(seg), "{seg}");
        }
    }

    #[test]
    fn routes() {
        assert_eq!(route("/users/42"), "/users/{id}");
        assert_eq!(route("/users/42/orders/550e8400-e29b-41d4-a716-446655440000/"), "/users/{id}/orders/{id}/");
        assert_eq!(route("/users/alice?x=1"), "/users/alice");
        assert_eq!(route("/api/v1/users"), "/api/v1/users");
        assert_eq!(route("http://h.example/users/42?u=http://x/1"), "/users/{id}");
        assert_eq!(route("/"), "/");
        assert_eq!(route("/assets/js/app.JS?v=3"), "/assets/js/{asset}");
        assert_eq!(route("/app.css"), "/{asset}");
        // A file served by the application can be a parameter.
        assert_eq!(route("/files/report.pdf"), "/files/report.pdf");
        assert_eq!(route("/js/app.js/edit"), "/js/app.js/edit");
    }

    #[test]
    fn fixed_segments() {
        let opts = PointOptions { path: true, ..Default::default() };
        let keys =
            |raw: &[u8]| -> Vec<Option<String>> { points(raw, &opts).iter().map(|p| fixed_segment(raw, p)).collect() };
        let some = |s: &str| Some(s.to_string());
        assert_eq!(
            keys(b"GET /api/users/42/profile?a=1 HTTP/1.1\r\nHost: h\r\n\r\n"),
            [None, some("/api"), some("/api/users"), None, some("/api/users/{id}/profile")]
        );
        assert_eq!(keys(b"GET http://h.example/a/b HTTP/1.1\r\nHost: h\r\n\r\n"), [some("/a"), some("/a/b")]);
        // Any file of a directory is the same place, attacked once.
        assert_eq!(keys(b"GET /js/app.js?v=3 HTTP/1.1\r\nHost: h\r\n\r\n"), [None, some("/js"), some("/js/{asset}")]);
        assert_eq!(
            keys(b"GET /files/report.pdf HTTP/1.1\r\nHost: h\r\n\r\n"),
            [some("/files"), some("/files/report.pdf")]
        );
        // A segment that looks the same under another parent is another place.
        assert_eq!(keys(b"GET /b/x HTTP/1.1\r\nHost: h\r\n\r\n"), [some("/b"), some("/b/x")]);
    }

    #[test]
    fn json_cookie_header() {
        let raw = b"POST /api HTTP/1.1\r\nHost: h\r\nCookie: s=1; t=2\r\nUser-Agent: x\r\nContent-Type: application/json\r\nContent-Length: 34\r\n\r\n{\"user\":{\"id\":5,\"tags\":[\"a\"]},\"z\":1}";
        let opts = PointOptions { cookies: true, headers: vec!["User-Agent".into()], ..Default::default() };
        let pts = points(raw, &opts);
        let names: Vec<&str> = pts.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["user.id", "user.tags[0]", "z", "s", "t", "User-Agent"]);
        let out = s(inject(raw, &pts[1], "\"q\"", true));
        assert!(out.ends_with(r#"{"user":{"id":5,"tags":["\"q\""]},"z":1}"#), "{out}");
        let out = s(inject(raw, &pts[4], "a;b", true));
        assert!(out.contains("Cookie: s=1; t=a%3Bb\r\n"), "{out}");
        let out = s(inject(raw, &pts[5], "evil", true));
        assert!(out.contains("User-Agent: evil\r\n"), "{out}");
    }
}
