//! Insertion points: the places in a request where a rule can put a value
//! (ZAP "variants"). Query and form parameters and JSON values are used by
//! default; cookies and selected headers are opt-in, like ZAP's defaults.

use serde::Serialize;
use serde_json::Value;

use crate::http::request::{find, split_head_body};
use crate::http::RawRequest;
use crate::scan::message::url_decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PointKind {
    Query,
    Form,
    Json,
    Cookie,
    Header,
}

#[derive(Debug, Clone, PartialEq)]
enum Loc {
    /// Index of the name=value pair in the query or form body.
    Pair(usize),
    Json(Vec<JsonKey>),
    Cookie(usize),
    Header(String),
}

#[derive(Debug, Clone, PartialEq)]
enum JsonKey {
    Field(String),
    Index(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub struct InsertionPoint {
    pub kind: PointKind,
    /// Parameter name (decoded); for JSON, a path like `user.tags[0]`.
    pub name: String,
    /// Original value (decoded).
    pub value: String,
    loc: Loc,
}

#[derive(Debug, Clone)]
pub struct PointOptions {
    pub query: bool,
    pub form: bool,
    pub json: bool,
    pub cookies: bool,
    /// Header names to inject into (e.g. User-Agent, Referer).
    pub headers: Vec<String>,
}

impl Default for PointOptions {
    fn default() -> Self {
        Self { query: true, form: true, json: true, cookies: false, headers: Vec::new() }
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

/// Form/query encoding (ZAP uses URLEncoder: space as '+').
pub fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// The request with `point` set to `value`. With `encode`, the value is escaped
/// for its context (URL-encoded in query/form, JSON-escaped in JSON, `;`/`,`/space
/// escaped in cookies); without it, it is inserted as-is (JSON still gets a valid
/// string). Content-Length is updated.
pub fn inject(raw: &[u8], point: &InsertionPoint, value: &str, encode: bool) -> Vec<u8> {
    let (head, body) = split_head_body(raw);
    let head = String::from_utf8_lossy(head).into_owned();
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
