//! Postman collections (v2.0 and v2.1) to requests.

use std::collections::HashMap;

use base64::Engine;
use serde_json::{json, Value};

use super::values::{self, Part, MULTIPART_BOUNDARY};
use super::{rebase, ApiRequest, Built};
use crate::error::{Error, Result};

#[derive(Debug, Default, Clone)]
pub struct Options {
    /// Replaces the scheme/host/port of every request; a path is put in front.
    pub base_url: Option<String>,
    /// Variable values; they override the collection's `variable` list.
    pub vars: Vec<(String, String)>,
}

/// Folders nested deeper than this are ignored.
const MAX_DEPTH: usize = 32;

pub fn build(doc: &Value, opts: &Options) -> Result<Built> {
    let items = doc
        .get("item")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::InvalidInput("not a Postman collection (v2.0/v2.1 with an \"item\" array)".into()))?;
    let mut vars: HashMap<String, String> = HashMap::new();
    for v in doc.get("variable").and_then(Value::as_array).into_iter().flatten() {
        if let Some(k) = v.get("key").or(v.get("id")).and_then(Value::as_str) {
            vars.insert(k.to_string(), v.get("value").map(values::scalar).unwrap_or_default());
        }
    }
    vars.extend(opts.vars.iter().cloned());
    let cx = Cx { vars, base: opts.base_url.clone() };
    let mut out = Built::default();
    walk(&cx, items, "", doc.get("auth"), 0, &mut out);
    Ok(out)
}

struct Cx {
    vars: HashMap<String, String>,
    base: Option<String>,
}

impl Cx {
    /// Substitutes `{{name}}`; unknown variables are left as they are.
    fn sub(&self, s: &str) -> String {
        let mut out = String::new();
        let mut rest = s;
        while let Some(i) = rest.find("{{") {
            out.push_str(&rest[..i]);
            let after = &rest[i + 2..];
            match after.find("}}") {
                Some(j) => {
                    let name = after[..j].trim();
                    match self.vars.get(name) {
                        Some(v) => out.push_str(v),
                        None => out.push_str(&rest[i..i + 2 + j + 2]),
                    }
                    rest = &after[j + 2..];
                }
                None => {
                    out.push_str(&rest[i..]);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        out
    }
}

fn walk(cx: &Cx, items: &[Value], prefix: &str, auth: Option<&Value>, depth: usize, out: &mut Built) {
    if depth > MAX_DEPTH {
        return;
    }
    for it in items {
        let name = it.get("name").and_then(Value::as_str).unwrap_or("");
        let path = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        let auth = it.get("auth").or(auth);
        if let Some(children) = it.get("item").and_then(Value::as_array) {
            walk(cx, children, &path, auth, depth + 1, out);
            continue;
        }
        let Some(req) = it.get("request") else { continue };
        match request(cx, &path, req, req.get("auth").or(auth)) {
            Ok(r) => out.requests.push(r),
            Err(e) => out.warn(format!("{path}: {e}")),
        }
    }
}

fn enabled(v: &Value) -> bool {
    v.get("disabled").and_then(Value::as_bool) != Some(true)
}

fn kv(cx: &Cx, v: &Value) -> Option<(String, String)> {
    let k = v.get("key")?.as_str()?;
    Some((cx.sub(k), cx.sub(&v.get("value").map(values::scalar).unwrap_or_default())))
}

fn request(cx: &Cx, name: &str, req: &Value, auth: Option<&Value>) -> Result<ApiRequest> {
    // A request may be just a URL string.
    let (method, url_v) = match req {
        Value::String(_) => ("GET".to_string(), req),
        _ => (
            req.get("method").and_then(Value::as_str).unwrap_or("GET").to_ascii_uppercase(),
            req.get("url").unwrap_or(&Value::Null),
        ),
    };
    let mut url = url_string(cx, url_v);
    let mut headers: Vec<(String, String)> = match req.get("header") {
        Some(Value::Array(hs)) => hs.iter().filter(|h| enabled(h)).filter_map(|h| kv(cx, h)).collect(),
        Some(Value::String(s)) => s.lines().filter_map(|l| header_line(&cx.sub(l))).collect(),
        _ => Vec::new(),
    };
    let has = |hs: &[(String, String)], n: &str| hs.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    let mut body = Vec::new();
    let mut content_type = None;
    if let Some(b) = req.get("body").filter(|b| enabled(b)) {
        match b.get("mode").and_then(Value::as_str) {
            Some("raw") => {
                body = cx.sub(b.get("raw").and_then(Value::as_str).unwrap_or("")).into_bytes();
                let lang = b.pointer("/options/raw/language").and_then(Value::as_str).unwrap_or("text");
                content_type = Some(match lang {
                    "json" => "application/json",
                    "xml" => "application/xml",
                    "html" => "text/html",
                    "javascript" => "application/javascript",
                    _ => "text/plain",
                });
            }
            Some("urlencoded") => {
                let fields: Vec<(String, String)> = b
                    .get("urlencoded")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|f| enabled(f))
                    .filter_map(|f| kv(cx, f))
                    .collect();
                body = values::form(&fields);
                content_type = Some("application/x-www-form-urlencoded");
            }
            Some("formdata") => {
                let parts: Vec<Part> = b
                    .get("formdata")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|f| enabled(f))
                    .filter_map(|f| {
                        let file = f.get("type").and_then(Value::as_str) == Some("file");
                        let (name, value) = kv(cx, f)?;
                        Some(if file {
                            Part { name, value: "test".into(), file: Some("test.txt".into()) }
                        } else {
                            Part { name, value, file: None }
                        })
                    })
                    .collect();
                body = values::multipart(&parts);
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
                headers.push(("Content-Type".into(), format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}")));
            }
            Some("graphql") => {
                let g = b.get("graphql").unwrap_or(&Value::Null);
                let query = cx.sub(g.get("query").and_then(Value::as_str).unwrap_or(""));
                let vars = g
                    .get("variables")
                    .and_then(Value::as_str)
                    .and_then(|v| serde_json::from_str::<Value>(&cx.sub(v)).ok())
                    .unwrap_or(json!({}));
                body = serde_json::to_vec(&json!({"query": query, "variables": vars})).unwrap_or_default();
                content_type = Some("application/json");
            }
            _ => {}
        }
    }
    if let Some(ct) = content_type.filter(|_| !has(&headers, "content-type")) {
        headers.push(("Content-Type".into(), ct.into()));
    }
    if let Some(a) = auth {
        apply_auth(cx, a, &mut headers, &mut url);
    }
    if !url.contains("://") {
        url = format!("http://{url}");
    }
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or("").to_string();
    let (host, path) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
    if host.contains("{{") {
        if cx.base.is_none() {
            return Err(Error::InvalidInput(format!(
                "unresolved variable in host of {url:?}; pass --var or --base-url"
            )));
        }
        // --base-url supplies the origin.
        url = format!("http://placeholder.invalid{path}");
    }
    if let Some(b) = &cx.base {
        url = rebase(&url, b)?;
    }
    url::Url::parse(&url).map_err(|e| Error::InvalidInput(format!("invalid URL {url:?}: {e}")))?;
    Ok(ApiRequest { name: name.to_string(), method, url, headers, body })
}

fn header_line(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once(':')?;
    let k = k.trim();
    (!k.is_empty()).then(|| (k.to_string(), v.trim().to_string()))
}

/// URL from a string or a v2 URL object; `:name` path variables are filled
/// from the object's `variable` list.
fn url_string(cx: &Cx, u: &Value) -> String {
    let obj = match u {
        Value::String(s) => return cx.sub(s),
        Value::Object(_) => u,
        _ => return String::new(),
    };
    let mut url = match obj.get("raw").and_then(Value::as_str) {
        Some(raw) => cx.sub(raw),
        None => {
            let join = |v: Option<&Value>, sep: &str| match v {
                Some(Value::Array(a)) => a.iter().map(values::scalar).collect::<Vec<_>>().join(sep),
                Some(v) => values::scalar(v),
                None => String::new(),
            };
            let mut s = String::new();
            if let Some(p) = obj.get("protocol").and_then(Value::as_str) {
                s.push_str(&format!("{p}://"));
            }
            s.push_str(&join(obj.get("host"), "."));
            if let Some(port) = obj.get("port") {
                s.push_str(&format!(":{}", values::scalar(port)));
            }
            let path = join(obj.get("path"), "/");
            if !path.is_empty() {
                s.push('/');
                s.push_str(path.trim_start_matches('/'));
            }
            let q: Vec<(String, String)> = obj
                .get("query")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|q| enabled(q))
                .filter_map(|q| kv(cx, q))
                .collect();
            if !q.is_empty() {
                s.push('?');
                s.push_str(&String::from_utf8_lossy(&values::form(&q)));
            }
            cx.sub(&s)
        }
    };
    for v in obj.get("variable").and_then(Value::as_array).into_iter().flatten() {
        if let Some((k, val)) = kv(cx, v) {
            let val = if val.is_empty() { "1".into() } else { val };
            url = replace_path_var(&url, &k, &val);
        }
    }
    url
}

fn replace_path_var(url: &str, name: &str, value: &str) -> String {
    let (head, query) = match url.find('?') {
        Some(i) => url.split_at(i),
        None => (url, ""),
    };
    let segs: Vec<String> =
        head.split('/').map(|s| if s == format!(":{name}") { value.to_string() } else { s.to_string() }).collect();
    format!("{}{query}", segs.join("/"))
}

/// Postman v2.1 stores auth parameters as [{key, value}], v2.0 as an object.
fn auth_param(cx: &Cx, a: &Value, kind: &str, key: &str) -> Option<String> {
    let section = a.get(kind)?;
    let v = match section {
        Value::Array(items) => {
            items.iter().find(|i| i.get("key").and_then(Value::as_str) == Some(key))?.get("value")?
        }
        Value::Object(_) => section.get(key)?,
        _ => return None,
    };
    Some(cx.sub(&values::scalar(v)))
}

fn apply_auth(cx: &Cx, a: &Value, headers: &mut Vec<(String, String)>, url: &mut String) {
    let has_auth = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("authorization"));
    let usable = |s: &String| !s.contains("{{");
    match a.get("type").and_then(Value::as_str) {
        Some("bearer") if !has_auth => {
            if let Some(t) = auth_param(cx, a, "bearer", "token").filter(usable) {
                headers.push(("Authorization".into(), format!("Bearer {t}")));
            }
        }
        Some("basic") if !has_auth => {
            let u = auth_param(cx, a, "basic", "username").unwrap_or_default();
            let p = auth_param(cx, a, "basic", "password").unwrap_or_default();
            if usable(&u) && usable(&p) {
                let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
                headers.push(("Authorization".into(), format!("Basic {token}")));
            }
        }
        Some("apikey") => {
            let key = auth_param(cx, a, "apikey", "key").unwrap_or_default();
            let value = auth_param(cx, a, "apikey", "value").unwrap_or_default();
            if key.is_empty() || !usable(&key) || !usable(&value) {
                return;
            }
            if auth_param(cx, a, "apikey", "in").as_deref() == Some("query") {
                let pair = String::from_utf8_lossy(&values::form(&[(key, value)])).to_string();
                url.push(if url.contains('?') { '&' } else { '?' });
                url.push_str(&pair);
            } else if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(&key)) {
                headers.push((key, value));
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header<'a>(r: &'a ApiRequest, name: &str) -> Option<&'a str> {
        r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    #[test]
    fn collection_requests() {
        let doc = json!({
            "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "variable": [{"key": "base", "value": "http://api.test:8080"}, {"key": "tok", "value": "T0K"}],
            "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{tok}}"}]},
            "item": [
                {"name": "Users", "item": [
                    {"name": "Get user", "request": {"method": "GET",
                        "header": [{"key": "X-A", "value": "1"}, {"key": "X-Off", "value": "2", "disabled": true}],
                        "url": {"raw": "{{base}}/users/:id?full=true", "variable": [{"key": "id", "value": "42"}]}}},
                    {"name": "Create", "request": {"method": "post", "url": "{{base}}/users",
                        "auth": {"type": "basic", "basic": [{"key": "username", "value": "u"}, {"key": "password", "value": "p"}]},
                        "body": {"mode": "raw", "raw": "{\"name\": \"{{who}}\"}", "options": {"raw": {"language": "json"}}}}},
                ]},
                {"name": "Login", "request": {"method": "POST",
                    "url": {"protocol": "https", "host": ["auth", "test"], "path": ["login"], "query": [{"key": "a", "value": "b c"}]},
                    "auth": {"type": "apikey", "apikey": [{"key": "key", "value": "api_key"}, {"key": "value", "value": "K"}, {"key": "in", "value": "query"}]},
                    "body": {"mode": "urlencoded", "urlencoded": [{"key": "user", "value": "admin"}, {"key": "x", "value": "y", "disabled": true}]}}},
                {"name": "Upload", "request": {"method": "PUT", "url": "{{base}}/files",
                    "body": {"mode": "formdata", "formdata": [{"key": "f", "type": "file", "src": "/etc/passwd"}, {"key": "t", "value": "v"}]}}},
                {"name": "Gql", "request": {"method": "POST", "url": "{{base}}/graphql",
                    "body": {"mode": "graphql", "graphql": {"query": "{ me { id } }", "variables": "{\"a\": 1}"}}}},
                {"name": "Unknown host", "request": "{{nohost}}/x"},
            ]
        });
        let b = build(&doc, &Options { vars: vec![("who".into(), "bob".into())], ..Default::default() }).unwrap();
        let r = &b.requests;
        assert_eq!(r.len(), 5, "{:?}", b.warnings);
        assert_eq!(r[0].name, "Users/Get user");
        assert_eq!(r[0].url, "http://api.test:8080/users/42?full=true");
        assert_eq!(header(&r[0], "X-A"), Some("1"));
        assert_eq!(header(&r[0], "X-Off"), None);
        assert_eq!(header(&r[0], "Authorization"), Some("Bearer T0K"));
        assert_eq!(r[1].method, "POST");
        assert_eq!(String::from_utf8_lossy(&r[1].body), "{\"name\": \"bob\"}");
        assert_eq!(header(&r[1], "Content-Type"), Some("application/json"));
        assert_eq!(header(&r[1], "Authorization"), Some("Basic dTpw"));
        assert_eq!(r[2].url, "https://auth.test/login?a=b+c&api_key=K");
        assert_eq!(String::from_utf8_lossy(&r[2].body), "user=admin");
        let up = String::from_utf8_lossy(&r[3].body).to_string();
        assert!(up.contains("filename=\"test.txt\"") && !up.contains("passwd"), "{up}");
        assert_eq!(String::from_utf8_lossy(&r[4].body), r#"{"query":"{ me { id } }","variables":{"a":1}}"#);
        assert!(b.warnings[0].starts_with("Unknown host:"), "{:?}", b.warnings);

        let o = Options { base_url: Some("http://127.0.0.1:3000".into()), ..Default::default() };
        let b = build(&doc, &o).unwrap();
        assert_eq!(b.requests[0].url, "http://127.0.0.1:3000/users/42?full=true");
        assert!(build(&json!({"openapi": "3.0.0"}), &Options::default()).is_err());
    }
}
