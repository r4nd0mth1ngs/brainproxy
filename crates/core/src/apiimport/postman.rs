//! Postman collections (v2.0 and v2.1) to requests.

use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use base64::Engine;
use regex::Regex;
use serde_json::{json, Value};

use super::values::{self, mentions, Part, MULTIPART_BOUNDARY};
use super::{looks_secret, merge_credential, rebase, shown_url, ApiRequest, Built, Credential};
use crate::auth::MARK;
use crate::error::{Error, Result};

#[derive(Debug, Default, Clone)]
pub struct Options {
    /// Replaces the scheme/host/port of every request; a path is put in front.
    pub base_url: Option<String>,
    /// Variable values; they override the collection's `variable` list.
    pub vars: Vec<(String, String)>,
    /// The `import api` rules: failures go in `skipped`, the collection's auth isn't
    /// applied, and `withheld` variables aren't substituted.
    pub guarded: bool,
    pub withheld: Vec<String>,
}

const HOST_VARIABLE: &str = "unresolved variable in host";

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
    for name in &opts.withheld {
        vars.remove(name);
    }
    let cx = Cx { vars, base: opts.base_url.clone(), guarded: opts.guarded };
    let mut out = Built::default();
    walk(&cx, items, "", doc.get("auth"), 0, &mut out);
    Ok(out)
}

struct Cx {
    vars: HashMap<String, String>,
    base: Option<String>,
    guarded: bool,
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
                    match self.vars.get(name).filter(|v| out.len() + v.len() <= super::MAX_DOCUMENT) {
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
        if cx.guarded {
            out.warn(format!("{prefix}: folders nested deeper than {MAX_DEPTH} levels were ignored"));
        }
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
        if cx.guarded && mentions(it, MARK) {
            out.skip(path, "contains a reserved placeholder".into());
            continue;
        }
        match request(cx, &path, req, req.get("auth").or(auth)) {
            Ok(r) => out.keep(cx.guarded, path, r),
            Err(e) => {
                out.base_url_required |= cx.guarded && e.to_string().contains(HOST_VARIABLE);
                out.fail(cx.guarded, path, &e)
            }
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
    if let Some(a) = auth.filter(|_| !cx.guarded) {
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
                "{HOST_VARIABLE} of {:?}; set the variable or a base URL",
                shown_url(&url)
            )));
        }
        // --base-url supplies the origin.
        url = format!("http://placeholder.invalid{path}");
    }
    if let Some(b) = &cx.base {
        url = rebase(&url, b)?;
    }
    url::Url::parse(&url).map_err(|e| Error::InvalidInput(format!("invalid URL {:?}: {e}", shown_url(&url))))?;
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

/// A collection variable, for the `import api` preview.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct Variable {
    pub name: String,
    /// None when secret.
    pub value: Option<String>,
    /// collection, cli (--var), or document (referenced, not declared).
    pub source: &'static str,
    pub secret: bool,
    pub used: bool,
}

/// What a collection holds besides requests.
#[derive(Debug, Default)]
pub struct Analysis {
    pub variables: Vec<Variable>,
    pub unresolved: Vec<String>,
    pub credentials: Vec<Credential>,
    pub warnings: Vec<String>,
    /// Variables a guarded build must not substitute.
    pub withheld: Vec<String>,
}

#[derive(Default)]
struct Refs {
    all: BTreeSet<String>,
    /// Referenced by auth or by a header or parameter with a secret name.
    secret: BTreeSet<String>,
    scripts: usize,
    file_bodies: usize,
}

fn refs_in(s: &str, into: &mut BTreeSet<String>) {
    let mut rest = s;
    while let Some((_, after)) = rest.split_once("{{") {
        let Some((name, tail)) = after.split_once("}}") else { break };
        if !name.trim().is_empty() {
            into.insert(name.trim().to_string());
        }
        rest = tail;
    }
}

/// The variables given to a secret name in text: a raw URL's `token={{t}}`, a raw body's `"password": "{{p}}"`.
fn secret_refs_in(s: &str, into: &mut BTreeSet<String>) {
    static PAIR: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"([A-Za-z0-9_.~-]+)["']?\s*[:=]\s*["']?([^"'&\s,}]*\{\{[^}]*\}\})"#).expect("valid regex")
    });
    if s.contains("{{") {
        PAIR.captures_iter(s).filter(|c| looks_secret(&c[1])).for_each(|c| refs_in(&c[2], into));
    }
}

/// The variables referenced by every string in `v`.
fn strings_in(v: &Value, into: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => refs_in(s, into),
        Value::Array(a) => a.iter().for_each(|x| strings_in(x, into)),
        Value::Object(m) => m.values().for_each(|x| strings_in(x, into)),
        _ => {}
    }
}

fn auth_credential(a: &Value, label: &str) -> Option<Credential> {
    let ty = a.get("type").and_then(Value::as_str)?;
    let header = |kind: &str| (kind.to_string(), Some("header".to_string()), Some("Authorization".to_string()));
    let param = |key: &str| {
        let section = a.get("apikey")?;
        match section {
            Value::Array(items) => {
                items.iter().find(|i| i.get("key").and_then(Value::as_str) == Some(key))?.get("value")?.as_str()
            }
            _ => section.get(key)?.as_str(),
        }
    };
    let (kind, location, name) = match ty {
        "noauth" => return None,
        "bearer" => header("bearer"),
        "basic" => header("basic"),
        "apikey" => {
            let at = if param("in") == Some("query") { "query" } else { "header" };
            ("api_key".to_string(), Some(at.to_string()), param("key").map(str::to_string))
        }
        "oauth2" => ("oauth2".to_string(), None, None),
        _ => ("other".to_string(), None, None),
    };
    let values: Vec<&str> = match a.get(ty) {
        Some(Value::Array(items)) => items.iter().filter_map(|i| i.get("value")?.as_str()).collect(),
        Some(Value::Object(m)) => m.values().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    let embedded = values.iter().any(|v| !v.is_empty() && !v.contains("{{"));
    Some(Credential { kind, location, name, source: format!("auth:{label}"), embedded })
}

fn scan(v: &Value, label: &str, refs: &mut Refs, credentials: &mut Vec<Credential>) {
    match v {
        Value::String(s) => {
            refs_in(s, &mut refs.all);
            secret_refs_in(s, &mut refs.secret);
        }
        Value::Array(a) => a.iter().for_each(|x| scan(x, label, refs, credentials)),
        Value::Object(m) => {
            let named = m.get("item").is_some() || m.get("request").is_some();
            let label = match m.get("name").and_then(Value::as_str).filter(|_| named) {
                Some(n) if label == "collection" => n.to_string(),
                Some(n) => format!("{label}/{n}"),
                None => label.to_string(),
            };
            // The collection's own name isn't part of an item's path.
            let label = if m.contains_key("info") { "collection" } else { label.as_str() };
            if m.get("key").and_then(Value::as_str).is_some_and(looks_secret) {
                m.values().for_each(|x| strings_in(x, &mut refs.secret));
            }
            for (k, x) in m {
                match k.as_str() {
                    "event" => {
                        let has_exec = |e: &Value| match e.pointer("/script/exec") {
                            Some(Value::Array(lines)) => {
                                lines.iter().any(|l| l.as_str().is_some_and(|l| !l.trim().is_empty()))
                            }
                            Some(Value::String(s)) => !s.trim().is_empty(),
                            _ => false,
                        };
                        refs.scripts += x.as_array().into_iter().flatten().filter(|e| has_exec(e)).count();
                    }
                    "auth" => {
                        strings_in(x, &mut refs.secret);
                        strings_in(x, &mut refs.all);
                        if let Some(c) = auth_credential(x, label) {
                            merge_credential(credentials, c);
                        }
                    }
                    "body" if x.get("mode").and_then(Value::as_str) == Some("file") => refs.file_bodies += 1,
                    _ => scan(x, label, refs, credentials),
                }
            }
        }
        _ => {}
    }
}

/// Reads a collection's variables, auth, and scripts for the `import api` rules, with
/// `vars` (from --var) on top of its `variable` list.
pub fn analyze(doc: &Value, vars: &[(String, String)]) -> Analysis {
    let mut out = Analysis::default();
    let mut refs = Refs::default();
    scan(doc, "collection", &mut refs, &mut out.credentials);
    // Name, value, source, marked secret by the collection.
    let mut declared: Vec<(String, String, &'static str, bool)> = Vec::new();
    for v in doc.get("variable").and_then(Value::as_array).into_iter().flatten() {
        if let Some(k) = v.get("key").or(v.get("id")).and_then(Value::as_str) {
            let value = v.get("value").map(values::scalar).unwrap_or_default();
            let marked = v.get("type").and_then(Value::as_str) == Some("secret");
            declared.push((k.to_string(), value, "collection", marked));
        }
    }
    for (k, v) in vars {
        let marked = declared.iter().any(|d| &d.0 == k && d.3);
        declared.retain(|d| &d.0 != k);
        declared.push((k.clone(), v.clone(), "cli", marked));
    }
    for (name, value, source, marked) in declared {
        let used = refs.all.contains(&name);
        let secret = marked || looks_secret(&name) || refs.secret.contains(&name);
        if secret {
            out.withheld.push(name.clone());
            if source == "cli" {
                out.warnings.push(format!(
                    "--var {name} looks like a credential and was not substituted; set it up with an auth profile"
                ));
            } else if !value.is_empty() {
                out.credentials.push(Credential {
                    kind: "other".into(),
                    location: None,
                    name: Some(name.clone()),
                    source: format!("variable:{name}"),
                    embedded: !value.contains("{{"),
                });
            }
        } else if value.is_empty() {
            out.withheld.push(name.clone());
            if used {
                out.unresolved.push(name.clone());
            }
        }
        // A URL with a password in it stays usable (the password is stripped later), but isn't shown.
        let hidden = secret || shown_url(&value) != value.split(['?', '#']).next().unwrap_or_default();
        out.variables.push(Variable { name, value: (!hidden).then_some(value), source, secret: hidden, used });
    }
    for name in &refs.all {
        if out.variables.iter().any(|v| &v.name == name) {
            continue;
        }
        if looks_secret(name) || refs.secret.contains(name) {
            out.withheld.push(name.clone());
            out.variables.push(Variable {
                name: name.clone(),
                value: None,
                source: "document",
                secret: true,
                used: true,
            });
        } else {
            out.unresolved.push(name.clone());
        }
    }
    out.unresolved.sort();
    if refs.scripts > 0 {
        out.warnings.push(format!("{} pre-request or test script(s) were not run", refs.scripts));
    }
    if refs.file_bodies > 0 {
        out.warnings.push(format!("{} file body/bodies can't be read and were sent empty", refs.file_bodies));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header<'a>(r: &'a ApiRequest, name: &str) -> Option<&'a str> {
        r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    #[test]
    fn analysis_keeps_secrets_out() {
        let doc = json!({
        "info": {"name": "c"},
        "variable": [
            {"key": "base", "value": "http://api.test"},
            {"key": "apiKey", "value": "LITERALKEY"},
            {"key": "k", "value": "USEDBYAUTH"},
            {"key": "hidden", "value": "MARKED", "type": "secret"},
            {"key": "blank", "value": ""},
            {"key": "withpw", "value": "http://u:PW@api.test"}],
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{k}}"}]},
        "event": [{"listen": "prerequest", "script": {"exec": ["pm.test()"]}}],
        "item": [
            {"name": "Folder", "item": [
                {"name": "One", "request": {"method": "GET", "url": "{{base}}/a/{{tenant}}?x={{blank}}",
                    "auth": {"type": "apikey", "apikey": [
                        {"key": "key", "value": "X-Key"}, {"key": "value", "value": "ITEMKEY"}, {"key": "in", "value": "header"}]},
                    "header": [{"key": "X-Token", "value": "{{viaheader}}"}],
                    "body": {"mode": "raw", "raw": "{\"a\": \"{{apiKey}}\"}"}}},
                {"name": "Two", "request": "{{nohost}}/x"}]},
            {"name": "Three", "request": {"method": "POST", "url": "{{base}}/f", "body": {"mode": "file", "file": {"src": "/etc/passwd"}}}}
        ]});
        let a = analyze(&doc, &[("password".into(), "CLISECRET".into()), ("region".into(), "eu".into())]);
        let text = format!("{a:?}");
        for secret in ["LITERALKEY", "USEDBYAUTH", "MARKED", "ITEMKEY", "CLISECRET", ":PW"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        let var = |n: &str| a.variables.iter().find(|v| v.name == n).unwrap();
        assert_eq!(var("base").value.as_deref(), Some("http://api.test"));
        assert_eq!(var("region").source, "cli");
        assert!(!var("region").used);
        for n in ["apiKey", "k", "hidden", "password", "withpw"] {
            assert!(var(n).secret && var(n).value.is_none(), "{n}");
        }
        assert!(var("viaheader").secret, "referenced by a secret header");
        assert_eq!(a.unresolved, ["blank", "nohost", "tenant"]);
        for n in ["apiKey", "k", "hidden", "password", "viaheader", "blank"] {
            assert!(a.withheld.iter().any(|w| w == n), "{n}");
        }
        assert!(!a.withheld.iter().any(|w| w == "withpw"));
        let c = |n: &str| a.credentials.iter().find(|c| c.name.as_deref() == Some(n)).unwrap();
        assert_eq!((c("Authorization").kind.as_str(), c("Authorization").embedded), ("bearer", false));
        assert_eq!(c("Authorization").source, "auth:collection");
        assert_eq!((c("X-Key").kind.as_str(), c("X-Key").embedded), ("api_key", true));
        assert_eq!(c("X-Key").source, "auth:Folder/One");
        assert_eq!(c("X-Key").location.as_deref(), Some("header"));
        assert!(a.warnings.iter().any(|w| w.starts_with("1 pre-request")), "{:?}", a.warnings);
        assert!(a.warnings.iter().any(|w| w.starts_with("1 file body")), "{:?}", a.warnings);
        assert!(a.warnings.iter().any(|w| w.starts_with("--var password")), "{:?}", a.warnings);

        // Guarded: no auth applied, secrets not substituted, a marker skips the item.
        let o = Options { guarded: true, withheld: a.withheld.clone(), ..Default::default() };
        let b = build(&doc, &o).unwrap();
        let text = format!("{:?}", b.requests);
        assert!(!text.contains("USEDBYAUTH") && !text.contains("LITERALKEY") && !text.contains("ITEMKEY"), "{text}");
        assert_eq!(String::from_utf8_lossy(&b.requests[0].body), "{\"a\": \"{{apiKey}}\"}");
        assert!(b.base_url_required);
        assert_eq!(b.skipped[0].operation, "Folder/Two");

        let doc =
            json!({"item": [{"name": "x", "request": {"url": "http://a.test/", "description": "«auth:p:password»"}}]});
        let b = build(&doc, &o).unwrap();
        assert!(b.requests.is_empty() && b.skipped[0].reason == "contains a reserved placeholder");
    }

    #[test]
    fn errors_leave_out_credentials_in_urls() {
        let doc = json!({"item": [{"name": "x", "request": "{{h}}/a?api_key=KEYVALUE"}]});
        let b = build(&doc, &Options { guarded: true, ..Default::default() }).unwrap();
        assert!(!format!("{b:?}").contains("KEYVALUE"), "{b:?}");
        let b = build(&doc, &Options::default()).unwrap();
        assert!(!format!("{b:?}").contains("KEYVALUE"), "{b:?}");
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
