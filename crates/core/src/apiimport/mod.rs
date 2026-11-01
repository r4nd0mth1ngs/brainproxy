//! API import: turns OpenAPI/Swagger documents, Postman collections, and
//! GraphQL schemas into concrete requests (example or typed default values for
//! every parameter), sends them through the guarded client, and records them in
//! history (source "import") so `scan active` and `fuzz` can work from them.

pub mod api;
pub mod graphql;
pub mod openapi;
pub mod postman;
mod values;

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use tokio::sync::Semaphore;

use crate::auth::AuthSession;
use crate::capture::Capture;
use crate::error::{Error, Result};
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use crate::jobs::JobControl;
use crate::session::Tool;
use crate::store::Store;

/// History source for imported requests.
pub const SOURCE: &str = "import";

/// Largest spec, collection, or schema accepted.
pub const MAX_DOCUMENT: usize = 32 << 20;

/// The most a guarded build holds in requests.
const MAX_BUILT: usize = 64 << 20;

/// One request built from an API description.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ApiRequest {
    /// operationId, Postman item path, or "query field" for GraphQL.
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    #[serde(serialize_with = "lossy")]
    pub body: Vec<u8>,
}

fn lossy<S: serde::Serializer>(b: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&String::from_utf8_lossy(b))
}

/// An operation that could not be turned into a request.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Skipped {
    pub operation: String,
    pub reason: String,
}

/// A credential a document asks for or holds. Never its value.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Credential {
    /// api_key, bearer, basic, oauth2, openid, mutual_tls, or other.
    pub kind: String,
    /// header, query, cookie, or none.
    #[serde(rename = "in")]
    pub location: Option<String>,
    pub name: Option<String>,
    pub source: String,
    /// The document holds a value (which was not used).
    pub embedded: bool,
}

/// Requests built from a document, plus what could not be turned into a request.
/// Only guarded builds (`import api`) fill `skipped`, `credentials` and `base_url_required`.
#[derive(Debug, Default, Serialize)]
pub struct Built {
    pub requests: Vec<ApiRequest>,
    pub warnings: Vec<String>,
    pub skipped: Vec<Skipped>,
    pub credentials: Vec<Credential>,
    pub base_url_required: bool,
    /// Bytes in `requests`, for a guarded build's limit.
    #[serde(skip)]
    size: usize,
}

impl Built {
    /// Adds a request. A guarded build stops at `MAX_BUILT`, as a small document can
    /// repeat a large example or variable any number of times.
    fn keep(&mut self, guarded: bool, operation: String, r: ApiRequest) {
        let size = r.url.len() + r.body.len() + r.headers.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>();
        if guarded && self.size + size > MAX_BUILT {
            self.skip(operation, format!("the document's requests add up to more than {} MiB", MAX_BUILT >> 20));
        } else {
            self.size += size;
            self.requests.push(r);
        }
    }

    fn warn(&mut self, w: String) {
        if self.warnings.len() < 100 {
            self.warnings.push(w);
        }
    }

    fn skip(&mut self, operation: String, reason: String) {
        self.skipped.push(Skipped { operation, reason });
    }

    /// A guarded build lists the operation as skipped; the others warn.
    fn fail(&mut self, guarded: bool, operation: String, e: &Error) {
        if guarded {
            let text = e.to_string();
            let reason = text.strip_prefix("invalid input: ").unwrap_or(&text).to_string();
            self.skip(operation, reason);
        } else {
            self.warn(format!("{operation}: {e}"));
        }
    }

    fn credential(&mut self, c: Credential) {
        merge_credential(&mut self.credentials, c);
    }
}

/// Adds `c`, one entry per location and name.
fn merge_credential(list: &mut Vec<Credential>, c: Credential) {
    let same = |o: &Credential| {
        o.location == c.location
            && match (&o.name, &c.name) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                (None, None) => o.kind == c.kind,
                _ => false,
            }
    };
    match list.iter_mut().find(|o| same(o)) {
        Some(o) => o.embedded |= c.embedded,
        None => list.push(c),
    }
}

/// Whether a header, parameter, or variable name looks like it holds a credential.
pub fn looks_secret(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase().replace('_', "-");
    n.starts_with("x-auth")
        || ["authorization", "cookie", "token", "secret", "api-key", "apikey", "password", "passwd"]
            .iter()
            .any(|s| n.contains(s))
}

/// A URL for messages: no userinfo, query, or fragment, which can hold credentials.
pub(crate) fn shown_url(url: &str) -> String {
    let bare = url.split(['?', '#']).next().unwrap_or_default();
    match bare.split_once("://") {
        Some((scheme, rest)) => {
            let end = rest.find('/').unwrap_or(rest.len());
            let (authority, path) = rest.split_at(end);
            format!("{scheme}://{}{path}", authority.rsplit('@').next().unwrap_or_default())
        }
        None => bare.to_string(),
    }
}

/// Parses JSON, or YAML when the text isn't JSON. YAML keys that aren't
/// strings (e.g. unquoted `200:` response codes) become strings; aliases are
/// bounded by the parser's budget, so alias bombs fail instead of exhausting memory.
pub fn parse_document(text: &str) -> Result<Value> {
    if text.len() > MAX_DOCUMENT {
        return Err(Error::InvalidInput(format!("document is larger than {} MiB", MAX_DOCUMENT >> 20)));
    }
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(v) = serde_json::from_str(trimmed) {
            return Ok(v);
        }
    }
    serde_saphyr::from_str::<AnyKeys>(trimmed)
        .map(|v| v.0)
        .map_err(|e| Error::InvalidInput(format!("not valid JSON or YAML: {e}")))
}

/// serde_json::Value that accepts non-string map keys.
struct AnyKeys(Value);

impl<'de> Deserialize<'de> for AnyKeys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(AnyVisitor).map(AnyKeys)
    }
}

struct AnyVisitor;

impl<'de> Visitor<'de> for AnyVisitor {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any YAML value")
    }
    fn visit_bool<E>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E>(self, v: f64) -> std::result::Result<Value, E> {
        Ok(Number::from_f64(v).map(Value::Number).unwrap_or(Value::Null))
    }
    fn visit_str<E>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        d.deserialize_any(AnyVisitor)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(AnyKeys(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(AnyKeys(k)) = map.next_key()? {
            let key = match k {
                Value::String(s) => s,
                Value::Null => "null".into(),
                Value::Bool(_) | Value::Number(_) => k.to_string(),
                _ => return Err(de::Error::custom("map keys must be scalars")),
            };
            let AnyKeys(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

/// Replaces the scheme/host/port of `url` with those of `base`. A path in
/// `base` (other than "/") is put in front of the URL's path.
pub fn rebase(url: &str, base: &str) -> Result<String> {
    let shown = shown_url(url);
    let mut u = url::Url::parse(url).map_err(|e| Error::InvalidInput(format!("invalid URL {shown:?}: {e}")))?;
    let b = parse_base(base)?;
    let prefix = b.path().trim_end_matches('/');
    if !prefix.is_empty() {
        let p = format!("{prefix}{}", u.path());
        u.set_path(&p);
    }
    let onto = shown_url(base);
    u.set_scheme(b.scheme()).map_err(|_| Error::InvalidInput(format!("cannot rebase {shown:?} onto {onto:?}")))?;
    u.set_host(b.host_str()).map_err(|e| Error::InvalidInput(format!("bad base URL host: {e}")))?;
    u.set_port(b.port()).map_err(|_| Error::InvalidInput(format!("cannot rebase {shown:?} onto {onto:?}")))?;
    Ok(u.to_string())
}

fn parse_base(base: &str) -> Result<url::Url> {
    let s = if base.contains("://") { base.to_string() } else { format!("https://{base}") };
    let shown = shown_url(base);
    let u = url::Url::parse(&s).map_err(|e| Error::InvalidInput(format!("invalid base URL {shown:?}: {e}")))?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        return Err(Error::InvalidInput(format!("base URL {shown:?} must be http(s)://host[:port][/path]")));
    }
    Ok(u)
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub send: SendOptions,
    /// Extra headers; they replace headers of the same name from the document.
    pub headers: Vec<(String, String)>,
    pub concurrency: usize,
    pub rate: Option<f64>,
    pub auth: Option<Arc<AuthSession>>,
    /// Requests listed in the summary.
    pub list_limit: usize,
    /// Whose session rules apply: requests made from a spec count as crawl traffic,
    /// and as scan traffic when they are a scan's baselines.
    pub tool: Tool,
    /// Report progress after every response under this stage, not every 25 responses.
    pub stage: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Sent {
    pub name: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub history_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct RunSummary {
    pub sent: usize,
    pub by_status: BTreeMap<String, usize>,
    pub errors: usize,
    pub skipped_out_of_scope: usize,
    pub out_of_scope_hosts: Vec<String>,
    pub new_findings: usize,
    pub stopped: bool,
    pub requests: Vec<Sent>,
    pub requests_truncated: bool,
    pub elapsed_ms: u64,
}

impl RunSummary {
    /// Nothing went out, because the scope refused all of it (some only once the name was
    /// resolved, so a plan can't tell beforehand).
    pub fn check_any_in_scope(&self) -> Result<()> {
        if self.sent == 0 && self.skipped_out_of_scope > 0 && !self.stopped {
            return Err(Error::OutOfScope(format!(
                "none of the requests is in scope (hosts: {}); nothing was sent",
                self.out_of_scope_hosts.join(", ")
            )));
        }
        Ok(())
    }
}

/// Applies `extra` headers over `req`'s and builds the raw request.
/// Rejects methods that aren't HTTP tokens and header fields with line breaks,
/// so a hostile document can't inject extra request lines.
pub fn build_raw(req: &ApiRequest, extra: &[(String, String)]) -> Result<(RawRequest, Target)> {
    if req.method.is_empty() || !req.method.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)) {
        return Err(Error::InvalidInput(format!("invalid method {:?}", req.method)));
    }
    let bad = |s: &str| s.contains(['\r', '\n', '\0']);
    if let Some((k, _)) = req.headers.iter().find(|(k, v)| k.is_empty() || bad(k) || bad(v) || k.contains(':')) {
        return Err(Error::InvalidInput(format!("invalid header {k:?}")));
    }
    let mut headers: Vec<(String, String)> =
        req.headers.iter().filter(|(k, _)| !extra.iter().any(|(e, _)| e.eq_ignore_ascii_case(k))).cloned().collect();
    headers.extend(extra.iter().cloned());
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("connection")) {
        headers.push(("Connection".into(), "keep-alive".into()));
    }
    RawRequest::build(&req.method, &req.url, &headers, &req.body)
}

/// Sends every request (in scope only), records each exchange, and passively scans them.
pub async fn run(project: &Path, requests: Vec<ApiRequest>, cfg: RunConfig, ctl: JobControl) -> Result<RunSummary> {
    let started = Instant::now();
    let guard = cfg.send.guard.clone().ok_or_else(|| Error::OutOfScope("no scope set".into()))?;
    let mut store = Store::open(project)?;
    let client = Arc::new(Client::new(cfg.send.clone()));
    let mut summary = RunSummary::default();
    let mut oos = std::collections::BTreeSet::new();
    let mut work = Vec::new();
    for req in requests {
        let (raw, target) = build_raw(&req, &cfg.headers)?;
        if guard.may_allow(&target.host, target.port) {
            work.push((req, raw, target));
        } else {
            summary.skipped_out_of_scope += 1;
            oos.insert(target.host.clone());
        }
    }
    let limiter = cfg.rate.filter(|r| *r > 0.0).map(|r| Duration::from_secs_f64(1.0 / r));
    let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let mut total = work.len();
    let tool = cfg.tool;
    if let Some(stage) = cfg.stage {
        ctl.set_progress(serde_json::json!({"stage": stage, "sent": 0, "total": total}));
    }
    // ponytail: one batch of tasks; fine for spec-sized inputs (thousands), stream if specs get huge.
    let mut tasks = Vec::new();
    for (i, (req, raw, target)) in work.into_iter().enumerate() {
        let (sem, client, auth, ctl) = (sem.clone(), client.clone(), cfg.auth.clone(), ctl.clone());
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            if let Some(d) = limiter {
                let due = started + d * i as u32;
                tokio::time::sleep_until(due.into()).await;
            }
            if ctl.stopped() {
                return None;
            }
            let sent = match auth.as_deref() {
                Some(a) => a.send_as(tool, &raw, &target).await,
                None => client.send(&raw, &target).await,
            };
            Some((req, raw, target, sent))
        }));
    }
    for task in tasks {
        let Ok(Some((req, raw, target, sent))) = task.await else { continue };
        // Host names pass may_allow; the resolved address can still be out of scope.
        if let Err(Error::OutOfScope(_)) = &sent {
            summary.skipped_out_of_scope += 1;
            oos.insert(target.host.clone());
            total -= 1;
            continue;
        }
        summary.sent += 1;
        let (status, error, id) = match sent {
            Ok(ex) => {
                let status = parse_response_head(&ex.response).ok().map(|h| h.status);
                let id = store.record(&Capture::new(
                    SOURCE,
                    &target,
                    &ex.request,
                    Some(&ex.response),
                    Some(ex.duration_ms as i64),
                    None,
                ))?;
                (status, None, id)
            }
            Err(e) => {
                let msg = e.to_string();
                let id = store.record(&Capture::new(SOURCE, &target, raw.as_bytes(), None, None, Some(&msg)))?;
                (None, Some(msg), id)
            }
        };
        let key = status.map(|s| s.to_string()).unwrap_or_else(|| "error".into());
        *summary.by_status.entry(key).or_default() += 1;
        if error.is_some() {
            summary.errors += 1;
        }
        if summary.requests.len() < cfg.list_limit {
            summary.requests.push(Sent {
                name: req.name,
                method: req.method,
                url: req.url,
                status,
                history_id: id,
                error,
            });
        } else {
            summary.requests_truncated = true;
        }
        if let Some(stage) = cfg.stage {
            ctl.set_progress(serde_json::json!({"stage": stage, "sent": summary.sent, "total": total}));
        } else if summary.sent % 25 == 0 {
            ctl.set_progress(serde_json::json!({"sent": summary.sent, "total": total}));
        }
    }
    summary.new_findings = crate::scan::passive::scan_pending(&mut store)?.new_findings;
    summary.out_of_scope_hosts = oos.into_iter().take(50).collect();
    summary.stopped = ctl.stopped();
    summary.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_with_numeric_keys() {
        let v = parse_document(
            "openapi: 3.0.0\npaths:\n  /a:\n    get:\n      responses:\n        200:\n          description: ok\n",
        )
        .unwrap();
        assert_eq!(v["paths"]["/a"]["get"]["responses"]["200"]["description"], "ok");
        assert_eq!(parse_document("{\"a\": [1, 2]}").unwrap()["a"][1], 2);
    }

    #[test]
    fn yaml_alias_bomb_is_rejected() {
        let mut doc = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            let p = i - 1;
            doc.push_str(&format!(
                "a{i}: &a{i} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]\n"
            ));
        }
        assert!(parse_document(&doc).is_err());
    }

    #[test]
    fn rebase_keeps_path_and_query() {
        assert_eq!(
            rebase("https://api.example.com/v1/pets?x=1", "http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080/v1/pets?x=1"
        );
        assert_eq!(rebase("https://a.test/pets", "http://b.test/api/").unwrap(), "http://b.test/api/pets");
    }

    #[test]
    fn hostile_methods_and_headers_are_rejected() {
        let ok = ApiRequest {
            name: "x".into(),
            method: "GET".into(),
            url: "http://a.test/".into(),
            headers: vec![],
            body: vec![],
        };
        let method = ApiRequest { method: "GET / HTTP/1.1\r\nX: y".into(), ..ok.clone() };
        let header = ApiRequest { headers: vec![("X-A".into(), "1\r\nHost: evil.test".into())], ..ok.clone() };
        assert!(build_raw(&ok, &[]).is_ok());
        assert!(build_raw(&method, &[]).is_err() && build_raw(&header, &[]).is_err());
    }

    #[test]
    fn secret_names_and_shown_urls() {
        for n in
            ["Authorization", "Cookie", "X-Auth-User", "x_auth", "api_key", "X-API-KEY", "apikey", "my_token", "PASSWD"]
        {
            assert!(looks_secret(n), "{n}");
        }
        for n in ["Accept", "limit", "author", "id", "X-Trace", "monkey"] {
            assert!(!looks_secret(n), "{n}");
        }
        assert_eq!(shown_url("https://u:p@a.test:8/x?k=v#f"), "https://a.test:8/x");
        assert_eq!(shown_url("/api?k=v"), "/api");
    }

    #[test]
    fn extra_headers_replace_document_headers() {
        let req = ApiRequest {
            name: "x".into(),
            method: "GET".into(),
            url: "http://a.test/".into(),
            headers: vec![("X-Api-Key".into(), "doc".into())],
            body: vec![],
        };
        let (raw, _) = build_raw(&req, &[("x-api-key".into(), "mine".into())]).unwrap();
        let text = String::from_utf8_lossy(raw.as_bytes()).to_string();
        assert!(text.contains("x-api-key: mine") && !text.contains("doc"), "{text}");
    }
}
