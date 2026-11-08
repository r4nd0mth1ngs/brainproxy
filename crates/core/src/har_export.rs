//! History rows as a HAR 1.2 file, for another tool or for `import har` in another project.
//!
//! Session secrets are masked as reports mask them ([`Redactor`]): cookie values,
//! `Authorization` credentials, API-key headers, token and password parameters in URLs and
//! bodies, JWTs, the project's own auth profile secrets, and every value masked once wherever
//! else it appears. A body that isn't text can't be searched for them, so it is left out
//! while masking; unmasked (`redact: false`) it goes in as base64.

use base64::Engine;
use rusqlite::OptionalExtension;
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::scan::redact::Redactor;
use crate::scan::report::{Body, HttpRequest, HttpResponse};
use crate::store::Store;

#[derive(Debug, Clone)]
pub struct Options {
    /// Mask session secrets (the default).
    pub redact: bool,
    /// More values to mask wherever they appear, as `report --mask`.
    pub mask: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options { redact: true, mask: Vec::new() }
    }
}

/// The HAR document and what went into it.
#[derive(Debug)]
pub struct Exported {
    pub har: Value,
    pub entries: usize,
    /// Places a secret was masked in.
    pub redacted: usize,
    /// Bodies left out because they aren't text and secrets were being masked.
    pub binary_bodies_left_out: usize,
}

/// One row, read and (when masking) masked, before it is written out.
struct Row {
    id: i64,
    time: String,
    source: String,
    duration_ms: Option<i64>,
    error: Option<String>,
    http_version: String,
    request: HttpRequest,
    request_body: Vec<u8>,
    response: Option<HttpResponse>,
    response_body: Vec<u8>,
}

const LEFT_OUT: &str = "body left out: it isn't text, so its secrets couldn't be masked (--no-redact keeps it)";

/// The history rows `ids`, in that order, as a HAR 1.2 document.
pub fn export(store: &Store, ids: &[i64], opts: &Options) -> Result<Exported> {
    let mut red = opts.redact.then(Redactor::default);
    if let Some(r) = red.as_mut() {
        for (profile, state) in store.auth_list()? {
            r.know(profile.secret_values(&state));
        }
        r.know(opts.mask.iter().cloned());
    }
    let mut rows = Vec::with_capacity(ids.len());
    for &id in ids {
        let mut row = read(store, id)?;
        if let Some(r) = red.as_mut() {
            r.exchange(&mut row.request, row.response.as_mut());
            if let Some(e) = row.error.as_mut() {
                r.text(e);
            }
        }
        rows.push(row);
    }
    // A value learnt from a later row may be quoted in an earlier one.
    if let Some(r) = red.as_mut() {
        for row in &mut rows {
            r.scrub_exchange(&mut row.request, row.response.as_mut());
            if let Some(e) = row.error.as_mut() {
                r.scrub(e);
            }
        }
    }
    let mut binary_bodies_left_out = 0;
    let entries: Vec<Value> = rows.iter().map(|row| entry(row, opts.redact, &mut binary_bodies_left_out)).collect();
    let har = json!({"log": {
        "version": "1.2",
        "creator": {"name": "brainproxy", "version": env!("CARGO_PKG_VERSION")},
        "entries": entries,
    }});
    Ok(Exported { har, entries: rows.len(), redacted: red.map_or(0, |r| r.masked), binary_bodies_left_out })
}

fn read(store: &Store, id: i64) -> Result<Row> {
    let headers = |s: Option<String>| -> Vec<(String, String)> {
        s.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    };
    store
        .conn
        .query_row(
            "SELECT time, source, method, url, req_headers, req_body, status, reason, resp_headers, resp_body, \
             duration_ms, error, substr(response, 1, 16) FROM history WHERE id = ?1",
            [id],
            |r| {
                let request_body: Vec<u8> = r.get(5)?;
                let status: Option<i64> = r.get(6)?;
                let response_body: Vec<u8> = r.get::<_, Option<Vec<u8>>>(9)?.unwrap_or_default();
                let head: Vec<u8> = r.get::<_, Option<Vec<u8>>>(12)?.unwrap_or_default();
                let response = status.map(|_| -> rusqlite::Result<HttpResponse> {
                    Ok(HttpResponse {
                        status,
                        reason: r.get(7)?,
                        headers: headers(r.get(8)?),
                        body: body(&response_body),
                    })
                });
                Ok(Row {
                    id,
                    time: r.get(0)?,
                    source: r.get(1)?,
                    duration_ms: r.get(10)?,
                    error: r.get(11)?,
                    http_version: http_version(&head),
                    request: HttpRequest {
                        method: r.get(2)?,
                        url: r.get(3)?,
                        headers: headers(r.get(4)?),
                        body: body(&request_body),
                    },
                    request_body,
                    response: response.transpose()?,
                    response_body,
                })
            },
        )
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("history item {id}")))
}

fn body(bytes: &[u8]) -> Body {
    match std::str::from_utf8(bytes) {
        Ok(s) => Body { text: s.to_string(), length: bytes.len(), truncated: false, binary: false },
        Err(_) => Body { text: String::new(), length: bytes.len(), truncated: false, binary: true },
    }
}

/// The response's protocol, as its status line gives it; HTTP/1.1 when there isn't one.
fn http_version(head: &[u8]) -> String {
    let line = String::from_utf8_lossy(head);
    let v = line.split(' ').next().unwrap_or_default();
    if v.starts_with("HTTP/") {
        v.to_string()
    } else {
        "HTTP/1.1".to_string()
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn pairs(headers: &[(String, String)]) -> Value {
    Value::Array(headers.iter().map(|(k, v)| json!({"name": k, "value": v})).collect())
}

/// `name=value` items of Cookie headers, or the first item of each Set-Cookie header.
fn cookies(headers: &[(String, String)], name: &str) -> Value {
    let mut out = Vec::new();
    for (_, v) in headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)) {
        let items: Vec<&str> = if name == "cookie" { v.split(';').collect() } else { v.split(';').take(1).collect() };
        for item in items {
            if let Some((n, val)) = item.trim().split_once('=') {
                out.push(json!({"name": n.trim(), "value": val.trim()}));
            }
        }
    }
    Value::Array(out)
}

fn decoded(s: &str) -> String {
    let s = s.replace('+', " ");
    percent_encoding::percent_decode_str(&s).decode_utf8_lossy().into_owned()
}

fn query(url: &str) -> Value {
    let q = url.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let q = q.split('#').next().unwrap_or_default();
    Value::Array(
        q.split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                json!({"name": decoded(k), "value": decoded(v)})
            })
            .collect(),
    )
}

/// A body's text for HAR, or None (and why, in `comment`) when it is left out.
fn content(b: &Body, raw: &[u8], redact: bool, left_out: &mut usize) -> (Option<String>, Option<&'static str>) {
    if !b.binary {
        (Some(b.text.clone()), None)
    } else if redact {
        *left_out += 1;
        (None, None)
    } else {
        (Some(base64::engine::general_purpose::STANDARD.encode(raw)), Some("base64"))
    }
}

fn entry(row: &Row, redact: bool, left_out: &mut usize) -> Value {
    let req = &row.request;
    let mut request = json!({
        "method": req.method,
        "url": req.url,
        "httpVersion": row.http_version,
        "cookies": cookies(&req.headers, "cookie"),
        "headers": pairs(&req.headers),
        "queryString": query(&req.url),
        "headersSize": -1,
        "bodySize": req.body.length,
    });
    if req.body.length > 0 {
        let mime = header(&req.headers, "content-type").unwrap_or_default();
        let mut post = Map::new();
        post.insert("mimeType".into(), json!(mime));
        match content(&req.body, &row.request_body, redact, left_out) {
            (Some(text), None) => {
                if mime.to_ascii_lowercase().starts_with("application/x-www-form-urlencoded") {
                    post.insert("params".into(), query(&format!("?{text}")));
                }
                post.insert("text".into(), json!(text));
            }
            (Some(text), Some(_)) => {
                // HAR 1.2 has no encoding for a request body; tools that read one use `_encoding`.
                post.insert("text".into(), json!(text));
                post.insert("_encoding".into(), json!("base64"));
            }
            (None, _) => {
                post.insert("text".into(), json!(""));
                post.insert("comment".into(), json!(LEFT_OUT));
            }
        }
        request["postData"] = Value::Object(post);
    }
    let response = match &row.response {
        Some(r) => {
            let mut c = Map::new();
            c.insert("size".into(), json!(r.body.length));
            c.insert("mimeType".into(), json!(header(&r.headers, "content-type").unwrap_or_default()));
            match content(&r.body, &row.response_body, redact, left_out) {
                (Some(text), encoding) => {
                    c.insert("text".into(), json!(text));
                    if let Some(e) = encoding {
                        c.insert("encoding".into(), json!(e));
                    }
                }
                (None, _) if r.body.length > 0 => {
                    c.insert("comment".into(), json!(LEFT_OUT));
                }
                (None, _) => {}
            }
            json!({
                "status": r.status.unwrap_or(0),
                "statusText": r.reason.clone().unwrap_or_default(),
                "httpVersion": row.http_version,
                "cookies": cookies(&r.headers, "set-cookie"),
                "headers": pairs(&r.headers),
                "content": Value::Object(c),
                "redirectURL": header(&r.headers, "location").unwrap_or_default(),
                "headersSize": -1,
                "bodySize": r.body.length,
            })
        }
        // No answer: as browsers write a failed request.
        None => json!({
            "status": 0, "statusText": "", "httpVersion": row.http_version, "cookies": [], "headers": [],
            "content": {"size": 0, "mimeType": ""}, "redirectURL": "", "headersSize": -1, "bodySize": -1,
        }),
    };
    let wait = row.duration_ms.unwrap_or(0).max(0);
    let mut e = json!({
        "startedDateTime": row.time,
        "time": wait,
        "request": request,
        "response": response,
        "cache": {},
        "timings": {"send": 0, "wait": wait, "receive": 0},
        "_brainproxy": {"history_id": row.id, "source": row.source},
    });
    if let Some(err) = &row.error {
        e["_error"] = json!(err);
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Capture;
    use crate::http::Target;

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    fn record(s: &mut Store, req: &str, resp: Option<&[u8]>) -> i64 {
        let t = Target { scheme: "https".into(), host: "app.test".into(), port: 443 };
        s.record(&Capture::new("proxy", &t, req.as_bytes(), resp, Some(12), None)).unwrap()
    }

    #[test]
    fn rows_become_har_entries_with_secrets_masked() {
        let mut s = store();
        let a = record(
            &mut s,
            "POST /login?next=/home&token=QUERYSECRET1 HTTP/1.1\r\nHost: app.test\r\nCookie: sid=COOKIESECRET1; lang=en\r\n\
             Authorization: Bearer AUTHSECRET123\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 34\r\n\r\n\
             user=alice&password=BODYSECRET1xx",
            Some(b"HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: sid=NEWSESSION99; Path=/\r\nContent-Length: 0\r\n\r\n"),
        );
        let b = record(
            &mut s,
            "GET /home HTTP/1.1\r\nHost: app.test\r\n\r\n",
            Some(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 27\r\n\r\n<p>your id: NEWSESSION99</p>",
            ),
        );
        let c = record(
            &mut s,
            "GET /logo HTTP/1.1\r\nHost: app.test\r\n\r\n",
            Some(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4\r\n\r\n\x89PN\xff"),
        );
        let x = export(&s, &[a, b, c], &Options::default()).unwrap();
        assert_eq!(x.entries, 3);
        assert_eq!(x.binary_bodies_left_out, 1);
        let text = x.har.to_string();
        for secret in ["QUERYSECRET1", "COOKIESECRET1", "AUTHSECRET123", "BODYSECRET1xx", "NEWSESSION99"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        let log = &x.har["log"];
        assert_eq!(log["version"], "1.2");
        let first = &log["entries"][0];
        assert_eq!(first["request"]["method"], "POST");
        assert_eq!(first["request"]["httpVersion"], "HTTP/1.1");
        assert_eq!(
            first["request"]["cookies"],
            json!([{"name": "sid", "value": "[redacted]"}, {"name": "lang", "value": "[redacted]"}])
        );
        assert_eq!(first["request"]["queryString"][0], json!({"name": "next", "value": "/home"}));
        assert_eq!(first["request"]["postData"]["params"][0], json!({"name": "user", "value": "alice"}));
        assert_eq!(first["response"]["status"], 302);
        assert_eq!(first["response"]["redirectURL"], "/home");
        assert_eq!(first["response"]["cookies"][0]["name"], "sid");
        assert_eq!(first["_brainproxy"], json!({"history_id": a, "source": "proxy"}));
        assert_eq!(first["time"], 12);
        // The session id learnt from the Set-Cookie is masked in a later body too.
        assert_eq!(log["entries"][1]["response"]["content"]["text"], "<p>your id: [redacted]</p>");
        let logo = &log["entries"][2]["response"]["content"];
        assert!(logo.get("text").is_none() && logo["comment"].as_str().unwrap().contains("--no-redact"), "{logo}");
    }

    #[test]
    fn unmasked_keeps_everything_and_binary_goes_as_base64() {
        let mut s = store();
        let a = record(
            &mut s,
            "GET /a HTTP/1.1\r\nHost: app.test\r\nCookie: sid=COOKIESECRET1\r\n\r\n",
            Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\xff\xfe"),
        );
        let b = record(&mut s, "GET /down HTTP/1.1\r\nHost: app.test\r\n\r\n", None);
        let x = export(&s, &[a, b], &Options { redact: false, mask: vec![] }).unwrap();
        assert_eq!((x.redacted, x.binary_bodies_left_out), (0, 0));
        let e = &x.har["log"]["entries"];
        assert_eq!(e[0]["request"]["cookies"][0]["value"], "COOKIESECRET1");
        assert_eq!(
            e[0]["response"]["content"],
            json!({"size": 2, "mimeType": "", "text": "//4=", "encoding": "base64"})
        );
        assert_eq!((e[1]["response"]["status"].as_i64(), e[1]["response"]["bodySize"].as_i64()), (Some(0), Some(-1)));
        assert!(export(&s, &[999], &Options::default()).is_err());
    }

    #[test]
    fn known_values_are_masked_anywhere() {
        let mut s = store();
        let a = record(&mut s, "GET /a?q=hello-MYTOKEN-77 HTTP/1.1\r\nHost: app.test\r\n\r\n", None);
        let x = export(&s, &[a], &Options { redact: true, mask: vec!["MYTOKEN-77".into()] }).unwrap();
        assert!(!x.har.to_string().contains("MYTOKEN-77"), "{}", x.har);
    }
}
