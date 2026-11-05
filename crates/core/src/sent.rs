//! History rows for requests brainproxy sends itself outside the proxy (`send`, `send
//! --race`, `ws send`, and a session's own login, check, macro, and token requests). Each
//! row is written just before its request goes out and completed when the request is
//! answered or fails, so a request that went on the wire leaves a row even when the command
//! is cancelled, killed, or crashes: such a row keeps the [`PENDING`] error.
//!
//! A row can keep no content (`--no-store`, or an OAuth token request, whose request and
//! answer hold secrets): only the method, the URL without its query string, the time,
//! source, and target. The response is left out (no status, so passive checks skip it), and
//! the error says so, starting with [`NOT_STORED`] (or [`TOKEN_OMITTED`]), then whether a
//! query string was left out, then how the request ended.
//!
//! An API document's fetch keeps its request as sent and the response's head, but not the
//! document: it can hold the credentials `import` reports by name and withholds. The error
//! says so ([`DOCUMENT_OMITTED`]), with the body's length and sha256.

use std::path::Path;

use crate::capture::Capture;
use crate::error::Result;
use crate::http::client::{final_response, sent_sni};
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, Client, Exchange, Target};
use crate::store::Store;

/// The error of a row whose request went out and whose outcome was never recorded.
pub const PENDING: &str = "sent; no response recorded (cancelled or interrupted)";
/// The error of a row whose command was stopped (Ctrl-C, SIGTERM, the app's Stop) while it
/// waited. The request may have gone out, or only partly (a connection still opening).
pub const CANCELLED: &str = "cancelled by user before a response was recorded";
/// How a `--no-store` row's error starts.
pub const NOT_STORED: &str = "not stored (--no-store): content omitted";
/// How an OAuth token request's row's error starts.
pub const TOKEN_OMITTED: &str = "token request: content omitted (it carries the client secret and tokens)";

/// How the error of an API document fetch whose body was left out starts.
pub const DOCUMENT_OMITTED: &str = "API document: body omitted (it can hold credentials the import withholds)";

/// Records requests of one source as they go out. See the module docs.
pub struct SentLog {
    pub store: Store,
    source: &'static str,
    /// Keep no content: the error's first words for such rows.
    omit: Option<&'static str>,
    /// Keep the request and the response's head, not its body: the error's first words.
    omit_body: Option<&'static str>,
    /// The sending client's `--sni`, recorded on the rows of TLS targets (see [`sent_sni`]).
    sni: Option<String>,
}

impl SentLog {
    /// With `no_store`, rows keep no content (marked [`NOT_STORED`]).
    pub fn open(project: &Path, source: &'static str, no_store: bool) -> Result<Self> {
        Ok(Self::new(Store::open(project)?, source, no_store))
    }

    pub fn new(store: Store, source: &'static str, no_store: bool) -> Self {
        Self { store, source, omit: no_store.then_some(NOT_STORED), omit_body: None, sni: None }
    }

    /// Rows keep no content, marked with `reason`.
    pub fn without_content(mut self, reason: &'static str) -> Self {
        self.omit = Some(reason);
        self
    }

    /// Rows keep the request and the response's head, but not the response body: their error
    /// starts with `reason` and gives the body's length and sha256.
    pub fn without_response_body(mut self, reason: &'static str) -> Self {
        self.omit_body = Some(reason);
        self
    }

    pub fn no_store(&self) -> bool {
        self.omit.is_some()
    }

    /// Rows record the TLS server name `client` sends in place of a target's host (`--sni`).
    pub fn sent_by(mut self, client: &Client) -> Self {
        self.sni = client.options().sni.clone();
        self
    }

    /// The row for `request` (as recorded) and how it ended.
    fn capture(
        &self,
        target: &Target,
        request: &[u8],
        response: Option<&[u8]>,
        duration_ms: Option<u64>,
        error: Option<&str>,
    ) -> Capture {
        let c = self.content(target, request, response, duration_ms, error);
        Capture { sni: sent_sni(self.sni.as_deref(), target), ..c }
    }

    /// What the row keeps of the request and how it ended; [`SentLog::capture`] adds the
    /// server name.
    fn content(
        &self,
        target: &Target,
        request: &[u8],
        response: Option<&[u8]>,
        duration_ms: Option<u64>,
        error: Option<&str>,
    ) -> Capture {
        let ms = duration_ms.map(|d| d as i64);
        let Some(omit) = self.omit else {
            if let (Some(reason), Some(r)) = (self.omit_body, response) {
                let (head, body) = split_head_body(final_response(r));
                let mut note = format!("{reason}; {} bytes, sha256 {}", body.len(), crate::fetch::sha256_hex(body));
                if let Some(e) = error {
                    note.push_str(&format!("; {e}"));
                }
                return Capture::new(self.source, target, request, Some(head), ms, Some(&note));
            }
            return Capture::new(self.source, target, request, response, ms, error);
        };
        content_omitted(self.source, target, request, response, ms, error, omit)
    }

    /// Records `request` as about to go out; returns its row.
    pub fn pending(&mut self, target: &Target, request: &[u8]) -> Result<i64> {
        self.store.record(&self.capture(target, request, None, None, Some(PENDING)))
    }

    /// Records `n` copies of `request` as about to go out, in one transaction, copy `i`
    /// tagged `tags(i)` (a race's rows say which race and where in it). Completing a row
    /// keeps its tags.
    pub fn pending_many(
        &mut self,
        target: &Target,
        request: &[u8],
        n: usize,
        tags: impl FnMut(usize) -> Vec<String>,
    ) -> Result<Vec<i64>> {
        let c = self.capture(target, request, None, None, Some(PENDING));
        let copies: Vec<Capture> = (0..n).map(tags).map(|tags| Capture { tags, ..c.clone() }).collect();
        self.store.record_batch(&copies)
    }

    /// Completes row `id`; returns the capture it now holds.
    pub fn complete(
        &mut self,
        id: i64,
        target: &Target,
        request: &[u8],
        response: Option<&[u8]>,
        duration_ms: Option<u64>,
        error: Option<&str>,
    ) -> Result<Capture> {
        let c = self.capture(target, request, response, duration_ms, error);
        self.store.update_capture(id, &c)?;
        Ok(c)
    }

    pub fn answered(&mut self, id: i64, ex: &Exchange) -> Result<()> {
        self.complete(id, &ex.target, &ex.request, Some(&ex.response), Some(ex.duration_ms), None).map(drop)
    }

    pub fn failed(&mut self, id: i64, target: &Target, request: &[u8], error: &str) -> Result<()> {
        self.complete(id, target, request, None, None, Some(error)).map(drop)
    }

    /// Runs the passive checks on rows `ids` (now complete) and anything else new; returns
    /// the new findings. Nothing for `--no-store` rows, which keep no response.
    pub fn scan(&mut self, ids: &[i64]) -> Result<usize> {
        if self.no_store() {
            return Ok(0);
        }
        let mut new = 0;
        // Rows a passive scan elsewhere skipped while they were waiting for their response.
        for id in ids {
            new += crate::scan::passive::scan_late(&mut self.store, *id)?;
        }
        Ok(new + crate::scan::passive::scan_pending(&mut self.store)?.new_findings)
    }
}

/// A row that keeps no content: the request line without its query string, the time, source
/// and target. The response is left out (no status, so passive checks skip it); the error
/// starts with `reason`, then says whether a query string was left out and how the request
/// ended. The proxy writes these too, for traffic it forwards outside the recording scope.
pub fn content_omitted(
    source: &str,
    target: &Target,
    request: &[u8],
    response: Option<&[u8]>,
    duration_ms: Option<i64>,
    error: Option<&str>,
    reason: &str,
) -> Capture {
    let (line, had_query) = request_line(request);
    let mut note = reason.to_string();
    if had_query {
        note.push_str("; query string omitted");
    }
    let status = response.and_then(|r| parse_response_head(final_response(r)).ok()).map(|h| h.status);
    match (error, status) {
        (Some(e), _) => note.push_str(&format!("; {e}")),
        (None, Some(s)) => note.push_str(&format!("; response status {s}")),
        (None, None) => {}
    }
    Capture::new(source, target, &line, None, duration_ms, Some(&note))
}

/// The request line alone, as a request without headers or body, its query string cut off;
/// and whether there was one.
fn request_line(request: &[u8]) -> (Vec<u8>, bool) {
    let line = request.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts: Vec<&[u8]> = line.splitn(3, |&b| b == b' ').collect();
    let mut had_query = false;
    if let Some(i) = parts.get(1).and_then(|t| t.iter().position(|&b| b == b'?')) {
        parts[1] = &parts[1][..i];
        had_query = true;
    }
    ([parts.join(&b' '), b"\r\n\r\n".to_vec()].concat(), had_query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_store_rows_keep_only_the_request_line() {
        let dir = std::env::temp_dir().join(format!("bp-sent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let project = dir.join("p.bpdb");
        let _ = std::fs::remove_file(&project);
        drop(Store::create(&project).unwrap());
        let mut log = SentLog::open(&project, "send", true).unwrap();
        let target = Target::from_url("http://a.test").unwrap();
        let req = b"POST /login?next=/home HTTP/1.1\r\nHost: a.test\r\nCookie: sid=secret\r\n\r\npassword=hunter2";
        let id = log.pending(&target, req).unwrap();
        let resp = b"HTTP/1.1 302 Found\r\nSet-Cookie: sid=new\r\nContent-Length: 0\r\n\r\n";
        log.complete(id, &target, req, Some(resp), Some(12), None).unwrap();
        let item = log.store.get(id).unwrap();
        assert_eq!(item.request, b"POST /login HTTP/1.1\r\n\r\n");
        assert!(item.response.is_empty());
        assert_eq!((item.entry.method.as_str(), item.entry.url.as_str()), ("POST", "http://a.test/login"));
        assert_eq!(item.entry.status, None);
        assert_eq!(
            item.entry.error.as_deref(),
            Some("not stored (--no-store): content omitted; query string omitted; response status 302")
        );
        assert_eq!(item.entry.duration_ms, Some(12));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rows_record_the_server_name_their_client_sends() {
        let client = |sni: Option<&str>| {
            Client::new(crate::http::SendOptions { sni: sni.map(str::to_string), ..Default::default() })
        };
        let sni = |log: &mut SentLog, url: &str| {
            let target = Target::from_url(url).unwrap();
            let id = log.pending(&target, b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
            log.store.get(id).unwrap().entry.sni
        };
        let mut overridden =
            SentLog::new(Store::open_in_memory().unwrap(), "send", false).sent_by(&client(Some("b.test")));
        assert_eq!(sni(&mut overridden, "https://a.test").as_deref(), Some("b.test"));
        // Plain HTTP sends no server name.
        assert_eq!(sni(&mut overridden, "http://a.test"), None);
        // Another client's override in the same process isn't this one's.
        let mut plain = SentLog::new(Store::open_in_memory().unwrap(), "send", false).sent_by(&client(None));
        assert_eq!(sni(&mut plain, "https://a.test"), None);
        // Naming the target's own host overrides nothing.
        let mut same = SentLog::new(Store::open_in_memory().unwrap(), "send", false).sent_by(&client(Some("A.test")));
        assert_eq!(sni(&mut same, "https://a.test"), None);
        // An IP address can't be a server name: none is sent, so none is recorded.
        for ip in ["127.0.0.1", "::1"] {
            let mut log = SentLog::new(Store::open_in_memory().unwrap(), "send", false).sent_by(&client(Some(ip)));
            assert_eq!(sni(&mut log, "https://a.test"), None, "{ip}");
        }
    }
}
