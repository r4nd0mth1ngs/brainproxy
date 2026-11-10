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
//!
//! Senders with many requests out at once (crawls, active scans, `authz`, `fuzz`) write
//! their rows the same way, through a writer thread of their own: see [`Rows`] and
//! [`RowBatch`]. The thread writes every row queued since its last write in one
//! transaction, and a request goes out only once its row is committed.

use std::path::Path;
use std::sync::Arc;

use crate::auth::AuthSession;
use crate::capture::Capture;
use crate::error::{Error, Result};
use crate::http::client::{final_response, sent_sni};
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, Client, Exchange, RawRequest, Target};
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

/// The error of a [`Rows`] row whose request was given up unanswered: it timed out, or the
/// command stopped waiting for it.
pub const ABANDONED: &str = "sent; no response recorded (timed out or stopped while waiting)";

/// A row write for a sender's writer thread: see [`Rows`].
pub enum RowWrite {
    /// A request about to go out. Its row is written and the id sent back once committed;
    /// None if it couldn't be written, and then the request isn't sent.
    Pending { capture: Box<Capture>, reply: tokio::sync::oneshot::Sender<Option<i64>> },
    /// How a pending row's request ended.
    Complete { id: i64, capture: Box<Capture> },
}

/// The row writes a writer thread has taken off its queue, written in one transaction.
#[derive(Default)]
pub struct RowBatch {
    pending: Vec<(Capture, tokio::sync::oneshot::Sender<Option<i64>>)>,
    done: Vec<(i64, Capture)>,
}

/// What [`RowBatch::write`] did.
#[derive(Debug, Default)]
pub struct Written {
    /// The rows written (pending), in the order queued.
    pub created: Vec<i64>,
    /// The rows completed: a passive scan may have passed them while they were pending
    /// (see [`crate::scan::passive::scan_late`]).
    pub completed: Vec<i64>,
    /// Writes that failed (each also printed to stderr).
    pub failed: usize,
}

impl RowBatch {
    pub fn push(&mut self, w: RowWrite) {
        match w {
            RowWrite::Pending { capture, reply } => self.pending.push((*capture, reply)),
            RowWrite::Complete { id, capture } => self.done.push((id, *capture)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.done.is_empty()
    }

    /// Writes the batch in one transaction, then sends the new rows' ids back. If that
    /// fails (one row too large, say), writes them one by one, so only the bad ones fail:
    /// a pending row that couldn't be written gets None, and its request isn't sent.
    pub fn write(&mut self, store: &mut Store) -> Written {
        let pending = std::mem::take(&mut self.pending);
        let done = std::mem::take(&mut self.done);
        let mut out = Written::default();
        if pending.is_empty() && done.is_empty() {
            return out;
        }
        let new: Vec<Capture> = pending.iter().map(|(c, _)| c.clone()).collect();
        match store.write_rows(&new, &done) {
            Ok(ids) => {
                for ((_, reply), id) in pending.into_iter().zip(ids) {
                    let _ = reply.send(Some(id));
                    out.created.push(id);
                }
                out.completed = done.into_iter().map(|(id, _)| id).collect();
            }
            Err(e) => {
                eprintln!(
                    "brainproxy: writing {} history rows failed ({e}); writing them one by one",
                    new.len() + done.len()
                );
                for (c, reply) in pending {
                    let id = store.record(&c).inspect_err(|e| eprintln!("brainproxy: history row not written: {e}"));
                    out.failed += id.is_err() as usize;
                    out.created.extend(id.as_ref().ok());
                    let _ = reply.send(id.ok());
                }
                for (id, c) in done {
                    match store.update_capture(id, &c) {
                        Ok(()) => out.completed.push(id),
                        Err(e) => {
                            eprintln!("brainproxy: history #{id} not completed: {e}");
                            out.failed += 1;
                        }
                    }
                }
            }
        }
        out
    }
}

/// Records the requests of one source as they go out, for a sender with many in flight:
/// each row is queued to the sender's writer thread (which writes it with others in a
/// [`RowBatch`]), and the request waits until it is committed. Cheap to clone.
#[derive(Clone)]
pub struct Rows {
    write: Arc<dyn Fn(RowWrite) + Send + Sync>,
    source: &'static str,
    /// See [`SentLog::sent_by`].
    sni: Option<String>,
    /// The error of a row whose request was given up unanswered.
    abandoned: &'static str,
    /// Keep no content: the error's first words for such rows.
    omit: Option<&'static str>,
}

impl Rows {
    /// Rows of `source`, handed to `write` (which queues them for the writer thread).
    pub fn new(source: &'static str, write: impl Fn(RowWrite) + Send + Sync + 'static) -> Self {
        Self { write: Arc::new(write), source, sni: None, abandoned: ABANDONED, omit: None }
    }

    /// Rows of `source` written to `store` at once, on the sending thread: for a sender with
    /// one request out at a time, which needs no writer thread.
    pub fn direct(source: &'static str, store: Store) -> Self {
        let store = std::sync::Mutex::new(store);
        Self::new(source, move |w| {
            let mut batch = RowBatch::default();
            batch.push(w);
            batch.write(&mut store.lock().unwrap());
        })
    }

    /// Rows record the TLS server name `client` sends in place of a target's host (`--sni`).
    pub fn sent_by(mut self, client: &Client) -> Self {
        self.sni = client.options().sni.clone();
        self
    }

    /// A row whose request is given up unanswered keeps `error` (default [`ABANDONED`]).
    pub fn abandoned_as(mut self, error: &'static str) -> Self {
        self.abandoned = error;
        self
    }

    /// Rows keep no content, as [`SentLog::without_content`]'s do.
    pub fn without_content(mut self, reason: &'static str) -> Self {
        self.omit = Some(reason);
        self
    }

    pub fn source(&self) -> &'static str {
        self.source
    }

    /// The row for `request` and how it ended.
    pub fn capture(
        &self,
        target: &Target,
        request: &[u8],
        response: Option<&[u8]>,
        duration_ms: Option<u64>,
        error: Option<&str>,
    ) -> Capture {
        let duration = duration_ms.map(|d| d as i64);
        let c = match self.omit {
            Some(reason) => content_omitted(self.source, target, request, response, duration, error, reason),
            None => Capture::new(self.source, target, request, response, duration, error),
        };
        Capture { sni: sent_sni(self.sni.as_deref(), target), ..c }
    }

    /// Writes the row of `request` (as recorded) as about to go out, and waits until it is
    /// committed. The returned row completes itself as given up if dropped open.
    pub async fn open(&self, target: &Target, request: Vec<u8>) -> Result<OpenRow> {
        let (reply, id) = tokio::sync::oneshot::channel();
        let capture = self.capture(target, &request, None, None, Some(PENDING));
        (self.write)(RowWrite::Pending { capture: Box::new(capture), reply });
        let Some(id) = id.await.ok().flatten() else {
            return Err(Error::Protocol("the request could not be recorded in history, so it wasn't sent".into()));
        };
        Ok(OpenRow { rows: self.clone(), id, target: target.clone(), request, open: true })
    }

    /// Sends `req` with `client`, its row written first and completed with the outcome.
    /// Returns the row (None when nothing was recorded or sent) and the result. A target the
    /// engagement scope refuses outright gets no row: the client refuses it unsent.
    pub async fn send(&self, client: &Client, req: &RawRequest, target: &Target) -> (Option<i64>, Result<Exchange>) {
        if client.options().guard.as_ref().is_some_and(|g| !g.may_allow(&target.host, target.port)) {
            return (None, client.send(req, target).await);
        }
        let row = match client.recorded_request(req, target) {
            Ok(recorded) => self.open(target, recorded).await,
            Err(e) => Err(e),
        };
        let mut row = match row {
            Ok(row) => row,
            Err(e) => return (None, Err(e)),
        };
        let result = client.send(req, target).await;
        match &result {
            Ok(ex) => row.answered(ex),
            Err(e) => row.failed(&e.to_string()),
        }
        (Some(row.id), result)
    }

    /// [`Rows::send_as`] with `session` if there is one, else [`Rows::send`] with `client`.
    pub async fn send_with(
        &self,
        client: &Client,
        session: Option<&AuthSession>,
        tool: crate::session::Tool,
        req: &RawRequest,
        target: &Target,
    ) -> (Vec<i64>, Result<Exchange>) {
        match session {
            Some(s) => self.send_as(s, tool, req, target).await,
            None => {
                let (id, result) = self.send(client, req, target).await;
                (id.into_iter().collect(), result)
            }
        }
    }

    /// [`Rows::send`] with `session` applied for `tool`, as [`AuthSession::send_as`] sends:
    /// the request, and the request sent again after a re-login, each get a row (in the
    /// order sent).
    pub async fn send_as(
        &self,
        session: &AuthSession,
        tool: crate::session::Tool,
        req: &RawRequest,
        target: &Target,
    ) -> (Vec<i64>, Result<Exchange>) {
        let mut ids = Vec::new();
        let prepared = session.prepare(tool, target, req.as_bytes(), &[], &[]).await;
        let (id, result) = self.send(&session.client, &RawRequest::from_bytes(prepared.request.clone()), target).await;
        ids.extend(id);
        let ex = match result {
            Ok(ex) => ex,
            Err(e) => return (ids, Err(e)),
        };
        if !session.after_response(&prepared, &ex.response).await {
            return (ids, Ok(ex));
        }
        let again = RawRequest::from_bytes(session.prepare(tool, target, req.as_bytes(), &[], &[]).await.request);
        let (id, result) = self.send(&session.client, &again, target).await;
        ids.extend(id);
        if let Ok(ex) = &result {
            session.observe(&ex.response);
        }
        (ids, result)
    }
}

/// A [`Rows`] row whose request is out. Completed by [`OpenRow::answered`] or
/// [`OpenRow::failed`]; dropped open (the request timed out, or the sender stopped waiting),
/// it completes itself with the [`Rows`]' given-up error.
pub struct OpenRow {
    rows: Rows,
    pub id: i64,
    target: Target,
    request: Vec<u8>,
    open: bool,
}

impl OpenRow {
    pub fn answered(&mut self, ex: &Exchange) {
        let c = self.rows.capture(&ex.target, &ex.request, Some(&ex.response), Some(ex.duration_ms), None);
        self.finish(c);
    }

    /// Answered with `response` to the request as recorded.
    pub fn answered_with(&mut self, response: &[u8], duration_ms: u64) {
        let c = self.rows.capture(&self.target, &self.request, Some(response), Some(duration_ms), None);
        self.finish(c);
    }

    pub fn failed(&mut self, error: &str) {
        let c = self.rows.capture(&self.target, &self.request, None, None, Some(error));
        self.finish(c);
    }

    fn finish(&mut self, capture: Capture) {
        self.open = false;
        (self.rows.write)(RowWrite::Complete { id: self.id, capture: Box::new(capture) });
    }
}

impl Drop for OpenRow {
    fn drop(&mut self) {
        if self.open {
            self.failed(self.rows.abandoned);
        }
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

    /// A request's row is committed before it goes out; one given up unanswered says so,
    /// and a target the scope refuses outright gets none.
    #[tokio::test]
    async fn rows_are_written_before_the_request_goes_out() {
        let dir = std::env::temp_dir().join(format!("bp-rows-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let project = dir.join("p.bpdb");
        let _ = std::fs::remove_file(&project);
        drop(Store::create(&project).unwrap());
        // A server that takes the request and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (got_tx, got) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let _ = got_tx.send(());
            std::future::pending::<()>().await;
            drop(s);
        });
        let rows = Rows::direct("crawl", Store::open(&project).unwrap());
        let in_scope = |host: &str| {
            let scope = crate::guard::ScopeSpec { name: None, include: vec![host.into()], exclude: vec![] };
            let guard = crate::guard::Guard::from_specs(vec![scope]).unwrap();
            Client::new(crate::http::SendOptions { guard: Some(guard), ..Default::default() })
        };
        let client = in_scope("127.0.0.1");
        let target = Target::from_url(&format!("http://127.0.0.1:{port}")).unwrap();
        let req = RawRequest::from_bytes(b"GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec());
        let sending = rows.send(&client, &req, &target);
        let waited = tokio::select! {
            r = sending => panic!("the server never answers: {:?}", r.1.err()),
            r = async { got.await.unwrap(); Store::open(&project).unwrap().list(&Default::default()).unwrap() } => r,
        };
        // On record while out, then given up (the future dropped).
        assert_eq!(waited.len(), 1);
        assert_eq!(waited[0].error.as_deref(), Some(PENDING));
        let store = Store::open(&project).unwrap();
        let item = store.get(waited[0].id).unwrap();
        assert_eq!(item.entry.error.as_deref(), Some(ABANDONED));
        assert_eq!(item.request, req.as_bytes());

        // Outside the engagement: refused unsent, and no row.
        let (id, sent) = rows.send(&in_scope("b.test"), &req, &target).await;
        assert!(id.is_none() && sent.is_err());
        assert_eq!(store.list(&Default::default()).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_batch_writes_rows_and_completions_together() {
        let mut store = Store::open_in_memory().unwrap();
        let target = Target::from_url("http://a.test").unwrap();
        let rows = Rows::new("scan", |_| {});
        let mut batch = RowBatch::default();
        let (reply, id) = tokio::sync::oneshot::channel();
        batch.push(RowWrite::Pending {
            capture: Box::new(rows.capture(&target, b"GET /a HTTP/1.1\r\n\r\n", None, None, Some(PENDING))),
            reply,
        });
        let written = batch.write(&mut store);
        let id = id.blocking_recv().unwrap().unwrap();
        assert!(written.completed.is_empty() && written.failed == 0);
        assert_eq!(written.created, vec![id]);
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let done = rows.capture(&target, b"GET /a HTTP/1.1\r\n\r\n", Some(resp), Some(3), None);
        batch.push(RowWrite::Complete { id, capture: Box::new(done) });
        // A completion of a row that doesn't exist fails alone.
        batch.push(RowWrite::Complete { id: 99, capture: Box::default() });
        let written = batch.write(&mut store);
        assert_eq!((written.completed, written.failed), (vec![id], 1));
        let item = store.get(id).unwrap();
        assert_eq!((item.entry.status, item.entry.error), (Some(200), None));
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
