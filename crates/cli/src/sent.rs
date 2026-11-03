//! History rows for requests the CLI sends itself (`send`, `send --race`, `ws send`). Each
//! row is written just before its request goes out and completed when the request is
//! answered or fails, so a request that went on the wire leaves a row even when the command
//! is cancelled, killed, or crashes: such a row keeps the [`PENDING`] error.
//!
//! With `--no-store` a row keeps no content: only the request line (method, URL), the time,
//! source, and target. The response is left out (no status, so passive checks skip it), and
//! the error says so, starting with [`NOT_STORED`], then how the request ended.

use std::path::Path;

use brainproxy_core::capture::Capture;
use brainproxy_core::http::client::final_response;
use brainproxy_core::http::{parse_response_head, Exchange, Target};
use brainproxy_core::store::Store;
use brainproxy_core::Error;

/// The error of a row whose request went out and whose outcome was never recorded.
pub(crate) const PENDING: &str = "sent; no response recorded (cancelled or interrupted)";
/// The error of a row whose command was stopped (Ctrl-C, SIGTERM, the app's Stop) while it waited.
pub(crate) const CANCELLED: &str = "cancelled by user after the request was sent";
/// How a `--no-store` row's error starts.
pub(crate) const NOT_STORED: &str = "not stored (--no-store): content omitted";

/// The error a command returns when it was stopped after sending.
pub(crate) fn cancelled(ids: &[i64]) -> Error {
    let message = if ids.is_empty() {
        "cancelled by user before anything was sent".to_string()
    } else {
        let rows = ids.iter().map(|id| format!("#{id}")).collect::<Vec<_>>().join(", ");
        format!("{CANCELLED} (history {rows})")
    };
    Error::Io(std::io::Error::new(std::io::ErrorKind::Interrupted, message))
}

pub(crate) struct SentLog {
    pub(crate) store: Store,
    source: &'static str,
    no_store: bool,
}

impl SentLog {
    pub(crate) fn open(project: &Path, source: &'static str, no_store: bool) -> Result<Self, Error> {
        Ok(Self::new(Store::open(project)?, source, no_store))
    }

    pub(crate) fn new(store: Store, source: &'static str, no_store: bool) -> Self {
        Self { store, source, no_store }
    }

    pub(crate) fn no_store(&self) -> bool {
        self.no_store
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
        let ms = duration_ms.map(|d| d as i64);
        if !self.no_store {
            return Capture::new(self.source, target, request, response, ms, error);
        }
        let status = response.and_then(|r| parse_response_head(final_response(r)).ok()).map(|h| h.status);
        let note = match (error, status) {
            (Some(e), _) => format!("{NOT_STORED}; {e}"),
            (None, Some(s)) => format!("{NOT_STORED}; response status {s}"),
            (None, None) => NOT_STORED.to_string(),
        };
        Capture::new(self.source, target, &request_line(request), None, ms, Some(&note))
    }

    /// Records `request` as about to go out; returns its row.
    pub(crate) fn pending(&mut self, target: &Target, request: &[u8]) -> Result<i64, Error> {
        self.store.record(&self.capture(target, request, None, None, Some(PENDING)))
    }

    /// Records `n` copies of `request` as about to go out, in one transaction.
    pub(crate) fn pending_many(&mut self, target: &Target, request: &[u8], n: usize) -> Result<Vec<i64>, Error> {
        let c = self.capture(target, request, None, None, Some(PENDING));
        self.store.record_batch(&vec![c; n])
    }

    /// Completes row `id`; returns the capture it now holds.
    pub(crate) fn complete(
        &mut self,
        id: i64,
        target: &Target,
        request: &[u8],
        response: Option<&[u8]>,
        duration_ms: Option<u64>,
        error: Option<&str>,
    ) -> Result<Capture, Error> {
        let c = self.capture(target, request, response, duration_ms, error);
        self.store.update_capture(id, &c)?;
        Ok(c)
    }

    pub(crate) fn answered(&mut self, id: i64, ex: &Exchange) -> Result<(), Error> {
        self.complete(id, &ex.target, &ex.request, Some(&ex.response), Some(ex.duration_ms), None).map(drop)
    }

    pub(crate) fn failed(&mut self, id: i64, target: &Target, request: &[u8], error: &str) -> Result<(), Error> {
        self.complete(id, target, request, None, None, Some(error)).map(drop)
    }

    /// Runs the passive checks on rows `ids` (now complete) and anything else new; returns
    /// the new findings. Nothing for `--no-store` rows, which keep no response.
    pub(crate) fn scan(&mut self, ids: &[i64]) -> Result<usize, Error> {
        if self.no_store {
            return Ok(0);
        }
        let mut new = 0;
        // Rows a passive scan elsewhere skipped while they were waiting for their response.
        for id in ids {
            new += brainproxy_core::scan::passive::scan_late(&mut self.store, *id)?;
        }
        Ok(new + brainproxy_core::scan::passive::scan_pending(&mut self.store)?.new_findings)
    }
}

/// The request line alone, as a request without headers or body.
fn request_line(request: &[u8]) -> Vec<u8> {
    let line = request.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    [line, b"\r\n\r\n"].concat()
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
        assert_eq!(item.request, b"POST /login?next=/home HTTP/1.1\r\n\r\n");
        assert!(item.response.is_empty());
        assert_eq!((item.entry.method.as_str(), item.entry.url.as_str()), ("POST", "http://a.test/login?next=/home"));
        assert_eq!(item.entry.status, None);
        assert_eq!(item.entry.error.as_deref(), Some("not stored (--no-store): content omitted; response status 302"));
        assert_eq!(item.entry.duration_ms, Some(12));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
