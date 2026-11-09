//! Live mode: while the proxy runs, each in-scope request it records that carries
//! credentials, uses a safe method, isn't a logout and got a 2xx response that isn't a
//! static asset is also tested in the background as other identities, all under one
//! authz run. Proxied traffic never waits for it: requests go through a bounded queue
//! and are dropped (and counted) when it is full, and each method, URL and body is
//! tested once.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Value};
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinSet;

use super::{has_credentials, AuthzConfig, AuthzTarget, Queue, Recorder, Tester, Writer, SAFE_METHODS};
use crate::auth::AuthProfile;
use crate::error::Result;
use crate::http::{RawRequest, Target};
use crate::jobs::JobControl;

/// How long tests already under way may finish once the proxy stops.
const GRACE: Duration = Duration::from_secs(2);

/// Requests remembered as tested. Past this the memory starts over, so a long-running
/// proxy stays small; the cost is testing some requests again.
const MAX_SEEN: usize = 100_000;

/// Content types and, when the response doesn't say, path extensions of static assets:
/// in a browser session they all carry the session cookie and would fill the queue.
const STATIC_TYPE_PREFIXES: &[&str] =
    &["image/", "font/", "audio/", "video/", "application/font", "application/x-font"];
const STATIC_TYPES: &[&str] = &[
    "text/css",
    "text/javascript",
    "text/ecmascript",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/wasm",
    "application/vnd.ms-fontobject",
];
const STATIC_EXTENSIONS: &[&str] = &[
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "woff", "woff2", "ttf",
    "otf", "eot", "mp3", "mp4", "webm", "wasm",
];

/// Whether a response is a static asset, by its content type or, without a useful one,
/// the extension of the path.
fn is_static(content_type: Option<&str>, path: &str) -> bool {
    let kind = content_type.unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if STATIC_TYPES.contains(&kind.as_str()) || STATIC_TYPE_PREFIXES.iter().any(|p| kind.starts_with(p)) {
        return true;
    }
    (kind.is_empty() || kind == "application/octet-stream")
        && path
            .rsplit('/')
            .next()
            .and_then(|name| name.rsplit_once('.'))
            .is_some_and(|(_, ext)| STATIC_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

/// Hashes of the requests already queued, of at most `max` entries.
struct Seen {
    set: HashSet<u64>,
    max: usize,
}

impl Seen {
    /// False when `key` is already there.
    fn insert(&mut self, key: u64) -> bool {
        if self.set.len() >= self.max && !self.set.contains(&key) {
            self.set.clear();
        }
        self.set.insert(key)
    }
}

pub struct LiveOptions {
    /// Requests waiting to be tested at most; more are dropped.
    pub queue: usize,
    /// Requests tested at once.
    pub concurrency: usize,
    /// Paths not tested (logging out would end the owner's session).
    pub exclude: Regex,
}

#[derive(Default)]
struct Counts {
    offered: AtomicU64,
    queued: AtomicU64,
    tested: AtomicU64,
    dropped: AtomicU64,
    duplicates: AtomicU64,
    methods: AtomicU64,
    excluded: AtomicU64,
    no_credentials: AtomicU64,
    status: AtomicU64,
    assets: AtomicU64,
}

/// What the proxy offers recorded requests to. `offer` never blocks.
pub struct Live {
    run_id: i64,
    tx: tokio::sync::mpsc::Sender<AuthzTarget>,
    seen: Mutex<Seen>,
    exclude: Regex,
    profiles: Vec<AuthProfile>,
    counts: Counts,
    tester: Arc<Tester>,
    ctl: JobControl,
}

/// The background worker; `finish` ends it once the proxy has stopped.
pub struct LiveWorker {
    live: Arc<Live>,
    task: tokio::task::JoinHandle<()>,
    shutdown: oneshot::Sender<()>,
    out: Queue,
    writer: Writer,
}

impl Live {
    /// Starts testing in the background under `run_id` (a job of kind `authz`). Needs a
    /// tokio runtime.
    pub fn start(
        project: &Path,
        run_id: i64,
        cfg: AuthzConfig,
        opts: LiveOptions,
        ctl: JobControl,
    ) -> Result<(Arc<Live>, LiveWorker)> {
        let (out, rows, writer) = super::writer(Recorder::open(project, run_id)?);
        let tester = Arc::new(Tester::new(cfg, ctl.clone(), rows)?);
        let (tx, rx) = tokio::sync::mpsc::channel(opts.queue.max(1));
        let live = Arc::new(Live {
            run_id,
            tx,
            seen: Mutex::new(Seen { set: HashSet::new(), max: MAX_SEEN }),
            exclude: opts.exclude,
            profiles: tester.profiles(),
            counts: Counts::default(),
            tester,
            ctl,
        });
        let (shutdown, stop_rx) = oneshot::channel();
        let task = tokio::spawn(work(live.clone(), rx, out.clone(), opts.concurrency.max(1), stop_rx));
        live.progress();
        Ok((live.clone(), LiveWorker { live, task, shutdown, out, writer }))
    }

    pub fn run_id(&self) -> i64 {
        self.run_id
    }

    /// Queues a recorded request for testing unless it is one not to test, already
    /// tested, or the queue is full. `status` and `content_type` are its response's:
    /// without a 2xx there is no baseline to compare with (a WebSocket handshake, an
    /// error, a 304), and a later copy that gets one can still be tested.
    pub fn offer(
        &self,
        history_id: i64,
        target: &Target,
        request: &[u8],
        status: Option<u16>,
        content_type: Option<&str>,
    ) {
        if self.ctl.stopped() {
            return;
        }
        let c = &self.counts;
        c.offered.fetch_add(1, Ordering::Relaxed);
        let raw = RawRequest::from_bytes(request.to_vec());
        let Ok(head) = raw.head() else { return };
        let method = head.method.to_ascii_uppercase();
        let path = head.target.split('?').next().unwrap_or("/");
        // A GraphQL mutation is MUTATION whatever its method, so one sent as GET isn't tested.
        // Only a request with a safe method is read for one: the others are skipped anyway.
        let unsafe_method =
            !SAFE_METHODS.contains(&method.as_str()) || crate::apiimport::graphql::is_mutation_request(request);
        let skip = if unsafe_method {
            Some(&c.methods)
        } else if self.exclude.is_match(path) {
            Some(&c.excluded)
        } else if !has_credentials(request, &self.profiles) {
            Some(&c.no_credentials)
        } else if status.is_none_or(|s| !(200..300).contains(&s)) {
            Some(&c.status)
        } else if is_static(content_type, path) {
            Some(&c.assets)
        } else {
            None
        };
        if let Some(n) = skip {
            n.fetch_add(1, Ordering::Relaxed);
            self.progress();
            return;
        }
        let key = {
            let mut h = DefaultHasher::new();
            (target.origin(), &method, &head.target, raw.body()).hash(&mut h);
            h.finish()
        };
        if !self.seen.lock().unwrap().insert(key) {
            c.duplicates.fetch_add(1, Ordering::Relaxed);
            self.progress();
            return;
        }
        let t = AuthzTarget { history_id: Some(history_id), target: target.clone(), request: request.to_vec() };
        if self.tx.try_send(t).is_ok() {
            c.queued.fetch_add(1, Ordering::Relaxed);
        } else {
            // Not tested, so a later copy may be.
            c.dropped.fetch_add(1, Ordering::Relaxed);
            self.seen.lock().unwrap().set.remove(&key);
        }
        self.progress();
    }

    /// Counts so far, as stored in the job's progress.
    pub fn stats(&self) -> Value {
        let c = &self.counts;
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let queued = n(&c.queued);
        let tested = n(&c.tested);
        json!({
            "identities": self.tester.identities(),
            "offered": n(&c.offered),
            "queued": queued,
            "tested": tested,
            "waiting": queued.saturating_sub(tested),
            "dropped_queue_full": n(&c.dropped),
            "duplicates": n(&c.duplicates),
            "skipped_methods": n(&c.methods),
            "skipped_excluded_paths": n(&c.excluded),
            "skipped_no_credentials": n(&c.no_credentials),
            "skipped_status": n(&c.status),
            "skipped_static": n(&c.assets),
            "sent": self.tester.sent(),
        })
    }

    fn progress(&self) {
        self.ctl.set_progress(self.stats());
    }
}

async fn work(
    live: Arc<Live>,
    mut rx: tokio::sync::mpsc::Receiver<AuthzTarget>,
    out: Queue,
    concurrency: usize,
    mut shutdown: oneshot::Receiver<()>,
) {
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut tests = JoinSet::new();
    loop {
        let t = tokio::select! {
            t = rx.recv() => match t { Some(t) => t, None => break },
            _ = &mut shutdown => break,
        };
        let permit = tokio::select! {
            p = sem.clone().acquire_owned() => p.expect("the semaphore is never closed"),
            _ = &mut shutdown => break,
        };
        let (live, out) = (live.clone(), out.clone());
        tests.spawn(async move {
            let _permit = permit;
            if live.ctl.stopped() {
                return;
            }
            let outcome = live.tester.test(&t).await;
            out.outcome(outcome);
            live.counts.tested.fetch_add(1, Ordering::Relaxed);
            live.progress();
        });
        while tests.try_join_next().is_some() {}
    }
    // Requests still queued are left untested; tests under way get a moment to finish.
    let deadline = tokio::time::sleep(GRACE);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            next = tests.join_next() => if next.is_none() { break },
            _ = &mut deadline => {
                tests.abort_all();
                break;
            }
        }
    }
}

impl LiveWorker {
    /// Ends the worker (call once the proxy no longer offers requests) and returns the
    /// run's summary.
    pub async fn finish(self) -> Result<Value> {
        let _ = self.shutdown.send(());
        let _ = self.task.await;
        let live = self.live;
        let mut v = live.stats();
        // With the worker gone, nothing writes any more.
        let recorder = super::join_writer(self.out, self.writer).await?;
        v["run_id"] = json!(live.run_id);
        v["verdicts"] = json!(recorder.verdicts());
        v["new_findings"] = json!(recorder.new_findings());
        v["stopped"] = json!(live.ctl.stopped());
        live.progress();
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_assets_by_type_or_extension() {
        assert!(is_static(Some("text/javascript; charset=utf-8"), "/app"));
        assert!(is_static(Some("IMAGE/PNG"), "/avatar"));
        assert!(is_static(Some("font/woff2"), "/f"));
        assert!(is_static(None, "/static/app.min.JS"));
        assert!(is_static(Some("application/octet-stream"), "/a/b.woff2"));
        assert!(!is_static(Some("application/json"), "/api/orders/1"));
        assert!(!is_static(Some("text/html"), "/report.png"));
        assert!(!is_static(None, "/api/orders/1"));
        assert!(!is_static(None, "/v1.2/orders"));
    }

    #[test]
    fn seen_stays_bounded() {
        let mut seen = Seen { set: HashSet::new(), max: 2 };
        assert!(seen.insert(1));
        assert!(seen.insert(2));
        assert!(!seen.insert(1), "already there, whether or not it is full");
        assert!(seen.insert(3), "a new one starts over");
        assert_eq!(seen.set.len(), 1);
    }
}
