//! Active scanner. Rules are ported from OWASP ZAP's ascanrules add-on
//! (https://github.com/zaproxy/zap-extensions, Apache License 2.0); each rule
//! file names the ZAP class it came from.
//!
//! Every request goes through the HTTP client and therefore the engagement scope
//! guard. Every request a rule or declarative check (`--checks`) sends is recorded in
//! history (source "scan"), finding or not: its row is written just before it goes out and
//! completed when it is answered or fails (see `crate::sent::Rows`). A check's request
//! whose method isn't opted in (`ActiveConfig::check_methods`) is not sent.
//!
//! Out-of-band checks register their payloads (`Cx::oob_payload`/`oob_register`);
//! after the last unit, `run` waits up to `ActiveConfig::oob_wait` while
//! correlating interactions the OOB listener received (see `crate::oob`).

pub mod points;
pub mod policy;
pub mod rules;
pub mod source_sink;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::auth::AuthSession;
use crate::capture::{decode_body, Capture};
use crate::error::{Error, Result};
use crate::http::client::HostPolicy;
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use crate::jobs::JobControl;
use crate::oob::{self, Endpoint, Payload, ScanPayload};
use crate::rules::{Engine, EngineRules, Ruled};
use crate::scan::active::source_sink::{Sink, SourceSink};
use crate::scan::{AlertDef, Finding, Message};
use crate::sent::{RowBatch, RowWrite, Rows};
use crate::session::Tool;
use crate::store::Store;
pub use points::{InsertionPoint, PointKind, PointOptions};
pub use policy::{Threshold, Tuning};

/// How many attacks a rule tries (ZAP attack strength).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Strength {
    Low,
    Medium,
    High,
    Insane,
}

/// What one invocation of a rule covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleScope {
    /// Once per insertion point of each target request (ZAP AbstractAppParamPlugin).
    Param,
    /// Once per target request (ZAP AbstractAppPlugin).
    Page,
    /// Once per scheme://host:port (ZAP AbstractHostPlugin).
    Host,
}

pub type BoxFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

pub trait ActiveRule: Send + Sync {
    /// ZAP plugin id.
    fn id(&self) -> u32;
    fn name(&self) -> &'static str;
    fn alerts(&self) -> &'static [&'static AlertDef];
    fn scope(&self) -> RuleScope;
    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a>;
    /// Rules this one needs (ZAP `getDependency`): selected along with it, it is
    /// skipped when one of them is excluded, and its units start only once every
    /// unit of those rules has finished.
    fn depends_on(&self) -> &'static [u32] {
        &[]
    }
    /// Start order, lowest first: units that may run long start early, so the
    /// scan doesn't end waiting on one of them.
    fn order(&self) -> u8 {
        match self.scope() {
            RuleScope::Param => 1,
            _ => 2,
        }
    }
}

impl std::fmt::Debug for dyn ActiveRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A response received during scanning.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// e.g. "HTTP/1.1 200 OK" (ZAP's prime header).
    pub status_line: String,
    pub headers: Vec<(String, String)>,
    /// Decoded body.
    pub body: Vec<u8>,
    pub duration: Duration,
    /// The request as sent and the response as received.
    pub request: Vec<u8>,
    pub raw: Vec<u8>,
    /// The history row already holding this exchange (a declarative check's request).
    history_id: Option<i64>,
    /// The response as the server sent it, when a match-and-replace rule changed what the scan
    /// rule reads (`raw` and the rest are then the response after it).
    received: Option<Vec<u8>>,
    text: OnceLock<String>,
}

impl Response {
    pub(crate) fn parse(request: Vec<u8>, raw: Vec<u8>, duration: Duration) -> Result<Self> {
        let mut start = 0;
        while let Ok(h) = parse_response_head(&raw[start..]) {
            if (100..200).contains(&h.status) && h.status != 101 {
                start += split_head_body(&raw[start..]).0.len();
            } else {
                break;
            }
        }
        let fin = &raw[start..];
        let head = parse_response_head(fin)?;
        let body = decode_body(&head.headers, split_head_body(fin).1);
        let status_line =
            String::from_utf8_lossy(fin.split(|&b| b == b'\r' || b == b'\n').next().unwrap_or_default()).into_owned();
        Ok(Self {
            status: head.status,
            status_line,
            headers: head.headers,
            body,
            duration,
            request,
            raw,
            history_id: None,
            received: None,
            text: OnceLock::new(),
        })
    }

    /// A recorded response (passive checks), from its parts; the body is decoded.
    pub(crate) fn recorded(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            status_line: format!("HTTP/1.1 {status}"),
            headers,
            body,
            duration: Duration::ZERO,
            request: Vec::new(),
            raw: Vec::new(),
            history_id: None,
            received: None,
            text: OnceLock::new(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The response as the server sent it: what a session goes by.
    fn received(&self) -> &[u8] {
        self.received.as_deref().unwrap_or(&self.raw)
    }

    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers.iter().filter(move |(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The response head as text (status line and headers), like ZAP's
    /// `getResponseHeader().toString()`.
    pub fn head_text(&self) -> String {
        let mut s = self.status_line.clone();
        s.push_str("\r\n");
        for (k, v) in &self.headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        s.push_str("\r\n");
        s
    }

    /// Decoded body as text (lossy UTF-8).
    pub fn body_str(&self) -> &str {
        self.text.get_or_init(|| String::from_utf8_lossy(&self.body).into_owned())
    }

    pub fn content_type(&self) -> String {
        self.header("content-type").unwrap_or("").to_ascii_lowercase()
    }
}

/// The request a rule is attacking, with its original (baseline) response.
pub struct Base {
    pub history_id: Option<i64>,
    pub target: Target,
    pub request: Vec<u8>,
    pub msg: Message,
    pub response: Response,
}

enum Report {
    Finding {
        target: Target,
        finding: Finding,
        /// The row that already holds the exchange; None records it now.
        history_id: Option<i64>,
        request: Vec<u8>,
        response: Vec<u8>,
        duration_ms: i64,
    },
    /// A request's row, written before it goes out and completed after (see [`Rows`]).
    Row(RowWrite),
    Oob {
        target: Target,
        token: String,
        finding: Finding,
        request: Vec<u8>,
        response: Option<Vec<u8>>,
        duration_ms: Option<i64>,
        /// The attack's row.
        history_id: Option<i64>,
        check: Option<String>,
    },
}

struct Shared {
    client: Client,
    /// Every request's row, written by the recorder thread.
    rows: Rows,
    auth: Option<Arc<AuthSession>>,
    strength: Strength,
    tuning: Tuning,
    ctl: JobControl,
    deadline: Option<Instant>,
    limiter: Option<Limiter>,
    requests: AtomicU64,
    reports: Mutex<mpsc::Sender<Report>>,
    raised: Mutex<BTreeMap<&'static str, usize>>,
    /// Findings not raised because their confidence was below their rule's threshold.
    below_threshold: Mutex<BTreeMap<&'static str, usize>>,
    /// Keys rules mark as done for the whole run (ZAP's knowledge base).
    once: Mutex<HashSet<String>>,
    /// Soft-404 signatures per origin: (status, body length bucket, body start).
    not_found: tokio::sync::Mutex<HashMap<String, Option<(u16, String)>>>,
    oob: Option<Endpoint>,
    /// The endpoint per target origin (see `Endpoint::for_target`).
    oob_by_origin: Mutex<HashMap<String, Endpoint>>,
    oob_payloads: AtomicU64,
    /// Stored-input tracking for the persistent XSS rules.
    source_sink: Mutex<SourceSink>,
    /// Per origin: no requests before this time (the server asked us to slow down).
    paused: Mutex<HashMap<String, Instant>>,
    /// Responses to requests several checks send alike (see `Cx::send_once`).
    sent_once: Mutex<HashMap<Vec<u8>, SentOnce>>,
    /// See `ActiveConfig::check_methods`.
    check_methods: Vec<String>,
    /// Check requests not sent because their method wasn't opted in.
    check_skipped_methods: AtomicU64,
    /// Match-and-replace rules that list scans, as they were when the scan started.
    match_rules: Option<EngineRules>,
}

/// One response shared by identical requests; an error is kept as its message.
type SentOnce = Arc<tokio::sync::OnceCell<std::result::Result<Response, String>>>;

/// Everything a rule needs for one unit of work.
pub struct Cx {
    base: Arc<Base>,
    point: Option<InsertionPoint>,
    shared: Arc<Shared>,
    /// The rule's strength and threshold in this scan.
    strength: Strength,
    threshold: Threshold,
    /// Which session rules apply: a ported rule's (scan) or a declarative check's (checks).
    tool: Tool,
    /// The rows of this unit's requests that failed, by the request as the rule gave it: an
    /// out-of-band attack without a response is registered with its row (`oob_register`).
    failed: Mutex<HashMap<Vec<u8>, i64>>,
}

impl Cx {
    pub fn base(&self) -> &Message {
        &self.base.msg
    }

    pub fn base_response(&self) -> &Response {
        &self.base.response
    }

    pub fn base_request(&self) -> &[u8] {
        &self.base.request
    }

    pub fn target(&self) -> &Target {
        &self.base.target
    }

    /// The insertion point under attack (Param-scoped rules only).
    pub fn point(&self) -> &InsertionPoint {
        self.point.as_ref().expect("point() is only available to Param-scoped rules")
    }

    pub fn strength(&self) -> Strength {
        self.strength
    }

    /// Whether a finding of this confidence passes the rule's threshold; one that doesn't is
    /// counted, not raised.
    fn passes(&self, finding: &Finding, confidence: crate::scan::Confidence) -> bool {
        let ok = self.threshold.passes(confidence);
        if !ok {
            *self.shared.below_threshold.lock().unwrap().entry(finding.def.alert_ref).or_default() += 1;
        }
        ok
    }

    /// True once the scan was asked to stop or ran out of time; rules should return.
    pub fn stopped(&self) -> bool {
        self.shared.ctl.stopped() || self.shared.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// Returns true the first time `key` is seen in this run (ZAP's Kb checks),
    /// so work shared between targets (e.g. a file per directory) is done once.
    pub fn once(&self, key: &str) -> bool {
        self.shared.once.lock().unwrap().insert(key.to_string())
    }

    /// Sends the base request with the insertion point set to `value`, escaped
    /// for its context (ZAP setParameter).
    pub async fn send_payload(&self, value: &str) -> Result<Response> {
        self.send(points::inject(&self.base.request, self.point(), value, true)).await
    }

    /// Like `send_payload` but `value` is inserted without escaping (ZAP setEscapedParameter).
    pub async fn send_payload_raw(&self, value: &str) -> Result<Response> {
        self.send(points::inject(&self.base.request, self.point(), value, false)).await
    }

    /// The base request rebuilt as `method path_and_query` with the same headers
    /// and no body (for rules that request other paths on the same host).
    pub fn request_for(&self, method: &str, path_and_query: &str) -> Vec<u8> {
        let req = RawRequest::from_bytes(self.base.request.clone());
        let (head, _) = req.split();
        let head = String::from_utf8_lossy(head);
        let mut lines = head.trim_end_matches("\r\n").split("\r\n");
        let version = lines.next().and_then(|l| l.rsplit(' ').next()).unwrap_or("HTTP/1.1").to_string();
        let mut out = format!("{method} {path_and_query} {version}\r\n");
        for l in lines {
            let name = l.split(':').next().unwrap_or("").trim();
            if !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("content-type")
                && !name.eq_ignore_ascii_case("transfer-encoding")
            {
                out.push_str(l);
                out.push_str("\r\n");
            }
        }
        out.push_str("\r\n");
        out.into_bytes()
    }

    /// Sends a raw request to the base target.
    pub async fn send(&self, request: Vec<u8>) -> Result<Response> {
        let target = self.base.target.clone();
        self.send_to(&target, request).await
    }

    /// Sends a raw request to another target (e.g. the same host over http).
    /// Still subject to the engagement scope.
    /// A 429, or a 503 with Retry-After, pauses every request to that origin for
    /// the time asked (5 s without one, at most 60 s); the request is then sent once more.
    pub async fn send_to(&self, target: &Target, request: Vec<u8>) -> Result<Response> {
        let origin = target.origin();
        let mut retried = false;
        loop {
            let until = self.shared.paused.lock().unwrap().get(&origin).copied();
            while until.is_some_and(|u| Instant::now() < u) && !self.stopped() {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            let resp = self.send_to_once(target, request.clone()).await?;
            let retry_after = resp.header("retry-after").map(|v| v.trim().parse::<u64>().unwrap_or(5));
            if retried || !(resp.status == 429 || resp.status == 503 && retry_after.is_some()) {
                return Ok(resp);
            }
            let wait = Duration::from_secs(retry_after.unwrap_or(5).clamp(1, 60));
            let mut paused = self.shared.paused.lock().unwrap();
            let until = paused.entry(origin.clone()).or_insert_with(Instant::now);
            *until = (*until).max(Instant::now() + wait);
            retried = true;
        }
    }

    async fn send_to_once(&self, target: &Target, request: Vec<u8>) -> Result<Response> {
        self.rate_turn().await?;
        self.shared.requests.fetch_add(1, Ordering::Relaxed);
        // Match-and-replace rules that list scans see the request as the scan rule made it; the
        // session is applied to what they leave.
        let given = request;
        let ruled = match &self.shared.match_rules {
            Some(rules) => Some(rules.request(self.shared.client.options(), target, given.clone())?),
            None => None,
        };
        let request = ruled.as_ref().map_or(&given, |r| &r.bytes);
        let Some(auth) = &self.shared.auth else {
            return self.client_send(request.clone(), target, &given, ruled.as_ref()).await;
        };
        // The attacked cookie or parameter keeps its payload.
        let (cookie, param): (Vec<&str>, Vec<&str>) = match &self.point {
            Some(p) if p.kind == PointKind::Cookie => (vec![p.name.as_str()], vec![]),
            Some(p) => (vec![], vec![p.session_name()]),
            None => (vec![], vec![]),
        };
        let prepared = auth.prepare(self.tool, target, request, &cookie, &param).await;
        let mut resp = self.client_send(prepared.request.clone(), target, &given, ruled.as_ref()).await?;
        if auth.after_response(&prepared, resp.received()).await {
            let again = auth.prepare(self.tool, target, request, &cookie, &param).await;
            resp = self.client_send(again.request, target, &given, ruled.as_ref()).await?;
            auth.observe(resp.received());
        }
        Ok(resp)
    }

    /// Sends `request` with the client, recorded just before it goes out and completed when
    /// it is answered or fails (a request that times out, or a scan that stops, leaves it
    /// saying so). A declarative check's request whose method isn't opted in is refused,
    /// unsent. `given` is the request as the rule gave it (before match-and-replace rules and
    /// the session were applied), and `ruled` what the match-and-replace rules made of it.
    async fn client_send(
        &self,
        request: Vec<u8>,
        target: &Target,
        given: &[u8],
        ruled: Option<&Ruled>,
    ) -> Result<Response> {
        let req = RawRequest::from_bytes(request);
        let client = &self.shared.client;
        let out_of_scope = client.options().guard.as_ref().is_some_and(|g| !g.may_allow(&target.host, target.port));
        // As for the targets the ported rules attack. Out of scope, the client refuses it
        // before anything is sent.
        use crate::apiimport::api::{missing_opt_in, DEFAULT_METHODS};
        let opt_in = missing_opt_in(req.as_bytes(), DEFAULT_METHODS, &self.shared.check_methods);
        if let Some(opt_in) = opt_in.filter(|_| self.tool == Tool::Checks && !out_of_scope) {
            self.shared.check_skipped_methods.fetch_add(1, Ordering::Relaxed);
            return Err(Error::InvalidInput(format!(
                "a check's {opt_in} request isn't sent without --include-methods {opt_in}"
            )));
        }
        let by = self.shared.match_rules.as_ref().zip(ruled);
        let (id, result, response) = self.shared.rows.send_ruled(client, &req, target, by).await;
        let ex = match result {
            Ok(ex) => ex,
            Err(e) => {
                if let Some(id) = id {
                    self.failed.lock().unwrap().insert(given.to_vec(), id);
                }
                return Err(e);
            }
        };
        // The scan rule reads the response after the match-and-replace rules; the session goes
        // by the one received.
        let duration = Duration::from_millis(ex.duration_ms);
        let mut resp = match response.filter(Ruled::changed) {
            Some(ruled) => {
                let mut resp = Response::parse(ex.request, ruled.bytes, duration)?;
                resp.received = Some(ex.response);
                resp
            }
            None => Response::parse(ex.request, ex.response, duration)?,
        };
        resp.history_id = id;
        Ok(resp)
    }

    /// Runs `send` once per scan for `key` (with the target added): later callers,
    /// and ones already waiting, get the same response. For side-effect-free
    /// requests that several checks send byte for byte alike.
    pub(crate) async fn send_once(&self, key: &[u8], send: impl Future<Output = Result<Response>>) -> Result<Response> {
        let mut k = self.base.target.origin().into_bytes();
        k.push(0);
        k.extend_from_slice(key);
        let cell = self.shared.sent_once.lock().unwrap().entry(k).or_default().clone();
        cell.get_or_init(|| async { send.await.map_err(|e| e.to_string()) }).await.clone().map_err(Error::Protocol)
    }

    /// Waits for this request's turn under `--rate`. With many units queued at a slow
    /// rate a turn can be far off, so the wait ends early, with an error, when the scan
    /// stops or reaches `--max-minutes`.
    async fn rate_turn(&self) -> Result<()> {
        let stopped = || Err(Error::Protocol("scan stopped".into()));
        if self.stopped() {
            return stopped();
        }
        if let Some(l) = &self.shared.limiter {
            let at = l.slot().await;
            while Instant::now() < at {
                if self.stopped() {
                    return stopped();
                }
                tokio::time::sleep_until(at.min(Instant::now() + Duration::from_millis(250)).into()).await;
            }
            if self.stopped() {
                return stopped();
            }
        }
        Ok(())
    }

    /// A raw TCP connection to `host:port` for rules that speak another protocol
    /// (e.g. TLS records). Goes through the client, so the engagement scope applies.
    pub async fn connect_raw(&self, host: &str, port: u16) -> Result<crate::http::client::Stream> {
        self.rate_turn().await?;
        self.shared.requests.fetch_add(1, Ordering::Relaxed);
        self.shared.client.connect(&Target { scheme: "http".into(), host: host.into(), port }).await
    }

    /// Sends a request and follows up to 5 redirects with GETs (ZAP's default
    /// `sendAndReceive(msg)`); returns the final response. Redirects outside the
    /// engagement scope end with an out-of-scope error.
    pub async fn send_following(&self, request: Vec<u8>) -> Result<Response> {
        let target = self.base.target.clone();
        self.send_following_to(&target, request).await
    }

    /// `send_following` for a request to another target (still in scope).
    pub async fn send_following_to(&self, target: &Target, request: Vec<u8>) -> Result<Response> {
        let mut target = target.clone();
        let mut resp = self.send_to(&target, request).await?;
        for _ in 0..5 {
            if !matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(loc) = resp.header("location").map(str::to_string) else { break };
            let current = url::Url::parse(&format!("{}{}", target.origin(), self.path_of(&resp.request)))
                .map_err(|e| Error::Protocol(e.to_string()))?;
            let next = current.join(&loc).map_err(|e| Error::Protocol(format!("bad redirect {loc:?}: {e}")))?;
            target = Target::from_url(next.as_str())?;
            let mut pq = next.path().to_string();
            if let Some(q) = next.query() {
                pq.push('?');
                pq.push_str(q);
            }
            let req = RawRequest::from_bytes(self.request_for("GET", &pq)).set_header("Host", &target.host_header());
            resp = self.send_to(&target, req.into_bytes()).await?;
        }
        Ok(resp)
    }

    fn path_of(&self, request: &[u8]) -> String {
        RawRequest::from_bytes(request.to_vec()).head().map(|h| h.target).unwrap_or_else(|_| "/".into())
    }

    /// Whether a response is a "not found" page: a 404, or a page that looks like
    /// what this host returns for a random path (soft 404).
    pub async fn not_found(&self, resp: &Response) -> bool {
        if resp.status == 404 {
            return true;
        }
        let origin = self.base.target.origin();
        let mut cache = self.shared.not_found.lock().await;
        if !cache.contains_key(&origin) {
            let probe = format!("/brainproxy-{:x}/{:x}.html", rand_u64(), rand_u64());
            let sig = match self.send(self.request_for("GET", &probe)).await {
                Ok(r) if r.status != 404 => Some((r.status, signature(&r))),
                _ => None,
            };
            cache.insert(origin.clone(), sig);
        }
        matches!(cache.get(&origin), Some(Some((status, sig))) if *status == resp.status && *sig == signature(resp))
    }

    /// Records a finding with the exchange that proves it.
    pub fn report(&self, finding: Finding, resp: &Response) {
        if !self.passes(&finding, finding.confidence) {
            return;
        }
        *self.shared.raised.lock().unwrap().entry(finding.def.alert_ref).or_default() += 1;
        let _ = self.shared.reports.lock().unwrap().send(Report::Finding {
            target: self.base.target.clone(),
            finding,
            history_id: resp.history_id,
            request: resp.request.clone(),
            response: resp.raw.clone(),
            duration_ms: resp.duration.as_millis() as i64,
        });
    }

    /// A unique marker value for the attacked parameter, remembered as stored input
    /// from this request (ZAP `SourceSinkUtils.getUniqueValue`).
    pub fn source_value(&self) -> String {
        let key = source_sink::source_key(&self.base.msg.url, &self.point().name);
        self.shared.source_sink.lock().unwrap().unique_value(key)
    }

    /// Records the base request as a sink for every marker in `resp` (ZAP `testForSink`).
    pub fn test_for_sink(&self, resp: &Response) {
        let sink = Sink { target: self.base.target.clone(), request: self.base.request.clone() };
        self.shared.source_sink.lock().unwrap().test_for_sink(resp.body_str(), &sink);
    }

    /// Pages that displayed input stored through the attacked parameter.
    pub fn sinks(&self) -> Vec<Sink> {
        let key = source_sink::source_key(&self.base.msg.url, &self.point().name);
        self.shared.source_sink.lock().unwrap().sinks(&key)
    }

    /// A fresh out-of-band payload, or None when no OOB listener is running
    /// (rules then skip their out-of-band checks, like ZAP without OAST).
    pub fn oob_payload(&self) -> Option<Payload> {
        let base = self.shared.oob.as_ref()?;
        let t = &self.base.target;
        let ep = self
            .shared
            .oob_by_origin
            .lock()
            .unwrap()
            .entry(t.origin())
            .or_insert_with(|| base.for_target(&t.host, t.port))
            .clone();
        ep.payload().ok()
    }

    /// The base request with the insertion point set to `value` (escaped), for
    /// rules that need the attack request before sending it.
    pub fn payload_request(&self, value: &str) -> Vec<u8> {
        points::inject(&self.base.request, self.point(), value, true)
    }

    /// Registers the attack that carried `payload`: an interaction with its token
    /// later raises `finding` (evidence and other info are filled in then).
    /// `request` is the attack as built; the sent request and the response are
    /// taken from `resp` when the attack got one.
    pub fn oob_register(&self, payload: &Payload, finding: Finding, request: &[u8], resp: Option<&Response>) {
        self.oob_register_check(payload, finding, request, resp, None);
    }

    /// `oob_register` for a declarative check: `check` (JSON) holds its alert
    /// and the interactsh matchers an interaction must pass.
    pub(crate) fn oob_register_check(
        &self,
        payload: &Payload,
        finding: Finding,
        request: &[u8],
        resp: Option<&Response>,
        check: Option<String>,
    ) {
        // A callback raises the alert at its own confidence.
        if !self.passes(&finding, finding.def.confidence) {
            return;
        }
        self.shared.oob_payloads.fetch_add(1, Ordering::Relaxed);
        // The attack's row: the one its response came from, or the one of the attack that
        // failed. Correlating then records no second row for it.
        let history_id = match resp {
            Some(r) => r.history_id,
            None => self.failed.lock().unwrap().remove(request),
        };
        let _ = self.shared.reports.lock().unwrap().send(Report::Oob {
            check,
            target: self.base.target.clone(),
            token: payload.token.clone(),
            finding,
            request: resp.map_or_else(|| request.to_vec(), |r| r.request.clone()),
            response: resp.map(|r| r.raw.clone()),
            duration_ms: resp.map(|r| r.duration.as_millis() as i64),
            history_id,
        });
    }
}

/// The error a scan request's row keeps if it is given up unanswered.
const ABANDONED: &str = "sent; no response recorded (the check timed out or the scan stopped)";

/// The most reports the recorder takes off its queue before writing the rows among them.
const ROW_BATCH: usize = 512;

/// Records a finding (with its exchange's row, if it has none yet) or an out-of-band
/// payload; returns the new findings.
fn record_report(store: &mut Store, r: Report) -> Result<usize> {
    match r {
        Report::Finding { target, finding, history_id, request, response, duration_ms } => {
            let id = match history_id {
                Some(id) => id,
                None => {
                    store.record(&Capture::new("scan", &target, &request, Some(&response), Some(duration_ms), None))?
                }
            };
            let msg = Message::from_exchange(id, &target, &request, &response);
            store.record_findings("active", &msg, std::slice::from_ref(&finding))
        }
        Report::Oob { target, token, finding, request, response, duration_ms, history_id, check } => {
            store.oob_add_scan_payload(&ScanPayload {
                token: &token,
                alert_ref: finding.def.alert_ref,
                rule_id: finding.def.alert_ref.split('-').next().and_then(|s| s.parse().ok()).unwrap_or(0),
                param: &finding.param,
                attack: &finding.attack,
                other_info: &finding.other_info,
                target: &target,
                request: &request,
                response: response.as_deref(),
                duration_ms,
                history_id,
                check: check.as_deref(),
            })?;
            Ok(0)
        }
        Report::Row(_) => unreachable!("rows are written in batches"),
    }
}

fn signature(r: &Response) -> String {
    // Length bucket plus the first 64 bytes: robust to small dynamic parts.
    format!("{}:{}", r.body.len() / 64, String::from_utf8_lossy(&r.body[..r.body.len().min(64)]))
}

fn rand_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    h.finish()
}

/// Spaces requests evenly across all tasks sharing it (also used by the crawler).
pub(crate) struct Limiter {
    interval: Duration,
    next: tokio::sync::Mutex<Instant>,
}

impl Limiter {
    /// None when there is no limit (no rate, or not positive).
    pub(crate) fn new(rate: Option<f64>) -> Option<Limiter> {
        rate.filter(|r| *r > 0.0).map(|r| Limiter {
            interval: Duration::from_secs_f64(1.0 / r),
            next: tokio::sync::Mutex::new(Instant::now()),
        })
    }

    pub(crate) async fn wait(&self) {
        tokio::time::sleep_until(self.slot().await.into()).await;
    }

    /// Takes the next slot: when the caller may send.
    pub(crate) async fn slot(&self) -> Instant {
        let mut next = self.next.lock().await;
        let at = (*next).max(Instant::now());
        *next = at + self.interval;
        at
    }
}

/// The active rules' alert definition for `alert_ref`.
pub fn alert_def(alert_ref: &str) -> Option<&'static AlertDef> {
    all_rules().iter().flat_map(|r| r.alerts().iter().copied()).find(|a| a.alert_ref == alert_ref)
}

pub fn all_rules() -> &'static [Box<dyn ActiveRule>] {
    static RULES: OnceLock<Vec<Box<dyn ActiveRule>>> = OnceLock::new();
    RULES.get_or_init(rules::all)
}

#[derive(Debug, Clone)]
pub struct ActiveConfig {
    /// For every rule `tuning` gives no strength of its own.
    pub strength: Strength,
    /// Thresholds, and rules' own strengths (a scan policy's; see [`policy`]).
    pub tuning: Tuning,
    pub concurrency: usize,
    pub rate: Option<f64>,
    pub send: SendOptions,
    pub points: PointOptions,
    /// Only these rule ids (None: all).
    pub rules: Option<Vec<u32>>,
    pub exclude_rules: Vec<u32>,
    /// Skip the ported rules (run only `checks`).
    pub no_rules: bool,
    /// Declarative checks to run as well (see `crate::checks::into_rules`).
    pub checks: Vec<&'static dyn ActiveRule>,
    pub max_duration: Option<Duration>,
    /// Logged-in session applied to every request (an attacked cookie keeps its payload).
    pub auth: Option<Arc<AuthSession>>,
    /// Running OOB listener's public endpoint; None skips out-of-band checks.
    pub oob: Option<Endpoint>,
    /// How long to wait for out-of-band interactions after the last unit.
    pub oob_wait: Duration,
    /// Methods a declarative check may send besides GET, HEAD, OPTIONS and POST (upper
    /// case; MUTATION for a GraphQL mutation, ALL for anything): `--include-methods`.
    pub check_methods: Vec<String>,
    /// When the scan ends (also stopped with `job stop`, or timed out), delete the attack rows it wrote that
    /// back nothing (see [`Store::prune_unreferenced`]). Base requests are never its rows.
    pub prune: bool,
}

/// The project's active scan setting, `setting.active`: shared by the app and the CLI.
pub const SETTINGS_KEY: &str = "active";

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize, PartialEq)]
#[serde(default)]
pub struct ActiveSettings {
    /// Scans keep only the attack requests that back a finding (or anything else that refers
    /// to them): see [`ActiveConfig::prune`]. Off by default: every request is kept.
    pub prune: bool,
}

/// Out-of-band part of a scan.
#[derive(Debug, Clone, Serialize, Default)]
pub struct OobSummary {
    pub payloads: u64,
    /// Interactions correlated during this scan (any token).
    pub interactions: usize,
    /// Interactions that matched a scan payload and raised a finding hit.
    pub matched: usize,
    pub waited_ms: u64,
}

/// A request to attack, with its baseline response.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub history_id: Option<i64>,
    pub target: Target,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    /// Round-trip time of the baseline exchange, if known.
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ActiveSummary {
    pub targets: usize,
    pub insertion_points: usize,
    pub rules: usize,
    pub units: usize,
    pub units_done: usize,
    pub requests: u64,
    /// Findings raised in this run, per alert ref.
    pub raised: BTreeMap<String, usize>,
    /// Findings not raised, per alert ref, because their confidence was below their rule's
    /// threshold (see [`policy`]).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub below_threshold: BTreeMap<String, usize>,
    pub new_findings: usize,
    /// Rule units that crashed (panicked) instead of finishing.
    pub errors: usize,
    /// Check requests not sent because their method wasn't opted in (`check_methods`).
    pub check_skipped_methods: u64,
    /// Hosts the scope doesn't list that base requests named in their Host header, refused
    /// (through MCP without `--host-header-test`): those requests weren't attacked.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refused_hosts: Vec<String>,
    /// None when no OOB listener was running (out-of-band checks skipped).
    pub oob: Option<OobSummary>,
    /// Attack rows deleted at the end because nothing referred to them; None when the scan
    /// kept every request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruned: Option<usize>,
    /// Why pruning stopped before it was done; the rows it hadn't reached are kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prune_error: Option<String>,
    pub stopped: bool,
    pub timed_out: bool,
    pub elapsed_ms: u64,
}

/// Counts down a rule's units left when dropped.
struct Finished<'a>(&'a tokio::sync::watch::Sender<usize>);

impl Drop for Finished<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

/// The ported rules a scan runs for `rules` (None: all) less `exclude`: the rules the selected
/// ones depend on are pulled in unless excluded, and a rule missing one (excluded, or itself
/// dropped for that reason) is dropped.
pub fn select_rules(rules: Option<&[u32]>, exclude: &[u32]) -> Vec<&'static dyn ActiveRule> {
    let mut selected: Vec<&'static dyn ActiveRule> = all_rules()
        .iter()
        .map(|r| r.as_ref())
        .filter(|r| rules.is_none_or(|ids| ids.contains(&r.id())) && !exclude.contains(&r.id()))
        .collect();
    loop {
        let ids: HashSet<u32> = selected.iter().map(|r| r.id()).collect();
        let missing: Vec<&'static dyn ActiveRule> = all_rules()
            .iter()
            .map(|r| r.as_ref())
            .filter(|r| !ids.contains(&r.id()) && !exclude.contains(&r.id()))
            .filter(|r| selected.iter().any(|sel| sel.depends_on().contains(&r.id())))
            .collect();
        if missing.is_empty() {
            break;
        }
        selected.extend(missing);
    }
    // Until nothing changes: dropping a rule can leave another without what it needs.
    loop {
        let ids: HashSet<u32> = selected.iter().map(|r| r.id()).collect();
        let before = selected.len();
        selected.retain(|r| r.depends_on().iter().all(|d| ids.contains(d)));
        if selected.len() == before {
            return selected;
        }
    }
}

/// The ids of [`select_rules`], in id order.
pub fn selected_rule_ids(rules: Option<&[u32]>, exclude: &[u32]) -> Vec<u32> {
    let mut ids: Vec<u32> = select_rules(rules, exclude).iter().map(|r| r.id()).collect();
    ids.sort_unstable();
    ids
}

/// One rule run on one target (and insertion point, for Param rules).
type Unit = (Arc<Base>, &'static dyn ActiveRule, Option<InsertionPoint>);

pub async fn run(
    project: &Path,
    targets: Vec<ScanTarget>,
    cfg: ActiveConfig,
    ctl: JobControl,
) -> Result<ActiveSummary> {
    let started = Instant::now();
    let mut rules = if cfg.no_rules { vec![] } else { select_rules(cfg.rules.as_deref(), &cfg.exclude_rules) };
    rules.extend(cfg.checks.iter().copied());
    // Session rules tell the ported rules (scan) from declarative checks (checks), and a policy
    // tunes ported rules only. A check is told by identity: every check's id is 0, as is
    // Directory Browsing's.
    let checks = cfg.checks.clone();
    let is_check = move |r: &'static dyn ActiveRule| checks.iter().any(|c| std::ptr::addr_eq(*c, r));
    if rules.is_empty() {
        return Err(Error::InvalidInput("no active rules or checks selected".into()));
    }

    // Recorder: every request's row (written before the request goes out, completed
    // after), then the findings they back. The rows queued since the last write are
    // written together, before any finding or payload that came after them.
    let (tx, rx) = mpsc::channel::<Report>();
    let mut store = Store::open(project)?;
    let match_rules = EngineRules::load(&store, Engine::Scan)?;
    // It also keeps the ids of the rows it wrote, the ones pruning may delete.
    let writer = std::thread::spawn(move || -> Result<(usize, Store, Vec<i64>)> {
        let mut new = 0;
        let mut created = Vec::new();
        let mut rows = RowBatch::default();
        while let Ok(first) = rx.recv() {
            for r in std::iter::once(first).chain(rx.try_iter().take(ROW_BATCH)) {
                if let Report::Row(w) = r {
                    rows.push(w);
                    continue;
                }
                created.extend(rows.write(&mut store).created);
                new += record_report(&mut store, r)?;
            }
            created.extend(rows.write(&mut store).created);
        }
        Ok((new, store, created))
    });
    // A rule's own change to the Host is its test (Cloud Metadata names the metadata service),
    // so the rules' client lets those go; base requests are checked below.
    let client = Client::new(SendOptions { host: HostPolicy::Allow, ..cfg.send.clone() });
    let tx_rows = tx.clone();
    let rows = Rows::new("scan", move |w| drop(tx_rows.send(Report::Row(w)))).abandoned_as(ABANDONED).sent_by(&client);

    // A base request is checked as any request is: one whose Host the scope doesn't list is
    // refused (an agent's that isn't a stated test) or attacked as it is. A rule's own change to
    // the Host is its test (Cloud Metadata names the metadata service), so the rules' client
    // lets those go.
    let mut refused_hosts: Vec<String> = Vec::new();
    let targets: Vec<ScanTarget> = targets
        .into_iter()
        .filter(|t| match cfg.send.foreign_host(&t.request, &t.target) {
            Some(h) if cfg.send.host == HostPolicy::Refuse => {
                if !refused_hosts.contains(&h) {
                    refused_hosts.push(h);
                }
                false
            }
            _ => true,
        })
        .collect();
    let shared = Arc::new(Shared {
        client,
        rows,
        auth: cfg.auth.clone(),
        strength: cfg.strength,
        tuning: cfg.tuning.clone(),
        ctl: ctl.clone(),
        deadline: cfg.max_duration.map(|d| started + d),
        limiter: Limiter::new(cfg.rate),
        requests: AtomicU64::new(0),
        reports: Mutex::new(tx),
        raised: Mutex::new(BTreeMap::new()),
        below_threshold: Mutex::new(BTreeMap::new()),
        once: Mutex::new(HashSet::new()),
        not_found: tokio::sync::Mutex::new(HashMap::new()),
        oob: cfg.oob.clone(),
        oob_by_origin: Mutex::new(HashMap::new()),
        oob_payloads: AtomicU64::new(0),
        source_sink: Mutex::new(SourceSink::default()),
        sent_once: Mutex::new(HashMap::new()),
        paused: Mutex::new(HashMap::new()),
        check_methods: cfg.check_methods.clone(),
        check_skipped_methods: AtomicU64::new(0),
        match_rules,
    });

    // Build units of work.
    let mut units: Vec<Unit> = Vec::new();
    let mut hosts_seen = HashSet::new();
    let mut fixed_segments = HashSet::new();
    let mut point_count = 0;
    for t in &targets {
        let duration = Duration::from_millis(t.duration_ms.unwrap_or(0));
        // Requests recorded with `Connection: close` (e.g. from `send --url`) are
        // re-sent with keep-alive, so the client can reuse connections.
        let request = keep_alive(&t.request);
        // The baseline is read as the attack responses will be: after the response rules that
        // list scans, or a rule's rewrite would look like the attack's doing.
        let baseline = match &shared.match_rules {
            Some(rules) => rules.response(&t.target, &t.request, t.response.clone()).bytes,
            None => t.response.clone(),
        };
        let Ok(response) = Response::parse(request.clone(), baseline, duration) else { continue };
        let msg = Message::from_exchange(t.history_id.unwrap_or(0), &t.target, &request, &t.response);
        let mut pts = points::points(&request, &cfg.points);
        // A fixed URL path segment (`/api`) is attacked once per method and origin, not on
        // every target: GET and POST can reach different code.
        pts.retain(|p| {
            points::fixed_segment(&request, p)
                .is_none_or(|prefix| fixed_segments.insert((msg.method.clone(), t.target.origin(), prefix)))
        });
        let base = Arc::new(Base { history_id: t.history_id, target: t.target.clone(), request, msg, response });
        point_count += pts.len();
        let first_for_host = hosts_seen.insert(t.target.origin());
        for &rule in &rules {
            match rule.scope() {
                RuleScope::Host if first_for_host => units.push((base.clone(), rule, None)),
                RuleScope::Host => {}
                RuleScope::Page => units.push((base.clone(), rule, None)),
                RuleScope::Param => {
                    for p in &pts {
                        units.push((base.clone(), rule, Some(p.clone())));
                    }
                }
            }
        }
    }

    let total = units.len();
    let done = Arc::new(AtomicU64::new(0));
    let sem = Arc::new(tokio::sync::Semaphore::new(cfg.concurrency.max(1)));
    let mut errors = 0;
    // The semaphore is fair, so units start in this order.
    units.sort_by_key(|u| u.1.order());
    // Units left per rule; a rule's units wait for those of the rules it depends on.
    let mut left: HashMap<u32, usize> = HashMap::new();
    for u in &units {
        *left.entry(u.1.id()).or_default() += 1;
    }
    let left: Arc<HashMap<u32, tokio::sync::watch::Sender<usize>>> =
        Arc::new(left.into_iter().map(|(id, n)| (id, tokio::sync::watch::Sender::new(n))).collect());
    let mut tasks = Vec::with_capacity(units.len());
    for (base, rule, point) in units {
        let (shared, sem, done, ctl, left) = (shared.clone(), sem.clone(), done.clone(), ctl.clone(), left.clone());
        let check = is_check(rule);
        let tool = if check { Tool::Checks } else { Tool::Scan };
        tasks.push(tokio::spawn(async move {
            // Counts the unit as finished even when the rule panics.
            let _finished = Finished(&left[&rule.id()]);
            for dep in rule.depends_on() {
                if let Some(tx) = left.get(dep) {
                    let _ = tx.subscribe().wait_for(|n| *n == 0).await;
                }
            }
            let Ok(_permit) = sem.acquire().await else { return };
            let (strength, threshold) = if check {
                (shared.strength, shared.tuning.threshold)
            } else {
                (shared.tuning.strength(rule.id(), shared.strength), shared.tuning.threshold(rule.id()))
            };
            let cx = Cx { base, point, shared: shared.clone(), strength, threshold, tool, failed: Mutex::default() };
            if !cx.stopped() {
                rule.scan(&cx).await;
            }
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 10 == 0 || n as usize == total {
                ctl.set_progress(serde_json::json!({
                    "units_done": n,
                    "units": total,
                    "requests": shared.requests.load(Ordering::Relaxed),
                    "raised": shared.raised.lock().unwrap().values().sum::<usize>(),
                }));
            }
        }));
    }
    for t in tasks {
        // A panicking rule is an error, not a silently skipped unit.
        if t.await.is_err() {
            errors += 1;
        }
    }

    let mut summary_raised: BTreeMap<String, usize> =
        shared.raised.lock().unwrap().iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let below_threshold: BTreeMap<String, usize> =
        shared.below_threshold.lock().unwrap().iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let requests = shared.requests.load(Ordering::Relaxed);
    let timed_out = shared.deadline.is_some_and(|d| Instant::now() >= d);
    let oob_payloads = shared.oob_payloads.load(Ordering::Relaxed);
    let oob_enabled = shared.oob.is_some();
    let check_skipped_methods = shared.check_skipped_methods.load(Ordering::Relaxed);
    // Close the channel so the writer finishes.
    *shared.reports.lock().unwrap() = mpsc::channel().0;
    drop(shared);
    let (mut new_findings, mut store, created) = tokio::task::spawn_blocking(move || writer.join())
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?
        .map_err(|_| Error::Protocol("active scan writer panicked".into()))??;

    // Deferred out-of-band check: correlate until the wait is over (not at all
    // when stopped), so slow callbacks still count without blocking the units.
    let oob = if oob_enabled {
        let waited = Instant::now();
        let wait = if oob_payloads > 0 && !ctl.stopped() { cfg.oob_wait } else { Duration::ZERO };
        let mut s = OobSummary { payloads: oob_payloads, ..Default::default() };
        loop {
            let c = oob::correlate(&mut store, alert_def)?;
            s.interactions += c.interactions;
            s.matched += c.matched;
            new_findings += c.new_findings;
            for r in c.raised {
                *summary_raised.entry(r).or_default() += 1;
            }
            if waited.elapsed() >= wait || ctl.stopped() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250).min(wait.saturating_sub(waited.elapsed()))).await;
        }
        s.waited_ms = waited.elapsed().as_millis() as u64;
        Some(s)
    } else {
        None
    };
    // After the out-of-band wait, so a late callback's finding keeps its attack.
    // A failure here doesn't fail the scan: what was deleted stays deleted, the rest is kept.
    let (pruned, prune_error) = if cfg.prune {
        let (n, e) = store.prune_unreferenced(&created);
        (Some(n), e.map(|e| e.to_string()))
    } else {
        (None, None)
    };

    Ok(ActiveSummary {
        targets: targets.len(),
        insertion_points: point_count,
        rules: rules.len(),
        units: total,
        units_done: done.load(Ordering::Relaxed) as usize,
        requests,
        raised: summary_raised,
        below_threshold,
        new_findings,
        errors,
        check_skipped_methods,
        refused_hosts,
        oob,
        pruned,
        prune_error,
        stopped: ctl.stopped(),
        timed_out,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

/// `request` with `Connection: close` replaced by `keep-alive`; other requests unchanged.
fn keep_alive(request: &[u8]) -> Vec<u8> {
    let raw = RawRequest::from_bytes(request.to_vec());
    let close = raw.head().is_ok_and(|h| {
        h.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.trim().eq_ignore_ascii_case("close"))
    });
    if close {
        raw.set_header("Connection", "keep-alive").into_bytes()
    } else {
        request.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Boom;

    impl ActiveRule for Boom {
        fn id(&self) -> u32 {
            999_999
        }
        fn name(&self) -> &'static str {
            "boom"
        }
        fn alerts(&self) -> &'static [&'static AlertDef] {
            &[]
        }
        fn scope(&self) -> RuleScope {
            RuleScope::Page
        }
        fn scan<'a>(&'a self, _cx: &'a Cx) -> BoxFuture<'a> {
            Box::pin(async { std::panic::panic_any("boom-rule-test") })
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_panicking_rule_counts_as_an_error() {
        // Keep the expected panic out of the test log (scripts/check.sh greps for "panicked").
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info.payload().downcast_ref::<&str>() != Some(&"boom-rule-test") {
                prev(info);
            }
        }));
        static BOOM: Boom = Boom;
        let project = std::env::temp_dir().join(format!("bp-active-boom-{}.bpdb", std::process::id()));
        let _ = std::fs::remove_file(&project);
        let target = ScanTarget {
            history_id: None,
            target: Target::from_url("http://127.0.0.1:9/").unwrap(),
            request: b"GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n".to_vec(),
            response: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
            duration_ms: None,
        };
        let cfg = ActiveConfig {
            strength: Strength::Medium,
            tuning: Default::default(),
            concurrency: 1,
            rate: None,
            send: SendOptions::default(),
            points: PointOptions::default(),
            rules: None,
            exclude_rules: vec![],
            no_rules: true,
            checks: vec![&BOOM],
            max_duration: None,
            auth: None,
            oob: None,
            oob_wait: Duration::ZERO,
            check_methods: vec![],
            prune: false,
        };
        let s = run(&project, vec![target], cfg, JobControl::default()).await.unwrap();
        let _ = std::fs::remove_file(&project);
        assert_eq!((s.units, s.units_done, s.errors), (1, 0, 1), "{s:?}");
    }

    static PRUNE_ALERT: AlertDef = AlertDef {
        alert_ref: "999998",
        name: "prune test",
        risk: crate::scan::Risk::Low,
        confidence: crate::scan::Confidence::Low,
        cwe: 0,
        wasc: 0,
        description: "",
        solution: "",
        references: &[],
        tags: &[],
    };

    /// Sends three attacks; the second one backs a finding.
    struct ThreeAttacks;

    impl ActiveRule for ThreeAttacks {
        fn id(&self) -> u32 {
            999_998
        }
        fn name(&self) -> &'static str {
            "three attacks"
        }
        fn alerts(&self) -> &'static [&'static AlertDef] {
            static ALERTS: &[&AlertDef] = &[&PRUNE_ALERT];
            ALERTS
        }
        fn scope(&self) -> RuleScope {
            RuleScope::Page
        }
        fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
            Box::pin(async move {
                let host = format!("{}:{}", cx.base.target.host, cx.base.target.port);
                for path in ["/a", "/b", "/c"] {
                    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes();
                    if let Ok(resp) = cx.send(req).await {
                        if path == "/b" {
                            cx.report(PRUNE_ALERT.raise("", ""), &resp);
                        }
                    }
                }
            })
        }
    }

    /// A server that answers every request with an empty 200.
    async fn answering_server() -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let mut got = Vec::new();
                    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                });
            }
        });
        port
    }

    /// Runs [`ThreeAttacks`] on a base request recorded in history; returns the base row's id,
    /// the summary, and the history rows left as (id, path).
    async fn scan_three(name: &str, prune: bool) -> (i64, ActiveSummary, Vec<(i64, String)>) {
        scan_three_tuned(name, prune, Tuning::default()).await
    }

    async fn scan_three_tuned(name: &str, prune: bool, tuning: Tuning) -> (i64, ActiveSummary, Vec<(i64, String)>) {
        use url::Url;
        static RULE: ThreeAttacks = ThreeAttacks;
        let port = answering_server().await;
        let project = std::env::temp_dir().join(format!("bp-active-{name}-{}.bpdb", std::process::id()));
        let _ = std::fs::remove_file(&project);
        let target = Target::from_url(&format!("http://127.0.0.1:{port}/")).unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
        let base = Store::create(&project)
            .unwrap()
            .record(&Capture::new("proxy", &target, &request, Some(&response), Some(1), None))
            .unwrap();
        let t = ScanTarget { history_id: Some(base), target, request, response, duration_ms: Some(1) };
        let scope = crate::guard::ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] };
        let guard = crate::guard::Guard::from_specs(vec![scope]).unwrap();
        let cfg = ActiveConfig {
            strength: Strength::Medium,
            tuning,
            concurrency: 1,
            rate: None,
            send: SendOptions { guard: Some(guard), ..Default::default() },
            points: PointOptions::default(),
            rules: None,
            exclude_rules: vec![],
            no_rules: true,
            checks: vec![&RULE],
            max_duration: None,
            auth: None,
            oob: None,
            oob_wait: Duration::ZERO,
            check_methods: vec![],
            prune,
        };
        let s = run(&project, vec![t], cfg, JobControl::default()).await.unwrap();
        let store = Store::open(&project).unwrap();
        let rows = store
            .list(&Default::default())
            .unwrap()
            .into_iter()
            .map(|e| (e.id, Url::parse(&e.url).unwrap().path().to_string()))
            .collect();
        drop(store);
        let _ = std::fs::remove_file(&project);
        (base, s, rows)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pruning_keeps_the_base_request_and_the_attack_behind_a_finding() {
        let (base, s, rows) = scan_three("prune", true).await;
        assert_eq!((s.new_findings, s.pruned), (1, Some(2)), "{s:?}");
        let mut paths: Vec<&str> = rows.iter().map(|(_, p)| p.as_str()).collect();
        paths.sort();
        assert_eq!(paths, ["/", "/b"], "{rows:?}");
        assert!(rows.iter().any(|(id, p)| *id == base && p == "/"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn by_default_a_scan_keeps_every_request() {
        let (_, s, rows) = scan_three("keep", false).await;
        assert_eq!((s.new_findings, s.pruned), (1, None), "{s:?}");
        assert_eq!(rows.len(), 4, "{rows:?}");
        assert!(!serde_json::to_value(&s).unwrap().as_object().unwrap().contains_key("pruned"));
    }

    /// [`ThreeAttacks`] runs as a declarative check here: a check takes the scan's strength and
    /// threshold, never a policy's settings for a rule of the same id (every check's id is 0,
    /// as is Directory Browsing's).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_check_takes_the_scans_threshold_and_no_rules_own_settings() {
        use policy::RuleTuning;
        let own = RuleTuning { strength: Some(Strength::Insane), threshold: Some(Threshold::High) };
        let tuning = Tuning { threshold: Threshold::Low, rules: [(999_998, own), (0, own)].into() };
        let (_, s, rows) = scan_three_tuned("tuned", false, tuning).await;
        assert_eq!((s.requests, rows.len(), s.new_findings), (3, 4, 1), "{s:?}");
        assert!(s.below_threshold.is_empty(), "{s:?}");
        // The scan's threshold applies: its low-confidence finding is counted, not raised.
        let high = Tuning { threshold: Threshold::High, ..Default::default() };
        let (_, s, _) = scan_three_tuned("tuned-scan", false, high).await;
        assert_eq!((s.requests, s.new_findings, s.raised.len()), (3, 0, 0), "{s:?}");
        assert_eq!(s.below_threshold, [("999998".to_string(), 1)].into());
    }

    /// Selected rules bring the rules they depend on; a rule left without one is dropped, along
    /// the whole chain (persistent XSS 40014 needs Spider 40017, which needs Prime 40016).
    #[test]
    fn rules_are_selected_with_what_they_depend_on() {
        assert_eq!(selected_rule_ids(Some(&[40014]), &[]), [40014, 40016, 40017]);
        assert_eq!(selected_rule_ids(Some(&[40014, 40034]), &[40017]), [40034]);
        let all = selected_rule_ids(None, &[40016]);
        assert!(!all.contains(&40017) && !all.contains(&40014) && all.contains(&40012), "{all:?}");
        assert_eq!(all.len(), all_rules().len() - 3);
    }
}
