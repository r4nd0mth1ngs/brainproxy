//! Active scanner. Rules are ported from OWASP ZAP's ascanrules add-on
//! (https://github.com/zaproxy/zap-extensions, Apache License 2.0); each rule
//! file names the ZAP class it came from.
//!
//! Every request goes through the HTTP client and therefore the engagement scope
//! guard. Attack exchanges are recorded in history (source "scan") only when they
//! back a finding.
//!
//! Out-of-band checks register their payloads (`Cx::oob_payload`/`oob_register`);
//! after the last unit, `run` waits up to `ActiveConfig::oob_wait` while
//! correlating interactions the OOB listener received (see `crate::oob`).

pub mod points;
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
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use crate::jobs::JobControl;
use crate::oob::{self, Endpoint, Payload, ScanPayload};
use crate::scan::active::source_sink::{Sink, SourceSink};
use crate::scan::{AlertDef, Finding, Message};
use crate::store::Store;
pub use points::{InsertionPoint, PointKind, PointOptions};

/// How many attacks a rule tries (ZAP attack strength).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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
    /// Rules run in phases: every unit of a phase finishes before the next starts
    /// (ZAP runs a rule's dependencies first).
    fn phase(&self) -> u8 {
        0
    }
    /// Rules this one needs (ZAP `getDependency`): selected along with it, and
    /// it is skipped when one of them is excluded.
    fn depends_on(&self) -> &'static [u32] {
        &[]
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
    text: OnceLock<String>,
}

impl Response {
    fn parse(request: Vec<u8>, raw: Vec<u8>, duration: Duration) -> Result<Self> {
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
            text: OnceLock::new(),
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
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
        request: Vec<u8>,
        response: Vec<u8>,
        duration_ms: i64,
    },
    Oob {
        target: Target,
        token: String,
        finding: Finding,
        request: Vec<u8>,
        response: Option<Vec<u8>>,
        duration_ms: Option<i64>,
    },
}

struct Shared {
    client: Client,
    auth: Option<Arc<AuthSession>>,
    strength: Strength,
    ctl: JobControl,
    deadline: Option<Instant>,
    limiter: Option<Limiter>,
    requests: AtomicU64,
    reports: Mutex<mpsc::Sender<Report>>,
    raised: Mutex<BTreeMap<&'static str, usize>>,
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
}

/// Everything a rule needs for one unit of work.
pub struct Cx {
    base: Arc<Base>,
    point: Option<InsertionPoint>,
    shared: Arc<Shared>,
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
        self.shared.strength
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
    pub async fn send_to(&self, target: &Target, request: Vec<u8>) -> Result<Response> {
        if self.stopped() {
            return Err(Error::Protocol("scan stopped".into()));
        }
        if let Some(l) = &self.shared.limiter {
            l.wait().await;
        }
        self.shared.requests.fetch_add(1, Ordering::Relaxed);
        let Some(auth) = &self.shared.auth else {
            let ex = self.shared.client.send(&RawRequest::from_bytes(request), target).await?;
            return Response::parse(ex.request, ex.response, Duration::from_millis(ex.duration_ms));
        };
        let attacked_cookie = self.point.as_ref().filter(|p| p.kind == PointKind::Cookie).map(|p| p.name.as_str());
        let keep: Vec<&str> = attacked_cookie.into_iter().collect();
        let generation = auth.generation();
        let mut ex = self.shared.client.send(&RawRequest::from_bytes(auth.apply(&request, &keep)), target).await?;
        auth.observe(&ex.response);
        if auth.is_logged_out(&ex.response) && auth.relogin(generation).await {
            ex = self.shared.client.send(&RawRequest::from_bytes(auth.apply(&request, &keep)), target).await?;
            auth.observe(&ex.response);
        }
        Response::parse(ex.request, ex.response, Duration::from_millis(ex.duration_ms))
    }

    /// A raw TCP connection to `host:port` for rules that speak another protocol
    /// (e.g. TLS records). Goes through the client, so the engagement scope applies.
    pub async fn connect_raw(&self, host: &str, port: u16) -> Result<crate::http::client::Stream> {
        if self.stopped() {
            return Err(Error::Protocol("scan stopped".into()));
        }
        if let Some(l) = &self.shared.limiter {
            l.wait().await;
        }
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
        *self.shared.raised.lock().unwrap().entry(finding.def.alert_ref).or_default() += 1;
        let _ = self.shared.reports.lock().unwrap().send(Report::Finding {
            target: self.base.target.clone(),
            finding,
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
        self.shared.oob_payloads.fetch_add(1, Ordering::Relaxed);
        let _ = self.shared.reports.lock().unwrap().send(Report::Oob {
            target: self.base.target.clone(),
            token: payload.token.clone(),
            finding,
            request: resp.map_or_else(|| request.to_vec(), |r| r.request.clone()),
            response: resp.map(|r| r.raw.clone()),
            duration_ms: resp.map(|r| r.duration.as_millis() as i64),
        });
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

struct Limiter {
    interval: Duration,
    next: tokio::sync::Mutex<Instant>,
}

impl Limiter {
    async fn wait(&self) {
        let at = {
            let mut next = self.next.lock().await;
            let at = (*next).max(Instant::now());
            *next = at + self.interval;
            at
        };
        tokio::time::sleep_until(at.into()).await;
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
    pub strength: Strength,
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
    pub new_findings: usize,
    /// None when no OOB listener was running (out-of-band checks skipped).
    pub oob: Option<OobSummary>,
    pub stopped: bool,
    pub timed_out: bool,
    pub elapsed_ms: u64,
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
    let mut rules: Vec<&'static dyn ActiveRule> = all_rules()
        .iter()
        .map(|r| r.as_ref())
        .filter(|r| {
            !cfg.no_rules
                && cfg.rules.as_ref().is_none_or(|ids| ids.contains(&r.id()))
                && !cfg.exclude_rules.contains(&r.id())
        })
        .collect();
    // Pull in dependencies of selected rules, then drop rules missing one (excluded).
    loop {
        let ids: HashSet<u32> = rules.iter().map(|r| r.id()).collect();
        let missing: Vec<&'static dyn ActiveRule> = all_rules()
            .iter()
            .map(|r| r.as_ref())
            .filter(|r| !ids.contains(&r.id()) && !cfg.exclude_rules.contains(&r.id()))
            .filter(|r| rules.iter().any(|sel| sel.depends_on().contains(&r.id())))
            .collect();
        if missing.is_empty() {
            break;
        }
        rules.extend(missing);
    }
    let ids: HashSet<u32> = rules.iter().map(|r| r.id()).collect();
    rules.retain(|r| r.depends_on().iter().all(|d| ids.contains(d)));
    rules.extend(cfg.checks.iter().copied());
    if rules.is_empty() {
        return Err(Error::InvalidInput("no active rules or checks selected".into()));
    }

    // Recorder: attack exchanges that back findings go to history, then findings.
    let (tx, rx) = mpsc::channel::<Report>();
    let mut store = Store::open(project)?;
    let writer = std::thread::spawn(move || -> Result<(usize, Store)> {
        let mut new = 0;
        while let Ok(r) = rx.recv() {
            match r {
                Report::Finding { target, finding, request, response, duration_ms } => {
                    let cap = Capture::new("scan", &target, &request, Some(&response), Some(duration_ms), None);
                    let id = store.record(&cap)?;
                    let msg = Message::from_exchange(id, &target, &request, &response);
                    new += store.record_findings("active", &msg, std::slice::from_ref(&finding))?;
                }
                Report::Oob { target, token, finding, request, response, duration_ms } => {
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
                    })?;
                }
            }
        }
        Ok((new, store))
    });

    let shared = Arc::new(Shared {
        client: Client::new(cfg.send.clone()),
        auth: cfg.auth.clone(),
        strength: cfg.strength,
        ctl: ctl.clone(),
        deadline: cfg.max_duration.map(|d| started + d),
        limiter: cfg.rate.filter(|r| *r > 0.0).map(|r| Limiter {
            interval: Duration::from_secs_f64(1.0 / r),
            next: tokio::sync::Mutex::new(Instant::now()),
        }),
        requests: AtomicU64::new(0),
        reports: Mutex::new(tx),
        raised: Mutex::new(BTreeMap::new()),
        once: Mutex::new(HashSet::new()),
        not_found: tokio::sync::Mutex::new(HashMap::new()),
        oob: cfg.oob.clone(),
        oob_by_origin: Mutex::new(HashMap::new()),
        oob_payloads: AtomicU64::new(0),
        source_sink: Mutex::new(SourceSink::default()),
    });

    // Build units of work.
    let mut units: Vec<Unit> = Vec::new();
    let mut hosts_seen = HashSet::new();
    let mut point_count = 0;
    for t in &targets {
        let duration = Duration::from_millis(t.duration_ms.unwrap_or(0));
        let Ok(response) = Response::parse(t.request.clone(), t.response.clone(), duration) else { continue };
        let msg = Message::from_exchange(t.history_id.unwrap_or(0), &t.target, &t.request, &t.response);
        let base = Arc::new(Base {
            history_id: t.history_id,
            target: t.target.clone(),
            request: t.request.clone(),
            msg,
            response,
        });
        let pts = points::points(&t.request, &cfg.points);
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
    units.sort_by_key(|u| u.1.phase());
    let mut phases: Vec<Vec<Unit>> = Vec::new();
    for u in units {
        match phases.last_mut() {
            Some(p) if p[0].1.phase() == u.1.phase() => p.push(u),
            _ => phases.push(vec![u]),
        }
    }
    for units in phases {
        let mut tasks = Vec::with_capacity(units.len());
        for (base, rule, point) in units {
            let (shared, sem, done, ctl) = (shared.clone(), sem.clone(), done.clone(), ctl.clone());
            tasks.push(tokio::spawn(async move {
                let Ok(_permit) = sem.acquire().await else { return };
                let cx = Cx { base, point, shared: shared.clone() };
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
            let _ = t.await;
        }
    }

    let mut summary_raised: BTreeMap<String, usize> =
        shared.raised.lock().unwrap().iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let requests = shared.requests.load(Ordering::Relaxed);
    let timed_out = shared.deadline.is_some_and(|d| Instant::now() >= d);
    let oob_payloads = shared.oob_payloads.load(Ordering::Relaxed);
    let oob_enabled = shared.oob.is_some();
    // Close the channel so the writer finishes.
    *shared.reports.lock().unwrap() = mpsc::channel().0;
    drop(shared);
    let (mut new_findings, mut store) = tokio::task::spawn_blocking(move || writer.join())
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

    Ok(ActiveSummary {
        targets: targets.len(),
        insertion_points: point_count,
        rules: rules.len(),
        units: total,
        units_done: done.load(Ordering::Relaxed) as usize,
        requests,
        raised: summary_raised,
        new_findings,
        oob,
        stopped: ctl.stopped(),
        timed_out,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}
