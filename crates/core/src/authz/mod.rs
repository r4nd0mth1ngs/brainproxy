//! Access-control testing across identities. Each recorded request is
//! sent again as the identity that made it (the baseline, twice, to learn what changes
//! on its own), without any login (the anonymous control), and as every other identity.
//! Each response is compared with the baseline and labelled:
//!
//! - `enforced`: refused (an error status, a logged-out page, or a body saying so);
//! - `bypass`: the owner's data came back (their private values or username, or a
//!   nearly identical response when there is nothing private to look for);
//! - `public`: the anonymous control got the same response, so nothing is protected;
//! - `different`: a successful but different response (e.g. the identity's own data);
//! - `inconclusive`: a successful response with nothing to compare (an empty body, `{}`,
//!   or a HEAD or OPTIONS request), so it says nothing about access.
//!
//! Bypasses of medium or high confidence become findings. Everything is recorded in
//! `authz_results`, one row per request and identity, with the history ids of the
//! baseline and the replay so the two can be compared (`diff`).

pub(crate) mod compare;
pub mod live;

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};

use crate::auth::{request_cookies, static_cookies, AuthProfile, AuthSession};
use crate::error::{Error, Result};
use crate::http::{Client, Exchange, RawRequest, SendOptions, Target};
use crate::jobs::JobControl;
use crate::scan::active::Limiter;
use crate::scan::{AlertDef, Confidence, Message, Risk};
use crate::store::Store;
use compare::{
    mentions, private_hits, private_values, privileged_path, references_object, says_denied, similarity, Body, Noise,
};

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS authz_results (
    run_id INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    source_id INTEGER,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    owner TEXT NOT NULL,
    identity TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence TEXT,
    status INTEGER,
    similarity REAL,
    private_total INTEGER,
    private_hits INTEGER,
    history_id INTEGER,
    baseline_history_id INTEGER,
    reason TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, idx)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS authz_results_verdict ON authz_results(run_id, verdict);
";

pub const AUTHZ_RESULT_COLUMNS: &[(&str, &str, &str)] = &[
    ("run_id", "INTEGER", "Run id (jobs.id of the authz run)"),
    ("idx", "INTEGER", "Row number within the run"),
    ("source_id", "INTEGER", "history.id of the request tested (NULL for a URL given on the command line)"),
    ("method", "TEXT", "Request method"),
    ("url", "TEXT", "Request URL"),
    (
        "owner",
        "TEXT",
        "Identity whose response is the baseline: an auth profile, or 'recorded' (the request's own credentials)",
    ),
    (
        "identity",
        "TEXT",
        "Identity the request was sent as: an auth profile, 'anonymous', or the owner (verdict baseline)",
    ),
    ("verdict", "TEXT", "baseline, enforced, bypass, public, different, inconclusive, error, skipped"),
    ("confidence", "TEXT", "For bypass: low, medium, high (medium and high are also findings)"),
    ("status", "INTEGER", "Response status"),
    (
        "similarity",
        "REAL",
        "0..1 likeness to the baseline response, leaving out what changes between identical requests",
    ),
    (
        "private_total",
        "INTEGER",
        "Owner values in the baseline that the anonymous response and the request don't contain",
    ),
    ("private_hits", "INTEGER", "How many of them this response contains"),
    ("history_id", "INTEGER", "history.id of this response"),
    ("baseline_history_id", "INTEGER", "history.id of the baseline response"),
    ("reason", "TEXT", "Why the verdict was given"),
    ("evidence", "TEXT", "What showed the bypass"),
];

/// Methods replayed unless asked otherwise. Replaying a request that changes state as
/// another user changes their data, so POST and the like are opt-in.
pub const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

/// Paths not replayed by default: logging out would end the owner's session.
pub const DEFAULT_EXCLUDE: &str = r"(?i)(log|sign)[-_]?(out|off)\b";

/// The identity that sends without any credentials.
pub const ANONYMOUS: &str = "anonymous";
/// Owner label for a request re-sent with the credentials it was recorded with.
pub const RECORDED: &str = "recorded";

static BYPASS: AlertDef = AlertDef {
    alert_ref: "100003",
    name: "Access Control Bypass",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 639,
    wasc: 2,
    description: "A request made by one user returned that user's data when it was sent with another user's \
        session. The server doesn't check that the logged-in user may access the object or function the request \
        names (broken object level authorization / IDOR, or missing function level authorization).",
    solution: "Check authorization on the server for every request: that the logged-in user owns or may access \
        the object named in the request, and may use the function. Deny by default, enforce the checks in one \
        place, and don't rely on identifiers being hard to guess. Compare the two responses (other info) to \
        confirm what was exposed.",
    references: &[
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "API1:2023", "API5:2023"],
};

static UNAUTHENTICATED: AlertDef = AlertDef {
    alert_ref: "100004",
    name: "Protected Content Without Authentication",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 306,
    wasc: 1,
    description: "A request made by a logged-in user returned that user's data when it was sent with no session \
        at all. The server doesn't require authentication for it.",
    solution: "Require a valid session for every request that returns or changes a user's data, and check \
        authorization as well. Compare the two responses (other info) to confirm what was exposed.",
    references: &[
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "API2:2023"],
};

/// Alert definitions raised by authz runs.
pub fn alerts() -> [&'static AlertDef; 2] {
    [&BYPASS, &UNAUTHENTICATED]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Baseline,
    Enforced,
    Bypass,
    Public,
    Different,
    Inconclusive,
    Error,
    Skipped,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Baseline => "baseline",
            Verdict::Enforced => "enforced",
            Verdict::Bypass => "bypass",
            Verdict::Public => "public",
            Verdict::Different => "different",
            Verdict::Inconclusive => "inconclusive",
            Verdict::Error => "error",
            Verdict::Skipped => "skipped",
        }
    }
}

pub struct AuthzConfig {
    /// Identities to send each request as (besides the owner and the anonymous control).
    pub identities: Vec<Arc<AuthSession>>,
    /// Also send without credentials.
    pub anonymous: bool,
    /// Owner of every request; otherwise detected per request from `known`.
    pub owner: Option<Arc<AuthSession>>,
    /// Sessions that may have made the recorded requests. Their cookies, tokens and
    /// headers are also what gets removed before a request is sent as someone else.
    pub known: Vec<Arc<AuthSession>>,
    /// Cookies that aren't credentials and stay on the request (e.g. a locale).
    pub keep_cookies: Vec<String>,
    pub send: SendOptions,
    pub concurrency: usize,
    pub rate: Option<f64>,
}

/// A request to test.
#[derive(Debug, Clone)]
pub struct AuthzTarget {
    pub history_id: Option<i64>,
    pub target: Target,
    pub request: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthzSummary {
    pub run_id: i64,
    pub requests: usize,
    pub sent: u64,
    pub identities: Vec<String>,
    pub verdicts: BTreeMap<String, usize>,
    pub new_findings: usize,
    pub stopped: bool,
}

/// Profile names whose auth placeholders the request carries, in order of appearance.
pub fn placeholder_profiles(request: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(crate::http::request::split_head_body(request).0);
    let mut out: Vec<String> = Vec::new();
    for part in text.split("«auth:").skip(1) {
        if let Some((name, _)) = part.split_once(':') {
            if !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// The identity whose credentials the request carries: by its auth placeholders, else
/// by a cookie, token or header value equal to one in that session.
fn detect_owner(request: &[u8], known: &[Arc<AuthSession>]) -> Option<Arc<AuthSession>> {
    let names = placeholder_profiles(request);
    if let Some(s) = names.iter().find_map(|n| known.iter().find(|s| &s.profile.name == n)) {
        return Some(s.clone());
    }
    let head = RawRequest::from_bytes(request.to_vec()).head().ok()?;
    let cookies = request_cookies(request);
    known
        .iter()
        .find(|s| {
            let st = s.state();
            st.cookies
                .iter()
                .cloned()
                .chain(static_cookies(&s.profile))
                .any(|(k, v)| v.len() >= 4 && cookies.iter().any(|(ck, cv)| *ck == k && *cv == v))
                || st.token.as_ref().is_some_and(|t| {
                    t.len() >= 8 && head.headers.iter().any(|(k, v)| !k.eq_ignore_ascii_case("cookie") && v.contains(t))
                })
                || s.profile.headers.iter().any(|(name, value)| {
                    !name.eq_ignore_ascii_case("cookie")
                        && value.len() >= 8
                        && head.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case(name) && v.trim() == value.trim())
                })
        })
        .cloned()
}

/// The request without credentials: no Authorization header, no header any known
/// session sets or that carries an auth placeholder, no query parameter that does (a
/// signature or token placed there), and no cookies except `keep`.
pub(crate) fn strip_auth(raw: &[u8], known: &[Arc<AuthSession>], keep: &[String]) -> Vec<u8> {
    let raw = &*strip_query_auth(raw);
    let req = RawRequest::from_bytes(raw.to_vec());
    let Ok(head) = req.head() else { return raw.to_vec() };
    let mut names = credential_headers(known.iter().map(|s| &s.profile));
    names.insert("authorization".to_string());
    for (k, v) in &head.headers {
        if v.contains("«auth:") {
            names.insert(k.to_ascii_lowercase());
        }
    }
    names.remove("cookie");
    let mut req = req;
    for n in &names {
        req = req.remove_header(n);
    }
    let kept: Vec<String> = request_cookies(raw)
        .into_iter()
        .filter(|(k, v)| keep.contains(k) && !v.contains("«auth:"))
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    req = if kept.is_empty() { req.remove_header("Cookie") } else { req.set_header("Cookie", &kept.join("; ")) };
    req.into_bytes()
}

/// The request without query parameters that carry an auth placeholder.
fn strip_query_auth(raw: &[u8]) -> Vec<u8> {
    let (head, body) = crate::http::request::split_head_body(raw);
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = String::from_utf8_lossy(&head[..line_end]);
    let mut words: Vec<&str> = line.split(' ').collect();
    let Some((path, query)) = words.get(1).and_then(|u| u.split_once('?')) else { return raw.to_vec() };
    if !query.contains("«auth:") {
        return raw.to_vec();
    }
    let kept: Vec<&str> = query.split('&').filter(|p| !p.contains("«auth:")).collect();
    let uri = if kept.is_empty() { path.to_string() } else { format!("{path}?{}", kept.join("&")) };
    words[1] = &uri;
    let mut out = words.join(" ").into_bytes();
    out.extend_from_slice(&head[line_end..]);
    out.extend_from_slice(body);
    out
}

/// Requests recorded with `Connection: close` are re-sent with keep-alive.
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

/// One identity's result for one request.
#[derive(Debug, Clone)]
struct Row {
    identity: String,
    verdict: Verdict,
    confidence: Option<Confidence>,
    status: Option<u16>,
    similarity: Option<f64>,
    private: Option<(usize, usize)>,
    exchange: Option<Exchange>,
    reason: String,
    evidence: String,
}

impl Row {
    fn new(identity: &str, verdict: Verdict, reason: impl Into<String>) -> Row {
        Row {
            identity: identity.to_string(),
            verdict,
            confidence: None,
            status: None,
            similarity: None,
            private: None,
            exchange: None,
            reason: reason.into(),
            evidence: String::new(),
        }
    }
}

/// Everything learned about one request, ready to record with a [`Recorder`].
pub struct Outcome {
    source_id: Option<i64>,
    method: String,
    url: String,
    owner: String,
    /// The first row is the baseline (or why there is none).
    rows: Vec<Row>,
}

/// What a response is judged against.
struct Baseline<'a> {
    body: &'a Body,
    noise: &'a Noise,
    private: &'a [(String, String)],
    owner_user: Option<&'a str>,
    /// The request names an object (id, UUID, email).
    object: bool,
    privileged: bool,
    /// The baseline has a body worth comparing: not empty, and not HEAD or OPTIONS.
    comparable: bool,
}

/// Labels one identity's response. `user` is the identity's own username, if known.
fn judge(
    base: &Baseline,
    body: &Body,
    logged_out: bool,
    request_text: &str,
    anonymous: bool,
    user: Option<&str>,
) -> Row {
    let mut row = Row::new("", Verdict::Different, "");
    row.status = body.status;
    let Some(status) = body.status else {
        row.verdict = Verdict::Error;
        row.reason = "unparseable response".into();
        return row;
    };
    if !body.success() {
        row.verdict = Verdict::Enforced;
        row.reason = format!("status {status}");
        return row;
    }
    if logged_out {
        row.verdict = Verdict::Enforced;
        row.reason = "logged-out response".into();
        return row;
    }
    if says_denied(&body.text) && !says_denied(&base.body.text) {
        row.verdict = Verdict::Enforced;
        row.reason = "response says access is denied".into();
        return row;
    }
    // Two empty bodies are "identical", which says nothing about who may see what.
    if !base.comparable {
        row.verdict = Verdict::Inconclusive;
        row.reason = "a successful response with nothing to compare (no body, or HEAD or OPTIONS)".into();
        return row;
    }
    let sim = similarity(base.body, body, base.noise);
    let hits = private_hits(base.private, body);
    row.similarity = Some((sim * 1000.0).round() / 1000.0);
    row.private = Some((base.private.len(), hits));
    let user_leak = base.owner_user.filter(|u| {
        u.chars().count() >= 3
            && user != Some(*u)
            && mentions(&base.body.text, u)
            && !mentions(request_text, u)
            && mentions(&body.text, u)
    });
    if anonymous {
        if let Some(u) = user_leak {
            row.verdict = Verdict::Bypass;
            row.confidence = Some(Confidence::High);
            row.reason = "the owner's data came back without a session".into();
            row.evidence = format!("the owner's username {u:?} is in the response");
        } else if sim >= 0.9 {
            row.verdict = Verdict::Public;
            row.reason = format!("same response without a session (similarity {sim:.2})");
        } else {
            row.reason = format!("different response (similarity {sim:.2})");
        }
        return row;
    }
    let by_values = base.private.len() >= 2 && hits * 10 >= base.private.len() * 6;
    // A private value that didn't come back means this is someone else's data, however
    // alike the rest is.
    let by_similarity = base.private.len() < 2 && hits == base.private.len() && sim >= 0.95;
    let own_data =
        user.is_some_and(|w| w.chars().count() >= 3 && mentions(&body.text, w) && !mentions(&base.body.text, w));
    if !(by_values || user_leak.is_some() || by_similarity) || (own_data && user_leak.is_none() && !by_values) {
        row.reason = if own_data {
            format!("the identity's own data (similarity {sim:.2})")
        } else {
            format!("different response (similarity {sim:.2}, {hits} of {} owner values)", base.private.len())
        };
        return row;
    }
    row.verdict = Verdict::Bypass;
    row.confidence = Some(if base.object {
        if by_values || user_leak.is_some() {
            Confidence::High
        } else {
            Confidence::Medium
        }
    } else if base.privileged {
        Confidence::Medium
    } else {
        Confidence::Low
    });
    row.reason = if base.object {
        "the owner's response came back for another identity".into()
    } else {
        "the same response came back for another identity; the request names no object, so it may be shared".into()
    };
    let mut evidence = Vec::new();
    if by_values {
        let example = base
            .private
            .iter()
            .find(|p| private_hits(std::slice::from_ref(p), body) == 1)
            .map(|(k, v)| format!(", e.g. {k}={v}"));
        evidence.push(format!("{hits} of {} owner values{}", base.private.len(), example.unwrap_or_default()));
    }
    if let Some(u) = user_leak {
        evidence.push(format!("the owner's username {u:?}"));
    }
    if evidence.is_empty() {
        evidence.push(format!("similarity {sim:.2}"));
    }
    row.evidence = evidence.join("; ");
    row
}

/// Who a request is sent as.
#[derive(Clone)]
enum As {
    Owner(Arc<AuthSession>),
    /// The request's own credentials, unchanged.
    Recorded,
    Session(Arc<AuthSession>),
    Anonymous,
}

/// Sends requests as the owner, the anonymous control and the other identities, and
/// judges each response: the engine behind [`run`] (a list of requests) and the proxy's
/// live mode (each request as it is recorded). Stops sending once `ctl` is stopped.
pub struct Tester {
    client: Client,
    cfg: AuthzConfig,
    limiter: Option<Limiter>,
    sent: AtomicU64,
    ctl: JobControl,
    identities: Vec<String>,
}

impl Tester {
    pub fn new(cfg: AuthzConfig, ctl: JobControl) -> Result<Tester> {
        if !cfg.anonymous && cfg.identities.is_empty() {
            return Err(Error::InvalidInput(
                "nothing to compare: pass --as NAME or leave the anonymous control on".into(),
            ));
        }
        let mut identities: Vec<String> = Vec::new();
        if cfg.anonymous {
            identities.push(ANONYMOUS.to_string());
        }
        identities.extend(cfg.identities.iter().map(|s| s.profile.name.clone()));
        Ok(Tester {
            client: Client::new(cfg.send.clone()),
            limiter: Limiter::new(cfg.rate),
            cfg,
            sent: AtomicU64::new(0),
            ctl,
            identities,
        })
    }

    /// The identities each request is compared across: `anonymous` first if on.
    pub fn identities(&self) -> &[String] {
        &self.identities
    }

    /// Requests sent so far.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Profiles whose credentials are recognised and removed.
    pub fn profiles(&self) -> Vec<AuthProfile> {
        self.cfg.known.iter().map(|s| s.profile.clone()).collect()
    }

    /// Sends unless the run is stopped, before or while waiting for the rate limit
    /// (then None).
    async fn send(&self, who: &As, request: &[u8], target: &Target) -> Option<Result<Exchange>> {
        if let Some(l) = &self.limiter {
            tokio::select! {
                _ = l.wait() => {}
                _ = self.until_stopped() => return None,
            }
        }
        if self.ctl.stopped() {
            return None;
        }
        Some(self.send_now(who, request, target).await)
    }

    async fn until_stopped(&self) {
        while !self.ctl.stopped() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn send_now(&self, who: &As, request: &[u8], target: &Target) -> Result<Exchange> {
        self.sent.fetch_add(1, Ordering::Relaxed);
        let strip = || RawRequest::from_bytes(strip_auth(request, &self.cfg.known, &self.cfg.keep_cookies));
        match who {
            As::Recorded => self.client.send(&RawRequest::from_bytes(request.to_vec()), target).await,
            As::Anonymous => self.client.send(&strip(), target).await,
            As::Owner(s) | As::Session(s) => s.send(&strip(), target).await,
        }
    }

    /// Whether a response sent as `who` shows a lost session, by the patterns of the
    /// profile that sent it. The anonymous control and recorded credentials use the
    /// owner's, else those of the identities under test: other stored profiles may be
    /// for other applications.
    fn logged_out(&self, who: &As, owner: Option<&Arc<AuthSession>>, response: &[u8]) -> bool {
        match (who, owner) {
            (As::Owner(s) | As::Session(s), _) | (As::Anonymous | As::Recorded, Some(s)) => s.is_logged_out(response),
            (As::Anonymous | As::Recorded, None) => self.cfg.identities.iter().any(|s| s.is_logged_out(response)),
        }
    }

    /// Tests one request. A stopped run returns what was learned before it stopped.
    pub async fn test(&self, t: &AuthzTarget) -> Outcome {
        let request = keep_alive(&t.request);
        let msg = Message::from_exchange(0, &t.target, &request, b"");
        let owner = self.cfg.owner.clone().or_else(|| detect_owner(&request, &self.cfg.known));
        let (owner_name, owner_as) = match &owner {
            Some(s) => (s.profile.name.clone(), As::Owner(s.clone())),
            None => (RECORDED.to_string(), As::Recorded),
        };
        let mut out = Outcome {
            source_id: t.history_id,
            method: msg.method.clone(),
            url: msg.url.clone(),
            owner: owner_name.clone(),
            rows: vec![],
        };

        let first = match self.send(&owner_as, &request, &t.target).await {
            None => return out,
            Some(Ok(ex)) => ex,
            Some(Err(e)) => {
                out.rows.push(Row::new(&owner_name, Verdict::Error, format!("baseline failed: {e}")));
                return out;
            }
        };
        let body = Body::parse(&first.response);
        let mut base_row = Row::new(&owner_name, Verdict::Baseline, "");
        base_row.status = body.status;
        let unusable = if !body.success() {
            Some(format!(
                "baseline status {}",
                body.status.map(|s| s.to_string()).unwrap_or_else(|| "unparseable".into())
            ))
        } else if self.logged_out(&owner_as, owner.as_ref(), &first.response) {
            Some("baseline looks logged out".to_string())
        } else {
            None
        };
        base_row.exchange = Some(first);
        if let Some(why) = unusable {
            base_row.verdict = Verdict::Skipped;
            base_row.reason = format!("{why}; nothing to compare against");
            out.rows.push(base_row);
            return out;
        }
        out.rows.push(base_row);
        // The baseline again: whatever differs between the two is noise. A second
        // response that isn't a like one (rate limited, an error, logged out) would
        // mask real differences, so then nothing is left out.
        let noise = match self.send(&owner_as, &request, &t.target).await {
            None => return out,
            Some(Ok(ex)) => {
                let again = Body::parse(&ex.response);
                let alike = again.success()
                    && again.json.is_some() == body.json.is_some()
                    && !self.logged_out(&owner_as, owner.as_ref(), &ex.response);
                if alike {
                    Noise::learn(&body, &again)
                } else {
                    Noise::default()
                }
            }
            Some(Err(_)) => Noise::default(),
        };
        if self.cfg.owner.is_none()
            && owner.is_none()
            && !has_credentials(&request, self.cfg.known.iter().map(|s| &s.profile))
        {
            out.rows[0].reason = "the request carries no credentials".into();
        }

        let stripped =
            String::from_utf8_lossy(&strip_auth(&request, &self.cfg.known, &self.cfg.keep_cookies)).into_owned();
        let mut sends: Vec<(String, As, Option<String>)> = Vec::new();
        if self.cfg.anonymous {
            sends.push((ANONYMOUS.to_string(), As::Anonymous, None));
        }
        for s in &self.cfg.identities {
            if owner.as_ref().is_some_and(|o| Arc::ptr_eq(o, s) || o.profile.name == s.profile.name) {
                continue;
            }
            sends.push((s.profile.name.clone(), As::Session(s.clone()), s.profile.username.clone()));
        }
        let owner_user = owner.as_ref().and_then(|o| o.profile.username.clone());
        let object =
            references_object(&msg.path, &format!("{} {}", msg.query.clone().unwrap_or_default(), msg.req_body_str()));
        let privileged = privileged_path(&msg.path);
        let comparable =
            !matches!(msg.method.to_ascii_uppercase().as_str(), "HEAD" | "OPTIONS") && noise.has_content(&body);
        // The anonymous control goes first: what it gets isn't private.
        let mut anon_text = None;
        let mut anon_public = false;
        let mut private = None;
        let nothing_private = Vec::new();
        for (name, who, user) in sends {
            let anonymous = matches!(who, As::Anonymous);
            let ex = match self.send(&who, &request, &t.target).await {
                None => break,
                Some(Ok(ex)) => ex,
                Some(Err(e)) => {
                    out.rows.push(Row::new(&name, Verdict::Error, e.to_string()));
                    continue;
                }
            };
            let resp = Body::parse(&ex.response);
            let private: &Vec<(String, String)> = if anonymous {
                anon_text = Some(resp.text.clone());
                // Judged on the owner's username only; its own text can't count as private.
                &nothing_private
            } else {
                private.get_or_insert_with(|| {
                    let mut public: Vec<&str> = vec![&stripped];
                    public.extend(anon_text.as_deref());
                    private_values(&body, &noise, &public)
                })
            };
            let base = Baseline {
                body: &body,
                noise: &noise,
                private,
                owner_user: owner_user.as_deref(),
                object,
                privileged,
                comparable,
            };
            let mut row = judge(
                &base,
                &resp,
                self.logged_out(&who, owner.as_ref(), &ex.response),
                &stripped,
                anonymous,
                user.as_deref(),
            );
            if anonymous && row.verdict == Verdict::Public {
                anon_public = true;
            }
            if !anonymous && anon_public && row.verdict == Verdict::Bypass {
                row.verdict = Verdict::Public;
                row.confidence = None;
                row.reason = "the anonymous control got the same response".into();
                row.evidence.clear();
            }
            row.identity = name;
            row.exchange = Some(ex);
            out.rows.push(row);
        }
        out
    }
}

/// Whether the request carries credentials: a Cookie or Authorization header, an auth
/// placeholder, or a header one of `profiles` sends (an API key, a token header).
pub fn has_credentials<'a>(request: &[u8], profiles: impl IntoIterator<Item = &'a AuthProfile>) -> bool {
    let Ok(head) = RawRequest::from_bytes(request.to_vec()).head() else { return false };
    let names = credential_headers(profiles);
    head.target.contains("«auth:")
        || head.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("cookie")
                || k.eq_ignore_ascii_case("authorization")
                || v.contains("«auth:")
                || names.contains(&k.to_ascii_lowercase())
        })
}

/// Lowercase names of the headers the profiles send: static headers and the token header.
fn credential_headers<'a>(profiles: impl IntoIterator<Item = &'a AuthProfile>) -> HashSet<String> {
    let mut names = HashSet::new();
    for p in profiles {
        if let Some((k, _)) = p.token_header.as_deref().and_then(|t| t.split_once(':')) {
            names.insert(k.trim().to_ascii_lowercase());
        }
        for (k, _) in &p.headers {
            names.insert(k.trim().to_ascii_lowercase());
        }
    }
    names
}

/// Writes outcomes under one run: the result rows, the exchanges (history, source
/// `authz`) and the findings.
pub struct Recorder {
    store: Store,
    run_id: i64,
    idx: i64,
    new_findings: usize,
    verdicts: BTreeMap<String, usize>,
}

impl Recorder {
    pub fn open(project: &Path, run_id: i64) -> Result<Recorder> {
        let store = Store::open(project)?;
        let idx = store.authz_next_idx(run_id)?;
        Ok(Recorder { store, run_id, idx, new_findings: 0, verdicts: BTreeMap::new() })
    }

    pub fn record(&mut self, o: &Outcome) -> Result<()> {
        let (n, c) = self.store.authz_record(self.run_id, &mut self.idx, o)?;
        self.new_findings += n;
        for (k, v) in c {
            *self.verdicts.entry(k).or_default() += v;
        }
        Ok(())
    }

    /// New findings recorded so far.
    pub fn new_findings(&self) -> usize {
        self.new_findings
    }

    /// Rows recorded so far per verdict.
    pub fn verdicts(&self) -> &BTreeMap<String, usize> {
        &self.verdicts
    }
}

/// Runs the comparison for every target and records the results under `run_id`.
pub async fn run(
    project: &Path,
    run_id: i64,
    targets: Vec<AuthzTarget>,
    cfg: AuthzConfig,
    ctl: JobControl,
) -> Result<AuthzSummary> {
    let concurrency = cfg.concurrency.max(1);
    let tester = Arc::new(Tester::new(cfg, ctl.clone())?);

    let (tx, rx) = mpsc::channel::<Outcome>();
    let mut recorder = Recorder::open(project, run_id)?;
    let writer = std::thread::spawn(move || -> Result<Recorder> {
        while let Ok(o) = rx.recv() {
            recorder.record(&o)?;
        }
        Ok(recorder)
    });

    let total = targets.len();
    let done = Arc::new(AtomicU64::new(0));
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut tasks = Vec::with_capacity(total);
    for t in targets {
        let (tester, sem, done, ctl, tx) = (tester.clone(), sem.clone(), done.clone(), ctl.clone(), tx.clone());
        tasks.push(tokio::spawn(async move {
            let Ok(_permit) = sem.acquire().await else { return };
            if ctl.stopped() {
                return;
            }
            let outcome = tester.test(&t).await;
            let _ = tx.send(outcome);
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            ctl.set_progress(json!({"requests_done": n, "requests": total, "sent": tester.sent()}));
        }));
    }
    drop(tx);
    for t in tasks {
        let _ = t.await;
    }
    let recorder = tokio::task::spawn_blocking(move || writer.join())
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?
        .map_err(|_| Error::Protocol("authz writer panicked".into()))??;
    Ok(AuthzSummary {
        run_id,
        requests: total,
        sent: tester.sent(),
        identities: tester.identities().to_vec(),
        verdicts: recorder.verdicts().clone(),
        new_findings: recorder.new_findings(),
        stopped: ctl.stopped(),
    })
}

impl Store {
    fn authz_next_idx(&self, run_id: i64) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT coalesce(max(idx), 0) + 1 FROM authz_results WHERE run_id = ?1",
            [run_id],
            |r| r.get(0),
        )?)
    }

    /// Records one request's exchanges, result rows and findings. Returns the number of
    /// new findings and the rows per verdict.
    fn authz_record(&mut self, run_id: i64, idx: &mut i64, o: &Outcome) -> Result<(usize, BTreeMap<String, usize>)> {
        let mut new = 0;
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut baseline_id = None;
        for (i, r) in o.rows.iter().enumerate() {
            let history_id = match &r.exchange {
                Some(ex) => Some(self.record_exchange("authz", ex)?),
                None => None,
            };
            if i == 0 {
                baseline_id = history_id;
            }
            self.conn.execute(
                "INSERT INTO authz_results (run_id, idx, source_id, method, url, owner, identity, verdict, confidence,
                    status, similarity, private_total, private_hits, history_id, baseline_history_id, reason, evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    run_id,
                    *idx,
                    o.source_id,
                    o.method,
                    o.url,
                    o.owner,
                    r.identity,
                    r.verdict.as_str(),
                    r.confidence.map(Confidence::as_str),
                    r.status,
                    r.similarity,
                    r.private.map(|p| p.0 as i64),
                    r.private.map(|p| p.1 as i64),
                    history_id,
                    baseline_id,
                    r.reason,
                    r.evidence,
                ],
            )?;
            *idx += 1;
            *counts.entry(r.verdict.as_str().to_string()).or_default() += 1;
            let (Verdict::Bypass, Some(conf), Some(ex), Some(id)) = (r.verdict, r.confidence, &r.exchange, history_id)
            else {
                continue;
            };
            if conf < Confidence::Medium {
                continue;
            }
            let anonymous = r.identity == ANONYMOUS;
            let def = if anonymous { &UNAUTHENTICATED } else { &BYPASS };
            let msg = Message::from_exchange(id, &ex.target, &ex.request, &ex.response);
            let compare = baseline_id
                .map(|b| format!(" Compare: brainproxy diff {b} {id} --part response-body"))
                .unwrap_or_default();
            let who = if anonymous { "no session".to_string() } else { format!("{}'s session", r.identity) };
            let finding = def
                .raise(format!("as {}", r.identity), r.evidence.clone())
                .confidence(conf)
                .attack(format!("{} {} sent with {who}", o.method, o.url))
                .other_info(format!(
                    "{} made this request (baseline history {}); sent with {who} it returned {}: {}.{compare}",
                    o.owner,
                    baseline_id.map(|b| b.to_string()).unwrap_or_else(|| "-".into()),
                    r.evidence,
                    r.reason,
                ));
            new += self.record_findings("authz", &msg, &[finding])?;
        }
        Ok((new, counts))
    }

    /// Result rows of a run, optionally filtered by verdict and identity.
    pub fn authz_results(
        &self,
        run_id: i64,
        verdict: Option<&str>,
        identity: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT idx, source_id, method, url, owner, identity, verdict, confidence, status, similarity,
                    private_total, private_hits, history_id, baseline_history_id, reason, evidence
             FROM authz_results WHERE run_id = ?1 AND (?2 IS NULL OR verdict = ?2) AND (?3 IS NULL OR identity = ?3)
             ORDER BY idx LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![run_id, verdict, identity, limit as i64], |r| {
            Ok(json!({
                "idx": r.get::<_, i64>(0)?,
                "source_id": r.get::<_, Option<i64>>(1)?,
                "method": r.get::<_, String>(2)?,
                "url": r.get::<_, String>(3)?,
                "owner": r.get::<_, String>(4)?,
                "identity": r.get::<_, String>(5)?,
                "verdict": r.get::<_, String>(6)?,
                "confidence": r.get::<_, Option<String>>(7)?,
                "status": r.get::<_, Option<i64>>(8)?,
                "similarity": r.get::<_, Option<f64>>(9)?,
                "private_total": r.get::<_, Option<i64>>(10)?,
                "private_hits": r.get::<_, Option<i64>>(11)?,
                "history_id": r.get::<_, Option<i64>>(12)?,
                "baseline_history_id": r.get::<_, Option<i64>>(13)?,
                "reason": r.get::<_, String>(14)?,
                "evidence": r.get::<_, String>(15)?,
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Rows per verdict for a run.
    pub fn authz_counts(&self, run_id: i64) -> Result<BTreeMap<String, i64>> {
        let mut stmt =
            self.conn.prepare("SELECT verdict, count(*) FROM authz_results WHERE run_id = ?1 GROUP BY verdict")?;
        let rows = stmt.query_map([run_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// One row per request with a cell per identity: verdict, confidence, status, history id.
    pub fn authz_matrix(&self, run_id: i64, limit: usize) -> Result<Value> {
        let rows = self.authz_results(run_id, None, None, i64::MAX as usize)?;
        let mut identities: Vec<String> = Vec::new();
        let mut requests: Vec<Value> = Vec::new();
        let mut current = None;
        let mut truncated = false;
        for r in rows {
            // A request's rows are consecutive and start with its baseline (or why there is none).
            let key = (r["source_id"].clone(), r["method"].clone(), r["url"].clone());
            let verdict = r["verdict"].as_str().unwrap_or("");
            if current.as_ref() != Some(&key) || matches!(verdict, "baseline" | "skipped") {
                if requests.len() >= limit {
                    truncated = true;
                    break;
                }
                current = Some(key);
                let mut req = json!({
                    "source_id": r["source_id"],
                    "method": r["method"],
                    "url": r["url"],
                    "owner": r["owner"],
                    "baseline_history_id": r["history_id"],
                    "baseline_status": r["status"],
                    "cells": {},
                });
                if verdict != "baseline" {
                    req["skipped"] = json!(format!("{verdict}: {}", r["reason"].as_str().unwrap_or("")));
                }
                requests.push(req);
                if matches!(verdict, "baseline" | "skipped") || r["identity"] == r["owner"] {
                    continue;
                }
            }
            let identity = r["identity"].as_str().unwrap_or("").to_string();
            if !identities.contains(&identity) {
                identities.push(identity.clone());
            }
            let last = requests.last_mut().expect("a request row was pushed");
            last["cells"][identity] = json!({
                "verdict": r["verdict"],
                "confidence": r["confidence"],
                "status": r["status"],
                "history_id": r["history_id"],
            });
        }
        Ok(json!({"run_id": run_id, "identities": identities, "requests": requests, "truncated": truncated}))
    }

    /// Recent authz runs, newest first, with their rows per verdict.
    pub fn authz_runs(&self, limit: usize) -> Result<Vec<Value>> {
        let ids: Vec<i64> = {
            let mut stmt = self.conn.prepare("SELECT id FROM jobs WHERE kind = 'authz' ORDER BY id DESC LIMIT ?1")?;
            let rows = stmt.query_map([limit as i64], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                let job = self.job_get(id)?;
                Ok(json!({
                    "run_id": id,
                    "time": job["time"],
                    "state": job["state"],
                    "args": job["args"],
                    "verdicts": self.authz_counts(id)?,
                }))
            })
            .collect()
    }

    /// Whether a job is an authz run.
    pub fn authz_run_exists(&self, run_id: i64) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT kind FROM jobs WHERE id = ?1", [run_id], |r| r.get::<_, String>(0))
            .optional()?
            .is_some_and(|k| k == "authz"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthProfile;

    fn session(name: &str, profile: AuthProfile) -> Arc<AuthSession> {
        let scope = crate::guard::ScopeSpec { name: None, include: vec!["a.test".into()], exclude: vec![] };
        let guard = crate::guard::Guard::from_specs(vec![scope]).unwrap();
        let client = Client::new(SendOptions { guard: Some(guard), ..Default::default() });
        Arc::new(
            AuthSession::new(
                Path::new("/nonexistent"),
                AuthProfile { name: name.into(), ..profile },
                Default::default(),
                client,
            )
            .unwrap(),
        )
    }

    fn json_resp(body: &str) -> Body {
        Body::parse(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}").as_bytes())
    }

    #[test]
    fn strip_removes_credentials_and_keeps_named_cookies() {
        let key = session("key", AuthProfile { headers: vec![("X-Api-Key".into(), "k".into())], ..Default::default() });
        let req = "GET /a HTTP/1.1\r\nHost: a.test\r\nAuthorization: Bearer x\r\nX-Api-Key: k\r\n\
                   X-Other: «auth:app:header:X-Other»\r\nCookie: sid=1; lang=en\r\nAccept: */*\r\n\r\n";
        let signed = "GET /a?x=1&sig=«auth:k:sign:s» HTTP/1.1\r\nHost: a.test\r\n\r\n";
        assert!(has_credentials(signed.as_bytes(), [&key.profile]));
        let out = String::from_utf8(strip_auth(signed.as_bytes(), &[], &[])).unwrap();
        assert!(out.starts_with("GET /a?x=1 HTTP/1.1\r\n"), "{out}");
        let only =
            String::from_utf8(strip_query_auth("GET /a?sig=«auth:k:sign:s» HTTP/1.1\r\n\r\n".as_bytes())).unwrap();
        assert!(only.starts_with("GET /a HTTP/1.1\r\n"), "{only}");
        let out = String::from_utf8(strip_auth(req.as_bytes(), std::slice::from_ref(&key), &["lang".into()])).unwrap();
        assert_eq!(out, "GET /a HTTP/1.1\r\nHost: a.test\r\nCookie: lang=en\r\nAccept: */*\r\n\r\n");
        let out = String::from_utf8(strip_auth(req.as_bytes(), &[key], &[])).unwrap();
        assert_eq!(out, "GET /a HTTP/1.1\r\nHost: a.test\r\nAccept: */*\r\n\r\n");
    }

    #[test]
    fn owner_by_placeholder_or_header_value() {
        let alice = session(
            "alice",
            AuthProfile { headers: vec![("X-Api-Key".into(), "alice-key-123".into())], ..Default::default() },
        );
        let bob = session(
            "bob",
            AuthProfile { headers: vec![("X-Api-Key".into(), "bob-key-4567".into())], ..Default::default() },
        );
        let known = [alice, bob];
        let by_ph = b"GET / HTTP/1.1\r\nCookie: sid=\xc2\xabauth:bob:cookie:sid\xc2\xbb\r\n\r\n";
        assert_eq!(placeholder_profiles(by_ph), vec!["bob".to_string()]);
        assert_eq!(detect_owner(by_ph, &known).unwrap().profile.name, "bob");
        let by_value = b"GET / HTTP/1.1\r\nX-Api-Key: alice-key-123\r\n\r\n";
        assert_eq!(detect_owner(by_value, &known).unwrap().profile.name, "alice");
        assert!(detect_owner(b"GET / HTTP/1.1\r\n\r\n", &known).is_none());
        // A static Cookie header, as captured through the proxy.
        let carol = session(
            "carol",
            AuthProfile { headers: vec![("Cookie".into(), "sid=carol-session".into())], ..Default::default() },
        );
        let known = [known[0].clone(), carol];
        let by_cookie = b"GET / HTTP/1.1\r\nCookie: lang=en; sid=carol-session\r\n\r\n";
        assert_eq!(detect_owner(by_cookie, &known).unwrap().profile.name, "carol");
    }

    #[test]
    fn credentials_include_profile_headers() {
        let key =
            AuthProfile { name: "k".into(), headers: vec![("X-Api-Key".into(), "v".into())], ..Default::default() };
        let req = b"GET / HTTP/1.1\r\nHost: a.test\r\nx-api-key: abc\r\n\r\n";
        assert!(has_credentials(req, [&key]));
        assert!(!has_credentials(req, []));
        assert!(has_credentials(b"GET / HTTP/1.1\r\nCookie: a=b\r\n\r\n", []));
    }

    fn judged(base_json: &str, resp: &str, object: bool, anonymous: bool, user: Option<&str>) -> Row {
        let body = json_resp(base_json);
        let noise = Noise::default();
        let private = private_values(&body, &noise, &["GET /api/orders/17"]);
        let base = Baseline {
            body: &body,
            noise: &noise,
            private: &private,
            owner_user: Some("alice"),
            object,
            privileged: false,
            comparable: true,
        };
        judge(&base, &json_resp(resp), false, "GET /api/orders/17", anonymous, user)
    }

    #[test]
    fn nothing_to_compare_is_not_a_bypass() {
        let noise = Noise::default();
        for empty in [Body::parse(b"HTTP/1.1 204 No Content\r\n\r\n"), json_resp("{}"), json_resp("[]")] {
            assert!(!noise.has_content(&empty), "{empty:?}");
            let comparable = noise.has_content(&empty);
            let base = Baseline {
                body: &empty,
                noise: &noise,
                private: &[],
                owner_user: None,
                object: true,
                privileged: false,
                comparable,
            };
            for anonymous in [false, true] {
                let r = judge(&base, &empty, false, "", anonymous, None);
                assert_eq!((r.verdict, r.confidence), (Verdict::Inconclusive, None), "{r:?}");
            }
            // A refusal still counts.
            let refused = Body::parse(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            assert_eq!(judge(&base, &refused, false, "", false, None).verdict, Verdict::Enforced);
        }
    }

    #[test]
    fn one_private_value_must_come_back() {
        let shared: String = (0..40).map(|i| format!(r#""k{i}":"v{i}","#)).collect();
        let body = json_resp(&format!(r#"{{{shared}"ref":"r-alice"}}"#));
        let noise = Noise::default();
        let private = [("ref".to_string(), "r-alice".to_string())];
        let base = Baseline {
            body: &body,
            noise: &noise,
            private: &private,
            owner_user: None,
            object: true,
            privileged: false,
            comparable: true,
        };
        let theirs = json_resp(&format!(r#"{{{shared}"ref":"r-bob"}}"#));
        let r = judge(&base, &theirs, false, "", false, None);
        assert!(r.similarity.unwrap() >= 0.95, "{r:?}");
        assert_eq!(r.verdict, Verdict::Different, "{r:?}");
        let r = judge(&base, &body, false, "", false, None);
        assert_eq!(r.verdict, Verdict::Bypass, "{r:?}");
    }

    #[test]
    fn verdicts() {
        let alice = r#"{"id":17,"owner":"alice","email":"alice@a.test","total":"12.50"}"#;
        let r = judged(alice, alice, true, false, Some("bob"));
        assert_eq!((r.verdict, r.confidence), (Verdict::Bypass, Some(Confidence::High)), "{r:?}");
        let r =
            judged(alice, r#"{"id":18,"owner":"bob","email":"bob@a.test","total":"3.00"}"#, true, false, Some("bob"));
        assert_eq!(r.verdict, Verdict::Different, "{r:?}");
        let r = judged(alice, alice, true, true, None);
        assert_eq!((r.verdict, r.confidence), (Verdict::Bypass, Some(Confidence::High)), "{r:?}");
        let shared = r#"{"products":["a","b"],"currency":"EUR"}"#;
        let r = judged(shared, shared, false, false, Some("bob"));
        assert_eq!((r.verdict, r.confidence), (Verdict::Bypass, Some(Confidence::Low)), "{r:?}");
        let r = judged(shared, shared, false, true, None);
        assert_eq!(r.verdict, Verdict::Public, "{r:?}");
        let denied = Body::parse(b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"Access denied\"}");
        let body = json_resp(alice);
        let noise = Noise::default();
        let base = Baseline {
            body: &body,
            noise: &noise,
            private: &[],
            owner_user: None,
            object: true,
            privileged: false,
            comparable: true,
        };
        assert_eq!(judge(&base, &denied, false, "", false, None).verdict, Verdict::Enforced);
        let forbidden = Body::parse(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        assert_eq!(judge(&base, &forbidden, false, "", false, None).verdict, Verdict::Enforced);
    }
}
