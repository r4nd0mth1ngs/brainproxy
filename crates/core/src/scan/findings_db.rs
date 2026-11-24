//! Findings storage. Repeated instances of the same issue (same alert, method, URL
//! without its query or path parameters, and parameter) are folded into one row with a hit
//! count, so a missing header seen 500 times on a page is one finding, and a response with
//! two versioned Server headers is one finding, not two. The first evidence is kept.

use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::scan::{Confidence, Finding, Message, Risk};
use crate::store::Store;

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    source TEXT NOT NULL,
    rule_id INTEGER NOT NULL,
    alert_ref TEXT NOT NULL,
    name TEXT NOT NULL,
    risk TEXT NOT NULL,
    risk_level INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    cwe INTEGER,
    wasc INTEGER,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    param TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    other_info TEXT NOT NULL DEFAULT '',
    history_id INTEGER,
    last_history_id INTEGER,
    hits INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'open',
    note TEXT,
    dedupe TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS findings_alert ON findings(alert_ref);
CREATE INDEX IF NOT EXISTS findings_host ON findings(host);
CREATE TABLE IF NOT EXISTS finding_types (
    alert_ref TEXT PRIMARY KEY,
    rule_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    solution TEXT NOT NULL,
    refs TEXT NOT NULL,
    tags TEXT NOT NULL
);
";

pub const FINDING_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Finding id"),
    ("time", "TEXT", "When first seen"),
    ("source", "TEXT", "passive, active, authz, or manual (added by hand with `findings add`)"),
    ("rule_id", "INTEGER", "Rule id (ZAP plugin id for ported rules)"),
    ("alert_ref", "TEXT", "Alert type id; join finding_types for description/solution"),
    ("name", "TEXT", "Alert name"),
    ("risk", "TEXT", "info, low, medium, high, critical"),
    ("risk_level", "INTEGER", "0 info, 1 low, 2 medium, 3 high, 4 critical (for sorting/filtering)"),
    ("confidence", "TEXT", "low, medium, high"),
    ("cwe", "INTEGER", "CWE id"),
    ("wasc", "INTEGER", "WASC id"),
    ("host", "TEXT", "Host"),
    ("method", "TEXT", "Request method"),
    ("url", "TEXT", "URL where first seen"),
    ("param", "TEXT", "Affected parameter, header, or cookie"),
    ("evidence", "TEXT", "Matched evidence"),
    ("other_info", "TEXT", "Extra detail"),
    ("attack", "TEXT", "Payload that triggered an active finding"),
    ("history_id", "INTEGER", "history.id where first seen (source manual: the first linked entry)"),
    (
        "last_history_id",
        "INTEGER",
        "history.id where last seen (source manual: the last linked entry; `findings show` lists them all in history_ids)",
    ),
    (
        "base_history_id",
        "INTEGER",
        "Source active: history.id of the request the attack (history_id) was built from, its baseline \
         (`findings verify` sends both); NULL for other sources and for findings from before brainproxy kept it",
    ),
    (
        "hits",
        "INTEGER",
        "Times seen (same alert, method, URL without query or path parameters, param); 0 for a triaged passive finding that \
         `scan passive --rescan` didn't find again (kept so its triage isn't lost)",
    ),
    (
        "state",
        "TEXT",
        "open, confirmed, false_positive, fixed, accepted_risk, retest_pending, or removed (source manual, by \
         `findings remove`; hidden unless --state all). A fixed finding a scanner sees again is open again",
    ),
    ("note", "TEXT", "Free-text note"),
    (
        "origin",
        "TEXT",
        "Who or what added it: gui (the desktop app), cli (a terminal or script), mcp (an agent through MCP); \
         NULL for findings from before brainproxy kept it",
    ),
    (
        "state_origin",
        "TEXT",
        "gui, cli or mcp: who last changed state with `findings mark` (or `findings remove`); scanner when a scanner \
         saw a fixed finding again and opened it; NULL if never changed",
    ),
    ("state_changed_at", "TEXT", "UTC time of the last state change; NULL if never changed"),
    ("note_origin", "TEXT", "gui, cli or mcp: who last set the note with `findings mark --note`; NULL if never set"),
    ("note_changed_at", "TEXT", "UTC time the note was last set"),
    ("issue_id", "INTEGER", "The issue (root cause: alert type and host) it is an instance of; join issues"),
    (
        "suppressed_by",
        "INTEGER",
        "The suppression rule (suppressions.id, `findings suppress`) that marked it a false positive; NULL when none \
         did, or once its state was changed since",
    ),
    (
        "scanner_risk",
        "TEXT",
        "While a person's rating (`findings rate`) holds: the scanner's own risk (risk is the person's); NULL otherwise",
    ),
    ("scanner_risk_level", "INTEGER", "scanner_risk as a level"),
    ("scanner_confidence", "TEXT", "While a person's rating holds: the scanner's own confidence"),
    ("rated_reason", "TEXT", "Why a person rated it"),
    (
        "rated_origin",
        "TEXT",
        "gui or cli: who rated it (for an alert filter's rating, who added the filter); NULL when the scanner's \
         rating stands",
    ),
    ("rated_at", "TEXT", "When it was rated"),
    (
        "rated_by",
        "INTEGER",
        "The alert filter (suppressions.id with action 'rate', `findings filter`) whose rating it has; NULL when \
         a person rated it, or the scanner's rating stands",
    ),
];

/// Column documentation for the alert types.
pub const FINDING_TYPE_COLUMNS: &[(&str, &str, &str)] = &[
    ("alert_ref", "TEXT", "Alert type id (findings.alert_ref)"),
    ("rule_id", "INTEGER", "Rule id; 0 for a title added by hand"),
    ("name", "TEXT", "Alert name, or the title of findings added by hand"),
    ("description", "TEXT", "What the issue is"),
    ("solution", "TEXT", "How to fix it"),
    ("refs", "TEXT", "JSON array of reference URLs"),
    ("tags", "TEXT", "JSON array of tags (manual for a title added by hand)"),
    (
        "description_origin",
        "TEXT",
        "gui, cli or mcp: who wrote the description of a title added by hand (gave it first, filled it in \
         when blank, or replaced it); NULL for a scanner's own text, and from before brainproxy kept it",
    ),
    ("solution_origin", "TEXT", "gui, cli or mcp: who wrote the solution, as description_origin"),
];

/// Triage states a finding can be marked with. `removed` is set only by `findings remove`.
pub const STATES: &[&str] = &["open", "confirmed", "false_positive", "fixed", "accepted_risk", "retest_pending"];

/// Sets a finding's state and/or note and who set them, and puts each change on its
/// timeline. An empty note clears it.
pub(crate) fn mark_one(conn: &rusqlite::Connection, id: i64, state: Option<&str>, note: Option<&str>) -> Result<()> {
    mark_with(conn, id, state, note, None)
}

/// [`mark_one`], with what caused a state change (its text and request) on its event: a
/// retest's outcome stays with the fix it made.
pub(crate) fn mark_with(
    conn: &rusqlite::Connection,
    id: i64,
    state: Option<&str>,
    note: Option<&str>,
    cause: Option<(&str, Option<i64>)>,
) -> Result<()> {
    if let Some(s) = state.filter(|s| !STATES.contains(s)) {
        return Err(Error::InvalidInput(format!("unknown state {s:?}: one of {}", STATES.join(", "))));
    }
    type Before = (String, Option<String>, Option<String>, Option<String>);
    let before: Option<Before> = conn
        .prepare_cached(
            "SELECT state, note, state_origin, note_origin FROM findings WHERE id = ?1 AND state != 'removed'",
        )?
        .query_row([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .optional()?;
    // A retest's outcome (`cause`) is held back by the retest itself (`finding_retested`).
    if let Some((old_state, old_note, state_by, note_by)) = before.as_ref().filter(|_| cause.is_none()) {
        let instead = format!(
            "suggest the change with `findings mark {id} --suggest` and the same --state or --note, for a person \
             to decide"
        );
        if state.is_some_and(|s| s != old_state) {
            let what = format!("finding {id}'s state ({})", old_state.replace('_', " "));
            crate::provenance::agent_may_change(&what, state_by.as_deref(), &instead)?;
        }
        let shown = |n: Option<&str>| n.map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
        if note.is_some() && shown(note) != shown(old_note.as_deref()) {
            crate::provenance::agent_may_change(&format!("finding {id}'s note"), note_by.as_deref(), &instead)?;
        }
    }
    // The state it already has is no change: who changed it and when stay as they were, so the
    // timeline and `state_changed_at` (what a later sighting of a fixed finding is compared
    // with) keep telling the truth. Decided by the row as the UPDATE finds it, so a scanner
    // reopening it meanwhile can't turn a real mark into a no-op.
    let n = conn.execute(
        "UPDATE findings SET state = COALESCE(?1, state),
            note = CASE WHEN ?2 IS NULL THEN note ELSE NULLIF(?2, '') END,
            state_origin = CASE WHEN ?1 IS NULL OR ?1 = state THEN state_origin ELSE ?4 END,
            suppressed_by = CASE WHEN ?1 IS NULL OR ?1 = state THEN suppressed_by ELSE NULL END,
            state_changed_at = CASE WHEN ?1 IS NULL OR ?1 = state THEN state_changed_at
                ELSE strftime('%Y-%m-%dT%H:%M:%fZ','now') END,
            note_origin = CASE WHEN ?2 IS NULL THEN note_origin ELSE ?4 END,
            note_changed_at = CASE WHEN ?2 IS NULL THEN note_changed_at
                ELSE strftime('%Y-%m-%dT%H:%M:%fZ','now') END
         WHERE id = ?3 AND state != 'removed'",
        params![state, note, id, crate::provenance::origin()],
    )?;
    if n == 0 {
        let exists = conn.query_row("SELECT 1 FROM findings WHERE id = ?1", [id], |_| Ok(())).optional()?;
        return Err(match exists {
            Some(()) => Error::Conflict(format!("finding {id} was removed; add it again to record it")),
            None => Error::NotFound(format!("finding {id}")),
        });
    }
    let (old_state, old_note, ..) = before.unwrap_or_default();
    let event = |kind, old: Option<&str>, new: Option<&str>, text: Option<&str>, history_id: Option<i64>| {
        crate::scan::issues::record(
            conn,
            &crate::scan::issues::Event { finding: Some(id), kind, old, new, text, history_id, ..Default::default() },
        )
    };
    if let Some(s) = state.filter(|s| *s != old_state) {
        event("state", Some(&old_state), Some(s), cause.map(|c| c.0), cause.and_then(|c| c.1))?;
    }
    if let Some(n) = note.map(str::trim).map(|n| Some(n).filter(|n| !n.is_empty())) {
        // Compared as the note is shown: a note re-saved with other spacing isn't a change.
        if n != old_note.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
            event("note", old_note.as_deref(), None, n, None)?;
        }
    }
    Ok(())
}

/// A person's rating of scanner findings: a risk and/or a confidence (the one left out stays
/// as it is), and why.
#[derive(Debug, Clone, Copy)]
pub struct Rating<'a> {
    pub risk: Option<&'a str>,
    pub confidence: Option<&'a str>,
    pub reason: &'a str,
}

/// "medium/high": a risk and confidence, as a rating event records them.
fn rating_text(risk: &str, confidence: &str) -> String {
    format!("{risk}/{confidence}")
}

/// Rates a scanner finding as a person sees it: `risk` and/or `confidence` (the one left out
/// stays) in place of the scanner's, which is kept beside it (scanner_risk, scanner_confidence)
/// while the rating holds, with `reason`, by `origin`, and a `rated` event on its timeline
/// (`text`, else the reason). Lists, filters, reports and gates use the rating. A finding
/// added by hand has its own risk to edit. Returns whether anything changed.
pub(crate) fn rate_one(
    conn: &rusqlite::Connection,
    id: i64,
    rating: &Rating<'_>,
    origin: &str,
    text: Option<&str>,
    history_id: Option<i64>,
) -> Result<bool> {
    let Rating { risk, confidence, reason } = *rating;
    type Row = (String, String, String, String, Option<String>, Option<String>);
    let (source, state, old_risk, old_confidence, old_reason, rated_by): Row = conn
        .prepare_cached(
            "SELECT source, state, risk, confidence, rated_reason, rated_origin FROM findings WHERE id = ?1",
        )?
        .query_row([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
    if source == MANUAL_SOURCE {
        return Err(Error::InvalidInput(format!(
            "finding {id} was added by hand: its risk and confidence are its own (`findings edit {id} --risk ...`)"
        )));
    }
    if state == REMOVED {
        return Err(Error::Conflict(format!("finding {id} was removed")));
    }
    let new_risk = risk.unwrap_or(&old_risk);
    let new_confidence = confidence.unwrap_or(&old_confidence);
    let level = Risk::parse(new_risk).ok_or_else(|| Error::InvalidInput(format!("unknown risk {new_risk:?}")))?.level();
    if Confidence::parse(new_confidence).is_none() {
        return Err(Error::InvalidInput(format!("unknown confidence {new_confidence:?}")));
    }
    if rated_by.is_some()
        && new_risk == old_risk
        && new_confidence == old_confidence
        && old_reason.as_deref() == Some(reason)
    {
        return Ok(false);
    }
    conn.prepare_cached(
        "UPDATE findings SET
            scanner_risk = CASE WHEN rated_origin IS NULL THEN risk ELSE scanner_risk END,
            scanner_risk_level = CASE WHEN rated_origin IS NULL THEN risk_level ELSE scanner_risk_level END,
            scanner_confidence = CASE WHEN rated_origin IS NULL THEN confidence ELSE scanner_confidence END,
            risk = ?2, risk_level = ?3, confidence = ?4, rated_reason = ?5, rated_origin = ?6,
            rated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), rated_by = NULL
         WHERE id = ?1",
    )?
    .execute(params![id, new_risk, level, new_confidence, reason, origin])?;
    crate::scan::issues::record(
        conn,
        &crate::scan::issues::Event {
            origin: Some(origin),
            finding: Some(id),
            kind: "rated",
            old: Some(&rating_text(&old_risk, &old_confidence)),
            new: Some(&rating_text(new_risk, new_confidence)),
            text: Some(text.unwrap_or(reason)),
            history_id,
            ..Default::default()
        },
    )?;
    Ok(true)
}

/// Gives a rated finding the scanner's rating back (the highest its sightings gave since).
/// Returns whether it was rated.
fn unrate_one(conn: &rusqlite::Connection, id: i64) -> Result<bool> {
    let row: Option<(String, String, String, String)> = conn
        .query_row(
            "SELECT risk, confidence, scanner_risk, scanner_confidence FROM findings
             WHERE id = ?1 AND rated_origin IS NOT NULL",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((risk, confidence, scanner_risk, scanner_confidence)) = row else {
        return Ok(false);
    };
    conn.execute(
        "UPDATE findings SET risk = scanner_risk, risk_level = scanner_risk_level, confidence = scanner_confidence,
            scanner_risk = NULL, scanner_risk_level = NULL, scanner_confidence = NULL,
            rated_reason = NULL, rated_origin = NULL, rated_at = NULL, rated_by = NULL
         WHERE id = ?1",
        [id],
    )?;
    crate::scan::issues::record(
        conn,
        &crate::scan::issues::Event {
            finding: Some(id),
            kind: "rated",
            old: Some(&rating_text(&risk, &confidence)),
            new: Some(&rating_text(&scanner_risk, &scanner_confidence)),
            text: Some("the scanner's rating again"),
            ..Default::default()
        },
    )?;
    Ok(true)
}

/// A finding's rating as lists show it: null when the scanner's stands. `filter` is the alert
/// filter that rated it, null when a person did.
fn rated_json(
    reason: Option<String>,
    origin: Option<String>,
    at: Option<String>,
    scanner_risk: Option<String>,
    scanner_confidence: Option<String>,
    filter: Option<i64>,
) -> Value {
    match origin {
        None => Value::Null,
        Some(o) => json!({
            "scanner_risk": scanner_risk,
            "scanner_confidence": scanner_confidence,
            "reason": reason,
            "by": crate::provenance::describe(Some(&o)),
            "origin": o,
            "at": at,
            "filter": filter,
        }),
    }
}

/// Column documentation for the suppression rules (`findings suppress`) and alert filters
/// (`findings filter`), which share the table.
pub const SUPPRESSION_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Rule id"),
    ("time", "TEXT", "When it was added"),
    (
        "action",
        "TEXT",
        "suppress (`findings suppress`: marks what it matches a false positive) or rate (`findings filter`: \
         gives what it matches its risk and/or confidence)",
    ),
    ("alert_ref", "TEXT", "Alert ref or rule id it matches (findings.alert_ref, or findings.rule_id as text)"),
    ("host", "TEXT", "Host it matches (findings.host, lowercase); '' for any host (alert filters only)"),
    ("port", "INTEGER", "Only findings on this port (--host NAME:PORT); NULL for any"),
    ("path_prefix", "TEXT", "Only findings whose URL path starts with this; '' for any path"),
    ("param", "TEXT", "Only findings of this parameter, header or cookie; NULL for any"),
    ("url_regex", "TEXT", "Alert filters: only findings whose URL this regex finds a match in; NULL for any"),
    ("param_regex", "TEXT", "Alert filters: only findings whose parameter this regex finds a match in; NULL for any"),
    ("risk", "TEXT", "Alert filters: the risk it gives; NULL keeps the scanner's"),
    ("confidence", "TEXT", "Alert filters: the confidence it gives; NULL keeps the scanner's"),
    (
        "reason",
        "TEXT",
        "Why: the note of each finding a suppression marks, the rating reason of each finding a filter rates",
    ),
    ("origin", "TEXT", "Who added it: gui or cli (agents can't)"),
];

/// A suppression rule to add: findings of `alert` on `host` (under `path_prefix`, of `param`)
/// are false positives, for `reason`, now and whenever a scanner finds one again.
#[derive(Debug, Clone, Default)]
pub struct Suppression {
    pub alert: String,
    pub host: String,
    pub path_prefix: String,
    pub param: Option<String>,
    pub reason: String,
}

/// An alert filter to add: scanner findings of `alert` (on `host`, any when `None`; under
/// `path_prefix`; of `param`; whose URL and parameter the regexes find a match in) take `risk`
/// and/or `confidence` in place of the scanner's, for `reason`, now and whenever found again.
#[derive(Debug, Clone, Default)]
pub struct AlertFilter {
    pub alert: String,
    pub host: Option<String>,
    pub path_prefix: String,
    pub url_regex: Option<String>,
    pub param: Option<String>,
    pub param_regex: Option<String>,
    pub risk: Option<String>,
    pub confidence: Option<String>,
    pub reason: String,
}

/// What a rule does to the findings it matches, as the table's `action` holds it.
const SUPPRESS: &str = "suppress";
const RATE: &str = "rate";

/// Longest URL or parameter regex an alert filter takes.
const FILTER_REGEX_MAX: usize = 1000;

/// A filter's regex, compiled with a size limit, so a pattern that would blow up is refused
/// rather than run on every finding.
fn filter_regex(flag: &str, src: &str) -> Result<regex::Regex> {
    if src.len() > FILTER_REGEX_MAX {
        return Err(Error::InvalidInput(format!("{flag}: at most {FILTER_REGEX_MAX} bytes")));
    }
    regex::RegexBuilder::new(src)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| Error::InvalidInput(format!("{flag} {src:?}: not a valid regex ({e})")))
}

/// A stored rule, as matching needs it.
struct Rule {
    id: i64,
    port: Option<u16>,
    path_prefix: String,
    param: Option<String>,
    url_regex: Option<regex::Regex>,
    param_regex: Option<regex::Regex>,
    risk: Option<String>,
    confidence: Option<String>,
    reason: String,
    origin: Option<String>,
}

impl Rule {
    fn matches(&self, url: &str, param: &str) -> bool {
        if self.param.as_deref().is_some_and(|p| p != param) {
            return false;
        }
        if self.param_regex.as_ref().is_some_and(|r| !r.is_match(param)) {
            return false;
        }
        if self.url_regex.as_ref().is_some_and(|r| !r.is_match(url)) {
            return false;
        }
        if self.path_prefix.is_empty() && self.port.is_none() {
            return true;
        }
        url::Url::parse(&identity_url(url)).is_ok_and(|u| {
            u.path().starts_with(&self.path_prefix) && self.port.is_none_or(|p| u.port_or_known_default() == Some(p))
        })
    }
}

/// The rules doing `action` for `alert_ref` (or its rule id) on `host`, or on any host,
/// oldest first. A stored regex that no longer compiles (a lower size limit in a later build,
/// say) leaves its rule out rather than letting it match everything.
fn rules_for(
    conn: &rusqlite::Connection,
    action: &str,
    alert_ref: &str,
    rule_id: i64,
    host: &str,
) -> Result<Vec<Rule>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, path_prefix, param, reason, origin, port, url_regex, param_regex, risk, confidence
         FROM suppressions
         WHERE action = ?4 AND (alert_ref = ?1 OR alert_ref = CAST(?2 AS TEXT)) AND (host = lower(?3) OR host = '')
         ORDER BY id",
    )?;
    type Row = (i64, String, Option<String>, String, Option<String>, Option<u16>, Option<String>, Option<String>);
    type Given = (Option<String>, Option<String>);
    let rows: Vec<(Row, Given)> = stmt
        .query_map(params![alert_ref, rule_id, host, action], |r| {
            Ok((
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?),
                (r.get(8)?, r.get(9)?),
            ))
        })?
        .collect::<std::result::Result<_, _>>()?;
    let mut rules = Vec::with_capacity(rows.len());
    for ((id, path_prefix, param, reason, origin, port, url_regex, param_regex), (risk, confidence)) in rows {
        let compile = |src: Option<String>| src.map(|s| filter_regex("regex", &s)).transpose();
        let (Ok(url_regex), Ok(param_regex)) = (compile(url_regex), compile(param_regex)) else {
            continue;
        };
        // Nor does a rating no build can give (a hand-edited row): it would fail the whole scan's
        // write, not just this rule.
        if risk.as_deref().is_some_and(|r| Risk::parse(r).is_none())
            || confidence.as_deref().is_some_and(|c| Confidence::parse(c).is_none())
        {
            continue;
        }
        rules.push(Rule { id, port, path_prefix, param, url_regex, param_regex, risk, confidence, reason, origin });
    }
    Ok(rules)
}

/// Marks an open finding nobody triaged a false positive by `rule`, as the rule's author set
/// it (an agent can't undo it either), with the reason as its note when it has none, and a
/// state event that names the rule. Returns whether it changed.
fn suppress_by(conn: &rusqlite::Connection, finding: i64, rule: &Rule, history_id: Option<i64>) -> Result<bool> {
    let n = conn
        .prepare_cached(
            "UPDATE findings SET state = 'false_positive', state_origin = ?2, suppressed_by = ?3,
                state_changed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                note_origin = CASE WHEN note IS NULL THEN ?2 ELSE note_origin END,
                note_changed_at = CASE WHEN note IS NULL THEN strftime('%Y-%m-%dT%H:%M:%fZ','now')
                    ELSE note_changed_at END,
                note = COALESCE(note, ?4)
             WHERE id = ?1 AND state = 'open' AND source != ?5
                AND (state_origin IS NULL OR state_origin = ?6)",
        )?
        .execute(params![finding, rule.origin, rule.id, rule.reason, MANUAL_SOURCE, crate::provenance::SCANNER])?;
    if n == 0 {
        return Ok(false);
    }
    let text = format!("suppressed by rule {}: {}", rule.id, rule.reason);
    crate::scan::issues::record(
        conn,
        &crate::scan::issues::Event {
            origin: rule.origin.as_deref(),
            finding: Some(finding),
            kind: "state",
            old: Some("open"),
            new: Some("false_positive"),
            text: Some(&text),
            history_id,
            ..Default::default()
        },
    )?;
    Ok(true)
}

/// A suppression rule's `--host`: findings keep their host without the port, so `NAME:PORT`
/// (or `[v6]:PORT`) becomes the name to match plus a port the URL must have.
fn suppression_host(given: &str) -> Result<(String, Option<u16>)> {
    let given = given.trim();
    let bad = || Error::InvalidInput(format!("--host {given:?}: give a host name, such as app.test or 127.0.0.1:3000"));
    if given.is_empty() || given.contains(['/', ' ', '@', '?', '#']) {
        return Err(bad());
    }
    let parsed = url::Url::parse(&format!("http://{given}/")).map_err(|_| bad())?;
    let host = url_host(&parsed).to_ascii_lowercase();
    if host.is_empty() {
        return Err(bad());
    }
    let has_port = if given.starts_with('[') { given.contains("]:") } else { given.contains(':') };
    // `port()` is None for http's default, so `NAME:80` reads back as no port: it was given.
    Ok((host, has_port.then(|| parsed.port().unwrap_or(80))))
}

/// A new finding a scanner found, matched against the suppression rules: the first (oldest)
/// that matches marks it. Returns whether one did.
pub(crate) fn suppress_new(conn: &rusqlite::Connection, finding: i64, history_id: Option<i64>) -> Result<bool> {
    let (alert_ref, rule_id, host, url, param): (String, i64, String, String, String) = conn
        .prepare_cached("SELECT alert_ref, rule_id, host, url, param FROM findings WHERE id = ?1")?
        .query_row([finding], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
    for rule in rules_for(conn, SUPPRESS, &alert_ref, rule_id, &host)? {
        if rule.matches(&url, &param) {
            return suppress_by(conn, finding, &rule, history_id);
        }
    }
    Ok(false)
}

/// Gives a scanner finding nobody rated `rule`'s rating, as the filter's author rated it, with
/// its timeline naming the filter, and the filter in `rated_by`. Returns whether it changed.
/// Which states qualify is the caller's: adding a filter takes open findings only, while a new
/// finding is rated in whatever state its issue's decision gave it (a rating isn't a state).
fn rate_by(conn: &rusqlite::Connection, finding: i64, rule: &Rule, history_id: Option<i64>) -> Result<bool> {
    let fits: bool = conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM findings WHERE id = ?1 AND state != ?3 AND source != ?2
                AND rated_origin IS NULL)",
        )?
        .query_row(params![finding, MANUAL_SOURCE, REMOVED], |r| r.get(0))?;
    if !fits {
        return Ok(false);
    }
    let rating = Rating { risk: rule.risk.as_deref(), confidence: rule.confidence.as_deref(), reason: &rule.reason };
    let text = format!("re-rated by filter {}: {}", rule.id, rule.reason);
    // Every filter is added with an origin; one without would be from a hand-edited project.
    let origin = rule.origin.as_deref().unwrap_or("cli");
    if !rate_one(conn, finding, &rating, origin, Some(&text), history_id)? {
        return Ok(false);
    }
    conn.prepare_cached("UPDATE findings SET rated_by = ?2 WHERE id = ?1")?.execute(params![finding, rule.id])?;
    Ok(true)
}

/// A new finding a scanner found, matched against the alert filters: the first (oldest) that
/// matches rates it. Returns whether one did.
pub(crate) fn rate_new(conn: &rusqlite::Connection, finding: i64, history_id: Option<i64>) -> Result<bool> {
    let (alert_ref, rule_id, host, url, param): (String, i64, String, String, String) = conn
        .prepare_cached("SELECT alert_ref, rule_id, host, url, param FROM findings WHERE id = ?1")?
        .query_row([finding], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
    for rule in rules_for(conn, RATE, &alert_ref, rule_id, &host)? {
        if rule.matches(&url, &param) {
            return rate_by(conn, finding, &rule, history_id);
        }
    }
    Ok(false)
}

/// The findings of an issue that aren't removed; an issue with none is not found.
fn issue_ids(conn: &rusqlite::Connection, issue: i64) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare_cached("SELECT id FROM findings WHERE issue_id = ?1 AND state != ?2 ORDER BY id")?;
    let ids: Vec<i64> =
        stmt.query_map(params![issue, REMOVED], |r| r.get(0))?.collect::<std::result::Result<_, _>>()?;
    if ids.is_empty() {
        return Err(Error::NotFound(format!("issue {issue} (or it has no findings)")));
    }
    Ok(ids)
}

/// A finding's state as stored (`removed` included).
fn current_state(conn: &rusqlite::Connection, id: i64) -> Result<String> {
    conn.query_row("SELECT state FROM findings WHERE id = ?1", [id], |r| r.get(0))
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("finding {id}")))
}

/// What makes two findings the same issue. The URL keeps scheme, host and port (two
/// services on one host are different findings) and drops the query (parameters are `param`)
/// and its path's `;name=value` parameters: a session id there (`/login;jsessionid=...`) is new
/// each session, and would make the same finding a new one every time. A URL with neither
/// keys as it did before, so its fingerprint stays the same.
pub(crate) fn dedupe_key(alert_ref: &str, method: &str, url: &str, param: &str) -> String {
    format!("{alert_ref}|{method}|{}|{param}", identity_url(url))
}

/// A finding's URL as its identity sees it ([`dedupe_key`]): without the query or the path's
/// `;name=value` parameters. What a request has to go to, to be one to the finding's address.
pub(crate) fn identity_url(url: &str) -> std::borrow::Cow<'_, str> {
    without_path_params(url.split('?').next().unwrap_or(url))
}

/// The key before schema v18, which kept path parameters. The v10 migration re-keys with it,
/// so its plainer merge (no notes, provenance or risk kept) only joins what v2 joined; v18
/// then merges the rest with everything kept.
fn dedupe_key_v2(alert_ref: &str, method: &str, url: &str, param: &str) -> String {
    let base = url.split('?').next().unwrap_or(url);
    format!("{alert_ref}|{method}|{base}|{param}")
}

/// `url` without the `;name=value` parameters of its path segments: `/a;jsessionid=1/b` is
/// `/a/b`. A `;` piece with no `=` stays, since it isn't a parameter and may be part of a name.
/// A fragment is left as it is: a client-side route (`#/view;id=1`) never reaches the server,
/// and its parameters tell routes apart.
fn without_path_params(url: &str) -> std::borrow::Cow<'_, str> {
    let cut = url.find('#').unwrap_or(url.len());
    if !url[..cut].contains(';') {
        return url.into();
    }
    let (url, fragment) = url.split_at(cut);
    // The authority (which could hold a `;` in a user name) is left as it is.
    let path_at = url.find("://").map_or(0, |i| url[i + 3..].find('/').map_or(url.len(), |j| i + 3 + j));
    let (origin, path) = url.split_at(path_at);
    let path: Vec<String> = path
        .split('/')
        .map(|segment| {
            let mut pieces = segment.split(';');
            let mut kept = pieces.next().unwrap_or_default().to_string();
            for piece in pieces.filter(|p| !p.contains('=')) {
                kept.push(';');
                kept.push_str(piece);
            }
            kept
        })
        .collect();
    format!("{origin}{}{fragment}", path.join("/")).into()
}

/// A finding's identity ([`dedupe_key`]) as a hash: what reports export (SARIF's
/// `partialFingerprints`, `report json`'s `fingerprint`) so a redacted report still matches
/// its findings, and a secret in the URL's path doesn't travel with it.
pub fn fingerprint(alert_ref: &str, method: &str, url: &str, param: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(dedupe_key(alert_ref, method, url, param).as_bytes());
    hex::encode(&hash[..16])
}

/// Schema v10: re-keys findings stored with the old key (which included the evidence and
/// left out the port) and merges the rows that are now one finding: hits are summed, the
/// last sighting kept, and a confirmed or false-positive mark wins over open.
pub(crate) fn rekey_findings(conn: &rusqlite::Connection) -> Result<()> {
    struct Kept {
        id: i64,
        hits: i64,
        last: Option<i64>,
        state: String,
    }
    let mut kept: std::collections::HashMap<String, Kept> = std::collections::HashMap::new();
    let mut drop = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT id, alert_ref, method, url, param, hits, last_history_id, state FROM findings ORDER BY id",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let key = dedupe_key_v2(
                &r.get::<_, String>(1)?,
                &r.get::<_, String>(2)?,
                &r.get::<_, String>(3)?,
                &r.get::<_, String>(4)?,
            );
            let (id, hits, last, state): (i64, i64, Option<i64>, String) = (r.get(0)?, r.get(5)?, r.get(6)?, r.get(7)?);
            match kept.get_mut(&key) {
                Some(k) => {
                    k.hits += hits;
                    k.last = k.last.max(last);
                    if k.state == "open" {
                        k.state = state;
                    }
                    drop.push(id);
                }
                None => {
                    kept.insert(key, Kept { id, hits, last, state });
                }
            }
        }
    }
    // In the migration's transaction. Temporary unique keys first, so no update collides
    // with a row that is about to go.
    conn.execute("UPDATE findings SET dedupe = 'v10-' || id", [])?;
    for id in drop {
        conn.execute("DELETE FROM findings WHERE id = ?1", [id])?;
    }
    for (key, k) in kept {
        conn.execute(
            "UPDATE findings SET dedupe = ?1, hits = ?2, last_history_id = ?3, state = ?4 WHERE id = ?5",
            params![key, k.hits, k.last, k.state, k.id],
        )?;
    }
    Ok(())
}

/// Schema v18: the key drops path parameters (#99), so findings stored once per session id
/// (`/login;jsessionid=A`, `/login;jsessionid=B`) are one finding again. Each set that is now
/// one is merged into its first row: hits summed, the earliest first sighting and the latest
/// last one kept, the highest risk, and the most recent state and note decisions with who
/// made them. The others' timelines and scan observations move to it, so nothing a person
/// recorded is lost. Removed findings (tombstones) keep their own keys.
pub(crate) fn rekey_v18(conn: &rusqlite::Connection) -> Result<()> {
    #[derive(Clone)]
    struct Row {
        id: i64,
        dedupe: String,
        source: String,
        hits: i64,
        history_id: Option<i64>,
        last: Option<i64>,
        risk: String,
        risk_level: i64,
        state: (String, Option<String>, Option<String>),
        note: (Option<String>, Option<String>, Option<String>),
        issue: Option<i64>,
    }
    let mut groups: Vec<(String, Vec<Row>)> = Vec::new();
    {
        let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut stmt = conn.prepare(
            "SELECT id, dedupe, source, alert_ref, method, url, param, hits, history_id, last_history_id, risk,
                risk_level, state, state_origin, state_changed_at, note, note_origin, note_changed_at, issue_id
             FROM findings WHERE state != 'removed' ORDER BY id",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let key = dedupe_key(
                &r.get::<_, String>(3)?,
                &r.get::<_, String>(4)?,
                &r.get::<_, String>(5)?,
                &r.get::<_, String>(6)?,
            );
            let row = Row {
                id: r.get(0)?,
                dedupe: r.get(1)?,
                source: r.get(2)?,
                hits: r.get(7)?,
                history_id: r.get(8)?,
                last: r.get(9)?,
                risk: r.get(10)?,
                risk_level: r.get(11)?,
                state: (r.get(12)?, r.get(13)?, r.get(14)?),
                note: (r.get(15)?, r.get(16)?, r.get(17)?),
                issue: r.get(18)?,
            };
            let at = *index.entry(key.clone()).or_insert_with(|| {
                groups.push((key, Vec::new()));
                groups.len() - 1
            });
            groups[at].1.push(row);
        }
    }
    groups.retain(|(key, rows)| rows.len() > 1 || rows[0].dedupe != *key);
    if groups.is_empty() {
        return Ok(());
    }
    // In the migration's transaction. Temporary unique keys first, so no update collides with
    // a row that is about to go or get another key.
    for row in groups.iter().flat_map(|(_, rows)| rows) {
        conn.execute("UPDATE findings SET dedupe = 'v18-' || id WHERE id = ?1", [row.id])?;
    }
    for (key, rows) in groups {
        let kept = rows[0].clone();
        let dropped: Vec<&Row> = rows[1..].iter().collect();
        // The latest decision wins; one with no time (from before brainproxy kept it) loses to
        // one with a time, and among those the first that isn't open wins.
        let latest = |at: fn(&Row) -> Option<&String>, set: fn(&Row) -> bool| -> &Row {
            rows.iter()
                .filter(|r| at(r).is_some())
                .max_by(|a, b| at(a).cmp(&at(b)))
                .or_else(|| rows.iter().find(|r| set(r)))
                .unwrap_or(&rows[0])
        };
        let state = latest(|r| r.state.2.as_ref(), |r| r.state.0 != "open").state.clone();
        let note = latest(|r| r.note.2.as_ref(), |r| r.note.0.is_some()).note.clone();
        let riskiest = rows.iter().max_by_key(|r| r.risk_level).unwrap_or(&rows[0]);
        let hits: i64 = rows.iter().map(|r| r.hits).sum();
        let (mut first, mut last) = (rows.iter().find_map(|r| r.history_id), rows.iter().filter_map(|r| r.last).max());
        let issue = merged_issue(conn, &rows.iter().map(|r| (r.id, r.issue)).collect::<Vec<_>>())?;
        for d in &dropped {
            conn.execute("UPDATE finding_events SET finding_id = ?1 WHERE finding_id = ?2", [kept.id, d.id])?;
            // One scan's view of the merged finding: found (new, then still) beats not found.
            conn.execute(
                "INSERT INTO scan_observations (job_id, finding_id, seen, time)
                    SELECT job_id, ?1, seen, time FROM scan_observations WHERE finding_id = ?2 AND true
                 ON CONFLICT(job_id, finding_id) DO UPDATE SET seen = CASE
                    WHEN 'new' IN (seen, excluded.seen) THEN 'new'
                    WHEN 'still' IN (seen, excluded.seen) THEN 'still' ELSE seen END",
                [kept.id, d.id],
            )?;
            conn.execute("DELETE FROM scan_observations WHERE finding_id = ?1", [d.id])?;
            conn.execute("DELETE FROM findings WHERE id = ?1", [d.id])?;
        }
        // A finding added by hand links history entries, the whole list in meta: the merged one
        // links them all, in order.
        if kept.source == MANUAL_SOURCE {
            let mut links: Vec<i64> = Vec::new();
            for r in &rows {
                for h in history_ids(conn, r.id, r.history_id, r.last)? {
                    if !links.contains(&h) {
                        links.push(h);
                    }
                }
            }
            (first, last) = (links.first().copied(), links.last().copied());
            for r in &rows {
                conn.execute("DELETE FROM meta WHERE key = ?1", [history_key(r.id)])?;
            }
            if links.len() > 2 {
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                    params![history_key(kept.id), serde_json::to_string(&links).unwrap_or_default()],
                )?;
            }
        }
        if issue != kept.issue {
            // Recorded with no origin, like the events v15 built: no one made this move.
            let ids = rows[1..].iter().map(|r| r.id.to_string()).collect::<Vec<_>>().join(", ");
            conn.execute(
                "INSERT INTO finding_events (finding_id, issue_id, kind, old, new, text)
                 VALUES (?1, ?2, 'moved', ?3, ?4, ?5)",
                params![
                    kept.id,
                    issue,
                    kept.issue.map(|i| i.to_string()),
                    issue.map(|i| i.to_string()),
                    format!("merged with finding {ids}: the same finding with another session id in its path")
                ],
            )?;
        }
        conn.execute(
            "UPDATE findings SET dedupe = ?1, hits = ?2, history_id = ?3, last_history_id = ?4, risk = ?5,
                risk_level = ?6, state = ?7, state_origin = ?8, state_changed_at = ?9, note = ?10, note_origin = ?11,
                note_changed_at = ?12, issue_id = ?14
             WHERE id = ?13",
            params![
                key,
                hits,
                first,
                last,
                riskiest.risk,
                riskiest.risk_level,
                state.0,
                state.1,
                state.2,
                note.0,
                note.1,
                note.2,
                kept.id,
                issue
            ],
        )?;
    }
    Ok(())
}

/// The issue a merged finding goes in, given its rows (id, issue) first row first: its first
/// row's, unless merging would leave another of their issues with no findings while that issue
/// holds a person's records (a title, a CVSS rating, a write-up or its own events). Then that
/// one, so its records still belong to an issue with findings, as `issue show` and reports need.
fn merged_issue(conn: &rusqlite::Connection, rows: &[(i64, Option<i64>)]) -> Result<Option<i64>> {
    let first = rows[0].1;
    let ids = serde_json::to_string(&rows.iter().map(|r| r.0).collect::<Vec<_>>()).unwrap_or_default();
    let mut seen = Vec::new();
    for issue in rows.iter().filter_map(|r| r.1).filter(|&i| Some(i) != first) {
        if seen.contains(&issue) {
            continue;
        }
        seen.push(issue);
        let stranded: bool = conn.query_row(
            "SELECT NOT EXISTS (SELECT 1 FROM findings WHERE issue_id = ?1 AND state != 'removed'
                    AND id NOT IN (SELECT value FROM json_each(?2)))
                AND EXISTS (SELECT 1 FROM issues WHERE id = ?1 AND (title IS NOT NULL OR cvss_vector IS NOT NULL
                    OR narrative IS NOT NULL OR EXISTS (SELECT 1 FROM finding_events e
                        WHERE e.issue_id = ?1 AND e.finding_id IS NULL)))",
            params![issue, ids],
            |r| r.get(0),
        )?;
        if stranded {
            return Ok(Some(issue));
        }
    }
    Ok(first)
}

/// The history entries a finding links: a finding added by hand keeps the whole list in meta
/// when it has more than two; otherwise its first and last sighting.
fn history_ids(conn: &rusqlite::Connection, id: i64, first: Option<i64>, last: Option<i64>) -> Result<Vec<i64>> {
    let list: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [history_key(id)], |r| r.get(0)).optional()?;
    if let Some(list) = list {
        return Ok(serde_json::from_str(&list).unwrap_or_default());
    }
    let mut ids: Vec<i64> = first.into_iter().collect();
    ids.extend(last.filter(|l| Some(*l) != first));
    Ok(ids)
}

/// A clause leaving out the findings whose alert ref starts with one of `keep`, for a statement
/// whose first parameter is the findings' source; and the statement's parameters.
fn not_kept(source: &str, keep: &[String]) -> (String, Vec<String>) {
    let mut clause = String::new();
    let mut args = vec![source.to_string()];
    for prefix in keep {
        args.push(prefix.clone());
        clause.push_str(&format!(" AND substr(alert_ref, 1, length(?{0})) != ?{0}", args.len()));
    }
    (clause, args)
}

/// The request rule whose script answered a history row, from its `edited_by` (JSON).
pub fn answered_by(edited_by: Option<&str>) -> Option<u32> {
    let edits: Vec<crate::provenance::Edit> = serde_json::from_str(edited_by?).ok()?;
    edits.iter().find(|e| e.outcome == Some(crate::provenance::Outcome::Answered)).and_then(|e| e.rule)
}

impl Store {
    /// Captures after `after_id` from the given sources, ready for scanning. A row whose
    /// response a request rule's script made up (its `edited_by` says it was answered) says so
    /// ([`Message::answered_by`]), and so do the findings raised from it.
    pub fn scan_messages_after(&self, after_id: i64, sources: &[String], limit: usize) -> Result<Vec<Message>> {
        let placeholders = (0..sources.len()).map(|i| format!("?{}", i + 3)).collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT id, method, url, scheme, host, port, path, query, req_headers, req_body, status, resp_headers, resp_body,
                    edited_by
             FROM history WHERE id > ?1 AND status IS NOT NULL AND source IN ({placeholders}) ORDER BY id LIMIT ?2"
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(after_id), Box::new(limit as i64)];
        for s in sources {
            args.push(Box::new(s.clone()));
        }
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter().map(|b| b.as_ref())), |r| {
            let headers = |s: Option<String>| -> Vec<(String, String)> {
                s.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
            };
            Ok(Message::new(
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                headers(r.get(8)?),
                r.get::<_, Option<Vec<u8>>>(9)?.unwrap_or_default(),
                r.get(10)?,
                headers(r.get(11)?),
                r.get::<_, Option<Vec<u8>>>(12)?.unwrap_or_default(),
            )
            .answered_by(answered_by(r.get::<_, Option<String>>(13)?.as_deref())))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Highest history id, used to skip scanning when nothing is new.
    pub fn max_history_id(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT coalesce(max(id), 0) FROM history", [], |r| r.get(0))?)
    }

    /// Stores findings for one message; returns how many were new.
    pub fn record_findings(&mut self, source: &str, msg: &Message, findings: &[Finding]) -> Result<usize> {
        self.record_findings_from(source, msg, findings, None)
    }

    /// [`Store::record_findings`] for an attack: `base` is the history row of the request it
    /// was built from. Like the attack and evidence, a finding keeps the base of its first
    /// sighting, so the three always describe the same exchange (history_id).
    pub fn record_findings_from(
        &mut self,
        source: &str,
        msg: &Message,
        findings: &[Finding],
        base: Option<i64>,
    ) -> Result<usize> {
        let urls = vec![msg.url.as_str(); findings.len()];
        self.record_findings_at(source, msg, findings, &urls, base)
    }

    /// The passive scanner's [`Store::record_findings`]. A finding of a rule that judges only
    /// the page (`page_level`, by alert ref), in a response that is a copy of a page it was
    /// already found in at another URL of the same origin, is another sighting of that one: a
    /// single-page app answers every unknown path with its start page, and many sites share one
    /// error page, so one missing header there is one finding, not one per URL. A copy has the
    /// same status, body and evidence, so a page with content of its own is a finding of its own.
    pub fn record_passive_findings(
        &mut self,
        msg: &Message,
        findings: &[Finding],
        page_level: impl Fn(&str) -> bool,
    ) -> Result<usize> {
        let mut first = Vec::with_capacity(findings.len());
        for f in findings {
            first.push(if page_level(f.def.alert_ref) { self.first_page_copy(msg, f)? } else { None });
        }
        let urls: Vec<&str> = first.iter().map(|u| u.as_deref().unwrap_or(&msg.url)).collect();
        self.record_findings_at("passive", msg, findings, &urls, None)
    }

    /// The URL of the first passive finding like `f` whose first sighting got the same answer as
    /// `msg`, from the same origin. An empty body isn't a page: many endpoints answer with one.
    fn first_page_copy(&self, msg: &Message, f: &Finding) -> Result<Option<String>> {
        if msg.resp_body.is_empty() {
            return Ok(None);
        }
        // Only one counted so far (hits > 0): during a rescan, one not found again yet could
        // take sightings and then be found nowhere itself (its row may no longer be scanned).
        // The length is compared first: SQLite reads it from the row's header, where comparing
        // bodies reads each one in full.
        let mut stmt = self.conn.prepare_cached(
            "SELECT f.url FROM findings f JOIN history h ON h.id = f.history_id
             WHERE f.alert_ref = ?1 AND f.host = ?2 AND f.source = 'passive' AND f.method = ?3 AND f.param = ?4
                AND f.evidence = ?5 AND f.hits > 0 AND f.state != 'removed'
                AND h.scheme = ?6 AND h.port = ?7 AND h.status = ?8 AND length(h.resp_body) = ?10
                AND h.resp_body = ?9
             ORDER BY f.id LIMIT 1",
        )?;
        let evidence = truncate(&f.evidence, 2000);
        let args = params![
            f.def.alert_ref,
            msg.host,
            msg.method,
            f.param,
            evidence,
            msg.scheme,
            msg.port,
            msg.status,
            msg.resp_body,
            i64::try_from(msg.resp_body.len()).unwrap_or(i64::MAX)
        ];
        Ok(stmt.query_row(args, |r| r.get(0)).optional()?)
    }

    /// Records `findings` from `msg`, each at its URL in `urls`: the message's own, or that of
    /// the first page it is a copy of.
    fn record_findings_at(
        &mut self,
        source: &str,
        msg: &Message,
        findings: &[Finding],
        urls: &[&str],
        base: Option<i64>,
    ) -> Result<usize> {
        if findings.is_empty() {
            return Ok(0);
        }
        let tx = self.write_tx()?;
        let mut new = 0;
        // A row inserted now has an id above every earlier one; one found again keeps its own
        // (hits alone can't tell: a rescan sets them to 0 first).
        let before: i64 = tx.query_row("SELECT coalesce(max(id), 0) FROM findings", [], |r| r.get(0))?;
        let mut created = std::collections::HashSet::new();
        // One response can raise the same finding twice (two versioned Server headers): it
        // takes the higher of the risks, as one sighting.
        let keys: Vec<String> =
            findings.iter().zip(urls).map(|(f, url)| dedupe_key(f.def.alert_ref, &msg.method, url, &f.param)).collect();
        let mut risks: std::collections::HashMap<&str, Risk> = std::collections::HashMap::new();
        for (f, key) in findings.iter().zip(&keys) {
            let r = risks.entry(key).or_insert(f.risk);
            if f.risk.level() > r.level() {
                *r = f.risk;
            }
        }
        {
            let mut types = tx.prepare_cached(
                "INSERT OR IGNORE INTO finding_types (alert_ref, rule_id, name, description, solution, refs, tags)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            let mut insert = tx.prepare_cached(
                "INSERT INTO findings (source, rule_id, alert_ref, name, risk, risk_level, confidence, cwe, wasc, host,
                    method, url, param, evidence, other_info, history_id, last_history_id, dedupe, attack, origin,
                    base_history_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16, ?17, ?18, ?19, ?20)
                 ON CONFLICT(dedupe) DO UPDATE SET hits = hits + 1, last_history_id = excluded.last_history_id,
                    risk = CASE WHEN rated_origin IS NOT NULL THEN risk
                        WHEN hits = 0 OR excluded.risk_level > risk_level THEN excluded.risk ELSE risk END,
                    risk_level = CASE WHEN rated_origin IS NOT NULL THEN risk_level WHEN hits = 0 THEN excluded.risk_level
                        ELSE max(risk_level, excluded.risk_level) END,
                    scanner_risk = CASE WHEN rated_origin IS NULL THEN scanner_risk
                        WHEN hits = 0 OR excluded.risk_level > scanner_risk_level THEN excluded.risk ELSE scanner_risk END,
                    scanner_risk_level = CASE WHEN rated_origin IS NULL THEN scanner_risk_level
                        WHEN hits = 0 THEN excluded.risk_level ELSE max(scanner_risk_level, excluded.risk_level) END
                 RETURNING id, risk",
            )?;
            // A finding's risk is the highest any of its sightings gave since a rescan started
            // counting them again (hits 0): a sighting rated higher raises it, and a rescan
            // rates it afresh, so a rule that rated something too high, then was fixed, lowers
            // it. Not simply the latest rating: one key can be rated differently at once (a
            // library file served old and new under two query strings), and the high one must
            // not hide behind the low. Read first so a change goes on the timeline. A person's
            // rating (`findings rate`) stays the finding's risk; the scanner's own goes on beside
            // it in scanner_risk, for when the rating is cleared.
            let mut risk_before = tx.prepare_cached("SELECT risk FROM findings WHERE dedupe = ?1")?;
            // A finding marked fixed that is seen again is open again, when what saw it was
            // recorded after it was marked: a rescan of older traffic doesn't reopen it. The
            // scanner made that change, not whoever started the process (an agent that started
            // the proxy, say), so it is recorded as the scanner's.
            let mut reopen = tx.prepare_cached(
                "UPDATE findings SET state = 'open', state_origin = ?2,
                    state_changed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE id = ?1 AND state = 'fixed'
                    AND (state_changed_at IS NULL OR (SELECT time FROM history WHERE id = ?3) >= state_changed_at)",
            )?;
            for ((f, dedupe), url) in findings.iter().zip(&keys).zip(urls) {
                let d = f.def;
                // A finding raised from a script's answer is filed under its rule's id all the same.
                let of = d.alert_ref.strip_prefix(crate::scan::passive::SCRIPT_ANSWER_PREFIX).unwrap_or(d.alert_ref);
                let rule_id: u32 = of.split('-').next().and_then(|s| s.parse().ok()).unwrap_or(0);
                types.execute(params![
                    d.alert_ref,
                    rule_id,
                    d.name,
                    d.description,
                    d.solution,
                    serde_json::to_string(d.references).unwrap_or_default(),
                    serde_json::to_string(d.tags).unwrap_or_default(),
                ])?;
                let risk = risks.get(dedupe.as_str()).copied().unwrap_or(f.risk);
                let old_risk: Option<String> = risk_before.query_row([dedupe], |r| r.get(0)).optional()?;
                let (id, now_risk): (i64, String) = insert.query_row(
                    params![
                        source,
                        rule_id,
                        d.alert_ref,
                        d.name,
                        risk.as_str(),
                        risk.level(),
                        f.confidence.as_str(),
                        d.cwe,
                        d.wasc,
                        msg.host,
                        msg.method,
                        url,
                        f.param,
                        truncate(&f.evidence, 2000),
                        truncate(&f.other_info, 4000),
                        msg.history_id,
                        dedupe,
                        truncate(&f.attack, 2000),
                        crate::provenance::origin(),
                        base,
                    ],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if id > before && created.insert(id) {
                    new += 1;
                    crate::scan::issues::found(&tx, id, d.alert_ref, &msg.host, Some(msg.history_id))?;
                    continue;
                }
                if let Some(old) = old_risk.as_deref().filter(|old| *old != now_risk) {
                    crate::scan::issues::record(
                        &tx,
                        &crate::scan::issues::Event {
                            finding: Some(id),
                            kind: "risk",
                            old: Some(old),
                            new: Some(&now_risk),
                            history_id: Some(msg.history_id),
                            ..Default::default()
                        },
                    )?;
                }
                if reopen.execute(params![id, crate::provenance::SCANNER, msg.history_id])? > 0 {
                    crate::scan::issues::record(
                        &tx,
                        &crate::scan::issues::Event {
                            finding: Some(id),
                            origin: Some(crate::provenance::SCANNER),
                            kind: "regressed",
                            old: Some("fixed"),
                            new: Some("open"),
                            history_id: Some(msg.history_id),
                            ..Default::default()
                        },
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(new)
    }

    /// Findings grouped by alert type: one row per alert with instance counts and examples.
    pub fn findings_grouped(&self, filter: &FindingFilter) -> Result<Vec<Value>> {
        let (where_sql, args) = filter.sql();
        let sql = format!(
            "SELECT alert_ref, name, max(risk_level) AS risk_level, count(*) AS instances, sum(hits) AS hits,
                count(DISTINCT host) AS hosts, min(id) AS first_id,
                json_group_array(json_object('id', id, 'url', url, 'param', param, 'evidence', substr(evidence, 1, 200)))
                    AS examples,
                group_concat(DISTINCT source) AS sources
             FROM findings WHERE {where_sql} GROUP BY alert_ref ORDER BY risk_level DESC, instances DESC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            let examples: String = r.get(7)?;
            let mut ex: Vec<Value> = serde_json::from_str(&examples).unwrap_or_default();
            let total = ex.len();
            ex.truncate(filter.examples);
            Ok(json!({
                "alert_ref": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                // From the highest level: a bare `risk` column would be the first finding's.
                "risk": crate::scan::issues::risk_name(r.get(2)?),
                // One source, or several joined by commas when scanners share an alert type.
                "source": r.get::<_, String>(8)?,
                "instances": r.get::<_, i64>(3)?,
                "hits": r.get::<_, i64>(4)?,
                "hosts": r.get::<_, i64>(5)?,
                "examples": ex,
                "more_examples": total.saturating_sub(filter.examples),
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Individual findings (one row per instance).
    pub fn findings_list(&self, filter: &FindingFilter, limit: usize) -> Result<Vec<Value>> {
        self.findings_page(filter, limit, 0)
    }

    /// How many findings match `filter`.
    pub fn findings_count(&self, filter: &FindingFilter) -> Result<usize> {
        let (where_sql, args) = filter.sql();
        let n: i64 = self.conn.query_row(
            &format!("SELECT count(*) FROM findings WHERE {where_sql}"),
            rusqlite::params_from_iter(args.iter()),
            |r| r.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// [`Store::findings_list`] from the `offset`th match on, in the same order.
    pub fn findings_page(&self, filter: &FindingFilter, limit: usize, offset: usize) -> Result<Vec<Value>> {
        let (where_sql, args) = filter.sql();
        // SQLite's LIMIT is a signed 64-bit integer: a larger one would be read as negative
        // (no limit), which is what it means anyway, but say so rather than wrap.
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT id, alert_ref, name, risk, confidence, host, method, url, param, substr(evidence, 1, 300),
                hits, history_id, state, origin, state_origin, state_changed_at, note_origin, note_changed_at, source,
                issue_id, suppressed_by, rated_reason, rated_origin, rated_at, scanner_risk, scanner_confidence, rated_by
             FROM findings WHERE {where_sql} ORDER BY risk_level DESC, id LIMIT {limit} OFFSET {offset}"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "alert_ref": r.get::<_, String>(1)?,
                "name": r.get::<_, String>(2)?,
                "risk": r.get::<_, String>(3)?,
                "confidence": r.get::<_, String>(4)?,
                "host": r.get::<_, String>(5)?,
                "method": r.get::<_, String>(6)?,
                "url": r.get::<_, String>(7)?,
                "param": r.get::<_, String>(8)?,
                "evidence": r.get::<_, String>(9)?,
                "hits": r.get::<_, i64>(10)?,
                "history_id": r.get::<_, Option<i64>>(11)?,
                "state": r.get::<_, String>(12)?,
                "origin": r.get::<_, Option<String>>(13)?,
                "state_origin": r.get::<_, Option<String>>(14)?,
                "state_changed_at": r.get::<_, Option<String>>(15)?,
                "note_origin": r.get::<_, Option<String>>(16)?,
                "note_changed_at": r.get::<_, Option<String>>(17)?,
                "source": r.get::<_, String>(18)?,
                "issue_id": r.get::<_, Option<i64>>(19)?,
                "suppressed_by": r.get::<_, Option<i64>>(20)?,
                // A person's rating in place of the scanner's (`findings rate`); null when none.
                "rated": rated_json(r.get(21)?, r.get(22)?, r.get(23)?, r.get(24)?, r.get(25)?, r.get(26)?),
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// One finding with its alert type's description, solution, and references.
    pub fn finding_get(&self, id: i64) -> Result<Value> {
        // Read in one transaction, so what it shows and its revision are of the same moment: a
        // revision of an edit made between two reads would let an edit from what was shown
        // overwrite that change unseen. It only reads, so it is rolled back.
        let snapshot = if self.conn.is_autocommit() { Some(self.conn.unchecked_transaction()?) } else { None };
        let found = self.finding_read(id);
        drop(snapshot);
        found
    }

    fn finding_read(&self, id: i64) -> Result<Value> {
        let r = self.query(
            "SELECT f.*, t.description, t.solution, json(t.refs) AS refs, json(t.tags) AS tags, t.description_origin,
                t.solution_origin
             FROM findings f LEFT JOIN finding_types t ON t.alert_ref = f.alert_ref WHERE f.id = ?1",
            &[id.to_string()],
            1,
            100_000,
        )?;
        let row = r.rows.into_iter().next().ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
        let mut obj: serde_json::Map<String, Value> = r.columns.into_iter().zip(row).collect();
        obj.remove("dedupe");
        let origin = obj.get("origin").and_then(Value::as_str).map(str::to_string);
        obj.insert("origin_text".into(), json!(format!("added {}", crate::provenance::describe(origin.as_deref()))));
        for k in ["refs", "tags"] {
            if let Some(Value::String(s)) = obj.get(k) {
                let v = serde_json::from_str(s).unwrap_or(Value::Null);
                obj.insert(k.into(), v);
            }
        }
        if obj.get("source").and_then(Value::as_str) == Some(MANUAL_SOURCE) {
            obj.insert("history_ids".into(), json!(self.finding_history_ids(id)?));
            // What `findings edit --if-revision` checks.
            obj.insert("revision".into(), json!(manual_revision(&self.conn, id)?));
            let stored = |key: String| -> Result<Option<Value>> {
                Ok(self.meta_get(&key)?.and_then(|v| serde_json::from_str(&v).ok()))
            };
            if let Some(removed) = stored(removed_key(id))? {
                obj.insert("removed".into(), removed);
            }
            let alert_ref = obj.get("alert_ref").and_then(Value::as_str).unwrap_or_default().to_string();
            if let Some(earlier) = stored(replaced_texts_key(&alert_ref))? {
                obj.insert("replaced_texts".into(), earlier);
            }
        }
        Ok(Value::Object(obj))
    }

    /// Sets a finding's triage state and/or note. Each change records who made it and when,
    /// so a finding hidden as a false positive, or a note replaced, says by whom. A removed
    /// finding stays as it was removed.
    pub fn finding_mark(&self, id: i64, state: Option<&str>, note: Option<&str>) -> Result<()> {
        mark_one(&self.conn, id, state, note)
    }

    /// Triages several findings at once: all of them change, or none does (an unknown or
    /// removed one fails the whole call).
    ///
    /// With `if_state`, each finding must still be in that state (compare and swap): a finding
    /// someone else triaged since it was read fails the call, rather than being overwritten.
    pub fn findings_mark(
        &mut self,
        ids: &[i64],
        state: Option<&str>,
        note: Option<&str>,
        if_state: Option<&str>,
    ) -> Result<()> {
        let tx = self.write_tx()?;
        for &id in ids {
            if let Some(want) = if_state {
                let now = current_state(&tx, id)?;
                if now != want {
                    return Err(Error::Conflict(format!(
                        "finding {id} is {now}, not {want} (--if-state): it was changed since it was read; read it \
                         again, then decide"
                    )));
                }
            }
            mark_one(&tx, id, state, note)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Adds a suppression rule and applies it to the findings it matches that are open and
    /// nobody triaged (a person's decision stays theirs). A person adds rules: under an MCP
    /// tool call it is refused. Returns the rule's id and how many findings it marked.
    pub fn suppression_add(&mut self, s: &Suppression) -> Result<(i64, usize)> {
        if crate::provenance::origin() == "mcp" {
            return Err(Error::InvalidInput(
                "a suppression rule is a person's decision about findings not yet seen; suggest marking the \
                 findings instead (`findings mark ID --suggest --state false_positive --note ...`)"
                    .into(),
            ));
        }
        let alert = s.alert.trim();
        let (host, port) = suppression_host(&s.host)?;
        let reason = s.reason.trim();
        let prefix = s.path_prefix.trim();
        if alert.is_empty() {
            return Err(Error::InvalidInput("give the alert ref or rule id it suppresses (--alert)".into()));
        }
        if reason.is_empty() {
            return Err(Error::InvalidInput("give the reason (--reason): it is the note of each finding".into()));
        }
        if !prefix.is_empty() && !prefix.starts_with('/') {
            return Err(Error::InvalidInput(format!("--path-prefix {prefix:?}: a path starts with /")));
        }
        let tx = self.write_tx()?;
        tx.execute(
            "INSERT INTO suppressions (alert_ref, host, path_prefix, param, reason, origin, port)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![alert, host, prefix, s.param, reason, crate::provenance::origin(), port],
        )?;
        let id = tx.last_insert_rowid();
        let rule = Rule {
            id,
            port,
            path_prefix: prefix.to_string(),
            param: s.param.clone(),
            url_regex: None,
            param_regex: None,
            risk: None,
            confidence: None,
            reason: reason.to_string(),
            origin: Some(crate::provenance::origin().to_string()),
        };
        let found: Vec<(i64, String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, url, param FROM findings WHERE (alert_ref = ?1 OR CAST(rule_id AS TEXT) = ?1)
                    AND host = ?2 AND state = 'open' ORDER BY id",
            )?;
            let rows = stmt.query_map(params![alert, host], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut marked = 0;
        for (finding, url, param) in found {
            if rule.matches(&url, &param) && suppress_by(&tx, finding, &rule, None)? {
                marked += 1;
            }
        }
        tx.commit()?;
        Ok((id, marked))
    }

    /// The suppression rules, oldest first, with how many findings each marked that are still
    /// false positives by it.
    pub fn suppressions_list(&self) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.time, s.alert_ref, s.host, s.path_prefix, s.param, s.reason, s.origin,
                (SELECT count(*) FROM findings f WHERE f.suppressed_by = s.id AND f.state = 'false_positive'), s.port
             FROM suppressions s WHERE s.action = 'suppress' ORDER BY s.id",
        )?;
        let rows = stmt.query_map([], |r| {
            let origin: Option<String> = r.get(7)?;
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "time": r.get::<_, String>(1)?,
                "alert_ref": r.get::<_, String>(2)?,
                "host": r.get::<_, String>(3)?,
                "path_prefix": r.get::<_, String>(4)?,
                "param": r.get::<_, Option<String>>(5)?,
                "reason": r.get::<_, String>(6)?,
                "by": crate::provenance::describe(origin.as_deref()),
                "origin": origin,
                "findings": r.get::<_, i64>(8)?,
                "port": r.get::<_, Option<u16>>(9)?,
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Removes a suppression rule: findings found later are no longer marked by it. With
    /// `reopen`, the findings it marked that are still false positives by it are open again;
    /// otherwise they keep the state. Refused under an MCP tool call, like adding one. Returns
    /// how many findings were opened again.
    pub fn suppression_remove(&mut self, id: i64, reopen: bool) -> Result<usize> {
        if crate::provenance::origin() == "mcp" {
            return Err(Error::InvalidInput(
                "a suppression rule is a person's decision; an agent can't remove it (suggest reopening its \
                 findings with `findings mark ID --suggest --state open`)"
                    .into(),
            ));
        }
        let tx = self.write_tx()?;
        if tx.execute("DELETE FROM suppressions WHERE id = ?1 AND action = ?2", params![id, SUPPRESS])? == 0 {
            return Err(Error::NotFound(format!("suppression rule {id}")));
        }
        let mut reopened = 0;
        if reopen {
            let ids: Vec<i64> = {
                let mut stmt = tx.prepare(
                    "SELECT id FROM findings WHERE suppressed_by = ?1 AND state = 'false_positive' ORDER BY id",
                )?;
                let rows = stmt.query_map([id], |r| r.get(0))?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            let cause = format!("suppression rule {id} removed");
            for f in ids {
                mark_with(&tx, f, Some("open"), None, Some((&cause, None)))?;
                reopened += 1;
            }
        }
        tx.commit()?;
        Ok(reopened)
    }

    /// Adds an alert filter and applies it to the open scanner findings it matches that nobody
    /// rated (a person's rating, or an issue's, stays theirs). A person adds filters: under an
    /// MCP tool call it is refused. Returns the filter's id and how many findings it rated.
    pub fn filter_add(&mut self, f: &AlertFilter) -> Result<(i64, usize)> {
        if crate::provenance::origin() == "mcp" {
            return Err(Error::InvalidInput(
                "an alert filter is a person's rating of findings not yet seen; suggest a rating on the findings \
                 instead (`findings mark ID --suggest --note ...`)"
                    .into(),
            ));
        }
        let alert = f.alert.trim();
        let reason = f.reason.trim();
        let prefix = f.path_prefix.trim();
        if alert.is_empty() {
            return Err(Error::InvalidInput("give the alert ref or rule id it re-rates (--alert)".into()));
        }
        if reason.is_empty() {
            return Err(Error::InvalidInput(
                "give the reason (--reason): it is the rating reason of each finding".into(),
            ));
        }
        let risk = f.risk.as_deref().map(str::trim);
        let confidence = f.confidence.as_deref().map(str::trim);
        if risk.is_none() && confidence.is_none() {
            return Err(Error::InvalidInput("give --risk and/or --confidence".into()));
        }
        if let Some(r) = risk {
            if matches!(r, "false_positive" | "false-positive") {
                return Err(Error::InvalidInput(
                    "--risk false_positive: a filter re-rates; to mark findings false positives use findings \
                     suppress"
                        .into(),
                ));
            }
            Risk::parse(r).ok_or_else(|| Error::InvalidInput(format!("unknown risk {r:?}")))?;
        }
        if let Some(c) = confidence {
            Confidence::parse(c).ok_or_else(|| Error::InvalidInput(format!("unknown confidence {c:?}")))?;
        }
        if !prefix.is_empty() && !prefix.starts_with('/') {
            return Err(Error::InvalidInput(format!("--path-prefix {prefix:?}: a path starts with /")));
        }
        let (host, port) = match f.host.as_deref() {
            Some(h) => suppression_host(h)?,
            None => (String::new(), None),
        };
        let url_regex = f.url_regex.as_deref().map(|r| filter_regex("--url-regex", r)).transpose()?;
        let param_regex = f.param_regex.as_deref().map(|r| filter_regex("--param-regex", r)).transpose()?;
        let origin = crate::provenance::origin();
        let tx = self.write_tx()?;
        tx.execute(
            "INSERT INTO suppressions (action, alert_ref, host, path_prefix, param, reason, origin, port, url_regex,
                param_regex, risk, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                RATE,
                alert,
                host,
                prefix,
                f.param,
                reason,
                origin,
                port,
                f.url_regex,
                f.param_regex,
                risk,
                confidence
            ],
        )?;
        let id = tx.last_insert_rowid();
        let rule = Rule {
            id,
            port,
            path_prefix: prefix.to_string(),
            param: f.param.clone(),
            url_regex,
            param_regex,
            risk: risk.map(str::to_string),
            confidence: confidence.map(str::to_string),
            reason: reason.to_string(),
            origin: Some(origin.to_string()),
        };
        let found: Vec<(i64, String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, url, param FROM findings WHERE (alert_ref = ?1 OR CAST(rule_id AS TEXT) = ?1)
                    AND (host = ?2 OR ?2 = '') AND state = 'open' AND source != ?3 AND rated_origin IS NULL
                 ORDER BY id",
            )?;
            let rows =
                stmt.query_map(params![alert, host, MANUAL_SOURCE], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut rated = 0;
        for (finding, url, param) in found {
            if rule.matches(&url, &param) && rate_by(&tx, finding, &rule, None)? {
                rated += 1;
            }
        }
        tx.commit()?;
        Ok((id, rated))
    }

    /// The alert filters, oldest first, with how many findings still have each one's rating
    /// (`holds`).
    pub fn filters_list(&self) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.time, s.alert_ref, s.host, s.port, s.path_prefix, s.url_regex, s.param, s.param_regex,
                s.risk, s.confidence, s.reason, s.origin,
                (SELECT count(*) FROM findings f WHERE f.rated_by = s.id AND f.rated_origin IS NOT NULL)
             FROM suppressions s WHERE s.action = 'rate' ORDER BY s.id",
        )?;
        let rows = stmt.query_map([], |r| {
            let host: String = r.get(3)?;
            let origin: Option<String> = r.get(12)?;
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "time": r.get::<_, String>(1)?,
                "alert_ref": r.get::<_, String>(2)?,
                // null: any host.
                "host": Some(host).filter(|h| !h.is_empty()),
                "port": r.get::<_, Option<u16>>(4)?,
                "path_prefix": r.get::<_, String>(5)?,
                "url_regex": r.get::<_, Option<String>>(6)?,
                "param": r.get::<_, Option<String>>(7)?,
                "param_regex": r.get::<_, Option<String>>(8)?,
                "risk": r.get::<_, Option<String>>(9)?,
                "confidence": r.get::<_, Option<String>>(10)?,
                "reason": r.get::<_, String>(11)?,
                "by": crate::provenance::describe(origin.as_deref()),
                "origin": origin,
                "holds": r.get::<_, i64>(13)?,
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Removes an alert filter: findings found later are no longer rated by it. With `unrate`,
    /// the findings that still have its rating get the scanner's back; otherwise they keep it
    /// (`rated_by` still names the filter). Refused under an MCP tool call, like adding one.
    /// Returns how many findings got the scanner's rating back.
    pub fn filter_remove(&mut self, id: i64, unrate: bool) -> Result<usize> {
        if crate::provenance::origin() == "mcp" {
            return Err(Error::InvalidInput(
                "an alert filter is a person's decision; an agent can't remove it (suggest a rating on its \
                 findings with `findings mark ID --suggest --note ...`)"
                    .into(),
            ));
        }
        let tx = self.write_tx()?;
        if tx.execute("DELETE FROM suppressions WHERE id = ?1 AND action = ?2", params![id, RATE])? == 0 {
            return Err(Error::NotFound(format!("alert filter {id}")));
        }
        let mut unrated = 0;
        if unrate {
            let ids: Vec<i64> = {
                let mut stmt =
                    tx.prepare("SELECT id FROM findings WHERE rated_by = ?1 AND rated_origin IS NOT NULL ORDER BY id")?;
                let rows = stmt.query_map([id], |r| r.get(0))?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            for f in ids {
                if unrate_one(&tx, f)? {
                    unrated += 1;
                }
            }
        }
        tx.commit()?;
        Ok(unrated)
    }

    /// Rates findings as a person sees them (`rating`), or with `None` gives them the scanner's
    /// rating back: `ids` and the scanner findings of each of `issues`, all or none. An issue
    /// rated as a whole keeps the rating for the findings it gets later. A person does this:
    /// under an MCP tool call it is refused. Returns the findings changed.
    pub fn findings_rate(&mut self, ids: &[i64], issues: &[i64], rating: Option<&Rating<'_>>) -> Result<Vec<i64>> {
        if crate::provenance::origin() == "mcp" {
            return Err(Error::InvalidInput(
                "rating a finding is a person's call; suggest one on the finding instead (`findings mark ID \
                 --suggest --note ...`)"
                    .into(),
            ));
        }
        if let Some(r) = rating {
            if r.risk.is_none() && r.confidence.is_none() {
                return Err(Error::InvalidInput("give --risk and/or --confidence (or --clear)".into()));
            }
            if r.reason.trim().is_empty() {
                return Err(Error::InvalidInput("give the reason for the rating (--reason)".into()));
            }
        }
        let tx = self.write_tx()?;
        let mut all: Vec<i64> = ids.to_vec();
        for &issue in issues {
            let ids = issue_ids(&tx, issue)?;
            let mut stmt = tx.prepare_cached("SELECT source FROM findings WHERE id = ?1")?;
            for id in ids {
                // A finding added by hand to the issue keeps the risk it was given.
                if stmt.query_row([id], |r| r.get::<_, String>(0))? != MANUAL_SOURCE {
                    all.push(id);
                }
            }
        }
        all.sort_unstable();
        all.dedup();
        let origin = crate::provenance::origin();
        let mut changed = Vec::new();
        for &id in &all {
            let done = match rating {
                Some(r) => rate_one(&tx, id, &Rating { reason: r.reason.trim(), ..*r }, origin, None, None)?,
                None => {
                    current_state(&tx, id)?;
                    unrate_one(&tx, id)?
                }
            };
            if done {
                changed.push(id);
            }
        }
        for &issue in issues {
            crate::scan::issues::set_rating(&tx, issue, rating)?;
        }
        tx.commit()?;
        Ok(changed)
    }

    /// [`Store::findings_mark`] for `ids` and every finding of `issues`, as one change. Each
    /// issue marked as a whole takes the state as its decision when it is false positive or
    /// accepted risk, so the instances it gets later arrive in that state too; another state
    /// ends its decision. Findings marked by id leave their issue's decision as it is: that is
    /// a decision about those instances only.
    pub fn findings_mark_issues(
        &mut self,
        ids: &[i64],
        issues: &[i64],
        state: Option<&str>,
        note: Option<&str>,
        if_state: Option<&str>,
    ) -> Result<Vec<i64>> {
        let tx = self.write_tx()?;
        let mut all: Vec<i64> = ids.to_vec();
        for &issue in issues {
            all.extend(issue_ids(&tx, issue)?);
        }
        all.sort_unstable();
        all.dedup();
        for &id in &all {
            if let Some(want) = if_state {
                let now = current_state(&tx, id)?;
                if now != want {
                    return Err(Error::Conflict(format!(
                        "finding {id} is {now}, not {want} (--if-state): it was changed since it was read; read it \
                         again, then decide"
                    )));
                }
            }
            mark_one(&tx, id, state, note)?;
        }
        for &issue in issues {
            crate::scan::issues::decide(&tx, issue, state, note)?;
        }
        tx.commit()?;
        Ok(all)
    }

    /// Puts a suggested state and/or note on each finding's timeline (an event of kind
    /// `suggested`: old is its state then, new the state suggested, text the note) and changes
    /// nothing else: how an agent proposes a change to a finding a person triaged, which it
    /// may not change itself. Anyone may suggest. All of them, or none.
    pub fn findings_suggest(&mut self, ids: &[i64], state: Option<&str>, note: Option<&str>) -> Result<()> {
        if let Some(s) = state.filter(|s| !STATES.contains(s)) {
            return Err(Error::InvalidInput(format!("unknown state {s:?}: one of {}", STATES.join(", "))));
        }
        let note = note.map(str::trim).filter(|n| !n.is_empty());
        if state.is_none() && note.is_none() {
            return Err(Error::InvalidInput("a suggestion needs --state and/or a --note".into()));
        }
        let tx = self.write_tx()?;
        for &id in ids {
            let now = current_state(&tx, id)?;
            if now == REMOVED {
                return Err(Error::Conflict(format!("finding {id} was removed")));
            }
            crate::scan::issues::record(
                &tx,
                &crate::scan::issues::Event {
                    finding: Some(id),
                    kind: "suggested",
                    old: Some(&now),
                    new: state,
                    text: note,
                    ..Default::default()
                },
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Dismisses the suggestion `event` (a `suggested` event on finding `id`): a `dismissed` event
    /// whose `old` is the suggestion's event id, so it no longer waits for a person. False, with
    /// nothing recorded, when it was dismissed already.
    pub fn finding_dismiss(&mut self, id: i64, event: i64) -> Result<bool> {
        let tx = self.write_tx()?;
        current_state(&tx, id)?;
        let kind: Option<String> = tx
            .query_row("SELECT kind FROM finding_events WHERE id = ?1 AND finding_id = ?2", params![event, id], |r| {
                r.get(0)
            })
            .optional()?;
        match kind.as_deref() {
            None => return Err(Error::NotFound(format!("event {event} on finding {id}"))),
            Some("suggested") => {}
            Some(k) => return Err(Error::InvalidInput(format!("event {event} is a {k} event, not a suggestion"))),
        }
        let old = event.to_string();
        let done: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM finding_events WHERE finding_id = ?1 AND kind = 'dismissed' AND old = ?2)",
            params![id, old],
            |r| r.get(0),
        )?;
        if done {
            return Ok(false);
        }
        crate::scan::issues::record(
            &tx,
            &crate::scan::issues::Event { finding: Some(id), kind: "dismissed", old: Some(&old), ..Default::default() },
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Starts a full rescan of `source` findings: their hit counts go to 0, to be counted again,
    /// and nothing else changes, so a finding found again keeps its id, state, note and who
    /// set them. Returns the highest finding id, to tell new findings from the ones found again.
    ///
    /// Findings whose alert ref starts with one of `keep` are left as they are: what found them
    /// (a script check whose file changed, say) won't run, so the rescan can't count them again.
    pub(crate) fn findings_rescan_start(&mut self, source: &str, keep: &[String]) -> Result<i64> {
        let tx = self.write_tx()?;
        let (kept, args) = not_kept(source, keep);
        tx.execute(
            &format!("UPDATE findings SET hits = 0 WHERE source = ?1{kept}"),
            rusqlite::params_from_iter(&args),
        )?;
        let max: i64 = tx.query_row("SELECT coalesce(max(id), 0) FROM findings", [], |r| r.get(0))?;
        tx.commit()?;
        Ok(max)
    }

    /// Ends a rescan: a finding it didn't find again goes, unless someone triaged it (changed
    /// its state, or wrote or cleared a note). That one stays with 0 hits, so a person's decision isn't lost
    /// to a rescan an agent ran. Returns (removed, kept).
    ///
    /// Findings whose alert ref starts with one of `keep` stay whatever the rescan found (see
    /// [`Store::findings_rescan_start`]): what would have found them again failed or didn't run.
    pub(crate) fn findings_rescan_finish(&mut self, source: &str, keep: &[String]) -> Result<(usize, usize)> {
        let tx = self.write_tx()?;
        let (kept_clause, args) = not_kept(source, keep);
        // Clearing a note is a decision too: note_origin says someone touched it.
        // So is anything else on its timeline (a retest, a move to another issue, a ticket) or
        // on its issue's (a title, a rating, a write-up): a record someone made stays. A risk
        // change is the scanner's own record, not someone's.
        let triaged = "(state != 'open' OR note IS NOT NULL OR state_origin IS NOT NULL OR note_origin IS NOT NULL
            OR EXISTS (SELECT 1 FROM finding_events e WHERE e.finding_id = findings.id
                AND e.kind NOT IN ('created', 'risk'))
            OR EXISTS (SELECT 1 FROM finding_events e WHERE e.finding_id IS NULL AND e.issue_id = findings.issue_id))";
        // A finding that goes takes its timeline and scan observations with it.
        let gone = format!("SELECT id FROM findings WHERE source = ?1 AND hits = 0 AND NOT {triaged}{kept_clause}");
        let args = || rusqlite::params_from_iter(&args);
        tx.execute(&format!("DELETE FROM finding_events WHERE finding_id IN ({gone})"), args())?;
        tx.execute(&format!("DELETE FROM scan_observations WHERE finding_id IN ({gone})"), args())?;
        let removed = tx.execute(
            &format!("DELETE FROM findings WHERE source = ?1 AND hits = 0 AND NOT {triaged}{kept_clause}"),
            args(),
        )?;
        let kept: i64 = tx.query_row(
            &format!("SELECT count(*) FROM findings WHERE source = ?1 AND hits = 0 AND {triaged}"),
            [source],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok((removed, kept as usize))
    }

    /// Findings of `source` added after finding `after`.
    pub(crate) fn findings_count_after(&self, source: &str, after: i64) -> Result<usize> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM findings WHERE source = ?1 AND id > ?2",
            params![source, after],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Records a finding a person found by hand; returns its id. Nothing is sent. Findings with
    /// the same title share an alert type (`manual:<title>`), which holds the description and
    /// solution: one left out keeps the type's, and one that differs from it is refused unless
    /// `replace_text`, when the type's earlier text is kept in meta (`findings show` lists it).
    pub fn finding_add(&mut self, f: &ManualFinding) -> Result<i64> {
        let title = f.title.trim();
        if title.is_empty() || title.len() > MANUAL_TITLE_MAX {
            return Err(Error::InvalidInput(format!("the title must be 1 to {MANUAL_TITLE_MAX} bytes")));
        }
        let alert_ref = manual_alert_ref(title)?;
        check_sizes(&[
            ("evidence", &f.evidence, MANUAL_EVIDENCE_MAX),
            ("parameter", &f.param, MANUAL_EVIDENCE_MAX),
            ("description", &f.description, MANUAL_TEXT_MAX),
            ("solution", &f.solution, MANUAL_TEXT_MAX),
        ])?;
        let tx = self.write_tx()?;
        // The linked entries must exist; the first gives the URL and method when none are given.
        let (history, first) = linked_entries(&tx, &f.history)?;
        let url = match (&f.url, &first) {
            (Some(u), _) => u.trim().to_string(),
            (None, Some((_, u))) => u.clone(),
            (None, None) => return Err(Error::InvalidInput("give --url or --history-id".into())),
        };
        let (parsed, url) = manual_url(&url)?;
        let method = match (&f.method, &first) {
            (Some(m), _) => manual_method(m)?,
            (None, Some((m, _))) => m.clone(),
            (None, None) => "GET".to_string(),
        };
        let host = url_host(&parsed);
        let dedupe = dedupe_key(&alert_ref, &method, &url, &f.param);
        if let Some(id) =
            tx.query_row("SELECT id FROM findings WHERE dedupe = ?1", [&dedupe], |r| r.get::<_, i64>(0)).optional()?
        {
            return Err(Error::Conflict(format!(
                "finding {id} is already this issue (same title, method, URL without its query or path parameters, \
                 and parameter)"
            )));
        }
        let replaced = texts_replaced(&tx, &alert_ref, f)?;
        if !replaced.is_empty() {
            if !f.replace_text {
                return Err(Error::Conflict(format!(
                    "the {} differs from the one every finding titled {title:?} shares; leave it out to keep \
                     that one, or give --replace-text to replace it",
                    replaced.join(" and ")
                )));
            }
            keep_replaced_texts(&tx, &alert_ref)?;
        }
        // Each text says who wrote it: whoever gave it first, filled it in when it was blank, or
        // replaced it. Giving the same text again changes neither.
        tx.execute(
            "INSERT INTO finding_types (alert_ref, rule_id, name, description, solution, refs, tags,
                description_origin, solution_origin)
             VALUES (?1, 0, ?2, ?3, ?4, '[]', '[\"manual\"]',
                CASE WHEN ?3 != '' THEN ?5 END, CASE WHEN ?4 != '' THEN ?5 END)
             ON CONFLICT(alert_ref) DO UPDATE SET
                description = CASE WHEN excluded.description != '' THEN excluded.description ELSE description END,
                solution = CASE WHEN excluded.solution != '' THEN excluded.solution ELSE solution END,
                description_origin = CASE WHEN excluded.description NOT IN ('', description)
                    THEN excluded.description_origin ELSE description_origin END,
                solution_origin = CASE WHEN excluded.solution NOT IN ('', solution)
                    THEN excluded.solution_origin ELSE solution_origin END",
            params![alert_ref, title, f.description.trim(), f.solution.trim(), crate::provenance::origin()],
        )?;
        tx.execute(
            "INSERT INTO findings (source, rule_id, alert_ref, name, risk, risk_level, confidence, cwe, host,
                method, url, param, evidence, history_id, last_history_id, dedupe, origin)
             VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                MANUAL_SOURCE,
                alert_ref,
                title,
                f.risk.as_str(),
                f.risk.level(),
                f.confidence.as_str(),
                f.cwe.filter(|&c| c > 0),
                host,
                method,
                url,
                f.param,
                f.evidence,
                history.first(),
                history.last(),
                dedupe,
                crate::provenance::origin(),
            ],
        )?;
        let id = tx.last_insert_rowid();
        crate::scan::issues::created(&tx, id, &alert_ref, &host, history.first().copied())?;
        // The table holds a first and a last entry; the whole list goes in meta.
        if history.len() > 2 {
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                params![history_key(id), serde_json::to_string(&history).unwrap_or_default()],
            )?;
        }
        tx.commit()?;
        Ok(id)
    }

    /// Changes a finding added by hand in place: only what `e` gives changes, and its id, state,
    /// note, origin and timeline stay. Returns what changed. An edit that changes something
    /// records an `edited` event (by this process's origin) whose `text` names the fields and
    /// whose `old` and `new` hold their values (the description's and solution's are in
    /// `replaced_texts` when replaced). A new title or host moves it to the issue of its new alert
    /// type and host, with a `moved` event.
    ///
    /// The description and solution belong to the alert type that every finding of a title
    /// shares, as for [`Store::finding_add`]: a given one fills a blank one, and one that differs
    /// from a text the type has (an empty one too) is refused unless `replace_text`. A new title
    /// takes the texts of the type it joins, or this finding's when that one has none.
    pub fn finding_edit(&mut self, id: i64, e: &FindingEdit) -> Result<FindingEdited> {
        let title = match &e.title {
            Some(t) => {
                let t = t.trim();
                if t.is_empty() || t.len() > MANUAL_TITLE_MAX {
                    return Err(Error::InvalidInput(format!("the title must be 1 to {MANUAL_TITLE_MAX} bytes")));
                }
                Some(t.to_string())
            }
            None => None,
        };
        let none = String::new();
        check_sizes(&[
            ("evidence", e.evidence.as_ref().unwrap_or(&none), MANUAL_EVIDENCE_MAX),
            ("parameter", e.param.as_ref().unwrap_or(&none), MANUAL_EVIDENCE_MAX),
            ("description", e.description.as_ref().unwrap_or(&none), MANUAL_TEXT_MAX),
            ("solution", e.solution.as_ref().unwrap_or(&none), MANUAL_TEXT_MAX),
        ])?;
        let tx = self.write_tx()?;
        let old = ManualRow::load(&tx, id)?;
        if old.source != MANUAL_SOURCE {
            return Err(Error::InvalidInput(format!(
                "finding {id} came from the {} scanner; only findings added by hand can be edited (mark it instead)",
                old.source
            )));
        }
        if old.state == REMOVED {
            return Err(Error::Conflict(format!("finding {id} was removed")));
        }
        if e.only_own {
            // A person who triaged it, noted it, edited it, filed it, moved it, or wrote up or
            // reviewed its issue has vouched for it as it is: an agent then marks it, as it
            // would a person's own.
            let person_touched: bool = tx.query_row(
                "SELECT IFNULL(f.state_origin, 'mcp') != 'mcp' OR IFNULL(f.note_origin, 'mcp') != 'mcp'
                    OR EXISTS (SELECT 1 FROM finding_events e WHERE IFNULL(e.origin, '') != 'mcp'
                        AND e.kind NOT IN ('created', 'regressed', 'risk')
                        AND (e.finding_id = f.id OR (e.finding_id IS NULL AND e.issue_id = f.issue_id)))
                 FROM findings f WHERE f.id = ?1",
                [id],
                |r| r.get(0),
            )?;
            if old.origin.as_deref() != Some("mcp") || person_touched {
                let whose = if old.origin.as_deref() != Some("mcp") {
                    format!("it was added {}", crate::provenance::describe(old.origin.as_deref()))
                } else {
                    "a person has changed it since (its state, note, fields, ticket or issue)".to_string()
                };
                return Err(Error::InvalidInput(format!(
                    "finding {id}: through MCP an agent edits only the findings it added that no person has changed \
                     since, and {whose}; mark it with a note instead (findings mark {id} --note ...)"
                )));
            }
        }
        if let Some(want) = e.if_revision.as_deref() {
            let now = old.revision();
            if want != now {
                return Err(Error::Conflict(format!(
                    "finding {id} is at revision {now}, not {want}: it was changed elsewhere meanwhile; show it again"
                )));
            }
        }

        let mut new = old.clone();
        if let Some(t) = &title {
            new.title = t.clone();
            new.alert_ref = manual_alert_ref(t)?;
        }
        if let Some(r) = e.risk {
            new.risk = r.as_str().to_string();
        }
        if let Some(c) = e.confidence {
            new.confidence = c.as_str().to_string();
        }
        if let Some(u) = &e.url {
            let (parsed, url) = manual_url(u.trim())?;
            new.host = url_host(&parsed);
            new.url = url;
        }
        if let Some(m) = &e.method {
            new.method = manual_method(m)?;
        }
        if let Some(p) = &e.param {
            new.param = p.clone();
        }
        if let Some(c) = e.cwe {
            new.cwe = c.filter(|&c| c > 0).map(i64::from);
        }
        if let Some(h) = &e.history {
            new.history = linked_entries(&tx, h)?.0;
        }
        if let Some(ev) = &e.evidence {
            new.evidence = ev.clone();
        }

        let dedupe = dedupe_key(&new.alert_ref, &new.method, &new.url, &new.param);
        if let Some(other) = tx
            .query_row("SELECT id FROM findings WHERE dedupe = ?1 AND id != ?2", params![dedupe, id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
        {
            return Err(Error::Conflict(format!(
                "finding {other} is already this issue (same title, method, URL without its query or path \
                 parameters, and parameter)"
            )));
        }

        // The texts of the alert type it is in after the edit: given ones, else (for a new title)
        // this finding's, where that type has none.
        let carried = (new.alert_ref != old.alert_ref).then_some(&old);
        let (texts, replaced) =
            edit_texts(&tx, &new, e.description.as_deref(), e.solution.as_deref(), carried, e.replace_text)?;
        new.description = texts.0;
        new.solution = texts.1;

        let changed = old.changes(&new);
        if changed.is_empty() {
            tx.commit()?;
            return Ok(FindingEdited { changed, replaced, revision: old.revision() });
        }
        // Looked up before the row changes, which would make it find itself.
        let issue = match old.issue {
            Some(from) if new.alert_ref != old.alert_ref || new.host != old.host => {
                issue_after_edit(&tx, id, from, &old, &new)?
            }
            _ => IssueChange::Keep,
        };
        tx.execute(
            "UPDATE findings SET name = ?2, alert_ref = ?3, risk = ?4, risk_level = ?5, confidence = ?6, cwe = ?7,
                host = ?8, method = ?9, url = ?10, param = ?11, evidence = ?12, history_id = ?13,
                last_history_id = ?14, dedupe = ?15
             WHERE id = ?1",
            params![
                id,
                new.title,
                new.alert_ref,
                new.risk,
                Risk::parse(&new.risk).map_or(0, Risk::level),
                new.confidence,
                new.cwe,
                new.host,
                new.method,
                new.url,
                new.param,
                new.evidence,
                new.history.first(),
                new.history.last(),
                dedupe,
            ],
        )?;
        // The table holds a first and a last entry; a longer list goes in meta.
        let list = (new.history.len() > 2).then(|| serde_json::to_string(&new.history).unwrap_or_default());
        match list {
            Some(l) => tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![history_key(id), l],
            )?,
            None => tx.execute("DELETE FROM meta WHERE key = ?1", [history_key(id)])?,
        };
        let (was, now) = old.values(&new, &changed);
        crate::scan::issues::record(
            &tx,
            &crate::scan::issues::Event {
                finding: Some(id),
                kind: "edited",
                old: was.as_deref(),
                new: now.as_deref(),
                text: Some(&changed.join(", ")),
                ..Default::default()
            },
        )?;
        match issue {
            IssueChange::Keep => {}
            IssueChange::Rekey(i) => {
                tx.execute(
                    "UPDATE issues SET alert_ref = ?2, host = ?3 WHERE id = ?1",
                    params![i, new.alert_ref, new.host],
                )?;
            }
            IssueChange::Move(from, to) => {
                crate::scan::issues::move_findings(&tx, &[id], from, to)?;
            }
        }
        // A comparison with a report from before the edit still knows it by what it was.
        let was = dedupe_key(&old.alert_ref, &old.method, &old.url, &old.param);
        if was != dedupe {
            let key = identities_key(id);
            let stored: Option<String> =
                tx.query_row("SELECT value FROM meta WHERE key = ?1", [&key], |r| r.get(0)).optional()?;
            let mut earlier: Vec<String> = stored.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
            let print = fingerprint(&old.alert_ref, &old.method, &old.url, &old.param);
            if !earlier.contains(&print) {
                earlier.push(print);
                tx.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![key, serde_json::to_string(&earlier).unwrap_or_default()],
                )?;
            }
        }
        let revision = ManualRow::load(&tx, id)?.revision();
        tx.commit()?;
        Ok(FindingEdited { changed, replaced, revision })
    }

    /// Removes findings added by hand; scanner findings are refused (mark them instead), and
    /// nothing is removed unless every id can be. A removed finding stays as a tombstone: state
    /// `removed` (hidden unless `--state all`) with who removed it as its `state_origin`, and in
    /// meta when it was removed, by whom, and the state it had and who set that, so a comparison
    /// can tell it from a fixed one. Its identity is freed, so the same
    /// issue can be added again. Returns how many were removed.
    pub fn findings_remove(&mut self, ids: &[i64]) -> Result<usize> {
        let mut unique: Vec<i64> = Vec::new();
        for &id in ids {
            if !unique.contains(&id) {
                unique.push(id);
            }
        }
        let tx = self.write_tx()?;
        for &id in &unique {
            let row: Option<(String, String)> = tx
                .query_row("SELECT source, state FROM findings WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            match row {
                None => return Err(Error::NotFound(format!("finding {id}"))),
                Some((s, _)) if s != MANUAL_SOURCE => {
                    return Err(Error::InvalidInput(format!(
                        "finding {id} came from the {s} scanner; only findings added by hand can be removed \
                         (mark it false_positive instead)"
                    )))
                }
                Some((_, state)) if state == REMOVED => {
                    return Err(Error::Conflict(format!("finding {id} was already removed")));
                }
                Some(_) => {}
            }
        }
        let origin = crate::provenance::origin();
        let mut removed = 0;
        for &id in &unique {
            tx.execute(
                "INSERT INTO meta (key, value)
                 SELECT ?1, json_object('time', strftime('%Y-%m-%dT%H:%M:%fZ','now'), 'state', state,
                    'state_origin', state_origin, 'state_changed_at', state_changed_at, 'by', ?3)
                 FROM findings WHERE id = ?2
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![removed_key(id), id, origin],
            )?;
            removed += tx.execute(
                "UPDATE findings SET state = ?1, dedupe = ?1 || ':' || id || ':' || dedupe,
                    state_origin = ?3,
                    state_changed_at = (SELECT json_extract(value, '$.time') FROM meta WHERE key = ?4)
                 WHERE id = ?2",
                params![REMOVED, id, origin, removed_key(id)],
            )?;
            crate::scan::issues::record(
                &tx,
                &crate::scan::issues::Event {
                    finding: Some(id),
                    kind: "removed",
                    new: Some(REMOVED),
                    ..Default::default()
                },
            )?;
        }
        tx.commit()?;
        Ok(removed)
    }

    /// Which texts of its alert type adding `f` would replace ("description", "solution"): those
    /// the type already has, shared with every finding of the same title, and `f` changes.
    pub fn manual_texts_replaced(&self, f: &ManualFinding) -> Result<Vec<&'static str>> {
        texts_replaced(&self.conn, &manual_alert_ref(f.title.trim())?, f)
    }

    /// Each history entry a finding added by hand links to, in order: its id, method and URL, and
    /// whether it went to another host or port than the finding's URL (linked by mistake, maybe).
    pub fn finding_links(&self, id: i64) -> Result<Vec<Value>> {
        let url: String = self
            .conn
            .query_row("SELECT url FROM findings WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
        let site = url::Url::parse(&url)
            .ok()
            .map(|u| (bare_host(u.host_str().unwrap_or_default()), u.port_or_known_default()));
        let mut links = Vec::new();
        for h in self.finding_history_ids(id)? {
            let row: Option<(String, String, String, i64)> = self
                .conn
                .query_row("SELECT method, url, host, port FROM history WHERE id = ?1", [h], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })
                .optional()?;
            let Some((method, url, host, port)) = row else { continue };
            let other_site =
                site.as_ref().is_some_and(|(h, p)| *h != bare_host(&host) || p.map(i64::from) != Some(port));
            links.push(json!({"id": h, "method": method, "url": url, "other_site": other_site}));
        }
        Ok(links)
    }

    /// The history entries a finding added by hand links to, in the order given.
    pub fn finding_history_ids(&self, id: i64) -> Result<Vec<i64>> {
        let (first, last): (Option<i64>, Option<i64>) = self
            .conn
            .query_row("SELECT history_id, last_history_id FROM findings WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?
            .unwrap_or_default();
        history_ids(&self.conn, id, first, last)
    }
}

/// `findings.source` of a finding added by hand.
pub const MANUAL_SOURCE: &str = "manual";
/// `findings.state` of a finding added by hand and then removed.
pub const REMOVED: &str = "removed";
const MANUAL_TITLE_MAX: usize = 300;
const MANUAL_EVIDENCE_MAX: usize = 10_000;
const MANUAL_TEXT_MAX: usize = 100_000;
const MANUAL_HISTORY_MAX: usize = 100;

/// A finding a person records by hand (`findings add`).
#[derive(Debug, Clone)]
pub struct ManualFinding {
    pub title: String,
    pub risk: Risk,
    pub confidence: Confidence,
    /// Default: the first history entry's URL.
    pub url: Option<String>,
    /// Default: the first history entry's method, else GET.
    pub method: Option<String>,
    pub param: String,
    pub evidence: String,
    pub description: String,
    pub solution: String,
    pub cwe: Option<u32>,
    /// History entries it was seen in; the first is the report's evidence.
    pub history: Vec<i64>,
    /// Replace the description or solution the type has when this one differs.
    pub replace_text: bool,
}

/// What `findings edit` changes in a finding added by hand: each field given, and nothing else.
#[derive(Debug, Clone, Default)]
pub struct FindingEdit {
    pub title: Option<String>,
    pub risk: Option<Risk>,
    pub confidence: Option<Confidence>,
    pub url: Option<String>,
    pub method: Option<String>,
    pub param: Option<String>,
    /// `Some(None)` clears it.
    pub cwe: Option<Option<u32>>,
    /// The history entries it links to, in place of the ones it has (empty: none).
    pub history: Option<Vec<i64>>,
    pub evidence: Option<String>,
    pub description: Option<String>,
    pub solution: Option<String>,
    /// Replace the description or solution its alert type has when the one given differs.
    pub replace_text: bool,
    /// Only if the finding is still at this revision (see [`crate::store::revision`]).
    pub if_revision: Option<String>,
    /// Only a finding added through MCP that no person has edited since (an agent's edit).
    pub only_own: bool,
}

/// What [`Store::finding_edit`] did.
#[derive(Debug, Clone)]
pub struct FindingEdited {
    /// The fields that changed, in the order `findings edit` lists them; empty when none did.
    pub changed: Vec<&'static str>,
    /// The texts of its alert type that were replaced ("description", "solution").
    pub replaced: Vec<&'static str>,
    /// Its revision after the edit.
    pub revision: String,
}

/// A finding added by hand, as `findings edit` reads and writes it.
#[derive(Debug, Clone)]
struct ManualRow {
    source: String,
    state: String,
    origin: Option<String>,
    issue: Option<i64>,
    title: String,
    alert_ref: String,
    risk: String,
    confidence: String,
    cwe: Option<i64>,
    host: String,
    method: String,
    url: String,
    param: String,
    evidence: String,
    history: Vec<i64>,
    description: String,
    solution: String,
}

impl ManualRow {
    fn load(conn: &rusqlite::Connection, id: i64) -> Result<Self> {
        type Row = (Option<i64>, Option<i64>, ManualRow);
        let (first, last, mut row): Row = conn
            .query_row(
                "SELECT f.history_id, f.last_history_id, f.source, f.state, f.origin, f.issue_id, f.name, f.alert_ref,
                    f.risk, f.confidence, f.cwe, f.host, f.method, f.url, f.param, f.evidence,
                    coalesce(t.description, ''), coalesce(t.solution, '')
                 FROM findings f LEFT JOIN finding_types t ON t.alert_ref = f.alert_ref WHERE f.id = ?1",
                [id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        ManualRow {
                            source: r.get(2)?,
                            state: r.get(3)?,
                            origin: r.get(4)?,
                            issue: r.get(5)?,
                            title: r.get(6)?,
                            alert_ref: r.get(7)?,
                            risk: r.get(8)?,
                            confidence: r.get(9)?,
                            cwe: r.get(10)?,
                            host: r.get(11)?,
                            method: r.get(12)?,
                            url: r.get(13)?,
                            param: r.get(14)?,
                            evidence: r.get(15)?,
                            history: Vec::new(),
                            description: r.get(16)?,
                            solution: r.get(17)?,
                        },
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
        row.history = history_ids(conn, id, first, last)?;
        Ok(row)
    }

    /// What `findings edit` can change, as stored.
    fn fields(&self) -> [(&'static str, Value); 11] {
        [
            ("title", json!(self.title)),
            ("risk", json!(self.risk)),
            ("confidence", json!(self.confidence)),
            ("method", json!(self.method)),
            ("url", json!(self.url)),
            ("param", json!(self.param)),
            ("cwe", json!(self.cwe)),
            ("history_ids", json!(self.history)),
            ("evidence", json!(self.evidence)),
            ("description", json!(self.description)),
            ("solution", json!(self.solution)),
        ]
    }

    fn revision(&self) -> String {
        crate::store::revision(&Value::Object(self.fields().into_iter().map(|(k, v)| (k.to_string(), v)).collect()))
    }

    /// The fields that differ in `new`.
    fn changes(&self, new: &ManualRow) -> Vec<&'static str> {
        self.fields().into_iter().zip(new.fields()).filter(|(a, b)| a.1 != b.1).map(|(a, _)| a.0).collect()
    }

    /// The values the `changed` fields had and have, as JSON objects for the `edited` event;
    /// None when only texts changed. The description and solution are left out: the type keeps
    /// a replaced one in `replaced_texts`, and one filled in replaced nothing.
    fn values(&self, new: &ManualRow, changed: &[&str]) -> (Option<String>, Option<String>) {
        let pick = |row: &ManualRow| -> Option<String> {
            let fields = row.fields().into_iter();
            let kept = fields.filter(|(k, _)| changed.contains(k) && !matches!(*k, "description" | "solution"));
            let map: serde_json::Map<String, Value> = kept.map(|(k, v)| (k.to_string(), v)).collect();
            (!map.is_empty()).then(|| Value::Object(map).to_string())
        };
        (pick(self), pick(new))
    }
}

/// The revision of finding `id` when it was added by hand (`findings show` gives it); None for
/// a scanner's, which `findings edit` doesn't change.
fn manual_revision(conn: &rusqlite::Connection, id: i64) -> Result<Option<String>> {
    let row = ManualRow::load(conn, id)?;
    Ok((row.source == MANUAL_SOURCE).then(|| row.revision()))
}

/// Refuses a text over its limit: (what it is, the text, the most bytes it may have).
fn check_sizes(texts: &[(&str, &String, usize)]) -> Result<()> {
    match texts.iter().find(|(_, text, max)| text.len() > *max) {
        Some((what, _, max)) => Err(Error::InvalidInput(format!("the {what} is over {max} bytes"))),
        None => Ok(()),
    }
}

/// A history entry's method and URL.
type Line = (String, String);

/// The history entries `ids` links to, each once and in order, with the first one's method and
/// URL. Each must exist and must not have been refused for the scope.
fn linked_entries(conn: &rusqlite::Connection, ids: &[i64]) -> Result<(Vec<i64>, Option<Line>)> {
    if ids.len() > MANUAL_HISTORY_MAX {
        return Err(Error::InvalidInput(format!("link at most {MANUAL_HISTORY_MAX} history entries")));
    }
    let mut history: Vec<i64> = Vec::new();
    let mut first: Option<Line> = None;
    for &id in ids {
        if history.contains(&id) {
            continue;
        }
        history.push(id);
        let row: Option<(String, String, Option<String>)> = conn
            .query_row("SELECT method, url, error FROM history WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        match row {
            // A request refused for its scope (its Host, say) went nowhere, so it shows
            // nothing, and a retest would send what was refused.
            Some((_, _, Some(e))) if e.starts_with("out of scope") => {
                return Err(Error::OutOfScope(format!(
                    "history entry {id} was refused for the scope when it was sent, so it can't be evidence"
                )))
            }
            Some((method, url, _)) => {
                first.get_or_insert((method, url));
            }
            None => return Err(Error::NotFound(format!("history entry {id}"))),
        }
    }
    Ok((history, first))
}

/// A method as given for a finding added by hand, in upper case: one word.
fn manual_method(method: &str) -> Result<String> {
    let method = method.trim().to_ascii_uppercase();
    if method.is_empty()
        || method.len() > 32
        || !method.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::InvalidInput(format!("{method:?} is not an HTTP method")));
    }
    Ok(method)
}

/// The host of a finding's URL as stored: without an IPv6 address's brackets.
fn url_host(parsed: &url::Url) -> String {
    parsed.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']').to_string()
}

/// Keeps the description and solution the alert type `alert_ref` has before they are replaced,
/// with when and by whom (gui, cli or mcp; MCP calls can't pass --replace-text, so an agent
/// never does), for `findings show` to list in `replaced_texts`.
fn keep_replaced_texts(conn: &rusqlite::Connection, alert_ref: &str) -> Result<()> {
    let key = replaced_texts_key(alert_ref);
    let earlier: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [&key], |r| r.get(0)).optional()?;
    let mut list: Vec<Value> = earlier.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
    let (description, solution, time): (String, String, String) = conn.query_row(
        "SELECT description, solution, strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM finding_types WHERE alert_ref = ?1",
        [alert_ref],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    list.push(json!({
        "time": time,
        "by": crate::provenance::origin(),
        "description": description,
        "solution": solution,
    }));
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, Value::Array(list).to_string()],
    )?;
    Ok(())
}

/// Sets the description and solution of the alert type an edited finding `row` is in (made
/// for a new title, named by it), and returns them with the texts it replaced. A given text
/// fills a blank one; one that differs from a text the type has (an empty one too) replaces it
/// only with `replace_text`, and the earlier one is kept. A text not given stays, or, when the
/// finding moved here from another type (`carried`) and this one has none, is that type's, with
/// whoever wrote it.
fn edit_texts(
    conn: &rusqlite::Connection,
    row: &ManualRow,
    description: Option<&str>,
    solution: Option<&str>,
    carried: Option<&ManualRow>,
    replace_text: bool,
) -> Result<((String, String), Vec<&'static str>)> {
    type Texts = (String, String, Option<String>, Option<String>);
    let texts = |alert_ref: &str| -> Result<Option<Texts>> {
        Ok(conn
            .query_row(
                "SELECT coalesce(description, ''), coalesce(solution, ''), description_origin, solution_origin
                 FROM finding_types WHERE alert_ref = ?1",
                [alert_ref],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?)
    };
    let current = texts(&row.alert_ref)?;
    let exists = current.is_some();
    let (mut d, mut s, mut d_by, mut s_by) = current.clone().unwrap_or_default();
    let from = match carried {
        Some(c) => texts(&c.alert_ref)?,
        None => None,
    };
    let by = crate::provenance::origin().to_string();
    let mut replaced = Vec::new();
    for (what, text, text_by, given, carry) in [
        ("description", &mut d, &mut d_by, description, from.as_ref().map(|f| (&f.0, &f.2))),
        ("solution", &mut s, &mut s_by, solution, from.as_ref().map(|f| (&f.1, &f.3))),
    ] {
        match given.map(str::trim) {
            Some(g) if g == text.as_str() => {}
            Some(g) => {
                if !text.is_empty() {
                    replaced.push(what);
                }
                *text = g.to_string();
                *text_by = (!g.is_empty()).then(|| by.clone());
            }
            None => {
                if let Some((t, t_by)) = carry.filter(|(t, _)| text.is_empty() && !t.is_empty()) {
                    *text = t.clone();
                    *text_by = t_by.clone();
                }
            }
        }
    }
    if !replaced.is_empty() {
        if !replace_text {
            return Err(Error::Conflict(format!(
                "the {} differs from the one every finding titled {:?} shares; leave it out to keep that one, or \
                 give --replace-text to replace it",
                replaced.join(" and "),
                row.title
            )));
        }
        keep_replaced_texts(conn, &row.alert_ref)?;
    }
    if !exists {
        conn.execute(
            "INSERT INTO finding_types (alert_ref, rule_id, name, description, solution, refs, tags,
                description_origin, solution_origin)
             VALUES (?1, 0, ?2, ?3, ?4, '[]', '[\"manual\"]', ?5, ?6)",
            params![row.alert_ref, row.title, d, s, d_by, s_by],
        )?;
    } else if current != Some((d.clone(), s.clone(), d_by.clone(), s_by.clone())) {
        conn.execute(
            "UPDATE finding_types SET description = ?2, solution = ?3, description_origin = ?4, solution_origin = ?5
             WHERE alert_ref = ?1",
            params![row.alert_ref, d, s, d_by, s_by],
        )?;
    }
    Ok(((d, s), replaced))
}

fn history_key(id: i64) -> String {
    format!("finding.{id}.history")
}

/// The identities (`fingerprint`s) a finding added by hand had before `findings edit` changed
/// its title, method, URL or parameter, oldest first, which `findings compare` still matches.
fn identities_key(id: i64) -> String {
    format!("finding.{id}.identities")
}

/// The earlier identities of every finding edited by hand, by finding id (see [`identities_key`]).
pub(crate) fn earlier_identities(conn: &rusqlite::Connection) -> Result<std::collections::HashMap<i64, Vec<String>>> {
    let mut stmt = conn.prepare("SELECT key, value FROM meta WHERE key LIKE 'finding.%.identities'")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = std::collections::HashMap::new();
    for row in rows {
        let (key, value) = row?;
        let id = key.strip_prefix("finding.").and_then(|k| k.strip_suffix(".identities")).and_then(|k| k.parse().ok());
        if let (Some(id), Ok(list)) = (id, serde_json::from_str::<Vec<String>>(&value)) {
            out.insert(id, list);
        }
    }
    Ok(out)
}

/// What an edit that changed a finding's alert type or host does to its issue.
enum IssueChange {
    Keep,
    /// The finding was its issue's only one: the issue (its title, CVSS and write-up) goes
    /// with it, to its new alert type and host.
    Rekey(i64),
    Move(i64, i64),
}

/// Where finding `id` of issue `from` goes once edited from `old` to `new`, which changed its
/// alert type or host. It joins the issue findings of its new type and host are in; else the
/// issue it was the only live finding of goes with it; else it leaves for one of its own. A
/// host change alone keeps it in an issue a person merged across hosts.
fn issue_after_edit(
    conn: &rusqlite::Connection,
    id: i64,
    from: i64,
    old: &ManualRow,
    new: &ManualRow,
) -> Result<IssueChange> {
    // Removed findings don't count: the issue's write-up isn't about them.
    let (others, elsewhere): (i64, i64) = conn.query_row(
        "SELECT count(*), coalesce(sum(host != ?3), 0) FROM findings WHERE issue_id = ?1 AND id != ?2 AND state != ?4",
        params![from, id, old.host, REMOVED],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if new.alert_ref == old.alert_ref && elsewhere > 0 {
        return Ok(IssueChange::Keep);
    }
    let joined: Option<i64> = conn.query_row(
        "SELECT min(issue_id) FROM findings WHERE alert_ref = ?1 AND host = ?2 AND id != ?3",
        params![new.alert_ref, new.host, id],
        |r| r.get(0),
    )?;
    let to = match joined {
        Some(to) => to,
        None if others == 0 => return Ok(IssueChange::Rekey(from)),
        None => crate::scan::issues::issue_for(conn, &new.alert_ref, &new.host)?,
    };
    Ok(if to == from { IssueChange::Keep } else { IssueChange::Move(from, to) })
}

/// When a finding was removed and by whom (`by`: gui or cli), and the triage state it had and
/// who set that.
fn removed_key(id: i64) -> String {
    format!("finding.{id}.removed")
}

/// The descriptions and solutions an alert type of findings added by hand had before they were
/// replaced, each with when and by whom (`by`) it was replaced.
fn replaced_texts_key(alert_ref: &str) -> String {
    format!("finding_type.{alert_ref}.replaced")
}

/// A host as compared: lower case, without an IPv6 address's brackets.
fn bare_host(host: &str) -> String {
    host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase()
}

/// Which texts of the type `alert_ref` `f` would replace: those it has and `f` gives differently.
fn texts_replaced(conn: &rusqlite::Connection, alert_ref: &str, f: &ManualFinding) -> Result<Vec<&'static str>> {
    let old: Option<(String, String)> = conn
        .query_row(
            "SELECT coalesce(description, ''), coalesce(solution, '') FROM finding_types WHERE alert_ref = ?1",
            [alert_ref],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((description, solution)) = old else { return Ok(Vec::new()) };
    let changed = |old: &str, new: &str| !old.is_empty() && !new.trim().is_empty() && old != new.trim();
    let mut replaced = Vec::new();
    if changed(&description, &f.description) {
        replaced.push("description");
    }
    if changed(&solution, &f.solution) {
        replaced.push("solution");
    }
    Ok(replaced)
}

/// `manual:` and the title in lower case, words joined by `-`, so findings with the same
/// title group together and never share a type with a scanner's. A slug over 64 characters is
/// cut and ends in a hash of the whole slug, so titles that differ only near the end stay apart.
pub(crate) fn manual_alert_ref(title: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut slug = String::new();
    for c in title.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            slug.push(c);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-');
    if slug.is_empty() {
        return Err(Error::InvalidInput("the title needs at least one letter or digit".into()));
    }
    if slug.chars().count() <= 64 {
        return Ok(format!("manual:{slug}"));
    }
    let head: String = slug.chars().take(55).collect();
    let hash = hex::encode(&Sha256::digest(slug.as_bytes())[..4]);
    Ok(format!("manual:{}-{hash}", head.trim_end_matches('-')))
}

/// An absolute http(s) or ws(s) URL with a host and no user name or password (it would show
/// in every list and report), and the URL as stored: the scheme, host and port as the parser
/// writes them, the path and query as given. The parser would resolve `/public/%2e%2e/admin`
/// to `/admin`, and that path is often the finding.
fn manual_url(url: &str) -> Result<(url::Url, String)> {
    use std::fmt::Write as _;
    let bad = || Error::InvalidInput(format!("{url:?} is not an http(s) or ws(s) URL with a host"));
    // The parser drops tabs and line breaks anywhere, so the URL it checked wouldn't be the one kept.
    if url.chars().any(char::is_control) {
        return Err(Error::InvalidInput("the URL has a control character or line break in it".into()));
    }
    let parsed = url::Url::parse(url).map_err(|_| bad())?;
    if !matches!(parsed.scheme(), "http" | "https" | "ws" | "wss") || parsed.host_str().is_none_or(str::is_empty) {
        return Err(bad());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::InvalidInput(
            "the URL has a user name or password; leave them out (they would show in every report)".into(),
        ));
    }
    // What follows the authority, found the way the parser finds it for these schemes.
    let after_scheme = &url[url.find(':').map_or(0, |i| i + 1)..];
    let authority = after_scheme.trim_start_matches(['/', '\\']);
    let rest = &authority[authority.find(['/', '\\', '?', '#']).unwrap_or(authority.len())..];
    let mut kept = parsed[..url::Position::BeforePath].to_string();
    if !rest.starts_with(['/', '\\']) {
        kept.push('/');
    }
    // A space or non-ASCII character can't go in a request as it is; it gets percent-encoded.
    for c in rest.chars() {
        if c == ' ' || !c.is_ascii() {
            let mut buf = [0; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(kept, "%{b:02X}");
            }
        } else {
            kept.push(c);
        }
    }
    // The kept URL must still point at the host and port that were checked.
    match url::Url::parse(&kept) {
        Ok(k) if k.host_str() == parsed.host_str() && k.port_or_known_default() == parsed.port_or_known_default() => {}
        _ => return Err(bad()),
    }
    Ok((parsed, kept))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[derive(Debug, Default, Clone)]
pub struct FindingFilter {
    pub min_risk: Option<Risk>,
    pub min_confidence: Option<Confidence>,
    pub host: Option<String>,
    pub alert_ref: Option<String>,
    pub state: Option<String>,
    pub source: Option<String>,
    /// Only these findings.
    pub ids: Option<Vec<i64>>,
    /// Only the findings of this issue.
    pub issue: Option<i64>,
    pub examples: usize,
}

impl FindingFilter {
    pub(crate) fn sql(&self) -> (String, Vec<String>) {
        let mut clauses = vec!["1=1".to_string()];
        let mut args: Vec<String> = Vec::new();
        fn bind(args: &mut Vec<String>, v: String) -> String {
            args.push(v);
            format!("?{}", args.len())
        }
        if let Some(r) = self.min_risk {
            clauses.push(format!("risk_level >= CAST({} AS INTEGER)", bind(&mut args, r.level().to_string())));
        }
        if let Some(c) = self.min_confidence {
            // Stored as text; rank it so "medium" also matches "high".
            let rank = "(CASE confidence WHEN 'low' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END)";
            clauses.push(format!("{rank} >= CAST({} AS INTEGER)", bind(&mut args, c.level().to_string())));
        }
        if let Some(h) = &self.host {
            clauses.push(format!("host = {}", bind(&mut args, h.clone())));
        }
        if let Some(a) = &self.alert_ref {
            let p = bind(&mut args, a.clone());
            clauses.push(format!("(alert_ref = {p} OR CAST(rule_id AS TEXT) = {p})"));
        }
        match self.state.as_deref() {
            Some("all") => {}
            // `mark` takes false-positive and stores false_positive; accept either spelling. Several
            // states are separated by commas.
            Some(s) => {
                let states: Vec<String> =
                    s.split(',').map(|s| s.trim().replace('-', "_")).filter(|s| !s.is_empty()).collect();
                if !states.iter().any(|s| s == "all") {
                    let list = serde_json::to_string(&states).unwrap_or_default();
                    clauses.push(format!("state IN (SELECT value FROM json_each({}))", bind(&mut args, list)));
                }
            }
            // Work still to do: not dismissed, resolved or removed.
            None => clauses.push("state NOT IN ('false_positive', 'fixed', 'accepted_risk', 'removed')".into()),
        }
        if let Some(s) = &self.source {
            clauses.push(format!("source = {}", bind(&mut args, s.clone())));
        }
        if let Some(ids) = &self.ids {
            let list = serde_json::to_string(ids).unwrap_or_default();
            clauses.push(format!("id IN (SELECT value FROM json_each({}))", bind(&mut args, list)));
        }
        if let Some(i) = self.issue {
            clauses.push(format!("issue_id = CAST({} AS INTEGER)", bind(&mut args, i.to_string())));
        }
        (clauses.join(" AND "), args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Capture;
    use crate::http::Target;

    fn manual(title: &str, url: Option<&str>, history: Vec<i64>) -> ManualFinding {
        ManualFinding {
            title: title.into(),
            risk: Risk::Medium,
            confidence: Confidence::Medium,
            url: url.map(str::to_string),
            method: None,
            param: String::new(),
            evidence: String::new(),
            description: String::new(),
            solution: String::new(),
            cwe: None,
            history,
            replace_text: false,
        }
    }

    fn store() -> (Store, i64) {
        let s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "https".into(), host: "app.test".into(), port: 443 };
        let req = b"POST /orders/7?x=1 HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let id = s.record(&Capture::new("send", &target, req, None, None, None)).unwrap();
        (s, id)
    }

    #[test]
    fn titles_become_alert_refs() {
        assert_eq!(manual_alert_ref("  SQL Injection (login)! ").unwrap(), "manual:sql-injection-login");
        assert_eq!(manual_alert_ref("Überprüfung fehlt").unwrap(), "manual:überprüfung-fehlt");
        assert!(manual_alert_ref("!!!").is_err());
        // Long slugs are cut and hashed: 55 characters, '-', 8 hex digits.
        let long = manual_alert_ref(&"a".repeat(500)).unwrap();
        assert_eq!(long.len(), "manual:".len() + 64);
        assert!(long.starts_with(&format!("manual:{}-", "a".repeat(55))), "{long}");
        let exact = "b".repeat(64);
        assert_eq!(manual_alert_ref(&exact).unwrap(), format!("manual:{exact}"));
        // Only titles that come out the same share a type.
        let a = "Stored XSS in the account settings display name field on the profile page";
        let b = "Stored XSS in the account settings display name field on the admin page";
        assert_ne!(manual_alert_ref(a).unwrap(), manual_alert_ref(b).unwrap());
        assert_eq!(manual_alert_ref(a).unwrap(), manual_alert_ref(&format!("  {}!", a.to_uppercase())).unwrap());
    }

    #[test]
    fn titles_that_differ_are_different_issues() {
        let (mut s, _) = store();
        let a = "Stored cross-site scripting in the user profile page through the display name";
        let b = "Stored cross-site scripting in the user profile page through the biography";
        let mut f = manual(a, Some("https://app.test/profile"), vec![]);
        f.description = "Display name.".into();
        let first = s.finding_add(&f).unwrap();
        f.title = b.into();
        f.description = "Biography.".into();
        let second = s.finding_add(&f).unwrap();
        let (x, y) = (s.finding_get(first).unwrap(), s.finding_get(second).unwrap());
        assert_ne!(x["alert_ref"], y["alert_ref"]);
        assert_eq!((x["description"].as_str(), y["description"].as_str()), (Some("Display name."), Some("Biography.")));
        assert_eq!((x["name"].as_str(), y["name"].as_str()), (Some(a), Some(b)));
    }

    #[test]
    fn urls_keep_no_credentials() {
        let (mut s, _) = store();
        for url in ["https://admin:hunter2@app.test/x", "https://admin@app.test/x", "https://:pw@app.test/x"] {
            let e = s.finding_add(&manual("X", Some(url), vec![])).unwrap_err();
            assert!(matches!(e, Error::InvalidInput(ref m) if !m.contains("hunter2")), "{url}: {e}");
        }
        assert_eq!(s.findings_list(&FindingFilter::default(), 10).unwrap().len(), 0);
    }

    #[test]
    fn a_finding_added_by_hand() {
        let (mut s, h) = store();
        // URL and method come from the first linked entry when not given.
        let mut f = manual("Order IDOR", None, vec![h]);
        f.description = "Read anyone's order.".into();
        let id = s.finding_add(&f).unwrap();
        let v = s.finding_get(id).unwrap();
        assert_eq!(v["source"], "manual");
        assert_eq!(v["alert_ref"], "manual:order-idor");
        assert_eq!((v["method"].as_str(), v["url"].as_str()), (Some("POST"), Some("https://app.test/orders/7?x=1")));
        assert_eq!((v["host"].as_str(), v["history_id"].as_i64()), (Some("app.test"), Some(h)));
        assert_eq!(v["history_ids"], json!([h]));
        assert_eq!((v["description"].as_str(), v["tags"].clone()), (Some("Read anyone's order."), json!(["manual"])));

        // The same issue again (the query isn't part of it) is refused, not counted as a hit.
        let mut again = manual("order idor", Some("https://app.test/orders/7?x=2"), vec![]);
        again.method = Some("post".into());
        let e = s.finding_add(&again).unwrap_err();
        assert!(matches!(e, Error::Conflict(_)), "{e}");
        // Another URL with the same title joins the type; no description keeps its text.
        let other = s.finding_add(&manual("Order IDOR", Some("https://app.test/orders/8"), vec![])).unwrap();
        assert_eq!(s.finding_get(other).unwrap()["description"], "Read anyone's order.");
        assert_eq!(s.finding_get(other).unwrap()["method"], "GET");
        let mut f = manual("Order IDOR", Some("https://app.test/orders/9"), vec![]);
        f.description = "Newer text.".into();
        assert_eq!(s.manual_texts_replaced(&f).unwrap(), ["description"]);
        f.description = " Read anyone's order. ".into();
        assert!(s.manual_texts_replaced(&f).unwrap().is_empty());
        // Another description is refused unless asked for, and nothing is added.
        f.description = "Newer text.".into();
        assert!(matches!(s.finding_add(&f), Err(Error::Conflict(ref m)) if m.contains("--replace-text")));
        assert_eq!(s.finding_get(id).unwrap()["description"], "Read anyone's order.");
        assert_eq!(s.findings_list(&FindingFilter::default(), 10).unwrap().len(), 2);
        // Asked for, it replaces the text and keeps the earlier one.
        f.replace_text = true;
        s.finding_add(&f).unwrap();
        let v = s.finding_get(id).unwrap();
        assert_eq!(v["description"], "Newer text.");
        let earlier = v["replaced_texts"].as_array().unwrap();
        assert_eq!((earlier.len(), earlier[0]["description"].as_str()), (1, Some("Read anyone's order.")));
        assert!(earlier[0]["time"].as_str().is_some_and(|t| t.ends_with('Z')), "{v}");
        let groups =
            s.findings_grouped(&FindingFilter { source: Some("manual".into()), ..Default::default() }).unwrap();
        assert_eq!((groups.len(), groups[0]["instances"].as_i64()), (1, Some(3)));
        assert_eq!(groups[0]["source"], "manual");
        // Marked like any other.
        s.finding_mark(id, Some("confirmed"), Some("checked")).unwrap();
        assert_eq!(s.finding_get(id).unwrap()["state"], "confirmed");
    }

    #[test]
    fn a_group_is_as_risky_as_its_riskiest_finding() {
        let (mut s, _) = store();
        for (path, risk) in [("/orders/7", Risk::Low), ("/orders/8", Risk::High), ("/orders/9", Risk::Medium)] {
            let mut f = manual("Order IDOR", Some(&format!("https://app.test{path}")), vec![]);
            f.risk = risk;
            s.finding_add(&f).unwrap();
        }
        let groups = s.findings_grouped(&FindingFilter::default()).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!((groups[0]["risk"].as_str(), groups[0]["instances"].as_i64()), (Some("high"), Some(3)));
    }

    #[test]
    fn bad_input_is_refused() {
        let (mut s, h) = store();
        for url in ["app.test/x", "ftp://app.test/", "file:///etc/passwd", "http://", "javascript:alert(1)"] {
            let e = s.finding_add(&manual("X", Some(url), vec![])).unwrap_err();
            assert!(matches!(e, Error::InvalidInput(_)), "{url}: {e}");
        }
        assert!(matches!(s.finding_add(&manual("X", None, vec![])), Err(Error::InvalidInput(_))));
        assert!(matches!(s.finding_add(&manual("X", None, vec![h, 999])), Err(Error::NotFound(_))));
        assert!(matches!(s.finding_add(&manual(" ", Some("http://a.test/"), vec![])), Err(Error::InvalidInput(_))));
        let mut f = manual("X", Some("http://a.test/"), vec![]);
        f.method = Some("GET /".into());
        assert!(matches!(s.finding_add(&f), Err(Error::InvalidInput(_))));
        f.method = None;
        f.evidence = "x".repeat(MANUAL_EVIDENCE_MAX + 1);
        assert!(matches!(s.finding_add(&f), Err(Error::InvalidInput(_))));
        // Nothing was stored on the way.
        assert_eq!(s.findings_list(&FindingFilter::default(), 10).unwrap().len(), 0);
    }

    #[test]
    fn links_and_removal() {
        let (mut s, h) = store();
        let target = Target { scheme: "https".into(), host: "app.test".into(), port: 443 };
        let more: Vec<i64> = (0..3)
            .map(|_| {
                s.record(&Capture::new("send", &target, b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", None, None, None))
                    .unwrap()
            })
            .collect();
        let links = vec![h, more[0], h, more[1], more[2]];
        let id = s.finding_add(&manual("Many", None, links)).unwrap();
        let want = vec![h, more[0], more[1], more[2]];
        assert_eq!(s.finding_history_ids(id).unwrap(), want);
        let two = s.finding_add(&manual("Two", None, vec![more[1], h])).unwrap();
        assert_eq!(s.finding_history_ids(two).unwrap(), [more[1], h]);

        // A scanner's finding can't be removed, and then nothing is.
        s.conn
            .execute(
                "INSERT INTO findings (source, rule_id, alert_ref, name, risk, risk_level, confidence, host, method, url, dedupe)
                 VALUES ('passive', 10037, '10037', 'X', 'low', 1, 'medium', 'app.test', 'GET', 'https://app.test/', 'k')",
                [],
            )
            .unwrap();
        let scanner = s.conn.last_insert_rowid();
        assert!(matches!(s.findings_remove(&[id, scanner]), Err(Error::InvalidInput(_))));
        assert!(matches!(s.findings_remove(&[id, 999]), Err(Error::NotFound(_))));
        assert_eq!(s.findings_list(&FindingFilter::default(), 10).unwrap().len(), 3);
        s.finding_mark(id, Some("confirmed"), Some("seen twice")).unwrap();
        assert_eq!(s.findings_remove(&[id]).unwrap(), 1);

        // Removed, it is a tombstone: hidden unless asked for, with when and what it was.
        let all = FindingFilter { state: Some("all".into()), ..Default::default() };
        assert_eq!(s.findings_list(&FindingFilter::default(), 10).unwrap().len(), 2);
        assert_eq!(s.findings_list(&all, 10).unwrap().len(), 3);
        let removed = FindingFilter { state: Some("removed".into()), ..Default::default() };
        assert_eq!(s.findings_list(&removed, 10).unwrap()[0]["id"], id);
        // Several states, separated by commas, in either spelling.
        let live = FindingFilter { state: Some("open, confirmed,false-positive".into()), ..Default::default() };
        assert_eq!(s.findings_list(&live, 10).unwrap().len(), 2);
        let confirmed = FindingFilter { state: Some("confirmed,removed".into()), ..Default::default() };
        assert_eq!(s.findings_list(&confirmed, 10).unwrap().len(), 1);
        let v = s.finding_get(id).unwrap();
        assert_eq!((v["state"].as_str(), v["note"].as_str()), (Some("removed"), Some("seen twice")));
        assert_eq!(v["removed"]["state"], "confirmed");
        assert!(v["removed"]["time"].as_str().is_some_and(|t| t.ends_with('Z')), "{v}");
        assert_eq!(v["history_ids"], json!(want));
        assert!(matches!(s.finding_mark(id, Some("open"), None), Err(Error::Conflict(_))));
        assert!(matches!(s.findings_remove(&[id]), Err(Error::Conflict(_))));
        // Several at once: all or none, and an empty note clears it.
        let live: Vec<i64> =
            s.findings_list(&FindingFilter::default(), 10).unwrap().iter().filter_map(|v| v["id"].as_i64()).collect();
        let other = *live.iter().find(|&&f| f != scanner).unwrap();
        assert!(matches!(
            s.findings_mark(&[other, scanner, id], Some("confirmed"), None, None),
            Err(Error::Conflict(_))
        ));
        assert_eq!(s.finding_get(other).unwrap()["state"], "open");
        s.findings_mark(&[other, scanner], Some("false_positive"), Some("both noise"), None).unwrap();
        for f in [other, scanner] {
            let v = s.finding_get(f).unwrap();
            assert_eq!((v["state"].as_str(), v["note"].as_str()), (Some("false_positive"), Some("both noise")));
        }
        s.finding_mark(other, None, Some("")).unwrap();
        let v = s.finding_get(other).unwrap();
        assert!(v["note"].is_null() && v["state"] == "false_positive", "{v}");
        let types = |s: &Store| s.query("SELECT alert_ref FROM finding_types", &[], 10, 100).unwrap().rows.len();
        assert_eq!(types(&s), 2);
        // The same issue can be added again, as a new finding.
        let again = s.finding_add(&manual("Many", None, vec![h])).unwrap();
        assert_ne!(again, id);
        assert_eq!(s.finding_get(again).unwrap()["state"], "open");
        assert_eq!(s.finding_get(id).unwrap()["state"], "removed");
    }

    #[test]
    fn links_to_another_site_are_told_apart() {
        let (mut s, h) = store();
        let target = Target { scheme: "https".into(), host: "b.test".into(), port: 8443 };
        let other = s
            .record(&Capture::new("send", &target, b"GET /x HTTP/1.1\r\nHost: b.test\r\n\r\n", None, None, None))
            .unwrap();
        let id = s.finding_add(&manual("Mixed", Some("https://APP.test/orders/7"), vec![h, other])).unwrap();
        let links = s.finding_links(id).unwrap();
        assert_eq!(
            links,
            [
                json!({"id": h, "method": "POST", "url": "https://app.test/orders/7?x=1", "other_site": false}),
                json!({"id": other, "method": "GET", "url": "https://b.test:8443/x", "other_site": true}),
            ]
        );
        // Same host, another port is another site too; ws(s) URLs use their default ports.
        let port = s.finding_add(&manual("Port", Some("https://app.test:8443/"), vec![h])).unwrap();
        assert_eq!(s.finding_links(port).unwrap()[0]["other_site"], true);
        let socket = s.finding_add(&manual("Socket", Some("wss://app.test/live"), vec![h])).unwrap();
        assert_eq!(s.finding_links(socket).unwrap()[0]["other_site"], false);
        assert!(matches!(s.finding_links(999), Err(Error::NotFound(_))));
    }

    #[test]
    fn size_limits_hold_at_the_edge() {
        let (mut s, h) = store();
        let ok = |s: &mut Store, f: &ManualFinding| s.finding_add(f).map(|_| ());
        let at = |title: &str| manual(title, Some("http://a.test/"), vec![]);
        // The title is measured after trimming, in bytes.
        ok(&mut s, &at(&format!("  {}  ", "a".repeat(MANUAL_TITLE_MAX)))).unwrap();
        assert!(matches!(ok(&mut s, &at(&"é".repeat(MANUAL_TITLE_MAX / 2 + 1))), Err(Error::InvalidInput(_))));
        let mut f = at("Texts");
        f.description = "d".repeat(MANUAL_TEXT_MAX);
        f.solution = "s".repeat(MANUAL_TEXT_MAX);
        f.evidence = "e".repeat(MANUAL_EVIDENCE_MAX);
        f.param = "p".repeat(MANUAL_EVIDENCE_MAX);
        ok(&mut s, &f).unwrap();
        for which in 0..4 {
            let mut f = at(&format!("Over {which}"));
            match which {
                0 => f.description = "d".repeat(MANUAL_TEXT_MAX + 1),
                1 => f.solution = "s".repeat(MANUAL_TEXT_MAX + 1),
                2 => f.evidence = "e".repeat(MANUAL_EVIDENCE_MAX + 1),
                _ => f.param = "p".repeat(MANUAL_EVIDENCE_MAX + 1),
            }
            assert!(matches!(ok(&mut s, &f), Err(Error::InvalidInput(_))), "{which}");
        }
        // At most so many links, counted as given.
        let many = vec![h; MANUAL_HISTORY_MAX + 1];
        assert!(matches!(s.finding_add(&manual("Links", None, many)), Err(Error::InvalidInput(_))));
        let id = s.finding_add(&manual("Links", None, vec![h; MANUAL_HISTORY_MAX])).unwrap();
        assert_eq!(s.finding_history_ids(id).unwrap(), [h]);
        // Nothing over a limit was stored, not even its type.
        let n = |s: &Store, sql: &str| s.query(sql, &[], 100, 100).unwrap().rows.len();
        assert_eq!(n(&s, "SELECT id FROM findings"), 3);
        assert_eq!(n(&s, "SELECT alert_ref FROM finding_types WHERE alert_ref LIKE 'manual:over-%'"), 0);
    }

    #[test]
    fn fields_are_normalised() {
        let (mut s, h) = store();
        let mut add = |f: &ManualFinding| {
            let id = s.finding_add(f).unwrap();
            s.finding_get(id).unwrap()
        };
        let mut f = manual("Case", Some(" HTTPS://App.Test:443/a b "), vec![h]);
        f.method = Some(" patch ".into());
        f.cwe = Some(0);
        let v = add(&f);
        // The given URL and method win over the linked entry's; CWE 0 is no CWE.
        assert_eq!((v["url"].as_str(), v["method"].as_str()), (Some("https://app.test/a%20b"), Some("PATCH")));
        assert_eq!(
            (v["host"].as_str(), v["history_id"].as_i64(), v["cwe"].clone()),
            (Some("app.test"), Some(h), Value::Null)
        );
        // A URL but no method: the linked entry's method still applies.
        let v = add(&manual("Method", Some("https://app.test/z"), vec![h]));
        assert_eq!(v["method"], "POST");
        let mut f = manual("Six", Some("http://[::1]:8080/x"), vec![]);
        f.cwe = Some(639);
        let v = add(&f);
        assert_eq!(
            (v["host"].as_str(), v["cwe"].as_i64(), v["method"].as_str()),
            (Some("::1"), Some(639), Some("GET"))
        );
        let v = add(&manual("Socket", Some("wss://app.test/live"), vec![]));
        assert_eq!(v["url"], "wss://app.test/live");
        // Two links: no meta row, the table's first and last are enough.
        let target = Target { scheme: "https".into(), host: "app.test".into(), port: 443 };
        let other = s
            .record(&Capture::new("send", &target, b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", None, None, None))
            .unwrap();
        let two = s.finding_add(&manual("Pair", Some("http://a.test/"), vec![other, h])).unwrap();
        assert_eq!(s.finding_history_ids(two).unwrap(), [other, h]);
        assert_eq!(s.meta_get(&history_key(two)).unwrap(), None);
    }

    #[test]
    fn the_path_and_query_are_kept_as_given() {
        let (mut s, _) = store();
        let mut add = |title: &str, url: &str| {
            let id = s.finding_add(&manual(title, Some(url), vec![])).unwrap();
            s.finding_get(id).unwrap()["url"].as_str().unwrap().to_string()
        };
        // Dot segments, encoded dots and slashes, and brackets are often the finding itself.
        assert_eq!(add("Traversal", "https://app.test/public/%2e%2e/admin"), "https://app.test/public/%2e%2e/admin");
        assert_eq!(add("Dots", " HTTPS://App.Test:443/a/../b/./c "), "https://app.test/a/../b/./c");
        assert_eq!(
            add("Slash", "http://app.test:8080/files/..%2f..%2fetc?ids[]=1&a=%41"),
            "http://app.test:8080/files/..%2f..%2fetc?ids[]=1&a=%41"
        );
        assert_eq!(add("Backslash", "http://app.test/a\\..\\b"), "http://app.test/a\\..\\b");
        // Only the root is added; a query or fragment right after the host stays as it was.
        assert_eq!(add("Root", "https://app.test"), "https://app.test/");
        assert_eq!(add("Query", "https://app.test?q='"), "https://app.test/?q='");
        assert_eq!(add("Unicode", "https://app.test/ä?q=a b"), "https://app.test/%C3%A4?q=a%20b");
        // Same path, other query: still one finding.
        let dup = s.finding_add(&manual("Traversal", Some("https://app.test/public/%2e%2e/admin?x=1"), vec![]));
        assert!(matches!(dup, Err(Error::Conflict(_))), "{dup:?}");
        // The parser would drop a line break, so the URL it checked wouldn't be the one kept.
        for url in ["https://app.test/a\nb", "https://app.test/a\tb", "https://app.test/\u{7f}"] {
            assert!(
                matches!(s.finding_add(&manual("Control", Some(url), vec![])), Err(Error::InvalidInput(_))),
                "{url:?}"
            );
        }
    }

    #[test]
    fn a_refused_duplicate_changes_nothing() {
        let (mut s, _) = store();
        let mut f = manual("Order IDOR", Some("https://app.test/orders/7"), vec![]);
        f.description = "First.".into();
        let id = s.finding_add(&f).unwrap();
        f.description = "Second.".into();
        f.url = Some("https://app.test/orders/7?other=1".into());
        assert!(matches!(s.finding_add(&f), Err(Error::Conflict(ref m)) if m.contains("already this issue")));
        assert_eq!(s.finding_get(id).unwrap()["description"], "First.");
        // Another parameter or method is another issue.
        f.description = "First.".into();
        f.param = "id".into();
        s.finding_add(&f).unwrap();
        f.method = Some("DELETE".into());
        s.finding_add(&f).unwrap();
        assert_eq!(s.findings_list(&FindingFilter::default(), 10).unwrap().len(), 3);
    }

    #[test]
    fn scanners_leave_findings_added_by_hand_alone() {
        let (mut s, h) = store();
        let id = s.finding_add(&manual("Order IDOR", None, vec![h])).unwrap();
        s.conn
            .execute(
                "INSERT INTO finding_types (alert_ref, rule_id, name, description, solution, refs, tags)
                 VALUES ('10037', 10037, 'X', '', '', '[]', '[]')",
                [],
            )
            .unwrap();
        // A passive rescan starts its own findings over, not the tester's.
        crate::scan::passive::rescan(&mut s).unwrap();
        let items = s.findings_list(&FindingFilter::default(), 100).unwrap();
        assert!(items.iter().any(|i| i["id"] == id && i["source"] == "manual"));
        assert!(items.iter().all(|i| i["source"].is_string()));
        let only =
            s.findings_list(&FindingFilter { source: Some("manual".into()), ..Default::default() }, 100).unwrap();
        assert_eq!(only.len(), 1);
        // Removing it keeps every scanner type, used or not; the same id twice is one removal.
        assert_eq!(s.findings_remove(&[id, id]).unwrap(), 1);
        assert_eq!(s.findings_remove(&[]).unwrap(), 0);
        let types = s.query("SELECT alert_ref FROM finding_types WHERE alert_ref = '10037'", &[], 10, 10).unwrap();
        assert_eq!(types.rows.len(), 1);
        assert_eq!(s.finding_get(id).unwrap()["state"], "removed");
        assert!(matches!(s.findings_remove(&[id]), Err(Error::Conflict(_))));
        // A passive rescan leaves the tombstone too.
        crate::scan::passive::rescan(&mut s).unwrap();
        assert_eq!(s.finding_get(id).unwrap()["state"], "removed");
    }

    #[test]
    fn a_cleared_note_is_triage_a_rescan_keeps() {
        let mut s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        s.record(&Capture::new("send", &target, b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", Some(resp), None, None))
            .unwrap();
        crate::scan::passive::scan_pending(&mut s).unwrap();
        let ids: Vec<i64> =
            s.findings_list(&FindingFilter::default(), 100).unwrap().iter().filter_map(|v| v["id"].as_i64()).collect();
        assert!(ids.len() > 1);
        s.finding_mark(ids[0], None, Some("")).unwrap();
        // Nothing is found again: only the finding someone touched stays.
        s.findings_rescan_start("passive", &[]).unwrap();
        assert_eq!(s.findings_rescan_finish("passive", &[]).unwrap(), (ids.len() - 1, 1));
        let v = s.finding_get(ids[0]).unwrap();
        assert!(v["note"].is_null() && v["hits"] == 0, "{v}");
    }

    /// Records a GET of `path` on app.test with an X-Powered-By header (rule 10037, low) and
    /// runs the passive scan; returns the history id.
    fn seen_at(s: &mut Store, path: &str) -> i64 {
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        let req = format!("GET {path} HTTP/1.1\r\nHost: app.test\r\n\r\n");
        let h = s.record(&Capture::new("send", &target, req.as_bytes(), Some(resp), None, None)).unwrap();
        crate::scan::passive::scan_pending(s).unwrap();
        h
    }

    fn xpb(s: &Store) -> Vec<Value> {
        let all = FindingFilter { alert_ref: Some("10037".into()), state: Some("all".into()), ..Default::default() };
        s.findings_list(&all, 100).unwrap()
    }

    #[test]
    fn a_person_s_rating_holds_over_sightings_and_reaches_an_issue_s_new_instances() {
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/x");
        let x = xpb(&s)[0].clone();
        let (id, scanner) = (x["id"].as_i64().unwrap(), x["risk"].as_str().unwrap().to_string());
        let up = Rating { risk: Some("high"), confidence: Some("high"), reason: "leaks the exact build" };
        assert!(matches!(
            s.findings_rate(&[id], &[], Some(&Rating { risk: None, confidence: None, reason: "x" })),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            s.findings_rate(&[id], &[], Some(&Rating { reason: " ", ..up })),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(s.findings_rate(&[id], &[], Some(&up)).unwrap(), [id]);
        // Rated the same again: nothing changes, nothing goes on the timeline.
        assert!(s.findings_rate(&[id], &[], Some(&up)).unwrap().is_empty());
        let rated = |s: &Store| xpb(s).into_iter().find(|f| f["id"] == id).unwrap();
        let f = rated(&s);
        assert_eq!((f["risk"].as_str(), f["confidence"].as_str()), (Some("high"), Some("high")));
        assert_eq!(f["rated"]["scanner_risk"].as_str(), Some(scanner.as_str()), "{f}");
        // A filter and the order go by the rating.
        let high = FindingFilter { min_risk: Some(Risk::High), ..Default::default() };
        assert_eq!(s.findings_list(&high, 10).unwrap().len(), 1);
        // Seen again: the scanner's rating goes on beside it, the person's stays.
        seen_at(&mut s, "/x");
        assert_eq!(rated(&s)["risk"], "high");
        let events: Vec<Value> = s.finding_events(id).unwrap().into_iter().filter(|e| e["kind"] == "rated").collect();
        assert_eq!(events.len(), 1);
        assert_eq!((events[0]["new"].as_str(), events[0]["text"].as_str()), (Some("high/high"), Some(up.reason)));
        // Cleared, the scanner's rating is back.
        assert_eq!(s.findings_rate(&[id], &[], None).unwrap(), [id]);
        let f = rated(&s);
        assert_eq!((f["risk"].as_str(), f["rated"].is_null()), (Some(scanner.as_str()), true), "{f}");
        // Rated as a whole issue, a new instance arrives rated, by the person who rated it.
        let issue = f["issue_id"].as_i64().unwrap();
        let down = Rating { risk: Some("info"), confidence: None, reason: "internal host" };
        s.findings_rate(&[], &[issue], Some(&down)).unwrap();
        assert_eq!(s.issue_get(issue).unwrap()["rating"]["risk"], "info");
        seen_at(&mut s, "/y");
        let y = xpb(&s).into_iter().find(|f| f["url"].as_str().unwrap().ends_with("/y")).unwrap();
        assert_eq!((y["risk"].as_str(), y["rated"]["origin"].as_str()), (Some("info"), Some("cli")), "{y}");
        s.findings_rate(&[], &[issue], None).unwrap();
        assert!(s.issue_get(issue).unwrap()["rating"].is_null());
        seen_at(&mut s, "/z");
        let z = xpb(&s).into_iter().find(|f| f["url"].as_str().unwrap().ends_with("/z")).unwrap();
        assert!(z["rated"].is_null(), "{z}");
    }

    #[test]
    fn suppression_rules_mark_what_they_match_now_and_later() {
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/x");
        seen_at(&mut s, "/static/a.js");
        let state_of = |s: &Store, path: &str| -> (String, Option<i64>, Option<String>) {
            let f = xpb(s).into_iter().find(|f| f["url"].as_str().unwrap().ends_with(path)).unwrap();
            let full = s.finding_get(f["id"].as_i64().unwrap()).unwrap();
            (f["state"].as_str().unwrap().into(), f["suppressed_by"].as_i64(), full["note"].as_str().map(Into::into))
        };
        // A triaged finding is a person's decision: the rule leaves it.
        let x = xpb(&s).into_iter().find(|f| f["url"].as_str().unwrap().ends_with("/x")).unwrap();
        s.finding_mark(x["id"].as_i64().unwrap(), Some("confirmed"), None).unwrap();
        let bad = Suppression { alert: "10037".into(), host: "app.test".into(), ..Default::default() };
        assert!(matches!(s.suppression_add(&bad), Err(Error::InvalidInput(_))), "a reason is needed");
        let rule = Suppression {
            alert: "10037".into(),
            host: "APP.test".into(),
            path_prefix: "/static/".into(),
            param: None,
            reason: "static files are served by the CDN".into(),
        };
        let (id, marked) = s.suppression_add(&rule).unwrap();
        assert_eq!(marked, 1);
        assert_eq!(state_of(&s, "/static/a.js"), ("false_positive".into(), Some(id), Some(rule.reason.clone())));
        assert_eq!(state_of(&s, "/x").0, "confirmed");
        // Found later: marked on arrival, as the rule's author set it, and the timeline says why.
        seen_at(&mut s, "/static/b.js");
        seen_at(&mut s, "/y");
        assert_eq!(state_of(&s, "/static/b.js").0, "false_positive");
        assert_eq!(state_of(&s, "/y").0, "open");
        let b = xpb(&s).into_iter().find(|f| f["url"].as_str().unwrap().ends_with("/static/b.js")).unwrap();
        assert_eq!(b["state_origin"], "cli");
        let last = s.finding_events(b["id"].as_i64().unwrap()).unwrap().pop().unwrap();
        assert_eq!(last["text"], format!("suppressed by rule {id}: static files are served by the CDN"));
        let list = s.suppressions_list().unwrap();
        assert_eq!((list[0]["host"].as_str(), list[0]["findings"].as_i64()), (Some("app.test"), Some(2)));
        // A person who changes one's state takes it from the rule.
        s.finding_mark(b["id"].as_i64().unwrap(), Some("confirmed"), None).unwrap();
        assert_eq!(state_of(&s, "/static/b.js"), ("confirmed".into(), None, Some(rule.reason.clone())));
        // Removed with --reopen, what it still holds is open again; later sightings aren't marked.
        assert_eq!(s.suppression_remove(id, true).unwrap(), 1);
        assert_eq!(state_of(&s, "/static/a.js").0, "open");
        seen_at(&mut s, "/static/c.js");
        assert_eq!(state_of(&s, "/static/c.js").0, "open");
        assert!(matches!(s.suppression_remove(id, false), Err(Error::NotFound(_))));
    }

    fn filter(alert: &str, risk: Option<&str>, reason: &str) -> AlertFilter {
        AlertFilter { alert: alert.into(), risk: risk.map(str::to_string), reason: reason.into(), ..Default::default() }
    }

    fn at(s: &Store, path: &str) -> Value {
        xpb(s).into_iter().find(|f| f["url"].as_str().unwrap().ends_with(path)).unwrap()
    }

    #[test]
    fn alert_filters_match_any_host_a_port_a_url_and_a_parameter() {
        let rule = |url: Option<&str>, param: Option<&str>| Rule {
            id: 1,
            port: None,
            path_prefix: String::new(),
            param: None,
            url_regex: url.map(|r| filter_regex("--url-regex", r).unwrap()),
            param_regex: param.map(|r| filter_regex("--param-regex", r).unwrap()),
            risk: Some("info".into()),
            confidence: None,
            reason: "r".into(),
            origin: None,
        };
        assert!(rule(Some(r"/api/v\d+/"), None).matches("http://a.test/api/v2/x?q=1", ""));
        assert!(!rule(Some(r"/api/v\d+/"), None).matches("http://a.test/web/x", ""));
        // The URL as found, query included.
        assert!(rule(Some(r"[?&]debug="), None).matches("http://a.test/x?debug=1", ""));
        assert!(rule(None, Some("^(?i)x-.*")).matches("http://a.test/", "X-Powered-By"));
        assert!(!rule(None, Some("^(?i)x-.*")).matches("http://a.test/", "Server"));
        assert!(matches!(filter_regex("--url-regex", "("), Err(Error::InvalidInput(_))));
        assert!(matches!(filter_regex("--url-regex", &"a".repeat(1001)), Err(Error::InvalidInput(_))));

        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/a1");
        seen_at(&mut s, "/b");
        let url = at(&s, "/a1")["url"].as_str().unwrap().to_string();
        let port = url::Url::parse(&url).unwrap().port_or_known_default().unwrap();
        let on = |host: &str| AlertFilter { host: Some(host.into()), ..filter("10037", Some("info"), "noise") };
        assert_eq!(s.filter_add(&on("other.test")).unwrap().1, 0, "another host");
        assert_eq!(s.filter_add(&on(&format!("app.test:{}", port.wrapping_add(1)))).unwrap().1, 0, "another port");
        // No host: any host. A regex picks among the URLs.
        let by_url = AlertFilter { url_regex: Some(r"/a\d$".into()), ..filter("10037", Some("info"), "noise") };
        assert_eq!(s.filter_add(&by_url).unwrap().1, 1);
        assert_eq!(at(&s, "/a1")["risk"], "info");
        assert_eq!(at(&s, "/b")["rated"], Value::Null);
        // The rule id matches too, and a later filter leaves what an earlier one rated.
        let (late, rated) = s.filter_add(&filter("10037", Some("high"), "all of them")).unwrap();
        assert_eq!(rated, 1);
        assert_eq!(
            (at(&s, "/a1")["risk"].as_str(), at(&s, "/b")["rated"]["filter"].as_i64()),
            (Some("info"), Some(late))
        );
        let list = s.filters_list().unwrap();
        assert_eq!(list.len(), 4);
        assert_eq!(
            (list[0]["host"].as_str(), list[1]["port"].as_u64()),
            (Some("other.test"), Some(u64::from(port) + 1))
        );
        assert!(list[2]["host"].is_null());
        assert_eq!(list.iter().map(|f| f["holds"].as_i64().unwrap()).collect::<Vec<_>>(), [0, 0, 1, 1]);
        // Filters aren't suppression rules.
        assert!(s.suppressions_list().unwrap().is_empty());
        assert!(matches!(s.suppression_remove(late, false), Err(Error::NotFound(_))));
        // What a filter needs.
        for bad in [
            filter("10037", None, "x"),
            filter("10037", Some("false_positive"), "x"),
            filter("10037", Some("severe"), "x"),
            filter("10037", Some("low"), " "),
            filter(" ", Some("low"), "x"),
            AlertFilter { path_prefix: "static".into(), ..filter("10037", Some("low"), "x") },
            AlertFilter { param_regex: Some("[".into()), ..filter("10037", Some("low"), "x") },
            AlertFilter { confidence: Some("sure".into()), ..filter("10037", None, "x") },
        ] {
            assert!(matches!(s.filter_add(&bad), Err(Error::InvalidInput(_))), "{bad:?}");
        }
    }

    #[test]
    fn a_filter_rates_what_it_matches_now_and_when_found_again() {
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/x");
        seen_at(&mut s, "/y");
        let scanner = at(&s, "/x")["risk"].as_str().unwrap().to_string();
        // A person's rating is theirs: the filter leaves it.
        let y = at(&s, "/y")["id"].as_i64().unwrap();
        let own = Rating { risk: Some("medium"), confidence: None, reason: "mine" };
        s.findings_rate(&[y], &[], Some(&own)).unwrap();
        let f = AlertFilter { confidence: Some("low".into()), ..filter("10037", Some("info"), "internal only") };
        let (id, rated) = s.filter_add(&f).unwrap();
        assert_eq!(rated, 1);
        let x = at(&s, "/x");
        let xid = x["id"].as_i64().unwrap();
        assert_eq!((x["risk"].as_str(), x["confidence"].as_str()), (Some("info"), Some("low")));
        assert_eq!(x["rated"]["filter"], id);
        assert_eq!(x["rated"]["scanner_risk"].as_str(), Some(scanner.as_str()));
        assert_eq!(
            (x["rated"]["reason"].as_str(), x["rated"]["origin"].as_str()),
            (Some("internal only"), Some("cli"))
        );
        assert_eq!(at(&s, "/y")["risk"], "medium");
        assert!(at(&s, "/y")["rated"]["filter"].is_null());
        let last = s.finding_events(xid).unwrap().pop().unwrap();
        assert_eq!(
            (last["kind"].as_str(), last["text"].as_str()),
            (Some("rated"), Some(&*format!("re-rated by filter {id}: internal only")))
        );
        assert_eq!(s.finding_get(xid).unwrap()["rated_by"], id);
        // Seen again, the rating stands; found new, it arrives rated.
        seen_at(&mut s, "/x");
        assert_eq!((at(&s, "/x")["risk"].as_str(), at(&s, "/x")["hits"].as_i64()), (Some("info"), Some(2)));
        seen_at(&mut s, "/z");
        let z = at(&s, "/z");
        assert_eq!((z["risk"].as_str(), z["rated"]["filter"].as_i64()), (Some("info"), Some(id)), "{z}");
        assert_eq!(s.filters_list().unwrap()[0]["holds"], 2);
        // A person rating one takes it from the filter.
        let zid = z["id"].as_i64().unwrap();
        s.findings_rate(&[zid], &[], Some(&Rating { risk: Some("high"), confidence: None, reason: "no" })).unwrap();
        assert!(at(&s, "/z")["rated"]["filter"].is_null());
        assert!(s.finding_get(zid).unwrap()["rated_by"].is_null());
        // Removed with --unrate, what it still holds has the scanner's rating again; the rest stay.
        assert_eq!(s.filter_remove(id, true).unwrap(), 1);
        let x = at(&s, "/x");
        assert_eq!((x["risk"].as_str(), x["rated"].is_null()), (Some(scanner.as_str()), true), "{x}");
        assert_eq!(at(&s, "/z")["risk"], "high");
        assert_eq!(at(&s, "/y")["risk"], "medium");
        seen_at(&mut s, "/w");
        assert!(at(&s, "/w")["rated"].is_null());
        assert!(matches!(s.filter_remove(id, false), Err(Error::NotFound(_))));
        // Removed without, they keep it.
        let (again, _) = s.filter_add(&filter("10037", Some("info"), "again")).unwrap();
        assert_eq!(s.filter_remove(again, false).unwrap(), 0);
        assert_eq!(at(&s, "/w")["risk"], "info");
        // A row no build could have added is passed over, and the scan still records its findings.
        s.conn
            .execute(
                "INSERT INTO suppressions (action, alert_ref, host, reason, origin, risk, url_regex)
                 VALUES ('rate', '10037', '', 'hand-edited', 'cli', 'severe', NULL),
                        ('rate', '10037', '', 'hand-edited', 'cli', 'high', '(')",
                [],
            )
            .unwrap();
        seen_at(&mut s, "/v");
        assert!(at(&s, "/v")["rated"].is_null());
    }

    #[test]
    fn suppression_and_an_issue_s_rating_come_before_a_filter() {
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/x");
        let rule = Suppression {
            alert: "10037".into(),
            host: "app.test".into(),
            path_prefix: "/static/".into(),
            param: None,
            reason: "CDN".into(),
        };
        let (sid, _) = s.suppression_add(&rule).unwrap();
        let (fid, _) = s.filter_add(&filter("10037", Some("high"), "everywhere")).unwrap();
        // Suppressed: a false positive, and the filter doesn't rate it.
        seen_at(&mut s, "/static/a.js");
        let a = at(&s, "/static/a.js");
        assert_eq!((a["state"].as_str(), a["suppressed_by"].as_i64()), (Some("false_positive"), Some(sid)));
        assert!(a["rated"].is_null(), "{a}");
        // The issue rated as a whole: its new instances take that, not the filter's.
        let issue = at(&s, "/x")["issue_id"].as_i64().unwrap();
        s.findings_rate(&[], &[issue], Some(&Rating { risk: Some("medium"), confidence: None, reason: "issue" }))
            .unwrap();
        seen_at(&mut s, "/y");
        let y = at(&s, "/y");
        assert_eq!((y["risk"].as_str(), y["rated"]["filter"].as_i64()), (Some("medium"), None), "{y}");
        // Without the issue's rating, the filter rates it, in the state the issue's decision gives it.
        s.findings_rate(&[], &[issue], None).unwrap();
        s.findings_mark_issues(&[], &[issue], Some("accepted_risk"), None, None).unwrap();
        seen_at(&mut s, "/z");
        let z = at(&s, "/z");
        assert_eq!((z["state"].as_str(), z["rated"]["filter"].as_i64()), (Some("accepted_risk"), Some(fid)), "{z}");
        // A suppression rule and a filter are listed apart, and the suppression list is as before.
        let list = s.suppressions_list().unwrap();
        assert_eq!(list.len(), 1);
        let keys: Vec<&str> = list[0].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["id", "time", "alert_ref", "host", "path_prefix", "param", "reason", "by", "origin", "findings", "port"]
        );
        assert!(matches!(s.filter_remove(sid, false), Err(Error::NotFound(_))));
    }

    #[test]
    fn a_suppression_host_can_name_a_port() {
        assert_eq!(suppression_host("App.test").unwrap(), ("app.test".into(), None));
        assert_eq!(suppression_host("127.0.0.1:3300").unwrap(), ("127.0.0.1".into(), Some(3300)));
        assert_eq!(suppression_host("app.test:80").unwrap(), ("app.test".into(), Some(80)));
        assert_eq!(suppression_host("[::1]:8443").unwrap(), ("::1".into(), Some(8443)));
        assert_eq!(suppression_host("[::1]").unwrap(), ("::1".into(), None));
        for bad in ["", "app.test/x", "a b", "app.test:99999", "user@app.test"] {
            assert!(matches!(suppression_host(bad), Err(Error::InvalidInput(_))), "{bad:?}");
        }
        // Findings are stored by host name; the port picks among them by their URL.
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/x");
        let url = xpb(&s)[0]["url"].as_str().unwrap().to_string();
        let port = url::Url::parse(&url).unwrap().port_or_known_default().unwrap();
        let host = url_host(&url::Url::parse(&url).unwrap());
        let rule = |p: u16| Suppression {
            alert: "10037".into(),
            host: format!("{host}:{p}"),
            reason: "noise".into(),
            ..Default::default()
        };
        assert_eq!(s.suppression_add(&rule(port.wrapping_add(1))).unwrap().1, 0, "another port");
        assert_eq!(s.suppression_add(&rule(port)).unwrap().1, 1, "{url}");
        assert_eq!(s.suppressions_list().unwrap()[1]["port"], port);
    }

    #[test]
    fn the_key_drops_path_parameters() {
        let key = |url| dedupe_key("1", "GET", url, "p");
        assert_eq!(key("http://a.test/login;jsessionid=ABC"), "1|GET|http://a.test/login|p");
        assert_eq!(key("http://a.test/app;JSESSIONID=1;PHPSESSID=2/page?x=1"), "1|GET|http://a.test/app/page|p");
        assert_eq!(key("http://a.test/;sid=1"), "1|GET|http://a.test/|p");
        // Matrix parameters too: like a query, they hold values, not the resource.
        assert_eq!(key("http://a.test/cars;color=red/x"), "1|GET|http://a.test/cars/x|p");
        // A `;` that isn't a name=value parameter is part of the path.
        assert_eq!(key("http://a.test/a;b/c;d=1;e"), "1|GET|http://a.test/a;b/c;e|p");
        // Only the path: a query keeps going whole, and the authority is left alone.
        assert_eq!(key("http://a.test/x?a=1;b=2"), "1|GET|http://a.test/x|p");
        assert_eq!(key("http://u;x=1@a.test/x"), "1|GET|http://u;x=1@a.test/x|p");
        assert_eq!(key("http://a.test"), "1|GET|http://a.test|p");
        // A fragment is a client-side route: its parameters stay, the path's before it go.
        assert_eq!(key("http://a.test/#/view;id=1"), "1|GET|http://a.test/#/view;id=1|p");
        assert_eq!(key("http://a.test/x;s=1#/v;id=2"), "1|GET|http://a.test/x#/v;id=2|p");
        // A URL without path parameters keys as before, so its fingerprint doesn't change.
        use sha2::{Digest, Sha256};
        let v2 = hex::encode(&Sha256::digest(b"10037|GET|http://a.test/a|")[..16]);
        assert_eq!(fingerprint("10037", "GET", "http://a.test/a?q=1", ""), v2);
        assert_eq!(
            fingerprint("10037", "GET", "http://a.test/a;jsessionid=1", ""),
            fingerprint("10037", "GET", "http://a.test/a;jsessionid=2", "")
        );
    }

    #[test]
    fn a_session_id_in_the_path_is_the_same_finding() {
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/login;jsessionid=AAA");
        let h = seen_at(&mut s, "/login;jsessionid=BBB?next=/");
        let f = xpb(&s);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(
            (f[0]["hits"].as_i64(), f[0]["url"].as_str()),
            (Some(2), Some("http://app.test/login;jsessionid=AAA"))
        );
        assert_eq!(s.finding_get(f[0]["id"].as_i64().unwrap()).unwrap()["last_history_id"], h);
    }

    #[test]
    fn findings_stored_once_per_session_are_merged() {
        let mut s = Store::open_in_memory().unwrap();
        let (h1, _, h3) = (seen_at(&mut s, "/a"), seen_at(&mut s, "/b"), seen_at(&mut s, "/c"));
        let ids: Vec<i64> = xpb(&s).iter().map(|f| f["id"].as_i64().unwrap()).collect();
        let (a, b, c) = (ids[0], ids[1], ids[2]);
        // As schema v17 stored them: one finding per session id, each with its own v2 key.
        for (id, sid) in [(a, "A"), (b, "B"), (c, "C")] {
            s.conn
                .execute(
                    "UPDATE findings SET url = ?1, dedupe = alert_ref || '|GET|' || ?1 || '|' || param WHERE id = ?2",
                    params![format!("http://app.test/login;jsessionid={sid}"), id],
                )
                .unwrap();
        }
        // b was marked false positive, then a fixed later: the later decision wins. c has the
        // note and the highest risk; a, the first, is kept.
        s.finding_mark(b, Some("false_positive"), None).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        s.finding_mark(a, Some("fixed"), None).unwrap();
        s.finding_mark(c, None, Some("seen on login")).unwrap();
        s.conn.execute("UPDATE findings SET risk = 'medium', risk_level = 2 WHERE id = ?1", [c]).unwrap();
        s.conn
            .execute_batch(&format!(
                "INSERT INTO scan_observations (job_id, finding_id, seen) VALUES (1, {a}, 'gone'), (1, {b}, 'still'),
                    (2, {c}, 'new');"
            ))
            .unwrap();
        let removed = s.finding_add(&manual("Login IDOR", Some("http://app.test/login;jsessionid=A"), vec![])).unwrap();
        s.findings_remove(&[removed]).unwrap();
        let tombstone: String =
            s.conn.query_row("SELECT dedupe FROM findings WHERE id = ?1", [removed], |r| r.get(0)).unwrap();

        rekey_v18(&s.conn).unwrap();
        let left = xpb(&s);
        assert_eq!(left.len(), 1, "{left:?}");
        let f = s.finding_get(a).unwrap();
        assert_eq!(
            (f["hits"].as_i64(), f["history_id"].as_i64(), f["last_history_id"].as_i64()),
            (Some(3), Some(h1), Some(h3))
        );
        assert_eq!(
            (f["state"].as_str(), f["note"].as_str(), f["risk"].as_str()),
            (Some("fixed"), Some("seen on login"), Some("medium"))
        );
        assert!(f["state_changed_at"].is_string() && f["note_changed_at"].is_string(), "{f}");
        let key: String = s.conn.query_row("SELECT dedupe FROM findings WHERE id = ?1", [a], |r| r.get(0)).unwrap();
        assert_eq!(key, "10037|GET|http://app.test/login|");
        // Every timeline moved to it; one scan's view keeps the sighting over the "gone".
        let kinds: Vec<String> =
            s.finding_events(a).unwrap().iter().map(|e| e["kind"].as_str().unwrap().into()).collect();
        assert_eq!(kinds.iter().filter(|k| *k == "created").count(), 3, "{kinds:?}");
        assert!(kinds.contains(&"note".to_string()) && kinds.iter().filter(|k| *k == "state").count() == 2);
        let seen: Vec<(i64, i64, String)> = s
            .conn
            .prepare("SELECT job_id, finding_id, seen FROM scan_observations ORDER BY job_id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(seen, [(1, a, "still".to_string()), (2, a, "new".to_string())]);
        // A tombstone keeps its key, and running it again changes nothing.
        let after: String =
            s.conn.query_row("SELECT dedupe FROM findings WHERE id = ?1", [removed], |r| r.get(0)).unwrap();
        assert_eq!(after, tombstone);
        rekey_v18(&s.conn).unwrap();
        assert_eq!(s.finding_get(a).unwrap()["hits"], 3);
    }

    #[test]
    fn an_older_project_s_v10_step_leaves_session_ids_to_v18() {
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/a");
        seen_at(&mut s, "/b");
        let ids: Vec<i64> = xpb(&s).iter().map(|f| f["id"].as_i64().unwrap()).collect();
        for (id, sid, risk, level) in [(ids[0], "A", "low", 1), (ids[1], "B", "high", 3)] {
            s.conn
                .execute(
                    "UPDATE findings SET url = ?1, dedupe = 'old-' || id, risk = ?2, risk_level = ?3 WHERE id = ?4",
                    params![format!("http://app.test/login;jsessionid={sid}"), risk, level, id],
                )
                .unwrap();
        }
        s.finding_mark(ids[1], None, Some("seen on login")).unwrap();
        // v10's merge keeps neither notes nor the higher risk, so it only joins what v2 joined
        // (the query): the session ids are v18's to merge, with both kept.
        rekey_findings(&s.conn).unwrap();
        assert_eq!(xpb(&s).len(), 2);
        rekey_v18(&s.conn).unwrap();
        let f = s.finding_get(ids[0]).unwrap();
        assert_eq!(
            (f["risk"].as_str(), f["note"].as_str(), f["hits"].as_i64()),
            (Some("high"), Some("seen on login"), Some(2))
        );
    }

    #[test]
    fn a_merge_keeps_an_issue_s_records_with_its_finding() {
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/a");
        seen_at(&mut s, "/b");
        seen_at(&mut s, "/c");
        let ids: Vec<i64> = xpb(&s).iter().map(|f| f["id"].as_i64().unwrap()).collect();
        // b was split into an issue of its own with a write-up; a stays with c. As v17 keyed
        // them, a and b are two findings; now they are one.
        let split = s.issue_split(&[ids[1]], Some("Login page")).unwrap();
        s.issue_set_narrative(split, "Shown on the login page.").unwrap();
        for (id, sid) in [(ids[0], "A"), (ids[1], "B")] {
            s.conn
                .execute(
                    "UPDATE findings SET url = ?1, dedupe = 'old-' || id WHERE id = ?2",
                    params![format!("http://app.test/login;jsessionid={sid}"), id],
                )
                .unwrap();
        }
        let first = s.finding_get(ids[0]).unwrap()["issue_id"].as_i64().unwrap();
        rekey_v18(&s.conn).unwrap();
        // Moved to the split issue, which would otherwise have no findings and hide its
        // write-up; the move says why.
        let got = s.issue_get(split).unwrap();
        assert_eq!(got["findings"][0]["id"], ids[0]);
        assert_eq!(s.issue_narrative(split).unwrap().unwrap().text, "Shown on the login page.");
        let last = s.finding_events(ids[0]).unwrap().pop().unwrap();
        assert_eq!((last["kind"].as_str(), last["old"].as_str()), (Some("moved"), Some(first.to_string().as_str())));
        assert!(last["origin"].is_null() && last["text"].as_str().unwrap().contains("session id"), "{last}");
        assert_eq!(s.issue_finding_ids(first).unwrap(), [ids[2]]);
    }

    #[test]
    fn findings_added_by_hand_merge_their_links() {
        let (mut s, h1) = store();
        let target = Target { scheme: "https".into(), host: "app.test".into(), port: 443 };
        let mut hs = vec![h1];
        for _ in 0..3 {
            hs.push(s.record(&Capture::new("send", &target, b"GET / HTTP/1.1\r\n\r\n", None, None, None)).unwrap());
        }
        // As v17 stored them: each with the key it had then, which kept the path parameter
        // (this build refuses the second as the same finding, so the first's key goes back).
        let add = |s: &mut Store, sid: &str, links: Vec<i64>| {
            let url = format!("https://app.test/x;jsessionid={sid}");
            let id = s
                .finding_add(&ManualFinding {
                    method: Some("GET".into()),
                    ..manual("Session fixation", Some(&url), links)
                })
                .unwrap();
            s.conn.execute("UPDATE findings SET dedupe = 'v17-' || id WHERE id = ?1", [id]).unwrap();
            id
        };
        let a = add(&mut s, "A", vec![hs[0], hs[1], hs[2]]);
        let b = add(&mut s, "B", vec![hs[3], hs[1]]);
        rekey_v18(&s.conn).unwrap();
        assert_eq!(s.finding_history_ids(a).unwrap(), [hs[0], hs[1], hs[2], hs[3]]);
        assert!(matches!(s.finding_get(b), Err(Error::NotFound(_))));
        assert!(s.meta_get(&history_key(b)).unwrap().is_none());
        let f = s.finding_get(a).unwrap();
        assert_eq!((f["history_id"].as_i64(), f["last_history_id"].as_i64()), (Some(hs[0]), Some(hs[3])));
        // Added again by hand, it is the same finding.
        let again = ManualFinding {
            method: Some("GET".into()),
            ..manual("Session fixation", Some("https://app.test/x;jsessionid=C"), vec![])
        };
        assert!(matches!(s.finding_add(&again), Err(Error::Conflict(_))));
    }

    #[test]
    fn marking_the_state_a_finding_has_changes_nothing() {
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/x");
        let id = xpb(&s)[0]["id"].as_i64().unwrap();
        // Open already: no one changed it, and nothing goes on the timeline.
        s.finding_mark(id, Some("open"), None).unwrap();
        let f = s.finding_get(id).unwrap();
        assert!(f["state_changed_at"].is_null() && f["state_origin"].is_null(), "{f}");
        s.finding_mark(id, Some("fixed"), None).unwrap();
        let marked = s.finding_get(id).unwrap()["state_changed_at"].clone();
        // Seen again after the first mark: a second "fixed" must not move the time it is
        // compared with, or this sighting wouldn't count as a regression.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        let resp = b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        let h = s
            .record(&Capture::new(
                "send",
                &target,
                b"GET /x HTTP/1.1\r\nHost: app.test\r\n\r\n",
                Some(resp),
                None,
                None,
            ))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        s.findings_mark(&[id], Some("fixed"), Some("checked"), None).unwrap();
        let f = s.finding_get(id).unwrap();
        assert_eq!((f["state_changed_at"].clone(), f["note"].as_str()), (marked, Some("checked")));
        crate::scan::passive::scan_pending(&mut s).unwrap();
        assert_eq!(s.finding_get(id).unwrap()["state"], "open");
        assert_eq!(s.finding_events(id).unwrap().last().unwrap()["history_id"], h);
        let kinds: Vec<String> =
            s.finding_events(id).unwrap().iter().map(|e| e["kind"].as_str().unwrap().into()).collect();
        assert_eq!(kinds, ["created", "state", "note", "regressed"]);
        // The scanner reopened it, whoever started the process that scanned.
        let f = s.finding_get(id).unwrap();
        assert_eq!(f["state_origin"], crate::provenance::SCANNER, "{f}");
        let last = s.finding_events(id).unwrap().pop().unwrap();
        assert_eq!((last["origin"].as_str(), last["by"].as_str()), (Some("scanner"), Some("by the scanner")));
    }

    #[test]
    fn a_sighting_raises_the_risk_a_rescan_rates_it_afresh_and_both_say_so() {
        let mut s = Store::open_in_memory().unwrap();
        let h = seen_at(&mut s, "/x");
        let id = xpb(&s)[0]["id"].as_i64().unwrap();
        let msg = s.scan_messages_after(h - 1, &["send".to_string()], 1).unwrap().remove(0);
        let def = crate::scan::passive::scan_message(&msg, &Default::default())
            .into_iter()
            .find(|f| f.def.alert_ref == "10037")
            .unwrap();
        let rated = |risk| Finding { risk, ..def.clone() };
        // A higher rating raises it; two in one response are one sighting, at the higher.
        s.record_findings("passive", &msg, &[rated(Risk::Low), rated(Risk::High)]).unwrap();
        assert_eq!(s.finding_get(id).unwrap()["risk"], "high");
        // A lower one between rescans doesn't lower it: the same URL may be rated both ways.
        s.record_findings("passive", &msg, &[rated(Risk::Low)]).unwrap();
        assert_eq!(s.finding_get(id).unwrap()["risk"], "high");
        // A rescan counts afresh, so its first sighting sets the risk (a fixed rule lowers it),
        // and later ones raise it again.
        s.findings_rescan_start("passive", &[]).unwrap();
        s.record_findings("passive", &msg, &[rated(Risk::Low)]).unwrap();
        assert_eq!(s.finding_get(id).unwrap()["risk_level"], 1);
        s.record_findings("passive", &msg, &[rated(Risk::Info)]).unwrap();
        s.record_findings("passive", &msg, &[rated(Risk::Medium)]).unwrap();
        let risk: Vec<(String, String)> = s
            .finding_events(id)
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "risk")
            .map(|e| (e["old"].as_str().unwrap().into(), e["new"].as_str().unwrap().into()))
            .collect();
        assert_eq!(
            risk,
            [("low".into(), "high".into()), ("high".into(), "low".into()), ("low".into(), "medium".into())]
        );
        // The scanner's own record isn't triage: a rescan that doesn't find it removes it.
        s.findings_rescan_start("passive", &[]).unwrap();
        s.findings_rescan_finish("passive", &[]).unwrap();
        assert!(matches!(s.finding_get(id), Err(Error::NotFound(_))));
    }

    #[test]
    fn only_a_finding_added_by_hand_is_edited_and_its_links_are_kept_in_order() {
        let mut s = Store::open_in_memory().unwrap();
        seen_at(&mut s, "/a");
        let scanner = xpb(&s)[0]["id"].as_i64().unwrap();
        let e = s.finding_edit(scanner, &FindingEdit { risk: Some(Risk::High), ..Default::default() }).unwrap_err();
        assert!(matches!(e, Error::InvalidInput(ref m) if m.contains("passive scanner")), "{e}");
        assert_eq!(s.finding_get(scanner).unwrap()["risk"], "low");

        // More entries than the row holds go in meta; back to two, the list there goes.
        let hs: Vec<i64> = ["/b", "/c", "/d"].iter().map(|p| seen_at(&mut s, p)).collect();
        let id = s.finding_add(&manual("Leak", Some("http://app.test/x"), vec![])).unwrap();
        let rev = manual_revision(&s.conn, id).unwrap().unwrap();
        let edit = FindingEdit { history: Some(hs.clone()), if_revision: Some(rev.clone()), ..Default::default() };
        let done = s.finding_edit(id, &edit).unwrap();
        assert_eq!(done.changed, ["history_ids"]);
        assert_eq!(s.finding_history_ids(id).unwrap(), hs);
        assert_eq!(done.revision, manual_revision(&s.conn, id).unwrap().unwrap());
        s.finding_edit(id, &FindingEdit { history: Some(hs[..2].to_vec()), ..Default::default() }).unwrap();
        assert_eq!(s.finding_history_ids(id).unwrap(), hs[..2]);
        assert!(s.meta_get(&history_key(id)).unwrap().is_none());
        let stale = FindingEdit { risk: Some(Risk::Low), if_revision: Some(rev), ..Default::default() };
        assert!(matches!(s.finding_edit(id, &stale), Err(Error::Conflict(_))));

        // Joining a title whose findings have a write-up takes theirs; its own stays with its old title.
        let theirs =
            ManualFinding { description: "Theirs.".into(), ..manual("Other", Some("http://app.test/y"), vec![]) };
        s.finding_add(&theirs).unwrap();
        s.finding_edit(id, &FindingEdit { description: Some("Mine.".into()), ..Default::default() }).unwrap();
        let done = s.finding_edit(id, &FindingEdit { title: Some("other".into()), ..Default::default() }).unwrap();
        assert_eq!(done.changed, ["title", "description"]);
        let f = s.finding_get(id).unwrap();
        assert_eq!((f["alert_ref"].as_str(), f["description"].as_str()), (Some("manual:other"), Some("Theirs.")));
        let leak: String = s
            .conn
            .query_row("SELECT description FROM finding_types WHERE alert_ref = 'manual:leak'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(leak, "Mine.");
        // The same finding as the one it now shares a title with is refused.
        let same = FindingEdit { url: Some("http://app.test/y".into()), ..Default::default() };
        assert!(matches!(s.finding_edit(id, &same), Err(Error::Conflict(_))));
    }

    #[test]
    fn a_finding_is_shown_with_the_revision_of_what_it_shows() {
        let dir = std::env::temp_dir().join(format!("bp-findings-rev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.bpdb");
        let mut reader = Store::create(&path).unwrap();
        let id = reader.finding_add(&manual("Leak", Some("http://app.test/x"), vec![])).unwrap();
        let before = manual_revision(&reader.conn, id).unwrap().unwrap();
        // Another process edits the finding while it is being read: once the first statement has
        // its snapshot (its first instructions open the read), and before the read ends.
        let mut writer = std::panic::AssertUnwindSafe(Some(Store::open(&path).unwrap()));
        let mut steps = 0;
        reader
            .conn
            .progress_handler(
                1,
                Some(move || {
                    steps += 1;
                    if steps < 20 {
                        return false;
                    }
                    if let Some(mut w) = writer.take() {
                        let edit = FindingEdit { evidence: Some("changed".into()), ..Default::default() };
                        w.finding_edit(id, &edit).unwrap();
                    }
                    false
                }),
            )
            .unwrap();
        let shown = reader.finding_get(id).unwrap();
        reader.conn.progress_handler(1, None::<fn() -> bool>).unwrap();
        let after = manual_revision(&reader.conn, id).unwrap().unwrap();
        assert_ne!(before, after, "the edit happened");
        // Whichever version it showed, its revision is that version's.
        let want = if shown["evidence"] == "changed" { &after } else { &before };
        assert_eq!(shown["revision"].as_str(), Some(want.as_str()), "{shown}");
        drop(reader);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
