//! Findings storage. Repeated instances of the same issue (same alert, method, URL
//! without its query, and parameter) are folded into one row with a hit count, so a
//! missing header seen 500 times on a page is one finding, and a response with two
//! versioned Server headers is one finding, not two. The first evidence is kept.

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
    ("risk", "TEXT", "info, low, medium, high"),
    ("risk_level", "INTEGER", "0 info, 1 low, 2 medium, 3 high (for sorting/filtering)"),
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
    ("history_id", "INTEGER", "history.id where first seen"),
    ("last_history_id", "INTEGER", "history.id where last seen"),
    ("hits", "INTEGER", "Times seen (same alert, method, URL without query, param)"),
    ("state", "TEXT", "open, confirmed, false_positive"),
    ("note", "TEXT", "Free-text note"),
];

/// What makes two findings the same issue. The URL keeps scheme, host and port (two
/// services on one host are different findings) and drops the query (parameters are `param`).
pub(crate) fn dedupe_key(alert_ref: &str, method: &str, url: &str, param: &str) -> String {
    let base = url.split('?').next().unwrap_or(url);
    format!("{alert_ref}|{method}|{base}|{param}")
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
            let key = dedupe_key(
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

impl Store {
    /// Captures after `after_id` from the given sources, ready for scanning.
    pub fn scan_messages_after(&self, after_id: i64, sources: &[String], limit: usize) -> Result<Vec<Message>> {
        let placeholders = (0..sources.len()).map(|i| format!("?{}", i + 3)).collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT id, method, url, scheme, host, port, path, query, req_headers, req_body, status, resp_headers, resp_body
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
            ))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Highest history id, used to skip scanning when nothing is new.
    pub fn max_history_id(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT coalesce(max(id), 0) FROM history", [], |r| r.get(0))?)
    }

    /// Stores findings for one message; returns how many were new.
    pub fn record_findings(&mut self, source: &str, msg: &Message, findings: &[Finding]) -> Result<usize> {
        if findings.is_empty() {
            return Ok(0);
        }
        let tx = self.write_tx()?;
        let mut new = 0;
        {
            let mut types = tx.prepare_cached(
                "INSERT OR IGNORE INTO finding_types (alert_ref, rule_id, name, description, solution, refs, tags)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            let mut insert = tx.prepare_cached(
                "INSERT INTO findings (source, rule_id, alert_ref, name, risk, risk_level, confidence, cwe, wasc, host,
                    method, url, param, evidence, other_info, history_id, last_history_id, dedupe, attack)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16, ?17, ?18)
                 ON CONFLICT(dedupe) DO UPDATE SET hits = hits + 1, last_history_id = excluded.last_history_id
                 RETURNING hits",
            )?;
            for f in findings {
                let d = f.def;
                let rule_id: u32 = d.alert_ref.split('-').next().and_then(|s| s.parse().ok()).unwrap_or(0);
                types.execute(params![
                    d.alert_ref,
                    rule_id,
                    d.name,
                    d.description,
                    d.solution,
                    serde_json::to_string(d.references).unwrap_or_default(),
                    serde_json::to_string(d.tags).unwrap_or_default(),
                ])?;
                let dedupe = dedupe_key(d.alert_ref, &msg.method, &msg.url, &f.param);
                let hits: i64 = insert.query_row(
                    params![
                        source,
                        rule_id,
                        d.alert_ref,
                        d.name,
                        f.risk.as_str(),
                        f.risk.level(),
                        f.confidence.as_str(),
                        d.cwe,
                        d.wasc,
                        msg.host,
                        msg.method,
                        msg.url,
                        f.param,
                        truncate(&f.evidence, 2000),
                        truncate(&f.other_info, 4000),
                        msg.history_id,
                        dedupe,
                        truncate(&f.attack, 2000),
                    ],
                    |r| r.get(0),
                )?;
                if hits == 1 {
                    new += 1;
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
            "SELECT alert_ref, name, risk, max(risk_level) AS risk_level, count(*) AS instances, sum(hits) AS hits,
                count(DISTINCT host) AS hosts, min(id) AS first_id,
                json_group_array(json_object('id', id, 'url', url, 'param', param, 'evidence', substr(evidence, 1, 200)))
                    AS examples
             FROM findings WHERE {where_sql} GROUP BY alert_ref ORDER BY risk_level DESC, instances DESC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            let examples: String = r.get(8)?;
            let mut ex: Vec<Value> = serde_json::from_str(&examples).unwrap_or_default();
            let total = ex.len();
            ex.truncate(filter.examples);
            Ok(json!({
                "alert_ref": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                "risk": r.get::<_, String>(2)?,
                "instances": r.get::<_, i64>(4)?,
                "hits": r.get::<_, i64>(5)?,
                "hosts": r.get::<_, i64>(6)?,
                "examples": ex,
                "more_examples": total.saturating_sub(filter.examples),
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Individual findings (one row per instance).
    pub fn findings_list(&self, filter: &FindingFilter, limit: usize) -> Result<Vec<Value>> {
        let (where_sql, args) = filter.sql();
        let sql = format!(
            "SELECT id, alert_ref, name, risk, confidence, host, method, url, param, substr(evidence, 1, 300),
                hits, history_id, state, source
             FROM findings WHERE {where_sql} ORDER BY risk_level DESC, id LIMIT {limit}"
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
                "source": r.get::<_, String>(13)?,
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// One finding with its alert type's description, solution, and references.
    pub fn finding_get(&self, id: i64) -> Result<Value> {
        let r = self.query(
            "SELECT f.*, t.description, t.solution, json(t.refs) AS refs, json(t.tags) AS tags
             FROM findings f LEFT JOIN finding_types t ON t.alert_ref = f.alert_ref WHERE f.id = ?1",
            &[id.to_string()],
            1,
            100_000,
        )?;
        let row = r.rows.into_iter().next().ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
        let mut obj: serde_json::Map<String, Value> = r.columns.into_iter().zip(row).collect();
        obj.remove("dedupe");
        for k in ["refs", "tags"] {
            if let Some(Value::String(s)) = obj.get(k) {
                let v = serde_json::from_str(s).unwrap_or(Value::Null);
                obj.insert(k.into(), v);
            }
        }
        if obj.get("source").and_then(Value::as_str) == Some(MANUAL_SOURCE) {
            obj.insert("history_ids".into(), json!(self.finding_history_ids(id)?));
        }
        Ok(Value::Object(obj))
    }

    /// Sets a finding's triage state and/or note.
    pub fn finding_mark(&self, id: i64, state: Option<&str>, note: Option<&str>) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE findings SET state = COALESCE(?1, state), note = COALESCE(?2, note) WHERE id = ?3",
            params![state, note, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("finding {id}")));
        }
        Ok(())
    }

    /// Removes passive findings and resets the scan watermark, for a full rescan.
    pub fn findings_reset(&self, source: &str) -> Result<usize> {
        Ok(self.conn.execute("DELETE FROM findings WHERE source = ?1", [source])?)
    }

    /// Records a finding a person found by hand; returns its id. Nothing is sent. Findings with
    /// the same title share an alert type (`manual:<title>`), which holds the description and
    /// solution: one given here replaces the type's, one left out keeps it.
    pub fn finding_add(&mut self, f: &ManualFinding) -> Result<i64> {
        let title = f.title.trim();
        if title.is_empty() || title.len() > MANUAL_TITLE_MAX {
            return Err(Error::InvalidInput(format!("the title must be 1 to {MANUAL_TITLE_MAX} bytes")));
        }
        let alert_ref = manual_alert_ref(title)?;
        for (what, text, max) in [
            ("evidence", &f.evidence, MANUAL_EVIDENCE_MAX),
            ("parameter", &f.param, MANUAL_EVIDENCE_MAX),
            ("description", &f.description, MANUAL_TEXT_MAX),
            ("solution", &f.solution, MANUAL_TEXT_MAX),
        ] {
            if text.len() > max {
                return Err(Error::InvalidInput(format!("the {what} is over {max} bytes")));
            }
        }
        if f.history.len() > MANUAL_HISTORY_MAX {
            return Err(Error::InvalidInput(format!("link at most {MANUAL_HISTORY_MAX} history entries")));
        }
        let mut history: Vec<i64> = Vec::new();
        for &id in &f.history {
            if !history.contains(&id) {
                history.push(id);
            }
        }
        let tx = self.write_tx()?;
        // The linked entries must exist; the first gives the URL and method when none are given.
        let mut first: Option<(String, String)> = None;
        for &id in &history {
            let row: Option<(String, String)> = tx
                .query_row("SELECT method, url FROM history WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            match row {
                Some(r) => {
                    first.get_or_insert(r);
                }
                None => return Err(Error::NotFound(format!("history entry {id}"))),
            }
        }
        let url = match (&f.url, &first) {
            (Some(u), _) => u.trim().to_string(),
            (None, Some((_, u))) => u.clone(),
            (None, None) => return Err(Error::InvalidInput("give --url or --history-id".into())),
        };
        let parsed = manual_url(&url)?;
        let method = match (&f.method, &first) {
            (Some(m), _) => m.trim().to_ascii_uppercase(),
            (None, Some((m, _))) => m.clone(),
            (None, None) => "GET".to_string(),
        };
        if method.is_empty()
            || method.len() > 32
            || !method.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::InvalidInput(format!("{method:?} is not an HTTP method")));
        }
        let url = parsed.to_string();
        let host = parsed.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']').to_string();
        let dedupe = dedupe_key(&alert_ref, &method, &url, &f.param);
        if let Some(id) =
            tx.query_row("SELECT id FROM findings WHERE dedupe = ?1", [&dedupe], |r| r.get::<_, i64>(0)).optional()?
        {
            return Err(Error::Conflict(format!(
                "finding {id} is already this issue (same title, method, URL without its query, and parameter)"
            )));
        }
        tx.execute(
            "INSERT INTO finding_types (alert_ref, rule_id, name, description, solution, refs, tags)
             VALUES (?1, 0, ?2, ?3, ?4, '[]', '[\"manual\"]')
             ON CONFLICT(alert_ref) DO UPDATE SET
                description = CASE WHEN excluded.description != '' THEN excluded.description ELSE description END,
                solution = CASE WHEN excluded.solution != '' THEN excluded.solution ELSE solution END",
            params![alert_ref, title, f.description.trim(), f.solution.trim()],
        )?;
        tx.execute(
            "INSERT INTO findings (source, rule_id, alert_ref, name, risk, risk_level, confidence, cwe, host,
                method, url, param, evidence, history_id, last_history_id, dedupe)
             VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
            ],
        )?;
        let id = tx.last_insert_rowid();
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

    /// Removes findings added by hand; scanner findings are refused (mark them instead), and
    /// nothing is removed unless every id can be. Returns how many were removed.
    pub fn findings_remove(&mut self, ids: &[i64]) -> Result<usize> {
        let tx = self.write_tx()?;
        for &id in ids {
            let source: Option<String> =
                tx.query_row("SELECT source FROM findings WHERE id = ?1", [id], |r| r.get(0)).optional()?;
            match source.as_deref() {
                None => return Err(Error::NotFound(format!("finding {id}"))),
                Some(MANUAL_SOURCE) => {}
                Some(s) => {
                    return Err(Error::InvalidInput(format!(
                        "finding {id} came from the {s} scanner; only findings added by hand can be removed \
                         (mark it false_positive instead)"
                    )))
                }
            }
        }
        let mut removed = 0;
        for &id in ids {
            removed += tx.execute("DELETE FROM findings WHERE id = ?1", [id])?;
            tx.execute("DELETE FROM meta WHERE key = ?1", [history_key(id)])?;
        }
        tx.execute(
            "DELETE FROM finding_types WHERE alert_ref LIKE 'manual:%'
                AND alert_ref NOT IN (SELECT alert_ref FROM findings)",
            [],
        )?;
        tx.commit()?;
        Ok(removed)
    }

    /// The history entries a finding added by hand links to, in the order given.
    pub fn finding_history_ids(&self, id: i64) -> Result<Vec<i64>> {
        if let Some(list) = self.meta_get(&history_key(id))? {
            return Ok(serde_json::from_str(&list).unwrap_or_default());
        }
        let (first, last): (Option<i64>, Option<i64>) = self
            .conn
            .query_row("SELECT history_id, last_history_id FROM findings WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?
            .unwrap_or_default();
        let mut ids: Vec<i64> = first.into_iter().collect();
        ids.extend(last.filter(|l| Some(*l) != first));
        Ok(ids)
    }
}

/// `findings.source` of a finding added by hand.
pub const MANUAL_SOURCE: &str = "manual";
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
}

fn history_key(id: i64) -> String {
    format!("finding.{id}.history")
}

/// `manual:` and the title in lower case, words joined by `-`, so findings with the same
/// title group together and never share a type with a scanner's.
pub(crate) fn manual_alert_ref(title: &str) -> Result<String> {
    let mut slug = String::new();
    for c in title.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            slug.push(c);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
        if slug.chars().count() >= 64 {
            break;
        }
    }
    let slug = slug.trim_end_matches('-');
    if slug.is_empty() {
        return Err(Error::InvalidInput("the title needs at least one letter or digit".into()));
    }
    Ok(format!("manual:{slug}"))
}

/// An absolute http(s) or ws(s) URL with a host.
fn manual_url(url: &str) -> Result<url::Url> {
    let bad = || Error::InvalidInput(format!("{url:?} is not an http(s) or ws(s) URL with a host"));
    let parsed = url::Url::parse(url).map_err(|_| bad())?;
    if !matches!(parsed.scheme(), "http" | "https" | "ws" | "wss") || parsed.host_str().is_none_or(str::is_empty) {
        return Err(bad());
    }
    Ok(parsed)
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
            // `mark` takes false-positive and stores false_positive; accept either spelling.
            Some(s) => clauses.push(format!("state = {}", bind(&mut args, s.replace('-', "_")))),
            None => clauses.push("state != 'false_positive'".into()),
        }
        if let Some(s) = &self.source {
            clauses.push(format!("source = {}", bind(&mut args, s.clone())));
        }
        if let Some(ids) = &self.ids {
            let list = serde_json::to_string(ids).unwrap_or_default();
            clauses.push(format!("id IN (SELECT value FROM json_each({}))", bind(&mut args, list)));
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
        assert_eq!(manual_alert_ref(&"a".repeat(500)).unwrap().len(), "manual:".len() + 64);
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
        // Another URL with the same title joins the type; a new description replaces its text,
        // none keeps it.
        let other = s.finding_add(&manual("Order IDOR", Some("https://app.test/orders/8"), vec![])).unwrap();
        assert_eq!(s.finding_get(other).unwrap()["description"], "Read anyone's order.");
        assert_eq!(s.finding_get(other).unwrap()["method"], "GET");
        let mut f = manual("Order IDOR", Some("https://app.test/orders/9"), vec![]);
        f.description = "Newer text.".into();
        s.finding_add(&f).unwrap();
        assert_eq!(s.finding_get(id).unwrap()["description"], "Newer text.");
        let groups =
            s.findings_grouped(&FindingFilter { source: Some("manual".into()), ..Default::default() }).unwrap();
        assert_eq!((groups.len(), groups[0]["instances"].as_i64()), (1, Some(3)));
        // Marked like any other.
        s.finding_mark(id, Some("confirmed"), Some("checked")).unwrap();
        assert_eq!(s.finding_get(id).unwrap()["state"], "confirmed");
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
        assert_eq!(s.findings_remove(&[id]).unwrap(), 1);
        assert_eq!(s.meta_get(&history_key(id)).unwrap(), None);
        let types = |s: &Store| s.query("SELECT alert_ref FROM finding_types", &[], 10, 100).unwrap().rows.len();
        assert_eq!(types(&s), 1);
        s.findings_remove(&[two]).unwrap();
        assert_eq!(types(&s), 0);
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
    fn a_refused_duplicate_changes_nothing() {
        let (mut s, _) = store();
        let mut f = manual("Order IDOR", Some("https://app.test/orders/7"), vec![]);
        f.description = "First.".into();
        let id = s.finding_add(&f).unwrap();
        f.description = "Second.".into();
        f.url = Some("https://app.test/orders/7?other=1".into());
        assert!(matches!(s.finding_add(&f), Err(Error::Conflict(_))));
        assert_eq!(s.finding_get(id).unwrap()["description"], "First.");
        // Another parameter or method is another issue.
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
        s.findings_reset("passive").unwrap();
        crate::scan::passive::scan_pending(&mut s).unwrap();
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
        assert!(matches!(s.finding_get(id), Err(Error::NotFound(_))));
        assert!(matches!(s.findings_remove(&[id]), Err(Error::NotFound(_))));
    }
}
