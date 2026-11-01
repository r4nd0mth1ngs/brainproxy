//! Findings storage. Repeated instances of the same issue (same alert, method, URL
//! without its query, and parameter) are folded into one row with a hit count, so a
//! missing header seen 500 times on a page is one finding, and a response with two
//! versioned Server headers is one finding, not two. The first evidence is kept.

use rusqlite::params;
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
    ("source", "TEXT", "passive, active, or authz"),
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
                hits, history_id, state
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
        (clauses.join(" AND "), args)
    }
}
