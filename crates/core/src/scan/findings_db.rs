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
    ("history_id", "INTEGER", "history.id where first seen (source manual: the first linked entry)"),
    (
        "last_history_id",
        "INTEGER",
        "history.id where last seen (source manual: the last linked entry; `findings show` lists them all in history_ids)",
    ),
    (
        "hits",
        "INTEGER",
        "Times seen (same alert, method, URL without query, param); 0 for a triaged passive finding that \
         `scan passive --rescan` didn't find again (kept so its triage isn't lost)",
    ),
    (
        "state",
        "TEXT",
        "open, confirmed, false_positive, or removed (source manual, by `findings remove`; hidden unless --state all)",
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
        "gui, cli or mcp: who last changed state with `findings mark` (or `findings remove`); NULL if never changed",
    ),
    ("state_changed_at", "TEXT", "UTC time of the last state change; NULL if never changed"),
    ("note_origin", "TEXT", "gui, cli or mcp: who last set the note with `findings mark --note`; NULL if never set"),
    ("note_changed_at", "TEXT", "UTC time the note was last set"),
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
                    method, url, param, evidence, other_info, history_id, last_history_id, dedupe, attack, origin)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16, ?17, ?18, ?19)
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
                        crate::provenance::origin(),
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
                    AS examples,
                group_concat(DISTINCT source) AS sources
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
                // One source, or several joined by commas when scanners share an alert type.
                "source": r.get::<_, String>(9)?,
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
                hits, history_id, state, origin, state_origin, state_changed_at, note_origin, note_changed_at, source
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
                "origin": r.get::<_, Option<String>>(13)?,
                "state_origin": r.get::<_, Option<String>>(14)?,
                "state_changed_at": r.get::<_, Option<String>>(15)?,
                "note_origin": r.get::<_, Option<String>>(16)?,
                "note_changed_at": r.get::<_, Option<String>>(17)?,
                "source": r.get::<_, String>(18)?,
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
        let n = self.conn.execute(
            "UPDATE findings SET state = COALESCE(?1, state), note = COALESCE(?2, note),
                state_origin = CASE WHEN ?1 IS NULL THEN state_origin ELSE ?4 END,
                state_changed_at = CASE WHEN ?1 IS NULL THEN state_changed_at
                    ELSE strftime('%Y-%m-%dT%H:%M:%fZ','now') END,
                note_origin = CASE WHEN ?2 IS NULL THEN note_origin ELSE ?4 END,
                note_changed_at = CASE WHEN ?2 IS NULL THEN note_changed_at
                    ELSE strftime('%Y-%m-%dT%H:%M:%fZ','now') END
             WHERE id = ?3 AND state != 'removed'",
            params![state, note, id, crate::provenance::origin()],
        )?;
        if n == 0 {
            let exists = self.conn.query_row("SELECT 1 FROM findings WHERE id = ?1", [id], |_| Ok(())).optional()?;
            return Err(match exists {
                Some(()) => Error::Conflict(format!("finding {id} was removed; add it again to record it")),
                None => Error::NotFound(format!("finding {id}")),
            });
        }
        Ok(())
    }

    /// Starts a full rescan of `source` findings: their hit counts go to 0, to be counted again,
    /// and nothing else changes, so a finding found again keeps its id, state, note and who
    /// set them. Returns the highest finding id, to tell new findings from the ones found again.
    pub(crate) fn findings_rescan_start(&mut self, source: &str) -> Result<i64> {
        let tx = self.write_tx()?;
        tx.execute("UPDATE findings SET hits = 0 WHERE source = ?1", [source])?;
        let max: i64 = tx.query_row("SELECT coalesce(max(id), 0) FROM findings", [], |r| r.get(0))?;
        tx.commit()?;
        Ok(max)
    }

    /// Ends a rescan: a finding it didn't find again goes, unless someone triaged it (changed
    /// its state or wrote a note). That one stays with 0 hits, so a person's decision isn't lost
    /// to a rescan an agent ran. Returns (removed, kept).
    pub(crate) fn findings_rescan_finish(&mut self, source: &str) -> Result<(usize, usize)> {
        let tx = self.write_tx()?;
        let triaged = "(state != 'open' OR note IS NOT NULL OR state_origin IS NOT NULL)";
        let removed =
            tx.execute(&format!("DELETE FROM findings WHERE source = ?1 AND hits = 0 AND NOT {triaged}"), [source])?;
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
        let (parsed, url) = manual_url(&url)?;
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
        let host = parsed.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']').to_string();
        let dedupe = dedupe_key(&alert_ref, &method, &url, &f.param);
        if let Some(id) =
            tx.query_row("SELECT id FROM findings WHERE dedupe = ?1", [&dedupe], |r| r.get::<_, i64>(0)).optional()?
        {
            return Err(Error::Conflict(format!(
                "finding {id} is already this issue (same title, method, URL without its query, and parameter)"
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
            // The text it replaces is kept, with when it was replaced.
            let key = replaced_texts_key(&alert_ref);
            let earlier: Option<String> =
                tx.query_row("SELECT value FROM meta WHERE key = ?1", [&key], |r| r.get(0)).optional()?;
            let mut list: Vec<Value> = earlier.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
            let (description, solution, time): (String, String, String) = tx.query_row(
                "SELECT description, solution, strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM finding_types
                 WHERE alert_ref = ?1",
                [&alert_ref],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            list.push(json!({"time": time, "description": description, "solution": solution}));
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, Value::Array(list).to_string()],
            )?;
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
                    state_origin = ?3, state_changed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE id = ?2",
                params![REMOVED, id, origin],
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

fn history_key(id: i64) -> String {
    format!("finding.{id}.history")
}

/// When a finding was removed, and the triage state it had.
fn removed_key(id: i64) -> String {
    format!("finding.{id}.removed")
}

/// The descriptions and solutions an alert type of findings added by hand had before they were replaced.
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
            None => clauses.push("state NOT IN ('false_positive', 'removed')".into()),
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
}
