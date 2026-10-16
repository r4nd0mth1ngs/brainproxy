//! Capture store: one SQLite file per project. Every request brainproxy sends or
//! proxies is stored raw and pre-parsed into plain columns, so it can be searched
//! with ordinary SQL (`brainproxy query`). Opening a missing project creates it.

use std::path::Path;
use std::sync::Arc;

use regex::Regex;
use rusqlite::functions::FunctionFlags;
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};

use crate::capture::Capture;
use crate::error::{Error, Result};
use crate::http::{Exchange, Target};

const SCHEMA_VERSION: i64 = 6;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    source TEXT NOT NULL,
    scheme TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    req_headers TEXT NOT NULL,
    req_content_type TEXT,
    req_body BLOB NOT NULL,
    req_body_text TEXT,
    status INTEGER,
    reason TEXT,
    resp_headers TEXT,
    resp_content_type TEXT,
    resp_body BLOB,
    resp_body_text TEXT,
    resp_body_length INTEGER,
    title TEXT,
    duration_ms INTEGER,
    error TEXT,
    note TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    request BLOB NOT NULL,
    response BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS history_host ON history(host);
CREATE INDEX IF NOT EXISTS history_status ON history(status);
CREATE INDEX IF NOT EXISTS history_path ON history(path);

CREATE VIRTUAL TABLE IF NOT EXISTS history_fts USING fts5(
    url, req_headers, req_body_text, resp_headers, resp_body_text,
    content='history', content_rowid='id', tokenize=\"unicode61 tokenchars '_'\"
);
CREATE TRIGGER IF NOT EXISTS history_ai AFTER INSERT ON history BEGIN
    INSERT INTO history_fts(rowid, url, req_headers, req_body_text, resp_headers, resp_body_text)
    VALUES (new.id, new.url, new.req_headers, new.req_body_text, new.resp_headers, new.resp_body_text);
END;
CREATE TRIGGER IF NOT EXISTS history_ad AFTER DELETE ON history BEGIN
    INSERT INTO history_fts(history_fts, rowid, url, req_headers, req_body_text, resp_headers, resp_body_text)
    VALUES ('delete', old.id, old.url, old.req_headers, old.req_body_text, old.resp_headers, old.resp_body_text);
END;

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

const SCHEMA_V2: &str = "
CREATE TABLE IF NOT EXISTS intercepts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    direction TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    status INTEGER,
    original BLOB NOT NULL,
    edited BLOB,
    resolved_time TEXT
);
CREATE INDEX IF NOT EXISTS intercepts_state ON intercepts(state);
";

const SCHEMA_V3: &str = "
CREATE TABLE IF NOT EXISTS fuzz_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    state TEXT NOT NULL,
    mode TEXT NOT NULL,
    target TEXT NOT NULL,
    positions INTEGER NOT NULL,
    total INTEGER NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    matched INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    config TEXT NOT NULL,
    template BLOB NOT NULL,
    pid INTEGER,
    finished_time TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS fuzz_results (
    run_id INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    position INTEGER,
    payloads TEXT NOT NULL,
    history_id INTEGER,
    status INTEGER,
    length INTEGER,
    words INTEGER,
    lines INTEGER,
    duration_ms INTEGER,
    matched INTEGER NOT NULL DEFAULT 0,
    grep TEXT,
    extract TEXT,
    error TEXT,
    PRIMARY KEY (run_id, idx)
) WITHOUT ROWID;
";

pub const FUZZ_RUN_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Run id"),
    ("time", "TEXT", "UTC start time"),
    ("state", "TEXT", "queued, running, stopping, completed, stopped, failed"),
    ("mode", "TEXT", "sniper, battering-ram, pitchfork, cluster-bomb"),
    ("target", "TEXT", "Origin requests were sent to"),
    ("positions", "INTEGER", "Number of payload positions in the template"),
    ("total", "INTEGER", "Requests planned"),
    ("done", "INTEGER", "Requests finished so far"),
    ("matched", "INTEGER", "Results that matched --grep or --match-status"),
    ("errors", "INTEGER", "Requests that got no response"),
    ("config", "TEXT", "Run settings as JSON"),
    ("template", "BLOB", "Request template with payload markers"),
];

pub const FUZZ_RESULT_COLUMNS: &[(&str, &str, &str)] = &[
    ("run_id", "INTEGER", "fuzz_runs.id"),
    ("idx", "INTEGER", "Request number within the run, from 0"),
    ("position", "INTEGER", "Attacked position (sniper only), from 0"),
    ("payloads", "TEXT", "JSON array of the payloads used; json_extract(payloads, '$[0]')"),
    ("history_id", "INTEGER", "history.id of the stored exchange (NULL if not stored)"),
    ("status", "INTEGER", "Response status"),
    ("length", "INTEGER", "Decoded response body length"),
    ("words", "INTEGER", "Words in the response body"),
    ("lines", "INTEGER", "Lines in the response body"),
    ("duration_ms", "INTEGER", "Response time"),
    ("matched", "INTEGER", "1 if a --grep pattern or --match-status matched"),
    ("grep", "TEXT", "JSON array of grep patterns that matched"),
    ("extract", "TEXT", "Value captured by --extract"),
    ("error", "TEXT", "Error if no response was received"),
];

/// Column documentation for the intercept queue.
pub const INTERCEPT_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Intercept id"),
    ("time", "TEXT", "UTC time the message was held"),
    ("direction", "TEXT", "request or response"),
    ("state", "TEXT", "pending, forwarded, dropped, or expired (timed out)"),
    ("method", "TEXT", "Request method"),
    ("url", "TEXT", "Request URL"),
    ("status", "INTEGER", "Response status (response direction only)"),
    ("original", "BLOB", "The message as held"),
    ("edited", "BLOB", "Replacement message, if one was forwarded"),
    ("resolved_time", "TEXT", "When it was forwarded, dropped, or expired"),
];

/// Column documentation, served by `brainproxy schema` so an agent can write SQL
/// without guessing.
pub const HISTORY_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Capture id, increasing"),
    ("time", "TEXT", "UTC ISO-8601 time the capture was recorded"),
    ("source", "TEXT", "Tool that produced it: send, proxy, fuzz, scan, crawl"),
    ("scheme", "TEXT", "http or https"),
    ("host", "TEXT", "Target host name or IP"),
    ("port", "INTEGER", "Target port"),
    ("method", "TEXT", "HTTP method"),
    ("url", "TEXT", "Full URL including query string"),
    ("path", "TEXT", "URL path without query string"),
    ("query", "TEXT", "Raw query string without '?', or NULL"),
    ("req_headers", "TEXT", "Request headers as JSON [[name, value], ...]; use header(req_headers, 'name')"),
    ("req_content_type", "TEXT", "Request Content-Type, or NULL"),
    ("req_body", "BLOB", "Request body (chunking and compression removed)"),
    ("req_body_text", "TEXT", "Request body as text if valid UTF-8, else NULL"),
    ("status", "INTEGER", "Response status code; NULL if the request failed"),
    ("reason", "TEXT", "Response reason phrase"),
    ("resp_headers", "TEXT", "Response headers as JSON [[name, value], ...]; use header(resp_headers, 'name')"),
    ("resp_content_type", "TEXT", "Response Content-Type, or NULL"),
    ("resp_body", "BLOB", "Response body (chunking and gzip/deflate/br removed)"),
    ("resp_body_text", "TEXT", "Response body as text if valid UTF-8, else NULL"),
    ("resp_body_length", "INTEGER", "Length of the decoded response body"),
    ("title", "TEXT", "HTML <title>, if any"),
    ("duration_ms", "INTEGER", "Round-trip time"),
    ("error", "TEXT", "Error message when no response was received"),
    ("note", "TEXT", "Free-text note (set with `history note`)"),
    ("tags", "TEXT", "JSON array of tags (set with `history tag`)"),
    ("request", "BLOB", "Raw request bytes exactly as sent"),
    ("response", "BLOB", "Raw response bytes exactly as received"),
];

pub const FUNCTIONS: &[(&str, &str)] = &[
    ("header(headers_json, name)", "First value of a header, case-insensitive. NULL if absent."),
    ("regexp(pattern, text) / text REGEXP pattern", "Rust regex match. Prefix pattern with (?i) for case-insensitive."),
    ("regexp_extract(text, pattern[, group])", "First match (or capture group) of a regex, else NULL."),
    ("json_extract / json_each", "SQLite JSON functions; work on *_headers and JSON bodies."),
];

pub const EXAMPLES: &[(&str, &str)] = &[
    ("Server errors", "SELECT id, method, url, status FROM history WHERE status >= 500"),
    ("Endpoints seen", "SELECT DISTINCT method, host, path FROM history ORDER BY host, path"),
    ("Full-text search", "SELECT id, url FROM history WHERE id IN (SELECT rowid FROM history_fts WHERE history_fts MATCH 'password OR secret')"),
    ("Regex over bodies", "SELECT id, url FROM history WHERE resp_body_text REGEXP '(?i)sql syntax|ORA-[0-9]{5}'"),
    ("Header lookup", "SELECT id, url, header(resp_headers, 'server') AS server FROM history WHERE server IS NOT NULL"),
    ("Missing security header", "SELECT id, url FROM history WHERE resp_content_type LIKE 'text/html%' AND header(resp_headers, 'content-security-policy') IS NULL"),
    ("JSON body field", "SELECT id, json_extract(resp_body_text, '$.token') FROM history WHERE resp_content_type LIKE '%json%'"),
    ("Extract values", "SELECT id, regexp_extract(resp_body_text, 'csrf[^\"]*\"([^\"]+)', 1) AS csrf FROM history WHERE csrf IS NOT NULL"),
    ("Parameters seen", "SELECT DISTINCT path, query FROM history WHERE query IS NOT NULL"),
];

pub struct Store {
    pub(crate) conn: Connection,
}

/// One history row without bodies.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub id: i64,
    pub time: String,
    pub source: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub resp_content_type: Option<String>,
    pub resp_body_length: Option<i64>,
    pub title: Option<String>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
    pub note: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HistoryItem {
    pub entry: HistoryEntry,
    pub target: Target,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    pub resp_body: Option<Vec<u8>>,
}

#[derive(Debug, Default, Clone)]
pub struct HistoryFilter {
    pub host: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub source: Option<String>,
    pub tag: Option<String>,
    /// Substring searched in the raw request and response.
    pub contains: Option<String>,
    pub after_id: Option<i64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterceptEntry {
    pub id: i64,
    pub time: String,
    pub direction: String,
    pub state: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub length: i64,
    pub resolved_time: Option<String>,
}

/// Result of a read-only SQL query, in a compact column/row shape.
#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: usize,
    /// More rows existed than `limit` allowed.
    pub truncated: bool,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let store = Self::init(conn)?;
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let store = Self::init(Connection::open_in_memory()?)?;
        store.migrate()?;
        Ok(store)
    }

    /// Opens an existing project read-only, for `query`. Writes are impossible on
    /// this connection, so arbitrary SQL from an agent is safe to run.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::NotFound(format!("project {}", path.display())));
        }
        let conn =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        conn.pragma_update(None, "query_only", true)?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        register_functions(&conn)?;
        Ok(Self { conn })
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self.conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(Error::InvalidInput(format!(
                "project schema v{version} is newer than this build supports (v{SCHEMA_VERSION})"
            )));
        }
        if version < 1 {
            self.conn.execute_batch(SCHEMA)?;
        }
        if version < 2 {
            self.conn.execute_batch(SCHEMA_V2)?;
        }
        if version < 3 {
            self.conn.execute_batch(SCHEMA_V3)?;
        }
        if version < 4 {
            self.conn.execute_batch(crate::scan::findings_db::SCHEMA)?;
        }
        if version < 5 {
            self.conn.execute_batch(crate::jobs::SCHEMA)?;
        }
        if version < 6 {
            self.conn.execute_batch("ALTER TABLE findings ADD COLUMN attack TEXT NOT NULL DEFAULT '';")?;
        }
        if version < SCHEMA_VERSION {
            self.conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        Ok(())
    }

    /// Records many captures in one transaction.
    pub fn record_batch(&mut self, captures: &[Capture]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for c in captures {
            insert_capture(&tx, c)?;
        }
        tx.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn fuzz_create(
        &self,
        state: &str,
        mode: &str,
        target: &str,
        positions: usize,
        total: u64,
        config: &Value,
        template: &[u8],
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO fuzz_runs (state, mode, target, positions, total, config, template)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![state, mode, target, positions as i64, total as i64, config.to_string(), template],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Sets a run's state; `finished` also stamps the finish time.
    pub fn fuzz_set_state(
        &self,
        id: i64,
        state: &str,
        pid: Option<u32>,
        error: Option<&str>,
        finished: bool,
    ) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE fuzz_runs SET state = ?1, pid = COALESCE(?2, pid), error = COALESCE(?3, error),
                finished_time = CASE WHEN ?4 THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE finished_time END
             WHERE id = ?5",
            params![state, pid, error, finished, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("fuzz run {id}")));
        }
        Ok(())
    }

    pub fn fuzz_state(&self, id: i64) -> Result<String> {
        self.conn
            .query_row("SELECT state FROM fuzz_runs WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("fuzz run {id}")))
    }

    /// Records a batch of results (and their exchanges) in one transaction.
    pub fn fuzz_record(&mut self, run_id: i64, rows: &[crate::fuzz::engine::Row]) -> Result<()> {
        let tx = self.conn.transaction()?;
        let (mut matched, mut errors) = (0i64, 0i64);
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO fuzz_results (run_id, idx, position, payloads, history_id, status, length,
                    words, lines, duration_ms, matched, grep, extract, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            )?;
            for (capture, r) in rows {
                let history_id = capture.as_ref().map(|c| insert_capture(&tx, c)).transpose()?;
                matched += r.matched as i64;
                errors += r.error.is_some() as i64;
                stmt.execute(params![
                    run_id,
                    r.idx as i64,
                    r.position.map(|p| p as i64),
                    serde_json::to_string(&r.payloads).unwrap_or_default(),
                    history_id,
                    r.status,
                    r.length,
                    r.words,
                    r.lines,
                    r.duration_ms,
                    r.matched,
                    (!r.grep.is_empty()).then(|| serde_json::to_string(&r.grep).unwrap_or_default()),
                    r.extract,
                    r.error,
                ])?;
            }
        }
        tx.execute(
            "UPDATE fuzz_runs SET done = done + ?1, matched = matched + ?2, errors = errors + ?3 WHERE id = ?4",
            params![rows.len() as i64, matched, errors, run_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// One run's metadata (without the template).
    pub fn fuzz_run(&self, id: i64) -> Result<Value> {
        let r = self.query(
            "SELECT id, time, state, mode, target, positions, total, done, matched, errors, pid, finished_time, error,
                json(config) AS config
             FROM fuzz_runs WHERE id = ?1",
            &[id.to_string()],
            1,
            100_000,
        )?;
        let row = r.rows.into_iter().next().ok_or_else(|| Error::NotFound(format!("fuzz run {id}")))?;
        let mut obj: serde_json::Map<String, Value> = r.columns.into_iter().zip(row).collect();
        if let Some(Value::String(c)) = obj.get("config") {
            obj.insert("config".into(), serde_json::from_str(c).unwrap_or(Value::Null));
        }
        Ok(Value::Object(obj))
    }

    /// What an agent needs to triage a run without reading every row: status
    /// counts, the most common (baseline) response shape, outliers whose
    /// (status, words) shape is rare, matches, and errors.
    pub fn fuzz_summary(&self, id: i64, top: usize) -> Result<Value> {
        let run = self.fuzz_run(id)?;
        let done = run["done"].as_i64().unwrap_or(0);
        let p = [id.to_string()];
        let rows = |sql: &str, params: &[String]| -> Result<Vec<Value>> {
            let r = self.query(sql, params, top, 500)?;
            Ok(r.rows
                .into_iter()
                .map(|row| {
                    let mut obj: serde_json::Map<String, Value> = r.columns.iter().cloned().zip(row).collect();
                    for key in ["payloads", "grep"] {
                        if let Some(Value::String(s)) = obj.get(key) {
                            let parsed = serde_json::from_str(s).unwrap_or(Value::Null);
                            obj.insert(key.into(), parsed);
                        }
                    }
                    Value::Object(obj)
                })
                .collect())
        };
        let by_status = rows(
            "SELECT status, count(*) AS count FROM fuzz_results WHERE run_id = ?1 GROUP BY status ORDER BY count DESC",
            &p,
        )?;
        let baseline = rows(
            "SELECT status, words, count(*) AS count, min(length) AS min_length, max(length) AS max_length
             FROM fuzz_results WHERE run_id = ?1 AND error IS NULL GROUP BY status, words ORDER BY count DESC LIMIT 1",
            &p,
        )?;
        let threshold = (done / 100).max(1);
        let outliers = rows(
            "WITH g AS (SELECT status, words, count(*) AS c FROM fuzz_results
                        WHERE run_id = ?1 AND error IS NULL GROUP BY status, words)
             SELECT r.idx, r.payloads, r.status, r.length, r.words, r.duration_ms, r.history_id, g.c AS shape_count
             FROM fuzz_results r JOIN g ON g.status IS r.status AND g.words IS r.words
             WHERE r.run_id = ?1 AND g.c <= CAST(?2 AS INTEGER) ORDER BY g.c, r.idx",
            &[id.to_string(), threshold.to_string()],
        )?;
        let shapes: i64 = self.conn.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM fuzz_results WHERE run_id = ?1 AND error IS NULL GROUP BY status, words)",
            [id],
            |r| r.get(0),
        )?;
        let matches = rows(
            "SELECT idx, payloads, status, length, words, grep, extract, history_id
             FROM fuzz_results WHERE run_id = ?1 AND matched = 1 ORDER BY idx",
            &p,
        )?;
        let slowest = rows(
            "SELECT idx, payloads, status, duration_ms, history_id FROM fuzz_results
             WHERE run_id = ?1 AND error IS NULL ORDER BY duration_ms DESC LIMIT 3",
            &p,
        )?;
        let errors = rows(
            "SELECT error, count(*) AS count, min(idx) AS first_idx FROM fuzz_results
             WHERE run_id = ?1 AND error IS NOT NULL GROUP BY error ORDER BY count DESC",
            &p,
        )?;
        Ok(serde_json::json!({
            "run": run,
            "by_status": by_status,
            "baseline": baseline.into_iter().next(),
            "distinct_shapes": shapes,
            "outliers": {
                "rule": format!("(status, words) shape seen <= {threshold} time(s)"),
                "items": outliers,
            },
            "matches": matches,
            "slowest": slowest,
            "errors": errors,
            "hint": "More: brainproxy query \"SELECT * FROM fuzz_results WHERE run_id = N ...\"; join history ON history.id = history_id for bodies.",
        }))
    }

    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn meta_set(&self, key: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(v) => self.conn.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, v],
            )?,
            None => self.conn.execute("DELETE FROM meta WHERE key = ?1", [key])?,
        };
        Ok(())
    }

    /// Reads a JSON setting, or its default when unset.
    pub fn setting<T: serde::de::DeserializeOwned + Default>(&self, key: &str) -> Result<T> {
        match self.meta_get(&format!("setting.{key}"))? {
            Some(v) => serde_json::from_str(&v).map_err(|e| Error::InvalidInput(format!("setting {key}: {e}"))),
            None => Ok(T::default()),
        }
    }

    /// Writes a JSON setting and bumps the settings version so running proxies reload.
    pub fn set_setting<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let json = serde_json::to_string(value).map_err(|e| Error::InvalidInput(e.to_string()))?;
        self.meta_set(&format!("setting.{key}"), Some(&json))?;
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('settings_version', '1')
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
            [],
        )?;
        Ok(())
    }

    pub fn settings_version(&self) -> Result<i64> {
        Ok(self.meta_get("settings_version")?.and_then(|v| v.parse().ok()).unwrap_or(0))
    }

    pub fn intercept_create(
        &self,
        direction: &str,
        method: &str,
        url: &str,
        status: Option<u16>,
        original: &[u8],
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO intercepts (direction, method, url, status, original) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![direction, method, url, status, original],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Current state and edited message (if any) of an intercept.
    pub fn intercept_state(&self, id: i64) -> Result<(String, Option<Vec<u8>>)> {
        self.conn
            .query_row("SELECT state, edited FROM intercepts WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("intercept {id}")))
    }

    /// Moves a pending intercept to `state`. Fails if it isn't pending any more.
    pub fn intercept_resolve(&self, id: i64, state: &str, edited: Option<&[u8]>) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE intercepts SET state = ?1, edited = ?2, resolved_time = strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE id = ?3 AND state = 'pending'",
            params![state, edited, id],
        )?;
        if n == 0 {
            let (current, _) = self.intercept_state(id)?;
            return Err(Error::Conflict(format!("intercept {id} is {current}, not pending")));
        }
        Ok(())
    }

    pub fn intercept_list(&self, state: Option<&str>, limit: u32) -> Result<Vec<InterceptEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, time, direction, state, method, url, status, length(original), resolved_time
             FROM intercepts WHERE (?1 IS NULL OR state = ?1) ORDER BY id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![state, limit], |r| {
            Ok(InterceptEntry {
                id: r.get(0)?,
                time: r.get(1)?,
                direction: r.get(2)?,
                state: r.get(3)?,
                method: r.get(4)?,
                url: r.get(5)?,
                status: r.get(6)?,
                length: r.get(7)?,
                resolved_time: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn intercept_get(&self, id: i64) -> Result<(InterceptEntry, Vec<u8>, Option<Vec<u8>>)> {
        self.conn
            .query_row(
                "SELECT id, time, direction, state, method, url, status, length(original), resolved_time, original, edited
                 FROM intercepts WHERE id = ?1",
                [id],
                |r| {
                    let entry = InterceptEntry {
                        id: r.get(0)?,
                        time: r.get(1)?,
                        direction: r.get(2)?,
                        state: r.get(3)?,
                        method: r.get(4)?,
                        url: r.get(5)?,
                        status: r.get(6)?,
                        length: r.get(7)?,
                        resolved_time: r.get(8)?,
                    };
                    Ok((entry, r.get(9)?, r.get(10)?))
                },
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("intercept {id}")))
    }

    pub fn record_exchange(&self, source: &str, ex: &Exchange) -> Result<i64> {
        self.record(&Capture::new(
            source,
            &ex.target,
            &ex.request,
            Some(&ex.response),
            Some(ex.duration_ms as i64),
            None,
        ))
    }

    pub fn record_failure(&self, source: &str, target: &Target, request: &[u8], error: &str) -> Result<i64> {
        self.record(&Capture::new(source, target, request, None, None, Some(error)))
    }

    pub fn record(&self, c: &Capture) -> Result<i64> {
        insert_capture(&self.conn, c)
    }

    pub fn list(&self, f: &HistoryFilter) -> Result<Vec<HistoryEntry>> {
        let mut sql = format!("SELECT {ENTRY_COLS} FROM history WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut push = |clause: &str, v: Box<dyn rusqlite::ToSql>| {
            args.push(v);
            sql.push_str(&format!(" AND {}", clause.replace('?', &format!("?{}", args.len()))));
        };
        if let Some(h) = &f.host {
            push("host = ?", Box::new(h.clone()));
        }
        if let Some(m) = &f.method {
            push("method = ?", Box::new(m.to_ascii_uppercase()));
        }
        if let Some(s) = f.status {
            push("status = ?", Box::new(s));
        }
        if let Some(s) = &f.source {
            push("source = ?", Box::new(s.clone()));
        }
        if let Some(t) = &f.tag {
            push("EXISTS (SELECT 1 FROM json_each(tags) WHERE value = ?)", Box::new(t.clone()));
        }
        if let Some(id) = f.after_id {
            push("id > ?", Box::new(id));
        }
        if let Some(c) = &f.contains {
            args.push(Box::new(c.clone().into_bytes()));
            let n = args.len();
            sql.push_str(&format!(" AND (instr(request, ?{n}) > 0 OR instr(response, ?{n}) > 0)"));
        }
        sql.push_str(" ORDER BY id");
        if let Some(l) = f.limit {
            sql.push_str(&format!(" LIMIT {l}"));
        }
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter().map(|b| b.as_ref())), row_to_entry)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn get(&self, id: i64) -> Result<HistoryItem> {
        self.conn
            .query_row(
                &format!(
                    "SELECT {ENTRY_COLS}, scheme, host, port, request, response, resp_body FROM history WHERE id = ?1"
                ),
                [id],
                |r| {
                    Ok(HistoryItem {
                        entry: row_to_entry(r)?,
                        target: Target { scheme: r.get(13)?, host: r.get(14)?, port: r.get(15)? },
                        request: r.get(16)?,
                        response: r.get(17)?,
                        resp_body: r.get(18)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("history item {id}")))
    }

    pub fn set_note(&self, id: i64, note: Option<&str>) -> Result<()> {
        let n = self.conn.execute("UPDATE history SET note = ?1 WHERE id = ?2", params![note, id])?;
        if n == 0 {
            return Err(Error::NotFound(format!("history item {id}")));
        }
        Ok(())
    }

    /// Adds and removes tags; returns the resulting tag list.
    pub fn update_tags(&self, id: i64, add: &[String], remove: &[String]) -> Result<Vec<String>> {
        let current: String = self
            .conn
            .query_row("SELECT tags FROM history WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("history item {id}")))?;
        let mut tags: Vec<String> = serde_json::from_str(&current).unwrap_or_default();
        tags.retain(|t| !remove.contains(t));
        for t in add {
            if !tags.contains(t) {
                tags.push(t.clone());
            }
        }
        let json = serde_json::to_string(&tags).unwrap_or_else(|_| "[]".into());
        self.conn.execute("UPDATE history SET tags = ?1 WHERE id = ?2", params![json, id])?;
        Ok(tags)
    }

    pub fn count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT count(*) FROM history", [], |r| r.get(0))?)
    }

    /// Runs one SQL statement and returns up to `limit` rows. Text and blob cells
    /// longer than `max_cell` bytes are cut and marked. Blobs that aren't UTF-8
    /// come back as `{"base64": ...}`.
    pub fn query(&self, sql: &str, params: &[String], limit: usize, max_cell: usize) -> Result<QueryResult> {
        let mut stmt = self.conn.prepare(sql).map_err(|e| Error::InvalidInput(format!("SQL: {e}")))?;
        let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows_iter = stmt
            .query(rusqlite::params_from_iter(params.iter().map(|p| bind_value(p))))
            .map_err(|e| Error::InvalidInput(format!("SQL: {e}")))?;
        let mut rows = Vec::new();
        let mut truncated = false;
        while let Some(row) = rows_iter.next().map_err(|e| Error::InvalidInput(format!("SQL: {e}")))? {
            if rows.len() == limit {
                truncated = true;
                break;
            }
            let mut out = Vec::with_capacity(columns.len());
            for i in 0..columns.len() {
                out.push(cell(row.get_ref(i)?, max_cell));
            }
            rows.push(out);
        }
        Ok(QueryResult { row_count: rows.len(), columns, rows, truncated })
    }
}

pub(crate) fn insert_capture(conn: &Connection, c: &Capture) -> Result<i64> {
    conn.execute(
        "INSERT INTO history (source, scheme, host, port, method, url, path, query,
            req_headers, req_content_type, req_body, req_body_text,
            status, reason, resp_headers, resp_content_type, resp_body, resp_body_text, resp_body_length,
            title, duration_ms, error, request, response)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
            ?20, ?21, ?22, ?23, ?24)",
        params![
            c.source,
            c.scheme,
            c.host,
            c.port,
            c.method,
            c.url,
            c.path,
            c.query,
            c.req_headers,
            c.req_content_type,
            c.req_body,
            c.req_body_text,
            c.status,
            c.reason,
            c.resp_headers,
            c.resp_content_type,
            c.resp_body,
            c.resp_body_text,
            c.resp_body.as_ref().map(|b| b.len() as i64),
            c.title,
            c.duration_ms,
            c.error,
            c.request,
            c.response,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Binds parameters that are canonical integers ("42", "-7"; not "007" or "+5")
/// as integers, everything else as text. Comparisons against columns work
/// either way thanks to column affinity; this also makes expressions like
/// `?1 = 0` or `idx > ?1` behave as expected.
fn bind_value(p: &str) -> rusqlite::types::Value {
    match p.parse::<i64>() {
        Ok(i) if i.to_string() == p => rusqlite::types::Value::Integer(i),
        _ => rusqlite::types::Value::Text(p.to_string()),
    }
}

fn cell(v: ValueRef, max: usize) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(t) => json!(clip_text(&String::from_utf8_lossy(t), max)),
        ValueRef::Blob(b) => match std::str::from_utf8(b) {
            Ok(s) => json!(clip_text(s, max)),
            Err(_) => {
                use base64::Engine;
                let n = b.len().min(max);
                let mut v = json!({"base64": base64::engine::general_purpose::STANDARD.encode(&b[..n])});
                if n < b.len() {
                    v["truncated_from"] = json!(b.len());
                }
                v
            }
        },
    }
}

fn clip_text(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated, {} bytes total]", &s[..end], s.len())
}

fn register_functions(conn: &Connection) -> Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    conn.create_scalar_function("header", 2, flags, |ctx| {
        let Some(json) = ctx.get::<Option<String>>(0)? else { return Ok(None) };
        let name: String = ctx.get(1)?;
        let pairs: Vec<(String, String)> = serde_json::from_str(&json).unwrap_or_default();
        Ok(pairs.into_iter().find(|(k, _)| k.eq_ignore_ascii_case(&name)).map(|(_, v)| v))
    })?;
    conn.create_scalar_function("regexp", 2, flags, |ctx| {
        let re = cached_regex(ctx, 0)?;
        Ok(text_arg(ctx, 1)?.map(|t| re.is_match(&t)).unwrap_or(false))
    })?;
    for n_args in [2, 3] {
        conn.create_scalar_function("regexp_extract", n_args, flags, move |ctx| {
            let re = cached_regex(ctx, 1)?;
            let group: usize = if n_args == 3 { ctx.get::<i64>(2)? as usize } else { 0 };
            Ok(text_arg(ctx, 0)?
                .and_then(|t| re.captures(&t).and_then(|c| c.get(group)).map(|m| m.as_str().to_string())))
        })?;
    }
    Ok(())
}

fn cached_regex(ctx: &rusqlite::functions::Context, idx: i32) -> rusqlite::Result<Arc<Regex>> {
    ctx.get_or_create_aux(idx, |v| -> std::result::Result<Regex, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Regex::new(v.as_str()?)?)
    })
}

/// Text or UTF-8 blob argument as a string; NULL and non-UTF-8 blobs are None.
fn text_arg(ctx: &rusqlite::functions::Context, idx: usize) -> rusqlite::Result<Option<String>> {
    Ok(match ctx.get_raw(idx) {
        ValueRef::Text(t) | ValueRef::Blob(t) => std::str::from_utf8(t).ok().map(str::to_string),
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Null => None,
    })
}

const ENTRY_COLS: &str = "id, time, source, method, url, status, resp_content_type, resp_body_length, \
    title, duration_ms, error, note, tags";

fn row_to_entry(r: &rusqlite::Row) -> rusqlite::Result<HistoryEntry> {
    let tags: String = r.get(12)?;
    Ok(HistoryEntry {
        id: r.get(0)?,
        time: r.get(1)?,
        source: r.get(2)?,
        method: r.get(3)?,
        url: r.get(4)?,
        status: r.get(5)?,
        resp_content_type: r.get(6)?,
        resp_body_length: r.get(7)?,
        title: r.get(8)?,
        duration_ms: r.get(9)?,
        error: r.get(10)?,
        note: r.get(11)?,
        tags: serde_json::from_str(&tags).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(store: &Store) -> i64 {
        let ex = Exchange {
            target: Target::from_url("http://a.test").unwrap(),
            request: b"GET /x?id=1 HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec(),
            response: b"HTTP/1.1 500 Oops\r\nServer: nginx\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"token\":\"abc\",\"msg\":\"You have SQL syntax\"}".to_vec(),
            duration_ms: 7,
        };
        store.record_exchange("send", &ex).unwrap()
    }

    #[test]
    fn records_and_filters() {
        let s = Store::open_in_memory().unwrap();
        let id = sample(&s);
        s.record_failure("send", &Target::from_url("http://a.test").unwrap(), b"POST /y HTTP/1.1\r\n\r\n", "boom")
            .unwrap();

        let all = s.list(&HistoryFilter::default()).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].status, Some(500));
        assert_eq!(all[0].url, "http://a.test/x?id=1");

        let hits = s.list(&HistoryFilter { contains: Some("token".into()), ..Default::default() }).unwrap();
        assert_eq!(hits.len(), 1);
        let hits = s.list(&HistoryFilter { method: Some("post".into()), ..Default::default() }).unwrap();
        assert_eq!(hits[0].error.as_deref(), Some("boom"));

        s.set_note(id, Some("interesting")).unwrap();
        assert_eq!(s.get(id).unwrap().entry.note.as_deref(), Some("interesting"));
        assert_eq!(s.update_tags(id, &["sqli".into(), "todo".into()], &[]).unwrap(), ["sqli", "todo"]);
        assert_eq!(s.update_tags(id, &[], &["todo".into()]).unwrap(), ["sqli"]);
        let hits = s.list(&HistoryFilter { tag: Some("sqli".into()), ..Default::default() }).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(matches!(s.get(99), Err(Error::NotFound(_))));
    }

    #[test]
    fn sql_functions_and_fts() {
        let s = Store::open_in_memory().unwrap();
        sample(&s);
        let q = |sql: &str| s.query(sql, &[], 100, 1000).unwrap().rows;
        assert_eq!(q("SELECT header(resp_headers, 'SERVER') FROM history")[0][0], "nginx");
        assert_eq!(q("SELECT count(*) FROM history WHERE resp_body_text REGEXP '(?i)sql syntax'")[0][0], 1);
        assert_eq!(q("SELECT regexp_extract(resp_body_text, '\"token\":\"(\\w+)\"', 1) FROM history")[0][0], "abc");
        assert_eq!(q("SELECT json_extract(resp_body_text, '$.token') FROM history")[0][0], "abc");
        assert_eq!(q("SELECT rowid FROM history_fts WHERE history_fts MATCH 'syntax'").len(), 1);
    }

    #[test]
    fn query_limits_and_clips() {
        let s = Store::open_in_memory().unwrap();
        sample(&s);
        sample(&s);
        let r = s.query("SELECT resp_body_text FROM history", &[], 1, 5).unwrap();
        assert!(r.truncated);
        assert_eq!(r.rows.len(), 1);
        assert!(r.rows[0][0].as_str().unwrap().starts_with("{\"tok…[truncated"));
        let r = s.query("SELECT id FROM history WHERE id = ?1", &["2".into()], 10, 100).unwrap();
        assert_eq!(r.rows, vec![vec![json!(2)]]);
        let r = s.query("SELECT ?1 = 0, ?2 > 1, typeof(?3)", &["0".into(), "5".into(), "007".into()], 1, 100).unwrap();
        assert_eq!(r.rows, vec![vec![json!(1), json!(1), json!("text")]]);
        assert!(s.query("SELEC nope", &[], 1, 1).is_err());
    }

    #[test]
    fn read_only_connection_rejects_writes() {
        let dir = std::env::temp_dir().join(format!("bp-store-ro-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.bpdb");
        let _ = std::fs::remove_file(&path);
        sample(&Store::open(&path).unwrap());
        let ro = Store::open_read_only(&path).unwrap();
        assert!(ro.query("DELETE FROM history", &[], 10, 10).is_err());
        assert_eq!(ro.count().unwrap(), 1);
    }
}
