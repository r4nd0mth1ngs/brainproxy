//! Project store: a single SQLite file holding history (and later findings,
//! notes, and config). Opening a missing project creates it.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::http::{parse_response_head, Exchange, RawRequest, Target};

const SCHEMA_VERSION: i64 = 1;

pub struct Store {
    conn: Connection,
}

/// One history row without the raw bodies.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub id: i64,
    pub time: String,
    pub source: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub request_length: i64,
    pub response_length: i64,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HistoryItem {
    pub entry: HistoryEntry,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct HistoryFilter {
    pub host: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub source: Option<String>,
    /// Substring searched in raw request and response.
    pub contains: Option<String>,
    pub after_id: Option<i64>,
    pub limit: Option<u32>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let store = Self { conn: Connection::open_in_memory()? };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self.conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(Error::InvalidInput(format!(
                "project schema v{version} is newer than this build supports (v{SCHEMA_VERSION})"
            )));
        }
        if version < 1 {
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    source TEXT NOT NULL,
                    scheme TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status INTEGER,
                    request BLOB NOT NULL,
                    response BLOB NOT NULL,
                    duration_ms INTEGER,
                    error TEXT,
                    note TEXT
                );
                CREATE INDEX IF NOT EXISTS history_host ON history(host);
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                PRAGMA user_version = 1;",
            )?;
        }
        Ok(())
    }

    pub fn record_exchange(&self, source: &str, ex: &Exchange) -> Result<i64> {
        let status = parse_response_head(&ex.response).ok().map(|h| h.status);
        self.insert(source, &ex.target, &ex.request, &ex.response, status, Some(ex.duration_ms as i64), None)
    }

    pub fn record_failure(&self, source: &str, target: &Target, request: &[u8], error: &str) -> Result<i64> {
        self.insert(source, target, request, &[], None, None, Some(error))
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(
        &self,
        source: &str,
        target: &Target,
        request: &[u8],
        response: &[u8],
        status: Option<u16>,
        duration_ms: Option<i64>,
        error: Option<&str>,
    ) -> Result<i64> {
        let head = RawRequest::from_bytes(request.to_vec()).head().ok();
        let (method, path) = head.map(|h| (h.method, h.target)).unwrap_or_default();
        self.conn.execute(
            "INSERT INTO history (source, scheme, host, port, method, path, status, request, response, duration_ms, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                source,
                target.scheme,
                target.host,
                target.port,
                method,
                path,
                status,
                request,
                response,
                duration_ms,
                error
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list(&self, f: &HistoryFilter) -> Result<Vec<HistoryEntry>> {
        let mut sql = format!("SELECT {ENTRY_COLS} FROM history WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut push = |clause: &str, v: Box<dyn rusqlite::ToSql>| {
            args.push(v);
            sql.push_str(&format!(" AND {clause} ?{}", args.len()));
        };
        if let Some(h) = &f.host {
            push("host =", Box::new(h.clone()));
        }
        if let Some(m) = &f.method {
            push("method =", Box::new(m.to_ascii_uppercase()));
        }
        if let Some(s) = f.status {
            push("status =", Box::new(s));
        }
        if let Some(s) = &f.source {
            push("source =", Box::new(s.clone()));
        }
        if let Some(id) = f.after_id {
            push("id >", Box::new(id));
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
            .query_row(&format!("SELECT {ENTRY_COLS}, request, response FROM history WHERE id = ?1"), [id], |r| {
                Ok(HistoryItem { entry: row_to_entry(r)?, request: r.get(14)?, response: r.get(15)? })
            })
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

    pub fn count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT count(*) FROM history", [], |r| r.get(0))?)
    }
}

const ENTRY_COLS: &str = "id, time, source, scheme, host, port, method, path, status, \
    length(request), length(response), duration_ms, error, note";

fn row_to_entry(r: &rusqlite::Row) -> rusqlite::Result<HistoryEntry> {
    Ok(HistoryEntry {
        id: r.get(0)?,
        time: r.get(1)?,
        source: r.get(2)?,
        scheme: r.get(3)?,
        host: r.get(4)?,
        port: r.get(5)?,
        method: r.get(6)?,
        path: r.get(7)?,
        status: r.get(8)?,
        request_length: r.get(9)?,
        response_length: r.get(10)?,
        duration_ms: r.get(11)?,
        error: r.get(12)?,
        note: r.get(13)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_filters() {
        let s = Store::open_in_memory().unwrap();
        let target = Target::from_url("http://a.test").unwrap();
        let ex = Exchange {
            target: target.clone(),
            request: b"GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec(),
            response: b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnah".to_vec(),
            duration_ms: 7,
        };
        let id = s.record_exchange("send", &ex).unwrap();
        s.record_failure("send", &target, b"POST /y HTTP/1.1\r\n\r\n", "boom").unwrap();

        let all = s.list(&HistoryFilter::default()).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].status, Some(404));
        assert_eq!(all[0].path, "/x");

        let hits = s.list(&HistoryFilter { contains: Some("nah".into()), ..Default::default() }).unwrap();
        assert_eq!(hits.len(), 1);
        let hits = s.list(&HistoryFilter { method: Some("post".into()), ..Default::default() }).unwrap();
        assert_eq!(hits[0].error.as_deref(), Some("boom"));

        s.set_note(id, Some("interesting")).unwrap();
        assert_eq!(s.get(id).unwrap().entry.note.as_deref(), Some("interesting"));
        assert!(matches!(s.get(99), Err(Error::NotFound(_))));
    }
}
