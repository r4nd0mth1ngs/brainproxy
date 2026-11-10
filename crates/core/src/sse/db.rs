//! Event streams and their events in the project database. The request and the response (its
//! head, and its body as far as it is kept) are an ordinary history row;
//! `sse_streams.history_id` points to it.

use std::collections::HashMap;

use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use crate::capture::Capture;
use crate::error::{Error, Result};
use crate::sse::Event;
use crate::store::{insert_capture, update_capture, Store};

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sse_streams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    source TEXT NOT NULL,
    history_id INTEGER,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open',
    closed_time TEXT,
    events INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    ended TEXT,
    error TEXT,
    origin TEXT
);
CREATE INDEX IF NOT EXISTS sse_streams_host ON sse_streams(host);
CREATE INDEX IF NOT EXISTS sse_streams_history ON sse_streams(history_id);

CREATE TABLE IF NOT EXISTS sse_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id INTEGER NOT NULL,
    time TEXT NOT NULL,
    event TEXT NOT NULL,
    event_id TEXT,
    data TEXT,
    retry INTEGER,
    length INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sse_events_stream ON sse_events(stream_id, id);

CREATE VIRTUAL TABLE IF NOT EXISTS sse_events_fts USING fts5(
    data, content='sse_events', content_rowid='id', tokenize=\"unicode61 tokenchars '_'\"
);
CREATE TRIGGER IF NOT EXISTS sse_events_ai AFTER INSERT ON sse_events BEGIN
    INSERT INTO sse_events_fts(rowid, data) VALUES (new.id, new.data);
END;
CREATE TRIGGER IF NOT EXISTS sse_events_ad AFTER DELETE ON sse_events BEGIN
    INSERT INTO sse_events_fts(sse_events_fts, rowid, data) VALUES ('delete', old.id, old.data);
END;
";

pub const STREAM_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Stream id"),
    ("time", "TEXT", "UTC time the response's head arrived"),
    ("source", "TEXT", "proxy (browser traffic) or send (a stream `send` read)"),
    (
        "history_id",
        "INTEGER",
        "history.id of the request and its response: the head while the stream is open, then the body too, as \
         far as it is kept",
    ),
    ("url", "TEXT", "URL requested"),
    ("host", "TEXT", "Target host"),
    ("state", "TEXT", "open or closed"),
    ("closed_time", "TEXT", "When the stream ended, or recording of it did"),
    ("events", "INTEGER", "Events recorded"),
    (
        "truncated",
        "INTEGER",
        "1 if the stream went over what one may store (4 MiB of body or 10000 events): what came after is not \
         in the project",
    ),
    (
        "ended",
        "TEXT",
        "How it ended: server (the response ended or the server closed), client (the proxy's client went away), \
         stopped (the proxy stopped, or `send` stopped reading: wait, max-events, cap), error",
    ),
    (
        "error",
        "TEXT",
        "Why events are missing or reading stopped (over the cap, a coding that isn't decoded, recorder behind, \
         a read error)",
    ),
    ("origin", "TEXT", "gui, cli or mcp: who started the proxy or the send that recorded it (as history.origin)"),
];

pub const EVENT_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Event row id, increasing"),
    ("stream_id", "INTEGER", "sse_streams.id"),
    ("time", "TEXT", "UTC time the event's last line arrived"),
    ("event", "TEXT", "The event field: the event's type, message when the block names none"),
    ("event_id", "TEXT", "The id field (what a client sends back as Last-Event-ID), NULL when the block has none"),
    (
        "data",
        "TEXT",
        "The data lines joined with line breaks; NULL for a block without one, which a browser dispatches no \
         event for",
    ),
    ("retry", "INTEGER", "The retry field: milliseconds before the client reconnects"),
    ("length", "INTEGER", "Bytes of data"),
];

/// What the proxy records of a stream, in order. `key` names a stream within one recording
/// process; the database id comes from the `Open` record.
#[derive(Debug, Clone)]
pub enum SseRecord {
    Open {
        key: u64,
        /// The request and the response's head, stored as a history row.
        capture: Box<Capture>,
        url: String,
        time: String,
    },
    Event {
        key: u64,
        event: Event,
    },
    /// Something to say about the stream while it is open: it went over a cap (`truncated`),
    /// or its events can't be read.
    Note {
        key: u64,
        truncated: bool,
        error: String,
    },
    Close {
        key: u64,
        time: String,
        /// The exchange with the body as far as it was kept: the history row is rewritten from it.
        capture: Box<Capture>,
        truncated: bool,
        ended: &'static str,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct SseStream {
    pub id: i64,
    pub time: String,
    pub source: String,
    pub history_id: Option<i64>,
    pub url: String,
    pub host: String,
    pub state: String,
    pub closed_time: Option<String>,
    pub events: i64,
    pub truncated: bool,
    pub ended: Option<String>,
    pub error: Option<String>,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SseEvent {
    pub id: i64,
    pub stream_id: i64,
    pub time: String,
    pub event: String,
    pub event_id: Option<String>,
    #[serde(skip)]
    pub data: Option<String>,
    pub retry: Option<u64>,
    pub length: i64,
}

#[derive(Debug, Default, Clone)]
pub struct StreamFilter {
    pub host: Option<String>,
    pub source: Option<String>,
    pub state: Option<String>,
    pub after_id: Option<i64>,
    pub limit: u32,
    /// The newest `limit` streams (still listed oldest first) instead of the oldest.
    pub newest: bool,
}

#[derive(Debug, Default, Clone)]
pub struct EventFilter {
    /// Only events of this type.
    pub event: Option<String>,
    /// Substring of the data.
    pub contains: Option<String>,
    pub after_id: Option<i64>,
    pub limit: u32,
}

const STREAM_COLS: &str =
    "id, time, source, history_id, url, host, state, closed_time, events, truncated, ended, error, origin";
const EVENT_COLS: &str = "id, stream_id, time, event, event_id, data, retry, length";

fn row_to_stream(r: &rusqlite::Row) -> rusqlite::Result<SseStream> {
    Ok(SseStream {
        id: r.get(0)?,
        time: r.get(1)?,
        source: r.get(2)?,
        history_id: r.get(3)?,
        url: r.get(4)?,
        host: r.get(5)?,
        state: r.get(6)?,
        closed_time: r.get(7)?,
        events: r.get(8)?,
        truncated: r.get(9)?,
        ended: r.get(10)?,
        error: r.get(11)?,
        origin: r.get(12)?,
    })
}

fn row_to_event(r: &rusqlite::Row) -> rusqlite::Result<SseEvent> {
    Ok(SseEvent {
        id: r.get(0)?,
        stream_id: r.get(1)?,
        time: r.get(2)?,
        event: r.get(3)?,
        event_id: r.get(4)?,
        data: r.get(5)?,
        retry: r.get::<_, Option<i64>>(6)?.map(|n| n as u64),
        length: r.get(7)?,
    })
}

/// A stream row for the exchange recorded as history row `history_id`.
fn insert_stream(
    conn: &rusqlite::Connection,
    history_id: i64,
    capture: &Capture,
    source: &str,
    url: &str,
    time: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO sse_streams (time, source, history_id, url, host, origin) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            time,
            source,
            history_id,
            url,
            capture.host,
            capture.origin.as_deref().unwrap_or(crate::provenance::origin())
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn insert_event(conn: &rusqlite::Connection, stream: i64, e: &Event) -> Result<()> {
    conn.execute(
        "INSERT INTO sse_events (stream_id, time, event, event_id, data, retry, length)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            stream,
            e.time,
            e.event,
            e.event_id,
            e.data,
            // A retry past what SQLite holds is as good as the largest it does.
            e.retry.map(|n| n.min(i64::MAX as u64) as i64),
            e.data.as_ref().map_or(0, String::len) as i64
        ],
    )?;
    Ok(())
}

fn close_stream(
    conn: &rusqlite::Connection,
    stream: i64,
    time: &str,
    truncated: bool,
    ended: &str,
    error: Option<&str>,
) -> Result<()> {
    conn.execute(
        // The closing error says everything an earlier note did.
        "UPDATE sse_streams SET state = 'closed', closed_time = ?1, truncated = max(truncated, ?2), ended = ?3,
            error = COALESCE(?4, error)
         WHERE id = ?5",
        params![time, truncated, ended, error, stream],
    )?;
    Ok(())
}

impl Store {
    /// Records the proxy's stream records in one transaction. `ids` maps the recorder's stream
    /// keys to (stream id, history id) across calls; a closed stream's key is removed. Records
    /// for a key with no `Open` (it failed to record) are skipped. Returns the history ids of
    /// the streams that closed: their rows now hold a body the passive scanner hasn't seen.
    pub fn sse_record(&mut self, records: &[SseRecord], ids: &mut HashMap<u64, (i64, i64)>) -> Result<Vec<i64>> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        // A batch that fails is rolled back whole: the keys it opened or closed must be too,
        // or later events would be written to streams that aren't there.
        let before = ids.clone();
        let result = self.sse_record_in_tx(records, ids);
        if result.is_err() {
            *ids = before;
        }
        result
    }

    fn sse_record_in_tx(&mut self, records: &[SseRecord], ids: &mut HashMap<u64, (i64, i64)>) -> Result<Vec<i64>> {
        let mut closed = Vec::new();
        let tx = self.write_tx()?;
        for r in records {
            match r {
                SseRecord::Open { key, capture, url, time } => {
                    let history_id = insert_capture(&tx, capture)?;
                    ids.insert(*key, (insert_stream(&tx, history_id, capture, "proxy", url, time)?, history_id));
                }
                SseRecord::Event { key, event } => {
                    let Some(&(stream, _)) = ids.get(key) else { continue };
                    insert_event(&tx, stream, event)?;
                    tx.execute("UPDATE sse_streams SET events = events + 1 WHERE id = ?1", [stream])?;
                }
                SseRecord::Note { key, truncated, error } => {
                    let Some(&(stream, _)) = ids.get(key) else { continue };
                    tx.execute(
                        "UPDATE sse_streams SET truncated = max(truncated, ?1), error = ?2 WHERE id = ?3",
                        params![truncated, error, stream],
                    )?;
                }
                SseRecord::Close { key, time, capture, truncated, ended, error } => {
                    let Some((stream, history_id)) = ids.remove(key) else { continue };
                    update_capture(&tx, history_id, capture)?;
                    close_stream(&tx, stream, time, *truncated, ended, error.as_deref())?;
                    closed.push(history_id);
                }
            }
        }
        tx.commit()?;
        Ok(closed)
    }

    /// Records a stream a sender read to its end or its limits ([`crate::sse::read`]), whose
    /// exchange is already history row `history_id`. Returns the stream's id.
    pub fn sse_record_read(
        &mut self,
        history_id: i64,
        source: &str,
        url: &str,
        host: &str,
        read: &crate::sse::StreamRead,
    ) -> Result<i64> {
        let tx = self.write_tx()?;
        let now = crate::ws::now_iso();
        tx.execute(
            "INSERT INTO sse_streams (time, source, history_id, url, host, events, origin)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![read.opened, source, history_id, url, host, read.events.len() as i64, crate::provenance::origin()],
        )?;
        let stream = tx.last_insert_rowid();
        for e in &read.events {
            insert_event(&tx, stream, e)?;
        }
        let ended = match read.stopped {
            crate::sse::Stopped::Closed => "server",
            crate::sse::Stopped::Error => "error",
            _ => "stopped",
        };
        let why = match read.stopped {
            crate::sse::Stopped::Wait => Some("stopped reading: --stream-wait passed"),
            crate::sse::Stopped::MaxEvents => Some("stopped reading: --max-events arrived"),
            _ => None,
        };
        let error = match (read.note.as_deref(), why) {
            (Some(n), Some(w)) => Some(format!("{w}; {n}")),
            (n, w) => n.or(w).map(str::to_string),
        };
        close_stream(&tx, stream, &now, read.truncated, ended, error.as_deref())?;
        tx.commit()?;
        Ok(stream)
    }

    /// Marks streams of `source` still open as closed, with `error` as the reason (a proxy
    /// that was killed can't close them itself; their history rows keep the head only).
    pub fn sse_close_stale(&self, source: &str, error: &str) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE sse_streams SET state = 'closed', closed_time = ?1, ended = 'stopped',
                error = CASE WHEN error IS NULL THEN ?2 ELSE error || '; ' || ?2 END
             WHERE state = 'open' AND source = ?3",
            params![crate::ws::now_iso(), error, source],
        )?)
    }

    pub fn sse_streams(&self, f: &StreamFilter) -> Result<Vec<SseStream>> {
        let order = if f.newest { "DESC" } else { "" };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT * FROM (SELECT {STREAM_COLS} FROM sse_streams
                WHERE (?1 IS NULL OR host = ?1) AND (?2 IS NULL OR source = ?2) AND (?3 IS NULL OR state = ?3)
                    AND (?4 IS NULL OR id > ?4)
                ORDER BY id {order} LIMIT ?5)
             ORDER BY id"
        ))?;
        let rows = stmt.query_map(params![f.host, f.source, f.state, f.after_id, f.limit], row_to_stream)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn sse_stream(&self, id: i64) -> Result<SseStream> {
        self.conn
            .query_row(&format!("SELECT {STREAM_COLS} FROM sse_streams WHERE id = ?1"), [id], row_to_stream)
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("event stream {id}")))
    }

    /// The stream recorded for history row `history_id`, if it was one.
    pub fn sse_stream_of(&self, history_id: i64) -> Result<Option<SseStream>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {STREAM_COLS} FROM sse_streams WHERE history_id = ?1 ORDER BY id LIMIT 1"),
                [history_id],
                row_to_stream,
            )
            .optional()?)
    }

    pub fn sse_events(&self, stream: i64, f: &EventFilter) -> Result<Vec<SseEvent>> {
        self.sse_stream(stream)?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {EVENT_COLS} FROM sse_events
             WHERE stream_id = ?1 AND (?2 IS NULL OR event = ?2) AND (?3 IS NULL OR instr(data, ?3) > 0)
                AND (?4 IS NULL OR id > ?4)
             ORDER BY id LIMIT ?5"
        ))?;
        let rows = stmt.query_map(params![stream, f.event, f.contains, f.after_id, f.limit], row_to_event)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Event counts of a stream by type: [(event, count)].
    pub fn sse_event_counts(&self, stream: i64) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event, count(*) FROM sse_events WHERE stream_id = ?1 GROUP BY event ORDER BY event")?;
        let rows = stmt.query_map([stream], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn sse_event(&self, id: i64) -> Result<SseEvent> {
        self.conn
            .query_row(&format!("SELECT {EVENT_COLS} FROM sse_events WHERE id = ?1"), [id], row_to_event)
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("event {id}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Target;

    const REQUEST: &[u8] = b"GET /events HTTP/1.1\r\nHost: a.test\r\nAccept: text/event-stream\r\n\r\n";
    const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";

    fn capture(body: &[u8]) -> Box<Capture> {
        let target = Target::from_url("http://a.test").unwrap();
        Box::new(Capture::new("proxy", &target, REQUEST, Some(&[HEAD, body].concat()), Some(3), None))
    }

    fn event(event: &str, data: Option<&str>) -> Event {
        Event {
            time: crate::ws::now_iso(),
            event: event.into(),
            event_id: Some("7".into()),
            data: data.map(str::to_string),
            retry: Some(u64::MAX),
        }
    }

    #[test]
    fn records_streams_and_events() {
        let mut s = Store::open_in_memory().unwrap();
        let mut ids = HashMap::new();
        let open = |key| SseRecord::Open {
            key,
            capture: capture(b""),
            url: "http://a.test/events".into(),
            time: crate::ws::now_iso(),
        };
        let closed = s
            .sse_record(
                &[
                    open(4),
                    SseRecord::Event { key: 4, event: event("message", Some("secret_token=abc")) },
                    SseRecord::Event { key: 4, event: event("ping", None) },
                    SseRecord::Event { key: 99, event: event("message", Some("unknown key: skipped")) },
                ],
                &mut ids,
            )
            .unwrap();
        assert!(closed.is_empty());
        // The row is there while the stream is open, with the head.
        let stream = s.sse_stream(1).unwrap();
        assert_eq!((stream.state.as_str(), stream.events, stream.truncated), ("open", 2, false));
        // A stream that goes over the cap says so while it is open.
        let note = SseRecord::Note { key: 4, truncated: true, error: "over the cap".into() };
        s.sse_record(&[note], &mut ids).unwrap();
        let stream = s.sse_stream(1).unwrap();
        assert_eq!(
            (stream.state.as_str(), stream.truncated, stream.error.as_deref()),
            ("open", true, Some("over the cap"))
        );
        let history = stream.history_id.unwrap();
        assert_eq!(s.get(history).unwrap().resp_body.as_deref(), Some(b"".as_slice()));

        let body = b"data: secret_token=abc\n\nevent: ping\n\n";
        let close = SseRecord::Close {
            key: 4,
            time: crate::ws::now_iso(),
            capture: capture(body),
            truncated: false,
            ended: "server",
            error: Some("recording stopped".into()),
        };
        assert_eq!(s.sse_record(&[close], &mut ids).unwrap(), [history]);
        assert!(ids.is_empty());
        // Closing completes the history row and says how the stream ended.
        let stream = s.sse_stream(1).unwrap();
        assert_eq!(
            (stream.state.as_str(), stream.ended.as_deref(), stream.truncated),
            ("closed", Some("server"), true)
        );
        assert_eq!(stream.error.as_deref(), Some("recording stopped"));
        assert_eq!(s.get(history).unwrap().resp_body.as_deref(), Some(body.as_slice()));
        assert_eq!(s.sse_stream_of(history).unwrap().unwrap().id, 1);
        assert!(s.sse_stream_of(history + 1).unwrap().is_none());

        let all = s.sse_events(1, &EventFilter { limit: 10, ..Default::default() }).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            (all[0].data.as_deref(), all[0].length, all[0].retry),
            (Some("secret_token=abc"), 16, Some(i64::MAX as u64))
        );
        assert_eq!((all[1].event.as_str(), all[1].data.as_deref(), all[1].length), ("ping", None, 0));
        let pings = EventFilter { event: Some("ping".into()), limit: 10, ..Default::default() };
        assert_eq!(s.sse_events(1, &pings).unwrap().len(), 1);
        let hits = EventFilter { contains: Some("token=".into()), limit: 10, ..Default::default() };
        assert_eq!(s.sse_events(1, &hits).unwrap()[0].id, all[0].id);
        let after = EventFilter { after_id: Some(all[0].id), limit: 10, ..Default::default() };
        assert_eq!(s.sse_events(1, &after).unwrap().len(), 1);
        assert_eq!(s.sse_event(all[1].id).unwrap().event, "ping");
        assert_eq!(s.sse_event_counts(1).unwrap(), [("message".to_string(), 1), ("ping".to_string(), 1)]);
        let q = |sql: &str| s.query(sql, &[], 10, 100).unwrap().rows;
        assert_eq!(q("SELECT rowid FROM sse_events_fts WHERE sse_events_fts MATCH 'secret_token'").len(), 1);
        assert!(matches!(s.sse_events(42, &pings), Err(Error::NotFound(_))));

        // A batch that fails leaves the keys as they were: its stream was never written.
        let bad = SseRecord::Event { key: 8, event: Event { time: String::new(), ..event("message", Some("x")) } };
        s.conn.execute_batch("CREATE TRIGGER no_empty_time BEFORE INSERT ON sse_events WHEN new.time = '' BEGIN SELECT RAISE(ABORT, 'no time'); END;").unwrap();
        assert!(s.sse_record(&[open(8), bad], &mut ids).is_err());
        assert!(ids.is_empty());
        assert_eq!(s.sse_streams(&StreamFilter { limit: 10, ..Default::default() }).unwrap().len(), 1);
        s.conn.execute_batch("DROP TRIGGER no_empty_time").unwrap();
        assert!(matches!(s.sse_event(42), Err(Error::NotFound(_))));

        // A stream left open by a proxy that was killed.
        s.sse_record(&[open(5), open(6)], &mut ids).unwrap();
        let newest = s.sse_streams(&StreamFilter { limit: 1, newest: true, ..Default::default() }).unwrap();
        assert_eq!(newest[0].id, 3);
        let open_ones = StreamFilter { state: Some("open".into()), limit: 10, ..Default::default() };
        assert_eq!(s.sse_streams(&open_ones).unwrap().len(), 2);
        assert_eq!(s.sse_close_stale("proxy", "proxy stopped").unwrap(), 2);
        let stale = s.sse_stream(2).unwrap();
        assert_eq!((stale.state.as_str(), stale.error.as_deref()), ("closed", Some("proxy stopped")));
        // What an open stream already said stays.
        s.sse_record(&[open(7), SseRecord::Note { key: 7, truncated: true, error: "over the cap".into() }], &mut ids)
            .unwrap();
        s.sse_close_stale("proxy", "proxy stopped").unwrap();
        let stale = s.sse_stream(4).unwrap();
        assert_eq!((stale.truncated, stale.error.as_deref()), (true, Some("over the cap; proxy stopped")));
    }

    #[test]
    fn records_a_stream_a_sender_read() {
        let mut s = Store::open_in_memory().unwrap();
        let history = s.record(&capture(b"data: a\n\n")).unwrap();
        let read = crate::sse::StreamRead {
            opened: "2026-11-09T10:00:00.000Z".into(),
            events: vec![event("message", Some("a"))],
            stopped: crate::sse::Stopped::Wait,
            truncated: false,
            note: None,
        };
        let id = s.sse_record_read(history, "send", "http://a.test/events", "a.test", &read).unwrap();
        let stream = s.sse_stream(id).unwrap();
        assert_eq!((stream.source.as_str(), stream.state.as_str(), stream.events), ("send", "closed", 1));
        assert_eq!(stream.time, "2026-11-09T10:00:00.000Z");
        assert_eq!((stream.ended.as_deref(), stream.history_id), (Some("stopped"), Some(history)));
        assert!(stream.error.unwrap().contains("--stream-wait"));
        assert_eq!(s.sse_events(id, &EventFilter { limit: 5, ..Default::default() }).unwrap().len(), 1);
    }
}
