//! WebSocket connections and messages in the project database. The upgrade request and
//! its 101 response are an ordinary history row; `ws_connections.history_id` points to it.

use std::collections::HashMap;

use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use crate::capture::Capture;
use crate::error::{Error, Result};
use crate::store::{insert_capture, Store};
use crate::ws::{opcode_name, Direction, Message};

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS ws_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    source TEXT NOT NULL,
    history_id INTEGER,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    extensions TEXT,
    protocol TEXT,
    state TEXT NOT NULL DEFAULT 'open',
    closed_time TEXT,
    close_code INTEGER,
    close_reason TEXT,
    messages INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX IF NOT EXISTS ws_connections_host ON ws_connections(host);

CREATE TABLE IF NOT EXISTS ws_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id INTEGER NOT NULL,
    time TEXT NOT NULL,
    direction TEXT NOT NULL,
    opcode TEXT NOT NULL,
    payload BLOB NOT NULL,
    payload_text TEXT,
    length INTEGER NOT NULL,
    compressed INTEGER NOT NULL DEFAULT 0,
    fragments INTEGER NOT NULL DEFAULT 1,
    intercept TEXT
);
CREATE INDEX IF NOT EXISTS ws_messages_connection ON ws_messages(connection_id, id);

CREATE VIRTUAL TABLE IF NOT EXISTS ws_messages_fts USING fts5(
    payload_text, content='ws_messages', content_rowid='id', tokenize=\"unicode61 tokenchars '_'\"
);
CREATE TRIGGER IF NOT EXISTS ws_messages_ai AFTER INSERT ON ws_messages BEGIN
    INSERT INTO ws_messages_fts(rowid, payload_text) VALUES (new.id, new.payload_text);
END;
CREATE TRIGGER IF NOT EXISTS ws_messages_ad AFTER DELETE ON ws_messages BEGIN
    INSERT INTO ws_messages_fts(ws_messages_fts, rowid, payload_text) VALUES ('delete', old.id, old.payload_text);
END;
";

pub const CONNECTION_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Connection id"),
    ("time", "TEXT", "UTC time the upgrade was accepted"),
    ("source", "TEXT", "proxy (browser traffic) or replay (ws send)"),
    ("history_id", "INTEGER", "history.id of the upgrade request and its 101 response"),
    ("url", "TEXT", "ws:// or wss:// URL"),
    ("host", "TEXT", "Target host"),
    ("extensions", "TEXT", "Sec-WebSocket-Extensions the server accepted (e.g. permessage-deflate)"),
    ("protocol", "TEXT", "Sec-WebSocket-Protocol the server chose"),
    ("state", "TEXT", "open or closed"),
    ("closed_time", "TEXT", "When the connection ended"),
    ("close_code", "INTEGER", "Status code of the first close frame (1000 normal, 1006 never sent)"),
    ("close_reason", "TEXT", "Reason text of the first close frame"),
    ("messages", "INTEGER", "Messages recorded"),
    (
        "error",
        "TEXT",
        "Why recording stopped or missed messages (bad frame, over the size limit, recorder behind, proxy stopped)",
    ),
    (
        "origin",
        "TEXT",
        "gui, cli or mcp: who started the proxy or ws send that recorded it (as history.origin); NULL for \
         connections from before brainproxy kept it",
    ),
];

pub const MESSAGE_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Message id, increasing"),
    ("connection_id", "INTEGER", "ws_connections.id"),
    ("time", "TEXT", "UTC time the message (its last frame) arrived"),
    ("direction", "TEXT", "to-server (client to server) or to-client"),
    ("opcode", "TEXT", "text, binary, close, ping, or pong"),
    ("payload", "BLOB", "Payload, unmasked, fragments joined, decompressed"),
    ("payload_text", "TEXT", "Payload as text if valid UTF-8, else NULL"),
    ("length", "INTEGER", "Payload length"),
    ("compressed", "INTEGER", "1 if sent with permessage-deflate"),
    ("fragments", "INTEGER", "Frames the message came in"),
    (
        "intercept",
        "TEXT",
        "edited (payload is what was forwarded) or dropped, if held in intercept; rule, if a match-and-replace \
         rule rewrote the payload",
    ),
];

/// What the proxy (or `ws send`) records, in order. `key` names a connection within one
/// recording process; the database id comes from the `Open` event.
#[derive(Debug, Clone)]
pub enum WsEvent {
    Open {
        key: u64,
        /// The upgrade request and 101 response, stored as a history row.
        capture: Box<Capture>,
        source: &'static str,
        url: String,
        time: String,
    },
    Message {
        key: u64,
        direction: Direction,
        message: Message,
        intercept: Option<&'static str>,
    },
    Close {
        key: u64,
        time: String,
        code: Option<u16>,
        reason: Option<String>,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct WsConnection {
    pub id: i64,
    pub time: String,
    pub source: String,
    pub history_id: Option<i64>,
    pub url: String,
    pub host: String,
    pub extensions: Option<String>,
    pub protocol: Option<String>,
    pub state: String,
    pub closed_time: Option<String>,
    pub close_code: Option<u16>,
    pub close_reason: Option<String>,
    pub messages: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WsMessage {
    pub id: i64,
    pub connection_id: i64,
    pub time: String,
    pub direction: String,
    pub opcode: String,
    #[serde(skip)]
    pub payload: Vec<u8>,
    pub length: i64,
    pub compressed: bool,
    pub fragments: i64,
    pub intercept: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ConnectionFilter {
    pub host: Option<String>,
    pub source: Option<String>,
    pub state: Option<String>,
    pub after_id: Option<i64>,
    pub limit: u32,
    /// The newest `limit` connections (still listed oldest first) instead of the oldest.
    pub newest: bool,
}

#[derive(Debug, Default, Clone)]
pub struct MessageFilter {
    pub direction: Option<String>,
    pub opcode: Option<String>,
    /// Substring of the payload.
    pub contains: Option<String>,
    pub after_id: Option<i64>,
    pub limit: u32,
}

const CONN_COLS: &str = "id, time, source, history_id, url, host, extensions, protocol, state, closed_time, \
    close_code, close_reason, messages, error";
const MSG_COLS: &str = "id, connection_id, time, direction, opcode, payload, length, compressed, fragments, intercept";

fn row_to_connection(r: &rusqlite::Row) -> rusqlite::Result<WsConnection> {
    Ok(WsConnection {
        id: r.get(0)?,
        time: r.get(1)?,
        source: r.get(2)?,
        history_id: r.get(3)?,
        url: r.get(4)?,
        host: r.get(5)?,
        extensions: r.get(6)?,
        protocol: r.get(7)?,
        state: r.get(8)?,
        closed_time: r.get(9)?,
        close_code: r.get(10)?,
        close_reason: r.get(11)?,
        messages: r.get(12)?,
        error: r.get(13)?,
    })
}

fn row_to_message(r: &rusqlite::Row) -> rusqlite::Result<WsMessage> {
    Ok(WsMessage {
        id: r.get(0)?,
        connection_id: r.get(1)?,
        time: r.get(2)?,
        direction: r.get(3)?,
        opcode: r.get(4)?,
        payload: r.get(5)?,
        length: r.get(6)?,
        compressed: r.get(7)?,
        fragments: r.get(8)?,
        intercept: r.get(9)?,
    })
}

/// A connection row for the upgrade recorded as history row `history_id`.
fn insert_connection(
    conn: &rusqlite::Connection,
    history_id: i64,
    capture: &Capture,
    source: &str,
    url: &str,
    time: &str,
) -> Result<i64> {
    let resp = crate::http::parse_response_head(crate::http::client::final_response(&capture.response)).ok();
    let header = |n: &str| resp.as_ref().and_then(|h| h.header(n)).map(str::to_string);
    conn.execute(
        "INSERT INTO ws_connections (time, source, history_id, url, host, extensions, protocol, origin)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            time,
            source,
            history_id,
            url,
            capture.host,
            header("sec-websocket-extensions"),
            header("sec-websocket-protocol"),
            capture.origin.as_deref().unwrap_or(crate::provenance::origin())
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

impl Store {
    /// Records a connection whose upgrade is already history row `history_id` (`capture`, its
    /// request and 101 response); returns its id, for the keys of later [`Store::ws_record`] calls.
    pub fn ws_open_recorded(
        &self,
        history_id: i64,
        capture: &Capture,
        source: &str,
        url: &str,
        time: &str,
    ) -> Result<i64> {
        insert_connection(&self.conn, history_id, capture, source, url, time)
    }

    /// Records WebSocket events in one transaction. `ids` maps the recorder's connection keys
    /// to database ids across calls; a closed connection's key is removed. Events for a key
    /// with no `Open` (it failed to record) are skipped.
    pub fn ws_record(&mut self, events: &[WsEvent], ids: &mut HashMap<u64, i64>) -> Result<()> {
        // A batch that fails is rolled back whole: the keys it opened or closed must be too, or
        // later messages would be written under a rolled-back id, which AUTOINCREMENT hands to
        // the next connection.
        let before = ids.clone();
        let result = self.ws_record_in_tx(events, ids);
        if result.is_err() {
            *ids = before;
        }
        result
    }

    fn ws_record_in_tx(&mut self, events: &[WsEvent], ids: &mut HashMap<u64, i64>) -> Result<()> {
        let tx = self.write_tx()?;
        for e in events {
            match e {
                WsEvent::Open { key, capture, source, url, time } => {
                    let history_id = insert_capture(&tx, capture)?;
                    ids.insert(*key, insert_connection(&tx, history_id, capture, source, url, time)?);
                }
                WsEvent::Message { key, direction, message, intercept } => {
                    let Some(&conn) = ids.get(key) else { continue };
                    let text = std::str::from_utf8(&message.payload).ok();
                    tx.execute(
                        "INSERT INTO ws_messages (connection_id, time, direction, opcode, payload, payload_text, length,
                            compressed, fragments, intercept)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            conn,
                            message.time,
                            direction.as_str(),
                            opcode_name(message.opcode),
                            message.payload,
                            text,
                            message.payload.len() as i64,
                            message.compressed,
                            message.fragments,
                            intercept
                        ],
                    )?;
                    tx.execute("UPDATE ws_connections SET messages = messages + 1 WHERE id = ?1", [conn])?;
                }
                WsEvent::Close { key, time, code, reason, error } => {
                    let Some(conn) = ids.remove(key) else { continue };
                    tx.execute(
                        "UPDATE ws_connections SET state = 'closed', closed_time = ?1, close_code = ?2,
                            close_reason = ?3, error = COALESCE(error, ?4)
                         WHERE id = ?5",
                        params![time, code, reason, error, conn],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Marks connections of `source` still open as closed, with `error` as the reason
    /// (a proxy that stopped can't close them itself).
    pub fn ws_close_stale(&self, source: &str, error: &str) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE ws_connections SET state = 'closed', closed_time = ?1, error = COALESCE(error, ?2)
             WHERE state = 'open' AND source = ?3",
            params![crate::ws::now_iso(), error, source],
        )?)
    }

    /// Marks connection `id` closed with `error` as the reason, if it is still open (one whose
    /// `ws send` was killed). Returns whether it was.
    pub fn ws_close_open(&self, id: i64, error: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE ws_connections SET state = 'closed', closed_time = ?1, error = COALESCE(error, ?2)
             WHERE id = ?3 AND state = 'open'",
            params![crate::ws::now_iso(), error, id],
        )? > 0)
    }

    /// Ids of the open connections of `source`.
    pub fn ws_open_ids(&self, source: &str) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare("SELECT id FROM ws_connections WHERE state = 'open' AND source = ?1")?;
        let ids = stmt.query_map([source], |r| r.get(0))?;
        Ok(ids.collect::<std::result::Result<_, _>>()?)
    }

    pub fn ws_connections(&self, f: &ConnectionFilter) -> Result<Vec<WsConnection>> {
        let order = if f.newest { "DESC" } else { "" };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT * FROM (SELECT {CONN_COLS} FROM ws_connections
                WHERE (?1 IS NULL OR host = ?1) AND (?2 IS NULL OR source = ?2) AND (?3 IS NULL OR state = ?3)
                    AND (?4 IS NULL OR id > ?4)
                ORDER BY id {order} LIMIT ?5)
             ORDER BY id"
        ))?;
        let rows = stmt.query_map(params![f.host, f.source, f.state, f.after_id, f.limit], row_to_connection)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn ws_connection(&self, id: i64) -> Result<WsConnection> {
        self.conn
            .query_row(&format!("SELECT {CONN_COLS} FROM ws_connections WHERE id = ?1"), [id], row_to_connection)
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("WebSocket connection {id}")))
    }

    /// Message counts of a connection by direction and opcode: [(direction, opcode, count)].
    pub fn ws_message_counts(&self, connection: i64) -> Result<Vec<(String, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT direction, opcode, count(*) FROM ws_messages WHERE connection_id = ?1
             GROUP BY direction, opcode ORDER BY direction, opcode",
        )?;
        let rows = stmt.query_map([connection], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn ws_messages(&self, connection: i64, f: &MessageFilter) -> Result<Vec<WsMessage>> {
        self.ws_connection(connection)?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {MSG_COLS} FROM ws_messages
             WHERE connection_id = ?1 AND (?2 IS NULL OR direction = ?2) AND (?3 IS NULL OR opcode = ?3)
                AND (?4 IS NULL OR instr(payload, CAST(?4 AS BLOB)) > 0) AND (?5 IS NULL OR id > ?5)
             ORDER BY id LIMIT ?6"
        ))?;
        let rows = stmt
            .query_map(params![connection, f.direction, f.opcode, f.contains, f.after_id, f.limit], row_to_message)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn ws_message(&self, id: i64) -> Result<WsMessage> {
        self.conn
            .query_row(&format!("SELECT {MSG_COLS} FROM ws_messages WHERE id = ?1"), [id], row_to_message)
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("WebSocket message {id}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Target;
    use crate::ws::{close_payload, OP_CLOSE, OP_TEXT};

    fn open_event(key: u64) -> WsEvent {
        let target = Target::from_url("http://a.test").unwrap();
        let capture = Capture::new(
            "proxy",
            &target,
            b"GET /chat HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\n\r\n",
            Some(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"),
            Some(3),
            None,
        );
        WsEvent::Open {
            key,
            capture: Box::new(capture),
            source: "proxy",
            url: "ws://a.test/chat".into(),
            time: crate::ws::now_iso(),
        }
    }

    #[test]
    fn a_failed_batch_leaves_the_keys_as_they_were() {
        let mut s = Store::open_in_memory().unwrap();
        let mut ids = HashMap::new();
        let msg = |key, p: &[u8]| WsEvent::Message {
            key,
            direction: Direction::ToClient,
            message: Message::new(OP_TEXT, p.to_vec()),
            intercept: None,
        };
        s.conn
            .execute_batch(
                "CREATE TRIGGER no_fail BEFORE INSERT ON ws_messages WHEN new.payload_text = 'fail'
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        // Connection 1's batch is rolled back whole: its key mustn't keep the id it was given.
        assert!(s.ws_record(&[open_event(1), msg(1, b"fail")], &mut ids).is_err());
        assert!(ids.is_empty());
        s.conn.execute_batch("DROP TRIGGER no_fail").unwrap();
        // So connection 2, which AUTOINCREMENT gives the same id, gets only its own messages.
        s.ws_record(&[open_event(2), msg(1, b"lost: connection 1 never opened"), msg(2, b"mine")], &mut ids).unwrap();
        let conns = s.ws_connections(&ConnectionFilter { limit: 10, ..Default::default() }).unwrap();
        assert_eq!(conns.len(), 1);
        let all = MessageFilter { limit: 10, ..Default::default() };
        let payloads: Vec<_> = s.ws_messages(conns[0].id, &all).unwrap().into_iter().map(|m| m.payload).collect();
        assert_eq!(payloads, [b"mine".to_vec()]);
    }

    #[test]
    fn records_connections_and_messages() {
        let mut s = Store::open_in_memory().unwrap();
        let mut ids = HashMap::new();
        let msg = |key, dir, op, p: &[u8]| WsEvent::Message {
            key,
            direction: dir,
            message: Message::new(op, p.to_vec()),
            intercept: None,
        };
        s.ws_record(
            &[
                open_event(7),
                msg(7, Direction::ToServer, OP_TEXT, b"{\"subscribe\":\"prices\"}"),
                msg(7, Direction::ToClient, OP_TEXT, b"secret_token=abc"),
                msg(99, Direction::ToClient, OP_TEXT, b"unknown key: skipped"),
            ],
            &mut ids,
        )
        .unwrap();
        s.ws_record(
            &[
                msg(7, Direction::ToClient, OP_CLOSE, &close_payload(1000, "bye")),
                WsEvent::Close {
                    key: 7,
                    time: crate::ws::now_iso(),
                    code: Some(1000),
                    reason: Some("bye".into()),
                    error: None,
                },
            ],
            &mut ids,
        )
        .unwrap();
        assert!(ids.is_empty());

        s.ws_record(&[open_event(8)], &mut ids).unwrap();
        let newest = s.ws_connections(&ConnectionFilter { limit: 1, newest: true, ..Default::default() }).unwrap();
        assert_eq!(newest[0].id, 2);
        let conns = s.ws_connections(&ConnectionFilter { limit: 1, ..Default::default() }).unwrap();
        assert_eq!(conns.len(), 1);
        let c = &conns[0];
        assert_eq!((c.state.as_str(), c.messages, c.close_code), ("closed", 3, Some(1000)));
        assert_eq!(c.extensions.as_deref(), Some("permessage-deflate"));
        assert_eq!(s.get(c.history_id.unwrap()).unwrap().entry.status, Some(101));

        let to_client = MessageFilter { direction: Some("to-client".into()), limit: 10, ..Default::default() };
        assert_eq!(s.ws_messages(c.id, &to_client).unwrap().len(), 2);
        let hits = MessageFilter { contains: Some("subscribe".into()), limit: 10, ..Default::default() };
        assert_eq!(s.ws_messages(c.id, &hits).unwrap()[0].direction, "to-server");
        let q = |sql: &str| s.query(sql, &[], 10, 100).unwrap().rows;
        assert_eq!(q("SELECT rowid FROM ws_messages_fts WHERE ws_messages_fts MATCH 'secret_token'").len(), 1);
        assert!(matches!(s.ws_messages(42, &to_client), Err(Error::NotFound(_))));
    }

    #[test]
    fn stale_connections_are_closed() {
        let mut s = Store::open_in_memory().unwrap();
        s.ws_record(&[open_event(1)], &mut HashMap::new()).unwrap();
        assert_eq!(s.ws_close_stale("proxy", "proxy stopped").unwrap(), 1);
        let c = s.ws_connection(1).unwrap();
        assert_eq!((c.state.as_str(), c.error.as_deref()), ("closed", Some("proxy stopped")));
    }
}
