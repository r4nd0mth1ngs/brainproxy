//! `findings verify`: sends a finding's request with and without its payload, now, and says
//! what differs, so a person (or an agent) can judge whether the finding is real.
//!
//! The request without the payload is the one the scan built the attack from (the finding's
//! `base_history_id`). A finding from before brainproxy kept it falls back to a request in
//! history that the attack request repeats with only the payload changed; with neither, it is
//! refused. Both requests are sent again as recorded (`--request` swaps in an edited attack,
//! as Replay sends one), alternately `--repeat` times, each recorded with source `retest` like a
//! retest's, which the background passive scan leaves alone. Nothing about the finding changes:
//! what the responses mean is for whoever reads them.

use std::path::Path;

use brainproxy_core::diff::{diff, DiffMode};
use brainproxy_core::store::{HistoryItem, Store};
use brainproxy_core::Error;
use serde_json::{json, Value};

use crate::output::Out;
use crate::retest_cmd::{request_headers, Resender, Resent, METHOD_OVERRIDES, SAFE_METHODS};

/// Most times each request is sent: enough to tell a delay from noise, few enough not to flood.
const MAX_REPEAT: u32 = 20;
/// Body changes listed in the output; `history show` / `diff` have the rest.
const MAX_CHANGES: usize = 20;
/// Requests in history looked at for a baseline when the scan didn't record one.
const MATCH_CANDIDATES: i64 = 200;

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// The finding to verify.
    id: i64,
    /// Send each request this many times, alternately (at most 20): repeated sends tell a
    /// delay the payload causes from a slow server.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=MAX_REPEAT as i64))]
    repeat: u32,
    /// Auth profile to send as (its session is applied, logging in if it needs to).
    #[arg(long)]
    auth: Option<String>,
    /// Send requests that may change data (POST, PUT, DELETE, ...). Without it only GET, HEAD
    /// and OPTIONS are sent again.
    #[arg(long)]
    allow_unsafe: bool,
    /// Timeout in seconds, per request.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    /// Send this raw request (a file, or - for stdin) as the one with the payload, in place of
    /// the finding's attack: an attack edited by hand. It goes to the attack's target.
    #[arg(long, value_name = "FILE")]
    request: Option<String>,
}

/// A send's history row, and its error when it got no response.
type Row = (i64, Option<String>);

/// One send of one side.
struct Send {
    history_id: i64,
    status: Option<u16>,
    length: Option<i64>,
    duration_ms: Option<i64>,
    /// Whether the finding's evidence is in the response; None without evidence or response.
    evidence: Option<bool>,
    error: Option<String>,
    body: Vec<u8>,
}

impl Send {
    fn json(&self) -> Value {
        let mut v = json!({
            "history_id": self.history_id,
            "status": self.status,
            "length": self.length,
            "duration_ms": self.duration_ms,
            "evidence": self.evidence,
        });
        if let Some(e) = &self.error {
            v["error"] = json!(e);
        }
        v
    }
}

pub fn verify(project: &Path, a: VerifyArgs, out: &Out) -> Result<(), Error> {
    if a.request.as_deref().is_some_and(|f| f != "-") && crate::mcp::in_tool_call() {
        return Err(Error::InvalidInput(
            "--request FILE: through MCP the request comes from the call's stdin (--request -): a file is \
             sent and recorded as it is, so any file the server can read could reach the target"
                .into(),
        ));
    }
    let store = Store::open(project)?;
    let f = store.finding_get(a.id)?;
    if f["state"] == "removed" {
        return Err(Error::Conflict(format!("finding {} was removed", a.id)));
    }
    let attack = f["attack"].as_str().unwrap_or_default().to_string();
    let evidence = f["evidence"].as_str().unwrap_or_default().to_string();
    if attack.is_empty() && f["base_history_id"].is_null() {
        return Err(Error::InvalidInput(format!(
            "finding {} has no payload to compare without: only an active scan's finding, which records its \
             attack and the request it was built from, can be verified",
            a.id
        )));
    }
    // The attack is the first sighting's exchange, the one the base and the evidence go with.
    let attack_id = f["history_id"]
        .as_i64()
        .ok_or_else(|| Error::InvalidInput(format!("finding {} has no recorded request to send again", a.id)))?;
    let attack_item = store.get(attack_id)?;
    let (base_id, from) = match f["base_history_id"].as_i64() {
        Some(id) => (id, "scan"),
        None => {
            let none = || {
                format!(
                    "finding {} has no baseline: no request without the payload was recorded (it was found \
                     before brainproxy kept the request a scan starts from), and none in history repeats its \
                     attack request with only the payload changed; send one without the payload by hand \
                     (Replay), or scan again so the finding records one",
                    a.id
                )
            };
            match matching_base(&store, &attack_item, &attack)? {
                Some(id) => (id, "history"),
                None => return Err(Error::InvalidInput(none())),
            }
        }
    };
    let base_item = store.get(base_id)?;
    for (what, item) in [("request without the payload", &base_item), ("attack request", &attack_item)] {
        if item.entry.error.as_deref().is_some_and(|e| e.starts_with("out of scope")) {
            return Err(Error::OutOfScope(format!(
                "finding {}'s {what} (history {}) was refused for the scope when it was sent, so it isn't sent again",
                a.id, item.entry.id
            )));
        }
    }
    let attack_request = match &a.request {
        Some(file) => {
            let bytes = match file.as_str() {
                "-" => {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
                path => std::fs::read(path)?,
            };
            if bytes.iter().all(u8::is_ascii_whitespace) {
                return Err(Error::InvalidInput("--request: the request is empty".into()));
            }
            bytes
        }
        None => attack_item.request.clone(),
    };
    for (what, request, method) in [
        ("request without the payload", &base_item.request, &base_item.entry.method),
        ("attack request", &attack_request, &attack_item.entry.method),
    ] {
        let method = effective_method(request, method);
        if !a.allow_unsafe && !SAFE_METHODS.contains(&method.as_str()) {
            return Err(Error::InvalidInput(format!(
                "finding {}'s {what} is a {method}, which may change data when sent again; pass --allow-unsafe \
                 to send it",
                a.id
            )));
        }
    }

    let mut sender = Resender::open(project, &store, a.auth.as_deref(), a.timeout)?;
    drop(store);
    // Each side's rows, with the error of a send that got no response.
    let mut rows: (Vec<Row>, Vec<Row>) = (Vec::new(), Vec::new());
    // Alternately, so a server that slows down or changes meanwhile affects both alike.
    let sent = (|| {
        for _ in 0..a.repeat {
            for (side, target, request) in [
                (&mut rows.0, &base_item.target, &base_item.request),
                (&mut rows.1, &attack_item.target, &attack_request),
            ] {
                side.push(match sender.send(target, request)? {
                    Resent::Answered(id) => (id, None),
                    Resent::Failed(id, e) => (id, Some(e.to_string())),
                });
            }
        }
        Ok::<_, Error>(())
    })();
    sender.finish();
    sent?;

    let store = Store::open(project)?;
    let read = |side: &[Row]| -> Result<Vec<Send>, Error> {
        side.iter().map(|(id, error)| read_send(&store, *id, error.clone(), &evidence)).collect()
    };
    let (without, with) = (read(&rows.0)?, read(&rows.1)?);
    let differences = differences(&without, &with, !evidence.is_empty());
    let side = |sends: &[Send], request: i64| {
        let answered: Vec<&Send> = sends.iter().filter(|s| s.status.is_some()).collect();
        json!({
            "request_history_id": request,
            "history_ids": sends.iter().map(|s| s.history_id).collect::<Vec<_>>(),
            "status": answered.first().and_then(|s| s.status),
            "length": median(answered.iter().filter_map(|s| s.length)),
            "duration_ms": median(answered.iter().filter_map(|s| s.duration_ms)),
            "evidence": evidence_count(sends),
            "answered": answered.len(),
            "sends": sends.iter().map(Send::json).collect::<Vec<_>>(),
        })
    };
    let data = json!({
        "id": a.id,
        "name": f["name"],
        "param": f["param"],
        "attack": attack,
        "evidence": evidence,
        // scan: recorded by the scan that found it; history: a request in history the attack
        // request repeats with only the payload changed (a finding from before it was recorded).
        "baseline_from": from,
        "edited_request": a.request.is_some(),
        "repeat": a.repeat,
        "without": side(&without, base_id),
        "with": side(&with, attack_id),
        "differences": differences,
    });
    out.ok(data.clone(), || text(&data));
    Ok(())
}

/// The method the application acts on: a method-override header's, else the request line's.
fn effective_method(request: &[u8], method: &str) -> String {
    let overridden = request_headers(request).into_iter().find_map(|(k, v)| {
        METHOD_OVERRIDES.iter().any(|h| k.eq_ignore_ascii_case(h)).then(|| v.trim().to_ascii_uppercase())
    });
    match overridden {
        Some(m) => m,
        None => {
            let line = request.split(|&b| b == b' ').next().unwrap_or_default();
            let m = String::from_utf8_lossy(line).trim().to_ascii_uppercase();
            if m.is_empty() {
                method.to_ascii_uppercase()
            } else {
                m
            }
        }
    }
}

fn read_send(store: &Store, id: i64, error: Option<String>, evidence: &str) -> Result<Send, Error> {
    let item = store.get(id)?;
    let answered = item.entry.status.is_some();
    let body = item.resp_body.clone().unwrap_or_default();
    let found = |hay: &[u8]| !evidence.is_empty() && find(hay, evidence.as_bytes());
    Ok(Send {
        history_id: id,
        status: item.entry.status,
        length: item.entry.resp_body_length.or(answered.then_some(body.len() as i64)),
        duration_ms: item.entry.duration_ms,
        evidence: (answered && !evidence.is_empty()).then(|| found(&item.response) || found(&body)),
        error: error.or_else(|| item.entry.error.clone().filter(|_| !answered)),
        body,
    })
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// How many sends showed the evidence; None without evidence to look for, or no response.
fn evidence_count(sends: &[Send]) -> Option<usize> {
    let looked: Vec<bool> = sends.iter().filter_map(|s| s.evidence).collect();
    (!looked.is_empty()).then(|| looked.iter().filter(|&&b| b).count())
}

fn median(values: impl Iterator<Item = i64>) -> Option<i64> {
    let mut v: Vec<i64> = values.collect();
    v.sort_unstable();
    (!v.is_empty()).then(|| v[v.len() / 2])
}

/// What differs between the responses without and with the payload.
fn differences(without: &[Send], with: &[Send], has_evidence: bool) -> Value {
    let answered = |s: &[Send]| s.iter().filter_map(|x| x.status).collect::<Vec<_>>();
    let (sa, sb) = (answered(without), answered(with));
    let mut notes: Vec<String> = Vec::new();
    let status_changed = !sa.is_empty() && !sb.is_empty() && {
        let (mut a, mut b) = (sa.clone(), sb.clone());
        a.sort_unstable();
        a.dedup();
        b.sort_unstable();
        b.dedup();
        a != b
    };
    if status_changed {
        notes.push(format!("status {} without the payload, {} with it", join(&sa), join(&sb)));
    }
    let len = |s: &[Send]| median(s.iter().filter(|x| x.status.is_some()).filter_map(|x| x.length));
    let length_delta = len(with).zip(len(without)).map(|(b, a)| b - a);
    if let Some(d) = length_delta.filter(|d| *d != 0) {
        notes.push(format!("{d:+} bytes with the payload"));
    }
    let time = |s: &[Send]| median(s.iter().filter(|x| x.status.is_some()).filter_map(|x| x.duration_ms));
    let duration_delta = time(with).zip(time(without)).map(|(b, a)| b - a);
    // Under a second either way is the network's noise, not something a payload did.
    if let Some(d) = duration_delta.filter(|d| d.abs() >= 1000) {
        notes.push(format!("{} ms {} with the payload", d.abs(), if d > 0 { "slower" } else { "faster" }));
    }
    let failed = |s: &[Send]| s.iter().filter(|x| x.status.is_none()).count();
    if failed(with) > failed(without) {
        notes.push(format!("{} of {} sends with the payload got no response", failed(with), with.len()));
    }
    let evidence_only = has_evidence.then(|| {
        let shown = |s: &[Send]| s.iter().filter(|x| x.evidence == Some(true)).count();
        let answered_with = with.iter().filter(|x| x.status.is_some()).count();
        answered_with > 0 && shown(with) == answered_with && shown(without) == 0
    });
    if has_evidence {
        let seen = |s: &[Send]| s.iter().any(|x| x.evidence == Some(true));
        notes.push(match (seen(without), seen(with)) {
            (false, true) if evidence_only == Some(true) => "the evidence only with the payload".into(),
            (false, true) => "the evidence only with the payload, but not every time".into(),
            (true, true) => "the evidence with and without the payload".into(),
            (true, false) => "the evidence only without the payload".into(),
            (false, false) => "the evidence in neither response".into(),
        });
    }
    // The last answered response of each side, body against body.
    let last = |s: &[Send]| s.iter().rev().find(|x| x.status.is_some()).map(|x| x.body.clone());
    let body = match (last(without), last(with)) {
        (Some(a), Some(b)) => {
            let d = diff(&a, &b, DiffMode::Lines, MAX_CHANGES, 0);
            if !d.identical && !notes.iter().any(|n| n.contains("bytes")) {
                notes.push("the bodies differ".into());
            }
            json!({
                "identical": d.identical,
                "similarity": (d.similarity * 1000.0).round() / 1000.0,
                "deletions": d.deletions,
                "insertions": d.insertions,
                "changes": d.changes,
                "truncated": d.truncated,
            })
        }
        _ => Value::Null,
    };
    json!({
        "status_changed": status_changed,
        "length_delta": length_delta,
        "duration_delta_ms": duration_delta,
        "evidence_only_with_payload": evidence_only,
        "body": body,
        "summary": notes,
    })
}

fn join(statuses: &[u16]) -> String {
    let mut s = statuses.to_vec();
    s.dedup();
    s.iter().map(u16::to_string).collect::<Vec<_>>().join("/")
}

fn text(d: &Value) -> String {
    let mut out = format!(
        "finding {} ({}{}): sent {}× without and with the payload\n",
        d["id"],
        d["name"].as_str().unwrap_or_default(),
        d["param"].as_str().filter(|p| !p.is_empty()).map(|p| format!(", {p}")).unwrap_or_default(),
        d["repeat"]
    );
    for (label, key) in [("without", "without"), ("with   ", "with")] {
        for s in d[key]["sends"].as_array().into_iter().flatten() {
            let ev = match s["evidence"].as_bool() {
                Some(true) => "  evidence: yes",
                Some(false) => "  evidence: no",
                None => "",
            };
            let line = match s["status"].as_u64() {
                Some(status) => format!(
                    "{status}  {} B  {} ms{ev}",
                    s["length"].as_i64().unwrap_or(0),
                    s["duration_ms"].as_i64().unwrap_or(0)
                ),
                None => format!("no response: {}", s["error"].as_str().unwrap_or("failed")),
            };
            out.push_str(&format!("  {label}  #{:<6} {line}\n", s["history_id"].as_i64().unwrap_or(0)));
        }
    }
    let notes: Vec<&str> =
        d["differences"]["summary"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    if notes.is_empty() {
        out.push_str("  no difference\n");
    } else {
        out.push_str(&format!("  differs: {}\n", notes.join("; ")));
    }
    out
}

/// A request in history the attack request repeats with only the payload changed: the
/// baseline of a finding that didn't record one. The latest such request, if any.
fn matching_base(store: &Store, attack: &HistoryItem, payload: &str) -> Result<Option<i64>, Error> {
    let r = store.query(
        &format!(
            "SELECT h.id FROM history h, history a WHERE a.id = ?1 AND h.id != a.id AND h.method = a.method \
             AND h.host = a.host AND h.port = a.port AND h.path = a.path AND h.status IS NOT NULL \
             AND h.source NOT IN ('scan', 'retest') ORDER BY h.id DESC LIMIT {MATCH_CANDIDATES}"
        ),
        &[attack.entry.id.to_string()],
        MATCH_CANDIDATES as usize,
        50,
    )?;
    for id in r.rows.iter().filter_map(|row| row[0].as_i64()) {
        let item = store.get(id)?;
        if let Some(spans) = changed_spans(&item.request, &attack.request) {
            let related = |s: &[u8]| payload_part(&String::from_utf8_lossy(s), payload);
            if !spans.is_empty() && spans.iter().all(|r| related(&attack.request[r.clone()])) {
                return Ok(Some(id));
            }
        }
    }
    Ok(None)
}

/// Where `attack` differs from `base`, as ranges of `attack`: each changed head line's
/// changed part (Content-Length and Connection lines left out: a payload changes the one, a
/// scan the other), and the body's. None when the heads have different numbers of lines.
pub(crate) fn changed_spans(base: &[u8], attack: &[u8]) -> Option<Vec<std::ops::Range<usize>>> {
    let split = |m: &[u8]| -> (usize, usize) {
        let crlf = m.windows(4).position(|w| w == b"\r\n\r\n").map(|i| (i, i + 4));
        let lf = m.windows(2).position(|w| w == b"\n\n").map(|i| (i, i + 2));
        match (crlf, lf) {
            (Some(a), Some(b)) => {
                if a.0 <= b.0 {
                    a
                } else {
                    b
                }
            }
            (a, b) => a.or(b).unwrap_or((m.len(), m.len())),
        }
    };
    let lines = |m: &[u8], end: usize| -> Vec<std::ops::Range<usize>> {
        let mut out = Vec::new();
        let mut at = 0;
        for (i, &b) in m[..end].iter().enumerate() {
            if b == b'\n' {
                out.push(at..i);
                at = i + 1;
            }
        }
        out.push(at..end);
        out
    };
    let ((bh, bb), (ah, ab)) = (split(base), split(attack));
    let (bl, al) = (lines(base, bh), lines(attack, ah));
    if bl.len() != al.len() {
        return None;
    }
    let skipped = |l: &[u8]| {
        let l = String::from_utf8_lossy(l).to_ascii_lowercase();
        l.starts_with("content-length:") || l.starts_with("connection:")
    };
    let mut spans = Vec::new();
    for (b, a) in bl.iter().zip(&al) {
        let (bs, as_) = (&base[b.clone()], &attack[a.clone()]);
        if bs != as_ && !skipped(as_) {
            let r = middle(bs, as_);
            spans.push(a.start + r.start..a.start + r.end);
        }
    }
    let (bs, as_) = (&base[bb.min(base.len())..], &attack[ab.min(attack.len())..]);
    if bs != as_ {
        let r = middle(bs, as_);
        spans.push(ab + r.start..ab + r.end);
    }
    Some(spans)
}

/// The part of `b` that differs from `a`, after their common start and end.
fn middle(a: &[u8], b: &[u8]) -> std::ops::Range<usize> {
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let max = a.len().min(b.len()) - pre;
    let suf = a.iter().rev().zip(b.iter().rev()).take(max).take_while(|(x, y)| x == y).count();
    pre..b.len() - suf
}

/// Whether `changed` (part of a request) is the payload or part of it, as sent: raw,
/// percent-encoded (spaces as + or %20), or escaped in a JSON string.
fn payload_part(changed: &str, payload: &str) -> bool {
    if changed.is_empty() || payload.is_empty() {
        return false;
    }
    let forms = [
        changed.to_string(),
        percent_decode(changed, false),
        percent_decode(changed, true),
        serde_json::from_str::<String>(&format!("\"{changed}\"")).unwrap_or_default(),
    ];
    forms.iter().any(|f| !f.is_empty() && (payload.contains(f.as_str()) || f.contains(payload)))
}

fn percent_decode(s: &str, plus: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' if plus => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_are_what_the_payload_changed() {
        let base = b"GET /item?q=hi&x=1 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
        let attack = b"GET /item?q=hi%27+OR+1%3D1&x=1 HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n";
        let spans = changed_spans(base, attack).unwrap();
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(&attack[spans[0].clone()], b"%27+OR+1%3D1");
        assert!(payload_part("%27+OR+1%3D1", "hi' OR 1=1"));
        assert!(!payload_part("other", "hi' OR 1=1"));

        // A body: Content-Length changes with it, and isn't the payload.
        let base = b"POST /f HTTP/1.1\nContent-Length: 13\n\n{\"q\":\"hello\"}";
        let attack = b"POST /f HTTP/1.1\nContent-Length: 21\n\n{\"q\":\"hello\\\"<x>\\\"\"}";
        let spans = changed_spans(base, attack).unwrap();
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert!(payload_part(&String::from_utf8_lossy(&attack[spans[0].clone()]), "hello\"<x>\""));
        // Another header layout isn't the same request.
        assert!(changed_spans(b"GET / HTTP/1.1\nA: 1\n\n", b"GET / HTTP/1.1\n\n").is_none());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b+c%2", true), "a b c%2");
        assert_eq!(percent_decode("a+b%zz", false), "a+b%zz");
    }
}
