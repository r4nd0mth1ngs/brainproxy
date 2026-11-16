//! `send --sequence`: the group sent in order (see `brainproxy_core::sequence`), each request
//! recorded just before it goes out and completed once answered, then listed in order with how
//! far the group got.

use std::path::Path;
use std::sync::Arc;

use brainproxy_core::auth::AuthSession;
use brainproxy_core::http::h2::H2Request;
use brainproxy_core::http::{Client, RawRequest, Target};
use brainproxy_core::rules::{EngineRules, Ruled};
use brainproxy_core::sequence::{send_in_order, Connections, Step, Stop};
use brainproxy_core::Error;
use serde_json::{json, Value};

use crate::output::Out;
use crate::{exchange_json, mcp, process, sent, SendArgs};

/// The most requests one sequence takes, as for a race's total.
pub(crate) const MAX: usize = 1000;

/// What `send` set up for the group besides its requests: the rules and what they did to each
/// request, the client, the auth session, and the Host-header warning so far.
pub(crate) struct Setup<'a> {
    pub rules: Option<&'a EngineRules>,
    pub ruled: &'a [Ruled],
    pub client: Client,
    pub session: Option<Arc<AuthSession>>,
    pub host_warning: Option<String>,
}

/// Refuses a sequence the CLI can't send, before anything (a login included) is.
pub(crate) fn check(len: usize, http3: bool) -> Result<(), Error> {
    if len > MAX {
        return Err(Error::InvalidInput(format!("a sequence takes at most {MAX} requests, not {len}")));
    }
    if http3 {
        return Err(Error::InvalidInput(
            "--http3 doesn't go with --sequence: its requests go over TCP (HTTP/1.1, or HTTP/2 with --http2)".into(),
        ));
    }
    Ok(())
}

/// The tags on request `pos` (from 0) of a sequence of `n`: which sequence (`sequence:ID`), how
/// its requests were carried (`sequence-conn:single` or `sequence-conn:separate`), and where in it
/// the request was (`sequence-pos:2/3`).
fn row_tags(id: &str, connections: Connections, pos: usize, n: usize) -> Vec<String> {
    vec![
        format!("sequence:{id}"),
        format!("sequence-conn:{}", connections.name()),
        format!("sequence-pos:{}/{n}", pos + 1),
    ]
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn send(
    project: &Path,
    args: &SendArgs,
    requests: Vec<RawRequest>,
    target: Target,
    setup: Setup<'_>,
    connections: Connections,
    h2: bool,
    out: &Out,
) -> Result<(), Error> {
    let Setup { rules, ruled, client, session, host_warning } = setup;
    // Over HTTP/2, a request it can't carry is refused before anything goes out.
    if h2 {
        for (i, req) in requests.iter().enumerate() {
            H2Request::from_raw(req.as_bytes(), &target).map_err(|e| e.prefixed(&format!("request {i}: ")))?;
        }
    }
    let n = requests.len();
    let sequence_id = brainproxy_core::race::new_race_id()?;
    let lines: Vec<String> = requests
        .iter()
        .map(|req| String::from_utf8_lossy(req.as_bytes()).lines().next().unwrap_or("").to_string())
        .collect();
    let mut log = sent::SentLog::open(project, "send", args.no_store)?.sent_by(&client);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(Error::Io)?;
    // Each request's row, written just before it goes out; `open` is the one out and unanswered.
    let mut ids: Vec<Option<i64>> = vec![None; n];
    let mut open: Option<(usize, i64, Vec<u8>)> = None;
    let outcome = {
        let (log, ids, open) = (&mut log, &mut ids, &mut open);
        let watch = |step: Step<'_>| -> Result<(), Error> {
            match step {
                Step::Sending(i, recorded) => {
                    // A request match-and-replace rules changed says so on its row (and keeps
                    // saying so when the row is completed).
                    log.ruled(ruled.get(i).unwrap_or(&Default::default()));
                    let rows = log.pending_many(&target, recorded, 1, |_| row_tags(&sequence_id, connections, i, n))?;
                    let id = *rows.first().expect("one row is written for one copy");
                    ids[i] = Some(id);
                    *open = Some((i, id, recorded.to_vec()));
                    Ok(())
                }
                Step::Answered(_, ex) => match open.take() {
                    Some((_, id, _)) => log.answered(id, ex),
                    None => Ok(()),
                },
            }
        };
        let sending = send_in_order(&client, session.as_deref(), &target, &requests, connections, h2, watch);
        rt.block_on(async {
            tokio::select! {
                r = sending => Some(r),
                _ = process::interrupted() => None,
            }
        })
    };
    let rows: Vec<i64> = ids.iter().flatten().copied().collect();
    // Rows first: a failure saving the session mustn't leave one pending.
    let seq = match outcome {
        Some(Ok(seq)) => seq,
        Some(Err(e)) => {
            let failed = open.take().map(|(_, id, recorded)| log.failed(id, &target, &recorded, &e.to_string()));
            let _ = session.as_ref().map(|s| s.save());
            return failed.transpose().and(Err(e));
        }
        None => {
            let failed = open.take().map(|(_, id, recorded)| log.failed(id, &target, &recorded, sent::CANCELLED));
            let _ = session.as_ref().map(|s| s.save());
            return failed.transpose().and(Err(sent::cancelled(&rows)));
        }
    };
    // Every row is completed before a store error is reported, so none stays pending.
    let mut store_error = None;
    let mut done = |r: Result<(), Error>| {
        if let Err(e) = r {
            store_error.get_or_insert(e);
        }
    };
    // The request that failed after its row was written: the row says how.
    if let Some((i, id, recorded)) = open.take() {
        let error = seq.results.get(i).and_then(|r| r.as_ref().err()).map(Error::to_string);
        done(log.failed(id, &target, &recorded, error.as_deref().unwrap_or(sent::CANCELLED)));
    }
    let saved = session.as_ref().map(|s| s.save()).transpose();
    let mut items = Vec::with_capacity(n);
    let mut answered = 0;
    for (i, line) in lines.iter().enumerate() {
        let mut item = match seq.results.get(i) {
            Some(Ok(ex)) => {
                answered += 1;
                // As for one send: the row keeps the response as received and, beside it, what
                // the rules made of it, which is what is shown.
                let after = rules
                    .filter(|rules| rules.rewrites_responses(&target))
                    .map(|rules| rules.response(&target, &ex.request, ex.response.clone()))
                    .filter(|after| after.changed());
                if let (Some(after), Some(id)) = (&after, ids[i]) {
                    done(log.ruled_response(id, after));
                }
                let response = after.as_ref().map_or(&ex.response, |after| &after.bytes);
                let mut v = exchange_json(ids[i], &target, &ex.request, response, Some(ex.duration_ms), args.max_body);
                v["outcome"] = json!("answered");
                v
            }
            Some(Err(e)) => json!({"outcome": "failed", "id": ids[i], "error": e.to_string(), "kind": e.kind()}),
            None => json!({"outcome": "not_sent"}),
        };
        item["request"] = json!(i);
        item["request_line"] = json!(line);
        items.push(item);
    }
    if let Some(e) = store_error {
        return Err(e);
    }
    let new_findings = log.scan(&rows)?;
    let clients = [&client].into_iter().chain(session.as_deref().map(|s| s.client()));
    let host_warning = mcp::sent_host_warning(clients, host_warning, out);
    // The requests a stop left out, from `from` on.
    let unsent = |from: usize| match n - from {
        1 => format!("request {from} wasn't sent"),
        _ => format!("requests {from} to {} weren't sent", n - 1),
    };
    // Why it stopped, and the error it ends with: the failed request's (its kind and exit code),
    // saying where in the sequence it was.
    let (stopped, error) = match &seq.stopped {
        None => (Value::Null, None),
        Some(Stop::Failed { at }) => {
            let so = if at + 1 < n { format!(", so {}", unsent(at + 1)) } else { String::new() };
            let prefix = format!("request {at} of the sequence of {n} failed{so}: ");
            let e = seq.results.get(*at).and_then(|r| r.as_ref().err());
            let reason = e.map(Error::to_string).unwrap_or_default();
            let error = e.map_or_else(|| Error::Protocol(prefix.clone()), |e| e.prefixed(&prefix));
            (json!({"request": at, "cause": "failed", "reason": reason}), Some(error))
        }
        Some(Stop::Closed { next, why }) => {
            let message =
                format!("the sequence of {n} stopped after request {}, so {}: {why}", next - 1, unsent(*next));
            (json!({"request": next, "cause": "closed", "reason": why}), Some(Error::Protocol(message)))
        }
    };
    let mut data = json!({
        "sequence": connections.name(),
        "sequence_id": sequence_id,
        "target": target.origin(),
        "http2": h2,
        "connections": seq.connections,
        "total": n,
        "answered": answered,
        "complete": seq.stopped.is_none(),
        "stopped": stopped,
        "results": items,
        "hint": "Each result is one request of the group, in the order sent; outcome is answered, failed, or not_sent \
                 (after a stop). Open a row with history show ID; every row is tagged sequence:SEQUENCE_ID.",
    });
    // A rule whose script failed left that request as it was.
    let rule_errors: Vec<Value> = ruled
        .iter()
        .enumerate()
        .flat_map(|(i, r)| r.failed.iter().map(move |f| json!({"request": i, "id": f.id, "error": f.error})))
        .collect();
    if !rule_errors.is_empty() {
        data["rule_errors"] = json!(rule_errors);
    }
    if new_findings > 0 {
        data["new_findings"] = json!(new_findings);
    }
    if let Some(w) = host_warning {
        data["host_warning"] = json!(w);
    }
    if let Err(e) = saved {
        data["warning"] = json!(format!("the session's state wasn't saved: {e}"));
    }
    let text = text(&data);
    match error {
        None => out.ok(data, || text),
        Some(e) => {
            // The results so far go with the error: in error.data, and as text before it.
            if !out.json() {
                out.raw(format!("{text}\n").as_bytes());
            }
            out.error_data(data);
            return Err(e);
        }
    }
    Ok(())
}

/// The sequence for a person: a line saying how it was sent, then one per request.
fn text(data: &Value) -> String {
    let how = match data["sequence"].as_str() {
        Some("single") => "one connection",
        _ => "a connection each",
    };
    let mut lines = vec![format!(
        "sequence of {} over {how} ({} opened{}) -> {}  [tag sequence:{}]",
        data["total"],
        data["connections"],
        if data["http2"] == true { ", HTTP/2" } else { "" },
        data["target"].as_str().unwrap_or(""),
        data["sequence_id"].as_str().unwrap_or(""),
    )];
    for item in data["results"].as_array().into_iter().flatten() {
        let id = item["id"].as_i64().map(|id| format!("#{id}")).unwrap_or_default();
        let what = match item["outcome"].as_str() {
            Some("answered") => {
                let r = &item["response"];
                format!("{} {} ({} ms)", r["status"], r["reason"].as_str().unwrap_or(""), item["duration_ms"])
            }
            Some("failed") => format!("failed: {}", item["error"].as_str().unwrap_or("")),
            _ => "not sent".into(),
        };
        let (index, line) = (item["request"].as_u64().unwrap_or(0), item["request_line"].as_str().unwrap_or(""));
        lines.push(format!("{index:>4}  {id:<7} {what}  {line}"));
    }
    let stopped = &data["stopped"];
    if let (Some(at), Some(reason)) = (stopped["request"].as_u64(), stopped["reason"].as_str()) {
        lines.push(match stopped["cause"].as_str() {
            Some("closed") => {
                format!("stopped: the connection ended after request {} ({reason})", at.saturating_sub(1))
            }
            _ => format!("stopped: request {at} failed"),
        });
    }
    lines.join("\n")
}
