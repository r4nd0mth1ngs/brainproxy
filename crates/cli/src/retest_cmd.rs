//! `findings retest`: sends a finding's request again and records whether the finding is
//! still there.
//!
//! A passive finding's latest request is sent again (with an auth profile, when one is given)
//! and recorded with source `retest`, which the background passive scan leaves alone. The
//! finding's own rule (or passive check) then reads that one response: the finding is still
//! present when the rule raises it there again. Nothing else moves the finding's state, so
//! `--no-mark` records the outcome only. A rule that is switched off can't tell, and neither
//! can a reply of another status class than the original (a login redirect, an error page):
//! both are refused rather than taken as "fixed".
//!
//! An active finding's evidence is the attack exchange, not the request the scan started
//! from, and its rule may send other methods; it is retested by running the scan again, as
//! the error says. Findings added by hand are retested by hand, access-control findings with
//! `authz run`.

use std::path::Path;

use brainproxy_core::auth::Attempt;
use brainproxy_core::http::{Client, RawRequest, SendOptions};
use brainproxy_core::scan::findings_db::fingerprint;
use brainproxy_core::scan::issues::Retest;
// A retest's request is recorded with source RETEST_SOURCE, which the background passive scan
// never reads, so only the retest judges it.
use brainproxy_core::scan::passive::{self, PassiveSettings, RETEST_SOURCE};

use brainproxy_core::store::Store;
use serde_json::{json, Value};

use brainproxy_core::Error;

use crate::output::Out;
use crate::{auth_cmd, process, sent};

/// Methods a retest sends without being told it may: they shouldn't change anything.
const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

#[derive(clap::Args)]
pub struct RetestArgs {
    /// The finding to retest.
    id: i64,
    /// Auth profile to send as (its session is applied, logging in if it needs to).
    #[arg(long)]
    auth: Option<String>,
    /// Send a request that may change data (POST, PUT, DELETE, ...). Without it only GET,
    /// HEAD and OPTIONS are sent again.
    #[arg(long)]
    allow_unsafe: bool,
    /// Record the outcome only; leave the finding's state as it is.
    #[arg(long)]
    no_mark: bool,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
}

pub fn retest(project: &Path, a: RetestArgs, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    // Traffic recorded but not scanned yet may hold a newer sighting of the finding.
    passive::scan_pending(&mut store)?;
    let f = store.finding_get(a.id)?;
    let source = f["source"].as_str().unwrap_or_default().to_string();
    let history_id = f["last_history_id"].as_i64().or(f["history_id"].as_i64());
    match source.as_str() {
        "passive" => {}
        "active" => return Err(Error::InvalidInput(rescan_hint(a.id, &f, history_id))),
        "manual" => {
            return Err(Error::InvalidInput(format!(
                "finding {} was added by hand: test it again by hand, then `findings mark {} --state fixed` \
                 (or open) with a note",
                a.id, a.id
            )))
        }
        "authz" => {
            return Err(Error::InvalidInput(format!(
                "finding {} is an access-control finding: retest it with `authz run`",
                a.id
            )))
        }
        s => return Err(Error::InvalidInput(format!("finding {} from {s:?} can't be retested", a.id))),
    }
    if f["state"] == "removed" {
        return Err(Error::Conflict(format!("finding {} was removed", a.id)));
    }
    let history_id = history_id
        .ok_or_else(|| Error::InvalidInput(format!("finding {} has no recorded request to send again", a.id)))?;
    // The rule must be able to look: one switched off would call every finding fixed.
    let settings: PassiveSettings = store.setting(passive::SETTINGS_KEY)?;
    let alert_ref = f["alert_ref"].as_str().unwrap_or_default().to_string();
    let rule = f["rule_id"].as_i64().unwrap_or(0);
    let off = match alert_ref.strip_prefix("check:") {
        Some(check) => settings.disabled_checks.iter().any(|c| c == check),
        None => settings.disabled.iter().any(|&r| i64::from(r) == rule),
    };
    if off {
        return Err(Error::Conflict(format!(
            "finding {}'s rule ({alert_ref}) is switched off, so a retest can't tell whether it is still there; \
             switch it on (scan enable) first",
            a.id
        )));
    }
    // Nor can one that isn't there any more (a local check removed, a rule this build lacks).
    let loaded = match alert_ref.strip_prefix("check:") {
        Some(check) => passive::checks().iter().any(|c| c.id() == check),
        None => passive::all_rules().iter().any(|r| i64::from(r.id()) == rule),
    };
    if !loaded {
        return Err(Error::Conflict(format!(
            "finding {}'s rule ({alert_ref}) isn't loaded (a check removed, or from another build), so a retest \
             can't tell whether it is still there",
            a.id
        )));
    }
    let item = store.get(history_id)?;
    // A method-override header names the method the application acts on.
    let overridden = request_headers(&item.request).into_iter().find_map(|(k, v)| {
        METHOD_OVERRIDES.iter().any(|h| k.eq_ignore_ascii_case(h)).then(|| v.trim().to_ascii_uppercase())
    });
    let method = overridden.unwrap_or_else(|| item.entry.method.to_ascii_uppercase());
    if !a.allow_unsafe && !SAFE_METHODS.contains(&method.as_str()) {
        return Err(Error::InvalidInput(format!(
            "finding {}'s request is a {method}, which may change data when sent again; \
             pass --allow-unsafe to send it",
            a.id
        )));
    }
    let detail = format!("{method} {}", item.entry.url);
    let identity = |alert: &str, method: &str, url: &str, param: &str| fingerprint(alert, method, url, param);
    let want = identity(
        &alert_ref,
        f["method"].as_str().unwrap_or_default(),
        f["url"].as_str().unwrap_or_default(),
        f["param"].as_str().unwrap_or_default(),
    );
    let row = send_again(project, &store, &a, &item.target, &item.request)?;
    drop(store);
    let mut store = Store::open(project)?;
    let msg = store
        .scan_messages_after(row - 1, &[RETEST_SOURCE.to_string()], 1)?
        .into_iter()
        .find(|m| m.history_id == row)
        .ok_or_else(|| Error::Protocol(format!("the retest's response (history {row}) can't be read back")))?;
    let found = passive::scan_message(&msg, &settings)
        .iter()
        .any(|x| identity(x.def.alert_ref, &msg.method, &msg.url, &x.param) == want);
    // A reply of another kind (a redirect to a login page, an error, a 304 or a 206) can't show
    // the finding: that isn't "fixed".
    if !found && item.entry.status.is_some_and(|w| w != msg.status) {
        return Err(Error::Conflict(format!(
            "finding {}: the retest got status {} where its request had {} (history {row}), so it can't tell \
             whether the finding is still there; nothing was marked (an expired session? try --auth PROFILE)",
            a.id,
            msg.status,
            item.entry.status.unwrap_or(0)
        )));
    }
    // Nor can a reply that sets no cookie, for a finding about one: a server that sets a cookie
    // only for a request without one sends no Set-Cookie to a retest that carries one.
    if !found {
        let evidence = f["evidence"].as_str().unwrap_or_default();
        if let Some(name) = evidence_header(&item.response, evidence)
            .filter(|n| !msg.resp_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n)))
        {
            return Err(Error::Conflict(format!(
                "finding {}: it was seen in a {name} header, and the retest's reply (history {row}) sets no \
                 cookie, so it can't tell whether the finding is still there; nothing was marked",
                a.id
            )));
        }
    }
    let outcome = if found { Retest::StillPresent } else { Retest::NotReproduced };
    let state = store.finding_retested(a.id, outcome, Some(row), &detail, !a.no_mark)?;
    let data = json!({
        "id": a.id,
        "outcome": outcome.as_str(),
        "state": state,
        "previous_state": f["state"],
        "history_id": row,
        "request": detail,
    });
    out.ok(data, || {
        let said = match outcome {
            Retest::StillPresent => "still present",
            Retest::NotReproduced => "not reproduced",
        };
        format!("finding {}: {said} (now {})", a.id, state.replace('_', " "))
    });
    Ok(())
}

/// Headers that tell a server to act as if the request had another method.
const METHOD_OVERRIDES: &[&str] = &["x-http-method-override", "x-http-method", "x-method-override"];

/// A raw message's header lines, as (name, value).
fn request_headers(raw: &[u8]) -> Vec<(String, String)> {
    let head = raw.split(|&b| b == b'\n').skip(1).take_while(|l| !l.iter().all(|b| b.is_ascii_whitespace()));
    head.filter_map(|l| {
        let l = String::from_utf8_lossy(l);
        let (k, v) = l.split_once(':')?;
        Some((k.trim().to_string(), v.trim().to_string()))
    })
    .collect()
}

/// Set-Cookie, when the evidence was quoted from one: a server sends it only when it sets a
/// cookie (often only to a request without one), so a reply without any can't show the
/// finding. Other headers going away is how they are fixed.
fn evidence_header(response: &[u8], evidence: &str) -> Option<String> {
    let evidence = evidence.trim().to_ascii_lowercase();
    if evidence.is_empty() {
        return None;
    }
    request_headers(response).into_iter().find_map(|(k, v)| {
        let quoted = format!("{k}: {v}").to_ascii_lowercase().contains(&evidence);
        (quoted && k.eq_ignore_ascii_case("set-cookie")).then_some(k)
    })
}

/// How to retest an active finding: run its rule or check again, as a scan.
fn rescan_hint(id: i64, f: &Value, history_id: Option<i64>) -> String {
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let what = match f["alert_ref"].as_str().unwrap_or_default().strip_prefix("check:") {
        Some(check) => format!("--checks SOURCE --check-ids={}", quote(check)),
        None => format!("--rules={}", f["rule_id"].as_i64().unwrap_or(0)),
    };
    // The URL comes from the target: quoted, so the command can be pasted as it is.
    let url = quote(f["url"].as_str().unwrap_or_default());
    let target = match history_id {
        Some(_) => format!("{url} --include-methods {}", quote(f["method"].as_str().unwrap_or("GET"))),
        None => url,
    };
    format!(
        "finding {id} came from an active scan, whose evidence is an attack, not the request it started \
         from: retest it by scanning again (`scan active {target} {what}`), and mark it retest_pending \
         meanwhile; a completed scan that covers it and doesn't find it lists it as gone"
    )
}

/// Sends the request again, recorded with source `retest`; returns its history row.
fn send_again(
    project: &Path,
    store: &Store,
    a: &RetestArgs,
    target: &brainproxy_core::http::Target,
    request: &[u8],
) -> Result<i64, Error> {
    let guard = store.guard()?;
    crate::require_in_scope(&guard, target)?;
    let opts = SendOptions {
        guard: Some(guard),
        timeout: std::time::Duration::from_secs_f64(a.timeout.max(0.001)),
        verify_tls: false,
        sni: None,
        http2: false,
        // Sent again as it was recorded, with whatever Host it had then.
        host: brainproxy_core::http::client::HostPolicy::Allow,
    };
    let session = auth_cmd::maybe_session(project, a.auth.as_deref(), &opts)?;
    let client = Client::new(opts);
    let req = RawRequest::from_bytes(request.to_vec());
    let mut log = sent::SentLog::open(project, RETEST_SOURCE, false)?.sent_by(&client);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(Error::Io)?;
    let mut rows: Vec<i64> = Vec::new();
    let mut open: Option<(i64, Vec<u8>)> = None;
    let result = {
        let (log, rows, open) = (&mut log, &mut rows, &mut open);
        let sending = async {
            let sending = |log: &mut sent::SentLog, rows: &mut Vec<i64>, open: &mut Option<_>, r: &RawRequest| {
                let recorded = client.recorded_request(r, target)?;
                let id = log.pending(target, &recorded)?;
                rows.push(id);
                *open = Some((id, recorded));
                Ok::<_, Error>(())
            };
            match &session {
                Some(s) => {
                    let watch = |at: Attempt<'_>| match at {
                        Attempt::Sending(r) => sending(log, rows, open, r),
                        Attempt::Answered(ex) => match open.take() {
                            Some((id, _)) => log.answered(id, ex),
                            None => Ok(()),
                        },
                    };
                    s.send_as_watched(brainproxy_core::session::Tool::Send, &req, target, watch).await
                }
                None => {
                    sending(log, rows, open, &req)?;
                    let ex = client.send(&req, target).await?;
                    if let Some((id, _)) = open.take() {
                        log.answered(id, &ex)?;
                    }
                    Ok(ex)
                }
            }
        };
        rt.block_on(async {
            tokio::select! {
                r = sending => Some(r),
                _ = process::interrupted() => None,
            }
        })
    };
    let outcome = match (result, open) {
        (Some(Ok(_)), _) => Ok(*rows.last().expect("every request is recorded before it is sent")),
        (Some(Err(e)), Some((id, recorded))) => log.failed(id, target, &recorded, &e.to_string()).and(Err(e)),
        (Some(Err(e)), None) => Err(e),
        (None, Some((id, recorded))) => {
            log.failed(id, target, &recorded, sent::CANCELLED).and(Err(sent::cancelled(&rows)))
        }
        (None, None) => Err(sent::cancelled(&rows)),
    };
    if let Some(s) = &session {
        // A session that couldn't be saved logs in again next time; the retest stands.
        let _ = s.save();
    }
    outcome
}
