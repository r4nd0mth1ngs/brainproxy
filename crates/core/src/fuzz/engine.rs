//! Runs a fuzz plan: concurrent workers with keep-alive connections, an optional
//! shared rate limit, response analysis (status, size, words, lines, grep,
//! extract), and batched recording into the project database.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use regex::bytes::Regex;
use serde::Serialize;

use crate::auth::{request_cookies, AuthSession};
use crate::capture::{decode_body, Capture};
use crate::error::{Error, Result};
use crate::fuzz::plan::{Plan, Template};
use crate::http::client::final_response;
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use crate::rules::{Engine, EngineRules, Ruled};
use crate::sent::{RowBatch, RowWrite, Rows};
use crate::session::Tool;
use crate::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoreMode {
    /// Record every request/response in history.
    All,
    /// Record only matched results in history (all results still get a fuzz_results row).
    Matches,
    /// Record nothing in history.
    None,
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub concurrency: usize,
    /// Requests per second across all workers.
    pub rate: Option<f64>,
    pub send: SendOptions,
    pub grep: Vec<String>,
    pub extract: Option<String>,
    pub match_status: Vec<u16>,
    pub stop_on_match: bool,
    pub store: StoreMode,
    pub update_content_length: bool,
    /// URL-encode what isn't URL-safe in payloads placed in the request line or a form body.
    pub encode_payloads: bool,
    pub max_requests: Option<u64>,
    /// Logged-in session applied to every request; fuzzed cookies are left alone.
    pub auth: Option<Arc<AuthSession>>,
}

/// Outcome of one request.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FuzzResult {
    pub idx: u64,
    pub position: Option<usize>,
    pub payloads: Vec<String>,
    pub status: Option<u16>,
    /// Decoded response body length.
    pub length: Option<i64>,
    pub words: Option<i64>,
    pub lines: Option<i64>,
    pub duration_ms: Option<i64>,
    pub matched: bool,
    /// Grep patterns that matched.
    pub grep: Vec<String>,
    pub extract: Option<String>,
    pub error: Option<String>,
}

/// A result and its history row.
pub type Row = (History, FuzzResult);

/// A fuzz result's history row.
pub enum History {
    None,
    /// Written just before the request went out (`--store all`).
    Written(i64),
    /// To write with the result: a match under `--store matches`, known only once answered.
    Capture(Box<Capture>),
}

/// What the writer thread writes.
enum Write {
    Row(RowWrite),
    Result(Row),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Completed,
    StoppedOnMatch,
    Stopped,
}

struct Compiled {
    grep: Vec<(String, Regex)>,
    extract: Option<Regex>,
}

pub async fn run(
    project: &Path,
    run_id: i64,
    template: Template,
    plan: Plan,
    target: Target,
    cfg: EngineConfig,
) -> Result<Outcome> {
    let compiled = Arc::new(Compiled {
        grep: cfg
            .grep
            .iter()
            .map(|g| Regex::new(g).map(|r| (g.clone(), r)).map_err(|e| Error::InvalidInput(format!("grep {g:?}: {e}"))))
            .collect::<Result<_>>()?,
        extract: cfg
            .extract
            .as_deref()
            .map(|x| Regex::new(x).map_err(|e| Error::InvalidInput(format!("extract {x:?}: {e}"))))
            .transpose()?,
    });

    // History rows written before their requests go out, and results, in batches: the rows
    // first, as a result can point to one.
    let (tx, rx) = mpsc::channel::<Write>();
    let mut writer_store = Store::open(project)?;
    // Match-and-replace rules that list the fuzzer, as they are when the run starts.
    let rules = EngineRules::load(&writer_store, Engine::Fuzz)?;
    let writer = std::thread::spawn(move || -> Result<()> {
        while let Ok(first) = rx.recv() {
            let (mut rows, mut batch) = (RowBatch::default(), Vec::new());
            for w in std::iter::once(first).chain(rx.try_iter().take(499)) {
                match w {
                    Write::Row(w) => rows.push(w),
                    Write::Result(r) => batch.push(r),
                }
            }
            rows.write(&mut writer_store);
            if !batch.is_empty() {
                writer_store.fuzz_record(run_id, &batch)?;
            }
        }
        Ok(())
    });

    let total = cfg.max_requests.map_or(plan.total(), |m| m.min(plan.total()));
    let next = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let stopped_by_user = Arc::new(AtomicBool::new(false));
    let matched_stop = Arc::new(AtomicBool::new(false));
    let limiter = cfg.rate.filter(|r| *r > 0.0).map(|r| Arc::new(Limiter::new(r)));
    let client = Arc::new(Client::new(cfg.send.clone()));
    // With `--store all`, each request's row is written before it goes out.
    let rows = (cfg.store == StoreMode::All).then(|| {
        let tx = tx.clone();
        Rows::new("fuzz", move |w| drop(tx.send(Write::Row(w)))).sent_by(&client)
    });
    // Cookies and parameters that carry a payload must keep it rather than get the
    // session's value or a session rule's.
    let fuzzed: Arc<(Vec<String>, Vec<String>)> = Arc::new(if cfg.auth.is_some() {
        const SENTINEL: &str = "BPFUZZSENTINEL7q";
        let values = vec![SENTINEL.as_bytes(); template.positions()];
        let rendered = template.render(&values);
        let cookies =
            request_cookies(&rendered).into_iter().filter(|(_, v)| v.contains(SENTINEL)).map(|(k, _)| k).collect();
        let mut params: Vec<String> = crate::scan::active::points::points(&rendered, &Default::default())
            .into_iter()
            .filter(|p| p.value.contains(SENTINEL))
            .map(|p| p.session_name().to_string())
            .collect();
        if let Ok(h) = RawRequest::from_bytes(rendered).head() {
            params.extend(h.headers.into_iter().filter(|(_, v)| v.contains(SENTINEL)).map(|(k, _)| k));
        }
        (cookies, params)
    } else {
        Default::default()
    });
    let (template, plan, target, cfg) = (Arc::new(template), Arc::new(plan), Arc::new(target), Arc::new(cfg));

    let watcher = {
        let (stop, by_user, project) = (stop.clone(), stopped_by_user.clone(), project.to_path_buf());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let p = project.clone();
                let state = tokio::task::spawn_blocking(move || Store::open(&p)?.fuzz_state(run_id)).await;
                if let Ok(Ok(s)) = state {
                    if s == "stopping" {
                        by_user.store(true, Ordering::Relaxed);
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }
        })
    };

    let url_positions = Arc::new(template.url_positions());
    let mut workers = Vec::new();
    for _ in 0..cfg.concurrency.max(1).min(total.max(1) as usize) {
        let (next, stop, matched_stop, limiter, client, tx, rows, rules) = (
            next.clone(),
            stop.clone(),
            matched_stop.clone(),
            limiter.clone(),
            client.clone(),
            tx.clone(),
            rows.clone(),
            rules.clone(),
        );
        let url_positions = url_positions.clone();
        let (template, plan, target, cfg, compiled, fuzzed) =
            (template.clone(), plan.clone(), target.clone(), cfg.clone(), compiled.clone(), fuzzed.clone());
        workers.push(tokio::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let idx = next.fetch_add(1, Ordering::Relaxed);
                if idx >= total {
                    break;
                }
                if let Some(l) = &limiter {
                    l.wait().await;
                }
                let mut item = plan.item(idx);
                if cfg.encode_payloads {
                    for (v, url) in item.values.iter_mut().zip(url_positions.iter()) {
                        if *url {
                            *v = crate::codec::encode_loose(v);
                        }
                    }
                }
                let refs: Vec<&[u8]> = item.values.iter().map(Vec::as_slice).collect();
                let mut request = template.render(&refs);
                if cfg.update_content_length {
                    request = RawRequest::from_bytes(request).update_content_length().into_bytes();
                }
                let keep_cookies: Vec<&str> = fuzzed.0.iter().map(String::as_str).collect();
                let keep_params: Vec<&str> = fuzzed.1.iter().map(String::as_str).collect();
                // The rules see the request with its payloads in, then the session is applied.
                let mut refused = None;
                let ruled = match rules.as_ref().map(|r| r.request(client.options(), &target, request.clone())) {
                    Some(Ok(ruled)) => {
                        request = ruled.bytes.clone();
                        Some(ruled)
                    }
                    Some(Err(e)) => {
                        refused = Some(e);
                        None
                    }
                    None => None,
                };
                let by = rules.as_ref().zip(ruled.as_ref());
                let rendered = request.clone();
                let mut prepared = None;
                if let Some(a) = cfg.auth.as_ref().filter(|_| refused.is_none()) {
                    let p = a.prepare(Tool::Fuzz, &target, &rendered, &keep_cookies, &keep_params).await;
                    request = p.request.clone();
                    prepared = Some(p);
                }

                let mut started = Instant::now();
                let (mut row, mut result) = match refused {
                    Some(e) => (None, Err(e)),
                    None => exchange(&client, rows.as_ref(), &target, &request, by).await,
                };
                if let (Some(a), Some(p), Ok(answer)) = (&cfg.auth, &prepared, &result) {
                    // Session lost or stale session values: log in again or refresh them
                    // (once across workers) and retry this payload. Both requests have rows.
                    if a.after_response(p, answer.received()).await {
                        request = a.prepare(Tool::Fuzz, &target, &rendered, &keep_cookies, &keep_params).await.request;
                        started = Instant::now();
                        (row, result) = exchange(&client, rows.as_ref(), &target, &request, by).await;
                        if let Ok(answer) = &result {
                            a.observe(answer.received());
                        }
                    }
                }
                let duration = match &result {
                    Ok(answer) => answer.ms as i64,
                    Err(_) => started.elapsed().as_millis() as i64,
                };

                let mut res = FuzzResult {
                    idx,
                    position: item.position,
                    payloads: item.payloads.iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect(),
                    duration_ms: Some(duration),
                    ..Default::default()
                };
                let capture = match result {
                    Ok(answer) => {
                        analyze(&answer.response.bytes, &compiled, &cfg.match_status, &mut res);
                        (cfg.store == StoreMode::Matches && res.matched).then(|| {
                            let mut c =
                                Capture::new("fuzz", &target, &request, Some(answer.received()), Some(duration), None);
                            if answer.response.changed() {
                                c.response_edits = answer.response.edits();
                                c.modified_response = Some(answer.response.bytes);
                            }
                            c
                        })
                    }
                    Err(e) => {
                        res.error = Some(e.to_string());
                        // Refused before it went out (or its row couldn't be written): no row yet.
                        (cfg.store == StoreMode::All && row.is_none())
                            .then(|| Capture::new("fuzz", &target, &request, None, None, Some(&e.to_string())))
                    }
                };
                // A row written here says what the rules did to its request, as one written
                // before the request went out does.
                let capture = capture.map(|mut c| {
                    if let Some(ruled) = ruled.as_ref().filter(|r| r.changed()) {
                        c.original_request = ruled.original.clone();
                        c.edited_by = ruled.edits();
                    }
                    c
                });
                let history = match (row, capture) {
                    (Some(id), _) => History::Written(id),
                    (None, Some(c)) => History::Capture(Box::new(Capture { sni: client.sni(&target), ..c })),
                    (None, None) => History::None,
                };
                if res.matched && cfg.stop_on_match {
                    matched_stop.store(true, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                }
                if tx.send(Write::Result((history, res))).is_err() {
                    break;
                }
            }
        }));
    }
    drop((tx, rows));
    for w in workers {
        let _ = w.await;
    }
    watcher.abort();
    tokio::task::spawn_blocking(move || writer.join())
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?
        .map_err(|_| Error::Protocol("fuzz writer panicked".into()))??;

    Ok(if stopped_by_user.load(Ordering::Relaxed) {
        Outcome::Stopped
    } else if matched_stop.load(Ordering::Relaxed) {
        Outcome::StoppedOnMatch
    } else {
        Outcome::Completed
    })
}

/// A fuzz request's answer.
struct Answer {
    /// The response after the fuzzer's match-and-replace rules, which is what is analysed.
    response: Ruled,
    ms: u64,
}

impl Answer {
    /// The response as the server sent it: what a session and a history row go by.
    fn received(&self) -> &[u8] {
        self.response.original.as_deref().unwrap_or(&self.response.bytes)
    }
}

/// Sends on the client's kept-alive connections, on record in `rows` first if given, and
/// applies the fuzzer's response rules (`by`: its rules, and what they made of the request).
/// Returns the request's row and the answer.
async fn exchange(
    client: &Client,
    rows: Option<&Rows>,
    target: &Target,
    request: &[u8],
    by: Option<(&EngineRules, &Ruled)>,
) -> (Option<i64>, Result<Answer>) {
    let req = RawRequest::from_bytes(request.to_vec());
    let (id, sent, ruled) = match rows {
        Some(rows) => rows.send_ruled(client, &req, target, by).await,
        None => (None, client.send(&req, target).await, None),
    };
    let answer = sent.map(|ex| Answer {
        ms: ex.duration_ms,
        // A recorded request's row has what the rules made of the response; a request that
        // isn't recorded first gets its response ruled here.
        response: match (ruled, by) {
            (Some(ruled), _) => ruled,
            (None, Some((rules, _))) if rows.is_none() => rules.response(target, &ex.request, ex.response),
            (None, _) => Ruled { bytes: ex.response, ..Default::default() },
        },
    });
    (id, answer)
}

fn analyze(response: &[u8], c: &Compiled, match_status: &[u16], res: &mut FuzzResult) {
    let final_resp = final_response(response);
    let Ok(head) = parse_response_head(final_resp) else {
        res.error = Some("unparseable response".into());
        return;
    };
    let (head_bytes, raw_body) = split_head_body(final_resp);
    let body = decode_body(&head.headers, raw_body);
    res.status = Some(head.status);
    res.length = Some(body.len() as i64);
    res.words = Some(body.split(|b| b.is_ascii_whitespace()).filter(|w| !w.is_empty()).count() as i64);
    res.lines = Some(if body.is_empty() { 0 } else { body.split(|&b| b == b'\n').count() as i64 });

    if !c.grep.is_empty() || c.extract.is_some() {
        let mut haystack = head_bytes.to_vec();
        haystack.extend_from_slice(&body);
        res.grep = c.grep.iter().filter(|(_, r)| r.is_match(&haystack)).map(|(g, _)| g.clone()).collect();
        if let Some(x) = &c.extract {
            res.extract = x.captures(&haystack).and_then(|caps| {
                caps.get(1).or_else(|| caps.get(0)).map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
            });
        }
    }
    res.matched = !res.grep.is_empty() || match_status.contains(&head.status);
}

/// Spaces request starts evenly across all workers.
struct Limiter {
    interval: Duration,
    next: tokio::sync::Mutex<Instant>,
}

impl Limiter {
    fn new(rate: f64) -> Self {
        Self { interval: Duration::from_secs_f64(1.0 / rate), next: tokio::sync::Mutex::new(Instant::now()) }
    }

    async fn wait(&self) {
        let at = {
            let mut next = self.next.lock().await;
            let at = (*next).max(Instant::now());
            *next = at + self.interval;
            at
        };
        tokio::time::sleep_until(at.into()).await;
    }
}
