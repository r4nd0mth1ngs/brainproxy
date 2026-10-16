//! Runs a fuzz plan: concurrent workers with keep-alive connections, an optional
//! shared rate limit, response analysis (status, size, words, lines, grep,
//! extract), and batched recording into the project database.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use regex::bytes::Regex;
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use crate::capture::{decode_body, Capture};
use crate::error::{Error, Result};
use crate::fuzz::plan::{Plan, Template};
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, Client, RawRequest, SendOptions, Stream, Target, WireReader};
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
    pub max_requests: Option<u64>,
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

pub type Row = (Option<Capture>, FuzzResult);

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

    let (tx, rx) = mpsc::channel::<Row>();
    let mut writer_store = Store::open(project)?;
    let writer = std::thread::spawn(move || -> Result<()> {
        while let Ok(first) = rx.recv() {
            let mut batch = vec![first];
            while batch.len() < 500 {
                match rx.try_recv() {
                    Ok(r) => batch.push(r),
                    Err(_) => break,
                }
            }
            writer_store.fuzz_record(run_id, &batch)?;
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

    let mut workers = Vec::new();
    for _ in 0..cfg.concurrency.max(1).min(total.max(1) as usize) {
        let (next, stop, matched_stop, limiter, client, tx) =
            (next.clone(), stop.clone(), matched_stop.clone(), limiter.clone(), client.clone(), tx.clone());
        let (template, plan, target, cfg, compiled) =
            (template.clone(), plan.clone(), target.clone(), cfg.clone(), compiled.clone());
        workers.push(tokio::spawn(async move {
            let mut conn: Option<Conn> = None;
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
                let item = plan.item(idx);
                let refs: Vec<&[u8]> = item.values.iter().map(Vec::as_slice).collect();
                let mut request = template.render(&refs);
                if cfg.update_content_length {
                    request = RawRequest::from_bytes(request).update_content_length().into_bytes();
                }
                let method = RawRequest::from_bytes(request.clone()).head().map(|h| h.method).unwrap_or_default();

                let started = Instant::now();
                let result =
                    tokio::time::timeout(cfg.send.timeout, exchange(&client, &target, &mut conn, &request, &method))
                        .await
                        .unwrap_or_else(|_| Err(Error::Timeout(cfg.send.timeout)));
                let duration = started.elapsed().as_millis() as i64;

                let mut res = FuzzResult {
                    idx,
                    position: item.position,
                    payloads: item.payloads.iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect(),
                    duration_ms: Some(duration),
                    ..Default::default()
                };
                let capture = match result {
                    Ok(response) => {
                        analyze(&response, &compiled, &cfg.match_status, &mut res);
                        if close_after(&request, &response, &method) {
                            conn = None;
                        }
                        let keep = match cfg.store {
                            StoreMode::All => true,
                            StoreMode::Matches => res.matched,
                            StoreMode::None => false,
                        };
                        keep.then(|| Capture::new("fuzz", &target, &request, Some(&response), Some(duration), None))
                    }
                    Err(e) => {
                        conn = None;
                        res.error = Some(e.to_string());
                        (cfg.store == StoreMode::All)
                            .then(|| Capture::new("fuzz", &target, &request, None, None, Some(&e.to_string())))
                    }
                };
                if res.matched && cfg.stop_on_match {
                    matched_stop.store(true, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                }
                if tx.send((capture, res)).is_err() {
                    break;
                }
            }
        }));
    }
    drop(tx);
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

struct Conn {
    stream: Stream,
    reader: WireReader,
    used: bool,
}

/// Sends on the worker's kept-alive connection, reconnecting once if a reused
/// connection turns out to be closed.
async fn exchange(
    client: &Client,
    target: &Target,
    conn: &mut Option<Conn>,
    request: &[u8],
    method: &str,
) -> Result<Vec<u8>> {
    loop {
        if conn.is_none() {
            *conn = Some(Conn { stream: client.connect(target).await?, reader: WireReader::new(), used: false });
        }
        let c = conn.as_mut().unwrap();
        let reused = c.used;
        c.used = true;
        let result = async {
            c.stream.write_all(request).await?;
            c.stream.flush().await?;
            c.reader.read_response(&mut c.stream, method).await
        }
        .await;
        match result {
            Ok(r) => return Ok(r),
            Err(_) if reused => *conn = None,
            Err(e) => {
                *conn = None;
                return Err(e);
            }
        }
    }
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

fn final_response(resp: &[u8]) -> &[u8] {
    let mut start = 0;
    while let Ok(h) = parse_response_head(&resp[start..]) {
        if (100..200).contains(&h.status) && h.status != 101 {
            start += split_head_body(&resp[start..]).0.len();
        } else {
            break;
        }
    }
    &resp[start..]
}

/// Whether the connection can't be reused after this exchange.
fn close_after(request: &[u8], response: &[u8], method: &str) -> bool {
    let req_close = RawRequest::from_bytes(request.to_vec())
        .head()
        .map(|h| h.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close")))
        .unwrap_or(true);
    let Ok(h) = parse_response_head(final_response(response)) else { return true };
    req_close
        || h.header("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"))
        || (h.version == "HTTP/1.0" && !h.header("connection").is_some_and(|v| v.eq_ignore_ascii_case("keep-alive")))
        || (h.header("content-length").is_none()
            && !h.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
            && !method.eq_ignore_ascii_case("HEAD")
            && !matches!(h.status, 100..=199 | 204 | 304))
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
