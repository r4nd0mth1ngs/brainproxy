//! Browser crawl: explores a site in a headless Chromium-family browser, so pages built by
//! JavaScript (single-page apps) are crawled too. The browser goes only through the
//! crawl's own recording proxy ([`gateway`]), so every request it makes is checked against
//! the engagement scope and recorded in history (source `crawl-browser`), XHR and fetch()
//! calls included.
//!
//! Exploring works like a person would: load a URL, wait until the network and the DOM
//! have been quiet for a moment (bounded), then note the links (client-side routes from
//! history.pushState and hash routes too), and try each clickable element: buttons,
//! elements with click handlers, menu items. Before each click the visible fields are
//! filled with the spider's test values, so clicking a submit button sends the form.
//! Each resulting DOM state is keyed on its shape (address with ids masked, the set of
//! clickable elements, links and forms) and explored only once, which keeps lists, pagers
//! and repeated menus from multiplying the work. To try a click the crawler returns to
//! the state it was found in by loading the page again and repeating the clicks that led
//! there.
//!
//! Destructive actions are avoided by default: elements labelled like logout, delete or
//! remove are not clicked, confirm() dialogs answer no, logout-like URLs are not
//! requested, and DELETE requests are not sent.

mod cdp;
mod gateway;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::crawl::{field_value, is_static, CrawlConfig, Endpoint, Scope};
use crate::error::{Error, Result};
use crate::http::Client;
use crate::jobs::JobControl;
use crate::proxy::ca::CertAuthority;

use cdp::{Chrome, LaunchOptions};
use gateway::Gateway;

/// Element labels (text, aria-label, title, id, name, class, href) never clicked by default.
pub const DEFAULT_AVOID: &str = r"(?i)\b(log\s*-?\s*(out|off)|sign\s*-?\s*out|delete|remove|destroy|erase|purge|wipe|trash|deactivate|disable|unsubscribe|unregister|revoke|terminate|reset|uninstall|cancel\s+(my\s+)?(account|subscription|order|membership)|close\s+(my\s+)?account)\b";

const PAGE_JS: &str = include_str!("page.js");
/// Longest wait for a page to settle after a load or click.
const SETTLE_MAX: Duration = Duration::from_secs(10);
/// Settled: no request in flight for this long...
const NETWORK_QUIET: Duration = Duration::from_millis(500);
/// ...and no DOM change for this many milliseconds.
const DOM_QUIET_MS: f64 = 300.0;
/// Elements clicked per DOM state.
const MAX_CLICKS_PER_STATE: usize = 40;
/// Longest chain of clicks from a page load.
const MAX_CHAIN: usize = 6;
/// The same element (by key) is tried in at most this many states.
const MAX_PER_ELEMENT: usize = 3;
/// Labels and URLs listed in the summary.
const MAX_LISTED: usize = 50;
/// Longest URL queued, and longest label kept from a page.
const MAX_URL: usize = 4096;
/// --max-minutes when none is given: a hostile page can make every step wait for a timeout.
const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(30 * 60);
/// Commands timing out in a row before the tab is replaced by a fresh one.
const MAX_TIMEOUTS: usize = 3;

#[derive(Clone)]
pub struct BrowserCrawlConfig {
    /// Seeds, limits, scope, rate, headers and auth, as for the HTTP crawl. `concurrency`,
    /// `robots`, `sitemap` and `send.http2` don't apply: one tab, HTTP/1.1 upstream.
    pub crawl: CrawlConfig,
    /// A Chromium-family browser executable.
    pub browser: PathBuf,
    pub headless: bool,
    /// The project CA, trusted by the browser for this crawl only.
    pub ca: Arc<CertAuthority>,
    /// Elements whose label matches any of these are not clicked (empty: click everything).
    pub avoid: Vec<Regex>,
    /// Don't send DELETE requests.
    pub block_delete: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BrowserCrawlSummary {
    pub mode: String,
    /// Browser product and version.
    pub browser: String,
    /// Chromium's sandbox was on (off only with BRAINPROXY_BROWSER_NO_SANDBOX=1).
    pub sandbox: bool,
    /// Tabs replaced because their page stopped answering.
    pub tab_restarts: usize,
    /// Requests the browser made (all recorded, source crawl-browser).
    pub requests: usize,
    pub by_status: BTreeMap<String, usize>,
    pub depth_reached: usize,
    pub pages_loaded: usize,
    pub clicks: usize,
    pub forms_submitted: usize,
    /// Distinct DOM states explored.
    pub states: usize,
    pub endpoints: Vec<Endpoint>,
    pub endpoint_count: usize,
    /// XHR and fetch() calls.
    pub api_calls: Vec<Endpoint>,
    pub api_call_count: usize,
    /// Elements not clicked and links not followed because they look destructive (logout, delete, ...).
    pub not_clicked: Vec<String>,
    pub not_clicked_count: usize,
    /// Requests the browser tried that weren't sent (logout URLs, DELETE).
    pub blocked_requests: Vec<String>,
    pub blocked_count: usize,
    pub out_of_scope_hosts: Vec<String>,
    pub errors: usize,
    /// Exchanges that could not be saved to the project (e.g. too large).
    pub record_errors: usize,
    pub stopped: bool,
    pub limit_reached: bool,
    pub new_findings: usize,
    pub elapsed_ms: u64,
}

/// What the page script reports about the current page.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct Snapshot {
    pub url: String,
    pub title: String,
    /// Links with their labels (`href` is absolute).
    pub links: Vec<Clickable>,
    /// Addresses set by history.pushState/replaceState or hash changes since the last snapshot.
    pub routes: Vec<String>,
    /// URLs passed to window.open.
    pub opened: Vec<String>,
    pub clickables: Vec<Clickable>,
    pub forms: Vec<Form>,
}

impl Snapshot {
    /// The page script limits all this too, but a page can tamper with what that script uses.
    fn bounded(mut self) -> Self {
        self.routes.truncate(200);
        self.opened.truncate(200);
        self.links.truncate(500);
        self.clickables.truncate(300);
        self.forms.truncate(100);
        for c in self.links.iter_mut().chain(&mut self.clickables) {
            for s in [&mut c.text, &mut c.id, &mut c.name, &mut c.class, &mut c.title, &mut c.href, &mut c.action] {
                if s.len() > MAX_URL {
                    *s = s.chars().take(MAX_URL).collect();
                }
            }
        }
        self
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct Clickable {
    /// Identifies the element in this state: its description and position among equal ones.
    pub key: String,
    pub tag: String,
    pub role: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
    pub id: String,
    pub name: String,
    pub class: String,
    pub title: String,
    pub href: String,
    /// Clicking it submits a form (to `action`).
    pub submits: bool,
    pub action: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct Form {
    pub key: String,
    pub action: String,
    pub method: String,
    pub has_submit: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Field {
    i: usize,
    tag: String,
    #[serde(rename = "type")]
    kind: String,
    name: String,
    value: String,
    required: bool,
    checked: bool,
    options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum Step {
    Click(String),
    Submit(String),
}

/// A page load, or a page load followed by steps.
#[derive(Debug, Clone)]
struct Action {
    url: String,
    path: Vec<Step>,
    depth: usize,
    /// The state the last step starts from.
    parent: Option<u64>,
    /// The last step submits a form.
    submits: bool,
}

pub async fn crawl(project: &Path, cfg: BrowserCrawlConfig, ctl: JobControl) -> Result<BrowserCrawlSummary> {
    let started = Instant::now();
    let seeds = crate::crawl::parse_seeds(&cfg.crawl.seeds)?;
    let scope = Arc::new(Scope::new(&seeds, &cfg.crawl));
    let (save, writer) = crate::crawl::spawn_writer(project)?;
    let gateway = Gateway::start(
        gateway::Options {
            ca: cfg.ca.clone(),
            client: Client::new(cfg.crawl.send.clone()),
            auth: cfg.crawl.auth.clone(),
            headers: cfg.crawl.headers.clone(),
            scope: scope.clone(),
            exclude: cfg.crawl.exclude.clone(),
            block_delete: cfg.block_delete,
            rate: cfg.crawl.rate,
        },
        save,
    )
    .await?;
    let explored = async {
        let no_sandbox = cdp::sandbox_off();
        let chrome = Chrome::launch(&LaunchOptions {
            path: &cfg.browser,
            headless: cfg.headless,
            proxy: gateway.addr,
            ca_spki: cfg.ca.spki_sha256_base64(),
            no_sandbox,
        })?;
        let mut ex = Explorer::new(&chrome, &gateway, &cfg, &scope, &ctl, started);
        ex.summary.sandbox = !no_sandbox;
        // Ctrl-C ends the crawl normally, so the profile (the target's cookies) is removed.
        let ran = tokio::select! {
            r = ex.run(&seeds) => r,
            () = interrupted() => {
                ctl.request_stop();
                Ok(())
            }
        };
        let result = ran.map(|_| ex.finish());
        chrome.close().await;
        result
    }
    .await;
    let stats = gateway.stop().await;
    let (new_findings, record_errors) = crate::crawl::join_writer(writer).await?;
    let mut s = explored?;
    s.requests = stats.requests;
    s.by_status = stats.by_status;
    s.errors += stats.errors;
    let mut eps: Vec<Endpoint> = stats.endpoints.into_iter().collect();
    eps.sort();
    s.endpoint_count = eps.len();
    eps.truncate(200);
    s.endpoints = eps;
    let mut api: Vec<Endpoint> = stats.api_calls.into_iter().collect();
    api.sort();
    s.api_call_count = api.len();
    api.truncate(200);
    s.api_calls = api;
    s.blocked_requests = stats.blocked;
    s.blocked_count = stats.blocked_count;
    let mut hosts: BTreeSet<String> = s.out_of_scope_hosts.drain(..).collect();
    hosts.extend(stats.refused_hosts);
    s.out_of_scope_hosts = hosts.into_iter().take(MAX_LISTED).collect();
    s.new_findings = new_findings;
    s.record_errors = record_errors;
    s.stopped = ctl.stopped();
    s.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(s)
}

/// Resolves on Ctrl-C or, on Unix, a request to terminate.
async fn interrupted() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                () = ctrl_c => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    ctrl_c.await;
}

struct Explorer<'a> {
    chrome: &'a Chrome,
    session: String,
    target: String,
    /// Commands timed out in a row; a reply resets it.
    timeouts: AtomicUsize,
    gateway: &'a Gateway,
    cfg: &'a BrowserCrawlConfig,
    scope: &'a Scope,
    ctl: &'a JobControl,
    started: Instant,
    queue: VecDeque<Action>,
    seen_urls: HashSet<String>,
    seen_states: HashSet<u64>,
    /// (state key, element key) pairs already queued.
    tried: HashSet<String>,
    per_element: HashMap<String, usize>,
    per_path: HashMap<String, usize>,
    /// Page loads, clicks and form submissions so far, replays included (--max-pages).
    ops: usize,
    out_of_scope: BTreeSet<String>,
    not_clicked: BTreeSet<String>,
    not_clicked_count: usize,
    /// Where the tab is: the page loaded and the steps taken since.
    current: Option<(String, Vec<Step>)>,
    summary: BrowserCrawlSummary,
}

impl<'a> Explorer<'a> {
    fn new(
        chrome: &'a Chrome,
        gateway: &'a Gateway,
        cfg: &'a BrowserCrawlConfig,
        scope: &'a Scope,
        ctl: &'a JobControl,
        started: Instant,
    ) -> Self {
        Explorer {
            chrome,
            session: String::new(),
            target: String::new(),
            timeouts: AtomicUsize::new(0),
            gateway,
            cfg,
            scope,
            ctl,
            started,
            queue: VecDeque::new(),
            seen_urls: HashSet::new(),
            seen_states: HashSet::new(),
            tried: HashSet::new(),
            per_element: HashMap::new(),
            per_path: HashMap::new(),
            ops: 0,
            out_of_scope: BTreeSet::new(),
            not_clicked: BTreeSet::new(),
            not_clicked_count: 0,
            current: None,
            summary: BrowserCrawlSummary { mode: "browser".into(), ..Default::default() },
        }
    }

    async fn run(&mut self, seeds: &[Url]) -> Result<()> {
        self.open().await?;
        for s in seeds {
            self.enqueue_url(s.as_str(), 0);
        }
        while let Some(a) = self.queue.pop_front() {
            if self.ctl.stopped() {
                break;
            }
            let timed_out = self.started.elapsed() >= self.cfg.crawl.max_duration.unwrap_or(DEFAULT_MAX_DURATION);
            if self.ops >= self.cfg.crawl.max_pages || timed_out {
                self.summary.limit_reached = true;
                break;
            }
            if self.timeouts.load(Ordering::Relaxed) >= MAX_TIMEOUTS {
                self.replace_tab().await?;
            }
            self.summary.depth_reached = self.summary.depth_reached.max(a.depth);
            self.progress();
            match self.perform(&a).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) if !self.chrome.alive() => return Err(e),
                Err(e) => {
                    if matches!(e, Error::Timeout(_)) {
                        self.timeouts.fetch_add(1, Ordering::Relaxed);
                    }
                    self.summary.errors += 1;
                    self.current = None;
                    continue;
                }
            }
            if a.submits {
                self.summary.forms_submitted += 1;
            }
            match self.eval("window.__bp ? __bp.snapshot() : null").await {
                Ok(v) if !v.is_null() => {
                    let snap = serde_json::from_value::<Snapshot>(v).unwrap_or_default().bounded();
                    self.expand(&a, &snap);
                }
                // Not a page the script runs in (an error page, a download): nothing to explore.
                _ => self.current = None,
            }
        }
        self.progress();
        Ok(())
    }

    /// Opens the crawl's tab, with the page script in every document it loads.
    async fn open(&mut self) -> Result<()> {
        let version = self
            .chrome
            .call_timeout("Browser.getVersion", json!({}), None, Duration::from_secs(20))
            .await
            .map_err(|e| Error::InvalidInput(format!("the browser didn't start: {e}")))?;
        self.summary.browser = version["product"].as_str().unwrap_or("").to_string();
        self.chrome.call("Target.setDiscoverTargets", json!({"discover": true}), None).await?;
        let _ = self.chrome.call("Browser.setDownloadBehavior", json!({"behavior": "deny"}), None).await;
        self.open_tab().await
    }

    /// A new tab with the page script in every document it loads.
    async fn open_tab(&mut self) -> Result<()> {
        let target = self.chrome.call("Target.createTarget", json!({"url": "about:blank"}), None).await?;
        self.target = target["targetId"].as_str().unwrap_or("").to_string();
        let attached =
            self.chrome.call("Target.attachToTarget", json!({"targetId": self.target, "flatten": true}), None).await?;
        self.session = attached["sessionId"]
            .as_str()
            .ok_or_else(|| Error::Protocol("the browser gave no session for the crawl tab".into()))?
            .to_string();
        let s = Some(self.session.as_str());
        self.chrome.call("Page.enable", json!({}), s).await?;
        self.chrome.call("Page.addScriptToEvaluateOnNewDocument", json!({"source": PAGE_JS}), s).await?;
        Ok(())
    }

    /// Swaps a tab whose page stopped answering (a script spinning forever) for a fresh one.
    /// The new one opens first: closing a browser's last tab can end the browser.
    async fn replace_tab(&mut self) -> Result<()> {
        let old = std::mem::take(&mut self.target);
        self.open_tab().await?;
        let close = json!({"targetId": old});
        let _ = self.chrome.call_timeout("Target.closeTarget", close, None, Duration::from_secs(5)).await;
        self.timeouts.store(0, Ordering::Relaxed);
        self.current = None;
        self.summary.tab_restarts += 1;
        Ok(())
    }

    fn finish(&mut self) -> BrowserCrawlSummary {
        let mut s = std::mem::take(&mut self.summary);
        s.not_clicked = std::mem::take(&mut self.not_clicked).into_iter().collect();
        s.not_clicked_count = self.not_clicked_count;
        s.out_of_scope_hosts = std::mem::take(&mut self.out_of_scope).into_iter().collect();
        s
    }

    fn progress(&self) {
        let (requests, endpoints) = self.gateway.with_stats(|s| (s.requests, s.endpoints.len()));
        self.ctl.set_progress(json!({
            "mode": "browser",
            "depth": self.summary.depth_reached,
            "requests": requests,
            "queued": self.queue.len(),
            "endpoints": endpoints,
            "states": self.seen_states.len(),
            "clicks": self.summary.clicks,
        }));
    }

    async fn eval(&self, expression: &str) -> Result<Value> {
        let r = self
            .chrome
            .call_timeout(
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true}),
                Some(&self.session),
                Duration::from_secs(10),
            )
            .await
            .inspect_err(|e| {
                if matches!(e, Error::Timeout(_)) {
                    self.timeouts.fetch_add(1, Ordering::Relaxed);
                }
            })?;
        self.timeouts.store(0, Ordering::Relaxed);
        if let Some(ex) = r.get("exceptionDetails") {
            let text = ex["exception"]["description"].as_str().or(ex["text"].as_str()).unwrap_or("exception");
            return Err(Error::Protocol(format!("page script: {text}")));
        }
        Ok(r["result"]["value"].clone())
    }

    /// Waits until no request has been in flight and the DOM hasn't changed for a moment.
    async fn settle(&self) {
        let start = Instant::now();
        tokio::time::sleep(Duration::from_millis(150)).await;
        while !self.ctl.stopped() && start.elapsed() < SETTLE_MAX {
            let quiet = self.eval("window.__bp ? __bp.quiet() : [document.readyState, 1e9]").await.unwrap_or_default();
            let ready = quiet[0].as_str() == Some("complete");
            let dom_quiet = quiet[1].as_f64().unwrap_or(0.0) >= DOM_QUIET_MS;
            if ready && dom_quiet && self.gateway.idle_for() >= NETWORK_QUIET {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Takes one operation from the --max-pages budget; false when it is spent.
    fn spend(&mut self) -> bool {
        if self.ops >= self.cfg.crawl.max_pages {
            self.summary.limit_reached = true;
            return false;
        }
        self.ops += 1;
        true
    }

    /// Loads `url` afresh (through about:blank, so a change of fragment alone reloads too).
    async fn navigate(&mut self, url: &str) -> Result<bool> {
        if !self.spend() {
            return Ok(false);
        }
        let s = Some(self.session.as_str());
        self.chrome.call("Page.navigate", json!({"url": "about:blank"}), s).await?;
        let r = self.chrome.call("Page.navigate", json!({"url": url}), s).await?;
        self.summary.pages_loaded += 1;
        if r["errorText"].as_str().is_some_and(|e| !e.is_empty()) {
            self.summary.errors += 1;
            return Ok(false);
        }
        self.settle().await;
        Ok(true)
    }

    /// Brings the tab to the action's starting state and takes its last step.
    async fn perform(&mut self, a: &Action) -> Result<bool> {
        let Some((last, before)) = a.path.split_last() else {
            self.current = None;
            let ok = self.navigate(&a.url).await?;
            if ok {
                self.current = Some((a.url.clone(), vec![]));
            }
            return Ok(ok);
        };
        let at_start = self.current.as_ref().is_some_and(|(u, p)| *u == a.url && p.as_slice() == before);
        self.current = None;
        if !at_start {
            if !self.navigate(&a.url).await? {
                return Ok(false);
            }
            for step in before {
                if !self.step(step).await? {
                    return Ok(false);
                }
            }
        }
        if !self.step(last).await? {
            return Ok(false);
        }
        self.current = Some((a.url.clone(), a.path.clone()));
        Ok(true)
    }

    /// Fills the visible fields, then clicks or submits. False when the element is gone.
    async fn step(&mut self, step: &Step) -> Result<bool> {
        if !self.spend() {
            return Ok(false);
        }
        self.fill().await?;
        match step {
            Step::Click(key) => {
                let key = serde_json::to_string(key).unwrap_or_default();
                let at = self.eval(&format!("window.__bp ? __bp.locate({key}) : null")).await?;
                if at.is_null() {
                    return Ok(false);
                }
                let (x, y) = (at["x"].as_f64().unwrap_or(0.0), at["y"].as_f64().unwrap_or(0.0));
                if at["hit"].as_bool() == Some(true) {
                    // A real mouse click: hover, press, release (menus that open on hover or
                    // mousedown work as for a person).
                    let s = Some(self.session.as_str());
                    for (kind, button, buttons) in
                        [("mouseMoved", "none", 0), ("mousePressed", "left", 1), ("mouseReleased", "left", 0)]
                    {
                        let ev = json!({"type": kind, "x": x, "y": y, "button": button, "buttons": buttons, "clickCount": 1});
                        self.chrome.call("Input.dispatchMouseEvent", ev, s).await?;
                    }
                } else if self.eval(&format!("__bp.click({key})")).await? != json!(true) {
                    return Ok(false);
                }
                self.summary.clicks += 1;
            }
            Step::Submit(key) => {
                let key = serde_json::to_string(key).unwrap_or_default();
                if self.eval(&format!("window.__bp ? __bp.submit({key}) : false")).await? != json!(true) {
                    return Ok(false);
                }
            }
        }
        self.settle().await;
        Ok(true)
    }

    /// Gives empty fields the spider's test values (required boxes ticked, a select's first value).
    async fn fill(&self) -> Result<()> {
        let mut fields: Vec<Field> =
            serde_json::from_value(self.eval("window.__bp ? __bp.fields() : []").await?).unwrap_or_default();
        fields.truncate(200);
        let pairs: Vec<Value> = fields.iter().filter_map(|f| fill_value(f).map(|v| json!([f.i, v]))).collect();
        if !pairs.is_empty() {
            self.eval(&format!("__bp.setFields({})", Value::Array(pairs))).await?;
        }
        Ok(())
    }

    /// Queues a page load of `raw` if it is in scope and new.
    fn enqueue_url(&mut self, raw: &str, depth: usize) {
        if raw.len() > MAX_URL {
            return;
        }
        let Ok(u) = Url::parse(raw) else { return };
        if !matches!(u.scheme(), "http" | "https") {
            return;
        }
        if !self.scope.allows(&u) {
            if let Some(h) = u.host_str().filter(|_| !self.scope.host_allowed(&u)) {
                if self.out_of_scope.len() < MAX_LISTED {
                    self.out_of_scope.insert(h.to_ascii_lowercase());
                }
            }
            return;
        }
        if is_static(&u) {
            return;
        }
        let url = nav_url(&u);
        if !self.seen_urls.insert(url.clone()) {
            return;
        }
        let route = u.fragment().filter(|f| is_route(f)).map(|f| f.split('?').next().unwrap_or(f)).unwrap_or("");
        let n = self.per_path.entry(format!("{}{}#{route}", u.host_str().unwrap_or(""), u.path())).or_default();
        if *n >= self.cfg.crawl.max_per_path {
            return;
        }
        *n += 1;
        self.queue.push_back(Action { url, path: vec![], depth, parent: None, submits: false });
    }

    /// Queues what a state offers: its links and routes, and its clickable elements and forms.
    fn expand(&mut self, a: &Action, snap: &Snapshot) {
        let deeper = a.depth < self.cfg.crawl.max_depth;
        // Routes and pop-ups the last step produced are crawled wherever the page ended up.
        if deeper {
            for u in snap.routes.iter().chain(&snap.opened) {
                self.enqueue_url(u, a.depth + 1);
            }
        }
        let here = Url::parse(&snap.url).ok();
        if !here.as_ref().is_some_and(|u| self.scope.allows(u)) {
            if let Some(h) = here.as_ref().filter(|u| !self.scope.host_allowed(u)).and_then(|u| u.host_str()) {
                if self.out_of_scope.len() < MAX_LISTED {
                    self.out_of_scope.insert(h.to_ascii_lowercase());
                }
            }
            self.current = None;
            return;
        }
        // A click that changed the address: loading that address is crawled too.
        if !a.path.is_empty() && deeper {
            self.enqueue_url(&snap.url, a.depth + 1);
        }
        let key = state_key(snap);
        if a.parent == Some(key) {
            // Nothing visible changed: the tab is still in the state the step started from.
            self.current = Some((a.url.clone(), a.path[..a.path.len() - 1].to_vec()));
        }
        if !self.seen_states.insert(key) {
            return;
        }
        self.summary.states += 1;
        if !deeper {
            return;
        }
        for l in &snap.links {
            // A link labelled "Delete account" or "Log out" isn't followed either.
            if avoided(l, &self.cfg.avoid, &self.cfg.crawl.exclude) {
                self.not_clicked_count += 1;
                if self.not_clicked.len() < MAX_LISTED {
                    self.not_clicked.insert(describe(l));
                }
                continue;
            }
            self.enqueue_url(&l.href, a.depth + 1);
        }
        if a.path.len() >= MAX_CHAIN {
            return;
        }
        let mut queued = 0;
        let next = |explorer: &mut Self, step: Step, submits: bool| {
            let mut path = a.path.clone();
            path.push(step);
            explorer.queue.push_back(Action {
                url: a.url.clone(),
                path,
                depth: a.depth + 1,
                parent: Some(key),
                submits,
            });
        };
        for c in &snap.clickables {
            if queued >= MAX_CLICKS_PER_STATE {
                break;
            }
            if c.submits && !self.cfg.crawl.submit_forms {
                continue;
            }
            if avoided(c, &self.cfg.avoid, &self.cfg.crawl.exclude) {
                self.not_clicked_count += 1;
                if self.not_clicked.len() < MAX_LISTED {
                    self.not_clicked.insert(describe(c));
                }
                continue;
            }
            // Once per state; the same element in other states counts towards MAX_PER_ELEMENT.
            if !self.tried.insert(format!("{key:x} {}", c.key)) {
                continue;
            }
            let n = self.per_element.entry(c.key.clone()).or_default();
            if *n >= MAX_PER_ELEMENT {
                continue;
            }
            *n += 1;
            queued += 1;
            next(self, Step::Click(c.key.clone()), c.submits);
        }
        if self.cfg.crawl.submit_forms {
            // Forms without a submit button (those with one are submitted by clicking it).
            for f in snap.forms.iter().filter(|f| !f.has_submit) {
                if self.cfg.crawl.exclude.iter().any(|r| r.is_match(&f.action))
                    || !self.tried.insert(format!("{key:x} {} {}", f.key, f.action))
                {
                    continue;
                }
                next(self, Step::Submit(f.key.clone()), true);
            }
        }
    }
}

/// The value to type into a field, if it needs one.
fn fill_value(f: &Field) -> Option<Value> {
    match (f.tag.as_str(), f.kind.as_str()) {
        ("select", _) => {
            f.value.is_empty().then(|| f.options.iter().find(|o| !o.is_empty()).cloned()).flatten().map(Value::from)
        }
        (_, "checkbox" | "radio") => (f.required && !f.checked).then_some(Value::Bool(true)),
        (_, "file" | "submit" | "button" | "image" | "reset" | "hidden" | "range" | "color") => None,
        _ if !f.value.is_empty() => None,
        ("textarea", _) => Some(field_value(&f.name, "text", None).into()),
        _ => Some(field_value(&f.name, if f.kind.is_empty() { "text" } else { &f.kind }, None).into()),
    }
}

/// A fragment that is a client-side route (`#/users`, `#!/users`) rather than an anchor.
fn is_route(fragment: &str) -> bool {
    fragment.starts_with('/') || fragment.starts_with("!/")
}

/// The URL to load: anchors dropped, hash routes kept.
fn nav_url(u: &Url) -> String {
    let mut u = u.clone();
    if !u.fragment().is_some_and(is_route) {
        u.set_fragment(None);
    }
    u.to_string()
}

/// A path segment that is an id: digits, or a long hex/UUID-like string.
fn is_id(seg: &str) -> bool {
    !seg.is_empty()
        && (seg.bytes().all(|b| b.is_ascii_digit())
            || seg.len() >= 16 && seg.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
}

fn shape_path(p: &str) -> String {
    p.split('/').map(|s| if is_id(s) { "N" } else { s }).collect::<Vec<_>>().join("/")
}

/// An address with ids masked and only the names of query parameters: /items/7?page=2
/// and /items/9?page=3 have the same shape.
pub(crate) fn route_shape(raw: &str) -> String {
    let Ok(u) = Url::parse(raw) else { return raw.to_string() };
    let mut s = format!(
        "{}://{}:{}{}",
        u.scheme(),
        u.host_str().unwrap_or(""),
        u.port_or_known_default().unwrap_or(0),
        shape_path(u.path())
    );
    let mut names: Vec<String> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
    names.sort();
    names.dedup();
    if !names.is_empty() {
        s.push('?');
        s.push_str(&names.join("&"));
    }
    if let Some(f) = u.fragment().filter(|f| is_route(f)) {
        s.push('#');
        s.push_str(&shape_path(f.split('?').next().unwrap_or(f)));
    }
    s
}

/// Element text with numbers masked: "3 new messages" and "4 new messages" are the same.
fn shape_text(t: &str) -> String {
    static NUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+").unwrap());
    let t = NUM.replace_all(&t.to_lowercase(), "N").split_whitespace().collect::<Vec<_>>().join(" ");
    t.chars().take(40).collect()
}

/// Identifies a DOM state by its shape: the address (ids masked), and the sets (not lists:
/// order and repeats don't count) of clickable elements, link addresses and forms. Text
/// that isn't a label and field values don't count.
pub(crate) fn state_key(s: &Snapshot) -> u64 {
    let mut parts: BTreeSet<String> = BTreeSet::new();
    parts.insert(format!("at {}", route_shape(&s.url)));
    for c in &s.clickables {
        parts.insert(format!("click {}|{}|{}|{}|{}", c.tag, c.role, c.kind, shape_text(&c.text), c.id));
    }
    for l in &s.links {
        parts.insert(format!("link {}", route_shape(&l.href)));
    }
    for f in &s.forms {
        parts.insert(format!("form {} {}", f.method, route_shape(&f.action)));
    }
    let mut h = std::hash::DefaultHasher::new();
    parts.hash(&mut h);
    h.finish()
}

/// "deleteItem", "delete_item" and "delete-item" all read "delete item".
fn words(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    let mut prev_lower = false;
    for c in s.chars() {
        if c.is_uppercase() && prev_lower {
            out.push(' ');
        }
        out.push(if c == '_' { ' ' } else { c });
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
    }
    out
}

/// Whether an element must not be clicked: a label matching `avoid` (logout, delete, ...),
/// or a link or form target matching the crawl's URL exclusions.
pub(crate) fn avoided(c: &Clickable, avoid: &[Regex], exclude: &[Regex]) -> bool {
    let labels = [&c.text, &c.id, &c.name, &c.class, &c.title, &c.href]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| words(s))
        .collect::<Vec<_>>()
        .join(" | ");
    avoid.iter().any(|r| r.is_match(&labels))
        || [&c.href, &c.action].iter().any(|u| !u.is_empty() && exclude.iter().any(|r| r.is_match(u)))
}

/// A short description of an element for the summary.
fn describe(c: &Clickable) -> String {
    let label = [&c.text, &c.title, &c.id, &c.name, &c.class, &c.href]
        .into_iter()
        .find(|s| !s.is_empty())
        .cloned()
        .unwrap_or_default();
    format!("<{}> {}", c.tag, label.chars().take(60).collect::<String>())
}

/// Prints an HTML page to PDF in a headless Chromium at `browser`. The page is set as the
/// document's content, so nothing is fetched: the browser's proxy is a closed local port, and
/// a report's own policy allows no requests. The PDF is read back in chunks.
pub async fn print_pdf(browser: &Path, html: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let opts = cdp::LaunchOptions {
        path: browser,
        headless: true,
        // Port 9 (discard) on loopback: anything the page tried to load would fail there.
        proxy: std::net::SocketAddr::from(([127, 0, 0, 1], 9)),
        ca_spki: String::new(),
        no_sandbox: cdp::sandbox_off(),
    };
    let chrome = cdp::Chrome::launch(&opts)?;
    let result = async {
        let target = chrome.call("Target.createTarget", json!({"url": "about:blank"}), None).await?;
        let target = target["targetId"].as_str().unwrap_or_default().to_string();
        let attached = chrome.call("Target.attachToTarget", json!({"targetId": target, "flatten": true}), None).await?;
        let session = attached["sessionId"].as_str().unwrap_or_default().to_string();
        let s = Some(session.as_str());
        chrome.call("Page.enable", json!({}), s).await?;
        let tree = chrome.call("Page.getFrameTree", json!({}), s).await?;
        let frame = tree["frameTree"]["frame"]["id"].as_str().unwrap_or_default().to_string();
        chrome.call("Page.setDocumentContent", json!({"frameId": frame, "html": html}), s).await?;
        let printed = chrome
            .call_timeout(
                "Page.printToPDF",
                json!({"printBackground": true, "preferCSSPageSize": true, "transferMode": "ReturnAsStream"}),
                s,
                Duration::from_secs(120),
            )
            .await?;
        let handle = printed["stream"].as_str().unwrap_or_default().to_string();
        let mut pdf = Vec::new();
        loop {
            let chunk = chrome.call("IO.read", json!({"handle": handle, "size": 1 << 20}), s).await?;
            let data = chunk["data"].as_str().unwrap_or_default();
            if chunk["base64Encoded"] == true {
                pdf.extend(
                    base64::engine::general_purpose::STANDARD
                        .decode(data)
                        .map_err(|e| Error::Protocol(format!("the browser's PDF isn't base64: {e}")))?,
                );
            } else {
                pdf.extend_from_slice(data.as_bytes());
            }
            if chunk["eof"] == true {
                break;
            }
        }
        let _ = chrome.call("IO.close", json!({"handle": handle}), s).await;
        if !pdf.starts_with(b"%PDF") {
            return Err(Error::Protocol("the browser didn't return a PDF".into()));
        }
        Ok(pdf)
    }
    .await;
    chrome.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn click(tag: &str, text: &str) -> Clickable {
        Clickable { key: format!("{tag}|||{text}|#1"), tag: tag.into(), text: text.into(), ..Default::default() }
    }

    fn snap(url: &str, clicks: &[(&str, &str)], links: &[&str]) -> Snapshot {
        Snapshot {
            url: url.into(),
            clickables: clicks.iter().map(|(t, x)| click(t, x)).collect(),
            links: links
                .iter()
                .map(|s| Clickable { tag: "a".into(), href: s.to_string(), ..Default::default() })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn states_are_keyed_on_shape_not_content() {
        let a =
            snap("https://a.test/items/7?page=2", &[("button", "Edit"), ("button", "3 new")], &["https://a.test/x/1"]);
        // Other ids, page numbers, counts, order and repeats: the same state.
        let b = snap(
            "https://a.test/items/9?page=3",
            &[("button", "4 new"), ("button", "Edit"), ("button", "Edit")],
            &["https://a.test/x/2", "https://a.test/x/3"],
        );
        assert_eq!(state_key(&a), state_key(&b));
        // A new button, link, form, route or address: a new state.
        let c = snap(
            "https://a.test/items/7?page=2",
            &[("button", "Edit"), ("button", "3 new"), ("button", "Save")],
            &["https://a.test/x/1"],
        );
        assert_ne!(state_key(&a), state_key(&c));
        let d =
            snap("https://a.test/items/7?page=2", &[("button", "Edit"), ("button", "3 new")], &["https://a.test/y/1"]);
        assert_ne!(state_key(&a), state_key(&d));
        let mut e =
            snap("https://a.test/items/7?page=2", &[("button", "Edit"), ("button", "3 new")], &["https://a.test/x/1"]);
        e.forms.push(Form {
            key: "form#1".into(),
            action: "https://a.test/search".into(),
            method: "get".into(),
            has_submit: true,
        });
        assert_ne!(state_key(&a), state_key(&e));
        assert_ne!(
            state_key(&snap("https://a.test/#/users", &[], &[])),
            state_key(&snap("https://a.test/#/admin", &[], &[]))
        );
        assert_eq!(
            state_key(&snap("https://a.test/#/users/12", &[], &[])),
            state_key(&snap("https://a.test/#/users/13", &[], &[]))
        );
        // An in-page anchor isn't a route.
        assert_eq!(state_key(&snap("https://a.test/p#top", &[], &[])), state_key(&snap("https://a.test/p", &[], &[])));
        assert_ne!(
            state_key(&snap("https://a.test/about", &[], &[])),
            state_key(&snap("https://a.test/contact", &[], &[]))
        );
    }

    #[test]
    fn route_shapes_and_load_urls() {
        assert_eq!(
            route_shape("https://a.test/u/42/orders/3f2a9c1e-77aa-4bcd-9e00-1234567890ab?b=1&a=2&a=3"),
            "https://a.test:443/u/N/orders/N?a&b"
        );
        assert_eq!(route_shape("http://a.test:8080/#/users/7?tab=x"), "http://a.test:8080/#/users/N");
        let u = Url::parse("https://a.test/docs#section-2").unwrap();
        assert_eq!(nav_url(&u), "https://a.test/docs");
        let u = Url::parse("https://a.test/#!/settings").unwrap();
        assert_eq!(nav_url(&u), "https://a.test/#!/settings");
    }

    #[test]
    fn destructive_elements_are_not_clicked() {
        let avoid = vec![Regex::new(DEFAULT_AVOID).unwrap()];
        let exclude = vec![Regex::new(crate::crawl::DEFAULT_EXCLUDE).unwrap()];
        let no = |c: &Clickable| avoided(c, &avoid, &exclude);
        for text in [
            "Log out",
            "Logout",
            "Sign out",
            "Delete",
            "Remove item",
            "Delete account",
            "Cancel my subscription",
            "Reset",
        ] {
            assert!(no(&click("button", text)), "{text}");
        }
        for id in ["deleteItem", "delete_item", "btn-remove", "signOut"] {
            assert!(no(&Clickable { id: id.into(), tag: "button".into(), ..Default::default() }), "{id}");
        }
        let link = Clickable { tag: "a".into(), href: "/session/logout?next=/".into(), ..Default::default() };
        assert!(no(&link));
        // Links are judged by their labels too, not only their URL.
        let delete = Clickable {
            tag: "a".into(),
            text: "Delete account".into(),
            href: "https://a.test/account/7".into(),
            ..Default::default()
        };
        assert!(no(&delete));
        let profile = Clickable {
            tag: "a".into(),
            text: "Profile".into(),
            href: "https://a.test/account/7".into(),
            ..Default::default()
        };
        assert!(!no(&profile));
        let submit = Clickable {
            tag: "button".into(),
            text: "Go".into(),
            submits: true,
            action: "https://a.test/signout".into(),
            ..Default::default()
        };
        assert!(no(&submit));
        for text in
            ["Save", "Search", "Load more", "Show deleted items", "Removed", "Dropdown", "Next page", "Add to cart"]
        {
            assert!(!no(&click("button", text)), "{text}");
        }
        // --allow-destructive: nothing avoided by label, but excluded URLs still are.
        assert!(!avoided(&click("button", "Delete"), &[], &exclude));
        assert!(avoided(&link, &[], &exclude));
    }

    #[test]
    fn fields_get_test_values() {
        let f = |tag: &str, kind: &str, name: &str, value: &str| Field {
            tag: tag.into(),
            kind: kind.into(),
            name: name.into(),
            value: value.into(),
            ..Default::default()
        };
        assert_eq!(fill_value(&f("input", "email", "x", "")), Some(json!("foo-bar@example.com")));
        assert_eq!(fill_value(&f("input", "text", "q", "")), Some(json!("brainproxy")));
        assert_eq!(fill_value(&f("textarea", "textarea", "comment", "")), Some(json!("brainproxy")));
        assert_eq!(fill_value(&f("input", "text", "q", "kept")), None);
        assert_eq!(fill_value(&f("input", "file", "upload", "")), None);
        let mut sel = f("select", "select-one", "c", "");
        sel.options = vec!["".into(), "uk".into()];
        assert_eq!(fill_value(&sel), Some(json!("uk")));
        let mut terms = f("input", "checkbox", "terms", "on");
        assert_eq!(fill_value(&terms), None);
        terms.required = true;
        assert_eq!(fill_value(&terms), Some(json!(true)));
    }
}
