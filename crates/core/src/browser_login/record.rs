//! Recording a login's steps. `auth record start` opens the login browser with the DevTools
//! protocol attached; a script in each page ([`RECORD_JS`]) reports what the person does, and
//! `auth record finish` turns the recording into steps ([`derive`]). With a virtual
//! authenticator in the tab, a passkey the person registers is kept too.
//!
//! A recording holds what was typed, the password included, and a passkey's private key. Until
//! a profile is saved from it, it lives only in the memory of the process that holds the
//! browser, which hands it over a socket in a folder of its own that only the owner can enter
//! ([`ask`]). The project keeps where that socket is and how the recording stands
//! ([`Status`]), nothing of what it holds: `query` can read that table.

// The recorder itself runs where the DevTools pipe does (see [`crate::browser_crawl::cdp`]).
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{add_authenticator, authenticator_keys, Do, Passkey, Step, MAX_STEPS};
use crate::browser_crawl::cdp::{self, Chrome, LaunchOptions};
use crate::error::{Error, Result};
use crate::store::Store;

const RECORD_JS: &str = include_str!("record.js");
/// Where the project keeps how its recording stands (a [`Status`]).
const STATUS_KEY: &str = "auth.record.browser";
/// How long a finished recording is held for `auth record finish --save` to take.
const HOLD_MAX: Duration = Duration::from_secs(2 * 3600);
/// The isolated world the recorder's script runs in.
const WORLD: &str = "brainproxy_record";
/// Events kept: a login is a handful of steps.
const MAX_EVENTS: usize = 2000;

/// What the page script reports, and what the recorder adds (`goto`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Event {
    /// fill, select, check, click, press, or goto.
    pub t: String,
    pub css: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub value: String,
    pub checked: bool,
    pub key: String,
    /// The page it happened on, and whether in the page itself (not a frame in it).
    pub url: String,
    pub top: bool,
    /// Milliseconds since 1970, by the browser's clock.
    pub ts: u64,
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub id: String,
    pub autocomplete: String,
    pub maxlength: u32,
    pub hint: String,
    pub label: String,
    /// The last history row when it happened: what the proxy recorded before the step.
    pub history: i64,
}

/// A recording, as its recorder hands it to `auth record finish`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Recording {
    pub url: String,
    pub events: Vec<Event>,
    /// A virtual authenticator was in the tab.
    pub passkey: bool,
    /// Its credentials when last looked at.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<Passkey>,
    /// Whether a passkey signed in during the recording (a count went up).
    pub passkey_used: bool,
    /// Something happened where steps aren't recorded: another tab or window, or a frame.
    pub elsewhere: bool,
}

/// How the project's recording stands, and where its recorder answers. No secret in it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Status {
    /// starting, recording, done (the browser is closed; the recording is held), or failed.
    pub state: String,
    /// The recorder: the process that holds the browser and the recording.
    pub pid: u32,
    /// The socket it hands the recording over ([`ask`]).
    pub socket: PathBuf,
    /// The project file the recording is for. A copy of the project carries this note too, and
    /// the recording isn't the copy's to take or to end.
    pub project: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Store {
    /// How this project's recording stands. None too for a note copied in with another
    /// project's file.
    pub fn auth_recording_status(&self) -> Result<Option<Status>> {
        let own = self.path().and_then(|p| std::fs::canonicalize(p).ok());
        let status: Option<Status> = self.meta_get(STATUS_KEY)?.and_then(|s| serde_json::from_str(&s).ok());
        Ok(status.filter(|s| own.as_deref() == Some(s.project.as_path())))
    }

    pub fn auth_set_recording_status(&self, s: Option<&Status>) -> Result<()> {
        let json = s.map(|s| serde_json::to_string(s).map_err(|e| Error::InvalidInput(e.to_string()))).transpose()?;
        self.meta_set(STATUS_KEY, json.as_deref())
    }
}

/// What a recorder is asked over its socket.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ask {
    /// Stop recording (the browser closes) and give the recording; it is still held.
    Stop,
    /// The recording was taken into a profile, or isn't wanted: let go of it and exit.
    Done,
}

/// Asks the recorder at `socket`. For [`Ask::Stop`], the recording.
#[cfg(unix)]
pub fn ask(socket: &Path, what: Ask) -> Result<Option<Recording>> {
    use std::io::{Read, Write};
    let gone = |e: std::io::Error| Error::NotFound(format!("the login recording (its recorder doesn't answer: {e})"));
    let mut s = std::os::unix::net::UnixStream::connect(socket).map_err(gone)?;
    // Closing the browser and reading its passkeys takes a moment.
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(if what == Ask::Stop { b"stop\n" } else { b"done\n" }).map_err(gone)?;
    let mut reply = Vec::new();
    s.read_to_end(&mut reply).map_err(gone)?;
    if what == Ask::Done {
        return Ok(None);
    }
    let rec = serde_json::from_slice(&reply).map_err(|e| Error::Protocol(format!("the recorder's answer: {e}")))?;
    Ok(Some(rec))
}

#[cfg(not(unix))]
pub fn ask(_socket: &Path, _what: Ask) -> Result<Option<Recording>> {
    Err(Error::InvalidInput("steps are recorded on Linux and macOS".into()))
}

/// A new folder only its owner can enter, for the recorder's socket; removed when dropped.
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn new() -> Result<PrivateDir> {
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        let dir = std::env::temp_dir().join(format!("brainproxy-record-{}-{}", std::process::id(), hex::encode(rnd)));
        let mut b = std::fs::DirBuilder::new();
        b.recursive(false);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&dir)?;
        Ok(PrivateDir(dir))
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct RecordOptions<'a> {
    /// The profile `passkeys` are from: the counts they reach while recording are stored
    /// with it as they go, whatever becomes of the recording (the site has counted them).
    pub passkeys_from: Option<String>,
    pub browser: &'a Path,
    /// The running proxy, which records the login's traffic as it does today.
    pub proxy: SocketAddr,
    pub ca_spki: String,
    pub url: String,
    /// Put a virtual authenticator in the tab, so a passkey can be registered and used.
    pub passkey: bool,
    /// Passkeys it starts with (a profile's, to record its login again).
    pub passkeys: Vec<Passkey>,
    /// For automated tests of a login page: no window, and events a page script fires count.
    pub unattended: bool,
}

/// Opens the login browser at `opts.url` and records until the person closes it, `auth record
/// finish` asks ([`Ask::Stop`]), or the process is told to end. The recording is then held,
/// for [`HOLD_MAX`] at most, until it is taken into a profile ([`Ask::Done`]). The project is
/// told how the recording stands ([`Status`]) and nothing of what it holds.
#[cfg(unix)]
pub async fn record(project: &Path, opts: RecordOptions<'_>) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let store = Store::open(project)?;
    let dir = PrivateDir::new()?;
    let socket = dir.0.join("recorder");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let mut rec = Recording {
        url: opts.url.clone(),
        passkey: opts.passkey,
        passkeys: opts.passkeys.clone(),
        ..Default::default()
    };
    let mut status = Status {
        state: "starting".into(),
        pid: std::process::id(),
        socket,
        project: std::fs::canonicalize(project)?,
        error: None,
    };
    store.auth_set_recording_status(Some(&status))?;
    // Whoever asked for the recording while it ran gets it once the browser is closed.
    let mut waiting = Vec::new();
    let ran = run(&store, &opts, &mut rec, &mut status, &listener, &mut waiting).await;
    // Another recording may have taken the project's status since: then this one is over.
    let ours =
        |store: &Store| store.auth_recording_status().ok().flatten().is_some_and(|s| s.pid == std::process::id());
    let held = match ran {
        Ok(held) => held,
        Err(e) => {
            status.state = "failed".into();
            status.error = Some(e.to_string());
            if ours(&store) {
                store.auth_set_recording_status(Some(&status))?;
            }
            return Err(e);
        }
    };
    let json = serde_json::to_vec(&rec).map_err(|e| Error::InvalidInput(e.to_string()))?;
    for mut conn in waiting {
        let _ = conn.write_all(&json).await;
        let _ = conn.shutdown().await;
    }
    if held && ours(&store) {
        status.state = "done".into();
        store.auth_set_recording_status(Some(&status))?;
        let stop = crate::browser_crawl::interrupted();
        tokio::pin!(stop);
        let deadline = tokio::time::sleep(HOLD_MAX);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut stop => break,
                () = &mut deadline => break,
                conn = listener.accept() => {
                    let Ok((mut conn, _)) = conn else { continue };
                    match request(&mut conn).await {
                        Some(Ask::Stop) => {
                            let _ = conn.write_all(&json).await;
                            let _ = conn.shutdown().await;
                        }
                        Some(Ask::Done) => break,
                        None => {}
                    }
                }
            }
        }
    }
    if ours(&store) {
        store.auth_set_recording_status(None)?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn record(_project: &Path, _opts: RecordOptions<'_>) -> Result<()> {
    Err(Error::InvalidInput("steps are recorded on Linux and macOS".into()))
}

/// What a connection to the recorder asks, if it says so in time.
#[cfg(unix)]
async fn request(conn: &mut tokio::net::UnixStream) -> Option<Ask> {
    use tokio::io::AsyncReadExt;
    let mut line = [0u8; 8];
    let mut n = 0;
    let read = async {
        while n < line.len() && !line[..n].contains(&b'\n') {
            match conn.read(&mut line[n..]).await {
                Ok(0) | Err(_) => break,
                Ok(k) => n += k,
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), read).await;
    match line[..n].split(|b| *b == b'\n').next()? {
        b"stop" => Some(Ask::Stop),
        b"done" => Some(Ask::Done),
        _ => None,
    }
}

/// Records until asked to stop. Whether the recording is to be held afterwards (not when
/// it was called off).
#[cfg(unix)]
async fn run(
    store: &Store,
    opts: &RecordOptions<'_>,
    rec: &mut Recording,
    status: &mut Status,
    listener: &tokio::net::UnixListener,
    waiting: &mut Vec<tokio::net::UnixStream>,
) -> Result<bool> {
    let chrome = Chrome::launch(&LaunchOptions {
        path: opts.browser,
        headless: opts.unattended,
        proxy: opts.proxy,
        ca_spki: opts.ca_spki.clone(),
        no_sandbox: cdp::sandbox_off(),
        hands_off: true,
    })?;
    let mut events = chrome.events();
    chrome
        .call_timeout("Browser.getVersion", json!({}), None, Duration::from_secs(20))
        .await
        .map_err(|e| Error::InvalidInput(format!("the browser didn't start: {e}")))?;
    // The window's own tab.
    let targets = chrome.call("Target.getTargets", json!({}), None).await?;
    let page = targets["targetInfos"]
        .as_array()
        .and_then(|a| a.iter().find(|t| t["type"] == "page"))
        .and_then(|t| t["targetId"].as_str())
        .map(str::to_string);
    let page = match page {
        Some(p) => p,
        None => {
            let t = chrome.call("Target.createTarget", json!({"url": "about:blank"}), None).await?;
            t["targetId"].as_str().unwrap_or_default().to_string()
        }
    };
    let attached = chrome.call("Target.attachToTarget", json!({"targetId": page, "flatten": true}), None).await?;
    let session = attached["sessionId"]
        .as_str()
        .ok_or_else(|| Error::Protocol("the browser gave no session for the login tab".into()))?
        .to_string();
    let s = Some(session.as_str());
    chrome.call("Target.setDiscoverTargets", json!({"discover": true}), None).await?;
    chrome.call("Page.enable", json!({}), s).await?;
    chrome.call("Runtime.enable", json!({}), s).await?;
    // The script and the binding it reports through are in a world of their own: the page's
    // scripts can't call the binding, so a page can't make up steps the person never took.
    chrome.call("Runtime.addBinding", json!({"name": "__bpRecord", "executionContextName": WORLD}), s).await?;
    let script =
        if opts.unattended { format!("window.__bpRecordAll = true;\n{RECORD_JS}") } else { RECORD_JS.to_string() };
    chrome.call("Page.addScriptToEvaluateOnNewDocument", json!({"source": script, "worldName": WORLD}), s).await?;
    let authenticator = match opts.passkey {
        true => Some(add_authenticator(&chrome, &session, &opts.passkeys).await?),
        false => None,
    };
    let frames = chrome.call("Page.getFrameTree", json!({}), s).await?;
    let main_frame = frames["frameTree"]["frame"]["id"].as_str().unwrap_or_default().to_string();
    let opened = chrome.call("Page.navigate", json!({"url": opts.url}), s).await?;
    if let Some(e) = opened["errorText"].as_str().filter(|e| !e.is_empty()) {
        return Err(Error::InvalidInput(format!(
            "{} didn't load ({e}); is the proxy running and the site in scope?",
            opts.url
        )));
    }
    status.state = "recording".into();
    store.auth_set_recording_status(Some(status))?;

    // When the page itself asked for a navigation (a link, a form, a script): the one under
    // way, unless that was long ago (one that never came to a new page, a download say).
    let mut asked: Option<Instant> = None;
    // The first page is the one opened above.
    let mut started = false;
    let mut last_action = Instant::now() - Duration::from_secs(60);
    let mut held = true;
    let mut last_keys = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(300));
    let stop = crate::browser_crawl::interrupted();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            () = &mut stop => break,
            _ = tick.tick() => {
                if !chrome.alive() {
                    break;
                }
                // The passkeys as they are now: the person may close the browser at any time.
                if let Some(id) = authenticator.as_deref().filter(|_| last_keys.elapsed() >= Duration::from_secs(1)) {
                    last_keys = Instant::now();
                    look_at_keys(&chrome, &session, id, rec, store, opts.passkeys_from.as_deref()).await;
                }
            }
            conn = listener.accept() => {
                let Ok((mut conn, _)) = conn else { continue };
                match request(&mut conn).await {
                    Some(Ask::Stop) => {
                        waiting.push(conn);
                        break;
                    }
                    Some(Ask::Done) => {
                        held = false;
                        break;
                    }
                    None => {}
                }
            }
            msg = events.recv() => {
                let Some(msg) = msg else { break };
                let ours = msg["sessionId"].as_str() == Some(session.as_str());
                let params = &msg["params"];
                match msg["method"].as_str() {
                    Some("Runtime.bindingCalled") if ours && params["name"] == "__bpRecord" => {
                        let payload = params["payload"].as_str().unwrap_or_default();
                        let event = serde_json::from_str::<Event>(payload).ok().filter(|_| payload.len() <= 65536);
                        let Some(mut event) = event.filter(|_| rec.events.len() < MAX_EVENTS) else { continue };
                        if !event.top {
                            rec.elsewhere = true;
                        }
                        event.history = store.last_history_id().unwrap_or(0);
                        last_action = Instant::now();
                        rec.events.push(event);
                    }
                    Some("Page.frameRequestedNavigation") if ours && params["frameId"] == main_frame.as_str() => {
                        asked = Some(Instant::now());
                    }
                    Some("Page.frameNavigated") if ours && params["frame"]["parentId"].is_null() => {
                        let url = params["frame"]["url"].as_str().unwrap_or_default();
                        // A page the person opened by its address: nothing they did in the page
                        // led to it. (One a step led to is reached again by replaying the step.)
                        let by_page = asked.is_some_and(|at| at.elapsed() < Duration::from_secs(30));
                        let typed = started && !by_page && last_action.elapsed() > Duration::from_secs(1);
                        if typed && (url.starts_with("http://") || url.starts_with("https://")) && rec.events.len() < MAX_EVENTS {
                            let history = store.last_history_id().unwrap_or(0);
                            rec.events.push(Event { t: "goto".into(), url: url.to_string(), top: true, history, ..Default::default() });
                        }
                        started = true;
                        asked = None;
                    }
                    // Another tab or a pop-up window: what happens there isn't recorded.
                    Some("Target.targetCreated") if params["targetInfo"]["type"] == "page" && params["targetInfo"]["targetId"] != page.as_str() => {
                        rec.elsewhere = true;
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(id) = authenticator.as_deref().filter(|_| chrome.alive()) {
        look_at_keys(&chrome, &session, id, rec, store, opts.passkeys_from.as_deref()).await;
    }
    chrome.close().await;
    Ok(held)
}

/// Takes the authenticator's credentials into the recording.
#[cfg(unix)]
async fn look_at_keys(
    chrome: &Chrome,
    session: &str,
    id: &str,
    rec: &mut Recording,
    store: &Store,
    from: Option<&str>,
) {
    let Ok(keys) = authenticator_keys(chrome, session, id).await else { return };
    let signed = keys.iter().any(|k| {
        rec.passkeys.iter().find(|o| o.credential_id == k.credential_id).is_some_and(|o| k.sign_count > o.sign_count)
    });
    if let Some(profile) = from.filter(|_| signed) {
        let counts: Vec<(String, u64)> = keys.iter().map(|k| (k.credential_id.clone(), k.sign_count)).collect();
        if let Err(e) = store.auth_advance_passkeys(profile, &counts) {
            eprintln!("brainproxy: the passkey counts of {profile} weren't stored: {e}");
        }
    }
    rec.passkey_used |= signed;
    rec.passkeys = keys;
}

/// What a recording comes to.
#[derive(Debug, Default, PartialEq)]
pub struct Derived {
    pub steps: Vec<Step>,
    pub username: Option<String>,
    /// What was typed into the login's password field.
    pub password: Option<String>,
    /// The one-time code typed, and when (seconds since 1970).
    pub code: Option<(String, u64)>,
    /// The last history row when the last step was taken, and the page it was taken on: what
    /// the proxy recorded after them shows the logged-in site.
    pub last_history: i64,
    pub last_page: String,
    pub warnings: Vec<String>,
}

fn is_otp_field(e: &Event) -> bool {
    let names = [&e.name, &e.id, &e.hint].map(|s| s.to_ascii_lowercase());
    if e.autocomplete.contains("one-time-code") {
        return true;
    }
    // A customer number or a postcode is a "code" too, and typed the same every time.
    const OTHER: [&str; 12] = [
        "zip", "post", "country", "area", "promo", "coupon", "voucher", "discount", "invite", "referral", "customer",
        "company",
    ];
    if is_user_field(e) || names.iter().any(|n| OTHER.iter().any(|w| n.contains(w))) {
        return false;
    }
    let word = |n: &String, words: &[&str]| n.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| words.contains(&w));
    names.iter().any(|n| {
        ["otp", "totp", "mfa", "2fa", "twofa", "one-time", "verification", "authenticator"]
            .iter()
            .any(|w| n.contains(w))
            || word(n, &["code", "token", "passcode"])
    })
}

fn is_code(v: &str) -> bool {
    (4..=10).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit())
}

fn is_user_field(e: &Event) -> bool {
    let names = [&e.name, &e.id, &e.hint, &e.autocomplete].map(|s| s.to_ascii_lowercase());
    e.kind == "email"
        || names.iter().any(|n| ["user", "login", "email", "mail", "account", "ident"].iter().any(|w| n.contains(w)))
}

/// Turns what was recorded into steps: what was typed into the password field becomes
/// `{{password}}`, the user name `{{username}}`, a one-time code `{{totp}}` (or `{{totp:N}}`
/// for a box per digit); a field typed in twice keeps what it held last. `from` (1-based)
/// drops the steps before it, for a recording that did more than log in.
pub fn derive(rec: &Recording, from: usize) -> Derived {
    let mut out = Derived::default();
    let all: Vec<&Event> = rec.events.iter().filter(|e| e.top).collect();
    if all.len() < rec.events.len() || rec.elsewhere {
        out.warnings.push(
            "Something was done in another tab, a pop-up window or an embedded frame; steps there aren't recorded, \
             so the replay may stop short."
                .into(),
        );
    }
    let events = all;
    // The password: what the first password field held last.
    let password = events
        .iter()
        .find(|e| e.t == "fill" && e.kind == "password" && !e.value.is_empty())
        .and_then(|first| events.iter().rev().find(|e| e.t == "fill" && e.css == first.css))
        .map(|e| e.value.clone());
    // A code typed a digit per box: consecutive one-character fields, each given a digit.
    let single =
        |e: &Event| e.t == "fill" && e.maxlength == 1 && e.value.len() == 1 && e.value.as_bytes()[0].is_ascii_digit();
    let mut digit_of: std::collections::HashMap<usize, usize> = Default::default();
    let mut i = 0;
    while i < events.len() {
        let run = events[i..].iter().take_while(|e| single(e)).count();
        if run >= 4 {
            for n in 0..run {
                digit_of.insert(i + n, n + 1);
            }
            let code: String = events[i..i + run].iter().map(|e| e.value.as_str()).collect();
            out.code = Some((code, events[i + run - 1].ts / 1000));
        }
        i += run.max(1);
    }
    // The user name: a field that says so, else the last text typed before the password.
    let text = |e: &&&Event| e.t == "fill" && e.kind != "password" && !e.value.is_empty() && !is_code(&e.value);
    let before_password = events.iter().position(|e| e.t == "fill" && e.kind == "password").unwrap_or(events.len());
    let user = events
        .iter()
        .filter(text)
        .find(|e| is_user_field(e))
        .or_else(|| events[..before_password].iter().rfind(text))
        // What the field held last, if it was typed in twice.
        .and_then(|field| events.iter().filter(text).rfind(|e| e.css == field.css))
        .map(|e| (e.css.clone(), e.value.clone()));

    for (i, e) in events.iter().enumerate() {
        let mut step = Step {
            action: Do::Click,
            css: e.css.clone(),
            text: e.text.clone(),
            value: String::new(),
            masked: false,
            page: e.url.clone(),
        };
        match e.t.as_str() {
            "goto" => {
                step = Step {
                    action: Do::Goto,
                    css: String::new(),
                    text: None,
                    value: e.url.clone(),
                    masked: false,
                    page: String::new(),
                };
            }
            "fill" => {
                step.action = Do::Fill;
                step.masked = e.kind == "password";
                step.value = if let Some(n) = digit_of.get(&i) {
                    format!("{{{{totp:{n}}}}}")
                } else if e.kind == "password" && Some(&e.value) == password.as_ref() {
                    "{{password}}".into()
                } else if is_code(&e.value) && is_otp_field(e) {
                    out.code = Some((e.value.clone(), e.ts / 1000));
                    "{{totp}}".into()
                } else if user.as_ref().is_some_and(|(css, v)| css == &e.css && v == &e.value) {
                    "{{username}}".into()
                } else {
                    e.value.clone()
                };
                // Typed again (a correction): the field's last value is the one to type.
                if let Some(earlier) =
                    out.steps.iter().rposition(|s| s.action == Do::Fill && s.css == e.css && s.text == e.text)
                {
                    let acted =
                        out.steps[earlier + 1..].iter().any(|s| !matches!(s.action, Do::Fill | Do::Select | Do::Check));
                    if !acted {
                        out.steps.remove(earlier);
                    }
                }
            }
            "select" => {
                step.action = Do::Select;
                step.value = e.value.clone();
            }
            "check" => {
                step.action = Do::Check;
                step.value = if e.checked { "on" } else { "off" }.into();
            }
            "click" => {}
            "press" if e.key == "Enter" => {
                step.action = Do::Press;
                step.value = "Enter".into();
            }
            _ => continue,
        }
        out.last_history = out.last_history.max(e.history);
        out.last_page = e.url.split('#').next().unwrap_or_default().to_string();
        out.steps.push(step);
    }
    // From step `from` on, as the steps are numbered when shown.
    out.steps.drain(..from.saturating_sub(1).min(out.steps.len()));
    if out.steps.len() > MAX_STEPS {
        out.warnings.push(format!("Only the first {MAX_STEPS} of {} steps are kept.", out.steps.len()));
        out.steps.truncate(MAX_STEPS);
    }
    out.username = user.map(|(_, v)| v).filter(|_| out.steps.iter().any(|s| s.value == "{{username}}"));
    out.password = password.filter(|_| out.steps.iter().any(|s| s.value == "{{password}}"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill(css: &str, kind: &str, name: &str, value: &str) -> Event {
        Event {
            t: "fill".into(),
            css: css.into(),
            kind: kind.into(),
            name: name.into(),
            value: value.into(),
            top: true,
            ts: 59_000,
            ..Default::default()
        }
    }

    fn act(t: &str, css: &str) -> Event {
        Event {
            t: t.into(),
            css: css.into(),
            key: if t == "press" { "Enter".into() } else { String::new() },
            top: true,
            ..Default::default()
        }
    }

    fn lines(d: &Derived) -> Vec<String> {
        d.steps.iter().map(Step::line).collect()
    }

    #[test]
    fn typed_values_become_the_profiles() {
        let mut click = act("click", "button");
        click.text = Some("Sign in".into());
        click.history = 12;
        let rec = Recording {
            events: vec![
                fill("#user", "text", "user", "alixe"),
                fill("#user", "text", "user", "alice"),
                fill("#pw", "password", "pw", "s3cret!"),
                click,
                fill("input[name=\"otp\"]", "text", "otp", "123456"),
                act("press", "input[name=\"otp\"]"),
                Event {
                    t: "goto".into(),
                    url: "https://a.test/account".into(),
                    top: true,
                    history: 20,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let d = derive(&rec, 1);
        assert_eq!(
            lines(&d),
            [
                "fill #user with {{username}}",
                "fill #pw with {{password}}",
                "click button \"Sign in\"",
                "fill input[name=\"otp\"] with {{totp}}",
                "press Enter in input[name=\"otp\"]",
                "open https://a.test/account",
            ]
        );
        assert_eq!(d.username.as_deref(), Some("alice"));
        assert_eq!(d.password.as_deref(), Some("s3cret!"));
        assert_eq!(d.code, Some(("123456".into(), 59)));
        assert_eq!((d.last_history, d.last_page.as_str()), (20, "https://a.test/account"));
        assert!(d.warnings.is_empty());
        // No step holds what was typed into the password field.
        assert!(!serde_json::to_string(&d.steps).unwrap().contains("s3cret"));
        // From the fourth step on, as they are numbered when shown (the first field was typed
        // in twice, so the events number differently): the code alone.
        let rest = derive(&rec, 4);
        assert_eq!(lines(&rest), lines(&d)[3..]);
        assert_eq!((rest.password, rest.username, rest.code.is_some()), (None, None, true));
        assert!(derive(&rec, 9).steps.is_empty());
    }

    #[test]
    fn a_number_is_a_one_time_code_only_in_a_field_for_one() {
        let named = |name: &str| fill("#f", "text", name, "482913");
        for name in ["otp", "mfa_code", "verification-code", "token", "code"] {
            assert!(is_otp_field(&named(name)), "{name}");
        }
        // Typed the same at every login: a customer number, a postcode, a user name.
        for name in ["customer_code", "zip_code", "postcode", "promo-code", "username", "account_code", "pin"] {
            assert!(!is_otp_field(&named(name)), "{name}");
        }
        let mut hinted = named("customer_code");
        hinted.autocomplete = "one-time-code".into();
        assert!(is_otp_field(&hinted));
    }

    #[test]
    fn a_code_typed_a_digit_per_box_keeps_its_boxes() {
        let boxes: Vec<Event> = "492817"
            .chars()
            .enumerate()
            .map(|(i, c)| {
                let mut e = fill(&format!("form > input:nth-of-type({})", i + 1), "text", "", &c.to_string());
                e.maxlength = 1;
                e
            })
            .collect();
        let d = derive(&Recording { events: boxes, ..Default::default() }, 1);
        assert_eq!(d.steps.len(), 6);
        assert_eq!(d.steps[0].value, "{{totp:1}}");
        assert_eq!(d.steps[5].value, "{{totp:6}}");
        assert_eq!(d.code.as_ref().map(|c| c.0.as_str()), Some("492817"));
    }

    #[test]
    fn other_password_fields_stay_masked_and_frames_are_warned_about() {
        let mut framed = act("click", "#pay");
        framed.top = false;
        let rec = Recording {
            events: vec![
                fill("#pw", "password", "pw", "first"),
                act("click", "#next"),
                fill("#pin", "password", "pin", "4321"),
                fill("#zip", "text", "zip", "90210"),
                framed,
            ],
            ..Default::default()
        };
        let d = derive(&rec, 1);
        assert_eq!(
            lines(&d),
            ["fill #pw with {{password}}", "click #next", "fill #pin with ********", "fill #zip with 90210"]
        );
        assert!(d.steps[2].masked && d.steps[2].value == "4321");
        assert_eq!(d.code, None, "a number in a field that isn't for a code is typed as it was");
        assert_eq!(d.warnings.len(), 1);
    }
}
