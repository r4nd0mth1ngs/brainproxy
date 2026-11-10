//! A login replayed in a headless browser, for a login plain requests can't repeat: single
//! sign-on through another site, a page that builds the login in JavaScript, a passkey.
//!
//! `auth record` records what the person does in the login browser ([`record`]): pages opened,
//! fields filled, buttons clicked. The steps are kept with the profile, with `{{username}}`,
//! `{{password}}` and `{{totp}}` in place of what was typed. When the session is lost,
//! [`AuthSession::browser_login`] runs them again in a Chromium-family browser driven over the
//! DevTools protocol, and takes the cookies (and the token the page sends) into the session,
//! so scans, the fuzzer, the crawler and `send --auth` carry on as after any other login.
//!
//! The browser is the browser crawl's: its only way out is a gateway on loopback that sends
//! every request with the engagement-guarded client, so a step that would leave the scope is
//! refused, and each request is recorded (source `auth`) with the password and one-time code
//! replaced by their placeholders.
//!
//! A passkey is a credential in the DevTools protocol's virtual authenticator. One registered
//! while recording is stored with the profile ([`Passkey`]) and put back for every replay; its
//! signature counter is stored again after each one, so it only ever goes up.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::auth::{AuthSession, TotpUse};
use crate::browser_crawl::cdp::{self, Chrome, LaunchOptions};
use crate::browser_crawl::gateway::{self, Gateway, Tap};
use crate::error::{Error, Result};
use crate::http::{Client, RawRequest, Target};
use crate::proxy::ca::CertAuthority;
use crate::store::Store;

pub mod record;

const REPLAY_JS: &str = include_str!("replay.js");
/// Steps a recorded login may have.
pub const MAX_STEPS: usize = 200;
/// How long a step waits for its element to show.
const FIND_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the page may take to go quiet after a step.
const SETTLE_MAX: Duration = Duration::from_secs(10);
const NETWORK_QUIET: Duration = Duration::from_millis(500);
const DOM_QUIET_MS: f64 = 300.0;
/// How long a whole login may take.
const LOGIN_MAX: Duration = Duration::from_secs(120);

/// What a step does.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Do {
    /// Open `value` (a URL the person typed, or the page the login starts at).
    Goto,
    /// Type `value` into a field.
    Fill,
    /// Choose `value` in a select.
    Select,
    /// Tick or untick a box (`value`: on or off).
    Check,
    Click,
    /// Press a key (`value`: Enter) in a field.
    Press,
}

/// One recorded step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Step {
    #[serde(rename = "do")]
    pub action: Do,
    /// The element: a CSS selector, narrowed to the one that shows `text` when given.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub css: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// A URL, what to type (`{{username}}`, `{{password}}`, `{{totp}}`, `{{totp:N}}` for the
    /// code's Nth digit, or as typed), on/off, or a key.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
    /// `value` was typed into a password field: never shown.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub masked: bool,
    /// The page it was recorded on.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub page: String,
}

const VARS: [&str; 3] = ["{{username}}", "{{password}}", "{{totp"];

impl Step {
    /// Whether `value` is typed as recorded, with nothing filled in.
    pub(crate) fn literal(&self) -> bool {
        !VARS.iter().any(|v| self.value.contains(v))
    }

    /// Whether the step types a secret: the password, the one-time code, or what went into
    /// another password field.
    pub(crate) fn types_secret(&self) -> bool {
        matches!(self.action, Do::Fill)
            && !self.page.is_empty()
            && (self.masked || self.value.contains("{{password}}") || self.value.contains("{{totp"))
    }

    /// The step in a line, for a person: no typed secret in it.
    pub fn line(&self) -> String {
        let el = match &self.text {
            Some(t) => format!("{} {t:?}", self.css),
            None => self.css.clone(),
        };
        let value = if self.masked && self.literal() { "********" } else { self.value.as_str() };
        match self.action {
            Do::Goto => format!("open {value}"),
            Do::Fill => format!("fill {el} with {value}"),
            Do::Select => format!("choose {value} in {el}"),
            Do::Check => format!("turn {el} {value}"),
            Do::Click => format!("click {el}"),
            Do::Press => format!("press {value} in {el}"),
        }
    }
}

/// A profile's browser login.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrowserLogin {
    /// The page the login starts at.
    pub start_url: String,
    pub steps: Vec<Step>,
}

fn web_url(url: &str) -> Result<Target> {
    if url.chars().any(char::is_control) {
        return Err(Error::InvalidInput("a browser step's URL holds a control character".into()));
    }
    Target::from_url(url)
}

impl BrowserLogin {
    pub fn validate(&self) -> Result<()> {
        web_url(&self.start_url)?;
        if self.steps.len() > MAX_STEPS {
            return Err(Error::InvalidInput(format!("a browser login has at most {MAX_STEPS} steps")));
        }
        for (i, s) in self.steps.iter().enumerate() {
            let what = |e: &str| Error::InvalidInput(format!("browser step {}: {e}", i + 1));
            match s.action {
                Do::Goto => {
                    web_url(&s.value).map_err(|e| what(&e.to_string()))?;
                }
                _ if s.css.trim().is_empty() => return Err(what("names no element")),
                Do::Press if s.value != "Enter" => return Err(what("only the Enter key is pressed")),
                Do::Check if !matches!(s.value.as_str(), "on" | "off") => {
                    return Err(what("a box is turned on or off"))
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The pages the password and the one-time code are typed on.
    pub(crate) fn secret_pages(&self) -> impl Iterator<Item = &str> {
        let secret = |s: &&Step| s.value.contains("{{password}}") || s.value.contains("{{totp");
        self.steps.iter().filter(secret).map(|s| s.page.as_str()).filter(|p| !p.is_empty())
    }

    /// What was typed into other password fields and is kept as typed: the step's number, the
    /// value, and the page it was typed on.
    pub(crate) fn typed_secrets(&self) -> impl Iterator<Item = (usize, &str, &str)> {
        let kept = |(_, s): &(usize, &Step)| s.masked && s.literal() && !s.value.is_empty();
        self.steps.iter().enumerate().filter(kept).map(|(i, s)| (i + 1, s.value.as_str(), s.page.as_str()))
    }

    /// The page the login form is on: where the first step was taken, else where it starts.
    pub(crate) fn login_page(&self) -> &str {
        let first = self.steps.iter().find(|s| s.action != Do::Goto).map(|s| s.page.as_str());
        first.filter(|p| !p.is_empty()).unwrap_or(&self.start_url)
    }

    pub fn uses_totp(&self) -> bool {
        self.steps.iter().any(|s| s.value.contains("{{totp"))
    }

    /// The login with what was typed into other password fields hidden, for display.
    pub fn redacted(&self) -> BrowserLogin {
        let mut b = self.clone();
        for s in b.steps.iter_mut().filter(|s| s.masked && s.literal()) {
            s.value = "********".into();
        }
        b
    }

    /// What was typed into password fields and is kept as typed, for a report to mask.
    pub(crate) fn secret_values(&self) -> Vec<String> {
        self.steps.iter().filter(|s| s.masked && s.literal()).map(|s| s.value.clone()).collect()
    }

    /// Every page the steps open, with the step that opens it (0: the start).
    fn opened(&self) -> impl Iterator<Item = (usize, &str)> {
        std::iter::once((0, self.start_url.as_str()))
            .chain(self.steps.iter().enumerate().filter(|(_, s)| s.action == Do::Goto).map(|(i, s)| (i + 1, &*s.value)))
    }
}

/// A passkey: a credential of the virtual authenticator, as the DevTools protocol gives and
/// takes it. The private key is a credential like a stored password, and kept like one: in
/// the profile, in the project file only its owner can read, in the table `query` can't
/// read, and never shown ([`crate::auth::AuthProfile::redacted`] masks it).
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Passkey {
    /// base64
    pub credential_id: String,
    pub rp_id: String,
    /// base64; the account it signs in, for a login that names no user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
    /// base64 of the PKCS#8 key. Left out of a profile that is shown.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    /// Signatures made so far. A site refuses a count that doesn't go up.
    pub sign_count: u64,
    #[serde(default)]
    pub resident: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
}

impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Passkey({} for {}, count {})", self.credential_id, self.rp_id, self.sign_count)
    }
}

impl Passkey {
    /// From `WebAuthn.getCredentials`.
    fn from_cdp(v: &Value) -> Option<Passkey> {
        let text = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
        Some(Passkey {
            credential_id: text("credentialId")?,
            rp_id: text("rpId")?,
            user_handle: text("userHandle"),
            private_key: text("privateKey")?,
            sign_count: v.get("signCount").and_then(Value::as_u64).unwrap_or(0),
            resident: v.get("isResidentCredential").and_then(Value::as_bool).unwrap_or(false),
            user_name: text("userName"),
        })
    }

    /// For `WebAuthn.addCredential`.
    fn to_cdp(&self) -> Value {
        let mut v = json!({
            "credentialId": self.credential_id,
            "rpId": self.rp_id,
            "privateKey": self.private_key,
            "signCount": self.sign_count,
            // A key with no account to name can't be a discoverable one.
            "isResidentCredential": self.resident && self.user_handle.is_some(),
        });
        if let Some(h) = &self.user_handle {
            v["userHandle"] = json!(h);
        }
        v
    }

    /// What may be shown of it.
    pub fn summary(&self) -> Value {
        json!({
            "credential_id": self.credential_id,
            "rp_id": self.rp_id,
            "user_name": self.user_name,
            "sign_count": self.sign_count,
            "discoverable": self.resident,
        })
    }
}

pub(crate) fn lock_key(profile: &str) -> String {
    format!("auth.browser_login.{profile}")
}

impl Store {
    /// Stores the counts a profile's passkeys reached (credential id, count), each only if
    /// higher. The profile's row alone is written: its session stays as it is.
    pub(crate) fn auth_advance_passkeys(&self, profile: &str, counts: &[(String, u64)]) -> Result<()> {
        // Read and written in one transaction: another process may be saving the profile.
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        let (mut p, _) = self.auth_profile(profile)?;
        let mut changed = false;
        for k in &mut p.passkeys {
            if let Some((_, n)) = counts.iter().find(|(id, n)| *id == k.credential_id && *n > k.sign_count) {
                k.sign_count = *n;
                changed = true;
            }
        }
        if changed {
            let json = serde_json::to_string(&p).map_err(|e| Error::InvalidInput(e.to_string()))?;
            tx.execute("UPDATE auth_profiles SET profile = ?1 WHERE name = ?2", rusqlite::params![json, profile])?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// One process at a time logs in with a profile's passkeys or its one-time code: two that
/// loaded the same count would both sign with the next one, and two in the same period would
/// both send the same code; a site refuses a count or a code it has seen. The lock is a row in
/// the project (who and when), taken over from a holder that is gone for too long.
pub(crate) struct LoginLock {
    project: PathBuf,
    key: String,
    mine: String,
}

impl LoginLock {
    pub(crate) async fn acquire(project: &Path, profile: &str) -> Result<LoginLock> {
        let key = lock_key(profile);
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        let id = format!("{}-{}", std::process::id(), hex::encode(rnd));
        // Longer than any login takes (a wait for the next code and a second try included).
        let stale = 2 * LOGIN_MAX.as_secs() + 120;
        let started = Instant::now();
        let mut said = false;
        loop {
            let now = crate::totp::unix_now();
            let mine = format!("{id} {now}");
            let store = Store::open(project)?;
            // The check and the write in one statement, so two processes can't both win.
            let took = store.conn.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value
                 WHERE CAST(substr(meta.value, instr(meta.value, ' ') + 1) AS INTEGER) + ?3 < ?4",
                rusqlite::params![key, mine, stale as i64, now as i64],
            )?;
            if took == 1 {
                return Ok(LoginLock { project: project.to_path_buf(), key, mine });
            }
            // A holder that is gone (killed in the middle of a login) holds nothing.
            if let Some(held) = store.meta_get(&key)? {
                let pid = held.split('-').next().and_then(|p| p.parse::<u32>().ok());
                if pid.is_some_and(process_gone) {
                    store.conn.execute("DELETE FROM meta WHERE key = ?1 AND value = ?2", [&key, &held])?;
                    continue;
                }
            }
            if !said && started.elapsed() > Duration::from_secs(3) {
                said = true;
                eprintln!("brainproxy: {profile}: waiting for another brainproxy process that is logging in with it");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

/// Whether no process has this id any more. Where that can't be told, it is taken to be there.
fn process_gone(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else { return false };
        // SAFETY: signal 0 only checks that the process exists.
        pid > 0
            && unsafe { libc::kill(pid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

impl Drop for LoginLock {
    fn drop(&mut self) {
        if let Ok(store) = Store::open(&self.project) {
            let _ = store.conn.execute("DELETE FROM meta WHERE key = ?1 AND value = ?2", [&self.key, &self.mine]);
        }
    }
}

/// What a browser login needs of the machine: a Chromium-family browser, and the CA its
/// gateway signs with.
pub struct Launcher {
    pub browser: PathBuf,
    pub ca: Arc<CertAuthority>,
}

type Find = Box<dyn Fn() -> Result<Launcher> + Send + Sync>;
static LAUNCHER: OnceLock<Find> = OnceLock::new();

/// Says how this process finds the browser and the CA when a profile logs in with a browser
/// (the CLI knows where browsers are installed and where the CA is kept).
pub fn set_launcher(find: impl Fn() -> Result<Launcher> + Send + Sync + 'static) {
    let _ = LAUNCHER.set(Box::new(find));
}

fn launcher() -> Result<Launcher> {
    match LAUNCHER.get() {
        Some(find) => find(),
        None => Err(Error::InvalidInput("this profile logs in with a browser, which isn't set up here".into())),
    }
}

/// The recorded value with the profile's values in place: (text to type, whether it holds the code).
fn expand(value: &str, username: &str, password: &str, code: Option<&str>) -> Result<String> {
    let mut out = value.replace("{{username}}", username).replace("{{password}}", password);
    if !out.contains("{{totp") {
        return Ok(out);
    }
    let code = code.ok_or_else(|| {
        Error::InvalidInput("the step types a one-time code, but the profile has no TOTP secret".into())
    })?;
    out = out.replace("{{totp}}", code);
    // {{totp:N}}: the code's Nth digit, for a code typed into a box per digit.
    while let Some(i) = out.find("{{totp:") {
        let Some(end) = out[i..].find("}}").map(|j| i + j) else { break };
        let digit = out[i + 7..end]
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| code.chars().nth(n));
        let digit = digit.ok_or_else(|| {
            Error::InvalidInput(format!("the step types digit {} of a {}-digit code", &out[i + 7..end], code.len()))
        })?;
        out.replace_range(i..end + 2, &digit.to_string());
    }
    Ok(out)
}

/// Watches the login browser's requests: takes the token the page sends, and keeps the
/// password and the one-time code out of what is recorded.
struct LoginTap {
    guard: Arc<crate::guard::Guard>,
    profile: String,
    /// The header that carries the token, lowercase, and what stands before and after the
    /// token in its value.
    token: Option<(String, String, String)>,
    /// The host whose requests carry the session's token: the one the profile checks, else
    /// the one the login starts at. Another site's token (a sign-in provider's) isn't it.
    site: Option<String>,
    seen: Mutex<Option<String>>,
}

impl Tap for LoginTap {
    fn outgoing(&self, target: &Target, request: Vec<u8>) -> Vec<u8> {
        if let Some((name, before, after)) = &self.token {
            let ours = self.site.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(&target.host));
            let value = RawRequest::from_bytes(request.clone())
                .head()
                .ok()
                .filter(|_| ours)
                .and_then(|h| h.headers.into_iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v));
            let token = value.as_deref().map(str::trim).and_then(|v| {
                let v = v.strip_prefix(before.as_str())?.strip_suffix(after.as_str())?;
                (!v.is_empty() && !v.contains(crate::auth::MARK)).then(|| v.to_string())
            });
            if let Some(t) = token {
                *self.seen.lock().unwrap() = Some(t);
            }
        }
        self.guard.vault.conceal(&self.profile, &request, &target.origin())
    }
}

/// The tab a login is replayed in.
struct Tab<'a> {
    chrome: &'a Chrome,
    session: String,
    gateway: &'a Gateway,
}

impl Tab<'_> {
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        self.chrome.call(method, params, Some(&self.session)).await
    }

    async fn eval(&self, expression: &str) -> Result<Value> {
        let params = json!({"expression": expression, "returnByValue": true});
        let r =
            self.chrome.call_timeout("Runtime.evaluate", params, Some(&self.session), Duration::from_secs(10)).await?;
        if let Some(ex) = r.get("exceptionDetails") {
            let text = ex["exception"]["description"].as_str().or(ex["text"].as_str()).unwrap_or("exception");
            return Err(Error::Protocol(format!("page script: {text}")));
        }
        Ok(r["result"]["value"].clone())
    }

    /// A call of the replay script's `f` with the step's element first.
    async fn on(&self, f: &str, step: &Step, more: &[Value]) -> Result<Value> {
        let mut args = vec![json!(step.css), json!(step.text)];
        args.extend_from_slice(more);
        let args: Vec<String> = args.iter().map(Value::to_string).collect();
        self.eval(&format!("window.__bpl ? __bpl.{f}({}) : null", args.join(","))).await
    }

    /// Waits until no request has been in flight and the DOM hasn't changed for a moment.
    async fn settle(&self) {
        let start = Instant::now();
        tokio::time::sleep(Duration::from_millis(150)).await;
        while start.elapsed() < SETTLE_MAX {
            let quiet =
                self.eval("window.__bpl ? __bpl.quiet() : [document.readyState, 1e9]").await.unwrap_or_default();
            let ready = quiet[0].as_str() == Some("complete");
            let dom_quiet = quiet[1].as_f64().unwrap_or(0.0) >= DOM_QUIET_MS;
            if ready && dom_quiet && self.gateway.idle_for() >= NETWORK_QUIET {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Where the step's element is, once it shows.
    async fn locate(&self, step: &Step) -> Result<Value> {
        let start = Instant::now();
        loop {
            // A page between two documents has no script yet: asked again.
            let at = self.on("locate", step, &[]).await.unwrap_or_default();
            if !at.is_null() && at["off"] != json!(true) {
                return Ok(at);
            }
            if start.elapsed() >= FIND_TIMEOUT {
                let url = self.href().await;
                return Err(Error::InvalidInput(format!(
                    "{} wasn't found on {url} (the page changed since the login was recorded? record it again)",
                    step.css
                )));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn href(&self) -> String {
        self.eval("location.href").await.ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
    }

    async fn key(&self, kind: &str, key: &str, code: u32, text: Option<&str>) -> Result<()> {
        let mut ev =
            json!({"type": kind, "key": key, "code": key, "windowsVirtualKeyCode": code, "nativeVirtualKeyCode": code});
        if let Some(t) = text {
            ev["text"] = json!(t);
        }
        self.call("Input.dispatchKeyEvent", ev).await.map(drop)
    }

    async fn run(&self, step: &Step, typed: Option<&str>) -> Result<()> {
        match step.action {
            Do::Goto => {
                let r = self.call("Page.navigate", json!({"url": step.value})).await?;
                if let Some(e) = r["errorText"].as_str().filter(|e| !e.is_empty()) {
                    return Err(Error::InvalidInput(format!("{} didn't load ({e})", step.value)));
                }
            }
            Do::Fill => {
                let text = typed.unwrap_or_default();
                let at = self.locate(step).await?;
                // Typed as a person types (frameworks listen for it); a field the cursor won't
                // go into, or one being emptied, is set.
                if at["tag"] == "select" || text.is_empty() || self.on("focus", step, &[]).await? != json!(true) {
                    self.on("set", step, &[json!(text)]).await?;
                } else {
                    self.call("Input.insertText", json!({"text": text})).await?;
                }
            }
            Do::Select => {
                self.locate(step).await?;
                self.on("set", step, &[json!(typed.unwrap_or_default())]).await?;
            }
            Do::Check => {
                // A box its label draws doesn't show itself: found all the same.
                let start = Instant::now();
                while self.on("check", step, &[json!(step.value == "on")]).await.unwrap_or_default() != json!(true) {
                    if start.elapsed() >= FIND_TIMEOUT {
                        return Err(Error::InvalidInput(format!("{} wasn't found on {}", step.css, self.href().await)));
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
            Do::Click => {
                let at = self.locate(step).await?;
                let (x, y) = (at["x"].as_f64().unwrap_or(0.0), at["y"].as_f64().unwrap_or(0.0));
                if at["hit"] == json!(true) {
                    for (kind, button, buttons) in
                        [("mouseMoved", "none", 0), ("mousePressed", "left", 1), ("mouseReleased", "left", 0)]
                    {
                        let ev = json!({"type": kind, "x": x, "y": y, "button": button, "buttons": buttons, "clickCount": 1});
                        self.call("Input.dispatchMouseEvent", ev).await?;
                    }
                } else {
                    // Something lies over it (a banner): clicked by the page itself.
                    self.on("click", step, &[]).await?;
                }
            }
            Do::Press => {
                self.locate(step).await?;
                self.on("focus", step, &[]).await?;
                self.key("keyDown", "Enter", 13, Some("\r")).await?;
                self.key("keyUp", "Enter", 13, None).await?;
            }
        }
        self.settle().await;
        Ok(())
    }
}

/// A virtual authenticator in the tab, with `keys` in it; its id.
pub(crate) async fn add_authenticator(chrome: &Chrome, session: &str, keys: &[Passkey]) -> Result<String> {
    let s = Some(session);
    // No dialog of the browser's own: the virtual authenticator answers.
    if chrome.call("WebAuthn.enable", json!({"enableUI": false}), s).await.is_err() {
        chrome.call("WebAuthn.enable", json!({}), s).await?;
    }
    let options = |version: Option<&str>| {
        let mut o = json!({
            "protocol": "ctap2",
            "transport": "internal",
            "hasResidentKey": true,
            "hasUserVerification": true,
            "isUserVerified": true,
            "automaticPresenceSimulation": true,
        });
        if let Some(v) = version {
            o["ctap2Version"] = json!(v);
        }
        json!({"options": o})
    };
    let added = match chrome.call("WebAuthn.addVirtualAuthenticator", options(Some("ctap2_1")), s).await {
        Ok(v) => v,
        // A browser from before CTAP 2.1 was an option.
        Err(_) => chrome.call("WebAuthn.addVirtualAuthenticator", options(None), s).await?,
    };
    let id = added["authenticatorId"]
        .as_str()
        .ok_or_else(|| Error::Protocol("the browser gave no virtual authenticator".into()))?
        .to_string();
    for k in keys {
        chrome
            .call("WebAuthn.addCredential", json!({"authenticatorId": id, "credential": k.to_cdp()}), s)
            .await
            .map_err(|e| Error::InvalidInput(format!("the passkey for {} couldn't be loaded: {e}", k.rp_id)))?;
    }
    Ok(id)
}

/// The authenticator's credentials as they are now.
pub(crate) async fn authenticator_keys(chrome: &Chrome, session: &str, id: &str) -> Result<Vec<Passkey>> {
    let got = chrome.call("WebAuthn.getCredentials", json!({"authenticatorId": id}), Some(session)).await?;
    Ok(got["credentials"].as_array().map(|a| a.iter().filter_map(Passkey::from_cdp).collect()).unwrap_or_default())
}

/// Whether a cookie the browser holds goes to `host` (over `secure`).
fn cookie_for(cookie: &Value, host: &str, secure: bool) -> bool {
    let domain = cookie["domain"].as_str().unwrap_or("").trim_start_matches('.').to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let on_host = !domain.is_empty() && (host == domain || host.ends_with(&format!(".{domain}")));
    on_host && (secure || cookie["secure"] != json!(true))
}

/// A browser login under way: the page it ended on (its text; a browser gives no status).
type LoginFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(String, Option<u16>)>> + Send + 'a>>;

impl AuthSession {
    /// Runs the profile's recorded steps in a headless browser and takes what came of it into
    /// the session: the site's cookies, and the token its pages sent. Gives the page the login
    /// ended on (its text; a browser gives no status), for the caller to judge the login by.
    pub(crate) fn browser_login<'a>(&'a self, password: &'a str) -> LoginFuture<'a> {
        // Boxed, and said to be Send: the login's gateway serves requests on tasks of its own,
        // and a gateway (the crawl's) can itself start a login.
        Box::pin(self.browser_login_now(password))
    }

    async fn browser_login_now(&self, password: &str) -> Result<(String, Option<u16>)> {
        let p = &self.profile;
        let Some(login) = &p.browser else {
            return Err(Error::InvalidInput("the profile has no browser login".into()));
        };
        let guard = self.client.options().guard.clone().ok_or_else(|| {
            Error::OutOfScope("a browser login needs the engagement scope, and none is set for this command".into())
        })?;
        // Refused before a browser starts: a page the steps open that the scope doesn't cover.
        for (i, url) in login.opened() {
            let t = web_url(url)?;
            if !guard.may_allow(&t.host, t.port) {
                let what = if i == 0 { "the login's start page".to_string() } else { format!("browser step {i}") };
                return Err(Error::OutOfScope(format!(
                    "{what} opens {}:{}, which is outside the engagement scope: not followed",
                    t.host, t.port
                )));
            }
        }
        let launcher = launcher()?;
        // The passkeys' counts as they are now: another process may have signed since this
        // session loaded the profile. (The caller holds the profile's login lock.)
        let passkeys = match p.passkeys.is_empty() {
            true => vec![],
            false => Store::open(&self.project)?.auth_profile(&p.name)?.0.passkeys,
        };

        let token = p.token_header.as_deref().and_then(|tpl| {
            let (name, value) = tpl.split_once(':')?;
            let (before, after) = value.trim().split_once("{{token}}")?;
            Some((name.trim().to_ascii_lowercase(), before.to_string(), after.to_string()))
        });
        let site = p.check_url.as_deref().unwrap_or(&login.start_url);
        let tap = Arc::new(LoginTap {
            guard: guard.clone(),
            profile: p.name.clone(),
            token,
            site: Target::from_url(site).ok().map(|t| t.host),
            seen: Mutex::new(None),
        });
        let (save, writer) = crate::crawl::spawn_writer(&self.project)?;
        let gateway = Gateway::start(
            gateway::Options {
                ca: launcher.ca.clone(),
                client: Client::new(self.client.options().clone()),
                auth: None,
                headers: vec![],
                scope: None,
                exclude: vec![],
                block_delete: false,
                rate: None,
                source: "auth",
                tap: Some(tap.clone()),
                no_store: self.no_store.load(std::sync::atomic::Ordering::SeqCst),
            },
            save,
        )
        .await?;
        let outcome = async {
            let chrome = Chrome::launch(&LaunchOptions {
                path: &launcher.browser,
                headless: !std::env::var("BRAINPROXY_LOGIN_BROWSER_SHOW").is_ok_and(|v| !v.is_empty() && v != "0"),
                proxy: gateway.addr,
                ca_spki: launcher.ca.spki_sha256_base64(),
                no_sandbox: cdp::sandbox_off(),
                hands_off: false,
            })?;
            let ran = self.replay(&chrome, &gateway, &guard, &passkeys, password, &tap).await;
            chrome.close().await;
            ran
        }
        .await;
        let stats = gateway.stop().await;
        let _ = crate::crawl::join_writer(writer).await;
        let (text, cookies) = outcome.map_err(|e| match stats.refused_hosts.iter().next() {
            // What the scope refused on the way is most likely why a step found nothing.
            Some(host) if !matches!(e, Error::OutOfScope(_)) => Error::InvalidInput(format!(
                "{e} ({host} is outside the engagement scope and was refused: add it to the scope if the login needs it)"
            )),
            _ => e,
        })?;
        let mut st = self.state.lock().unwrap();
        st.cookies = cookies;
        if p.token_header.is_some() {
            st.token = tap.seen.lock().unwrap().clone();
        }
        Ok((text, None))
    }

    /// The steps, in a tab of `chrome`. Gives the last page's text and the site's cookies.
    async fn replay(
        &self,
        chrome: &Chrome,
        gateway: &Gateway,
        guard: &crate::guard::Guard,
        passkeys: &[Passkey],
        password: &str,
        tap: &LoginTap,
    ) -> Result<(String, Vec<(String, String)>)> {
        let p = &self.profile;
        chrome
            .call_timeout("Browser.getVersion", json!({}), None, Duration::from_secs(20))
            .await
            .map_err(|e| Error::InvalidInput(format!("the browser didn't start: {e}")))?;
        // Pop-up windows are closed as they open (the steps run in one tab), downloads refused.
        chrome.call("Target.setDiscoverTargets", json!({"discover": true}), None).await?;
        let _ = chrome.call("Browser.setDownloadBehavior", json!({"behavior": "deny"}), None).await;
        let target = chrome.call("Target.createTarget", json!({"url": "about:blank"}), None).await?;
        let target = target["targetId"].as_str().unwrap_or_default().to_string();
        let attached = chrome.call("Target.attachToTarget", json!({"targetId": target, "flatten": true}), None).await?;
        let session = attached["sessionId"]
            .as_str()
            .ok_or_else(|| Error::Protocol("the browser gave no session for the login tab".into()))?
            .to_string();
        let tab = Tab { chrome, session, gateway };
        tab.call("Page.enable", json!({})).await?;
        tab.call("Page.addScriptToEvaluateOnNewDocument", json!({"source": REPLAY_JS})).await?;
        let authenticator = match passkeys.is_empty() {
            true => None,
            false => Some(add_authenticator(chrome, &tab.session, passkeys).await?),
        };
        // Only the steps are cut short when they take too long: what follows them must run.
        let ran =
            tokio::time::timeout(LOGIN_MAX, self.run_steps(&tab, guard, password, tap)).await.unwrap_or_else(|_| {
                Err(Error::InvalidInput(format!("the browser login took more than {}s", LOGIN_MAX.as_secs())))
            });
        // The counts the passkeys reached, whatever came of the login: a signature made is
        // one the site has counted.
        if let Some(id) = &authenticator {
            if let Ok(keys) = authenticator_keys(chrome, &tab.session, id).await {
                let counts: Vec<(String, u64)> = keys.into_iter().map(|k| (k.credential_id, k.sign_count)).collect();
                Store::open(&self.project)?.auth_advance_passkeys(&p.name, &counts)?;
            }
        }
        ran?;
        let url = tab.href().await;
        let page = url::Url::parse(&url).ok();
        // The session is for the site the profile checks, else the one the login ended on.
        let checked = p.check_url.as_deref().and_then(|u| Target::from_url(u).ok()).map(|t| t.host);
        let site = checked.or_else(|| page.as_ref().and_then(|u| u.host_str().map(str::to_string)));
        let secure = match p.check_url.as_deref().and_then(|u| url::Url::parse(u).ok()) {
            Some(u) => u.scheme() == "https",
            None => page.as_ref().is_some_and(|u| u.scheme() == "https"),
        };
        let all = chrome.call("Storage.getCookies", json!({}), None).await?;
        let mut cookies: Vec<(String, String)> = Vec::new();
        for c in all["cookies"].as_array().into_iter().flatten() {
            let (Some(name), Some(value)) = (c["name"].as_str(), c["value"].as_str()) else { continue };
            if site.as_deref().is_some_and(|s| cookie_for(c, s, secure)) && !name.is_empty() {
                cookies.retain(|(n, _)| n != name);
                cookies.push((name.to_string(), value.to_string()));
            }
        }
        let text = tab.eval("window.__bpl ? __bpl.text() : ''").await.ok();
        Ok((text.and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(), cookies))
    }

    /// Runs the recorded steps in `tab`, the start page first.
    async fn run_steps(
        &self,
        tab: &Tab<'_>,
        guard: &crate::guard::Guard,
        password: &str,
        tap: &LoginTap,
    ) -> Result<()> {
        let p = &self.profile;
        let Some(login) = &p.browser else {
            return Err(Error::InvalidInput("the profile has no browser login".into()));
        };
        let start = Step {
            action: Do::Goto,
            css: String::new(),
            text: None,
            value: login.start_url.clone(),
            masked: false,
            page: String::new(),
        };
        let username = p.username.as_deref().unwrap_or("");
        let generator = match login.uses_totp() {
            true => p.totp.as_ref().map(|t| t.generator()).transpose()?,
            false => None,
        };
        // One code for the whole login: its digits may go into a box each.
        let mut code: Option<String> = None;
        for (i, step) in std::iter::once(&start).chain(&login.steps).enumerate() {
            let named = |e: Error| {
                let what = if i == 0 {
                    "the login's start page".to_string()
                } else {
                    format!("browser step {i} ({})", step.line())
                };
                match e {
                    Error::OutOfScope(m) => Error::OutOfScope(format!("{what}: {m}")),
                    e => Error::InvalidInput(format!("{what}: {e}")),
                }
            };
            let typed = match step.action {
                Do::Fill | Do::Select => {
                    // A secret is typed on the site it was typed on when recorded, and no
                    // other: a login that now leads somewhere else doesn't get it.
                    if step.types_secret() {
                        let here = Target::from_url(&tab.href().await).map(|t| t.origin()).unwrap_or_default();
                        let there = Target::from_url(&step.page).map(|t| t.origin()).unwrap_or_default();
                        if here != there {
                            return Err(named(Error::InvalidInput(format!(
                                "the page is on {}, not on {there} where this was typed when the login was recorded: \
                                 not typed (record the login again if it changed)",
                                if here.is_empty() { "no site" } else { &here }
                            ))));
                        }
                    }
                    if step.value.contains("{{totp") && code.is_none() {
                        if let Some(g) = &generator {
                            // A code about to run out would be stale by the time the form is sent.
                            let (_, left) = g.window();
                            let margin = Duration::from_secs(3).min(Duration::from_secs(g.period) / 5);
                            if left < margin {
                                tokio::time::sleep(left + Duration::from_millis(100)).await;
                            }
                            guard.vault.note_totp_use(&p.name, TotpUse::now(g));
                            code = Some(g.now());
                        }
                    }
                    Some(expand(&step.value, username, password, code.as_deref()).map_err(named)?)
                }
                _ => None,
            };
            tab.run(step, typed.as_deref()).await.map_err(named)?;
            // Where the step led: a page outside the scope isn't one to carry on from.
            let url = tab.href().await;
            if let Ok(t) = Target::from_url(&url) {
                if !guard.may_allow(&t.host, t.port) {
                    let m = format!("it led to {}:{}, outside the engagement scope: not followed", t.host, t.port);
                    return Err(named(Error::OutOfScope(m)));
                }
            } else if url.starts_with("chrome-error:") {
                return Err(named(Error::InvalidInput("the page it led to didn't load".into())));
            }
        }
        // The token the page's own requests carry may come a moment after the last step.
        if tap.token.is_some() {
            let start = Instant::now();
            while tap.seen.lock().unwrap().is_none() && start.elapsed() < Duration::from_secs(3) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(action: Do, css: &str, value: &str) -> Step {
        Step { action, css: css.into(), text: None, value: value.into(), masked: false, page: String::new() }
    }

    #[test]
    fn values_are_filled_in_and_secrets_stay_out_of_what_is_shown() {
        assert_eq!(expand("{{username}}", "al", "pw", None).unwrap(), "al");
        assert_eq!(expand("{{password}}", "al", "p{{w", None).unwrap(), "p{{w");
        assert_eq!(expand("{{totp}}", "", "", Some("123456")).unwrap(), "123456");
        assert_eq!(expand("{{totp:1}}{{totp:6}}", "", "", Some("123456")).unwrap(), "16");
        assert!(expand("{{totp:7}}", "", "", Some("123456")).is_err());
        assert!(expand("{{totp}}", "", "", None).is_err());

        let mut other = step(Do::Fill, "#pin", "4321");
        other.masked = true;
        let mut pass = step(Do::Fill, "#pw", "{{password}}");
        pass.masked = true;
        let login = BrowserLogin { start_url: "https://a.test/login".into(), steps: vec![pass.clone(), other.clone()] };
        assert_eq!(login.secret_values(), vec!["4321".to_string()]);
        assert_eq!(login.redacted().steps[1].value, "********");
        assert_eq!(login.redacted().steps[0].value, "{{password}}");
        assert_eq!(other.line(), "fill #pin with ********");
        assert_eq!(pass.line(), "fill #pw with {{password}}");
        let mut button = step(Do::Click, "button", "");
        button.text = Some("Sign in".into());
        assert_eq!(button.line(), "click button \"Sign in\"");
    }

    #[test]
    fn steps_are_checked() {
        let ok = |steps: Vec<Step>| BrowserLogin { start_url: "https://a.test/".into(), steps }.validate();
        assert!(ok(vec![step(Do::Goto, "", "https://a.test/x"), step(Do::Press, "#q", "Enter")]).is_ok());
        assert!(ok(vec![step(Do::Goto, "", "javascript:alert(1)")]).is_err());
        assert!(ok(vec![step(Do::Goto, "", "file:///etc/passwd")]).is_err());
        assert!(ok(vec![step(Do::Click, " ", "")]).is_err());
        assert!(ok(vec![step(Do::Press, "#q", "F12")]).is_err());
        assert!(ok(vec![step(Do::Check, "#c", "maybe")]).is_err());
        assert!(ok(vec![step(Do::Click, "#b", ""); MAX_STEPS + 1]).is_err());
        assert!(BrowserLogin { start_url: "ftp://a.test/".into(), steps: vec![] }.validate().is_err());
    }

    #[test]
    fn a_passkeys_count_only_goes_up_and_its_key_is_never_shown() {
        use crate::auth::{AuthProfile, SessionState};
        let store = Store::open_in_memory().unwrap();
        let key = Passkey {
            credential_id: "aWQ=".into(),
            rp_id: "a.test".into(),
            user_handle: Some("dQ==".into()),
            private_key: "c2VjcmV0LWtleQ==".into(),
            sign_count: 5,
            resident: true,
            user_name: None,
        };
        let profile = AuthProfile {
            name: "p".into(),
            browser: Some(BrowserLogin { start_url: "https://a.test/login".into(), steps: vec![] }),
            passkeys: vec![key.clone()],
            relogin_interval_secs: 5,
            max_relogins: 20,
            ..Default::default()
        };
        store.auth_save_profile(&profile).unwrap();
        let state =
            SessionState { cookies: vec![("sid".into(), "live".into())], logged_in: true, ..Default::default() };
        store.auth_save_state("p", &state).unwrap();
        let count = || store.auth_profile("p").unwrap().0.passkeys[0].sign_count;
        store.auth_advance_passkeys("p", &[("aWQ=".into(), 3), ("other".into(), 9)]).unwrap();
        assert_eq!(count(), 5);
        store.auth_advance_passkeys("p", &[("aWQ=".into(), 7)]).unwrap();
        assert_eq!(count(), 7);
        // Only the count was written: the session is as it was.
        assert_eq!(store.auth_profile("p").unwrap().1, state);
        // Saved again with the count a browser started from: the stored one stays.
        store.auth_save_profile(&profile).unwrap();
        assert_eq!(count(), 7);
        // Shown, it has no key; a report masks the key wherever something quotes it.
        let shown = serde_json::to_string(&profile.redacted()).unwrap();
        assert!(shown.contains("\"rp_id\":\"a.test\"") && !shown.contains("c2VjcmV0"), "{shown}");
        assert!(profile.secret_values(&SessionState::default()).contains(&key.private_key));
        assert!(!key.summary().to_string().contains("c2VjcmV0"));
        assert!(!format!("{key:?}").contains("c2VjcmV0") && !format!("{profile:?}").contains("c2VjcmV0"));
        assert_eq!(key.to_cdp()["signCount"], 5);
        assert_eq!(Passkey::from_cdp(&key.to_cdp()), Some(key.clone()));
        // `query` can't read where it is kept.
        let stored: String = store.conn.query_row("SELECT profile FROM auth_profiles", [], |r| r.get(0)).unwrap();
        assert!(stored.contains("c2VjcmV0LWtleQ=="));
        let elsewhere: i64 =
            store.conn.query_row("SELECT count(*) FROM meta WHERE value LIKE '%c2VjcmV0%'", [], |r| r.get(0)).unwrap();
        assert_eq!(elsewhere, 0);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_login_lock_is_one_at_a_time_and_a_dead_holders_is_taken_over() {
        let dir = std::env::temp_dir().join(format!("bp-login-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let project = dir.join("p.bpdb");
        let _ = std::fs::remove_file(&project);
        let store = Store::open(&project).unwrap();
        let held = LoginLock::acquire(&project, "p").await.unwrap();
        // Held by this (live) process: a second taker waits.
        let second = tokio::time::timeout(Duration::from_millis(700), LoginLock::acquire(&project, "p")).await;
        assert!(second.is_err());
        drop(held);
        assert_eq!(store.meta_get(&lock_key("p")).unwrap(), None);
        // Left by a process that is gone: taken over at once, however fresh.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        let left = format!("{dead}-00 {}", crate::totp::unix_now());
        store.meta_set(&lock_key("p"), Some(&left)).unwrap();
        let taken = tokio::time::timeout(Duration::from_secs(5), LoginLock::acquire(&project, "p")).await;
        assert!(taken.is_ok_and(|l| l.is_ok()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cookies_are_taken_for_the_site_only() {
        let c = |domain: &str, secure: bool| json!({"name": "sid", "value": "v", "domain": domain, "secure": secure});
        assert!(cookie_for(&c("app.test", false), "app.test", false));
        assert!(cookie_for(&c(".app.test", true), "www.app.test", true));
        assert!(!cookie_for(&c(".app.test", true), "www.app.test", false));
        assert!(!cookie_for(&c("idp.test", false), "app.test", false));
        assert!(!cookie_for(&c("pp.test", false), "app.test", false));
        assert!(!cookie_for(&c("", false), "app.test", false));
    }
}
