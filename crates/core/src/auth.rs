//! Authenticated sessions. A profile describes how to log in (or static headers
//! such as an API token) and how to tell a logged-out response apart. A session
//! applies its cookies and headers to outgoing requests, learns new cookies from
//! responses (session rotation), and logs in again when it notices it has been
//! logged out, so long crawls, fuzz runs, and scans stay authenticated.
//!
//! All requests go through the normal client, so login traffic is bound by the
//! engagement scope like everything else.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use regex::Regex;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::capture::{decode_body, Capture};
use crate::error::{Error, Result};
use crate::http::request::{find, split_head_body};
use crate::http::{parse_response_head, Client, Exchange, RawRequest, Target};
use crate::scan::message::SetCookie;
use crate::store::Store;

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS auth_profiles (
    name TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT '{}',
    updated TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
";

/// Where a password comes from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Secret {
    /// Stored in the project file.
    Literal(String),
    /// Read from this environment variable at login time; never stored.
    Env(String),
}

impl Secret {
    pub(crate) fn resolve(&self) -> Result<String> {
        match self {
            Secret::Literal(s) => Ok(s.clone()),
            Secret::Env(var) => std::env::var(var)
                .map_err(|_| Error::InvalidInput(format!("password environment variable {var} is not set"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AuthProfile {
    pub name: String,
    /// Login endpoint. Without it the profile only adds static headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
    #[serde(default = "post")]
    pub login_method: String,
    /// Login body with {{username}}, {{password}}, {{csrf}} placeholders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_body: Option<String>,
    /// A full raw login request template (overrides method/body); sent to login_url's origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_request: Option<String>,
    #[serde(default)]
    pub login_headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Page to fetch first for a CSRF token, and the regex (group 1) that extracts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csrf_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csrf_regex: Option<String>,
    /// Regex (group 1) extracting a token from the login response, and the header
    /// template that carries it, e.g. "Authorization: Bearer {{token}}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_header: Option<String>,
    /// Regex that only matches when logged in (used to verify a login).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logged_in: Option<String>,
    /// Regex that matches a logged-out response (login page, "session expired").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logged_out: Option<String>,
    /// URL fetched to verify the session after login and for `auth status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_url: Option<String>,
    /// Headers added to every request (API keys, bearer tokens, basic auth).
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Minimum seconds between automatic re-logins.
    #[serde(default = "five")]
    pub relogin_interval_secs: u64,
    /// Maximum automatic re-logins per command run.
    #[serde(default = "twenty")]
    pub max_relogins: u32,
    /// HTTP Basic, Digest, or NTLM credentials (the username and password above) for
    /// some hosts, answered on every command (see [`crate::connection::platform`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<crate::connection::PlatformAuth>,
}

fn post() -> String {
    "POST".into()
}
fn five() -> u64 {
    5
}
fn twenty() -> u32 {
    20
}

impl AuthProfile {
    pub fn has_login(&self) -> bool {
        self.login_url.is_some()
    }

    /// A profile with no login or headers, whose session its macros and rules make.
    pub(crate) fn without_login(name: &str) -> Self {
        AuthProfile {
            name: name.to_string(),
            login_method: post(),
            relogin_interval_secs: five(),
            max_relogins: twenty(),
            ..Default::default()
        }
    }

    /// Checks regexes and required fields, for a profile with no macros or rules.
    pub fn validate(&self) -> Result<()> {
        self.validate_with(&Default::default())
    }

    /// Checks regexes and required fields: a profile needs a login, a header, or at least
    /// one of the macros and rules in `handling`.
    pub fn validate_with(&self, handling: &crate::session::Handling) -> Result<()> {
        if !self.has_login()
            && self.headers.is_empty()
            && self.platform.is_none()
            && handling.macros.is_empty()
            && handling.rules.is_empty()
            && handling.signers.is_empty()
        {
            return Err(Error::InvalidInput(format!(
                "profile needs --login-url, --platform, at least one --header, or a macro \
                 (`auth macro add {} MACRO --step ...` makes a profile with no login)",
                self.name
            )));
        }
        self.validate_fields()
    }

    fn validate_fields(&self) -> Result<()> {
        if let Some(p) = &self.platform {
            p.validate(self.username.as_deref(), self.password.as_ref())?;
        }
        for (what, re) in [
            ("csrf", &self.csrf_regex),
            ("token", &self.token_regex),
            ("logged-in", &self.logged_in),
            ("logged-out", &self.logged_out),
        ] {
            if let Some(r) = re {
                Regex::new(r).map_err(|e| Error::InvalidInput(format!("--{what} regex: {e}")))?;
            }
        }
        if self.csrf_url.is_some() != self.csrf_regex.is_some() {
            return Err(Error::InvalidInput("--csrf-url and --csrf-regex go together".into()));
        }
        if self.token_regex.is_some() != self.token_header.is_some() {
            return Err(Error::InvalidInput("--token-regex and --token-header go together".into()));
        }
        Ok(())
    }

    /// The profile with the password and static header values hidden, for display.
    pub fn redacted(&self) -> AuthProfile {
        let mut p = self.clone();
        if let Some(Secret::Literal(_)) = p.password {
            p.password = Some(Secret::Literal("********".into()));
        }
        for (_, v) in &mut p.headers {
            *v = "********".into();
        }
        p
    }
}

/// Session state persisted between commands.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SessionState {
    #[serde(default)]
    pub cookies: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub logged_in: bool,
    /// Latest values extracted by the profile's macros.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vars: Vec<crate::session::SessionVar>,
    /// Macro runs so far, so placeholders of different runs differ across commands.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub macro_runs: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Store {
    /// Adds or replaces a profile (keeping no old session state).
    pub fn auth_save_profile(&self, p: &AuthProfile) -> Result<()> {
        p.validate_with(&self.auth_handling(&p.name)?)?;
        let json = serde_json::to_string(p).map_err(|e| Error::InvalidInput(e.to_string()))?;
        self.conn.execute(
            "INSERT INTO auth_profiles (name, profile, state) VALUES (?1, ?2, '{}')
             ON CONFLICT(name) DO UPDATE SET profile = excluded.profile, state = '{}',
                updated = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![p.name, json],
        )?;
        // Running proxies reload platform credentials with the settings.
        self.bump_settings_version()
    }

    pub fn auth_profile(&self, name: &str) -> Result<(AuthProfile, SessionState)> {
        let row: Option<(String, String)> = self
            .conn
            .query_row("SELECT profile, state FROM auth_profiles WHERE name = ?1", [name], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let (p, s) = row.ok_or_else(|| Error::NotFound(format!("auth profile {name:?}")))?;
        let profile = serde_json::from_str(&p).map_err(|e| Error::InvalidInput(format!("stored profile: {e}")))?;
        let state = serde_json::from_str(&s).unwrap_or_default();
        Ok((profile, state))
    }

    pub fn auth_save_state(&self, name: &str, state: &SessionState) -> Result<()> {
        let json = serde_json::to_string(state).map_err(|e| Error::InvalidInput(e.to_string()))?;
        self.conn.execute(
            "UPDATE auth_profiles SET state = ?1, updated = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE name = ?2",
            params![json, name],
        )?;
        Ok(())
    }

    pub fn auth_list(&self) -> Result<Vec<(AuthProfile, SessionState)>> {
        let mut stmt = self.conn.prepare("SELECT profile, state FROM auth_profiles ORDER BY name")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (p, s) = row?;
            if let Ok(p) = serde_json::from_str(&p) {
                out.push((p, serde_json::from_str(&s).unwrap_or_default()));
            }
        }
        Ok(out)
    }

    pub fn auth_remove(&self, name: &str) -> Result<()> {
        if self.conn.execute("DELETE FROM auth_profiles WHERE name = ?1", [name])? == 0 {
            return Err(Error::NotFound(format!("auth profile {name:?}")));
        }
        self.auth_clear_handling(name)?;
        self.bump_settings_version()
    }
}

/// The text that stands in for a secret value: `«auth:PROFILE:KIND»`, where KIND is
/// `header:NAME`, `cookie:NAME`, `token`, `password`, `password:form` or `password:json`.
pub fn placeholder(profile: &str, kind: &str) -> String {
    format!("«auth:{profile}:{kind}»")
}

pub(crate) const MARK: &str = "«auth:";

#[derive(Clone)]
struct VaultEntry {
    value: String,
    /// Lowercase header the value may be filled into; None for a value that may go
    /// anywhere in a request to one of `origins` (a password, a macro value).
    header: Option<String>,
    /// Origins an anywhere value may be sent to.
    origins: Vec<String>,
}

/// Values of per-run macro placeholders kept at most; older ones fall back to the
/// variable's latest value.
const RUN_ENTRIES: usize = 4096;

#[derive(Clone, Default)]
struct VaultInner {
    entries: HashMap<String, VaultEntry>,
    /// Per-run placeholders in the order they were added, for pruning.
    runs: std::collections::VecDeque<String>,
    /// Request signers, in the order they run, and the placeholders they fill.
    signers: Vec<crate::sign::Loaded>,
    sign_marks: std::collections::HashSet<String>,
}

/// Current values behind auth placeholders. The auth layer writes placeholders into
/// requests instead of secrets, so history and every other record of a request
/// hold the placeholder; [`Vault::resolve`] puts the real values in as the bytes go
/// on the wire. It lives in the project's [`crate::guard::Guard`], which every client
/// of a command shares.
#[derive(Default)]
pub struct Vault(Mutex<VaultInner>);

impl Clone for Vault {
    fn clone(&self) -> Self {
        Vault(Mutex::new(self.0.lock().unwrap().clone()))
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vault({} values)", self.0.lock().unwrap().entries.len())
    }
}

impl Vault {
    fn put(&self, ph: String, value: &str, header: Option<&str>, origins: Vec<String>) {
        let entry =
            VaultEntry { value: value.to_string(), header: header.map(|h| h.trim().to_ascii_lowercase()), origins };
        self.0.lock().unwrap().entries.insert(ph, entry);
    }

    /// Lets an anywhere value (password, macro value) also go to `origin`.
    pub(crate) fn allow(&self, ph: &str, origin: &str) {
        if let Some(e) = self.0.lock().unwrap().entries.get_mut(ph) {
            if e.header.is_none() && !e.origins.iter().any(|o| o == origin) {
                e.origins.push(origin.to_string());
            }
        }
    }

    /// Registers a macro value: its per-run placeholders and the variable's latest
    /// value (which history replays of an older run fall back to), each encoded for
    /// the raw, form and JSON contexts.
    pub(crate) fn put_var(&self, profile: &str, var: &crate::session::SessionVar) {
        let mut inner = self.0.lock().unwrap();
        for enc in [Enc::Raw, Enc::Form, Enc::Json] {
            let value = encode(&var.value, enc);
            let entry = VaultEntry { value, header: None, origins: var.origins.clone() };
            let run = placeholder(profile, &crate::session::var_kind(&var.name, Some(var.run), enc));
            if inner.entries.insert(run.clone(), entry.clone()).is_none() {
                inner.runs.push_back(run);
            }
            inner.entries.insert(placeholder(profile, &crate::session::var_kind(&var.name, None, enc)), entry);
        }
        while inner.runs.len() > RUN_ENTRIES {
            if let Some(old) = inner.runs.pop_front() {
                inner.entries.remove(&old);
            }
        }
    }

    /// Registers a profile's session values: cookies, token, static headers, macro values.
    fn put_session(&self, p: &AuthProfile, st: &SessionState) {
        // A static Cookie header's cookies first, so a learned cookie of the same name wins.
        for (k, v) in static_cookies(p) {
            self.put(placeholder(&p.name, &format!("cookie:{k}")), &v, Some("cookie"), vec![]);
        }
        for (k, v) in &st.cookies {
            self.put(placeholder(&p.name, &format!("cookie:{k}")), v, Some("cookie"), vec![]);
        }
        if let (Some(tpl), Some(tok)) = (&p.token_header, &st.token) {
            if let Some((k, _)) = tpl.split_once(':') {
                self.put(placeholder(&p.name, "token"), tok, Some(k), vec![]);
            }
        }
        for (k, v) in p.headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("cookie")) {
            self.put(placeholder(&p.name, &format!("header:{k}")), v, Some(k), vec![]);
        }
        for var in &st.vars {
            self.put_var(&p.name, var);
        }
    }

    /// Registers a profile's request signers, replacing those it had.
    pub(crate) fn put_signers(&self, profile: &str, signers: &[crate::sign::Signer]) {
        let mut inner = self.0.lock().unwrap();
        inner.signers.retain(|l| l.profile != profile);
        for signer in signers {
            let key = crate::sign::load_key(signer);
            inner.sign_marks.extend(signer.marks(profile));
            inner.signers.push(crate::sign::Loaded { profile: profile.to_string(), signer: signer.clone(), key });
        }
    }

    /// Registers a password, encoded for each login body type, for the login origin (and
    /// the origins of macro steps that use it, which stay allowed).
    pub(crate) fn put_password(&self, p: &AuthProfile, password: &str) {
        let origin = p.login_url.as_deref().and_then(|u| Target::from_url(u).ok()).map(|t| t.origin());
        for enc in [Enc::Raw, Enc::Form, Enc::Json] {
            let ph = placeholder(&p.name, enc.password_kind());
            let mut origins: Vec<String> = origin.iter().cloned().collect();
            if let Some(old) = self.0.lock().unwrap().entries.get(&ph) {
                origins.extend(old.origins.iter().filter(|o| Some(*o) != origin.as_ref()).cloned());
            }
            self.put(ph, &encode(password, enc), None, origins);
        }
    }

    /// The request with placeholders replaced by their values. A header value is only
    /// filled into its own header, and a password or macro value only into requests to
    /// the origins it belongs to, so a placeholder can't be moved somewhere that
    /// reflects it back. Fails on a placeholder left over (profile removed, never logged
    /// in, password variable unset, or the placeholder moved out of its header). Signers
    /// run last, over the request as it will be sent; their placeholders only count in the head.
    pub fn resolve<'a>(&self, raw: &'a [u8], target: &Target) -> Result<Cow<'a, [u8]>> {
        if find(raw, MARK.as_bytes()).is_none() {
            return Ok(Cow::Borrowed(raw));
        }
        let inner = self.0.lock().unwrap();
        let origin = target.origin();
        let anywhere = |e: &VaultEntry| e.header.is_none() && e.origins.iter().any(|o| o == &origin);
        let (head, body) = split_head_body(raw);
        let mut out = Vec::with_capacity(raw.len());
        for line in head.split_inclusive(|&b| b == b'\n') {
            let name = line
                .iter()
                .position(|&b| b == b':')
                .map(|i| String::from_utf8_lossy(&line[..i]).trim().to_ascii_lowercase());
            let allowed = |e: &VaultEntry| anywhere(e) || (e.header.is_some() && e.header == name);
            out.extend(fill(&inner.entries, &inner.sign_marks, line, allowed)?);
        }
        let new_body = fill(&inner.entries, &Default::default(), body, anywhere)?;
        let body_changed = new_body != body;
        out.extend(new_body);
        if body_changed {
            out = RawRequest::from_bytes(out).update_content_length().into_bytes();
        }
        if find(&out, MARK.as_bytes()).is_some() {
            // Every generated header first: a signer may cover another's.
            let stamp = crate::sign::Stamp::new()?;
            for signer in &inner.signers {
                out = signer.set_headers(out, target, &stamp)?;
            }
            for signer in &inner.signers {
                out = signer.sign(out, target, &stamp)?;
            }
        }
        Ok(Cow::Owned(out))
    }
}

/// `text` with each placeholder replaced by its value, where `allowed` lets it go.
/// A per-run macro placeholder no longer kept falls back to the variable's latest value.
/// Placeholders in `later` stay for the signers.
fn fill(
    entries: &HashMap<String, VaultEntry>,
    later: &std::collections::HashSet<String>,
    text: &[u8],
    allowed: impl Fn(&VaultEntry) -> bool,
) -> Result<Vec<u8>> {
    const END: &[u8] = "»".as_bytes();
    let mut out = Vec::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = find(rest, MARK.as_bytes()) {
        out.extend_from_slice(&rest[..i]);
        rest = &rest[i..];
        let end = find(&rest[..rest.len().min(400)], END).map(|j| j + END.len());
        let ph = end.map(|j| String::from_utf8_lossy(&rest[..j]).into_owned());
        if let (Some(ph), Some(j)) = (&ph, end) {
            if later.contains(ph) {
                out.extend_from_slice(&rest[..j]);
                rest = &rest[j..];
                continue;
            }
        }
        let entry = ph
            .as_deref()
            .and_then(|ph| entries.get(ph).or_else(|| entries.get(&crate::session::latest_placeholder(ph)?)));
        match (entry.filter(|e| allowed(e)), end) {
            (Some(e), Some(j)) => {
                out.extend_from_slice(e.value.as_bytes());
                rest = &rest[j..];
            }
            _ => {
                let shown: String = String::from_utf8_lossy(rest)
                    .chars()
                    .take(120)
                    .take_while(|&c| c != '»')
                    .chain(Some('»'))
                    .collect();
                return Err(Error::InvalidInput(format!(
                    "no value for {shown} in this request: the auth profile was removed, has not logged in \
                     (`auth login`), its password variable is unset, or the placeholder is outside its header"
                )));
            }
        }
    }
    out.extend_from_slice(rest);
    Ok(out)
}

impl Store {
    /// Loads every profile's stored values into `vault`, so requests re-sent from
    /// history (replay, `send`, scans of stored requests) get their placeholders filled.
    pub(crate) fn auth_fill_vault(&self, vault: &Vault) -> Result<()> {
        for (p, st) in self.auth_list()? {
            vault.put_session(&p, &st);
            if let Some(pw) = p.password.as_ref().and_then(|s| s.resolve().ok()) {
                vault.put_password(&p, &pw);
            }
            vault.put_signers(&p.name, &self.auth_handling(&p.name)?.signers);
        }
        Ok(())
    }
}

/// Outcome of a login attempt.
#[derive(Debug, Clone, Serialize)]
pub struct LoginResult {
    pub success: bool,
    pub status: Option<u16>,
    pub cookies: Vec<String>,
    pub token: bool,
    pub reason: String,
    pub history_ids: Vec<i64>,
}

/// Outcome of `AuthSession::check`.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub url: String,
    pub status: Option<u16>,
    pub logged_in: bool,
    pub history_id: Option<i64>,
}

/// Cookie name/value pairs from a raw request's Cookie headers.
pub fn request_cookies(raw: &[u8]) -> Vec<(String, String)> {
    RawRequest::from_bytes(raw.to_vec())
        .head()
        .map(|h| {
            h.headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .flat_map(|(_, v)| v.split(';').map(str::to_string).collect::<Vec<_>>())
                .filter_map(|c| {
                    let (k, v) = c.split_once('=')?;
                    Some((k.trim().to_string(), v.trim().to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

struct Compiled {
    csrf: Option<Regex>,
    token: Option<Regex>,
    logged_in: Option<Regex>,
    logged_out: Option<Regex>,
}

/// A live session shared by every request of a command run.
pub struct AuthSession {
    pub profile: AuthProfile,
    re: Compiled,
    pub(crate) client: Client,
    project: PathBuf,
    pub(crate) state: Mutex<SessionState>,
    /// Bumped on every login, so concurrent workers re-login only once.
    generation: AtomicU64,
    relogins: AtomicU32,
    last_login: Mutex<Option<Instant>>,
    login_lock: tokio::sync::Mutex<()>,
    /// Macros and session rules (see [`crate::session`]).
    pub(crate) handling: crate::session::Runtime,
}

impl std::fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession").field("profile", &self.profile.name).finish_non_exhaustive()
    }
}

impl AuthSession {
    pub fn load(project: &Path, name: &str, client: Client) -> Result<Self> {
        let store = Store::open(project)?;
        let (profile, state) = store.auth_profile(name)?;
        let handling = store.auth_handling(name)?;
        Self::new(project, profile, state, client)?.with_handling(handling)
    }

    pub fn new(project: &Path, profile: AuthProfile, state: SessionState, client: Client) -> Result<Self> {
        // Whether it has something to do depends on its macros and rules: checked when saved.
        profile.validate_fields()?;
        let compile = |r: &Option<String>| {
            r.as_deref().map(Regex::new).transpose().map_err(|e| Error::InvalidInput(e.to_string()))
        };
        Ok(Self {
            re: Compiled {
                csrf: compile(&profile.csrf_regex)?,
                token: compile(&profile.token_regex)?,
                logged_in: compile(&profile.logged_in)?,
                logged_out: compile(&profile.logged_out)?,
            },
            profile,
            client,
            project: project.to_path_buf(),
            state: Mutex::new(state),
            generation: AtomicU64::new(0),
            relogins: AtomicU32::new(0),
            last_login: Mutex::new(None),
            login_lock: tokio::sync::Mutex::new(()),
            handling: Default::default(),
        })
    }

    pub fn state(&self) -> SessionState {
        self.state.lock().unwrap().clone()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Persists the current cookies/token so the next command can reuse them.
    pub fn save(&self) -> Result<()> {
        Store::open(&self.project)?.auth_save_state(&self.profile.name, &self.state())
    }

    /// Logs in if the profile has a login and no session yet.
    pub async fn ensure(&self) -> Result<()> {
        let needs = self.profile.has_login() && !self.state.lock().unwrap().logged_in;
        if needs {
            let r = self.login().await?;
            if !r.success {
                return Err(Error::InvalidInput(format!("login failed: {}", r.reason)));
            }
        }
        Ok(())
    }

    /// The Cookie and auth headers the session would add (for external tools).
    pub fn headers(&self) -> Vec<(String, String)> {
        let st = self.state.lock().unwrap();
        let mut h = Vec::new();
        if !st.cookies.is_empty() {
            h.push((
                "Cookie".into(),
                st.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "),
            ));
        }
        if let (Some(tpl), Some(tok)) = (&self.profile.token_header, &st.token) {
            if let Some((k, v)) = tpl.replace("{{token}}", tok).split_once(':') {
                h.push((k.trim().into(), v.trim().into()));
            }
        }
        for (k, v) in &self.profile.headers {
            h.push((k.clone(), v.clone()));
        }
        h
    }

    /// Adds the session's cookies and headers to a raw request, as placeholders
    /// ([`placeholder`]) that the client fills in on the wire, so no record of the
    /// request holds the secret. Cookies the session knows replace the request's
    /// values (stale captures), except cookies named in `keep`, which are left as
    /// the caller set them (e.g. a cookie being attacked or fuzzed).
    pub fn apply(&self, raw: &[u8], keep: &[&str]) -> Vec<u8> {
        let st = self.state.lock().unwrap();
        if let Some(g) = &self.client.options().guard {
            g.vault.put_session(&self.profile, &st);
        }
        let ph = |kind: &str| placeholder(&self.profile.name, kind);
        let mut req = RawRequest::from_bytes(raw.to_vec());
        // Learned cookies, and those of a static Cookie header, merged into the request's.
        let mut session: Vec<String> = st.cookies.iter().map(|(k, _)| k.clone()).collect();
        for (k, _) in static_cookies(&self.profile) {
            if !session.contains(&k) {
                session.push(k);
            }
        }
        if !session.is_empty() {
            let existing = request_cookies(raw);
            let mut merged: Vec<(String, String)> = Vec::new();
            for (k, v) in &existing {
                let replaced = !keep.contains(&k.as_str()) && session.contains(k);
                if !replaced {
                    merged.push((k.clone(), v.clone()));
                }
            }
            for k in &session {
                if !merged.iter().any(|(n, _)| n == k) {
                    merged.push((k.clone(), ph(&format!("cookie:{k}"))));
                }
            }
            let value = merged.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
            req = req.set_header("Cookie", &value);
        }
        if let (Some(tpl), Some(_)) = (&self.profile.token_header, &st.token) {
            if let Some((k, v)) = tpl.replace("{{token}}", &ph("token")).split_once(':') {
                req = req.set_header(k.trim(), v.trim());
            }
        }
        for (k, _) in self.profile.headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("cookie")) {
            req = req.set_header(k, &ph(&format!("header:{k}")));
        }
        req.into_bytes()
    }

    /// Fetches the profile's check URL with the session applied and reports
    /// whether it still looks logged in. None when the profile has no check URL.
    pub async fn check(&self) -> Result<Option<CheckResult>> {
        let Some(url) = &self.profile.check_url else { return Ok(None) };
        let (req, target) = RawRequest::build("GET", url, &[], b"")?;
        let ex = self.client.send(&RawRequest::from_bytes(self.apply(req.as_bytes(), &[])), &target).await?;
        self.observe(&ex.response);
        let history_id = self.record(&ex);
        let logged_in = !self.is_logged_out(&ex.response)
            && self.re.logged_in.as_ref().is_none_or(|re| re.is_match(&response_text(&ex.response)));
        self.state.lock().unwrap().logged_in = logged_in;
        Ok(Some(CheckResult {
            url: url.clone(),
            status: parse_response_head(&ex.response).ok().map(|h| h.status),
            logged_in,
            history_id,
        }))
    }

    /// Learns cookies set by a response (all Set-Cookie headers, including on
    /// redirects and interim responses).
    pub fn observe(&self, response: &[u8]) {
        let mut st = self.state.lock().unwrap();
        let mut rest = response;
        while let Ok(head) = parse_response_head(rest) {
            for (k, v) in &head.headers {
                if k.eq_ignore_ascii_case("set-cookie") {
                    let c = SetCookie::parse(v);
                    if c.name.is_empty() {
                        continue;
                    }
                    st.cookies.retain(|(n, _)| n != &c.name);
                    if !c.value.is_empty()
                        && !crate::scan::passive::util::cookie_expired(&c)
                        && c.attr("max-age") != Some("0")
                    {
                        st.cookies.push((c.name.clone(), c.value.clone()));
                    }
                }
            }
            if (100..200).contains(&head.status) && head.status != 101 {
                rest = split_head_body(rest).1;
            } else {
                break;
            }
        }
    }

    /// Whether a response shows the session was lost: 401, a logged-out pattern,
    /// or a redirect to the login page.
    pub fn is_logged_out(&self, response: &[u8]) -> bool {
        if !self.profile.has_login() && !self.handling.active() {
            return false;
        }
        let Ok(head) = parse_response_head(response) else { return false };
        if head.status == 401 {
            return true;
        }
        if let (Some(loc), Some(login)) = (head.header("location"), self.profile.login_url.as_deref()) {
            let login_path = url::Url::parse(login).map(|u| u.path().to_string()).unwrap_or_default();
            if login_path.len() > 1 && loc.contains(&login_path) {
                return true;
            }
        }
        if let Some(re) = &self.re.logged_out {
            return re.is_match(&response_text(response));
        }
        false
    }

    /// Sends a request with the session applied, learning cookies, and logs in
    /// again (once) if the response shows the session was lost. Session rules for
    /// the `send` tool apply.
    pub async fn send(&self, req: &RawRequest, target: &Target) -> Result<Exchange> {
        self.send_as(crate::session::Tool::Send, req, target).await
    }

    /// [`AuthSession::send`] for requests of `tool`, whose session rules apply.
    pub async fn send_as(&self, tool: crate::session::Tool, req: &RawRequest, target: &Target) -> Result<Exchange> {
        let prepared = self.prepare(tool, target, req.as_bytes(), &[], &[]).await;
        let ex = self.client.send(&RawRequest::from_bytes(prepared.request.clone()), target).await?;
        if self.after_response(&prepared, &ex.response).await {
            let again = self.prepare(tool, target, req.as_bytes(), &[], &[]).await;
            let ex = self.client.send(&RawRequest::from_bytes(again.request), target).await?;
            self.observe(&ex.response);
            return Ok(ex);
        }
        Ok(ex)
    }

    /// Logs in again after a logout seen at `seen_generation`. Returns true if the
    /// caller should retry (a login happened, here or concurrently).
    pub async fn relogin(&self, seen_generation: u64) -> bool {
        if !self.profile.has_login() {
            return false;
        }
        let _guard = self.login_lock.lock().await;
        if self.generation() != seen_generation {
            return true; // Someone else already logged in again.
        }
        if self.relogins.load(Ordering::SeqCst) >= self.profile.max_relogins {
            return false;
        }
        if let Some(t) = *self.last_login.lock().unwrap() {
            if t.elapsed() < Duration::from_secs(self.profile.relogin_interval_secs) {
                return false;
            }
        }
        self.relogins.fetch_add(1, Ordering::SeqCst);
        matches!(self.login_inner().await, Ok(r) if r.success)
    }

    /// Performs the login now.
    pub async fn login(&self) -> Result<LoginResult> {
        let _guard = self.login_lock.lock().await;
        self.login_inner().await
    }

    async fn login_inner(&self) -> Result<LoginResult> {
        let p = &self.profile;
        let Some(login_url) = &p.login_url else {
            return Ok(LoginResult {
                success: true,
                status: None,
                cookies: vec![],
                token: false,
                reason: "static headers only".into(),
                history_ids: vec![],
            });
        };
        *self.last_login.lock().unwrap() = Some(Instant::now());
        // Start from a clean jar so stale session cookies don't leak into the login.
        {
            let mut st = self.state.lock().unwrap();
            st.cookies.clear();
            st.token = None;
            st.logged_in = false;
        }
        let mut history = Vec::new();
        let username = p.username.clone().unwrap_or_default();
        let password = p.password.as_ref().map(Secret::resolve).transpose()?.unwrap_or_default();
        if let Some(g) = &self.client.options().guard {
            g.vault.put_password(p, &password);
        }

        let mut csrf = String::new();
        if let (Some(url), Some(re)) = (&p.csrf_url, &self.re.csrf) {
            let (req, target) = RawRequest::build("GET", url, &[], b"")?;
            let ex = self.client.send(&RawRequest::from_bytes(self.apply(req.as_bytes(), &[])), &target).await?;
            self.observe(&ex.response);
            history.push(self.record(&ex));
            csrf = re
                .captures(&response_text(&ex.response))
                .and_then(|c| c.get(1).or_else(|| c.get(0)))
                .map(|m| crate::scan::passive::util::decode_entities(m.as_str()))
                .ok_or_else(|| Error::InvalidInput("CSRF token not found on --csrf-url page".into()))?;
        }

        let target = Target::from_url(login_url)?;
        let req = match &p.login_request {
            Some(tpl) => {
                let text = fill_template(tpl, &username, &p.name, &csrf);
                RawRequest::from_bytes(text.into_bytes()).normalize_line_endings().update_content_length()
            }
            None => {
                let body = p.login_body.clone().unwrap_or_default();
                let json = body.trim_start().starts_with('{');
                let mut headers = p.login_headers.clone();
                if !body.is_empty() && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                    let ct = if json { "application/json" } else { "application/x-www-form-urlencoded" };
                    headers.push(("Content-Type".into(), ct.into()));
                }
                let enc = if json { Enc::Json } else { Enc::Form };
                let body = substitute(&body, &username, &placeholder(&p.name, enc.password_kind()), &csrf, enc);
                RawRequest::build(&p.login_method, login_url, &headers, body.as_bytes())?.0
            }
        };

        // The token may come with any response of the login: the first one (often a
        // redirect) or one after it. When several have it, the last one wins (as before,
        // when only the final page was searched).
        let mut token = None;
        let mut find_token = |response: &[u8]| {
            if let Some(re) = &self.re.token {
                if let Some(m) = re.captures(&response_text(response)).and_then(|c| c.get(1).or_else(|| c.get(0))) {
                    token = Some(m.as_str().to_string());
                }
            }
        };
        // Send, following redirects (with cookies) like a browser would.
        let mut ex = self.client.send(&RawRequest::from_bytes(self.apply(req.as_bytes(), &[])), &target).await?;
        self.observe(&ex.response);
        find_token(&ex.response);
        history.push(self.record(&ex));
        let mut current = url::Url::parse(login_url).map_err(|e| Error::InvalidInput(e.to_string()))?;
        for _ in 0..5 {
            let Ok(head) = parse_response_head(&ex.response) else { break };
            if !matches!(head.status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(next) = head.header("location").and_then(|l| current.join(l).ok()) else { break };
            current = next;
            // 307 and 308 repeat the request there (a login POST stays a POST, with its
            // body); the others continue with a GET, as browsers do.
            let (r, t) = match req.head() {
                Ok(h) if matches!(head.status, 307 | 308) => {
                    let same_origin = Target::from_url(current.as_str()).is_ok_and(|t| t.origin() == target.origin());
                    let headers = replayed_headers(h.headers, same_origin);
                    RawRequest::build(&h.method, current.as_str(), &headers, req.body())?
                }
                _ => RawRequest::build("GET", current.as_str(), &[], b"")?,
            };
            ex = self.client.send(&RawRequest::from_bytes(self.apply(r.as_bytes(), &[])), &t).await?;
            self.observe(&ex.response);
            find_token(&ex.response);
            history.push(self.record(&ex));
        }

        let final_text = response_text(&ex.response);
        if self.re.token.is_some() {
            self.state.lock().unwrap().token = token;
        }

        // Verify: check URL if given, else the final login response.
        let (verify_text, status) = match &p.check_url {
            Some(u) => {
                let (r, t) = RawRequest::build("GET", u, &[], b"")?;
                let cex = self.client.send(&RawRequest::from_bytes(self.apply(r.as_bytes(), &[])), &t).await?;
                self.observe(&cex.response);
                history.push(self.record(&cex));
                let logged_out = self.is_logged_out(&cex.response);
                let text = response_text(&cex.response);
                (if logged_out { None } else { Some(text) }, parse_response_head(&cex.response).ok().map(|h| h.status))
            }
            None => (Some(final_text.clone()), parse_response_head(&ex.response).ok().map(|h| h.status)),
        };
        let st = self.state();
        let (success, reason) = match verify_text {
            None => (false, "the check URL still looks logged out".to_string()),
            Some(text) => match (&self.re.logged_in, &self.re.logged_out) {
                (Some(re), _) if re.is_match(&text) => (true, "logged-in pattern matched".into()),
                (Some(_), _) => (false, "logged-in pattern did not match".into()),
                (None, Some(re)) if re.is_match(&text) => (false, "logged-out pattern matched after login".into()),
                _ if st.token.is_some() => (true, "token extracted".into()),
                _ if !st.cookies.is_empty() => (true, "session cookies set".into()),
                _ => (false, "no cookies or token were set; add --logged-in to verify".into()),
            },
        };
        {
            let mut st = self.state.lock().unwrap();
            st.logged_in = success;
            st.last_login = Some(now_iso());
            st.last_error = (!success).then(|| reason.clone());
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        let _ = self.save();
        let st = self.state();
        Ok(LoginResult {
            success,
            status,
            cookies: st.cookies.iter().map(|(k, _)| k.clone()).collect(),
            token: st.token.is_some(),
            reason,
            history_ids: history.into_iter().flatten().collect(),
        })
    }

    pub(crate) fn record(&self, ex: &Exchange) -> Option<i64> {
        let store = Store::open(&self.project).ok()?;
        store
            .record(&Capture::new(
                "auth",
                &ex.target,
                &ex.request,
                Some(&ex.response),
                Some(ex.duration_ms as i64),
                None,
            ))
            .ok()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Enc {
    Form,
    Json,
    Raw,
}

impl Enc {
    pub(crate) fn password_kind(self) -> &'static str {
        match self {
            Enc::Raw => "password",
            Enc::Form => "password:form",
            Enc::Json => "password:json",
        }
    }
}

pub(crate) fn encode(v: &str, enc: Enc) -> String {
    match enc {
        Enc::Form => url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>(),
        Enc::Json => {
            let s = serde_json::to_string(v).unwrap_or_default();
            s[1..s.len() - 1].to_string()
        }
        Enc::Raw => v.to_string(),
    }
}

/// The headers a 307/308 login redirect repeats: not the framing ones, and not the
/// template's credentials on another origin (browsers drop Authorization there).
fn replayed_headers(headers: Vec<(String, String)>, same_origin: bool) -> Vec<(String, String)> {
    let dropped: &[&str] = if same_origin {
        &["host", "content-length", "transfer-encoding"]
    } else {
        &["host", "content-length", "transfer-encoding", "authorization", "cookie"]
    };
    headers.into_iter().filter(|(k, _)| !dropped.iter().any(|f| k.eq_ignore_ascii_case(f))).collect()
}

/// The cookies of a profile's static Cookie header.
pub(crate) fn static_cookies(p: &AuthProfile) -> Vec<(String, String)> {
    p.headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';'))
        .filter_map(|c| {
            let (k, v) = c.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// Fills a raw login request template part by part: the body encoded for its
/// Content-Type (sniffed as JSON when there is none), header values as they are (a
/// CSRF header carries the token itself), and the request line URL-encoded.
fn fill_template(tpl: &str, user: &str, profile: &str, csrf: &str) -> String {
    let (head, sep, body) = match (tpl.find("\r\n\r\n"), tpl.find("\n\n")) {
        (Some(a), b) if b.is_none_or(|b| a < b) => (&tpl[..a], "\r\n\r\n", &tpl[a + 4..]),
        (_, Some(b)) => (&tpl[..b], "\n\n", &tpl[b + 2..]),
        _ => (tpl, "", ""),
    };
    let (line, headers) = head.split_once('\n').map_or((head, None), |(l, h)| (l, Some(h)));
    let content_type = headers
        .into_iter()
        .flat_map(str::lines)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase());
    let enc = match content_type {
        Some(ct) if ct.contains("json") => Enc::Json,
        Some(ct) if ct.contains("x-www-form-urlencoded") => Enc::Form,
        Some(_) => Enc::Raw,
        None if body.trim_start().starts_with('{') => Enc::Json,
        None => Enc::Raw,
    };
    let fill = |text: &str, enc: Enc| substitute(text, user, &placeholder(profile, enc.password_kind()), csrf, enc);
    let mut out = fill(line, Enc::Form);
    if let Some(h) = headers {
        out.push('\n');
        out.push_str(&fill(h, Enc::Raw));
    }
    out.push_str(sep);
    out.push_str(&fill(body, enc));
    out
}

/// Fills a login template. `pass` goes in as given (the password placeholder for
/// `enc`; the vault holds the encoded password); username and CSRF token are encoded.
fn substitute(tpl: &str, user: &str, pass: &str, csrf: &str, enc: Enc) -> String {
    tpl.replace("{{username}}", &encode(user, enc))
        .replace("{{password}}", pass)
        .replace("{{csrf}}", &encode(csrf, enc))
}

pub(crate) fn response_text(response: &[u8]) -> String {
    let Ok(head) = parse_response_head(response) else { return String::from_utf8_lossy(response).into_owned() };
    let (h, b) = split_head_body(response);
    let mut s = String::from_utf8_lossy(h).into_owned();
    s.push_str(&String::from_utf8_lossy(&decode_body(&head.headers, b)));
    s
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(profile: AuthProfile) -> AuthSession {
        let dir = std::env::temp_dir().join(format!("bp-auth-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let scope = crate::guard::ScopeSpec { name: None, include: vec!["a.test".into()], exclude: vec![] };
        let opts = crate::http::SendOptions {
            guard: Some(crate::guard::Guard::from_specs(vec![scope]).unwrap()),
            ..Default::default()
        };
        AuthSession::new(&dir.join("p.bpdb"), profile, SessionState::default(), Client::new(opts)).unwrap()
    }

    fn wire(s: &AuthSession, req: &[u8]) -> Result<String> {
        let target = Target::from_url("https://a.test").unwrap();
        Ok(String::from_utf8(s.client.fill_auth(req, &target)?.into_owned()).unwrap())
    }

    #[test]
    fn applies_and_learns_cookies() {
        let s = session(AuthProfile {
            name: "t".into(),
            login_url: Some("https://a.test/login".into()),
            logged_out: Some("Please log in".into()),
            headers: vec![("X-Api-Key".into(), "k".into())],
            ..Default::default()
        });
        s.observe(b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=new; Path=/\r\nSet-Cookie: theme=dark\r\n\r\n");
        let applied = s.apply(b"GET / HTTP/1.1\r\nHost: a.test\r\nCookie: sid=old; other=1\r\n\r\n", &[]);
        // The request (as recorded) holds placeholders; the wire form holds the values.
        let out = String::from_utf8(applied.clone()).unwrap();
        assert!(out.contains("Cookie: other=1; sid=«auth:t:cookie:sid»; theme=«auth:t:cookie:theme»\r\n"), "{out}");
        assert!(out.contains("X-Api-Key: «auth:t:header:X-Api-Key»\r\n"), "{out}");
        let sent = wire(&s, &applied).unwrap();
        assert!(sent.contains("Cookie: other=1; sid=new; theme=dark\r\n"), "{sent}");
        assert!(sent.contains("X-Api-Key: k\r\n"));
        // The attacked cookie is left alone.
        let out = String::from_utf8(s.apply(b"GET / HTTP/1.1\r\nCookie: sid=PAYLOAD\r\n\r\n", &["sid"])).unwrap();
        assert!(out.contains("sid=PAYLOAD") && !out.contains("sid=«"), "{out}");
        // A placeholder moved out of its header, or of an unknown profile, is refused.
        assert!(wire(&s, b"GET /?x=\xc2\xabauth:t:header:X-Api-Key\xc2\xbb HTTP/1.1\r\n\r\n").is_err());
        assert!(wire(&s, "GET / HTTP/1.1\r\nX-Api-Key: «auth:gone:header:X-Api-Key»\r\n\r\n".as_bytes()).is_err());
        // Deletion cookies are forgotten.
        s.observe(b"HTTP/1.1 200 OK\r\nSet-Cookie: theme=; Max-Age=0\r\n\r\n");
        assert_eq!(s.state().cookies, vec![("sid".to_string(), "new".to_string())]);
    }

    #[test]
    fn detects_logout() {
        let s = session(AuthProfile {
            name: "t".into(),
            login_url: Some("https://a.test/account/login".into()),
            logged_out: Some("(?i)session expired".into()),
            ..Default::default()
        });
        assert!(s.is_logged_out(b"HTTP/1.1 401 Unauthorized\r\n\r\n"));
        assert!(s.is_logged_out(b"HTTP/1.1 302 Found\r\nLocation: /account/login?next=/x\r\n\r\n"));
        assert!(s.is_logged_out(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nSession Expired"));
        assert!(!s.is_logged_out(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"));
        assert!(!s.is_logged_out(b"HTTP/1.1 302 Found\r\nLocation: /home\r\n\r\n"));
    }

    #[test]
    fn substitution_encodes_for_context() {
        assert_eq!(substitute("u={{username}}&p={{password}}", "a b", "PW", "", Enc::Form), "u=a+b&p=PW");
        assert_eq!(encode("p&w", Enc::Form), "p%26w");
        assert_eq!(encode("q\"x", Enc::Json), r#"q\"x"#);
    }

    #[test]
    fn a_login_redirect_to_another_origin_drops_template_credentials() {
        let h = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>();
        let sent = h(&[
            ("Host", "a.test"),
            ("Content-Length", "2"),
            ("Authorization", "Basic x"),
            ("Cookie", "a=1"),
            ("Content-Type", "application/json"),
        ]);
        assert_eq!(
            replayed_headers(sent.clone(), true),
            h(&[("Authorization", "Basic x"), ("Cookie", "a=1"), ("Content-Type", "application/json")])
        );
        assert_eq!(replayed_headers(sent, false), h(&[("Content-Type", "application/json")]));
    }

    #[test]
    fn login_templates_encode_each_part_for_its_place() {
        let tpl = "POST /login?u={{username}} HTTP/1.1\nAccept: application/json, */*\nContent-Type: application/x-www-form-urlencoded\nX-CSRF-Token: {{csrf}}\n\nuser={{username}}&pw={{password}}&t={{csrf}}";
        let out = fill_template(tpl, "alice+qa@corp.test", "t", "ab+c/d=1");
        let pw = placeholder("t", "password:form");
        assert_eq!(
            out,
            format!("POST /login?u=alice%2Bqa%40corp.test HTTP/1.1\nAccept: application/json, */*\nContent-Type: application/x-www-form-urlencoded\nX-CSRF-Token: ab+c/d=1\n\nuser=alice%2Bqa%40corp.test&pw={pw}&t=ab%2Bc%2Fd%3D1")
        );
        let json = fill_template(
            "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"u\":\"{{username}}\"}",
            "a\"b",
            "t",
            "",
        );
        assert!(json.ends_with("{\"u\":\"a\\\"b\"}"), "{json}");
    }

    #[test]
    fn a_static_cookie_header_merges_with_the_request_cookies() {
        let p = AuthProfile {
            name: "t".into(),
            headers: vec![("Cookie".into(), "sid=LOGGEDIN; theme=dark".into())],
            ..Default::default()
        };
        let s = session(p);
        let req = b"GET /x HTTP/1.1\r\nHost: a.test\r\nCookie: sid=PAYLOAD; other=1\r\n\r\n";
        let sent = wire(&s, &s.apply(req, &["sid"])).unwrap();
        assert!(sent.contains("Cookie: sid=PAYLOAD; other=1; theme=dark\r\n"), "{sent}");
        let sent = wire(&s, &s.apply(req, &[])).unwrap();
        assert!(sent.contains("Cookie: other=1; sid=LOGGEDIN; theme=dark\r\n"), "{sent}");
    }

    #[test]
    fn password_fills_login_origin_only() {
        let p = AuthProfile { name: "t".into(), login_url: Some("https://a.test/login".into()), ..Default::default() };
        let s = session(p.clone());
        s.client.options().guard.as_ref().unwrap().vault.put_password(&p, "p&w");
        let body = substitute("p={{password}}", "", &placeholder("t", "password:form"), "", Enc::Form);
        let req = format!("POST /login HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let sent = wire(&s, req.as_bytes()).unwrap();
        assert!(sent.ends_with("Content-Length: 7\r\n\r\np=p%26w"), "{sent}");
        let other = Target::from_url("https://b.test").unwrap();
        assert!(s.client.fill_auth(req.as_bytes(), &other).is_err());
    }

    #[test]
    fn validation_and_redaction() {
        // No login, no headers: only with a macro or a rule.
        let bare = AuthProfile { name: "x".into(), ..Default::default() };
        assert!(bare.validate().is_err());
        let rule = crate::session::SessionRule {
            id: 1,
            description: String::new(),
            tools: vec![],
            url: None,
            actions: vec![crate::session::Action::Login],
            invalid: None,
        };
        assert!(bare.validate_with(&crate::session::Handling { rules: vec![rule], ..Default::default() }).is_ok());
        let p = AuthProfile {
            name: "x".into(),
            login_url: Some("https://a.test/l".into()),
            password: Some(Secret::Literal("hunter2".into())),
            headers: vec![("Authorization".into(), "Bearer APIKEY123".into())],
            ..Default::default()
        };
        assert!(p.validate().is_ok());
        assert_eq!(p.redacted().password, Some(Secret::Literal("********".into())));
        assert_eq!(p.redacted().headers, vec![("Authorization".into(), "********".into())]);
        let bad = AuthProfile { csrf_url: Some("https://a.test/".into()), ..p.clone() };
        assert!(bad.validate().is_err());
    }
}
