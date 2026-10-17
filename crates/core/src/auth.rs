//! Authenticated sessions. A profile describes how to log in (or static headers
//! such as an API token) and how to tell a logged-out response apart. A session
//! applies its cookies and headers to outgoing requests, learns new cookies from
//! responses (session rotation), and logs in again when it notices it has been
//! logged out, so long crawls, fuzz runs, and scans stay authenticated.
//!
//! All requests go through the normal client, so login traffic is bound by the
//! engagement scope like everything else.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use regex::Regex;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::capture::{decode_body, Capture};
use crate::error::{Error, Result};
use crate::http::request::split_head_body;
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
    fn resolve(&self) -> Result<String> {
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

    /// Checks regexes and required fields.
    pub fn validate(&self) -> Result<()> {
        if !self.has_login() && self.headers.is_empty() {
            return Err(Error::InvalidInput("profile needs --login-url or at least one --header".into()));
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

    /// The profile with the password hidden, for display.
    pub fn redacted(&self) -> AuthProfile {
        let mut p = self.clone();
        if let Some(Secret::Literal(_)) = p.password {
            p.password = Some(Secret::Literal("********".into()));
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
}

impl Store {
    /// Adds or replaces a profile (keeping no old session state).
    pub fn auth_save_profile(&self, p: &AuthProfile) -> Result<()> {
        p.validate()?;
        let json = serde_json::to_string(p).map_err(|e| Error::InvalidInput(e.to_string()))?;
        self.conn.execute(
            "INSERT INTO auth_profiles (name, profile, state) VALUES (?1, ?2, '{}')
             ON CONFLICT(name) DO UPDATE SET profile = excluded.profile, state = '{}',
                updated = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![p.name, json],
        )?;
        Ok(())
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
    client: Client,
    project: PathBuf,
    state: Mutex<SessionState>,
    /// Bumped on every login, so concurrent workers re-login only once.
    generation: AtomicU64,
    relogins: AtomicU32,
    last_login: Mutex<Option<Instant>>,
    login_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession").field("profile", &self.profile.name).finish_non_exhaustive()
    }
}

impl AuthSession {
    pub fn load(project: &Path, name: &str, client: Client) -> Result<Self> {
        let (profile, state) = Store::open(project)?.auth_profile(name)?;
        Self::new(project, profile, state, client)
    }

    pub fn new(project: &Path, profile: AuthProfile, state: SessionState, client: Client) -> Result<Self> {
        profile.validate()?;
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

    /// Adds the session's cookies and headers to a raw request. Cookies the
    /// session knows replace the request's values (stale captures), except
    /// cookies named in `keep`, which are left as the caller set them (e.g. a
    /// cookie being attacked or fuzzed).
    pub fn apply(&self, raw: &[u8], keep: &[&str]) -> Vec<u8> {
        let st = self.state.lock().unwrap();
        let mut req = RawRequest::from_bytes(raw.to_vec());
        if !st.cookies.is_empty() {
            let existing = request_cookies(raw);
            let mut merged: Vec<(String, String)> = Vec::new();
            for (k, v) in &existing {
                let replaced = !keep.contains(&k.as_str()) && st.cookies.iter().any(|(n, _)| n == k);
                if !replaced {
                    merged.push((k.clone(), v.clone()));
                }
            }
            for (k, v) in &st.cookies {
                if !merged.iter().any(|(n, _)| n == k) {
                    merged.push((k.clone(), v.clone()));
                }
            }
            let value = merged.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
            req = req.set_header("Cookie", &value);
        }
        if let (Some(tpl), Some(tok)) = (&self.profile.token_header, &st.token) {
            if let Some((k, v)) = tpl.replace("{{token}}", tok).split_once(':') {
                req = req.set_header(k.trim(), v.trim());
            }
        }
        for (k, v) in &self.profile.headers {
            req = req.set_header(k, v);
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
        if !self.profile.has_login() {
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
    /// again (once) if the response shows the session was lost.
    pub async fn send(&self, req: &RawRequest, target: &Target) -> Result<Exchange> {
        let gen = self.generation();
        let prepared = RawRequest::from_bytes(self.apply(req.as_bytes(), &[]));
        let ex = self.client.send(&prepared, target).await?;
        self.observe(&ex.response);
        if self.is_logged_out(&ex.response) && self.relogin(gen).await {
            let again = RawRequest::from_bytes(self.apply(req.as_bytes(), &[]));
            let ex = self.client.send(&again, target).await?;
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
                let ct = tpl.to_ascii_lowercase();
                let enc = if ct.contains("application/json") {
                    Enc::Json
                } else if ct.contains("x-www-form-urlencoded") {
                    Enc::Form
                } else {
                    Enc::Raw
                };
                let text = substitute(tpl, &username, &password, &csrf, enc);
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
                let body = substitute(&body, &username, &password, &csrf, if json { Enc::Json } else { Enc::Form });
                RawRequest::build(&p.login_method, login_url, &headers, body.as_bytes())?.0
            }
        };

        // Send, following redirects (with cookies) like a browser would.
        let mut ex = self.client.send(&RawRequest::from_bytes(self.apply(req.as_bytes(), &[])), &target).await?;
        self.observe(&ex.response);
        history.push(self.record(&ex));
        let mut current = url::Url::parse(login_url).map_err(|e| Error::InvalidInput(e.to_string()))?;
        for _ in 0..5 {
            let Ok(head) = parse_response_head(&ex.response) else { break };
            if !matches!(head.status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(next) = head.header("location").and_then(|l| current.join(l).ok()) else { break };
            current = next;
            let (r, t) = RawRequest::build("GET", current.as_str(), &[], b"")?;
            ex = self.client.send(&RawRequest::from_bytes(self.apply(r.as_bytes(), &[])), &t).await?;
            self.observe(&ex.response);
            history.push(self.record(&ex));
        }

        let final_text = response_text(&ex.response);
        if let Some(re) = &self.re.token {
            let token =
                re.captures(&final_text).and_then(|c| c.get(1).or_else(|| c.get(0))).map(|m| m.as_str().to_string());
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

    fn record(&self, ex: &Exchange) -> Option<i64> {
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
enum Enc {
    Form,
    Json,
    Raw,
}

fn substitute(tpl: &str, user: &str, pass: &str, csrf: &str, enc: Enc) -> String {
    let e = |v: &str| match enc {
        Enc::Form => url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>(),
        Enc::Json => {
            let s = serde_json::to_string(v).unwrap_or_default();
            s[1..s.len() - 1].to_string()
        }
        Enc::Raw => v.to_string(),
    };
    tpl.replace("{{username}}", &e(user)).replace("{{password}}", &e(pass)).replace("{{csrf}}", &e(csrf))
}

fn response_text(response: &[u8]) -> String {
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
        AuthSession::new(&dir.join("p.bpdb"), profile, SessionState::default(), Client::new(Default::default()))
            .unwrap()
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
        let out =
            String::from_utf8(s.apply(b"GET / HTTP/1.1\r\nHost: a.test\r\nCookie: sid=old; other=1\r\n\r\n", &[]))
                .unwrap();
        assert!(out.contains("Cookie: other=1; sid=new; theme=dark\r\n"), "{out}");
        assert!(out.contains("X-Api-Key: k\r\n"));
        // The attacked cookie is left alone.
        let out = String::from_utf8(s.apply(b"GET / HTTP/1.1\r\nCookie: sid=PAYLOAD\r\n\r\n", &["sid"])).unwrap();
        assert!(out.contains("sid=PAYLOAD") && !out.contains("sid=new"), "{out}");
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
        assert_eq!(substitute("u={{username}}&p={{password}}", "a b", "p&w", "", Enc::Form), "u=a+b&p=p%26w");
        assert_eq!(substitute(r#"{"p":"{{password}}"}"#, "", "q\"x", "", Enc::Json), r#"{"p":"q\"x"}"#);
    }

    #[test]
    fn validation_and_redaction() {
        assert!(AuthProfile { name: "x".into(), ..Default::default() }.validate().is_err());
        let p = AuthProfile {
            name: "x".into(),
            login_url: Some("https://a.test/l".into()),
            password: Some(Secret::Literal("hunter2".into())),
            ..Default::default()
        };
        assert!(p.validate().is_ok());
        assert_eq!(p.redacted().password, Some(Secret::Literal("********".into())));
        let bad = AuthProfile { csrf_url: Some("https://a.test/".into()), ..p.clone() };
        assert!(bad.validate().is_err());
    }
}
