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

use crate::capture::decode_body;
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
            Secret::Env(var) => {
                std::env::var(var).map_err(|_| Error::InvalidInput(format!("environment variable {var} is not set")))
            }
        }
    }
}

/// An API key sent in the query string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryKey {
    pub name: String,
    pub value: String,
    /// The only origins it is sent to.
    pub origins: Vec<String>,
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
    /// API keys added to the query string of requests to their origins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_keys: Vec<QueryKey>,
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
    /// OAuth 2.0 token requests in place of a login (see [`crate::oauth`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<crate::oauth::OAuth>,
    /// The secret one-time codes are made from (see [`crate::totp`]): `{{totp}}` in the login
    /// request, a login step, a macro step or a browser step is the current code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<crate::totp::Totp>,
    /// Requests sent after the login request, in order: a one-time code form on its own page.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub login_steps: Vec<LoginStep>,
    /// A login replayed in a headless browser in place of a login request (see
    /// [`crate::browser_login`]): recorded steps, for a login plain requests can't repeat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<crate::browser_login::BrowserLogin>,
    /// Passkeys the browser login signs in with: credentials of its virtual authenticator.
    /// Their private keys are stored here like a stored password, and masked like one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<crate::browser_login::Passkey>,
    /// Who saved it last: gui, cli or mcp (None: before brainproxy kept it), set when it is
    /// saved. A proxied request its session goes on records this in `edited_by`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// A request that follows the login request, such as the form a one-time code is posted to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoginStep {
    /// Where it goes (the request line's path is what is sent).
    pub url: String,
    /// The raw request, with `{{totp}}`, `{{username}}`, `{{password}}` and `{{csrf}}` placeholders.
    pub request: String,
    /// Page fetched first for the step's own token. Without it, `csrf_regex` reads the
    /// responses since the request before (the login's, or the previous step's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csrf_url: Option<String>,
    /// Regex (group 1) for the token `{{csrf}}` stands for in this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csrf_regex: Option<String>,
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
        self.login_url.is_some() || self.oauth.is_some() || self.browser.is_some()
    }

    /// The origins the login sends its password and one-time code to: the login request's and
    /// its follow-up steps', and those of the pages a browser login types them on.
    pub(crate) fn login_origins(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let typed_on = self.browser.iter().flat_map(|b| b.secret_pages());
        for url in
            self.login_url.iter().chain(self.login_steps.iter().map(|s| &s.url)).map(String::as_str).chain(typed_on)
        {
            if let Ok(t) = Target::from_url(url) {
                if !out.contains(&t.origin()) {
                    out.push(t.origin());
                }
            }
        }
        out
    }

    /// Whether logging in sends a one-time code.
    pub fn login_uses_totp(&self) -> bool {
        const VAR: &str = "{{totp}}";
        self.login_body.as_deref().is_some_and(|b| b.contains(VAR))
            || self.login_request.as_deref().is_some_and(|r| r.contains(VAR))
            || self.login_steps.iter().any(|s| s.request.contains(VAR))
            || self.browser.as_ref().is_some_and(|b| b.uses_totp())
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
            && self.query_keys.is_empty()
            && self.platform.is_none()
            && handling.macros.is_empty()
            && handling.rules.is_empty()
            && handling.signers.is_empty()
        {
            return Err(Error::InvalidInput(format!(
                "profile needs --login-url, --platform, at least one --header or --query-key, or a macro \
                 (`auth macro add {} MACRO --step ...` makes a profile with no login)",
                self.name
            )));
        }
        self.validate_fields()
    }

    fn validate_fields(&self) -> Result<()> {
        if let Some(o) = &self.oauth {
            if self.login_url.is_some() {
                return Err(Error::InvalidInput("a profile logs in with --login-url or OAuth, not both".into()));
            }
            if self.token_regex.is_some() {
                return Err(Error::InvalidInput("OAuth reads the token itself: leave out --token-regex".into()));
            }
            o.validate(self.username.as_deref(), self.password.as_ref())?;
        }
        for q in &self.query_keys {
            // Sent as written, so nothing that means something in a query.
            let name_ok = !q.name.is_empty()
                && q.name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
            if !name_ok {
                return Err(Error::InvalidInput(format!("bad query key name {:?}", q.name)));
            }
            if q.origins.is_empty() {
                return Err(Error::InvalidInput(format!("query key {:?} needs --key-origin", q.name)));
            }
            for o in &q.origins {
                Target::from_url(o)?;
            }
        }
        if let Some(p) = &self.platform {
            p.validate(self.username.as_deref(), self.password.as_ref())?;
        }
        if let Some(t) = &self.totp {
            t.validate()?;
        }
        if let Some(b) = &self.browser {
            if self.login_url.is_some() || self.oauth.is_some() {
                return Err(Error::InvalidInput(
                    "a profile logs in with a login request, OAuth or recorded browser steps, not two of them".into(),
                ));
            }
            b.validate()?;
        }
        // A shown profile has no keys in it: it isn't one to save again.
        if self.passkeys.iter().any(|k| k.private_key.is_empty() || k.credential_id.is_empty() || k.rp_id.is_empty()) {
            return Err(Error::InvalidInput(
                "a passkey without its key, id or site can't sign in: record it again".into(),
            ));
        }
        if !self.login_steps.is_empty() && self.login_url.is_none() {
            return Err(Error::InvalidInput(
                "login steps follow a login request: the profile needs --login-url".into(),
            ));
        }
        for (i, step) in self.login_steps.iter().enumerate() {
            let what = |e: String| Error::InvalidInput(format!("login step {}: {e}", i + 1));
            Target::from_url(&step.url).map_err(|e| what(e.to_string()))?;
            RawRequest::from_bytes(step.request.clone().into_bytes()).head().map_err(|e| what(e.to_string()))?;
            if let Some(r) = &step.csrf_regex {
                Regex::new(r).map_err(|e| what(format!("token regex: {e}")))?;
            }
            if step.csrf_url.is_some() && step.csrf_regex.is_none() {
                return Err(what("a token page needs the regex that reads the token".into()));
            }
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
        // A browser login reads the token off the requests the page sends: no regex.
        let token_read_for_it = self.oauth.is_some() || (self.browser.is_some() && self.token_regex.is_none());
        if !token_read_for_it && self.token_regex.is_some() != self.token_header.is_some() {
            return Err(Error::InvalidInput("--token-regex and --token-header go together".into()));
        }
        // A line break would start another header (a Host, say) on every request.
        let token = self.token_header.as_deref().map(|h| h.split_once(':').unwrap_or((h, "")));
        let headers = self.headers.iter().chain(&self.login_headers).map(|(k, v)| (k.as_str(), v.as_str()));
        for (k, v) in headers.chain(token) {
            crate::http::request::check_header(k, v)?;
        }
        Ok(())
    }

    /// The profile with the password, static header values, and query keys hidden, for display.
    pub fn redacted(&self) -> AuthProfile {
        let mut p = self.clone();
        if let Some(Secret::Literal(_)) = p.password {
            p.password = Some(Secret::Literal("********".into()));
        }
        for (_, v) in &mut p.headers {
            *v = "********".into();
        }
        for q in &mut p.query_keys {
            q.value = "********".into();
        }
        p.oauth = p.oauth.as_ref().map(crate::oauth::OAuth::redacted);
        p.totp = p.totp.as_ref().map(crate::totp::Totp::redacted);
        for step in &mut p.login_steps {
            step.request = mask_authorization(&step.request);
        }
        p.browser = p.browser.as_ref().map(crate::browser_login::BrowserLogin::redacted);
        for k in &mut p.passkeys {
            k.private_key.clear();
        }
        p
    }

    /// Every secret value this profile and its session hold (passwords, client secrets,
    /// static header values and their credentials, query keys, cookies, tokens, macro
    /// values), for a report to mask wherever it quotes them. A password read from an unset
    /// environment variable is left out.
    pub fn secret_values(&self, st: &SessionState) -> Vec<String> {
        let resolve = |s: &Option<Secret>| s.as_ref().and_then(|s| s.resolve().ok());
        let mut out: Vec<String> = [&self.password].into_iter().filter_map(resolve).collect();
        if let Some(o) = &self.oauth {
            out.extend([&o.client_secret, &o.refresh_token].into_iter().filter_map(resolve));
        }
        // The secret codes are made from. A code itself is never on record (requests carry a
        // placeholder), and one a person typed while recording a login is spent.
        out.extend(self.totp.iter().flat_map(crate::totp::Totp::secret_values));
        out.extend(self.browser.iter().flat_map(|b| b.secret_values()));
        out.extend(self.passkeys.iter().map(|k| k.private_key.clone()));
        out.extend(static_cookies(self).into_iter().map(|(_, v)| v));
        // A profile's headers are there to authenticate, except the ordinary ones a profile may
        // set too: a User-Agent or Accept isn't a secret, and would be masked everywhere.
        const ORDINARY: &[&str] = &[
            "cookie",
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "content-type",
            "content-length",
            "host",
            "origin",
            "referer",
            "x-requested-with",
            "cache-control",
            "pragma",
            "connection",
            "dnt",
            "upgrade-insecure-requests",
        ];
        let ordinary = |k: &str| {
            let k = k.trim().to_ascii_lowercase();
            ORDINARY.contains(&k.as_str()) || k.starts_with("sec-")
        };
        for (_, v) in self.headers.iter().filter(|(k, _)| !ordinary(k)) {
            // "Bearer xyz": the credential alone is what other places quote.
            if let Some((_, cred)) = v.trim().split_once(' ') {
                out.push(cred.trim().to_string());
            }
            out.push(v.trim().to_string());
        }
        out.extend(self.query_keys.iter().map(|q| q.value.clone()));
        out.extend(st.cookies.iter().map(|(_, v)| v.clone()));
        out.extend(st.token.iter().chain(&st.refresh_token).cloned());
        // Macro values are often tokens, but may be a user id or a name: only distinctive ones.
        out.extend(st.vars.iter().map(|v| v.value.clone()).filter(|v| crate::scan::redact::distinctive(v)));
        out.retain(|v| !v.is_empty());
        out
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
    /// OAuth: the refresh token and when the access token runs out (unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires: Option<u64>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Store {
    /// Adds or replaces a profile (keeping no old session state), saved by this process's
    /// origin; one saved as it was (the app's edit form re-saves it) keeps its own.
    pub fn auth_save_profile(&self, p: &AuthProfile) -> Result<()> {
        p.validate_with(&self.auth_handling(&p.name)?)?;
        // Read and written in one transaction: a login in another process may be storing the
        // count a passkey just reached.
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)?;
        let old = self.auth_profile(&p.name).ok().map(|(old, _)| old);
        // A passkey's count never goes down: one kept from before keeps the higher of the two.
        let mut p = p.clone();
        for k in &mut p.passkeys {
            let before = old.iter().flat_map(|o| &o.passkeys).find(|o| o.credential_id == k.credential_id);
            k.sign_count = k.sign_count.max(before.map_or(0, |o| o.sign_count));
        }
        let kept =
            old.filter(|old| *old == AuthProfile { origin: old.origin.clone(), ..p.clone() }).map(|old| old.origin);
        let origin = kept.unwrap_or_else(|| Some(crate::provenance::origin().to_string()));
        let p = AuthProfile { origin, ..p };
        let json = serde_json::to_string(&p).map_err(|e| Error::InvalidInput(e.to_string()))?;
        self.conn.execute(
            "INSERT INTO auth_profiles (name, profile, state) VALUES (?1, ?2, '{}')
             ON CONFLICT(name) DO UPDATE SET profile = excluded.profile, state = '{}', state_origin = NULL,
                state_changed_at = NULL, updated = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![p.name, json],
        )?;
        tx.commit()?;
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

    /// Stores a profile's session (cookies, token, macro values) with who stored it: the
    /// process that logged in, got the OAuth token or learnt the cookies.
    pub fn auth_save_state(&self, name: &str, state: &SessionState) -> Result<()> {
        self.auth_keep_state(name, state, (Some(crate::provenance::origin().to_string()), None))
    }

    /// Stores a profile's session as stored earlier by `by` (who, and when: now when None), for
    /// tokens kept across a change to the profile.
    pub fn auth_keep_state(
        &self,
        name: &str,
        state: &SessionState,
        by: (Option<String>, Option<String>),
    ) -> Result<()> {
        let json = serde_json::to_string(state).map_err(|e| Error::InvalidInput(e.to_string()))?;
        self.conn.execute(
            "UPDATE auth_profiles SET state = ?1, state_origin = ?3, updated = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                state_changed_at = COALESCE(?4, strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE name = ?2",
            params![json, name, by.0, by.1],
        )?;
        Ok(())
    }

    /// Who stored a profile's session last (gui, cli or mcp), and when; None until a session is
    /// stored, and for one stored before brainproxy kept it.
    pub fn auth_state_origin(&self, name: &str) -> Result<(Option<String>, Option<String>)> {
        let row = self
            .conn
            .query_row("SELECT state_origin, state_changed_at FROM auth_profiles WHERE name = ?1", [name], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("auth profile {name:?}")))
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

    /// Notes the time step of a one-time code a profile's login has sent (typed while its
    /// login was recorded), so the same code isn't sent again.
    pub fn auth_note_code_used(&self, name: &str, step: u64) -> Result<()> {
        self.meta_set(&totp_used_key(name), Some(&step.to_string()))
    }

    pub fn auth_remove(&self, name: &str) -> Result<()> {
        if self.conn.execute("DELETE FROM auth_profiles WHERE name = ?1", [name])? == 0 {
            return Err(Error::NotFound(format!("auth profile {name:?}")));
        }
        self.auth_clear_handling(name)?;
        self.meta_set(&totp_used_key(name), None)?;
        self.meta_set(&crate::browser_login::lock_key(name), None)?;
        self.bump_settings_version()
    }
}

/// The text that stands in for a secret value: `«auth:PROFILE:KIND»`, where KIND is
/// `header:NAME`, `query:NAME`, `cookie:NAME`, `token`, `password`, `password:form` or `password:json`.
pub fn placeholder(profile: &str, kind: &str) -> String {
    format!("«auth:{profile}:{kind}»")
}

pub(crate) const MARK: &str = "«auth:";

/// Whether a parameter's value is a query key's placeholder, which is not for attacking.
pub(crate) fn is_query_key_placeholder(value: &str) -> bool {
    value.starts_with(MARK) && value.contains(":query:")
}

#[derive(Clone)]
struct VaultEntry {
    value: String,
    /// Lowercase header the value may be filled into; None for a value that may go
    /// anywhere in a request to one of `origins` (a password, a macro value).
    header: Option<String>,
    /// Origins an anywhere value may be sent to.
    origins: Vec<String>,
    /// A query key: filled only into the request line, for `origins`.
    request_line: bool,
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
    /// Placeholders whose value is a one-time code, worked out as a request is resolved.
    totp: HashMap<String, crate::totp::Generator>,
    /// When each of them last went out in a request.
    totp_sent: HashMap<String, TotpUse>,
}

/// A one-time code as it went out: its time step, and how far into its period that was.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct TotpUse {
    pub step: u64,
    pub into: Duration,
    pub left: Duration,
}

impl TotpUse {
    pub(crate) fn now(g: &crate::totp::Generator) -> TotpUse {
        let (into, left) = g.window();
        TotpUse { step: g.step(crate::totp::unix_now()), into, left }
    }
}

/// The placeholder kind of a profile's current one-time code.
pub(crate) const TOTP_KIND: &str = "totp";
/// How the placeholder kinds of what a browser login types into other password fields start
/// (the step's number follows, then `:form` or `:json`).
const TYPED_KIND: &str = "typed:";

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
        let entry = VaultEntry {
            value: value.to_string(),
            header: header.map(|h| h.trim().to_ascii_lowercase()),
            origins,
            request_line: false,
        };
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
            let entry = VaultEntry { value, header: None, origins: var.origins.clone(), request_line: false };
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
        for q in &p.query_keys {
            let entry = VaultEntry {
                value: encode(&q.value, Enc::Form),
                header: None,
                origins: q.origins.iter().filter_map(|o| Target::from_url(o).ok()).map(|t| t.origin()).collect(),
                request_line: true,
            };
            self.0.lock().unwrap().entries.insert(placeholder(&p.name, &format!("query:{}", q.name)), entry);
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
            inner.sign_marks.extend(signer.marks(profile));
            inner.signers.push(crate::sign::Loaded::new(profile, signer.clone()));
        }
    }

    /// Whether a signer fills a placeholder in the head of `raw`, so resolving it may block.
    pub(crate) fn signs(&self, raw: &[u8]) -> bool {
        if find(raw, MARK.as_bytes()).is_none() {
            return false;
        }
        let head = split_head_body(raw).0;
        self.0.lock().unwrap().sign_marks.iter().any(|m| find(head, m.as_bytes()).is_some())
    }

    /// Registers a password, encoded for each login body type, for the login's origins (and
    /// the origins of macro steps that use it, which stay allowed).
    pub(crate) fn put_password(&self, p: &AuthProfile, password: &str) {
        let login = p.login_origins();
        for enc in [Enc::Raw, Enc::Form, Enc::Json] {
            let ph = placeholder(&p.name, enc.password_kind());
            let mut origins = login.clone();
            if let Some(old) = self.0.lock().unwrap().entries.get(&ph) {
                origins.extend(old.origins.iter().filter(|o| !login.contains(o)).cloned());
            }
            self.put(ph, &encode(password, enc), None, origins);
        }
    }

    /// Registers a profile's one-time code for the login's origins (and those already allowed).
    /// The code is worked out each time a request that carries its placeholder is resolved.
    pub(crate) fn put_totp(&self, p: &AuthProfile, generator: crate::totp::Generator) {
        let ph = placeholder(&p.name, TOTP_KIND);
        let mut origins = p.login_origins();
        let mut inner = self.0.lock().unwrap();
        if let Some(old) = inner.entries.get(&ph) {
            let more: Vec<String> = old.origins.iter().filter(|o| !origins.contains(o)).cloned().collect();
            origins.extend(more);
        }
        let entry = VaultEntry { value: generator.now(), header: None, origins, request_line: false };
        inner.entries.insert(ph.clone(), entry);
        inner.totp.insert(ph, generator);
    }

    /// Registers what a browser login types into password fields other than the password's
    /// (kept, masked, in its steps), each for the site it is typed on, so the request that
    /// carries one is recorded with a placeholder too ([`Vault::conceal`]).
    pub(crate) fn put_typed(&self, p: &AuthProfile) {
        for (n, value, page) in p.browser.iter().flat_map(|b| b.typed_secrets()) {
            let origins: Vec<String> = Target::from_url(page).ok().map(|t| t.origin()).into_iter().collect();
            for (enc, suffix) in [(Enc::Raw, ""), (Enc::Form, ":form"), (Enc::Json, ":json")] {
                let ph = placeholder(&p.name, &format!("{TYPED_KIND}{n}{suffix}"));
                self.put(ph, &encode(value, enc), None, origins.clone());
            }
        }
    }

    /// Notes that a profile's one-time code went to the site some other way than in a request
    /// resolved here (typed into a page by the login browser).
    pub(crate) fn note_totp_use(&self, profile: &str, used: TotpUse) {
        self.0.lock().unwrap().totp_sent.insert(placeholder(profile, TOTP_KIND), used);
    }

    /// When a profile's one-time code last went out, forgetting it.
    pub(crate) fn take_totp_use(&self, profile: &str) -> Option<TotpUse> {
        self.0.lock().unwrap().totp_sent.remove(&placeholder(profile, TOTP_KIND))
    }

    /// The placeholders for the secrets of `profile` that `request` holds in the clear, put in
    /// their place: its password and what else its login types into password fields (as they
    /// stand in a form, in JSON, or as they are) and its current one-time code, in the request
    /// line, the header values and the body. A request the login browser sends is
    /// recorded like one brainproxy builds, with no secret in it; [`Vault::resolve`] puts the
    /// same bytes back on the wire (but for a code whose period has turned over since it was
    /// typed: the current one goes). Only in a request to an origin the value may go to anyway
    /// (the sites it was typed on): this never widens where a placeholder is filled in, or bytes
    /// that happen to match on some other site would open that site to the password.
    pub(crate) fn conceal(&self, profile: &str, request: &[u8], origin: &str) -> Vec<u8> {
        let inner = self.0.lock().unwrap();
        let totp = placeholder(profile, TOTP_KIND);
        let goes_here = |ph: &String| inner.entries.get(ph).is_some_and(|e| e.origins.iter().any(|o| o == origin));
        // The password in each form it takes, what else was typed into a password field, and
        // the current code. Longest first, so a value that holds another is replaced whole. A
        // value too short to be told from ordinary text stays.
        let typed = placeholder(profile, TYPED_KIND);
        let typed = typed.trim_end_matches('\u{bb}');
        let mut secrets: Vec<(String, String)> = inner
            .entries
            .iter()
            .filter(|(ph, e)| e.header.is_none() && !e.request_line && !inner.totp.contains_key(*ph))
            .filter(|(ph, _)| {
                [Enc::Form, Enc::Json, Enc::Raw].iter().any(|enc| **ph == placeholder(profile, enc.password_kind()))
                    || ph.starts_with(typed)
            })
            .filter(|(ph, _)| goes_here(ph))
            .map(|(ph, e)| (ph.clone(), e.value.clone()))
            .collect();
        if let Some(g) = inner.totp.get(&totp).filter(|_| goes_here(&totp)) {
            // The code the page was given: the current one, or the one before or the one noted
            // as typed, whose period may have turned over between the typing and the sending.
            let now = g.step(crate::totp::unix_now());
            let typed = inner.totp_sent.get(&totp).map(|u| u.step);
            for step in [Some(now), now.checked_sub(1), typed].into_iter().flatten() {
                let code = g.code_for_step(step);
                if !secrets.iter().any(|(ph, v)| *ph == totp && *v == code) {
                    secrets.push((totp.clone(), code));
                }
            }
        }
        secrets.retain(|(_, v)| v.len() >= 4);
        // (Of two forms that read the same, the plain one's placeholder.)
        secrets.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.len().cmp(&b.0.len())).then_with(|| a.0.cmp(&b.0)));
        let (head, body) = split_head_body(request);
        let mut used = false;
        let digit = |b: Option<&u8>| b.is_some_and(u8::is_ascii_digit);
        // `in_head`: a value with a line break in it can't stand in a header (see [`fill`]).
        let mut swap = |part: &[u8], in_head: bool| -> Vec<u8> {
            // The text still to search, and the placeholders put in so far (not searched again).
            let mut parts: Vec<(Vec<u8>, bool)> = vec![(part.to_vec(), false)];
            for (ph, value) in secrets.iter().filter(|(_, v)| !(in_head && v.contains(['\r', '\n', '\0']))) {
                let code = *ph == totp;
                let mut next = Vec::with_capacity(parts.len());
                for (bytes, placed) in parts {
                    if placed {
                        next.push((bytes, true));
                        continue;
                    }
                    let (mut start, mut from) = (0, 0);
                    while let Some(i) = find(&bytes[from..], value.as_bytes()).map(|i| i + from) {
                        let end = i + value.len();
                        // A code is a number of its own, not digits inside a longer one.
                        if code && (digit(i.checked_sub(1).and_then(|j| bytes.get(j))) || digit(bytes.get(end))) {
                            from = i + 1;
                            continue;
                        }
                        next.push((bytes[start..i].to_vec(), false));
                        next.push((ph.as_bytes().to_vec(), true));
                        (start, from) = (end, end);
                        used = true;
                    }
                    next.push((bytes[start..].to_vec(), false));
                }
                parts = next;
            }
            parts.into_iter().flat_map(|(b, _)| b).collect()
        };
        // The request line, each header's value (not the ones that frame the request), the body.
        let mut out = Vec::with_capacity(request.len());
        for (i, line) in head.split_inclusive(|&b| b == b'\n').enumerate() {
            let colon = line.iter().position(|&b| b == b':').filter(|_| i > 0);
            let name = colon.map(|c| String::from_utf8_lossy(&line[..c]).trim().to_ascii_lowercase());
            match (colon, name.as_deref()) {
                (_, Some("host" | "content-length" | "transfer-encoding")) => out.extend_from_slice(line),
                (Some(c), _) => {
                    out.extend_from_slice(&line[..=c]);
                    out.extend(swap(&line[c + 1..], true));
                }
                (None, _) => out.extend(swap(line, true)),
            }
        }
        let new_body = swap(body, false);
        if !used {
            return request.to_vec();
        }
        // The body's length on record is the placeholder's; `resolve` sets the real one again.
        let changed = new_body != body;
        out.extend(new_body);
        if changed {
            out = RawRequest::from_bytes(out).update_content_length().into_bytes();
        }
        out
    }

    /// The request with placeholders replaced by their values. A header value is only
    /// filled into its own header, and a password or macro value only into requests to
    /// the origins it belongs to, so a placeholder can't be moved somewhere that
    /// reflects it back; a query key goes only into the request line to its origins. Fails
    /// on a placeholder left over (profile removed, never logged in, password variable
    /// unset, or the placeholder moved out of its header). Signers
    /// run last, over the request as it will be sent; their placeholders only count in the head.
    pub fn resolve<'a>(&self, raw: &'a [u8], target: &Target) -> Result<Cow<'a, [u8]>> {
        if find(raw, MARK.as_bytes()).is_none() {
            return Ok(Cow::Borrowed(raw));
        }
        let mut inner = self.0.lock().unwrap();
        // One-time codes are worked out now: a request re-sent from history gets a current one.
        let codes: Vec<(String, crate::totp::Generator)> = inner
            .totp
            .iter()
            .filter(|(ph, _)| find(raw, ph.as_bytes()).is_some())
            .map(|(p, g)| (p.clone(), g.clone()))
            .collect();
        for (ph, g) in codes {
            if let Some(e) = inner.entries.get_mut(&ph) {
                e.value = g.now();
            }
            inner.totp_sent.insert(ph, TotpUse::now(&g));
        }
        let inner = inner;
        let origin = target.origin();
        let to_origin = |e: &VaultEntry| e.header.is_none() && e.origins.iter().any(|o| o == &origin);
        let anywhere = |e: &VaultEntry| !e.request_line && to_origin(e);
        let (head, body) = split_head_body(raw);
        let mut out = Vec::with_capacity(raw.len());
        for (i, line) in head.split_inclusive(|&b| b == b'\n').enumerate() {
            let name = line
                .iter()
                .position(|&b| b == b':')
                .map(|i| String::from_utf8_lossy(&line[..i]).trim().to_ascii_lowercase());
            let allowed = |e: &VaultEntry| {
                anywhere(e) || (e.header.is_some() && e.header == name) || (i == 0 && e.request_line && to_origin(e))
            };
            out.extend(fill(&inner.entries, &inner.sign_marks, line, true, allowed)?);
        }
        let new_body = fill(&inner.entries, &Default::default(), body, false, anywhere)?;
        let body_changed = new_body != body;
        out.extend(new_body);
        if body_changed {
            out = RawRequest::from_bytes(out).update_content_length().into_bytes();
        }
        if find(&out, MARK.as_bytes()).is_some() {
            // Every generated header first: a signer may cover another's.
            // Signing can take a while (a script, an RSA key), so not with every other send waiting.
            let (signers, marks) = (inner.signers.clone(), inner.sign_marks.clone());
            drop(inner);
            let stamp = crate::sign::Stamp::new()?;
            for signer in &signers {
                out = signer.set_headers(out, target, &stamp)?;
            }
            for signer in &signers {
                out = signer.sign(out, target, &stamp)?;
            }
            // A signer replaced since the placeholder was written leaves it unfilled.
            let head = split_head_body(&out).0;
            if let Some(mark) = marks.iter().find(|m| find(head, m.as_bytes()).is_some()) {
                return Err(Error::InvalidInput(format!("no signer fills {mark} in this request")));
            }
        }
        Ok(Cow::Owned(out))
    }
}

/// `text` with each placeholder replaced by its value, where `allowed` lets it go.
/// A per-run macro placeholder no longer kept falls back to the variable's latest value.
/// Placeholders in `later` stay for the signers. In the head (`head`), a value holding a CR, LF
/// or NUL is refused: a token or cookie learned from a reply, or a macro's value, would otherwise
/// start another header (a Host, say) on every request it goes into.
fn fill(
    entries: &HashMap<String, VaultEntry>,
    later: &std::collections::HashSet<String>,
    text: &[u8],
    head: bool,
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
            (Some(e), Some(j)) if head && e.value.contains(['\r', '\n', '\0']) => {
                let ph = String::from_utf8_lossy(&rest[..j]).into_owned();
                return Err(Error::InvalidInput(format!(
                    "the value for {ph} holds a line break or NUL, which would start another header: not \
                     sent (log in again, or check what the profile learns its values from)"
                )));
            }
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
            if let Some(g) = p.totp.as_ref().and_then(|t| t.generator().ok()) {
                vault.put_totp(&p, g);
            }
            vault.put_typed(&p);
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

/// What [`AuthSession::send_as_watched`] reports while it sends.
pub enum Attempt<'a> {
    /// This request is about to go out.
    Sending(&'a RawRequest),
    /// The request that went out last is answered (before any re-login it leads to).
    Answered(&'a Exchange),
}

/// A live session shared by every request of a command run.
pub struct AuthSession {
    pub profile: AuthProfile,
    re: Compiled,
    pub(crate) client: Client,
    pub(crate) project: PathBuf,
    pub(crate) state: Mutex<SessionState>,
    /// Bumped on every login, so concurrent workers re-login only once.
    generation: AtomicU64,
    relogins: AtomicU32,
    last_login: Mutex<Option<Instant>>,
    pub(crate) login_lock: tokio::sync::Mutex<()>,
    /// Macros and session rules (see [`crate::session`]).
    pub(crate) handling: crate::session::Runtime,
    /// Its own requests keep no content in history (`--no-store`).
    pub(crate) no_store: std::sync::atomic::AtomicBool,
    /// The time step of the one-time code this session sent last.
    totp_step: Mutex<Option<u64>>,
}

impl std::fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession").field("profile", &self.profile.name).finish_non_exhaustive()
    }
}

impl AuthSession {
    /// The client its requests go out with (logins, checks, macros, and what it sends for a tool).
    pub fn client(&self) -> &Client {
        &self.client
    }

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
            no_store: Default::default(),
            totp_step: Mutex::new(None),
        })
    }

    pub fn state(&self) -> SessionState {
        self.state.lock().unwrap().clone()
    }

    /// The session's own requests (login, CSRF page, check, macro steps, token requests)
    /// keep no content in history, as the command's do with `--no-store`.
    pub fn keep_no_content(&self) {
        self.no_store.store(true, Ordering::SeqCst);
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub(crate) fn bump_generation(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Whether the last login or token request was within the profile's re-login interval.
    pub(crate) fn logged_in_within_interval(&self) -> bool {
        let interval = Duration::from_secs(self.profile.relogin_interval_secs);
        self.last_login.lock().unwrap().is_some_and(|t| t.elapsed() < interval)
    }

    pub(crate) fn mark_login_time(&self) {
        *self.last_login.lock().unwrap() = Some(Instant::now());
    }

    /// Persists the current cookies/token so the next command can reuse them. An OAuth
    /// refresh token stays in memory unless the profile stores its secrets.
    pub fn save(&self) -> Result<()> {
        Store::open(&self.project)?.auth_save_state(&self.profile.name, &self.persisted_state())
    }

    /// The state as it goes in the project.
    fn persisted_state(&self) -> SessionState {
        let mut st = self.state();
        if !self.profile.oauth.as_ref().is_some_and(|o| o.store_secrets) {
            st.refresh_token = None;
        }
        st
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
        self.apply_keeping(raw, keep, &[])
    }

    /// [`AuthSession::apply`], also leaving the headers named in `keep_headers` (any case)
    /// as the caller set them: the token header and the profile's headers aren't put on
    /// over them (e.g. a scan rule's forged token in `Authorization`).
    pub fn apply_keeping(&self, raw: &[u8], keep: &[&str], keep_headers: &[&str]) -> Vec<u8> {
        let kept = |name: &str| keep_headers.iter().any(|h| h.eq_ignore_ascii_case(name));
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
                if !kept(k.trim()) {
                    req = req.set_header(k.trim(), v.trim());
                }
            }
        }
        for (k, _) in self.profile.headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("cookie") && !kept(k)) {
            req = req.set_header(k, &ph(&format!("header:{k}")));
        }
        req.into_bytes()
    }

    /// [`AuthSession::apply`] plus the query keys for `target`'s origin, as placeholders.
    pub fn apply_to(&self, raw: &[u8], keep: &[&str], target: &Target) -> Vec<u8> {
        self.apply_to_keeping(raw, keep, &[], target)
    }

    /// [`AuthSession::apply_to`] with [`AuthSession::apply_keeping`]'s `keep_headers`.
    pub fn apply_to_keeping(&self, raw: &[u8], keep: &[&str], keep_headers: &[&str], target: &Target) -> Vec<u8> {
        let mut out = self.apply_keeping(raw, keep, keep_headers);
        for q in &self.profile.query_keys {
            if q.origins.iter().any(|o| crate::sign::same_origin(o, target)) {
                let ph = placeholder(&self.profile.name, &format!("query:{}", q.name));
                out = crate::sign::set_query(&out, &q.name, |_| ph.clone());
            }
        }
        out
    }

    /// Fetches the profile's check URL with the session applied and reports
    /// whether it still looks logged in. None when the profile has no check URL.
    pub async fn check(&self) -> Result<Option<CheckResult>> {
        let Some(url) = &self.profile.check_url else { return Ok(None) };
        let (req, target) = RawRequest::build("GET", url, &[], b"")?;
        let (history_id, ex) =
            self.send_own(&RawRequest::from_bytes(self.apply_to(req.as_bytes(), &[], &target)), &target).await;
        let ex = ex?;
        self.observe(&ex.response);
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
        // A browser login's page is wherever the recording began or first typed: only a
        // redirect to that very path counts (its path may be a prefix of half the site).
        if let (Some(loc), Some(b)) = (head.header("location"), &self.profile.browser) {
            let path = |u: &str| {
                let u = u.split(['?', '#']).next().unwrap_or(u);
                u.split_once("://").map_or(u, |(_, rest)| rest.find('/').map_or("/", |i| &rest[i..])).to_string()
            };
            let login_path = path(b.login_page());
            if login_path.len() > 1 && path(loc) == login_path {
                return true;
            }
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
        self.send_as_watched(tool, req, target, |_| Ok(())).await
    }

    /// [`AuthSession::send_as`], telling `watch` about each request just before it goes out
    /// (with the session applied, as [`Client::recorded_request`] records it) and as soon as
    /// it is answered, before a lost session is renewed and the request sent again. An error
    /// from `watch` stops the send there.
    pub async fn send_as_watched(
        &self,
        tool: crate::session::Tool,
        req: &RawRequest,
        target: &Target,
        mut watch: impl FnMut(Attempt<'_>) -> Result<()>,
    ) -> Result<Exchange> {
        let prepared = self.prepare(tool, target, req.as_bytes(), &[], &[]).await;
        let first = RawRequest::from_bytes(prepared.request.clone());
        watch(Attempt::Sending(&first))?;
        let ex = self.client.send(&first, target).await?;
        watch(Attempt::Answered(&ex))?;
        if self.after_response(&prepared, &ex.response).await {
            let again = RawRequest::from_bytes(self.prepare(tool, target, req.as_bytes(), &[], &[]).await.request);
            watch(Attempt::Sending(&again))?;
            let ex = self.client.send(&again, target).await?;
            watch(Attempt::Answered(&ex))?;
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
        if p.oauth.is_some() {
            return self.oauth_login().await;
        }
        if p.login_url.is_none() && p.browser.is_none() {
            return Ok(LoginResult {
                success: true,
                status: None,
                cookies: vec![],
                token: false,
                reason: "static headers only".into(),
                history_ids: vec![],
            });
        }
        let totp = self.login_totp()?;
        // One process at a time, across commands: a code is sent once, a passkey's count used once.
        let _lock = match totp.is_some() || (p.browser.is_some() && !p.passkeys.is_empty()) {
            true => Some(crate::browser_login::LoginLock::acquire(&self.project, &p.name).await?),
            false => None,
        };
        let Some(totp) = totp else { return self.login_once().await };
        // A site may take each code once: one this profile already sent isn't sent again.
        self.await_unused_code(&totp).await;
        let vault = self.client.options().guard.as_ref().map(|g| &g.vault);
        let first = self.login_once().await?;
        let used = vault.and_then(|v| v.take_totp_use(&p.name));
        if let Some(u) = used {
            self.note_code_used(u.step);
        }
        // A code is refused for its timing alone when its period ended on the way, or the
        // site's clock is a little off ours right at a period's edge: then, and only then, the
        // login is tried once more (a wrong password isn't sent twice).
        let Some(wait) = used.filter(|_| !first.success).and_then(|u| retry_code_after(&totp, u)) else {
            return Ok(first);
        };
        eprintln!(
            "brainproxy: {}: the one-time code went out as its {}s period turned over; logging in once more",
            p.name, totp.period
        );
        tokio::time::sleep(wait).await;
        let mut second = self.login_once().await?;
        if let Some(u) = vault.and_then(|v| v.take_totp_use(&p.name)) {
            self.note_code_used(u.step);
        }
        second.history_ids.splice(0..0, first.history_ids);
        Ok(second)
    }

    /// The profile's code generator when its login sends a one-time code, registered with the
    /// vault. An error when the login needs a code and the profile has no secret to make it.
    fn login_totp(&self) -> Result<Option<crate::totp::Generator>> {
        let p = &self.profile;
        if !p.login_uses_totp() {
            return Ok(None);
        }
        let totp = p.totp.as_ref().ok_or_else(|| {
            Error::InvalidInput(format!(
                "the login sends a one-time code ({{{{totp}}}}) but profile {} has no TOTP secret: \
                 auth add {} ... --totp-secret-env VAR",
                p.name, p.name
            ))
        })?;
        let g = totp.generator()?;
        if let Some(guard) = &self.client.options().guard {
            guard.vault.put_totp(p, g.clone());
        }
        Ok(Some(g))
    }

    /// Waits for the next code when the current one was already sent, by this command or
    /// (as the project remembers) another.
    async fn await_unused_code(&self, g: &crate::totp::Generator) {
        let stored = Store::open(&self.project)
            .and_then(|s| s.meta_get(&totp_used_key(&self.profile.name)))
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u64>().ok());
        let last = (*self.totp_step.lock().unwrap()).max(stored);
        if last.is_some_and(|l| g.step(crate::totp::unix_now()) <= l) {
            let (_, left) = g.window();
            // A step far in the future isn't one of ours (a clock set back): no more than a period.
            let wait = left.min(Duration::from_secs(g.period)) + Duration::from_millis(250);
            eprintln!(
                "brainproxy: {}: the current one-time code was already used; waiting {:.0}s for the next",
                self.profile.name,
                wait.as_secs_f64().ceil()
            );
            tokio::time::sleep(wait).await;
        }
    }

    fn note_code_used(&self, step: u64) {
        *self.totp_step.lock().unwrap() = Some(step);
        if let Ok(store) = Store::open(&self.project) {
            let _ = store.meta_set(&totp_used_key(&self.profile.name), Some(&step.to_string()));
        }
    }

    /// One login attempt: the login request (and its follow-up steps), or the recorded
    /// browser steps.
    async fn login_once(&self) -> Result<LoginResult> {
        let p = &self.profile;
        *self.last_login.lock().unwrap() = Some(Instant::now());
        // Start from a clean jar so stale session cookies don't leak into the login.
        {
            let mut st = self.state.lock().unwrap();
            st.cookies.clear();
            st.token = None;
            st.logged_in = false;
        }
        let mut history = Vec::new();
        let password = p.password.as_ref().map(Secret::resolve).transpose()?.unwrap_or_default();
        if let Some(g) = &self.client.options().guard {
            g.vault.put_password(p, &password);
        }
        if p.browser.is_some() {
            if let Some(g) = &self.client.options().guard {
                g.vault.put_typed(p);
            }
            let (text, status) = self.browser_login(&password).await?;
            return self.verify_login(text, status, history).await;
        }
        let Some(login_url) = &p.login_url else {
            return Err(Error::InvalidInput(format!("profile {} has no login", p.name)));
        };
        let username = p.username.clone().unwrap_or_default();

        let mut csrf = String::new();
        if let (Some(url), Some(re)) = (&p.csrf_url, &self.re.csrf) {
            let text = self.fetch_text(url, &mut history).await?;
            csrf = token_in(re, &text)
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
                let body = with_code(&body, &p.name);
                RawRequest::build(&p.login_method, login_url, &headers, body.as_bytes())?.0
            }
        };

        // The token may come with any response of the login: the first one (often a
        // redirect) or one after it. When several have it, the last one wins (as before,
        // when only the final page was searched).
        let mut token = None;
        let mut find_token = |texts: &[String]| {
            if let Some(re) = &self.re.token {
                for text in texts {
                    if let Some(m) = re.captures(text).and_then(|c| c.get(1).or_else(|| c.get(0))) {
                        token = Some(m.as_str().to_string());
                    }
                }
            }
        };
        let (mut ex, mut texts) = self.send_following(&req, &target, login_url, &mut history).await?;
        find_token(&texts);
        // What follows the login request: a one-time code posted to its own form, say.
        for (i, step) in p.login_steps.iter().enumerate() {
            let mut csrf = String::new();
            if let Some(re) = &step.csrf_regex {
                let re = Regex::new(re).map_err(|e| Error::InvalidInput(e.to_string()))?;
                let text = match &step.csrf_url {
                    Some(url) => self.fetch_text(url, &mut history).await?,
                    None => texts.join("\n"),
                };
                csrf = token_in(&re, &text).ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "login step {}: its token wasn't found (did the request before it fail? see history)",
                        i + 1
                    ))
                })?;
            }
            let target = Target::from_url(&step.url)?;
            let text = fill_template(&step.request, &username, &p.name, &csrf);
            let req = RawRequest::from_bytes(text.into_bytes()).normalize_line_endings().update_content_length();
            (ex, texts) = self.send_following(&req, &target, &step.url, &mut history).await?;
            find_token(&texts);
        }
        if self.re.token.is_some() {
            self.state.lock().unwrap().token = token;
        }
        let status = parse_response_head(&ex.response).ok().map(|h| h.status);
        self.verify_login(response_text(&ex.response), status, history).await
    }

    /// Fetches a page of the login (the CSRF page) with the session applied; its text.
    async fn fetch_text(&self, url: &str, history: &mut Vec<Option<i64>>) -> Result<String> {
        let (req, target) = RawRequest::build("GET", url, &[], b"")?;
        let (id, ex) =
            self.send_own(&RawRequest::from_bytes(self.apply_to(req.as_bytes(), &[], &target)), &target).await;
        history.push(id);
        let ex = ex?;
        self.observe(&ex.response);
        Ok(response_text(&ex.response))
    }

    /// Sends one of the login's requests to `url`, following redirects (with cookies) like a
    /// browser would. The last exchange, and the text of every response on the way.
    async fn send_following(
        &self,
        req: &RawRequest,
        target: &Target,
        url: &str,
        history: &mut Vec<Option<i64>>,
    ) -> Result<(Exchange, Vec<String>)> {
        let (id, ex) = self.send_own(&RawRequest::from_bytes(self.apply_to(req.as_bytes(), &[], target)), target).await;
        history.push(id);
        let mut ex = ex?;
        self.observe(&ex.response);
        let mut texts = vec![response_text(&ex.response)];
        let mut current = url::Url::parse(url).map_err(|e| Error::InvalidInput(e.to_string()))?;
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
            let (id, next) = self.send_own(&RawRequest::from_bytes(self.apply_to(r.as_bytes(), &[], &t)), &t).await;
            history.push(id);
            ex = next?;
            self.observe(&ex.response);
            texts.push(response_text(&ex.response));
        }
        Ok((ex, texts))
    }

    /// Judges a login by what came of it: the check URL if the profile has one, else the page
    /// the login ended on (`final_text`, with its status). Stores the session.
    async fn verify_login(
        &self,
        final_text: String,
        final_status: Option<u16>,
        mut history: Vec<Option<i64>>,
    ) -> Result<LoginResult> {
        let p = &self.profile;
        let (verify_text, status) = match &p.check_url {
            Some(u) => {
                let (r, t) = RawRequest::build("GET", u, &[], b"")?;
                let (id, cex) = self.send_own(&RawRequest::from_bytes(self.apply_to(r.as_bytes(), &[], &t)), &t).await;
                history.push(id);
                let cex = cex?;
                self.observe(&cex.response);
                let logged_out = self.is_logged_out(&cex.response);
                let text = response_text(&cex.response);
                (if logged_out { None } else { Some(text) }, parse_response_head(&cex.response).ok().map(|h| h.status))
            }
            None => (Some(final_text), final_status),
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

    /// Sends one of the session's own requests (login, CSRF page, check, macro step) with
    /// its row (source auth) written before it goes out and completed after, as in
    /// [`crate::sent`]. The row id is None only when it couldn't be written; then nothing
    /// is sent and the result is that error.
    pub(crate) async fn send_own(&self, req: &RawRequest, target: &Target) -> (Option<i64>, Result<Exchange>) {
        self.send_recorded(req, target, None).await
    }

    /// [`AuthSession::send_own`], keeping no content when `omit` (its reason) is given.
    pub(crate) async fn send_recorded(
        &self,
        req: &RawRequest,
        target: &Target,
        omit: Option<&'static str>,
    ) -> (Option<i64>, Result<Exchange>) {
        let opened = crate::sent::SentLog::open(&self.project, "auth", self.no_store.load(Ordering::SeqCst))
            .map(|log| log.sent_by(&self.client));
        let mut log = match opened {
            Ok(log) => match omit {
                Some(reason) => log.without_content(reason),
                None => log,
            },
            Err(e) => return (None, Err(e)),
        };
        let recorded = match self.client.recorded_request(req, target) {
            Ok(r) => r,
            Err(e) => return (None, Err(e)),
        };
        let id = match log.pending(target, &recorded) {
            Ok(id) => id,
            Err(e) => return (None, Err(e)),
        };
        let result = self.client.send(req, target).await;
        let done = match &result {
            Ok(ex) => log.answered(id, ex).and_then(|_| crate::scan::passive::scan_late(&mut log.store, id).map(drop)),
            Err(e) => log.failed(id, target, &recorded, &e.to_string()),
        };
        if let Err(e) = done {
            eprintln!("brainproxy: history #{id} not completed: {e}");
        }
        (Some(id), result)
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
    let fill = |text: &str, enc: Enc| {
        with_code(&substitute(text, user, &placeholder(profile, enc.password_kind()), csrf, enc), profile)
    };
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

/// `{{totp}}` as the placeholder of the profile's one-time code, which the vault works out
/// as the request goes (digits: the same in a form, in JSON, and as they are).
fn with_code(text: &str, profile: &str) -> String {
    text.replace("{{totp}}", &placeholder(profile, TOTP_KIND))
}

/// A request template with the value of an Authorization header it holds as recorded
/// hidden, for display (one that is a placeholder stays).
fn mask_authorization(request: &str) -> String {
    let head_end = request.find("\r\n\r\n").or_else(|| request.find("\n\n")).unwrap_or(request.len());
    let (head, rest) = request.split_at(head_end);
    let lines: Vec<String> = head
        .split_inclusive('\n')
        .map(|line| match line.split_once(':') {
            Some((name, value)) if name.trim().eq_ignore_ascii_case("authorization") && !value.contains("{{") => {
                let end = &value[value.trim_end_matches(['\r', '\n']).len()..];
                format!("{name}: ********{end}")
            }
            _ => line.to_string(),
        })
        .collect();
    format!("{}{rest}", lines.concat())
}

/// The token a login page hands out, as `re` (group 1, else the match) reads it.
fn token_in(re: &Regex, text: &str) -> Option<String> {
    re.captures(text)
        .and_then(|c| c.get(1).or_else(|| c.get(0)))
        .map(|m| crate::scan::passive::util::decode_entities(m.as_str()))
}

fn totp_used_key(profile: &str) -> String {
    format!("auth.totp_used.{profile}")
}

/// How long to wait before a refused login is tried again with a one-time code, if the code's
/// timing may be why: it went out in its period's last moments, so the period may have turned
/// over on the way (wait for the next code), or in its first (the site's clock may be behind:
/// wait a little, the same code is then current there too).
fn retry_code_after(g: &crate::totp::Generator, used: TotpUse) -> Option<Duration> {
    let edge = Duration::from_secs(5).min(Duration::from_secs(g.period) / 4);
    let same_period = g.step(crate::totp::unix_now()) == used.step;
    let (into, left) = g.window();
    if used.left <= edge {
        // The next code: now if its period has begun, else when it does.
        Some(if same_period { left + Duration::from_millis(250) } else { Duration::ZERO })
    } else if used.into <= edge && same_period {
        Some(edge.saturating_sub(into))
    } else {
        // Sent well inside its period: the code was good when it arrived, however long the
        // login then took. Something else is wrong, and the login isn't sent twice.
        None
    }
}

pub(crate) fn response_text(response: &[u8]) -> String {
    let Ok(head) = parse_response_head(response) else { return String::from_utf8_lossy(response).into_owned() };
    let (h, b) = split_head_body(response);
    let mut s = String::from_utf8_lossy(h).into_owned();
    s.push_str(&String::from_utf8_lossy(&decode_body(&head.headers, b)));
    s
}

pub(crate) fn now_iso() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replaced_signers_placeholder_never_goes_out() {
        let signer = crate::sign::Signer {
            name: "s".into(),
            key: crate::sign::KeySource::Env("UNUSED".into()),
            key_encoding: Default::default(),
            origins: vec!["https://a.test".into()],
            to: crate::sign::Place::Header("X-Sig".into()),
            format: None,
            headers: vec![],
            kind: crate::sign::SignKind::Hmac {
                alg: crate::sign::HmacAlg::Sha256,
                canonical: "{{path}}".into(),
                output: Default::default(),
            },
        };
        let vault = Vault::default();
        vault.put_signers("p", std::slice::from_ref(&signer));
        vault.put_signers("p", &[]);
        let raw = signer.place(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", "p", &[]);
        let target = Target::from_url("https://a.test").unwrap();
        assert!(vault.resolve(&raw, &target).unwrap_err().to_string().contains("no signer fills"));
    }

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

    #[test]
    fn a_refresh_token_is_stored_only_with_the_secrets() {
        for store_secrets in [false, true] {
            let name = format!("oauth-store-{store_secrets}");
            let oauth = crate::oauth::OAuth {
                flow: crate::oauth::Flow::ClientCredentials,
                token_url: "https://a.test/token".into(),
                client_id: "c".into(),
                client_secret: Some(Secret::Env("UNUSED".into())),
                client_auth: Default::default(),
                scope: None,
                audience: None,
                params: vec![],
                refresh_token: None,
                authorize_url: None,
                redirect_port: None,
                store_secrets,
            };
            let s = session(AuthProfile { name: name.clone(), oauth: Some(oauth), ..Default::default() });
            let store = Store::open(&s.project).unwrap();
            store.auth_save_profile(&s.profile).unwrap();
            {
                let mut st = s.state.lock().unwrap();
                st.token = Some("ACCESS".into());
                st.refresh_token = Some("REFRESH".into());
            }
            s.save().unwrap();
            let (_, stored) = store.auth_profile(&name).unwrap();
            assert_eq!(stored.token.as_deref(), Some("ACCESS"));
            assert_eq!(stored.refresh_token.is_some(), store_secrets);
            // The command itself keeps using it either way.
            assert_eq!(s.state().refresh_token.as_deref(), Some("REFRESH"));
        }
    }

    fn vault_of(s: &AuthSession) -> &Vault {
        &s.client.options().guard.as_ref().unwrap().vault
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_script_signing_holds_up_no_other_task() {
        crate::sign_script::tests::use_test_runner();
        let script = "/^(a+)+$/.test('a'.repeat(40) + 'b');";
        let dir = std::env::temp_dir().join(format!("bp-auth-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("pre.js");
        std::fs::write(&file, script).unwrap();
        let signer = crate::sign::Signer {
            name: "script".into(),
            key: crate::sign::KeySource::None,
            key_encoding: Default::default(),
            origins: vec!["https://a.test".into()],
            to: crate::sign::Place::Header(crate::sign::SCRIPT_MARK_HEADER.into()),
            format: None,
            headers: vec![],
            kind: crate::sign::SignKind::Script {
                file,
                sha256: crate::fetch::sha256_hex(script.as_bytes()),
                vars: vec![],
            },
        };
        let s = session(AuthProfile { name: "p".into(), ..Default::default() });
        vault_of(&s).put_signers("p", std::slice::from_ref(&signer));
        let raw = signer.place(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", "p", &[]);
        let ticks = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let target = Target::from_url("https://a.test").unwrap();
        let e = s.client.fill_auth(&raw, &target).await.unwrap_err().to_string();
        ticker.abort();
        assert!(e.contains("time limit"), "{e}");
        // The only worker thread kept ticking while the script ran out its five seconds.
        assert!(ticks.load(std::sync::atomic::Ordering::SeqCst) > 100, "{ticks:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn wire(s: &AuthSession, req: &[u8]) -> Result<String> {
        let target = Target::from_url("https://a.test").unwrap();
        Ok(String::from_utf8(vault_of(s).resolve(req, &target)?.into_owned()).unwrap())
    }

    fn totp_profile(name: &str) -> AuthProfile {
        AuthProfile {
            name: name.into(),
            login_url: Some("https://a.test/login".into()),
            login_body: Some("u={{username}}&p={{password}}&code={{totp}}".into()),
            // "12345678901234567890", the RFC's key.
            totp: Some(crate::totp::Totp::from_input("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", None, None, None).unwrap()),
            ..Default::default()
        }
    }

    #[test]
    fn a_one_time_code_is_worked_out_as_the_request_goes_and_only_for_the_login_origin() {
        let p = totp_profile("otp");
        let s = session(p.clone());
        let g = p.totp.as_ref().unwrap().generator().unwrap();
        vault_of(&s).put_totp(&p, g.clone());
        let body = with_code("code={{totp}}", "otp");
        assert_eq!(body, "code=«auth:otp:totp»");
        let req = format!("POST /login HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let sent = wire(&s, req.as_bytes()).unwrap();
        // The code of now (or of a moment ago, if the period just turned over).
        let now = g.step(crate::totp::unix_now());
        let codes = [g.code_for_step(now), g.code_for_step(now - 1)];
        assert!(codes.iter().any(|c| sent.ends_with(&format!("Content-Length: 11\r\n\r\ncode={c}"))), "{sent}");
        // It went out: the session can tell which code, and when in its period.
        let used = vault_of(&s).take_totp_use("otp").unwrap();
        assert!(used.step == now || used.step == now - 1);
        assert_eq!(vault_of(&s).take_totp_use("otp"), None);
        // Nowhere else, like the password.
        let other = Target::from_url("https://b.test").unwrap();
        assert!(vault_of(&s).resolve(req.as_bytes(), &other).is_err());
        // Its secret is one a report masks; the profile shown hides it.
        assert!(p.secret_values(&SessionState::default()).contains(&"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string()));
        assert!(!serde_json::to_string(&p.redacted()).unwrap().contains("GEZDGNBV"));
        assert!(p.login_uses_totp() && !AuthProfile { login_body: None, ..p }.login_uses_totp());
    }

    #[test]
    fn what_a_login_browser_sends_is_recorded_with_placeholders_and_sent_as_it_was() {
        let p = totp_profile("b");
        let s = session(p.clone());
        let vault = vault_of(&s);
        vault.put_password(&p, "p&ss w0rd");
        let g = p.totp.as_ref().unwrap().generator().unwrap();
        vault.put_totp(&p, g.clone());
        let code = g.now();
        let origin = "https://sso.a.test";
        // Not a site the secrets go to: left as it is, and no placeholder is opened to it.
        let stray = b"GET /p&ss w0rd HTTP/1.1\r\nHost: sso.a.test\r\n\r\n";
        assert_eq!(vault.conceal("b", stray, origin), stray);
        let asked = "POST /x HTTP/1.1\r\nContent-Length: 20\r\n\r\n\u{ab}auth:b:password\u{bb}";
        assert!(vault.resolve(asked.as_bytes(), &Target::from_url(origin).unwrap()).is_err());
        // The page the password was typed on is one.
        for kind in ["password", "password:form", "password:json", TOTP_KIND] {
            vault.allow(&placeholder("b", kind), origin);
        }
        // A form: the password as a form holds it, the code as a number of its own.
        let body = format!("user=al&pass=p%26ss+w0rd&otp={code}&ref=9{code}9");
        let req = format!(
            "POST /login?c={code} HTTP/1.1\r\nHost: sso.a.test\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let kept = String::from_utf8(vault.conceal("b", req.as_bytes(), origin)).unwrap();
        assert!(kept.starts_with("POST /login?c=«auth:b:totp» HTTP/1.1\r\n"), "{kept}");
        assert!(
            kept.ends_with(&format!("user=al&pass=«auth:b:password:form»&otp=«auth:b:totp»&ref=9{code}9")),
            "{kept}"
        );
        assert!(!kept.contains("p%26ss"), "{kept}");
        // The same bytes go out again (unless the code's period turned over just now), to
        // the origin the page sent them to.
        let target = Target::from_url(origin).unwrap();
        let sent = String::from_utf8(vault.resolve(kept.as_bytes(), &target).unwrap().into_owned()).unwrap();
        assert!(sent == req || g.now() != code, "{sent}");
        // A code typed just before its period turned over is still one to hide: the current
        // one goes out in its place.
        let before = g.code_for_step(g.step(crate::totp::unix_now()) - 1);
        let late = format!("POST /login HTTP/1.1\r\nHost: sso.a.test\r\nContent-Length: 12\r\n\r\notp={before}");
        let kept = String::from_utf8(vault.conceal("b", late.as_bytes(), origin)).unwrap();
        assert!(kept.ends_with("otp=\u{ab}auth:b:totp\u{bb}"), "{kept}");
        // JSON, and a request with neither: as it was.
        let json = format!("POST /api HTTP/1.1\r\n\r\n{{\"pw\":\"p&ss w0rd\",\"otp\":\"{code}\"}}");
        let kept = String::from_utf8(vault.conceal("b", json.as_bytes(), origin)).unwrap();
        assert!(kept.contains("\"pw\":\"«auth:b:password»\"") && kept.contains("\"otp\":\"«auth:b:totp»\""), "{kept}");
        let plain = b"GET /home HTTP/1.1\r\nHost: a.test\r\n\r\n";
        assert_eq!(vault.conceal("b", plain, origin), plain);
    }

    #[test]
    fn other_password_fields_and_header_values_are_concealed_and_a_shown_step_hides_its_authorization() {
        use crate::browser_login::{BrowserLogin, Do, Step};
        let pin = Step {
            action: Do::Fill,
            css: "#pin".into(),
            text: None,
            value: "73-41 pin".into(),
            masked: true,
            page: "https://a.test/login".into(),
        };
        let p = AuthProfile {
            name: "b".into(),
            browser: Some(BrowserLogin { start_url: "https://a.test/login".into(), steps: vec![pin] }),
            login_steps: vec![],
            ..Default::default()
        };
        let s = session(p.clone());
        let vault = vault_of(&s);
        vault.put_typed(&p);
        let body = "pin=73-41+pin&next=%2F";
        let req = format!(
            "POST /pin HTTP/1.1\r\nHost: a.test\r\nX-Pin: 73-41 pin\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let kept = String::from_utf8(vault.conceal("b", req.as_bytes(), "https://a.test")).unwrap();
        assert!(kept.contains("X-Pin: \u{ab}auth:b:typed:1\u{bb}\r\n"), "{kept}");
        assert!(kept.ends_with("pin=\u{ab}auth:b:typed:1:form\u{bb}&next=%2F") && !kept.contains("73-41"), "{kept}");
        assert_eq!(wire(&s, kept.as_bytes()).unwrap(), req);
        // Typed on a.test: on another site it is left alone, and its placeholder doesn't go there.
        assert_eq!(vault.conceal("b", req.as_bytes(), "https://b.test"), req.as_bytes());

        let step = LoginStep {
            url: "https://a.test/mfa".into(),
            request: "POST /mfa HTTP/1.1\r\nHost: a.test\r\nAuthorization: Bearer old-ticket\r\nX-Csrf: {{csrf}}\r\n\r\notp={{totp}}".into(),
            csrf_url: None,
            csrf_regex: None,
        };
        let shown = AuthProfile { login_steps: vec![step], ..totp_profile("m") }.redacted();
        let request = &shown.login_steps[0].request;
        assert!(request.contains("Authorization: ********\r\nX-Csrf: {{csrf}}\r\n\r\notp={{totp}}"), "{request}");
    }

    #[test]
    fn a_refused_code_is_tried_again_only_at_a_periods_edge() {
        let g = totp_profile("r").totp.unwrap().generator().unwrap();
        let now = g.step(crate::totp::unix_now());
        let secs = Duration::from_secs;
        let used = |step, into: u64| TotpUse { step, into: secs(into), left: secs(30 - into) };
        // Sent in its period's last second, which has turned over since: again, now.
        assert_eq!(retry_code_after(&g, used(now - 1, 29)), Some(Duration::ZERO));
        // In the middle of its period the code was good, however long the login then took
        // (a browser's can outlast a period): something else is wrong, and it isn't sent twice.
        assert_eq!(retry_code_after(&g, used(now, 15)), None);
        assert_eq!(retry_code_after(&g, used(now - 1, 15)), None);
        assert_eq!(retry_code_after(&g, used(now - 1, 1)), None);
        // (The rest holds unless this very moment is the turn of a period.)
        if g.step(crate::totp::unix_now()) == now {
            // In its last seconds: the next code, when its period begins.
            let wait = retry_code_after(&g, used(now, 28)).unwrap();
            assert!(wait > Duration::ZERO && wait <= secs(30) + Duration::from_millis(250), "{wait:?}");
            // In its first: a little later, the same code.
            assert!(retry_code_after(&g, used(now, 1)).unwrap() <= secs(5));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_browser_login_that_starts_outside_the_scope_starts_no_browser() {
        let step = |action, value: &str| crate::browser_login::Step {
            action,
            css: String::new(),
            text: None,
            value: value.into(),
            masked: false,
            page: String::new(),
        };
        let profile = |start: &str, steps| AuthProfile {
            name: "b".into(),
            browser: Some(crate::browser_login::BrowserLogin { start_url: start.into(), steps }),
            ..Default::default()
        };
        let s = session(profile("https://elsewhere.test/login", vec![]));
        let e = s.login().await.unwrap_err();
        assert!(matches!(e, Error::OutOfScope(_)) && e.to_string().contains("elsewhere.test"), "{e}");
        // A page a later step opens, too: refused before the first step runs.
        let goto = step(crate::browser_login::Do::Goto, "https://idp.other.test/sso");
        let s = session(profile("https://a.test/login", vec![goto]));
        let e = s.login().await.unwrap_err();
        assert!(matches!(e, Error::OutOfScope(_)) && e.to_string().contains("browser step 1"), "{e}");
        assert!(profile("https://a.test/", vec![]).has_login());
    }

    #[test]
    fn a_browser_logins_page_and_the_sites_its_secrets_go_to() {
        use crate::browser_login::{BrowserLogin, Do, Step};
        let step = |action, value: &str, page: &str| Step {
            action,
            css: "#x".into(),
            text: None,
            value: value.into(),
            masked: false,
            page: page.into(),
        };
        let p = AuthProfile {
            name: "b".into(),
            browser: Some(BrowserLogin {
                start_url: "https://a.test/portal".into(),
                steps: vec![
                    step(Do::Click, "", "https://a.test/portal"),
                    step(Do::Fill, "{{username}}", "https://sso.a.test/signin?next=1"),
                    step(Do::Fill, "{{password}}", "https://sso.a.test/signin?next=1"),
                    step(Do::Fill, "{{totp:1}}", "https://sso.a.test/code"),
                    step(Do::Click, "", "https://a.test/portal/done"),
                ],
            }),
            ..Default::default()
        };
        // The password and the code go where they were typed, and nowhere else.
        assert_eq!(p.login_origins(), ["https://sso.a.test"]);
        // Only a redirect to the page the login began on says the session is lost: its path
        // is the start of others.
        let s = session(p);
        let to = |location: &str| format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\n\r\n");
        assert!(s.is_logged_out(to("/portal").as_bytes()));
        assert!(s.is_logged_out(to("https://a.test/portal?expired=1").as_bytes()));
        assert!(!s.is_logged_out(to("/portal/reports/7").as_bytes()));
        assert!(!s.is_logged_out(to("/home").as_bytes()));
        assert!(s.is_logged_out(b"HTTP/1.1 401 Unauthorized\r\n\r\n"));
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
    fn kept_headers_are_left_as_the_request_has_them() {
        let p = AuthProfile {
            name: "t".into(),
            headers: vec![("Authorization".into(), "Bearer real".into()), ("X-Api".into(), "k".into())],
            ..Default::default()
        };
        let s = session(p);
        let a = Target::from_url("https://a.test").unwrap();
        let req = b"GET / HTTP/1.1\r\nHost: a.test\r\nAuthorization: Bearer forged\r\n\r\n";
        let out = String::from_utf8(s.apply_to(req, &[], &a)).unwrap();
        assert!(out.contains("Authorization: «auth:t:header:Authorization»"), "{out}");
        let out = String::from_utf8(s.apply_to_keeping(req, &[], &["authorization"], &a)).unwrap();
        assert!(out.contains("Authorization: Bearer forged"), "{out}");
        assert!(out.contains("X-Api: «auth:t:header:X-Api»"), "{out}");
    }

    #[test]
    fn query_keys_stay_on_the_request_line_of_their_origin() {
        let p = AuthProfile {
            name: "t".into(),
            query_keys: vec![QueryKey {
                name: "api_key".into(),
                value: "a b&c".into(),
                origins: vec!["https://a.test".into()],
            }],
            ..Default::default()
        };
        assert!(p.validate().is_ok(), "a query key alone is enough");
        let s = session(p.clone());
        let a = Target::from_url("https://a.test").unwrap();
        let applied = s.apply_to(b"GET /x?api_key=old&b=1 HTTP/1.1\r\nHost: a.test\r\n\r\n", &[], &a);
        let out = String::from_utf8(applied.clone()).unwrap();
        assert!(out.starts_with("GET /x?b=1&api_key=«auth:t:query:api_key» HTTP/1.1\r\n"), "{out}");
        let sent = wire(&s, &applied).unwrap();
        assert!(sent.starts_with("GET /x?b=1&api_key=a+b%26c HTTP/1.1\r\n"), "{sent}");
        // Another origin gets no key, and can't be made to take one.
        let b = Target::from_url("https://b.test").unwrap();
        let out = String::from_utf8(s.apply_to(b"GET /x HTTP/1.1\r\nHost: b.test\r\n\r\n", &[], &b)).unwrap();
        assert!(!out.contains("api_key"), "{out}");
        assert!(vault_of(&s).resolve(&applied, &b).is_err());
        // Nor is it filled outside the request line.
        let ph = "«auth:t:query:api_key»";
        assert!(wire(&s, format!("GET / HTTP/1.1\r\nX-Reflect: {ph}\r\n\r\n").as_bytes()).is_err());
        assert!(wire(&s, format!("POST / HTTP/1.1\r\nContent-Length: 22\r\n\r\n{ph}").as_bytes()).is_err());
        // Shown masked.
        assert_eq!(p.redacted().query_keys[0].value, "********");
        assert!(!format!("{:?}", p.redacted()).contains("a b&c"));
        // Bad names and missing origins are refused.
        let bad = |name: &str, origins: Vec<String>| AuthProfile {
            name: "t".into(),
            query_keys: vec![QueryKey { name: name.into(), value: "v".into(), origins }],
            ..Default::default()
        };
        assert!(bad("a b", vec!["https://a.test".into()]).validate().is_err());
        assert!(bad("a", vec![]).validate().is_err());
    }

    #[test]
    fn query_keys_load_for_requests_from_history() {
        let p = AuthProfile {
            name: "t".into(),
            query_keys: vec![QueryKey {
                name: "k".into(),
                value: "v1".into(),
                origins: vec!["https://a.test:443".into()],
            }],
            ..Default::default()
        };
        let vault = Vault::default();
        vault.put_session(&p, &SessionState::default());
        let raw = "GET /?k=«auth:t:query:k» HTTP/1.1\r\n\r\n";
        let filled = vault.resolve(raw.as_bytes(), &Target::from_url("https://a.test").unwrap()).unwrap();
        assert!(String::from_utf8_lossy(&filled).starts_with("GET /?k=v1 "));
    }

    #[test]
    fn a_learned_value_with_a_line_break_is_never_filled_into_the_head() {
        let p = AuthProfile {
            name: "t".into(),
            token_header: Some("Authorization: Bearer {{token}}".into()),
            ..Default::default()
        };
        let vault = Vault::default();
        let st = SessionState { token: Some("abc\r\nHost: e.test".into()), ..Default::default() };
        vault.put_session(&p, &st);
        let raw = "GET / HTTP/1.1\r\nAuthorization: Bearer «auth:t:token»\r\n\r\n";
        let e = vault.resolve(raw.as_bytes(), &Target::from_url("https://a.test").unwrap()).unwrap_err();
        assert!(e.to_string().contains("line break"), "{e}");
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
        assert!(vault_of(&s).resolve(req.as_bytes(), &other).is_err());
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
            origin: None,
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
