//! Session handling on top of an auth profile: macros and session rules.
//!
//! A macro is an ordered list of requests. Each step can extract values from its
//! response (a regex group, a JSON path, a header, a cookie, or an HTML input by
//! name) into variables that later steps use as `{{name}}`; a later step's
//! parameters named like a variable are updated with its value too. The steps run
//! with the profile's session, so cookies carry through the sequence and into the
//! session.
//!
//! A session rule says what to do before a request of some tools (proxy, send,
//! fuzz, crawl, scan, checks) to some URLs goes out, in order: check the session is
//! still valid, run a macro, update the request's parameters, headers and cookies
//! from macro values (a fresh CSRF token per request during a scan), or log in again.
//!
//! Extracted values never reach a record of a request: requests carry placeholders
//! (`«auth:PROFILE:var:NAME#RUN»`) that the client fills in on the wire, like the
//! other auth values. Each macro run gets its own placeholders, so requests prepared
//! at the same time with different runs' values each send their own. Macro requests
//! go through the session's guarded client, so they are scope-checked like any other.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::{encode, placeholder, request_cookies, response_text, AuthProfile, AuthSession, Enc};
use crate::capture::decode_body;
use crate::error::{Error, Result};
use crate::http::request::{find, split_head_body};
use crate::http::{parse_response_head, RawRequest, Target};
use crate::scan::active::points::{inject, points, PointKind, PointOptions};
use crate::scan::message::SetCookie;
use crate::store::Store;

/// The tools a session rule can be limited to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Proxy,
    Send,
    Fuzz,
    Crawl,
    Scan,
    Checks,
}

impl Tool {
    pub const ALL: [Tool; 6] = [Tool::Proxy, Tool::Send, Tool::Fuzz, Tool::Crawl, Tool::Scan, Tool::Checks];

    pub fn name(self) -> &'static str {
        match self {
            Tool::Proxy => "proxy",
            Tool::Send => "send",
            Tool::Fuzz => "fuzz",
            Tool::Crawl => "crawl",
            Tool::Scan => "scan",
            Tool::Checks => "checks",
        }
    }

    pub fn parse(s: &str) -> Result<Tool> {
        Tool::ALL.into_iter().find(|t| t.name().eq_ignore_ascii_case(s.trim())).ok_or_else(|| {
            Error::InvalidInput(format!("unknown tool {s:?}; one of proxy, send, fuzz, crawl, scan, checks"))
        })
    }
}

/// A profile's macros and session rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Handling {
    #[serde(default)]
    pub macros: Vec<Macro>,
    #[serde(default)]
    pub rules: Vec<SessionRule>,
    /// Request signers a rule's `sign` action can use (see [`crate::sign`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<crate::sign::Signer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Macro {
    pub name: String,
    pub steps: Vec<MacroStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MacroStep {
    /// Where the request goes: scheme://host[:port].
    pub target: String,
    /// The raw request. `{{name}}` takes a value extracted by an earlier step (or the
    /// profile's `{{username}}` and `{{password}}`), encoded for where it stands.
    pub request: String,
    /// The history entry the request was copied from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_id: Option<i64>,
    #[serde(default)]
    pub extract: Vec<Extractor>,
}

/// Takes a value from a step's response into a variable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Extractor {
    pub var: String,
    pub from: ExtractFrom,
    /// Regex (group 1, else the whole match), JSON path (`data.token`, `items.0.id`),
    /// header name, cookie name, or HTML input name.
    pub expr: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ExtractFrom {
    Regex,
    Json,
    Header,
    Cookie,
    /// The value of `<input name=EXPR>` (or the content of `<meta name=EXPR>`).
    Input,
}

impl ExtractFrom {
    pub fn parse(s: &str) -> Result<ExtractFrom> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "regex" => ExtractFrom::Regex,
            "json" => ExtractFrom::Json,
            "header" => ExtractFrom::Header,
            "cookie" => ExtractFrom::Cookie,
            "input" => ExtractFrom::Input,
            _ => {
                return Err(Error::InvalidInput(format!(
                    "unknown extractor {s:?}; one of regex, json, header, cookie, input"
                )))
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionRule {
    pub id: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Tools the rule applies to; empty for all.
    #[serde(default)]
    pub tools: Vec<Tool>,
    /// Host pattern (`*.example.com`) or URL prefix (`https://example.com/api/`), `*`
    /// matching anything; None for every URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub actions: Vec<Action>,
    /// Regex that marks a response as rejected for stale session values (e.g. "invalid
    /// CSRF token"): the rule's macros run again and the request is sent once more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Fetch the profile's check URL (on every `every`th request). Valid: the rule's
    /// remaining actions are skipped; logged out: they run.
    Check {
        #[serde(default = "one")]
        every: u32,
    },
    /// Run a macro. `every`: 0 runs it once and again only when its values go stale
    /// (a logged-out or `invalid` response, or a failed check); 1 on every request;
    /// N on every Nth request.
    RunMacro {
        #[serde(rename = "macro")]
        name: String,
        #[serde(default)]
        every: u32,
    },
    /// Put macro values into the request: each parameter (query, form, JSON, multipart),
    /// header or cookie named PARAM gets variable VAR. Empty: each variable of the macros
    /// this rule ran into the parameters of its own name. A rule with no URL only puts a
    /// value into requests to the origins of the macro that extracted it.
    Update {
        #[serde(default)]
        params: Vec<(String, String)>,
    },
    /// Log in again with the profile when the session is not logged in (or a check
    /// before this action just failed).
    Login,
    /// Sign the request as it goes on the wire, whatever the rule's other actions did.
    Sign { signer: String },
}

fn one() -> u32 {
    1
}

impl Action {
    /// Parses `check[:N]`, `macro:NAME[:each|:N]`, `update[:PARAM[=VAR],...]`, `login`,
    /// `sign:NAME`.
    pub fn parse(spec: &str) -> Result<Action> {
        let (kind, rest) = spec.split_once(':').map_or((spec, None), |(k, r)| (k, Some(r)));
        let count = |s: &str| {
            s.parse::<u32>().map_err(|_| Error::InvalidInput(format!("{spec:?}: {s:?} is not a request count")))
        };
        Ok(match kind.trim().to_ascii_lowercase().as_str() {
            "check" => Action::Check { every: rest.map(count).transpose()?.unwrap_or(1).max(1) },
            "macro" => {
                let rest = rest.filter(|r| !r.is_empty()).ok_or_else(|| {
                    Error::InvalidInput(format!("{spec:?}: name the macro, e.g. macro:csrf or macro:csrf:each"))
                })?;
                let (name, every) = match rest.rsplit_once(':') {
                    Some((n, "each")) => (n, 1),
                    Some((n, e)) => (n, count(e)?),
                    None => (rest, 0),
                };
                Action::RunMacro { name: name.to_string(), every }
            }
            "update" => Action::Update {
                params: rest
                    .unwrap_or("")
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(|p| match p.split_once('=') {
                        Some((param, var)) => (param.trim().to_string(), var.trim().to_string()),
                        None => (p.to_string(), p.to_string()),
                    })
                    .collect(),
            },
            "login" => Action::Login,
            "sign" => Action::Sign {
                signer: rest
                    .filter(|r| !r.is_empty())
                    .ok_or_else(|| Error::InvalidInput(format!("{spec:?}: name the signer, e.g. sign:api")))?
                    .to_string(),
            },
            _ => {
                return Err(Error::InvalidInput(format!(
                    "unknown action {spec:?}; one of check[:N], macro:NAME[:each|:N], update[:PARAM[=VAR],...], login, sign:NAME"
                )))
            }
        })
    }
}

/// A macro value of the current session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionVar {
    pub name: String,
    pub value: String,
    /// The macro run that extracted it.
    pub run: u64,
    /// Origins the value may be sent to: the macro's steps' and those a rule with a URL
    /// put it in.
    #[serde(default)]
    pub origins: Vec<String>,
    /// The origins of the steps of the macro that extracted it.
    #[serde(default)]
    pub home: Vec<String>,
}

/// The placeholder kind of a macro variable: `var:NAME#RUN` (or `var:NAME`, its latest
/// value), with `:form` or `:json` for the encoded forms.
pub(crate) fn var_kind(name: &str, run: Option<u64>, enc: Enc) -> String {
    let suffix = match enc {
        Enc::Raw => "",
        Enc::Form => ":form",
        Enc::Json => ":json",
    };
    match run {
        Some(r) => format!("var:{name}#{r}{suffix}"),
        None => format!("var:{name}{suffix}"),
    }
}

/// The placeholder of a variable's latest value for a per-run placeholder.
pub(crate) fn latest_placeholder(ph: &str) -> Option<String> {
    let i = ph.find(":var:")?;
    let hash = i + ph[i..].find('#')?;
    let end = ph[hash..].find([':', '»']).map_or(ph.len(), |j| hash + j);
    Some(format!("{}{}", &ph[..hash], &ph[end..]))
}

fn valid_name(what: &str, name: &str) -> Result<()> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
        return Err(Error::InvalidInput(format!("{what} {name:?}: use letters, digits, '_', '-' and '.'")));
    }
    Ok(())
}

impl Macro {
    pub fn validate(&self) -> Result<()> {
        valid_name("macro name", &self.name)?;
        if self.steps.is_empty() {
            return Err(Error::InvalidInput(format!("macro {:?} has no steps", self.name)));
        }
        for (i, step) in self.steps.iter().enumerate() {
            Target::from_url(&step.target)
                .map_err(|e| Error::InvalidInput(format!("macro step {}: target: {e}", i + 1)))?;
            RawRequest::from_bytes(step.request.clone().into_bytes())
                .head()
                .map_err(|e| Error::InvalidInput(format!("macro step {}: request: {e}", i + 1)))?;
            for x in &step.extract {
                valid_name("variable", &x.var)?;
                if x.expr.is_empty() {
                    return Err(Error::InvalidInput(format!("macro step {}: extractor {} is empty", i + 1, x.var)));
                }
                if x.from == ExtractFrom::Regex {
                    Regex::new(&x.expr)
                        .map_err(|e| Error::InvalidInput(format!("macro step {}: regex: {e}", i + 1)))?;
                }
            }
        }
        Ok(())
    }

    /// Every variable the macro extracts.
    pub fn vars(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for x in self.steps.iter().flat_map(|s| &s.extract) {
            if !out.contains(&x.var.as_str()) {
                out.push(&x.var);
            }
        }
        out
    }
}

impl Handling {
    /// Checks the macros and rules against each other and the profile.
    pub fn validate(&self, profile: &AuthProfile) -> Result<()> {
        for (i, m) in self.macros.iter().enumerate() {
            m.validate()?;
            if self.macros[..i].iter().any(|o| o.name == m.name) {
                return Err(Error::InvalidInput(format!("two macros are named {:?}", m.name)));
            }
        }
        for (i, s) in self.signers.iter().enumerate() {
            s.validate()?;
            if self.signers[..i].iter().any(|o| o.name == s.name) {
                return Err(Error::InvalidInput(format!("two signers are named {:?}", s.name)));
            }
        }
        for r in &self.rules {
            let what = |e: String| Error::InvalidInput(format!("session rule {}: {e}", r.id));
            if r.actions.is_empty() {
                return Err(what("has no actions".into()));
            }
            if let Some(re) = &r.invalid {
                Regex::new(re).map_err(|e| what(format!("invalid regex: {e}")))?;
            }
            if let Some(u) = &r.url {
                UrlPattern::new(u).map_err(|e| what(e.to_string()))?;
            }
            for (i, a) in r.actions.iter().enumerate() {
                match a {
                    Action::Update { params }
                        if params.is_empty()
                            && !r.actions[..i].iter().any(|b| matches!(b, Action::RunMacro { .. })) =>
                    {
                        return Err(what("update with no parameters needs a macro before it in the rule".into()))
                    }
                    Action::Check { .. } if profile.check_url.is_none() => {
                        return Err(what("a check needs the profile's check URL (auth add --check-url)".into()))
                    }
                    Action::Login if !profile.has_login() => {
                        return Err(what("login needs a profile with a login (auth add --login-url)".into()))
                    }
                    Action::RunMacro { name, .. } if !self.macros.iter().any(|m| &m.name == name) => {
                        return Err(what(format!("no macro {name:?} (auth macro add)")))
                    }
                    Action::Sign { signer } if !self.signers.iter().any(|s| &s.name == signer) => {
                        return Err(what(format!("no signer {signer:?} (auth sign add)")))
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// A rule's URL scope: a host pattern, or a URL prefix when it has a scheme.
struct UrlPattern {
    re: Regex,
    url: bool,
}

impl UrlPattern {
    fn new(pattern: &str) -> Result<Self> {
        let p = pattern.trim();
        if p.is_empty() {
            return Err(Error::InvalidInput("empty URL pattern".into()));
        }
        let url = p.contains("://");
        let glob = regex::escape(p).replace(r"\*", ".*");
        let src = if url {
            format!("^{glob}")
        } else {
            // `*.example.com` covers example.com itself too.
            match glob.strip_prefix(r".*\.") {
                Some(base) => format!(r"^(.*\.)?{base}$"),
                None => format!("^{glob}$"),
            }
        };
        let re =
            RegexBuilder::new(&src).case_insensitive(true).build().map_err(|e| Error::InvalidInput(e.to_string()))?;
        Ok(UrlPattern { re, url })
    }

    fn matches(&self, target: &Target, url: &str) -> bool {
        if self.url {
            self.re.is_match(url)
        } else {
            self.re.is_match(&target.host)
        }
    }
}

/// A rule ready to run.
struct Compiled {
    url: Option<UrlPattern>,
    invalid: Option<Regex>,
    /// Requests seen per action, for `every`.
    counters: Vec<AtomicU64>,
}

/// One macro's cached run.
#[derive(Clone)]
struct Cached {
    run: u64,
    vars: Vec<String>,
    generation: u64,
}

/// The session's macros and rules at run time.
#[derive(Default)]
pub(crate) struct Runtime {
    cfg: Handling,
    compiled: Vec<Compiled>,
    cache: Mutex<HashMap<String, Cached>>,
    /// Bumped when cached macro values go stale, so concurrent workers refresh once.
    generation: AtomicU64,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl Runtime {
    /// Whether the profile has session rules (then responses are watched for a lost
    /// session even without a profile login).
    pub(crate) fn active(&self) -> bool {
        !self.cfg.rules.is_empty()
    }
}

/// A request with the session applied, and what the session looked like then.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The request to send (placeholders in place of session values).
    pub request: Vec<u8>,
    generation: u64,
    macro_generation: u64,
    /// The rules that applied (indexes).
    rules: Vec<usize>,
}

/// One macro step as run.
#[derive(Debug, Clone, Serialize)]
pub struct StepRun {
    pub step: usize,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub history_id: Option<i64>,
    pub extracted: Vec<Extracted>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Extracted {
    pub var: String,
    /// The value masked ([`mask`]); None when nothing was found.
    pub value: Option<String>,
}

/// Outcome of a macro run.
#[derive(Debug, Clone, Serialize)]
pub struct MacroRun {
    pub name: String,
    pub run: u64,
    pub steps: Vec<StepRun>,
    /// Variables a step was meant to extract but found nothing for.
    pub missing: Vec<String>,
}

impl MacroRun {
    pub fn complete(&self) -> bool {
        self.missing.is_empty() && self.steps.iter().all(|s| s.error.is_none())
    }

    /// The variables this run found.
    pub fn vars(&self) -> Vec<String> {
        self.steps.iter().flat_map(|s| &s.extracted).filter(|x| x.value.is_some()).map(|x| x.var.clone()).collect()
    }
}

/// A value for display: its length and at most its first four characters.
pub fn mask(value: &str) -> String {
    let n = value.chars().count();
    if n < 12 {
        format!("******** ({n} chars)")
    } else {
        format!("{}… ({n} chars)", value.chars().take(4).collect::<String>())
    }
}

impl Store {
    pub fn auth_handling(&self, profile: &str) -> Result<Handling> {
        Ok(self
            .meta_get(&handling_key(profile))?
            .map(|s| serde_json::from_str(&s).map_err(|e| Error::InvalidInput(format!("stored session rules: {e}"))))
            .transpose()?
            .unwrap_or_default())
    }

    /// Forgets a removed profile's macros and rules.
    pub(crate) fn auth_clear_handling(&self, profile: &str) -> Result<()> {
        self.meta_set(&handling_key(profile), None)
    }

    /// Makes a profile with no login or headers for its first macro.
    pub fn auth_create_for_macros(&self, name: &str, h: &Handling) -> Result<()> {
        let p = AuthProfile::without_login(name);
        h.validate(&p)?;
        p.validate_with(h)?;
        self.auth_write_handling(name, h)?;
        self.auth_save_profile(&p)
    }

    /// Stores a profile's macros and rules (checked against the profile first). A profile
    /// with no login or headers can't lose its last macro or rule: it would do nothing.
    pub fn auth_save_handling(&self, profile: &str, h: &Handling) -> Result<()> {
        let (p, _) = self.auth_profile(profile)?;
        p.validate_with(h)
            .map_err(|e| Error::InvalidInput(format!("{e}; to delete the profile itself: auth remove {profile}")))?;
        h.validate(&p)?;
        self.auth_write_handling(profile, h)
    }

    fn auth_write_handling(&self, profile: &str, h: &Handling) -> Result<()> {
        if *h == Handling::default() {
            return self.auth_clear_handling(profile);
        }
        let json = serde_json::to_string(h).map_err(|e| Error::InvalidInput(e.to_string()))?;
        self.meta_set(&handling_key(profile), Some(&json))
    }
}

fn handling_key(profile: &str) -> String {
    format!("auth.handling.{profile}")
}

/// The URL a request goes to.
fn request_url(raw: &[u8], target: &Target) -> String {
    let path = RawRequest::from_bytes(raw.to_vec()).head().map(|h| h.target).unwrap_or_else(|_| "/".into());
    if path.starts_with("http://") || path.starts_with("https://") {
        return path;
    }
    let joined = format!("{}{}", target.origin(), if path.starts_with('/') { path } else { format!("/{path}") });
    url::Url::parse(&joined).map(|u| u.to_string()).unwrap_or(joined)
}

impl AuthSession {
    /// Loads the profile's macros and rules into the session.
    pub fn with_handling(mut self, cfg: Handling) -> Result<Self> {
        cfg.validate(&self.profile)?;
        let mut compiled = Vec::new();
        for r in &cfg.rules {
            compiled.push(Compiled {
                url: r.url.as_deref().map(UrlPattern::new).transpose()?,
                invalid: r
                    .invalid
                    .as_deref()
                    .map(Regex::new)
                    .transpose()
                    .map_err(|e| Error::InvalidInput(e.to_string()))?,
                counters: r.actions.iter().map(|_| AtomicU64::new(0)).collect(),
            });
        }
        if let Some(g) = &self.client.options().guard {
            g.vault.put_signers(&self.profile.name, &cfg.signers);
        }
        self.handling = Runtime { cfg, compiled, ..Default::default() };
        Ok(self)
    }

    /// The session's macros and rules.
    pub fn handling(&self) -> &Handling {
        &self.handling.cfg
    }

    /// Applies the session to a request of `tool`: its cookies and headers, then the
    /// actions of each session rule for this tool and URL. Cookies in `keep_cookies`
    /// and parameters in `keep_params` (the ones being attacked) keep their values.
    pub async fn prepare(
        &self,
        tool: Tool,
        target: &Target,
        raw: &[u8],
        keep_cookies: &[&str],
        keep_params: &[&str],
    ) -> Prepared {
        let generation = self.generation();
        let macro_generation = self.handling.generation.load(Ordering::SeqCst);
        let mut request = raw.to_vec();
        let mut rules = Vec::new();
        if self.handling.active() {
            let url = request_url(raw, target);
            for (i, (rule, c)) in self.handling.cfg.rules.iter().zip(&self.handling.compiled).enumerate() {
                let tool_ok = rule.tools.is_empty() || rule.tools.contains(&tool);
                if tool_ok && c.url.as_ref().is_none_or(|u| u.matches(target, &url)) {
                    rules.push(i);
                    request = self
                        .run_rule(i, target, request, keep_params, keep_cookies, generation, macro_generation)
                        .await;
                }
            }
        }
        // The session goes on last, so it has the cookies the rules' macros just got. A
        // cookie or header a rule set from a macro value keeps it.
        let mark = placeholder(&self.profile.name, "var:");
        let mark = mark.trim_end_matches('»');
        let set: Vec<String> =
            request_cookies(&request).into_iter().filter(|(_, v)| v.contains(mark)).map(|(k, _)| k).collect();
        let headers: Vec<(String, String)> = RawRequest::from_bytes(request.clone())
            .head()
            .map(|h| h.headers)
            .unwrap_or_default()
            .into_iter()
            .filter(|(k, v)| !k.eq_ignore_ascii_case("cookie") && v.contains(mark))
            .collect();
        let mut keep: Vec<&str> = keep_cookies.to_vec();
        keep.extend(set.iter().map(String::as_str));
        let mut request = self.apply(&request, &keep);
        for (k, v) in &headers {
            request = RawRequest::from_bytes(request).set_header(k, v).into_bytes();
        }
        // Last, so nothing above moves them; the vault signs when the request is sent.
        let signers = rules.iter().flat_map(|&i| &self.handling.cfg.rules[i].actions).filter_map(|a| match a {
            Action::Sign { signer } => self.handling.cfg.signers.iter().find(|s| &s.name == signer),
            _ => None,
        });
        for s in signers.filter(|s| s.origins.iter().any(|o| crate::sign::same_origin(o, target))) {
            request = s.place(&request, &self.profile.name, keep_params);
        }
        Prepared { request, generation, macro_generation, rules }
    }

    /// Learns cookies from the response to a prepared request, and handles a lost
    /// session or stale macro values: logs in again and marks the macros of the rules
    /// that applied for a refresh. True when the request should be prepared and sent
    /// again (once).
    pub async fn after_response(&self, prepared: &Prepared, response: &[u8]) -> bool {
        self.observe(response);
        let logged_out = self.is_logged_out(response);
        let rules = || prepared.rules.iter().map(|&i| (&self.handling.cfg.rules[i], &self.handling.compiled[i]));
        let stale = logged_out || {
            let invalid: Vec<&Regex> = rules().filter_map(|(_, c)| c.invalid.as_ref()).collect();
            !invalid.is_empty() && {
                let text = response_text(response);
                invalid.iter().any(|re| re.is_match(&text))
            }
        };
        let mut retry = false;
        if stale && rules().any(|(r, _)| r.actions.iter().any(|a| matches!(a, Action::RunMacro { .. }))) {
            self.invalidate_macros(prepared.macro_generation);
            retry = true;
        }
        if logged_out && self.relogin(prepared.generation).await {
            retry = true;
        }
        retry
    }

    fn invalidate_macros(&self, seen: u64) {
        let _ = self.handling.generation.compare_exchange(seen, seen + 1, Ordering::SeqCst, Ordering::SeqCst);
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_rule(
        &self,
        i: usize,
        target: &Target,
        mut request: Vec<u8>,
        keep_params: &[&str],
        keep_cookies: &[&str],
        generation: u64,
        macro_generation: u64,
    ) -> Vec<u8> {
        let rule = &self.handling.cfg.rules[i];
        let scoped = rule.url.is_some();
        let counters = &self.handling.compiled[i].counters;
        // Variables of the macros this rule ran, with their runs.
        let mut local: HashMap<String, u64> = HashMap::new();
        let mut check_failed = false;
        for (a, action) in rule.actions.iter().enumerate() {
            let n = counters[a].fetch_add(1, Ordering::SeqCst);
            match action {
                Action::Check { every } => {
                    if !n.is_multiple_of(u64::from((*every).max(1))) {
                        break; // Not checked this time: taken as valid.
                    }
                    match self.check().await {
                        Ok(Some(c)) if !c.logged_in => {
                            check_failed = true;
                            self.invalidate_macros(macro_generation);
                        }
                        _ => break,
                    }
                }
                Action::RunMacro { name, every } => {
                    let fresh = match every {
                        0 => false,
                        e => n.is_multiple_of(u64::from(*e)),
                    };
                    let run = if fresh && !self.handling.cache.lock().unwrap().contains_key(name) {
                        // The first run goes alone, so requests prepared at the same time
                        // don't each start their own session on the site.
                        self.first_run(name).await
                    } else if fresh {
                        self.run_macro(name).await.ok().map(|r| Cached { vars: r.vars(), run: r.run, generation: 0 })
                    } else {
                        self.cached_run(name).await
                    };
                    if let Some(c) = run {
                        for v in c.vars {
                            local.insert(v, c.run);
                        }
                    }
                }
                Action::Update { params } => {
                    request = self.update_request(&request, target, params, &local, keep_params, keep_cookies, scoped);
                }
                Action::Login => {
                    if check_failed || !self.state.lock().unwrap().logged_in {
                        self.relogin(generation).await;
                    }
                }
                // Applied by `prepare`, after the session goes on.
                Action::Sign { .. } => {}
            }
        }
        request
    }

    /// The macro's cached run, running it first when there is none or it went stale
    /// (once, however many requests ask at the same time).
    async fn cached_run(&self, name: &str) -> Option<Cached> {
        let current = || {
            let generation = self.handling.generation.load(Ordering::SeqCst);
            self.handling.cache.lock().unwrap().get(name).filter(|c| c.generation == generation).cloned()
        };
        if let Some(c) = current() {
            return Some(c);
        }
        let _guard = self.handling.refresh_lock.lock().await;
        if let Some(c) = current() {
            return Some(c);
        }
        let run = self.run_macro(name).await.ok()?;
        Some(Cached { vars: run.vars(), run: run.run, generation: 0 })
    }

    /// A macro's first run in this session; a request that waited for another's runs
    /// its own afterwards.
    async fn first_run(&self, name: &str) -> Option<Cached> {
        let guard = self.handling.refresh_lock.lock().await;
        let ran = self.handling.cache.lock().unwrap().contains_key(name);
        if ran {
            drop(guard);
        }
        let run = self.run_macro(name).await.ok()?;
        Some(Cached { vars: run.vars(), run: run.run, generation: 0 })
    }

    /// Runs a macro now: each step with the session applied, values extracted into
    /// variables (stored as the session's latest), cookies learned into the session.
    pub async fn run_macro(&self, name: &str) -> Result<MacroRun> {
        let m = self
            .handling
            .cfg
            .macros
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| Error::NotFound(format!("macro {name:?} of profile {:?}", self.profile.name)))?;
        let generation = self.handling.generation.load(Ordering::SeqCst);
        let run = {
            let mut st = self.state.lock().unwrap();
            st.macro_runs += 1;
            st.macro_runs
        };
        let vault = self.client.options().guard.as_ref().map(|g| &g.vault);
        let mut origins: Vec<String> = Vec::new();
        for s in &m.steps {
            let o = Target::from_url(&s.target)?.origin();
            if !origins.contains(&o) {
                origins.push(o);
            }
        }
        let password = self.profile.password.as_ref().and_then(|p| p.resolve().ok());
        if let (Some(v), Some(pw)) = (vault, &password) {
            v.put_password(&self.profile, pw);
            for o in &origins {
                for enc in [Enc::Raw, Enc::Form, Enc::Json] {
                    v.allow(&placeholder(&self.profile.name, enc.password_kind()), o);
                }
            }
        }
        // Variables found so far in this run.
        let mut found: Vec<String> = Vec::new();
        let mut out = MacroRun { name: name.to_string(), run, steps: Vec::new(), missing: Vec::new() };
        for (i, step) in m.steps.iter().enumerate() {
            let target = Target::from_url(&step.target)?;
            let text = fill_vars(&step.request, |var, enc| {
                if found.iter().any(|f| f == var) {
                    return Some(placeholder(&self.profile.name, &var_kind(var, Some(run), enc)));
                }
                match var {
                    "username" => Some(encode(self.profile.username.as_deref().unwrap_or(""), enc)),
                    "password" if password.is_some() => Some(placeholder(&self.profile.name, enc.password_kind())),
                    _ => None,
                }
            });
            let mut raw =
                RawRequest::from_bytes(text.into_bytes()).normalize_line_endings().update_content_length().into_bytes();
            // Parameters named like an earlier step's variable get its value too.
            let derived: Vec<(String, String)> = found.iter().map(|v| (v.clone(), v.clone())).collect();
            let runs: HashMap<String, u64> = found.iter().map(|v| (v.clone(), run)).collect();
            raw = self.update_request(&raw, &target, &derived, &runs, &[], &[], false);
            let head = RawRequest::from_bytes(raw.clone()).head().ok();
            let mut sr = StepRun {
                step: i + 1,
                method: head.as_ref().map(|h| h.method.clone()).unwrap_or_default(),
                url: request_url(&raw, &target),
                status: None,
                history_id: None,
                extracted: Vec::new(),
                error: None,
            };
            let sent = self.client.send(&RawRequest::from_bytes(self.apply(&raw, &[])), &target).await;
            let ex = match sent {
                Ok(ex) => ex,
                Err(e) => {
                    sr.error = Some(e.to_string());
                    out.steps.push(sr);
                    out.missing.extend(step.extract.iter().map(|x| x.var.clone()));
                    break;
                }
            };
            self.observe(&ex.response);
            sr.history_id = self.record(&ex);
            sr.status = parse_response_head(&ex.response).ok().map(|h| h.status);
            for x in &step.extract {
                match extract(x, &ex.response) {
                    Some(value) => {
                        sr.extracted.push(Extracted { var: x.var.clone(), value: Some(mask(&value)) });
                        let var = SessionVar {
                            name: x.var.clone(),
                            value,
                            run,
                            origins: origins.clone(),
                            home: origins.clone(),
                        };
                        if let Some(v) = vault {
                            v.put_var(&self.profile.name, &var);
                        }
                        let mut st = self.state.lock().unwrap();
                        st.vars.retain(|v| v.name != var.name);
                        st.vars.push(var);
                        found.retain(|f| f != &x.var);
                        found.push(x.var.clone());
                    }
                    None => {
                        sr.extracted.push(Extracted { var: x.var.clone(), value: None });
                        out.missing.push(x.var.clone());
                    }
                }
            }
            out.steps.push(sr);
        }
        // Cached even when incomplete: a stale response refreshes it, rather than every request.
        self.handling.cache.lock().unwrap().insert(name.to_string(), Cached { run, vars: found, generation });
        Ok(out)
    }

    /// The request with each mapped parameter, header or cookie set to its variable's
    /// placeholder (from `runs`, else, when named in `params`, the session's latest value).
    /// With no `params`, only the variables in `runs` are mapped, each to its own name.
    /// `scoped` says the caller's URL pattern chose this request, which lets a value go to
    /// this origin from now on; otherwise it only goes to its macro's own origins. Parameters
    /// and headers named in `keep_params`, and cookies in `keep_cookies`, stay as they are.
    #[allow(clippy::too_many_arguments)]
    fn update_request(
        &self,
        raw: &[u8],
        target: &Target,
        params: &[(String, String)],
        runs: &HashMap<String, u64>,
        keep_params: &[&str],
        keep_cookies: &[&str],
        scoped: bool,
    ) -> Vec<u8> {
        let vars: HashMap<String, (u64, Vec<String>)> =
            self.state.lock().unwrap().vars.iter().map(|v| (v.name.clone(), (v.run, v.home.clone()))).collect();
        let mapping: Vec<(String, String)> = if params.is_empty() {
            let mut names: Vec<&String> = runs.keys().collect();
            names.sort();
            names.into_iter().map(|n| (n.clone(), n.clone())).collect()
        } else {
            params.to_vec()
        };
        let vault = self.client.options().guard.as_ref().map(|g| &g.vault);
        let origin = target.origin();
        let mut out = raw.to_vec();
        for (param, var) in mapping {
            if keep_params.iter().any(|k| k == &param) {
                continue;
            }
            let Some((latest, home)) = vars.get(&var) else { continue };
            if !scoped && !home.contains(&origin) {
                continue;
            }
            let cookies = !keep_cookies.iter().any(|k| k == &param);
            let run = runs.get(&var).copied().unwrap_or(*latest);
            let ph = |enc| placeholder(&self.profile.name, &var_kind(&var, Some(run), enc));
            let updated = set_param(&out, &param, cookies, ph);
            if updated == out {
                continue;
            }
            out = updated;
            if scoped {
                if let Some(v) = vault {
                    for enc in [Enc::Raw, Enc::Form, Enc::Json] {
                        v.allow(&ph(enc), &origin);
                        v.allow(&placeholder(&self.profile.name, &var_kind(&var, None, enc)), &origin);
                    }
                }
                let mut st = self.state.lock().unwrap();
                if let Some(sv) = st.vars.iter_mut().find(|v| v.name == var) {
                    if !sv.origins.contains(&origin) {
                        sv.origins.push(origin.clone());
                    }
                }
            }
        }
        out
    }
}

/// Fills `{{name}}` in a raw request template part by part: the request line
/// form-encoded, headers as they are, the body for its Content-Type. Names `value`
/// knows nothing about are left as written.
fn fill_vars(tpl: &str, value: impl Fn(&str, Enc) -> Option<String>) -> String {
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
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(i) = rest.find("{{") {
            out.push_str(&rest[..i]);
            let after = &rest[i + 2..];
            match after.find("}}").and_then(|j| value(after[..j].trim(), enc).map(|v| (j, v))) {
                Some((j, v)) => {
                    out.push_str(&v);
                    rest = &after[j + 2..];
                }
                None => {
                    out.push_str("{{");
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
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

/// The request with every query, form, JSON (by last key) and multipart parameter,
/// header and cookie named `name` set to the placeholder for its context.
fn set_param(raw: &[u8], name: &str, cookies: bool, ph: impl Fn(Enc) -> String) -> Vec<u8> {
    let mut out = raw.to_vec();
    let opts = PointOptions { cookies, ..Default::default() };
    // Values change, not positions; re-read the points after each change all the same.
    let mut done = 0;
    loop {
        let matching: Vec<_> = points(&out, &opts)
            .into_iter()
            .filter(|p| match p.kind {
                PointKind::Json => p.name.rsplit('.').next() == Some(name),
                _ => p.name == name,
            })
            .collect();
        let Some(p) = matching.into_iter().nth(done) else { break };
        let value = match p.kind {
            PointKind::Query | PointKind::Form => ph(Enc::Form),
            PointKind::Json => ph(Enc::Json),
            _ => ph(Enc::Raw),
        };
        out = inject(&out, &p, &value, false);
        done += 1;
    }
    out = set_multipart(&out, name, &ph(Enc::Raw));
    let req = RawRequest::from_bytes(out);
    let reserved = ["host", "content-length", "transfer-encoding", "cookie", "connection"];
    let old = req.head().ok().and_then(|h| h.headers.into_iter().find(|(k, _)| k.eq_ignore_ascii_case(name)));
    match old {
        Some((_, old)) if !reserved.iter().any(|r| r.eq_ignore_ascii_case(name)) => {
            // An Authorization header keeps its scheme ("Bearer VALUE").
            let value = match old.trim().split_once(' ') {
                Some((scheme, _)) if name.eq_ignore_ascii_case("authorization") => format!("{scheme} {}", ph(Enc::Raw)),
                _ => ph(Enc::Raw),
            };
            req.set_header(name, &value).into_bytes()
        }
        _ => req.into_bytes(),
    }
}

/// The non-file fields of a multipart/form-data request: name and the byte range of
/// its value in `raw`.
pub(crate) fn multipart_fields(raw: &[u8]) -> Vec<(String, std::ops::Range<usize>)> {
    let boundary = RawRequest::from_bytes(raw.to_vec()).head().ok().and_then(|h| {
        let ct = h.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type"))?.1.clone();
        if !ct.to_ascii_lowercase().starts_with("multipart/form-data") {
            return None;
        }
        ct.split(';').find_map(|p| p.trim().strip_prefix("boundary=").map(|b| b.trim_matches('"').to_string()))
    });
    let Some(boundary) = boundary.filter(|b| !b.is_empty()) else { return vec![] };
    let body_start = split_head_body(raw).0.len();
    let delim = format!("--{boundary}").into_bytes();
    // Where each delimiter starts, in `raw`.
    let mut marks = Vec::new();
    let mut at = body_start;
    while let Some(i) = find(&raw[at..], &delim) {
        marks.push(at + i);
        at += i + delim.len();
    }
    let mut out = Vec::new();
    for pair in marks.windows(2) {
        let (start, end) = (pair[0] + delim.len(), pair[1]);
        let part = &raw[start..end];
        let Some(h) = find(part, b"\r\n\r\n") else { continue };
        let headers = String::from_utf8_lossy(&part[..h]);
        let Some(disposition) = headers.lines().find(|l| l.to_ascii_lowercase().starts_with("content-disposition"))
        else {
            continue;
        };
        let params: Vec<(String, String)> = disposition
            .split(';')
            .skip(1)
            .filter_map(|p| p.split_once('='))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string()))
            .collect();
        if params.iter().any(|(k, _)| k == "filename") {
            continue;
        }
        let Some((_, name)) = params.into_iter().find(|(k, _)| k == "name") else { continue };
        // The value runs to the CRLF before the next delimiter.
        let value_end = if part.ends_with(b"\r\n") { end - 2 } else { end };
        out.push((name, start + h + 4..value_end.max(start + h + 4)));
    }
    out
}

/// A multipart/form-data body with the (non-file) field `name` set to `value`; every
/// other byte (file parts included) stays as it was.
fn set_multipart(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let fields: Vec<_> = multipart_fields(raw).into_iter().filter(|(n, _)| n == name).collect();
    if fields.is_empty() {
        return raw.to_vec();
    }
    let mut out = raw.to_vec();
    for (_, range) in fields.into_iter().rev() {
        out.splice(range, value.bytes());
    }
    RawRequest::from_bytes(out).update_content_length().into_bytes()
}

/// Runs an extractor on a response.
pub fn extract(x: &Extractor, response: &[u8]) -> Option<String> {
    // The final response of any 1xx interim ones.
    let mut rest = response;
    let mut head = parse_response_head(rest).ok()?;
    while (100..200).contains(&head.status) && head.status != 101 {
        rest = split_head_body(rest).1;
        head = parse_response_head(rest).ok()?;
    }
    let body = || String::from_utf8_lossy(&decode_body(&head.headers, split_head_body(rest).1)).into_owned();
    let value = match x.from {
        ExtractFrom::Regex => {
            let re = Regex::new(&x.expr).ok()?;
            let text = response_text(rest);
            let c = re.captures(&text)?;
            c.get(1).or_else(|| c.get(0))?.as_str().to_string()
        }
        ExtractFrom::Json => json_path(&serde_json::from_str(&body()).ok()?, &x.expr)?,
        ExtractFrom::Header => head.header(&x.expr)?.to_string(),
        ExtractFrom::Cookie => {
            head.headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, v)| SetCookie::parse(v))
                .rev()
                .find(|c| c.name == x.expr)?
                .value
        }
        ExtractFrom::Input => {
            let html = body();
            let tags = crate::scan::passive::util::tags(&html);
            let input = tags.iter().find(|t| t.name == "input" && t.attr("name") == Some(&x.expr));
            match input {
                Some(t) => t.attr("value").unwrap_or("").to_string(),
                None => tags
                    .iter()
                    .find(|t| t.name == "meta" && t.attr("name") == Some(&x.expr))?
                    .attr("content")?
                    .to_string(),
            }
        }
    };
    Some(value)
}

/// A value by dotted path (`data.items.0.id`, or `data.items[0].id`); strings as
/// they are, other values as JSON.
fn json_path(v: &Value, path: &str) -> Option<String> {
    let mut cur = v;
    for key in path.replace('[', ".").replace(']', "").split('.').filter(|k| !k.is_empty()) {
        cur = match cur {
            Value::Array(a) => a.get(key.parse::<usize>().ok()?)?,
            _ => cur.get(key)?,
        };
    }
    Some(match cur {
        Value::String(s) => s.clone(),
        Value::Null => return None,
        other => other.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x(from: ExtractFrom, expr: &str) -> Extractor {
        Extractor { var: "v".into(), from, expr: expr.into() }
    }

    #[test]
    fn extractors() {
        let resp = b"HTTP/1.1 200 OK\r\nX-Token: abc\r\nSet-Cookie: sid=1; Path=/\r\nSet-Cookie: XSRF=xyz\r\n\
            Content-Type: text/html\r\n\r\n<form><input type=hidden value=\"t&amp;1\" name=\"csrf\"></form>\
            <meta name=\"csrf-token\" content=\"m1\">{\"no\":1}";
        assert_eq!(extract(&x(ExtractFrom::Input, "csrf"), resp).as_deref(), Some("t&1"));
        assert_eq!(extract(&x(ExtractFrom::Input, "csrf-token"), resp).as_deref(), Some("m1"));
        assert_eq!(extract(&x(ExtractFrom::Header, "x-token"), resp).as_deref(), Some("abc"));
        assert_eq!(extract(&x(ExtractFrom::Cookie, "XSRF"), resp).as_deref(), Some("xyz"));
        assert_eq!(extract(&x(ExtractFrom::Regex, r#"value="([^"]+)" name"#), resp).as_deref(), Some("t&amp;1"));
        assert_eq!(extract(&x(ExtractFrom::Input, "nope"), resp), None);
        let json = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"data\":{\"items\":[{\"id\":7},{\"t\":\"s\"}]}}";
        assert_eq!(extract(&x(ExtractFrom::Json, "data.items.0.id"), json).as_deref(), Some("7"));
        assert_eq!(extract(&x(ExtractFrom::Json, "data.items[1].t"), json).as_deref(), Some("s"));
        assert_eq!(extract(&x(ExtractFrom::Json, "data.none"), json), None);
    }

    #[test]
    fn actions_parse() {
        assert_eq!(Action::parse("check:10").unwrap(), Action::Check { every: 10 });
        assert_eq!(Action::parse("check").unwrap(), Action::Check { every: 1 });
        assert_eq!(Action::parse("macro:csrf:each").unwrap(), Action::RunMacro { name: "csrf".into(), every: 1 });
        assert_eq!(Action::parse("macro:csrf").unwrap(), Action::RunMacro { name: "csrf".into(), every: 0 });
        assert_eq!(Action::parse("macro:csrf:5").unwrap(), Action::RunMacro { name: "csrf".into(), every: 5 });
        assert_eq!(
            Action::parse("update:csrf, X-Token=tok").unwrap(),
            Action::Update { params: vec![("csrf".into(), "csrf".into()), ("X-Token".into(), "tok".into())] }
        );
        assert_eq!(Action::parse("update").unwrap(), Action::Update { params: vec![] });
        assert_eq!(Action::parse("login").unwrap(), Action::Login);
        assert_eq!(Action::parse("sign:api").unwrap(), Action::Sign { signer: "api".into() });
        assert!(Action::parse("sign").is_err());
        assert!(
            Action::parse("macro").is_err() && Action::parse("dance").is_err() && Action::parse("check:x").is_err()
        );
    }

    #[test]
    fn url_patterns() {
        let t = |u: &str| Target::from_url(u).unwrap();
        let host = UrlPattern::new("*.a.test").unwrap();
        assert!(host.matches(&t("https://a.test"), "https://a.test/"));
        assert!(host.matches(&t("https://x.A.test"), "https://x.a.test/"));
        assert!(!host.matches(&t("https://b.test"), "https://b.test/"));
        assert!(!host.matches(&t("https://xa.test"), "https://xa.test/"));
        let url = UrlPattern::new("https://a.test/api/*/edit").unwrap();
        assert!(url.matches(&t("https://a.test"), "https://a.test/api/7/edit?x=1"));
        assert!(!url.matches(&t("https://a.test"), "https://a.test/web/7/edit"));
        assert_eq!(request_url(b"GET /p?q=1 HTTP/1.1\r\n\r\n", &t("https://a.test")), "https://a.test/p?q=1");
    }

    #[test]
    fn params_are_set_in_every_place() {
        let ph = |enc: Enc| match enc {
            Enc::Raw => "R".to_string(),
            Enc::Form => "F".to_string(),
            Enc::Json => "J".to_string(),
        };
        let form = b"POST /x?csrf=old&a=1 HTTP/1.1\r\nHost: a\r\nCookie: csrf=c; s=1\r\nX-Csrf: h\r\n\
            Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 12\r\n\r\ncsrf=old&b=2";
        let out = String::from_utf8(set_param(form, "csrf", true, ph)).unwrap();
        assert!(out.starts_with("POST /x?csrf=F&a=1 HTTP/1.1\r\n"), "{out}");
        assert!(out.contains("Cookie: csrf=R; s=1\r\n") && out.contains("X-Csrf: h\r\n"), "{out}");
        assert!(out.ends_with("Content-Length: 10\r\n\r\ncsrf=F&b=2"), "{out}");
        // An attacked cookie keeps its payload; the parameters of that name still update.
        let out = String::from_utf8(set_param(form, "csrf", false, ph)).unwrap();
        assert!(out.contains("Cookie: csrf=c; s=1\r\n") && out.contains("?csrf=F&"), "{out}");
        let out = String::from_utf8(set_param(form, "X-Csrf", true, ph)).unwrap();
        assert!(out.contains("X-Csrf: R\r\n"), "{out}");
        let auth = b"GET / HTTP/1.1\r\nAuthorization: Bearer old\r\n\r\n";
        let out = String::from_utf8(set_param(auth, "Authorization", true, ph)).unwrap();
        assert!(out.contains("Authorization: Bearer R\r\n"), "{out}");
        let json =
            b"POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"meta\":{\"csrf\":\"o\"},\"csrf\":\"p\"}";
        let out = String::from_utf8(set_param(json, "csrf", true, ph)).unwrap();
        assert!(out.contains("\"csrf\":\"J\"") && out.contains("{\"csrf\":\"J\"}") && !out.contains("\"o\""), "{out}");
        let mp = b"POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=XX\r\n\r\n--XX\r\n\
            Content-Disposition: form-data; name=\"csrf\"\r\n\r\nold\r\n--XX\r\n\
            Content-Disposition: form-data; name=\"f\"; filename=\"csrf\"\r\n\r\ndata\r\n--XX--\r\n";
        let out = String::from_utf8(set_param(mp, "csrf", true, ph)).unwrap();
        assert!(out.contains("name=\"csrf\"\r\n\r\nR\r\n--XX") && out.contains("\r\n\r\ndata\r\n"), "{out}");
        // A binary file part stays byte for byte.
        let mut bin = b"POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=\"XX\"\r\n\r\n--XX\r\n\
            Content-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n\r\n"
            .to_vec();
        bin.extend_from_slice(&[0xff, 0x00, 0xfe, 0xc3]);
        bin.extend_from_slice(b"\r\n--XX\r\nContent-Disposition: form-data; name=csrf\r\n\r\nold\r\n--XX--\r\n");
        let out = set_param(&bin, "csrf", true, ph);
        assert!(find(&out, &[0xff, 0x00, 0xfe, 0xc3, b'\r']).is_some());
        assert!(find(&out, b"name=csrf\r\n\r\nR\r\n--XX--").is_some(), "{}", String::from_utf8_lossy(&out));
        assert_eq!(multipart_fields(&bin).iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["csrf"]);
    }

    #[test]
    fn rule_updates_win_over_the_profile_but_not_over_an_attack() {
        let dir = std::env::temp_dir().join(format!("bp-session-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let scope = crate::guard::ScopeSpec { name: None, include: vec!["a.test".into()], exclude: vec![] };
        let opts = crate::http::SendOptions {
            guard: Some(crate::guard::Guard::from_specs(vec![scope]).unwrap()),
            ..Default::default()
        };
        let profile =
            AuthProfile { name: "t".into(), headers: vec![("X-Csrf".into(), "static".into())], ..Default::default() };
        let state = crate::auth::SessionState {
            vars: vec![SessionVar {
                name: "csrf".into(),
                value: "v1".into(),
                run: 1,
                origins: vec!["https://a.test".into()],
                home: vec!["https://a.test".into()],
            }],
            ..Default::default()
        };
        let update = Action::Update { params: vec![("X-Csrf".into(), "csrf".into()), ("csrf".into(), "csrf".into())] };
        let rule = SessionRule {
            id: 1,
            description: String::new(),
            tools: vec![Tool::Scan],
            url: None,
            actions: vec![update],
            invalid: None,
        };
        let s = AuthSession::new(&dir.join("p.bpdb"), profile, state, crate::http::Client::new(opts))
            .unwrap()
            .with_handling(Handling { rules: vec![rule], ..Default::default() })
            .unwrap();
        let target = Target::from_url("https://a.test").unwrap();
        let raw = b"GET /?csrf=old HTTP/1.1\r\nHost: a.test\r\nCookie: csrf=PAYLOAD\r\nX-Csrf: x\r\n\r\n";
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let p = rt.block_on(s.prepare(Tool::Scan, &target, raw, &["csrf"], &[]));
        let out = String::from_utf8(p.request).unwrap();
        assert!(out.starts_with("GET /?csrf=«auth:t:var:csrf#1:form» HTTP/1.1\r\n"), "{out}");
        assert!(out.contains("X-Csrf: «auth:t:var:csrf#1»\r\n"), "{out}");
        assert!(out.contains("Cookie: csrf=PAYLOAD\r\n"), "{out}");
        // Another tool: no rule, the profile's header.
        let p = rt.block_on(s.prepare(Tool::Fuzz, &target, raw, &[], &[]));
        assert!(String::from_utf8(p.request).unwrap().contains("X-Csrf: «auth:t:header:X-Csrf»\r\n"));
    }

    #[test]
    fn templates_fill_known_vars_for_their_place() {
        let tpl = "POST /a?t={{tok}} HTTP/1.1\nX-T: {{tok}}\nContent-Type: application/json\n\n{\"t\":\"{{tok}}\",\"o\":\"{{other}}\"}";
        let out = fill_vars(tpl, |v, enc| {
            (v == "tok").then(|| match enc {
                Enc::Form => "F".into(),
                Enc::Json => "J".into(),
                Enc::Raw => "R".into(),
            })
        });
        assert_eq!(
            out,
            "POST /a?t=F HTTP/1.1\nX-T: R\nContent-Type: application/json\n\n{\"t\":\"J\",\"o\":\"{{other}}\"}"
        );
    }

    #[test]
    fn run_placeholders_fall_back_to_the_latest_value() {
        assert_eq!(latest_placeholder("«auth:p:var:csrf#12:form»").as_deref(), Some("«auth:p:var:csrf:form»"));
        assert_eq!(latest_placeholder("«auth:p:var:csrf#12»").as_deref(), Some("«auth:p:var:csrf»"));
        assert_eq!(latest_placeholder("«auth:p:cookie:sid»"), None);
        assert_eq!(var_kind("t", Some(3), Enc::Json), "var:t#3:json");
        assert_eq!(mask("abcdefghijklmnop"), "abcd… (16 chars)");
        assert_eq!(mask("short"), "******** (5 chars)");
    }
}
