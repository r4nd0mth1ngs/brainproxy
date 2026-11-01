//! Authentication profiles: how to log in, and the live session that other
//! commands use with `--auth NAME`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use brainproxy_core::auth::{AuthProfile, AuthSession, QueryKey, Secret, SessionState};
use brainproxy_core::auth_record::{Mode, Recorded};
use brainproxy_core::http::{Client, RawRequest, SendOptions, Target};
use brainproxy_core::session::{Action, ExtractFrom, Extractor, Macro, MacroStep, SessionRule, Tool};
use brainproxy_core::sign::{HmacAlg, JwtAlg, KeySource, Place, SignKind, Signer};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::{Args, Subcommand};
use serde_json::json;

use crate::output::Out;

#[derive(Subcommand)]
pub enum AuthCmd {
    /// Add or replace a profile. Use it with `--auth NAME` on send, fuzz, crawl,
    /// scan active, and proxy start. For a session with no login, start with `auth macro add`.
    #[command(after_help = "Form login: --login-url URL --login-body 'user={{username}}&pass={{password}}' \
        --username alice --password-env APP_PW. JSON bodies (starting with '{') are sent as application/json.\n\
        CSRF: --csrf-url PAGE --csrf-regex 'name=\"csrf\" value=\"([^\"]+)\"' fills {{csrf}}.\n\
        Bearer token: --token-regex '\"token\":\"([^\"]+)\"' --token-header 'Authorization: Bearer {{token}}'.\n\
        Static API key only: --header 'X-Api-Key: ...', or --header-env 'X-Api-Key=ENV_VAR' to keep it off the \
        command line (no --login-url). A bearer token is --header-env 'Authorization=ENV_VAR' with the value \
        'Bearer abc' in the variable. In the query string: --query-key 'api_key=ENV_VAR' --key-origin https://api.test; \
        history keeps a placeholder, and the key goes only to the origins given.\n\
        Platform auth (HTTP Basic, Digest, NTLM): --platform ntlm --platform-host '*.corp.test' --username 'CORP\\bob' \
        --password-env BOB_PW. It answers those hosts' 401 challenges on every command, no --auth needed, and is added \
        on the wire only (history keeps the request without it).\n\
        Logout detection: a 401, a redirect to the login path, or --logged-out REGEX triggers an automatic re-login.")]
    Add(Box<AddArgs>),
    /// Log in now and store the session.
    Login {
        name: String,
        #[command(flatten)]
        net: NetArgs,
    },
    /// Stored session state; with a check URL, also fetch it to see if the session is still valid.
    Status {
        name: String,
        /// Don't contact the check URL; only report the stored state.
        #[arg(long)]
        offline: bool,
        #[command(flatten)]
        net: NetArgs,
    },
    /// The Cookie and auth headers the session adds (for external tools such as sqlmap or ffuf).
    Headers {
        name: String,
        /// Print "Name: value" lines with no envelope.
        #[arg(long)]
        raw: bool,
        /// Log in first if there is no session yet.
        #[arg(long)]
        login: bool,
        #[command(flatten)]
        net: NetArgs,
    },
    /// All profiles with their session state.
    List,
    /// One profile (password and header values redacted).
    Show { name: String },
    /// Delete a profile and its session.
    Remove { name: String },
    /// Build a profile by logging in once in a browser: `record start URL`, log in and
    /// open a page only a logged-in user sees, then `record finish NAME --save`.
    #[command(subcommand)]
    Record(RecordCmd),
    /// A profile's macros: requests run in order that extract values (a CSRF token, a
    /// one-time code) for later steps and for session rules.
    #[command(subcommand)]
    Macro(MacroCmd),
    /// A profile's session rules: what to do before requests of some tools to some URLs
    /// go out with `--auth NAME` (check the session, run a macro, update the request, log in).
    #[command(subcommand)]
    Rule(RuleCmd),
    /// A profile's request signers: HMAC signatures and JWTs computed as requests go out,
    /// for a session rule's `sign:NAME` action. Keys stay in the environment or a file.
    #[command(subcommand)]
    Sign(SignCmd),
}

#[derive(Subcommand)]
pub enum MacroCmd {
    /// Add or replace a macro. A profile that doesn't exist yet is made, with no login.
    #[command(after_help = "Steps run in the order given, with the profile's session; cookies carry \
        through. --step takes a history id, a raw request FILE (sent to its Host over --scheme), or \
        ORIGIN=FILE (e.g. https://app.test:8443=req.txt).\n\
        --extract STEP:VAR=KIND:EXPR takes a value from step STEP's response into VAR. KIND is regex \
        (group 1), json (a path like data.token or items.0.id), header, cookie (a Set-Cookie), or input \
        (an HTML <input name=EXPR>, or <meta name=EXPR content=...>).\n\
        Later steps use a value as {{VAR}} (also {{username}} and {{password}}), and their parameters \
        named VAR get it too. Example:\n  \
        brainproxy auth macro add app csrf --step 12 --extract '1:csrf=input:csrf'")]
    Add {
        profile: String,
        /// Macro name.
        name: String,
        /// A step: history id, FILE, or ORIGIN=FILE. Repeatable, in order.
        #[arg(long = "step", required = true)]
        steps: Vec<String>,
        /// STEP:VAR=KIND:EXPR. Repeatable.
        #[arg(long = "extract")]
        extract: Vec<String>,
        /// Scheme for FILE steps whose request line has no absolute URL.
        #[arg(long, default_value = "https")]
        scheme: String,
    },
    /// The profile's macros.
    List { profile: String },
    /// One macro with its requests and extractors.
    Show { profile: String, name: String },
    /// Run a macro now: each step's request, status, history id, and the values it
    /// extracted (masked). The values become the session's latest.
    Run {
        profile: String,
        name: String,
        #[command(flatten)]
        net: NetArgs,
    },
    /// Delete a macro (refused while a session rule runs it).
    Remove { profile: String, name: String },
}

#[derive(Subcommand)]
pub enum RuleCmd {
    /// Add a session rule; its actions run in order before each matching request.
    #[command(after_help = "Actions (--action, repeatable, in order):\n  \
        check[:N]               fetch the profile's check URL (every Nth request); valid skips the rest\n  \
        macro:NAME[:each|:N]    run a macro: once and again when its values go stale (default), on \
        every request, or every Nth\n  \
        update[:P[=VAR],...]    put macro values into the request: each query, form, JSON or multipart \
        parameter, header or cookie P gets VAR (default: the variables of this rule's macros, into \
        parameters of their names)\n  \
        login                   log in again with the profile if the session is not logged in\n  \
        sign:NAME               sign the request as it goes out, with a signer of `auth sign add`\n\
        A response that looks logged out, or matches --invalid, refreshes the rule's macros (and \
        logs in again) and the request is sent once more.\n\
        Fresh CSRF token per request during a scan or fuzz run:\n  \
        brainproxy auth rule add app --tool scan,fuzz --action macro:csrf:each --action update:csrf\n\
        Re-login when a check every 20 requests fails:\n  \
        brainproxy auth rule add app --action check:20 --action login")]
    Add {
        profile: String,
        /// check[:N], macro:NAME[:each|:N], update[:PARAM[=VAR],...], login, or sign:NAME. Repeatable, in order.
        #[arg(long = "action", required = true)]
        actions: Vec<String>,
        /// Only for these tools: proxy, send, fuzz, crawl (also import), scan, checks (default: all).
        #[arg(long = "tool", value_delimiter = ',')]
        tools: Vec<String>,
        /// Only for requests to this host pattern (*.example.com) or URL prefix (https://example.com/api/).
        /// Without it, macro values only go to the origins of the macro that extracted them.
        #[arg(long)]
        url: Option<String>,
        /// Regex marking a response rejected for stale values (e.g. "invalid csrf"): refresh and resend.
        #[arg(long)]
        invalid: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// The profile's session rules, in the order they run.
    List { profile: String },
    /// Delete a session rule by id.
    Remove { profile: String, id: u32 },
}

#[derive(Subcommand)]
pub enum SignCmd {
    /// Add or replace a signer. A profile that doesn't exist yet is made, with no login.
    /// Add a rule with `--action sign:NAME` to use it.
    #[command(after_help = "Templates (--canonical, --claims, --set-header) can use {{method}}, {{host}}, \
        {{path}}, {{query}}, {{body}}, {{body_sha256}}, {{body_sha256_base64}}, {{timestamp}}, \
        {{timestamp_ms}}, {{nonce}} and {{header:NAME}}. In --canonical, \\n \\r \\t and \\\\ are read \
        as escapes. The value is computed last, over the request as it is sent; history keeps a placeholder.\n\
        An HMAC of the request, with the time it covers in its own header:\n  \
        brainproxy auth sign add api hm --secret-env API_SECRET --origin https://api.test \\\n    \
        --to header:X-Signature --set-header 'X-Timestamp: {{timestamp}}' \\\n    \
        --canonical '{{method}}\\n{{path}}\\n{{query}}\\n{{header:X-Timestamp}}\\n{{body_sha256}}'\n  \
        brainproxy auth rule add api --action sign:hm\n\
        A JWT with chosen claims, good for five minutes:\n  \
        brainproxy auth sign add api tok --jwt HS256 --secret-env JWT_KEY --origin https://api.test \\\n    \
        --to header:Authorization --wrap 'Bearer {{signature}}' --claims '{\"sub\":\"admin\"}' --ttl 300")]
    Add(Box<SignAddArgs>),
    /// The profile's signers (they hold where a key is, not the key).
    List { profile: String },
    /// Delete a signer (refused while a session rule uses it).
    Remove { profile: String, name: String },
}

#[derive(Args)]
pub struct SignAddArgs {
    pub profile: String,
    /// Signer name.
    pub name: String,
    /// Environment variable holding the key (never stored).
    #[arg(long, conflicts_with = "secret_file", required_unless_present = "secret_file")]
    pub secret_env: Option<String>,
    /// File holding the key (never stored), e.g. a PEM private key for RS256.
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    /// How the key is written: raw, hex, or base64.
    #[arg(long, default_value = "raw")]
    pub secret_encoding: String,
    /// Origin it may sign for (scheme://host[:port]). Repeatable.
    #[arg(long = "origin", required = true)]
    pub origins: Vec<String>,
    /// Where the value goes: header:NAME or query:NAME.
    #[arg(long)]
    pub to: String,
    /// A header's value around the signature, e.g. 'Bearer {{signature}}'.
    #[arg(long)]
    pub wrap: Option<String>,
    /// 'NAME: TEMPLATE' header set before signing. Repeatable.
    #[arg(long = "set-header")]
    pub set_headers: Vec<String>,
    /// The string to HMAC.
    #[arg(long, conflicts_with = "jwt", required_unless_present = "jwt")]
    pub canonical: Option<String>,
    /// HMAC hash: sha1, sha256, sha384, or sha512.
    #[arg(long, default_value = "sha256", conflicts_with = "jwt")]
    pub hash: String,
    /// HMAC output: hex, base64, or base64url.
    #[arg(long, default_value = "hex", conflicts_with = "jwt")]
    pub output: String,
    /// Make a JWT with this algorithm: HS256, HS384, HS512, or RS256.
    #[arg(long)]
    pub jwt: Option<String>,
    /// JWT claims, a JSON object template.
    #[arg(long, requires = "jwt", default_value = "{}")]
    pub claims: String,
    /// Seconds a JWT is valid: sets iat and exp unless the claims do.
    #[arg(long, requires = "jwt")]
    pub ttl: Option<u64>,
    /// JWT kid header.
    #[arg(long, requires = "jwt")]
    pub kid: Option<String>,
    /// Start from the JWT already in the request (its header and claims, --claims on top).
    #[arg(long, requires = "jwt")]
    pub resign: bool,
    /// Replacing a signer, keep its place in the order instead of running it last.
    #[arg(long)]
    pub keep_place: bool,
}

#[derive(Subcommand)]
pub enum RecordCmd {
    /// Open a fresh browser profile at URL through the running proxy and start recording.
    Start {
        /// Login page (or the site's start page).
        url: String,
        /// Browser id from `browser list` (default: the first one found).
        #[arg(long)]
        browser: Option<String>,
    },
    /// Turn what the proxy recorded since `start` into a profile: the login request with
    /// placeholders, its CSRF token and where it comes from, a bearer token, and logged-in
    /// and logged-out checks. Single sign-on and one-time codes give a session profile.
    Finish {
        /// Profile name.
        name: String,
        /// Save the profile (else only show what was found).
        #[arg(long)]
        save: bool,
        /// Read the password from this environment variable at login instead of storing
        /// the recorded one in the project.
        #[arg(long)]
        password_env: Option<String>,
        /// Analyze history after this id instead of since `record start`.
        #[arg(long)]
        since: Option<i64>,
    },
}

#[derive(clap::Args)]
pub struct AddArgs {
    /// Profile name.
    name: String,
    /// Login endpoint. Without it the profile only adds --header values.
    #[arg(long)]
    login_url: Option<String>,
    /// Login method.
    #[arg(long, default_value = "POST")]
    login_method: String,
    /// Login body with {{username}}, {{password}}, and {{csrf}} placeholders (encoded for the body type).
    #[arg(long)]
    login_body: Option<String>,
    /// Raw login request file used instead of --login-method/--login-body (placeholders allowed);
    /// sent to the --login-url origin.
    #[arg(long, value_name = "FILE")]
    login_request: Option<String>,
    /// Header for the login request only ("Name: value"). Repeatable.
    #[arg(long)]
    login_header: Vec<String>,
    #[arg(long)]
    username: Option<String>,
    /// Password stored in the project file. Prefer --password-env. Also read from
    /// BRAINPROXY_SECRET_PASSWORD, which keeps it off the command line (the desktop app uses it).
    #[arg(long, conflicts_with = "password_env", env = "BRAINPROXY_SECRET_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// Environment variable holding the password, read at each login; never stored.
    #[arg(long)]
    password_env: Option<String>,
    /// Page fetched before login to extract a CSRF token.
    #[arg(long)]
    csrf_url: Option<String>,
    /// Regex extracting the CSRF token from --csrf-url (group 1).
    #[arg(long)]
    csrf_regex: Option<String>,
    /// Regex extracting a token from the login response (group 1).
    #[arg(long)]
    token_regex: Option<String>,
    /// Header carrying the token, e.g. "Authorization: Bearer {{token}}".
    #[arg(long)]
    token_header: Option<String>,
    /// Regex that only matches logged-in pages (verifies the login).
    #[arg(long)]
    logged_in: Option<String>,
    /// Regex that matches a logged-out response (login form, "session expired").
    #[arg(long)]
    logged_out: Option<String>,
    /// URL fetched to verify the session after login and by `auth status`.
    #[arg(long)]
    check_url: Option<String>,
    /// Header added to every request (API key, static bearer token). Repeatable.
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// NAME=ENV_VAR: a header like --header, its value read once from the environment
    /// variable and stored in the project. Repeatable.
    #[arg(long = "header-env", value_name = "NAME=ENV_VAR")]
    header_env: Vec<String>,
    /// NAME=ENV_VAR: an API key sent as this query parameter, read once from the environment
    /// variable and stored in the project. Needs --key-origin. Repeatable.
    #[arg(long = "query-key", value_name = "NAME=ENV_VAR", requires = "key_origins")]
    query_keys: Vec<String>,
    /// An origin (scheme://host[:port]) the --query-key values may go to. Repeatable.
    #[arg(long = "key-origin", value_name = "ORIGIN", requires = "query_keys")]
    key_origins: Vec<String>,
    /// When replacing a profile, keep its --query-key values. For an edit that can't see them.
    #[arg(long, conflicts_with = "query_keys")]
    keep_query_keys: bool,
    /// Minimum seconds between automatic re-logins.
    #[arg(long, default_value_t = 5)]
    relogin_interval: u64,
    /// Maximum automatic re-logins per command run.
    #[arg(long, default_value_t = 20)]
    max_relogins: u32,
    /// Platform authentication with --username and the password: answer this scheme's 401
    /// challenges from --platform-host hosts on every command.
    #[arg(long, value_parser = ["basic", "digest", "ntlm"], requires = "platform_host")]
    platform: Option<String>,
    /// Host pattern platform auth is offered to (host, *.domain, *, optional :port). Repeatable.
    #[arg(long, requires = "platform")]
    platform_host: Vec<String>,
    /// NTLM domain (else taken from a DOMAIN\user username).
    #[arg(long, requires = "platform")]
    domain: Option<String>,
}

/// Network options for commands that log in.
#[derive(clap::Args)]
pub struct NetArgs {
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    #[arg(long)]
    verify_tls: bool,
}

impl NetArgs {
    fn send_options(&self, project: &Path) -> Result<SendOptions, Error> {
        Ok(SendOptions {
            timeout: Duration::from_secs_f64(self.timeout.max(0.1)),
            verify_tls: self.verify_tls,
            sni: None,
            guard: Some(crate::project_guard(project)?),
            http2: false,
        })
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    Ok(tokio::runtime::Builder::new_current_thread().enable_all().build()?)
}

/// Loads a profile's session on a guarded client, logging in if it has no
/// session yet. Commands call `save()` on it when they finish.
pub fn load_session(project: &Path, name: &str, send: SendOptions) -> Result<Arc<AuthSession>, Error> {
    let session = AuthSession::load(project, name, Client::new(send))?;
    runtime()?.block_on(session.ensure())?;
    Ok(Arc::new(session))
}

/// `load_session` for an optional `--auth NAME`.
pub fn maybe_session(
    project: &Path,
    name: Option<&str>,
    send: &SendOptions,
) -> Result<Option<Arc<AuthSession>>, Error> {
    name.map(|n| load_session(project, n, send.clone())).transpose()
}

/// `NAME=ENV_VAR` with the variable read. Errors name the variable, never a value.
fn env_pair(flag: &str, spec: &str) -> Result<(String, String), Error> {
    let bad = || Error::InvalidInput(format!("{flag} {spec:?}: expected NAME=ENV_VAR"));
    let (name, var) = spec.split_once('=').ok_or_else(bad)?;
    let (name, var) = (name.trim(), var.trim());
    if name.is_empty() || var.is_empty() {
        return Err(bad());
    }
    let value = std::env::var(var).map_err(|_| Error::InvalidInput(format!("{flag}: {var} is not set")))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidInput(format!("{flag}: {var} is empty")));
    }
    if value.contains(['\r', '\n', '\0']) {
        return Err(Error::InvalidInput(format!("{flag}: {var} holds a line break")));
    }
    Ok((name.to_string(), value.to_string()))
}

fn state_json(state: &SessionState) -> serde_json::Value {
    json!({
        "logged_in": state.logged_in,
        "cookies": state.cookies.iter().map(|(k, _)| k).collect::<Vec<_>>(),
        "token": state.token.is_some(),
        "last_login": state.last_login,
        "last_error": state.last_error,
        "vars": state.vars.iter().map(|v| &v.name).collect::<Vec<_>>(),
    })
}

pub fn auth(project: &Path, home: &Path, cmd: AuthCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        AuthCmd::Record(cmd) => record(project, home, cmd, out)?,
        AuthCmd::Macro(cmd) => macro_cmd(project, cmd, out)?,
        AuthCmd::Rule(cmd) => rule_cmd(project, cmd, out)?,
        AuthCmd::Sign(cmd) => sign_cmd(project, cmd, out)?,
        AuthCmd::Add(a) => {
            let parse = |list: &[String]| {
                list.iter().map(|h| crate::request_args::parse_header(h)).collect::<Result<Vec<_>, _>>()
            };
            let login_request = a
                .login_request
                .as_deref()
                .map(|f| {
                    std::fs::read_to_string(f)
                        .map_err(|e| Error::InvalidInput(format!("cannot read login request {f:?}: {e}")))
                })
                .transpose()?;
            if login_request.is_some() && a.login_url.is_none() {
                return Err(Error::InvalidInput("--login-request needs --login-url (where to send it)".into()));
            }
            let mut headers = parse(&a.headers)?;
            for spec in &a.header_env {
                let (name, value) = env_pair("--header-env", spec)?;
                if name.is_empty() || name.contains([':', ' ', '\r', '\n']) {
                    return Err(Error::InvalidInput(format!("--header-env: bad header name {name:?}")));
                }
                headers.push((name, value));
            }
            let origins =
                a.key_origins.iter().map(|o| Target::from_url(o).map(|t| t.origin())).collect::<Result<Vec<_>, _>>()?;
            let query_keys = a
                .query_keys
                .iter()
                .map(|spec| {
                    let (name, value) = env_pair("--query-key", spec)?;
                    Ok(QueryKey { name, value, origins: origins.clone() })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let mut profile = AuthProfile {
                name: a.name,
                login_url: a.login_url,
                login_method: a.login_method.to_ascii_uppercase(),
                login_body: a.login_body,
                login_request,
                login_headers: parse(&a.login_header)?,
                username: a.username,
                password: a.password.map(Secret::Literal).or(a.password_env.map(Secret::Env)),
                csrf_url: a.csrf_url,
                csrf_regex: a.csrf_regex,
                token_regex: a.token_regex,
                token_header: a.token_header,
                logged_in: a.logged_in,
                logged_out: a.logged_out,
                check_url: a.check_url,
                headers,
                query_keys,
                relogin_interval_secs: a.relogin_interval,
                max_relogins: a.max_relogins,
                platform: a
                    .platform
                    .as_deref()
                    .map(|scheme| -> Result<_, Error> {
                        Ok(brainproxy_core::connection::PlatformAuth {
                            scheme: brainproxy_core::connection::PlatformScheme::parse(scheme)?,
                            hosts: a.platform_host.clone(),
                            domain: a.domain.clone(),
                        })
                    })
                    .transpose()?,
            };
            let store = Store::open(project)?;
            // `auth show` redacts header values; re-saving one unchanged (the GUI's edit form does)
            // keeps the stored value instead of storing the mask.
            if let Ok((old, _)) = store.auth_profile(&profile.name) {
                for (k, v) in &mut profile.headers {
                    if let Some((_, stored)) =
                        old.headers.iter().find(|(o, _)| v == "********" && o.eq_ignore_ascii_case(k))
                    {
                        *v = stored.clone();
                    }
                }
                if a.keep_query_keys {
                    profile.query_keys = old.query_keys;
                }
            }
            store.auth_save_profile(&profile)?;
            let shown = profile.redacted();
            out.ok(json!({"profile": shown, "next": format!("brainproxy auth login {}", shown.name)}), || {
                format!("profile {:?} saved; run: brainproxy auth login {}", shown.name, shown.name)
            });
        }
        AuthCmd::Login { name, net } => {
            let session = AuthSession::load(project, &name, Client::new(net.send_options(project)?))?;
            let r = runtime()?.block_on(session.login())?;
            let data = json!({"name": name, "login": r, "session": state_json(&session.state())});
            if !r.success {
                // Report the details, then fail with a stable exit code.
                return Err(Error::InvalidInput(format!(
                    "login failed: {} (requests: {:?}; inspect with history show ID)",
                    r.reason, r.history_ids
                )));
            }
            out.ok(data, || format!("logged in as {name}: {} (cookies: {})", r.reason, r.cookies.join(", ")));
        }
        AuthCmd::Status { name, offline, net } => {
            let (profile, state) = Store::open(project)?.auth_profile(&name)?;
            let mut data = json!({"name": name, "has_login": profile.has_login(), "session": state_json(&state)});
            if !offline && profile.check_url.is_some() {
                let session = AuthSession::new(project, profile, state, Client::new(net.send_options(project)?))?;
                let check = runtime()?.block_on(session.check())?;
                session.save()?;
                data["check"] = json!(check);
                data["session"] = state_json(&session.state());
            }
            out.ok(data.clone(), || {
                let live = data["check"]["logged_in"].as_bool();
                let stored = data["session"]["logged_in"].as_bool().unwrap_or(false);
                format!(
                    "{name}: {}{}",
                    if stored { "logged in" } else { "not logged in" },
                    live.map(|l| format!(" (check URL: {})", if l { "valid" } else { "logged out" }))
                        .unwrap_or_default()
                )
            });
        }
        AuthCmd::Headers { name, raw, login, net } => {
            let send = net.send_options(project)?;
            let session = if login {
                load_session(project, &name, send)?
            } else {
                Arc::new(AuthSession::load(project, &name, Client::new(send))?)
            };
            let headers = session.headers();
            if raw {
                let text: String = headers.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
                out.raw(text.as_bytes());
                return Ok(());
            }
            let data = json!({
                "name": name,
                "logged_in": session.state().logged_in,
                "headers": headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>(),
            });
            out.ok(data, || headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n"));
        }
        AuthCmd::List => {
            let items: Vec<_> = Store::open(project)?
                .auth_list()?
                .into_iter()
                .map(|(p, s)| {
                    json!({"name": p.name, "login_url": p.login_url, "username": p.username, "session": state_json(&s)})
                })
                .collect();
            out.ok(json!({"profiles": items}), || {
                items
                    .iter()
                    .map(|i| {
                        format!(
                            "{:<20} {:<14} {}",
                            i["name"].as_str().unwrap_or(""),
                            if i["session"]["logged_in"] == true { "logged in" } else { "not logged in" },
                            i["login_url"].as_str().unwrap_or("(headers only)")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        AuthCmd::Show { name } => {
            let store = Store::open(project)?;
            let (profile, state) = store.auth_profile(&name)?;
            let handling = store.auth_handling(&name)?;
            let data = json!({
                "profile": profile.redacted(),
                "session": state_json(&state),
                "macros": handling.macros.iter().map(macro_summary).collect::<Vec<_>>(),
                "rules": handling.rules,
                "signers": handling.signers,
            });
            out.ok(data.clone(), || serde_json::to_string_pretty(&data).unwrap_or_default());
        }
        AuthCmd::Remove { name } => {
            Store::open(project)?.auth_remove(&name)?;
            out.ok(json!({"name": name, "removed": true}), || format!("profile {name:?} removed"));
        }
    }
    Ok(())
}

const RECORD_KEY: &str = "auth.record";

fn record(project: &Path, home: &Path, cmd: RecordCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        RecordCmd::Start { url, browser } => {
            let guard = crate::project_guard(project)?;
            crate::require_in_scope(&guard, &brainproxy_core::http::Target::from_url(&url)?)?;
            let since = store.last_history_id()?;
            let found = crate::browser_cmd::find();
            let (browser, _) = crate::browser_cmd::open(project, home, &found, browser, url.clone(), Some("login"))?;
            store.meta_set(RECORD_KEY, Some(&json!({"since": since, "url": url}).to_string()))?;
            let data = json!({"since": since, "url": url, "browser": browser});
            out.ok(data, || {
                format!(
                    "Recording from history #{since}. Log in in the browser, open a page only a logged-in user sees, then: \
                     brainproxy auth record finish NAME --save"
                )
            });
        }
        RecordCmd::Finish { name, save, password_env, since } => {
            let started: serde_json::Value =
                store.meta_get(RECORD_KEY)?.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            let since = since.or_else(|| started["since"].as_i64()).ok_or_else(|| {
                Error::InvalidInput(
                    "no recording started; run `auth record start URL` first (or pass --since ID)".into(),
                )
            })?;
            let entries = store.list(&brainproxy_core::store::HistoryFilter {
                after_id: Some(since),
                source: Some("proxy".into()),
                limit: Some(5000),
                ..Default::default()
            })?;
            if entries.is_empty() {
                return Err(Error::NotFound(format!(
                    "no proxied requests after history #{since}; was the browser opened with `auth record start`?"
                )));
            }
            let recorded: Vec<Recorded> = entries
                .iter()
                .filter_map(|e| store.get(e.id).ok())
                .map(|h| Recorded { id: h.entry.id, target: h.target, request: h.request, response: h.response })
                .collect();
            let mut p = brainproxy_core::auth_record::analyze(&recorded, &name, started["url"].as_str());
            if let Some(var) = &password_env {
                if p.profile.password.is_some() {
                    p.profile.password = Some(Secret::Env(var.clone()));
                }
            }
            if save {
                p.profile.validate()?;
                store.auth_save_profile(&p.profile)?;
                store.meta_set(RECORD_KEY, None)?;
            }
            let data = json!({
                "saved": save,
                "recorded": recorded.len(),
                "mode": p.mode,
                "profile": p.profile.redacted(),
                "evidence": p.evidence,
                "found": p.found,
                "warnings": p.warnings,
            });
            out.ok(data, || {
                let mut lines = vec![format!(
                    "{} profile {name} from {} recorded requests{}",
                    match p.mode {
                        Mode::Replay => "Login",
                        Mode::Session => "Session-only",
                    },
                    recorded.len(),
                    if save { " (saved)" } else { " (not saved; add --save)" }
                )];
                lines.extend(p.found.iter().map(|f| format!("  found: {f}")));
                lines.extend(p.warnings.iter().map(|w| format!("  note:  {w}")));
                lines.join("\n")
            });
        }
    }
    Ok(())
}

fn macro_summary(m: &Macro) -> serde_json::Value {
    json!({
        "name": m.name,
        "steps": m.steps.len(),
        "vars": m.vars(),
        "requests": m.steps.iter().map(step_line).collect::<Vec<_>>(),
    })
}

/// "METHOD URL" of a macro step.
fn step_line(s: &MacroStep) -> String {
    let line = s.request.lines().next().unwrap_or("");
    let mut parts = line.split(' ');
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if path.starts_with("http://") || path.starts_with("https://") {
        format!("{method} {path}")
    } else {
        format!("{method} {}{path}", s.target.trim_end_matches('/'))
    }
}

/// A macro step from `--step`: a history id, FILE, or ORIGIN=FILE.
fn read_step(store: &Store, spec: &str, scheme: &str) -> Result<MacroStep, Error> {
    if let Ok(id) = spec.trim().parse::<i64>() {
        let h = store.get(id)?;
        return Ok(MacroStep {
            target: h.target.origin(),
            request: String::from_utf8_lossy(&h.request).into_owned(),
            history_id: Some(id),
            extract: vec![],
        });
    }
    let (origin, file) = match spec.split_once('=') {
        Some((o, f)) if o.starts_with("http://") || o.starts_with("https://") => (Some(o), f),
        _ => (None, spec),
    };
    let text = std::fs::read_to_string(file)
        .map_err(|e| Error::InvalidInput(format!("cannot read macro step {file:?}: {e}")))?;
    let target = match origin {
        Some(o) => Target::from_url(o)?,
        None => RawRequest::from_bytes(text.clone().into_bytes()).infer_target(scheme)?,
    };
    Ok(MacroStep { target: target.origin(), request: text, history_id: None, extract: vec![] })
}

/// `STEP:VAR=KIND:EXPR`.
fn parse_extract(spec: &str) -> Result<(usize, Extractor), Error> {
    let bad =
        || Error::InvalidInput(format!("--extract {spec:?}: expected STEP:VAR=KIND:EXPR, e.g. 1:csrf=input:csrf"));
    let (step, rest) = spec.split_once(':').ok_or_else(bad)?;
    let (var, rest) = rest.split_once('=').ok_or_else(bad)?;
    let (kind, expr) = rest.split_once(':').ok_or_else(bad)?;
    let step = step.trim().parse::<usize>().map_err(|_| bad())?;
    let x = Extractor { var: var.trim().to_string(), from: ExtractFrom::parse(kind)?, expr: expr.to_string() };
    Ok((step, x))
}

fn macro_cmd(project: &Path, cmd: MacroCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        MacroCmd::Add { profile, name, steps, extract, scheme } => {
            let mut h = store.auth_handling(&profile)?;
            let mut m = Macro {
                name: name.clone(),
                steps: steps.iter().map(|s| read_step(&store, s, &scheme)).collect::<Result<_, _>>()?,
            };
            for spec in &extract {
                let (step, x) = parse_extract(spec)?;
                let n = m.steps.len();
                let s = step
                    .checked_sub(1)
                    .and_then(|i| m.steps.get_mut(i))
                    .ok_or_else(|| Error::InvalidInput(format!("--extract {spec:?}: the macro has steps 1 to {n}")))?;
                s.extract.push(x);
            }
            let replaced = h.macros.iter().any(|o| o.name == name);
            h.macros.retain(|o| o.name != name);
            h.macros.push(m.clone());
            // A macro can start a profile with no login; `auth add` can set its options after.
            let created = matches!(store.auth_profile(&profile), Err(Error::NotFound(_)));
            if created {
                store.auth_create_for_macros(&profile, &h)?;
            } else {
                store.auth_save_handling(&profile, &h)?;
            }
            let summary = macro_summary(&m);
            out.ok(
                json!({"profile": profile, "profile_created": created, "macro": summary, "replaced": replaced}),
                || {
                    format!(
                    "macro {name:?} {} for {}{profile} ({} steps); try it: brainproxy auth macro run {profile} {name}",
                    if replaced { "replaced" } else { "saved" },
                    if created { "new profile " } else { "" },
                    m.steps.len()
                )
                },
            );
        }
        MacroCmd::List { profile } => {
            store.auth_profile(&profile)?;
            let items: Vec<_> = store.auth_handling(&profile)?.macros.iter().map(macro_summary).collect();
            out.ok(json!({"profile": profile, "macros": items}), || {
                items
                    .iter()
                    .map(|m| {
                        format!("{:<20} {} steps  vars: {}", m["name"].as_str().unwrap_or(""), m["steps"], m["vars"])
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        MacroCmd::Show { profile, name } => {
            let h = store.auth_handling(&profile)?;
            let m = h
                .macros
                .iter()
                .find(|m| m.name == name)
                .ok_or_else(|| Error::NotFound(format!("macro {name:?} of profile {profile:?}")))?;
            let data = json!({"profile": profile, "macro": m});
            out.ok(data.clone(), || serde_json::to_string_pretty(&data).unwrap_or_default());
        }
        MacroCmd::Run { profile, name, net } => {
            let session = AuthSession::load(project, &profile, Client::new(net.send_options(project)?))?;
            let run = runtime()?.block_on(session.run_macro(&name))?;
            session.save()?;
            let lines: Vec<String> = run
                .steps
                .iter()
                .map(|s| {
                    let mut line = format!(
                        "{}. {} {} -> {}{}",
                        s.step,
                        s.method,
                        s.url,
                        s.status.map_or("no response".to_string(), |c| c.to_string()),
                        s.history_id.map(|id| format!(" (history #{id})")).unwrap_or_default()
                    );
                    if let Some(e) = &s.error {
                        line.push_str(&format!(" error: {e}"));
                    }
                    for x in &s.extracted {
                        line.push_str(&format!("\n     {} = {}", x.var, x.value.as_deref().unwrap_or("(not found)")));
                    }
                    line
                })
                .collect();
            if !run.complete() {
                return Err(Error::InvalidInput(format!(
                    "macro {name:?} did not complete (missing: {}):\n{}",
                    run.missing.join(", "),
                    lines.join("\n")
                )));
            }
            out.ok(json!({"profile": profile, "run": run}), || lines.join("\n"));
        }
        MacroCmd::Remove { profile, name } => {
            let mut h = store.auth_handling(&profile)?;
            if !h.macros.iter().any(|m| m.name == name) {
                return Err(Error::NotFound(format!("macro {name:?} of profile {profile:?}")));
            }
            let users: Vec<u32> = h
                .rules
                .iter()
                .filter(|r| r.actions.iter().any(|a| matches!(a, Action::RunMacro { name: n, .. } if n == &name)))
                .map(|r| r.id)
                .collect();
            if !users.is_empty() {
                return Err(Error::InvalidInput(format!(
                    "session rules {users:?} run macro {name:?}; remove them first (auth rule remove {profile} ID)"
                )));
            }
            h.macros.retain(|m| m.name != name);
            store.auth_save_handling(&profile, &h)?;
            out.ok(json!({"profile": profile, "name": name, "removed": true}), || format!("macro {name:?} removed"));
        }
    }
    Ok(())
}

fn rule_line(r: &SessionRule) -> String {
    let tools = if r.tools.is_empty() {
        "all tools".to_string()
    } else {
        r.tools.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
    };
    let actions: Vec<String> = r
        .actions
        .iter()
        .map(|a| match a {
            Action::Check { every } if *every > 1 => format!("check every {every}"),
            Action::Check { .. } => "check".into(),
            Action::RunMacro { name, every: 0 } => format!("macro {name}"),
            Action::RunMacro { name, every: 1 } => format!("macro {name} each request"),
            Action::RunMacro { name, every } => format!("macro {name} every {every}"),
            Action::Update { params } if params.is_empty() => "update all".into(),
            Action::Update { params } => format!(
                "update {}",
                params
                    .iter()
                    .map(|(p, v)| if p == v { p.clone() } else { format!("{p}={v}") })
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Action::Login => "login".into(),
            Action::Sign { signer } => format!("sign {signer}"),
        })
        .collect();
    format!("#{:<3} {:<28} {:<24} {}", r.id, tools, r.url.as_deref().unwrap_or("any URL"), actions.join(" -> "))
}

fn rule_cmd(project: &Path, cmd: RuleCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        RuleCmd::Add { profile, actions, tools, url, invalid, description } => {
            let mut h = store.auth_handling(&profile)?;
            let mut tools = tools.iter().map(|t| Tool::parse(t)).collect::<Result<Vec<_>, _>>()?;
            tools.dedup();
            let rule = SessionRule {
                id: h.rules.iter().map(|r| r.id).max().unwrap_or(0) + 1,
                description: description.unwrap_or_default(),
                tools,
                url,
                actions: actions.iter().map(|a| Action::parse(a)).collect::<Result<_, _>>()?,
                invalid,
            };
            h.rules.push(rule.clone());
            store.auth_save_handling(&profile, &h)?;
            out.ok(json!({"profile": profile, "rule": rule}), || format!("session rule added: {}", rule_line(&rule)));
        }
        RuleCmd::List { profile } => {
            store.auth_profile(&profile)?;
            let rules = store.auth_handling(&profile)?.rules;
            out.ok(json!({"profile": profile, "rules": rules}), || {
                if rules.is_empty() {
                    format!("{profile} has no session rules")
                } else {
                    rules.iter().map(rule_line).collect::<Vec<_>>().join("\n")
                }
            });
        }
        RuleCmd::Remove { profile, id } => {
            let mut h = store.auth_handling(&profile)?;
            let before = h.rules.len();
            h.rules.retain(|r| r.id != id);
            if h.rules.len() == before {
                return Err(Error::NotFound(format!("session rule {id} of profile {profile:?}")));
            }
            store.auth_save_handling(&profile, &h)?;
            out.ok(json!({"profile": profile, "id": id, "removed": true}), || format!("session rule {id} removed"));
        }
    }
    Ok(())
}

fn parse_choice<T: serde::de::DeserializeOwned>(what: &str, s: &str, valid: &str) -> Result<T, Error> {
    serde_json::from_value(json!(s.trim().to_ascii_lowercase()))
        .map_err(|_| Error::InvalidInput(format!("unknown {what} {s:?}; one of {valid}")))
}

fn sign_cmd(project: &Path, cmd: SignCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        SignCmd::Add(args) => {
            let SignAddArgs {
                profile,
                name,
                secret_env,
                secret_file,
                secret_encoding,
                origins,
                to,
                wrap,
                set_headers,
                canonical,
                hash,
                output,
                jwt,
                claims,
                ttl,
                kid,
                resign,
                keep_place,
            } = *args;
            let key = match (secret_env, secret_file) {
                (Some(var), _) => KeySource::Env(var),
                (_, Some(path)) => KeySource::File(path),
                _ => return Err(Error::InvalidInput("give --secret-env or --secret-file".into())),
            };
            let kind = match jwt {
                Some(alg) => SignKind::Jwt { alg: JwtAlg::parse(&alg)?, claims, ttl, kid, resign },
                None => SignKind::Hmac {
                    alg: HmacAlg::parse(&hash)?,
                    canonical: canonical.unwrap_or_default(),
                    output: parse_choice("output", &output, "hex, base64, base64url")?,
                },
            };
            let headers = set_headers
                .iter()
                .map(|h| {
                    h.split_once(':')
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                        .ok_or_else(|| Error::InvalidInput(format!("--set-header {h:?}: use 'NAME: TEMPLATE'")))
                })
                .collect::<Result<_, _>>()?;
            let origins =
                origins.iter().map(|o| Target::from_url(o).map(|t| t.origin())).collect::<Result<Vec<_>, _>>()?;
            let signer = Signer {
                name: name.clone(),
                key,
                key_encoding: parse_choice("key encoding", &secret_encoding, "raw, hex, base64")?,
                origins,
                to: Place::parse(&to)?,
                format: wrap,
                headers,
                kind,
            };
            let mut h = store.auth_handling(&profile)?;
            let place = h.signers.iter().position(|s| s.name == name);
            let replaced = place.is_some();
            h.signers.retain(|s| s.name != name);
            match place.filter(|_| keep_place) {
                Some(i) => h.signers.insert(i, signer.clone()),
                None => h.signers.push(signer.clone()),
            }
            let created = matches!(store.auth_profile(&profile), Err(Error::NotFound(_)));
            if created {
                store.auth_create_for_macros(&profile, &h)?;
            } else {
                store.auth_save_handling(&profile, &h)?;
            }
            out.ok(
                json!({"profile": profile, "profile_created": created, "signer": signer, "replaced": replaced}),
                || {
                    format!(
                        "signer {name:?} {}; use it: brainproxy auth rule add {profile} --action sign:{name}",
                        if replaced { "replaced" } else { "saved" }
                    )
                },
            );
        }
        SignCmd::List { profile } => {
            store.auth_profile(&profile)?;
            let signers = store.auth_handling(&profile)?.signers;
            out.ok(json!({"profile": profile, "signers": signers}), || {
                if signers.is_empty() {
                    format!("{profile} has no signers")
                } else {
                    signers
                        .iter()
                        .map(|s| format!("{} -> {} for {}", s.name, s.to, s.origins.join(", ")))
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            });
        }
        SignCmd::Remove { profile, name } => {
            let mut h = store.auth_handling(&profile)?;
            if h.rules.iter().any(|r| r.actions.iter().any(|a| matches!(a, Action::Sign { signer } if signer == &name)))
            {
                return Err(Error::InvalidInput(format!("a session rule uses signer {name:?}; remove the rule first")));
            }
            let before = h.signers.len();
            h.signers.retain(|s| s.name != name);
            if h.signers.len() == before {
                return Err(Error::NotFound(format!("signer {name:?} of profile {profile:?}")));
            }
            store.auth_save_handling(&profile, &h)?;
            out.ok(json!({"profile": profile, "name": name, "removed": true}), || format!("signer {name:?} removed"));
        }
    }
    Ok(())
}
