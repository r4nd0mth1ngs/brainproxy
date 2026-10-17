//! Authentication profiles: how to log in, and the live session that other
//! commands use with `--auth NAME`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use brainproxy_core::auth::{AuthProfile, AuthSession, Secret, SessionState};
use brainproxy_core::http::{Client, SendOptions};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::json;

use crate::output::Out;

#[derive(Subcommand)]
pub enum AuthCmd {
    /// Add or replace a profile. Use it with `--auth NAME` on send, fuzz, crawl,
    /// scan active, and proxy start.
    #[command(after_help = "Form login: --login-url URL --login-body 'user={{username}}&pass={{password}}' \
        --username alice --password-env APP_PW. JSON bodies (starting with '{') are sent as application/json.\n\
        CSRF: --csrf-url PAGE --csrf-regex 'name=\"csrf\" value=\"([^\"]+)\"' fills {{csrf}}.\n\
        Bearer token: --token-regex '\"token\":\"([^\"]+)\"' --token-header 'Authorization: Bearer {{token}}'.\n\
        Static API key only: --header 'X-Api-Key: ...' (no --login-url).\n\
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
    /// One profile (password redacted).
    Show { name: String },
    /// Delete a profile and its session.
    Remove { name: String },
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
    /// Password stored in the project file. Prefer --password-env.
    #[arg(long, conflicts_with = "password_env")]
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
    /// Minimum seconds between automatic re-logins.
    #[arg(long, default_value_t = 5)]
    relogin_interval: u64,
    /// Maximum automatic re-logins per command run.
    #[arg(long, default_value_t = 20)]
    max_relogins: u32,
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

fn state_json(state: &SessionState) -> serde_json::Value {
    json!({
        "logged_in": state.logged_in,
        "cookies": state.cookies.iter().map(|(k, _)| k).collect::<Vec<_>>(),
        "token": state.token.is_some(),
        "last_login": state.last_login,
        "last_error": state.last_error,
    })
}

pub fn auth(project: &Path, cmd: AuthCmd, out: &Out) -> Result<(), Error> {
    match cmd {
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
            let profile = AuthProfile {
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
                headers: parse(&a.headers)?,
                relogin_interval_secs: a.relogin_interval,
                max_relogins: a.max_relogins,
            };
            Store::open(project)?.auth_save_profile(&profile)?;
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
            let (profile, state) = Store::open(project)?.auth_profile(&name)?;
            let data = json!({"profile": profile.redacted(), "session": state_json(&state)});
            out.ok(data.clone(), || serde_json::to_string_pretty(&data).unwrap_or_default());
        }
        AuthCmd::Remove { name } => {
            Store::open(project)?.auth_remove(&name)?;
            out.ok(json!({"name": name, "removed": true}), || format!("profile {name:?} removed"));
        }
    }
    Ok(())
}
