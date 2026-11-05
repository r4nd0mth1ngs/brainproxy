//! CLI for the intercepting proxy: CA, proxy lifecycle, scope, rules, intercept queue.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use brainproxy_core::authz::live::{Live, LiveOptions};
use brainproxy_core::authz::{AuthzConfig, ANONYMOUS, DEFAULT_EXCLUDE};
use brainproxy_core::http::{RawRequest, SendOptions, Target};
use brainproxy_core::jobs::{is_finished, JobControl};
use brainproxy_core::proxy::config::{
    InterceptSettings, LiveAuthz, Rule, RuleLocation, Scope, TimeoutAction, AUTHZ_KEY, INTERCEPT_KEY, RULES_KEY,
    SCOPE_KEY,
};
use brainproxy_core::proxy::{CertAuthority, ProxyOptions, ProxyState, STATE_KEY};
use brainproxy_core::store::{HistoryFilter, Store};
use brainproxy_core::{codec, Error};
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};

use crate::output::{body_value, Out};
use crate::process::{self, Liveness};

/// `proxy stop` asks the proxy to exit through this key (see `process::shutdown`).
const STOP_KEY: &str = "proxy.stop";
const LOCK_NAME: &str = "proxy";
/// Hands a `proxy restart`'s hold on the record to the proxy it starts (see `Saved::restart`).
const RESTART_ENV: &str = "BRAINPROXY_PROXY_RESTART";
/// Held by `proxy restart` for as long as it holds the record: what tells another container
/// that the restart still runs, since its pid means nothing there (see `process`).
const RESTART_LOCK: &str = "proxy-restart";
/// Set on the proxy a restart starts to go back to the old one: that one never goes back itself
/// (see [`go_back`]).
const BACK_ENV: &str = "BRAINPROXY_PROXY_RESTART_BACK";
/// The record of the proxy a restart replaces, given to the proxy it starts in its place: what
/// that one goes back to if the restart has gone (see [`go_back`]).
const WAS_ENV: &str = "BRAINPROXY_PROXY_RESTART_WAS";
/// Set on the guard a restart starts before it stops the old proxy: a `proxy run` that runs no
/// proxy itself, only stands by in case the restart goes away (see [`guard`]).
const GUARD_ENV: &str = "BRAINPROXY_PROXY_RESTART_GUARD";
/// Held by a restart's guard for as long as it runs: what tells another container that the
/// restart's hold lasts while the guard does, once the restart's own lock is free.
const GUARD_LOCK: &str = "proxy-restart-guard";
/// `proxy stop` calls off a restart under way by writing its token here; the restart looks
/// between its steps and while it waits for a proxy to come up, and so does a proxy started on
/// its behalf before it takes the record (see [`call_off`]). Tokens are never reused, so a
/// call-off left here once it has worked is harmless until the next one replaces it.
const CANCEL_KEY: &str = "proxy.restart.cancel";
/// How long `proxy stop` waits for a restart it called off to let go of the record. Its longest
/// step is stopping the old proxy: with a live authz run, `STOP_WAIT_AUTHZ` and then a kill.
const CANCEL_WAIT: Duration = Duration::from_secs(40);

/// How long a proxy may take to exit when asked to before it is killed. It exits as soon as
/// it is done: after waiting up to 3 s for requests already sent upstream, it writes out
/// every queued capture, which a busy proxy may take a while to do. With a live authz run
/// it also has to finish its tests and save the run.
const STOP_WAIT: Duration = Duration::from_secs(30);
const STOP_WAIT_AUTHZ: Duration = Duration::from_secs(30);
/// A proxy whose state has no start time is from an older version, which exits without
/// draining.
const STOP_WAIT_OLD: Duration = Duration::from_secs(5);
/// Set once this process, a `proxy run`, has recorded itself as the proxy: from then on a failure
/// is its own, not a failure to come up that a restart's proxy goes back from (see [`go_back`]).
static TOOK_RECORD: AtomicBool = AtomicBool::new(false);
/// A `proxy run` started on a restart's behalf either goes on to take the record (or fails by
/// itself), or gives up waiting to (see [`give_up_after`]), never both: whichever comes first
/// settles it here, from `WAITING` to `OWN` or `GAVE_UP`.
static SETTLED: AtomicU8 = AtomicU8::new(WAITING);
const WAITING: u8 = 0;
const OWN: u8 = 1;
const GAVE_UP: u8 = 2;
/// The live authz run this `proxy run` created, if any (0: none): failed if it gives up
/// waiting to take the record (see [`give_up_after`]), which ends the process under the run.
static LIVE_RUN: AtomicI64 = AtomicI64::new(0);
/// How long a proxy started on a restart's behalf has to take the record: the wait the restart
/// gives it, after which it kills it. Once the restart has gone, the proxy gives up by itself.
const WAIT_ENV: &str = "BRAINPROXY_PROXY_RESTART_WAIT";

/// The longest `--wait` that `start` takes, in seconds.
const MAX_WAIT: f64 = 3600.0;
/// The longest `--wait` that `restart` takes, in seconds, for the new proxy and for going back
/// to the old one each: while it waits, every other start is turned away. It is well below the
/// MCP server's default timeout, which kills a call.
const MAX_RESTART_WAIT: f64 = 60.0;

#[derive(Subcommand)]
pub enum CaCmd {
    /// Create the interception CA if missing (use --force to replace it).
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Export the CA certificate for clients to trust.
    Export {
        /// Write DER instead of PEM.
        #[arg(long)]
        der: bool,
        /// Write to this file instead of stdout. An existing file is kept unless --force.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Print the certificate itself rather than the JSON envelope.
        #[arg(long)]
        raw: bool,
        /// Overwrite an existing --out file.
        #[arg(long)]
        force: bool,
    },
    /// Add the CA to the system trust store. Debian/Kali: update-ca-certificates, needs root. Windows: the
    /// current user's Trusted Root store (certutil -user), no admin needed.
    InstallSystem,
}

#[derive(Subcommand)]
pub enum ProxyCmd {
    /// Start the proxy in the background and return once it is listening.
    Start(ProxyRunArgs),
    /// Run the proxy in the foreground until SIGINT/SIGTERM.
    Run(ProxyRunArgs),
    /// Stop the background proxy for this project. A restart under way is called off: the proxy
    /// it was replacing stays off, and it starts nothing.
    Stop {
        /// Only clear a record that can't be verified (its lock file isn't readable from this
        /// container). Nothing is signalled, and a proxy known to be running is left alone.
        #[arg(long)]
        forget: bool,
        /// Only stop the proxy if it is this pid, in this container: not one started since, or a
        /// restart under way. Fails with not_found otherwise.
        #[arg(long, value_name = "PID", conflicts_with = "forget")]
        pid: Option<u32>,
    },
    /// Move this project's running proxy to another address or options: stop it and start it again
    /// in one step, so no other start gets in between. Takes start's options, defaults included
    /// (--wait at most 60); if the new proxy doesn't come up, the old one is started again where it was.
    Restart(ProxyRunArgs),
    /// Show whether a proxy is running, with capture and intercept counts.
    Status,
    /// How the app starts this project's proxy (Settings › Proxy): who can connect, invisible mode
    /// and a redirect. Saved in the project file; `proxy start` doesn't read it.
    #[command(subcommand)]
    Setup(SetupCmd),
}

#[derive(Subcommand)]
pub enum SetupCmd {
    /// Show the saved setup, with the `proxy start` options it stands for.
    Show,
    /// Replace the saved setup in one write; whatever isn't given goes back to its default. It applies
    /// the next time the app starts the proxy.
    Set {
        /// Who can connect: `local` (127.0.0.1, this computer only) or `all` (0.0.0.0, every network
        /// interface: anyone who can reach this computer can use the proxy, with this project's auth
        /// profiles and platform auth). Not `all` in an MCP tool call.
        #[arg(long, value_enum, default_value = "local")]
        network: NetworkArg,
        /// Also serve clients that don't know they're proxied (`proxy start --invisible`). Not in an
        /// MCP tool call.
        #[arg(long)]
        invisible: bool,
        /// Send every request to this origin (`proxy start --redirect`); a path is dropped. Implies
        /// --invisible. Not in an MCP tool call.
        #[arg(long, value_name = "URL")]
        redirect: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, ValueEnum, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkArg {
    #[default]
    Local,
    All,
}

/// Settings key of the app's proxy setup (`setting.proxy_setup` in `meta`).
const SETUP_KEY: &str = "proxy_setup";

/// The app's proxy setup as stored; defaults are left out.
#[derive(serde::Serialize, serde::Deserialize, Default, PartialEq, Debug)]
struct ProxySetup {
    #[serde(default, skip_serializing_if = "is_local")]
    network: NetworkArg,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    invisible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirect: Option<String>,
}

fn is_local(n: &NetworkArg) -> bool {
    *n == NetworkArg::Local
}

impl ProxySetup {
    fn json(&self) -> Value {
        let host = if self.network == NetworkArg::All { "0.0.0.0" } else { "127.0.0.1" };
        let mut options = vec![];
        match &self.redirect {
            Some(r) => options.push(format!("--redirect={r}")),
            None if self.invisible => options.push("--invisible".to_string()),
            None => {}
        }
        json!({
            "network": self.network,
            "invisible": self.invisible || self.redirect.is_some(),
            "redirect": self.redirect,
            "host": host,
            "start_options": options,
        })
    }

    fn text(&self) -> String {
        let who = if self.network == NetworkArg::All {
            "every network interface (0.0.0.0)"
        } else {
            "this computer only (127.0.0.1)"
        };
        let mode = match &self.redirect {
            Some(r) => format!("invisible, everything sent to {r}"),
            None if self.invisible => "invisible".into(),
            None => "not invisible".into(),
        };
        format!("who can connect: {who}; {mode}")
    }
}

fn setup(project: &Path, cmd: SetupCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    let saved = match cmd {
        SetupCmd::Show => store.setting::<ProxySetup>(SETUP_KEY)?,
        SetupCmd::Set { network, invisible, redirect } => {
            if network == NetworkArg::All && crate::mcp::in_tool_call() {
                return Err(Error::InvalidInput(
                    "--network=all isn't offered through MCP: it lets anyone who can reach this computer use the \
                     proxy, so a person chooses it (Settings › Proxy in the app, or a terminal)"
                        .into(),
                ));
            }
            // The app starts the person's proxy with the setup the next time the project opens: an
            // agent's redirect would send everything they browse to an origin it chose.
            if (invisible || redirect.is_some()) && crate::mcp::in_tool_call() {
                return Err(Error::InvalidInput(
                    "--invisible and --redirect aren't offered through MCP: the app starts the person's proxy with \
                     them the next time the project opens, so a person chooses them (Settings › Proxy in the app, \
                     or a terminal)"
                        .into(),
                ));
            }
            let redirect = match redirect.as_deref().map(Target::from_url).transpose()? {
                Some(t) if t.port == 0 => {
                    return Err(Error::InvalidInput("--redirect needs a port from 1 to 65535".into()))
                }
                t => t.map(|t| t.origin()),
            };
            let setup = ProxySetup { network, invisible: invisible && redirect.is_none(), redirect };
            store.set_setting(SETUP_KEY, &setup)?;
            setup
        }
    };
    out.ok(saved.json(), || saved.text());
    Ok(())
}

#[derive(clap::Args, Clone)]
pub struct ProxyRunArgs {
    /// Address to listen on. Port 0 picks a free port.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
    /// Verify upstream TLS certificates.
    #[arg(long)]
    verify_tls: bool,
    /// Upstream connect/response timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    /// Seconds `start` waits for the proxy to come up (at most 3600; `restart`: 60).
    #[arg(long, default_value_t = 10.0)]
    wait: f64,
    /// Log file for `start` (default: next to the project file).
    #[arg(long)]
    log: Option<PathBuf>,
    /// Add this auth profile's session to in-scope requests and re-login when it is lost.
    #[arg(long, value_name = "NAME")]
    auth: Option<String>,
    /// Don't offer HTTP/2 to clients on intercepted TLS connections (HTTP/1.1 only).
    #[arg(long)]
    no_http2: bool,
    /// Invisible proxying for clients that don't know they're proxied (pointed here by DNS
    /// or /etc/hosts): route plain requests by their Host header and TLS by its SNI (port 443).
    #[arg(long)]
    invisible: bool,
    /// Send every request from this listener to this origin (http://HOST:PORT or https://...),
    /// like a reverse proxy. Implies --invisible.
    #[arg(long, value_name = "URL")]
    redirect: Option<String>,
    /// Live access-control testing: also send each in-scope GET/HEAD/OPTIONS request that
    /// carries credentials and got a 2xx that isn't a static asset as these auth profiles,
    /// and/or `anonymous` (no credentials), in the background. Comma-separated or
    /// repeatable. Results: authz matrix RUN.
    #[arg(long, value_name = "NAMES", value_delimiter = ',')]
    authz: Vec<String>,
    /// Requests per second live testing sends at most (0: no limit).
    #[arg(long, value_name = "N", default_value_t = 5.0)]
    authz_rate: f64,
    /// Requests waiting for live testing at most; more are dropped and counted.
    #[arg(long, value_name = "N", default_value_t = 100)]
    authz_queue: usize,
    /// Regex on paths live testing leaves alone.
    #[arg(long, value_name = "REGEX", default_value = DEFAULT_EXCLUDE)]
    authz_exclude: String,
    /// Cookie that isn't a credential and stays on live-tested requests. Repeatable or
    /// comma-separated.
    #[arg(long, value_name = "NAME", value_delimiter = ',')]
    authz_keep_cookie: Vec<String>,
}

impl ProxyRunArgs {
    /// The live access-control testing settings these arguments ask for.
    fn live_authz(&self) -> Result<LiveAuthz, Error> {
        let mut identities: Vec<String> = Vec::new();
        for n in &self.authz {
            let n = n.trim();
            if !n.is_empty() && n != ANONYMOUS && !identities.iter().any(|i| i == n) {
                identities.push(n.to_string());
            }
        }
        regex::Regex::new(&self.authz_exclude).map_err(|e| Error::InvalidInput(format!("--authz-exclude: {e}")))?;
        if self.authz_rate.is_nan() || self.authz_rate < 0.0 {
            return Err(Error::InvalidInput("--authz-rate must be 0 or more".into()));
        }
        Ok(LiveAuthz {
            enabled: !self.authz.iter().all(|n| n.trim().is_empty()),
            anonymous: self.authz.iter().any(|n| n.trim() == ANONYMOUS),
            identities,
            rate: (self.authz_rate > 0.0).then_some(self.authz_rate),
            queue: self.authz_queue.max(1),
            exclude: self.authz_exclude.clone(),
            keep_cookies: self.authz_keep_cookie.clone(),
            run_id: None,
        })
    }
}

#[derive(Subcommand)]
pub enum ScopeCmd {
    /// Show the current scope and the latest changes to what the proxy records (scope and
    /// TLS pass-through: who made each, when, and whether it narrowed recording).
    Show,
    /// Replace the scope. Patterns are case-insensitive regexes matched against host names.
    Set {
        #[arg(long)]
        include: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
        /// Record out-of-scope traffic in full too (it is never intercepted or modified). Without
        /// it, each out-of-scope request keeps only its request line, and an HTTPS tunnel a row.
        #[arg(long)]
        record_out_of_scope: bool,
    },
    /// Add patterns to the current scope.
    Add {
        #[arg(long)]
        include: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
    },
    /// Remove all scope patterns (everything in scope).
    Clear,
    /// Check whether a host is in scope.
    Check { host: String },
}

#[derive(Subcommand)]
pub enum RulesCmd {
    /// List match-and-replace rules.
    List,
    /// Add a rule. Header rules match each header line; an empty --match adds --replace as a new header.
    Add {
        #[arg(long, value_parser = RuleLocation::ALL.to_vec())]
        location: String,
        /// Regex to match (Rust syntax). Empty with a header location means "add header".
        #[arg(long = "match", default_value = "")]
        pattern: String,
        /// Replacement; $1-style group references allowed. Empty removes the match.
        #[arg(long, default_value = "")]
        replace: String,
        #[arg(long)]
        comment: Option<String>,
        /// Add the rule disabled.
        #[arg(long)]
        disabled: bool,
    },
    Remove {
        id: u32,
    },
    Enable {
        id: u32,
    },
    Disable {
        id: u32,
    },
    /// Remove all rules.
    Clear,
}

#[derive(Subcommand)]
pub enum InterceptCmd {
    /// Start holding matching messages in the queue. With no direction flag, requests are held.
    Enable {
        #[arg(long)]
        requests: bool,
        #[arg(long)]
        responses: bool,
        /// Hold WebSocket messages from the client (text and binary; control frames pass).
        #[arg(long)]
        ws_to_server: bool,
        /// Hold WebSocket messages from the server.
        #[arg(long)]
        ws_to_client: bool,
        /// Only hold messages for hosts matching this regex.
        #[arg(long)]
        host: Option<String>,
        /// Only hold messages for paths matching this regex (WebSocket: the upgrade request's path).
        #[arg(long)]
        path: Option<String>,
        /// Only hold these methods (regex alternation, e.g. "POST|PUT"). Not applied to WebSocket messages.
        #[arg(long)]
        method: Option<String>,
        /// Seconds a held message waits for a decision.
        #[arg(long, default_value_t = 120)]
        timeout: u64,
        /// What happens to a message nobody resolved in time.
        #[arg(long, value_enum, default_value = "forward")]
        timeout_action: TimeoutArg,
    },
    /// Stop holding new messages. Messages already held still wait for a decision.
    Disable,
    /// Show intercept settings and the number of pending messages.
    Status,
    /// List held messages.
    List {
        #[arg(long, value_enum, default_value = "pending")]
        state: StateArg,
        /// Wait up to this many seconds for at least one matching message.
        #[arg(long, default_value_t = 0.0)]
        wait: f64,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Show a held message.
    Show {
        id: i64,
        /// Print the message bytes only (edit them, then `forward --file`).
        #[arg(long)]
        raw: bool,
        #[arg(long, default_value_t = 65536)]
        max_body: usize,
    },
    /// Release a held message, optionally replaced by an edited version.
    Forward {
        id: i64,
        /// Replacement message file ('-' for stdin). Line endings and Content-Length are fixed unless
        /// --verbatim; a WebSocket message's payload is always taken as is.
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        verbatim: bool,
    },
    /// Drop a held message; the client receives a 502 (a dropped WebSocket message is just not delivered).
    Drop { id: i64 },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum TimeoutArg {
    Forward,
    Drop,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum StateArg {
    Pending,
    Forwarded,
    Dropped,
    Expired,
    All,
}

/// Where the CA and other per-user data live: `--home`, `$BRAINPROXY_HOME` (clap),
/// `$XDG_DATA_HOME/brainproxy`, `%APPDATA%\brainproxy` on Windows (the
/// per-user installer puts the app itself in `%LOCALAPPDATA%\brainproxy`), `~/.local/share/brainproxy`.
pub fn resolve_home(home: Option<PathBuf>) -> PathBuf {
    home.or_else(|| std::env::var_os("XDG_DATA_HOME").map(|d| PathBuf::from(d).join("brainproxy")))
        .or_else(|| std::env::var_os("APPDATA").filter(|_| cfg!(windows)).map(|d| PathBuf::from(d).join("brainproxy")))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/brainproxy")))
        .unwrap_or_else(|| PathBuf::from(".brainproxy"))
}

fn ca_dir(home: &Path) -> PathBuf {
    home.join("ca")
}

pub(crate) fn load_ca(home: &Path) -> Result<(CertAuthority, brainproxy_core::proxy::CaInfo), Error> {
    CertAuthority::load_or_create(&ca_dir(home))
}

fn fingerprint(der: &[u8]) -> String {
    codec::hash("sha256", der).unwrap_or_default()
}

pub fn ca(home: &Path, cmd: CaCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        CaCmd::Init { force } => {
            if force {
                CertAuthority::generate(&ca_dir(home))?;
            }
            let (ca, info) = load_ca(home)?;
            let data = json!({
                "cert_path": info.cert_path,
                "key_path": info.key_path,
                "created": info.created || force,
                "sha256": fingerprint(ca.cert_der()),
            });
            out.ok(data, || format!("CA: {}", info.cert_path.display()));
        }
        CaCmd::Export { der, out: path, raw, force } => {
            let (ca, info) = load_ca(home)?;
            let bytes = if der { ca.cert_der().to_vec() } else { ca.cert_pem().as_bytes().to_vec() };
            if let Some(path) = path {
                crate::output::write_file(&path, &bytes, force)?;
                out.ok(json!({"path": path, "format": if der { "der" } else { "pem" }}), || {
                    format!("wrote {}", path.display())
                });
            } else if raw || der {
                out.raw(&bytes);
            } else {
                let data = json!({"cert_path": info.cert_path, "pem": ca.cert_pem(), "sha256": fingerprint(ca.cert_der()),
                        // For Chromium's --ignore-certificate-errors-spki-list.
                        "spki_sha256_base64": ca.spki_sha256_base64()});
                out.ok(data, || ca.cert_pem().to_string());
            }
        }
        #[cfg(windows)]
        CaCmd::InstallSystem => {
            // The current user's Root store: no admin needed; Windows asks the user to confirm.
            let (ca, info) = load_ca(home)?;
            let result = std::process::Command::new("certutil")
                .args(["-user", "-addstore", "Root"])
                .arg(&info.cert_path)
                .output()
                .map_err(|e| Error::InvalidInput(format!("certutil: {e}")))?;
            if !result.status.success() {
                return Err(Error::InvalidInput(format!(
                    "certutil failed: {}",
                    String::from_utf8_lossy(&result.stdout).trim()
                )));
            }
            out.ok(json!({"installed": "CurrentUser\\Root", "sha256": fingerprint(ca.cert_der())}), || {
                "installed in the current user's Trusted Root store".into()
            });
        }
        #[cfg(not(windows))]
        CaCmd::InstallSystem => {
            let (ca, _) = load_ca(home)?;
            let dest = PathBuf::from("/usr/local/share/ca-certificates/brainproxy.crt");
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::InvalidInput(format!("cannot create {}: {e} (run as root)", parent.display()))
                })?;
            }
            std::fs::write(&dest, ca.cert_pem())
                .map_err(|e| Error::InvalidInput(format!("cannot write {}: {e} (run as root)", dest.display())))?;
            let result = std::process::Command::new("update-ca-certificates")
                .output()
                .map_err(|e| Error::InvalidInput(format!("update-ca-certificates: {e}")))?;
            if !result.status.success() {
                return Err(Error::InvalidInput(format!(
                    "update-ca-certificates failed: {}",
                    String::from_utf8_lossy(&result.stderr).trim()
                )));
            }
            out.ok(json!({"installed": dest, "sha256": fingerprint(ca.cert_der())}), || {
                format!("installed {}", dest.display())
            });
        }
    }
    Ok(())
}

/// The stored state plus the proxy's process start time, so a later process that reuses
/// the pid isn't taken for the proxy. States written by older versions lack it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Saved {
    #[serde(flatten)]
    state: ProxyState,
    #[serde(default)]
    start_time: Option<u64>,
    /// The proxy's PID namespace, recorded if it holds its lock file: see `process`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pid_ns: Option<String>,
    /// Set while `proxy restart` holds the record, from before it stops the proxy until the
    /// proxy it starts takes the record over: the pid is the restart's own, so every other start
    /// finds the record taken. The proxy it starts gets this token in [`RESTART_ENV`]. From
    /// another namespace it is judged by [`RESTART_LOCK`], not by the proxy's lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    restart: Option<String>,
    /// A restart's hold only: the record of the proxy it replaces, as stored. If the restart goes
    /// away while that proxy still runs, the proxy gets it back (see [`recorded`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    was: Option<String>,
    /// A restart's hold only: the proxy it is starting (pid and start time), from when it has
    /// started it, and before that, from just before it stops the old proxy, its guard (see
    /// [`guard`]). The hold lasts while that process runs, even if the restart has gone, so that
    /// it can go back (see [`go_back`]), and a stop that calls the restart off stops it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    starting: Option<(u32, Option<u64>)>,
    /// Set by `proxy stop` from before it asks the proxy to exit until the proxy is gone, so that
    /// a restart can't take the record meanwhile and start a proxy the stop meant to be off. The
    /// request itself ([`STOP_KEY`]) doesn't last that long: the proxy takes it as it sees it.
    /// In a restart's hold: set from before the restart asks the proxy it replaces to exit, so
    /// that its guard knows whether that proxy still runs as it was (see [`guard`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    stopping: bool,
    /// The record as stored. It is only ever replaced or cleared if it still reads the same.
    #[serde(skip)]
    raw: String,
}

fn parse_state(raw: &str) -> Option<Saved> {
    serde_json::from_str(raw).ok().map(|s| Saved { raw: raw.to_string(), ..s })
}

fn read_state(store: &Store) -> Result<Option<Saved>, Error> {
    Ok(store.meta_get(STATE_KEY)?.as_deref().and_then(parse_state))
}

/// The lock that vouches for the record `s` from another container. Between a restart's stop
/// and its start nobody holds the proxy's lock, so a restart's hold goes by the restart's.
fn lock_of(s: &Saved) -> &'static str {
    if s.restart.is_some() {
        RESTART_LOCK
    } else {
        LOCK_NAME
    }
}

fn liveness(store: &Store, s: &Saved) -> Liveness {
    match process::liveness(store, lock_of(s), s.state.pid, s.start_time, s.pid_ns.as_deref()) {
        Liveness::Gone if starting_here(s).is_some() => Liveness::Running,
        // From another container a restart's guard is known by its own lock, once the restart's
        // is free.
        Liveness::Gone if s.restart.is_some() && s.starting.is_some() && guard_held(store, s) => Liveness::Running,
        known => known,
    }
}

/// Whether a restart's guard holds [`GUARD_LOCK`], seen from another container than the
/// restart's: there `starting`'s pid means nothing.
fn guard_held(store: &Store, s: &Saved) -> bool {
    process::elsewhere(s.pid_ns.as_deref())
        && process::liveness(store, GUARD_LOCK, s.state.pid, None, s.pid_ns.as_deref()) == Liveness::Running
}

/// Whether the restart holding `s` itself has gone, whatever it was starting.
fn restart_gone(store: &Store, s: &Saved) -> bool {
    process::liveness(store, RESTART_LOCK, s.state.pid, s.start_time, s.pid_ns.as_deref()) == Liveness::Gone
}

/// The pid of the proxy a restart's hold says it is starting, if that still runs here. Orphaned,
/// it may never be reaped, so a zombie counts as gone.
fn starting_here(s: &Saved) -> Option<u32> {
    let (pid, start) = s.starting?;
    let here = !process::elsewhere(s.pid_ns.as_deref());
    (here && process::still_running(pid, start) != Some(false) && !process::exited(pid)).then_some(pid)
}

/// The saved state and what is known about it, clearing stale state left by a crash. A
/// restart's hold whose restart has gone gives the record back to the proxy it was replacing,
/// if that still runs.
fn recorded(store: &Store) -> Result<Option<(Saved, Liveness)>, Error> {
    let Some(s) = read_state(store)? else { return Ok(None) };
    match liveness(store, &s) {
        Liveness::Gone => {
            let back = replaced(store, &s);
            if store.meta_swap(STATE_KEY, Some(&s.raw), back.as_ref().map(|b| b.raw.as_str()))? && back.is_none() {
                return Ok(None);
            }
            // Given back, or changed meanwhile: judge what is there now.
            recorded(store)
        }
        known => Ok(Some((s, known))),
    }
}

/// The proxy that the restart holding `s` was replacing, if that proxy still runs.
fn replaced(store: &Store, s: &Saved) -> Option<Saved> {
    s.was.as_deref().and_then(parse_state).filter(|w| w.restart.is_none() && liveness(store, w) != Liveness::Gone)
}

/// The running proxy's saved state, clearing stale state left by a crash. Not a restart's
/// hold on the record, which has no proxy to connect to.
fn current(store: &Store) -> Result<Option<Saved>, Error> {
    Ok(recorded(store)?.filter(|(s, known)| *known == Liveness::Running && s.restart.is_none()).map(|(s, _)| s))
}

/// The running proxy for this project, clearing stale state left by a crash.
pub(crate) fn running(store: &Store) -> Result<Option<ProxyState>, Error> {
    Ok(current(store)?.map(|s| s.state))
}

/// The running proxy if it is in this container, so that its address can be connected to.
pub(crate) fn running_here(store: &Store) -> Result<Option<ProxyState>, Error> {
    Ok(current(store)?.filter(|s| !process::elsewhere(s.pid_ns.as_deref())).map(|s| s.state))
}

/// What [`stop`] did.
pub(crate) struct Stopped {
    /// The proxy that is off now: its pid, and whether the stop had to kill it. `None` if none ran.
    pub(crate) proxy: Option<(u32, bool)>,
    /// The pid of a `proxy restart` under way that the stop called off.
    pub(crate) restart: Option<u32>,
}

/// Stops this project's proxy if one runs. A restart under way is called off first (see
/// [`call_off`]): it doesn't start anything, and the proxy it had stopped stays off. With `only`,
/// it stops the proxy only if that pid is the one running here, and calls off nothing. Fails if
/// another proxy has taken the record by the time the proxy is gone.
pub(crate) fn stop(store: &Store, only: Option<u32>) -> Result<Stopped, Error> {
    match stop_once(store, only)? {
        (stopped, None) => Ok(stopped),
        (_, Some(since)) => Err(since),
    }
}

/// [`stop`], and again for a proxy that has taken the record meanwhile: what `project stop` does.
pub(crate) fn stop_every(store: &Store) -> Result<Stopped, Error> {
    let (first, mut since) = stop_once(store, None)?;
    for _ in 0..2 {
        if since.is_none() {
            break;
        }
        since = stop_once(store, None)?.1;
    }
    match since {
        None => Ok(first),
        Some(since) => Err(since),
    }
}

/// One [`stop`]: what it did, and the conflict it ends with if another proxy has the record now.
fn stop_once(store: &Store, only: Option<u32>) -> Result<(Stopped, Option<Error>), Error> {
    let mut hold = if only.is_none() { call_off(store, CANCEL_WAIT)? } else { None };
    // Marked as being stopped before it is asked to exit (see `Saved::stopping`).
    let (saved, stopping) = loop {
        let Some((saved, known)) = recorded(store)? else {
            // A restart called off had stopped its proxy already.
            let proxy =
                hold.as_ref().and_then(|h| h.was.as_deref()).and_then(parse_state).map(|w| (w.state.pid, false));
            return Ok((Stopped { proxy, restart: hold.map(|h| h.state.pid) }, None));
        };
        if let Some(pid) = only {
            if saved.state.pid != pid || saved.restart.is_some() || process::elsewhere(saved.pid_ns.as_deref()) {
                return Err(Error::NotFound(format!(
                    "pid {pid} isn't this project's proxy here (the record is now {}'s); nothing was stopped",
                    process::pid_text(saved.state.pid, saved.pid_ns.as_deref())
                )));
            }
        }
        // A restart that took the record since: called off too.
        if saved.restart.is_some() {
            match call_off(store, CANCEL_WAIT)? {
                Some(h) => hold = Some(h),
                None if known != Liveness::Running => return Err(already_running(&saved, known)),
                None => {}
            }
            continue;
        }
        if saved.stopping {
            let raw = saved.raw.clone();
            break (saved, raw);
        }
        let stopping = serde_json::to_string(&Saved { stopping: true, ..saved.clone() }).unwrap_or_default();
        if store.meta_swap(STATE_KEY, Some(&saved.raw), Some(&stopping))? {
            break (saved, stopping);
        }
        // A restart took it, or the proxy exited, since it was read.
    };
    let forced = match halt(store, &saved) {
        Ok(forced) => forced,
        Err(e) => {
            // It still runs: back to its record as found.
            store.meta_swap(STATE_KEY, Some(&stopping), Some(&saved.raw))?;
            return Err(e);
        }
    };
    store.meta_set(STOP_KEY, None)?;
    // The proxy clears its record as it exits. Anything there now is another proxy's.
    store.meta_swap(STATE_KEY, Some(&stopping), None)?;
    let stopped = Stopped { proxy: Some((saved.state.pid, forced)), restart: hold.map(|h| h.state.pid) };
    let since = recorded(store)?.map(|(now, _)| {
        Error::Conflict(format!(
            "stopped the proxy ({}), but another one has started since, on {} ({}); `brainproxy proxy stop` stops \
             that one",
            process::pid_text(saved.state.pid, saved.pid_ns.as_deref()),
            now.state.listen,
            process::pid_text(now.state.pid, now.pid_ns.as_deref())
        ))
    });
    Ok((stopped, since))
}

/// Calls off a `proxy restart` that holds the record, and waits up to `wait` for it to let go:
/// its hold, or `None` if there is none. Refused if the hold can't be verified, or is still
/// there after `wait`.
fn call_off(store: &Store, wait: Duration) -> Result<Option<Saved>, Error> {
    let Some((hold, known)) = recorded(store)?.filter(|(s, _)| s.restart.is_some()) else { return Ok(None) };
    let Some(token) = hold.restart.as_deref().filter(|_| known == Liveness::Running) else {
        return Err(already_running(&hold, known));
    };
    store.meta_set(CANCEL_KEY, Some(token))?;
    let held = || -> Result<Option<Saved>, Error> {
        Ok(recorded(store)?.map(|(s, _)| s).filter(|s| s.restart == hold.restart))
    };
    let deadline = Instant::now() + wait;
    while let Some(now) = held()?.filter(|_| Instant::now() < deadline) {
        // A restart that has gone can't call off the proxy it was starting: that is stopped here.
        if let Some(pid) = starting_here(&now).filter(|_| restart_gone(store, &now)) {
            let _ = process::terminate(pid, now.starting.and_then(|(_, start)| start), "proxy", STOP_WAIT);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Called off, the call-off stays: a proxy started on the restart's behalf that hasn't been
    // seen yet (going back, say) refuses the record by it (see `serve`). A later one replaces it.
    if held()?.is_some() {
        store.meta_swap(CANCEL_KEY, Some(token), None)?;
        return Err(Error::Conflict(format!(
            "the proxy is being restarted (`brainproxy proxy restart`, {}), and the restart hasn't given up {} s after \
             being asked to; try again once it has finished",
            process::pid_text(hold.state.pid, hold.pid_ns.as_deref()),
            wait.as_secs()
        )));
    }
    Ok(Some(hold))
}

/// Asks a `proxy restart` that holds the record to give up, without waiting for it: [`stop`]
/// does that later. Whether there was one.
pub(crate) fn ask_restart_to_give_up(store: &Store) -> Result<bool, Error> {
    match recorded(store)? {
        Some((s, Liveness::Running)) if s.restart.is_some() => {
            store.meta_set(CANCEL_KEY, s.restart.as_deref())?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Whether `proxy stop` has called off the restart whose token this is.
fn called_off(store: &Store, token: &str) -> bool {
    store.meta_get(CANCEL_KEY).ok().flatten().as_deref() == Some(token)
}

/// Asks the proxy recorded as `saved` to exit and waits until it has; whether it had to be
/// killed. Its record is the caller's to clear or replace.
fn halt(store: &Store, saved: &Saved) -> Result<bool, Error> {
    let Saved { state, start_time, pid_ns, .. } = saved;
    process::request_stop(store, STOP_KEY, state.pid)?;
    let wait = match (state.authz_run.is_some(), start_time.is_some()) {
        (true, _) => STOP_WAIT_AUTHZ,
        (false, true) => STOP_WAIT,
        (false, false) => STOP_WAIT_OLD,
    };
    let forced = if process::elsewhere(pid_ns.as_deref()) {
        process::await_exit_elsewhere(store, LOCK_NAME, STATE_KEY, state.pid, wait)?;
        false
    } else {
        process::terminate(state.pid, *start_time, "proxy", wait)?
    };
    // Killed, it couldn't save its run; the rows recorded so far stay.
    if let Some(id) = state.authz_run.filter(|_| forced) {
        if !is_finished(&store.job_state(id)?) {
            store.job_set_state(id, "failed", None, Some("the proxy was killed before the run was saved"), true)?;
        }
    }
    Ok(forced)
}

/// Clears a record that can't be verified: its pid, or `None` if there is no record.
fn forget(store: &Store) -> Result<Option<u32>, Error> {
    let Some((saved, known)) = recorded(store)? else { return Ok(None) };
    if known == Liveness::Running && saved.restart.is_some() {
        return Err(already_running(&saved, known));
    }
    if known == Liveness::Running {
        return Err(Error::Conflict(format!(
            "the proxy is running ({}), so its record stays; use `brainproxy proxy stop`",
            process::pid_text(saved.state.pid, saved.pid_ns.as_deref())
        )));
    }
    store.meta_swap(STATE_KEY, Some(&saved.raw), None)?;
    store.meta_set(STOP_KEY, None)?;
    Ok(Some(saved.state.pid))
}

/// An address to connect to the proxy on: a wildcard listen address isn't one, so its loopback.
/// Only the whole host is matched (`10.0.0.0:8080` stays as it is).
pub(crate) fn connect_addr(listen: &str) -> String {
    match listen.rsplit_once(':') {
        Some(("0.0.0.0", port)) => format!("127.0.0.1:{port}"),
        Some(("[::]", port)) => format!("[::1]:{port}"),
        _ => listen.to_string(),
    }
}

/// A listen address for text output: its URL, or for a wildcard address what it is and the
/// URL to use here.
fn listen_text(listen: &str) -> String {
    match connect_addr(listen) {
        addr if addr == listen => format!("http://{listen}"),
        addr => format!("{listen}, every network interface (here: http://{addr})"),
    }
}

fn usage_hints(state: &ProxyState) -> Value {
    let url = format!("http://{}", connect_addr(&state.listen));
    let ca = state.ca_cert.display();
    json!({
        "proxy_url": url,
        // Windows curl (Schannel) also wants a revocation check, which a local CA can't answer.
        "curl": format!(
            "curl --noproxy '' -x {url} --cacert {ca}{} https://TARGET/",
            if cfg!(windows) { " --ssl-no-revoke" } else { "" }
        ),
        "note": "--noproxy '' stops NO_PROXY (often set to localhost) from bypassing the proxy.",
        "env": format!("export http_proxy={url} https_proxy={url} HTTP_PROXY={url} HTTPS_PROXY={url}"),
        "trust_ca_for_tools": format!("export SSL_CERT_FILE={ca} REQUESTS_CA_BUNDLE={ca} CURL_CA_BUNDLE={ca}"),
        "chromium": format!("chromium --headless --proxy-server={url} --ignore-certificate-errors"),
    })
}

fn state_json(state: &ProxyState) -> Value {
    let mut v = json!(state);
    v["usage"] = usage_hints(state);
    v
}

pub fn proxy(project: &Path, home: &Path, cmd: ProxyCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        ProxyCmd::Start(args) => start(project, home, args, out),
        ProxyCmd::Run(_) if std::env::var_os(GUARD_ENV).is_some() => guard(project, home, out),
        ProxyCmd::Run(args) => {
            let hold = restart_hold();
            std::thread::scope(|s| {
                if let Some(wait) = restart_wait() {
                    let hold = hold.clone();
                    s.spawn(move || give_up_after(project, home, wait, hold, out));
                }
                let result = run_foreground(project, home, args, out);
                settle_own();
                result.map_err(|e| match TOOK_RECORD.load(Ordering::SeqCst) {
                    true => e,
                    false => go_back(project, home, hold, e),
                })
            })
        }
        ProxyCmd::Restart(args) => restart(project, home, args, out),
        ProxyCmd::Setup(cmd) => setup(project, cmd, out),
        ProxyCmd::Stop { forget: true, .. } => {
            let store = Store::open(project)?;
            let pid = forget(&store)?.ok_or_else(|| Error::NotFound("no proxy recorded for this project".into()))?;
            out.ok(json!({"forgotten": pid}), || format!("cleared the record of the proxy (pid {pid})"));
            Ok(())
        }
        ProxyCmd::Stop { forget: false, pid } => {
            let store = Store::open(project)?;
            let Stopped { proxy, restart } = stop(&store, pid)?;
            let (pid, forced) = proxy.ok_or_else(|| Error::NotFound("no proxy running for this project".into()))?;
            out.ok(json!({"stopped": pid, "forced": forced, "restart_called_off": restart}), || match restart {
                Some(r) => format!("stopped proxy (pid {pid}), calling off the restart under way (pid {r})"),
                None => format!("stopped proxy (pid {pid})"),
            });
            Ok(())
        }
        ProxyCmd::Status => {
            let store = Store::open(project)?;
            let (saved, known) = recorded(&store)?.unzip();
            let unverified = saved.as_ref().filter(|_| known == Some(Liveness::Unverified)).map(|s| {
                json!({"pid": s.state.pid, "listen": s.state.listen,
                    "reason": process::unverified_text(lock_of(s), s.state.pid),
                    "next": "brainproxy proxy stop --forget"})
            });
            let pid_ns = saved.as_ref().and_then(|s| s.pid_ns.clone());
            let (held, saved) = match saved {
                Some(s) if s.restart.is_some() => (known == Some(Liveness::Running), None),
                saved => (false, saved),
            };
            let state = saved.filter(|_| known == Some(Liveness::Running)).map(|s| s.state);
            let captures = store.list(&HistoryFilter { source: Some("proxy".into()), ..Default::default() })?.len();
            let pending = store.intercept_list(Some("pending"), u32::MAX)?.len();
            let intercept: InterceptSettings = store.setting(INTERCEPT_KEY)?;
            let rules: Vec<Rule> = store.setting(RULES_KEY)?;
            let scope: Scope = store.setting(SCOPE_KEY)?;
            let changes = store.recording_changes()?;
            let narrowed = changes.narrowed_by_agent();
            let authz = match state.as_ref().and_then(|s| s.authz_run) {
                Some(id) => {
                    let job = store.job_get(id)?;
                    json!({"run_id": id, "state": job["state"], "progress": job["progress"],
                        "next": format!("brainproxy authz matrix {id}")})
                }
                None => Value::Null,
            };
            let data = json!({
                "running": state.is_some(),
                "restarting": held,
                "proxy": state.as_ref().map(state_json),
                "other_pid_namespace": process::elsewhere(pid_ns.as_deref()),
                "unverified": unverified,
                "proxy_captures": captures,
                "pending_intercepts": pending,
                "intercept_enabled": intercept.enabled,
                "rules_enabled": rules.iter().filter(|r| r.enabled).count(),
                "scope": scope,
                "recording_last_change": changes.recent(1).first(),
                "recording_narrowed_by_agent": narrowed,
                "recording_kept_changes": changes.kept(),
                "authz": authz,
            });
            let notes: String = narrowed.iter().map(|c| format!("\nnot reviewed: {}", c.describe())).collect();
            out.ok(data, || {
                let status = match &state {
                    Some(s) => format!(
                        "running on {} ({}), {captures} captures, {pending} pending{}",
                        listen_text(&s.listen),
                        process::pid_text(s.pid, pid_ns.as_deref()),
                        live_text(s.authz_run)
                    ),
                    None => match &unverified {
                        Some(u) => u["reason"].as_str().unwrap_or_default().to_string(),
                        None if held => "not running: being restarted".into(),
                        None => "not running".into(),
                    },
                };
                status + &notes
            });
            Ok(())
        }
    }
}

fn start(project: &Path, home: &Path, args: ProxyRunArgs, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    if let Some((s, known)) = recorded(&store)? {
        return Err(already_running(&s, known));
    }
    let state = Launch::prepare(project, home, &args, &store, MAX_WAIT)?.spawn(&store, None)?;
    out.ok(state_json(&state), || {
        format!("proxy listening on {} (pid {}){}", listen_text(&state.listen), state.pid, live_text(state.authz_run))
    });
    Ok(())
}

/// A `proxy run` for the background, its options checked, ready to start.
struct Launch {
    cmd: std::process::Command,
    log: PathBuf,
    wait: f64,
}

impl Launch {
    /// Checks `args`, with a `--wait` of at most `max_wait` seconds.
    fn prepare(project: &Path, home: &Path, args: &ProxyRunArgs, store: &Store, max_wait: f64) -> Result<Self, Error> {
        // NaN fails this too.
        if !(0.0..=max_wait).contains(&args.wait) {
            return Err(Error::InvalidInput(format!("--wait must be from 0 to {max_wait} seconds")));
        }
        check_listen_arg(&args.listen)?;
        check_routing(args.invisible, args.redirect.is_some())?;
        load_ca(home)?; // Surface CA and scope problems here rather than in the log.
        store.guard()?;
        let project = std::fs::canonicalize(project)?;
        let log = args.log.clone().unwrap_or_else(|| project.with_extension("proxy.log"));
        let mut cmd = std::process::Command::new(std::env::current_exe()?);
        cmd.arg("--project")
            .arg(&project)
            .arg("--home")
            .arg(home)
            .args(["--format", "json", "proxy", "run", "--listen", &args.listen])
            .args(["--timeout", &args.timeout.to_string()])
            .arg("--log")
            .arg(&log)
            .env_remove(BACK_ENV)
            .env_remove(WAS_ENV)
            .env_remove(GUARD_ENV);
        if args.verify_tls {
            cmd.arg("--verify-tls");
        }
        if args.no_http2 {
            cmd.arg("--no-http2");
        }
        if args.invisible {
            cmd.arg("--invisible");
        }
        if let Some(r) = &args.redirect {
            Target::from_url(r)?;
            cmd.args(["--redirect", r]);
        }
        if let Some(name) = &args.auth {
            store.auth_profile(name)?; // Fail fast on an unknown profile.
            cmd.args(["--auth", name]);
        }
        let live = args.live_authz()?;
        if live.enabled {
            crate::authz_cmd::require_profiles(&project, &live.identities)?;
            cmd.arg("--authz").arg(args.authz.join(","));
            cmd.args(["--authz-rate", &args.authz_rate.to_string(), "--authz-queue", &args.authz_queue.to_string()]);
            cmd.arg("--authz-exclude").arg(&args.authz_exclude);
            if !args.authz_keep_cookie.is_empty() {
                cmd.arg("--authz-keep-cookie").arg(args.authz_keep_cookie.join(","));
            }
        }
        brainproxy_core::provenance::pass_on(&mut cmd);
        Ok(Self { cmd, log, wait: args.wait })
    }

    /// A restart's way back to the proxy it replaced, which doesn't go back again (see [`go_back`]).
    fn going_back(mut self) -> Self {
        self.cmd.env(BACK_ENV, "1");
        self
    }

    /// A restart's new proxy, in place of the one recorded as `was`: it goes back to that one if
    /// it can't come up once the restart has gone (see [`go_back`]).
    fn replacing(mut self, was: &str) -> Self {
        self.cmd.env(WAS_ENV, was);
        self
    }

    /// Starts it and waits until it is listening. `restart` is the token of the restart holding
    /// the record, which the new proxy then takes over; if `proxy stop` calls that restart off
    /// meanwhile, the new proxy is killed.
    fn spawn(mut self, store: &Store, restart: Option<&str>) -> Result<ProxyState, Error> {
        let log_file = std::fs::OpenOptions::new().create(true).append(true).open(&self.log)?;
        let log_start = log_file.metadata()?.len() as usize;
        match restart {
            Some(token) => self.cmd.env(RESTART_ENV, token).env(WAIT_ENV, self.wait.max(0.1).to_string()),
            None => self.cmd.env_remove(RESTART_ENV).env_remove(WAIT_ENV),
        };
        process::detach(&mut self.cmd);
        let mut child = self
            .cmd
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file.try_clone()?))
            .stderr(Stdio::from(log_file))
            .spawn()?;
        if let Some(token) = restart {
            let _ = mark_starting(store, token, child.id());
        }

        let deadline = Instant::now() + Duration::from_secs_f64(self.wait.max(0.1));
        loop {
            if let Some(status) = child.try_wait()? {
                let log_text = std::fs::read(&self.log).unwrap_or_default();
                let new = String::from_utf8_lossy(log_text.get(log_start..).unwrap_or_default()).into_owned();
                return Err(crate::jobs_cmd::child_failure("proxy", status, &new));
            }
            if let Some(Saved { state, .. }) = read_state(store)?.filter(|s| s.state.pid == child.id()) {
                return Ok(state);
            }
            if restart.is_some_and(|token| called_off(store, token)) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Conflict("called off by `brainproxy proxy stop`".into()));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                return Err(Error::Timeout(Duration::from_secs_f64(self.wait)));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Stops the running proxy and starts it with `args`, holding the record in between so that no
/// other start can take it (see `Saved::restart`). If the new proxy doesn't come up, the old one
/// is started again on the address it had, with its options, and the error says where it is: in
/// its message, and in its `data` (`stopped`, `failure`, `restarted`). With no proxy running
/// nothing is started: that is `start`'s job. `proxy stop` can call it off (see [`call_off`]).
fn restart(project: &Path, home: &Path, args: ProxyRunArgs, out: &Out) -> Result<(), Error> {
    out.error_data(json!({"stopped": false}));
    let store = Store::open(project)?;
    let Some((old, known)) = recorded(&store)? else {
        return Err(Error::NotFound(
            "no proxy running for this project; start one with `brainproxy proxy start`".into(),
        ));
    };
    // A `proxy stop` under way (`stopping`) wants the proxy off: leave it to that.
    if known != Liveness::Running || old.restart.is_some() || old.stopping {
        return Err(already_running(&old, known));
    }
    // Everything that can be checked is, before anything stops.
    let back = back_args(&old.state)?;
    // Through MCP the old proxy couldn't be started again where it was, if it listens where other
    // machines can reach it: a restart that failed would leave it off.
    if crate::mcp::in_tool_call() && check_listen_arg(&back.listen).is_err() {
        return Err(Error::InvalidInput(format!(
            "can't restart the proxy through MCP: it listens on {}, not loopback, and through MCP it couldn't be \
             started there again if the restart failed; a person can restart it in the app or a terminal",
            back.listen
        )));
    }
    // Nor could it go back to a redirect or invisible mode, which an agent can't start.
    if crate::mcp::in_tool_call() && (back.invisible || back.redirect.is_some()) {
        return Err(Error::InvalidInput(
            "can't restart the proxy through MCP: it runs with --invisible or --redirect, which a tool call can't \
             start again if the restart failed; a person can restart it in the app or a terminal"
                .into(),
        ));
    }
    let launch = Launch::prepare(project, home, &args, &store, MAX_RESTART_WAIT)?;

    // Before the hold goes in, so that from the moment it is there the lock vouches for it.
    let lock = process::RunLock::acquire(&store, RESTART_LOCK)?;
    let me = std::process::id();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let token = format!("{me}-{}", now.as_nanos());
    let hold = Saved {
        state: ProxyState { pid: me, started: now.as_secs().to_string(), authz_run: None, ..old.state.clone() },
        start_time: process::start_time(me),
        pid_ns: lock.as_ref().and_then(|_| process::pid_namespace()),
        restart: Some(token.clone()),
        was: Some(old.raw.clone()),
        starting: None,
        stopping: false,
        raw: String::new(),
    };
    let hold = serde_json::to_string(&hold).unwrap_or_default();
    // Fails if a stop has marked the record since it was read.
    if !store.meta_swap(STATE_KEY, Some(&old.raw), Some(&hold))? {
        return Err(Error::Conflict(
            "the proxy was stopped or replaced while restarting it; see `brainproxy proxy status`".into(),
        ));
    }
    // Gone from here on before the new proxy is recorded, this process would leave the old proxy
    // off: a guard stands by to start it again (see [`guard`]). It is recorded before anything
    // stops, so that the hold lasts as long as the guard is needed.
    if let Err(e) =
        start_guard(project, home, &token, &old.raw, &launch.log).and_then(|g| mark_starting(&store, &token, g))
    {
        let_go_to(&store, &token, Some(&old.raw))?;
        return Err(e);
    }
    // Marked before the old proxy is asked to stop, so that the guard tells a restart gone
    // before that, which leaves the old proxy running, from one gone during it.
    if let Err(e) = mark_stopping(&store, &token) {
        let_go_to(&store, &token, Some(&old.raw))?;
        return Err(e);
    }
    let forced = match halt(&store, &old) {
        Ok(forced) => forced,
        Err(e) => {
            // It still runs: give it its record back.
            let_go_to(&store, &token, Some(&old.raw))?;
            return Err(e);
        }
    };
    // The proxy is off from here, so every way out says where it is now. A request left behind
    // names the old pid, and a new proxy clears it as it starts anyway.
    let _ = store.meta_set(STOP_KEY, None);
    // Called off by `proxy stop`: nothing is started, and the record is let go of.
    let given_up = || {
        let _ = let_go(&store, &token);
        let _ = store.meta_swap(CANCEL_KEY, Some(&token), None);
        let e = Error::Conflict(format!(
            "the restart was called off by `brainproxy proxy stop` after it had stopped the proxy (pid {})",
            old.state.pid
        ));
        out.error_data(json!({"stopped": true, "failure": e.to_string(), "restarted": null, "called_off": true}));
        noted(e, "the proxy is off")
    };
    if called_off(&store, &token) {
        return Err(given_up());
    }

    let state = match launch.replacing(&old.raw).spawn(&store, Some(&token)) {
        Ok(state) => state,
        Err(_) if called_off(&store, &token) => return Err(given_up()),
        Err(e) => {
            let (note, restarted) = match back_to(project, home, &store, &token, &back) {
                Ok(s) => (
                    format!("the proxy was started again on {} (pid {})", s.listen, s.pid),
                    json!({"pid": s.pid, "listen": s.listen}),
                ),
                Err(_) if called_off(&store, &token) => return Err(given_up()),
                Err(e2) => {
                    // Not cleared, it goes when this process does.
                    let _ = let_go(&store, &token);
                    let note =
                        format!("the proxy couldn't be started again on {}: {e2}. {}", back.listen, where_now(&store));
                    (note, Value::Null)
                }
            };
            out.error_data(json!({"stopped": true, "failure": e.to_string(), "restarted": restarted}));
            return Err(noted(e, &note));
        }
    };
    drop(lock);
    let mut data = state_json(&state);
    data["replaced"] =
        json!({"pid": old.state.pid, "listen": old.state.listen, "forced": forced, "args": old.state.args});
    out.ok(data, || {
        format!(
            "proxy listening on {} (pid {}){}, replacing the one on {} (pid {})",
            listen_text(&state.listen),
            state.pid,
            live_text(state.authz_run),
            old.state.listen,
            old.state.pid
        )
    });
    Ok(())
}

/// The options to start the proxy recorded as `state` again with, where it is: what a restart
/// goes back to. Waiting for it no longer than a restart may.
fn back_args(state: &ProxyState) -> Result<ProxyRunArgs, Error> {
    let previous = previous_args(state)?;
    Ok(ProxyRunArgs { listen: state.listen.clone(), wait: previous.wait.min(MAX_RESTART_WAIT), ..previous })
}

/// A proxy started by a restart (not its way back) that fails before it is up, once the restart
/// has gone (killed by an MCP timeout or cancel, say): it starts the proxy the restart replaced
/// again itself, as the restart would have. While the restart runs, going back is its job, and
/// once a stop has called it off there is nothing to go back to. `back` is the restart's token
/// and the replaced proxy's record, from [`restart_hold`].
fn go_back(project: &Path, home: &Path, back: Option<(String, String)>, e: Error) -> Error {
    let Some((token, was)) = back else { return e };
    let Ok(store) = Store::open(project) else { return e };
    // The hold lasts while this proxy starts (`Saved::starting`), so it is only let go of from
    // another container, where the restart's lock is free.
    let gone = match read_state(&store) {
        Ok(None) => true,
        Ok(Some(now)) => now.restart.as_deref() == Some(token.as_str()) && restart_gone(&store, &now),
        Err(_) => false,
    };
    if !gone || called_off(&store, &token) {
        return e;
    }
    let Some(back) = parse_state(&was).and_then(|w| back_args(&w.state).ok()) else { return e };
    let note = match back_to(project, home, &store, &token, &back) {
        Ok(s) => format!(
            "the restart that started it had gone, so the proxy was started again on {} (pid {})",
            s.listen, s.pid
        ),
        Err(e2) => format!(
            "the restart that started it had gone, and the proxy couldn't be started again on {}: {e2}",
            back.listen
        ),
    };
    noted(e, &note)
}

/// Starts the proxy again with `back`, its options where it was, on behalf of the restart whose
/// token this is: the way back from a restart that couldn't finish.
fn back_to(project: &Path, home: &Path, store: &Store, token: &str, back: &ProxyRunArgs) -> Result<ProxyState, Error> {
    Launch::prepare(project, home, back, store, MAX_RESTART_WAIT).and_then(|l| l.going_back().spawn(store, Some(token)))
}

/// Starts the guard of the restart whose token this is, with its output in `log`: its pid. `was`
/// is the record of the proxy the restart replaces.
fn start_guard(project: &Path, home: &Path, token: &str, was: &str, log: &Path) -> Result<u32, Error> {
    let log = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg("--project")
        .arg(std::fs::canonicalize(project)?)
        .arg("--home")
        .arg(home)
        .args(["--format", "json", "proxy", "run"])
        .env(GUARD_ENV, "1")
        .env(RESTART_ENV, token)
        .env(WAS_ENV, was)
        .env_remove(BACK_ENV);
    brainproxy_core::provenance::pass_on(&mut cmd);
    process::detach(&mut cmd);
    let child = cmd.stdin(Stdio::null()).stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?;
    Ok(child.id())
}

/// Stands by for the restart whose token is in [`RESTART_ENV`], from just before it stops the old
/// proxy until it records the proxy it starts. Should the restart go away meanwhile (killed by an
/// MCP timeout or cancel, say), nothing would start the old proxy again: this finishes stopping it
/// and starts it again where it was, as the restart would have. Until then it is the hold's
/// `starting`, so the hold lasts while it does that, and a stop that calls the restart off stops
/// it. It exits quietly once the restart has recorded its proxy or let go of the record.
fn guard(project: &Path, home: &Path, out: &Out) -> Result<(), Error> {
    let (Ok(token), Ok(was)) = (std::env::var(RESTART_ENV), std::env::var(WAS_ENV)) else { return Ok(()) };
    let store = Store::open(project)?;
    // Taken as it starts, so that from another container the hold lasts while this runs (see
    // [`guard_held`]), and held until it exits. Without it (the guard of a restart just before
    // still exiting, say) this still stands by: only another container can't tell.
    let _lock = process::RunLock::acquire(&store, GUARD_LOCK).ok().flatten();
    let me = std::process::id();
    loop {
        let Some(hold) = read_state(&store)?.filter(|s| s.restart.as_deref() == Some(token.as_str())) else {
            return Ok(());
        };
        let recorded_me = match hold.starting {
            Some((pid, _)) if pid != me => return Ok(()),
            starting => starting.is_some(),
        };
        if restart_gone(&store, &hold) {
            if recorded_me && hold.stopping {
                break;
            }
            // Gone before it asked the old proxy to stop, the restart hadn't stopped anything:
            // that proxy gets its record back.
            return let_go_to(&store, &token, Some(&was));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let Some(old) = parse_state(&was) else { return Ok(()) };
    // It may have exited already, or be on its way out.
    if let Err(e) = halt(&store, &old) {
        // It still runs: give it its record back.
        let_go_to(&store, &token, Some(&was))?;
        return Err(e);
    }
    let _ = store.meta_set(STOP_KEY, None);
    let back = back_args(&old.state)?;
    let again = match called_off(&store, &token) {
        false => back_to(project, home, &store, &token, &back),
        true => Err(Error::Conflict("called off by `brainproxy proxy stop`".into())),
    };
    let had_gone = "the restart had gone before it started the new proxy";
    match again {
        Ok(s) => {
            out.ok(json!({"restarted": {"pid": s.pid, "listen": s.listen}}), || {
                format!("{had_gone}, so the proxy was started again on {} (pid {})", s.listen, s.pid)
            });
            Ok(())
        }
        // Called off by `proxy stop`: the proxy stays off.
        Err(_) if called_off(&store, &token) => let_go(&store, &token),
        Err(e) => {
            let _ = let_go(&store, &token);
            Err(noted(e, &format!("{had_gone}, and the proxy couldn't be started again on {}", back.listen)))
        }
    }
}

/// The token of the restart that started this process and the record of the proxy it replaces,
/// if this is the proxy it starts in that one's place (not its way back): what [`go_back`]
/// goes back to. From the environment, since the record may have changed by now.
fn restart_hold() -> Option<(String, String)> {
    if std::env::var_os(BACK_ENV).is_some() {
        return None;
    }
    Some((std::env::var(RESTART_ENV).ok()?, std::env::var(WAS_ENV).ok()?))
}

/// How long this `proxy run` has to take the record, if a restart started it: the wait the
/// restart gave it ([`WAIT_ENV`]).
fn restart_wait() -> Option<Duration> {
    std::env::var_os(RESTART_ENV)?;
    let wait = std::env::var(WAIT_ENV).ok().and_then(|w| w.parse::<f64>().ok());
    let wait = wait.filter(|w| (0.0..=MAX_RESTART_WAIT).contains(w)).unwrap_or(MAX_RESTART_WAIT);
    Some(Duration::from_secs_f64(wait.max(0.1)))
}

/// A `proxy run` started on a restart's behalf that hasn't taken the record `wait` after it
/// started gives up, once the restart has gone: hung before it is up (logging in for `--auth`
/// to a server that never answers, say), it would otherwise keep the restart's hold, and every
/// other start out, for as long as it hangs. While the restart runs, giving up is its job: it
/// kills this proxy at the same deadline. The proxy started in place of the old one goes back
/// to that one as it gives up (see [`go_back`]). Runs beside the proxy's own start until either
/// settles how it ends (see [`SETTLED`]), so the proxy can't take the record once this has gone
/// back, nor this go back once it has.
fn give_up_after(project: &Path, home: &Path, wait: Duration, back: Option<(String, String)>, out: &Out) {
    let deadline = Instant::now() + wait;
    let token = std::env::var(RESTART_ENV).ok();
    let mut store = None;
    while SETTLED.load(Ordering::SeqCst) == WAITING {
        std::thread::sleep(Duration::from_millis(50));
        if Instant::now() < deadline {
            continue;
        }
        if store.is_none() {
            store = Store::open(project).ok();
        }
        let restart_runs = store.as_ref().is_some_and(|store| {
            read_state(store).ok().flatten().is_some_and(|now| now.restart == token && !restart_gone(store, &now))
        });
        if restart_runs || SETTLED.compare_exchange(WAITING, GAVE_UP, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            continue;
        }
        let e = Error::Conflict(format!("gave up: not up within the restart's wait ({} s)", wait.as_secs_f64()));
        // The run this proxy created ends with it.
        let run = LIVE_RUN.load(Ordering::SeqCst);
        if let Some(store) = store.as_ref().filter(|_| run != 0) {
            if store.job_state(run).is_ok_and(|s| !is_finished(&s)) {
                let _ = store.job_set_state(run, "failed", None, Some(&e.to_string()), true);
            }
        }
        let e = go_back(project, home, back, e);
        out.error(e.kind(), &e.to_string());
        std::process::exit(e.exit_code());
    }
}

/// Settles that this `proxy run` goes on to take the record, or fails, by itself (see
/// [`SETTLED`]). If it has given up waiting to instead, it waits for that to end the process.
fn settle_own() {
    if SETTLED.compare_exchange(WAITING, OWN, Ordering::SeqCst, Ordering::SeqCst) == Err(GAVE_UP) {
        loop {
            std::thread::park();
        }
    }
}

/// Records in the hold of the restart whose token this is that it is starting `pid`.
fn mark_starting(store: &Store, token: &str, pid: u32) -> Result<(), Error> {
    if let Some(hold) = read_state(store)?.filter(|s| s.restart.as_deref() == Some(token)) {
        let marked = Saved { starting: Some((pid, process::start_time(pid))), ..hold.clone() };
        store.meta_swap(STATE_KEY, Some(&hold.raw), Some(&serde_json::to_string(&marked).unwrap_or_default()))?;
    }
    Ok(())
}

/// Records in the hold of the restart whose token this is that it is stopping the proxy it
/// replaces (see `Saved::stopping`). Fails if the hold isn't as it was.
fn mark_stopping(store: &Store, token: &str) -> Result<(), Error> {
    let hold = read_state(store)?.filter(|s| s.restart.as_deref() == Some(token));
    let marked = hold.as_ref().map(|h| serde_json::to_string(&Saved { stopping: true, ..h.clone() }));
    match (hold, marked) {
        (Some(hold), Some(Ok(marked))) if store.meta_swap(STATE_KEY, Some(&hold.raw), Some(&marked))? => Ok(()),
        _ => Err(Error::Conflict(
            "the proxy was stopped or replaced while restarting it; see `brainproxy proxy status`".into(),
        )),
    }
}

/// Lets go of the hold of the restart whose token this is, as it reads now.
fn let_go(store: &Store, token: &str) -> Result<(), Error> {
    let_go_to(store, token, None)
}

/// Replaces the hold of the restart whose token this is, as it reads now, with `record`.
fn let_go_to(store: &Store, token: &str, record: Option<&str>) -> Result<(), Error> {
    if let Some(hold) = read_state(store)?.filter(|s| s.restart.as_deref() == Some(token)) {
        store.meta_swap(STATE_KEY, Some(&hold.raw), record)?;
    }
    Ok(())
}

/// The options the proxy recorded as `state` was started with, to start it again alike.
fn previous_args(state: &ProxyState) -> Result<ProxyRunArgs, Error> {
    #[derive(clap::Parser)]
    #[command(no_binary_name = true)]
    struct Previous {
        #[command(flatten)]
        args: ProxyRunArgs,
    }
    let unreadable = || {
        Error::Conflict(format!(
            "can't restart the proxy: the options it runs with ({}) can't be read, so it couldn't be started again \
             if the restart failed. Stop it and start it again instead",
            state.args.join(" ")
        ))
    };
    let rest = match state.args.as_slice() {
        [proxy, run, rest @ ..] if proxy == "proxy" && run == "run" => rest,
        // Recorded by a version that didn't keep them.
        [] => &[],
        _ => return Err(unreadable()),
    };
    <Previous as clap::Parser>::try_parse_from(rest).map(|p| p.args).map_err(|_| unreadable())
}

/// Where this project's proxy is now, for a failed restart's message.
fn where_now(store: &Store) -> String {
    match current(store) {
        Ok(Some(s)) => {
            format!(
                "A proxy is running on {} ({}) now",
                s.state.listen,
                process::pid_text(s.state.pid, s.pid_ns.as_deref())
            )
        }
        Ok(None) => "It is off now".into(),
        Err(_) => "See `brainproxy proxy status` for whether it runs".into(),
    }
}

/// `e` with `note` after its message, keeping its kind where it has a message to add to.
fn noted(e: Error, note: &str) -> Error {
    match e {
        Error::InvalidInput(m) => Error::InvalidInput(format!("{m}; {note}")),
        Error::NotFound(m) => Error::NotFound(format!("{m}; {note}")),
        Error::OutOfScope(m) => Error::OutOfScope(format!("{m}; {note}")),
        Error::Conflict(m) => Error::Conflict(format!("{m}; {note}")),
        Error::Connect(m) => Error::Connect(format!("{m}; {note}")),
        Error::Tls(m) => Error::Tls(format!("{m}; {note}")),
        Error::Protocol(m) => Error::Protocol(format!("{m}; {note}")),
        e => Error::Conflict(format!("{e}; {note}")),
    }
}

fn already_running(s: &Saved, known: Liveness) -> Error {
    if known == Liveness::Unverified {
        return Error::Conflict(process::unverified_text(lock_of(s), s.state.pid));
    }
    let pid = process::pid_text(s.state.pid, s.pid_ns.as_deref());
    if s.restart.is_some() {
        return Error::Conflict(format!(
            "the proxy is being restarted (`brainproxy proxy restart`, {pid}); try again once that has finished"
        ));
    }
    if s.stopping {
        return Error::Conflict(format!(
            "the proxy is being stopped (`brainproxy proxy stop`, {pid}); start it with `brainproxy proxy start` once \
             it has"
        ));
    }
    Error::Conflict(format!("proxy already running on {} ({pid})", s.state.listen))
}

fn live_text(run: Option<i64>) -> String {
    run.map(|id| format!("; live authz run {id} (brainproxy authz matrix {id})")).unwrap_or_default()
}

/// Live access-control testing for one proxy run: the job and what it needs to start.
struct LiveRun {
    run_id: i64,
    cfg: AuthzConfig,
    opts: LiveOptions,
    ctl: JobControl,
}

fn run_foreground(project: &Path, home: &Path, args: ProxyRunArgs, out: &Out) -> Result<(), Error> {
    let (ca, info) = load_ca(home)?;
    let store = Store::open(project)?;
    if let Some((s, known)) = recorded(&store)?.filter(|(s, _)| !replaceable(s)) {
        return Err(already_running(&s, known));
    }
    // Fail before listening if there is no scope; the scope can't change while we run.
    let guard = store.guard()?;
    let upstream = SendOptions {
        timeout: Duration::from_secs_f64(args.timeout.max(0.001)),
        verify_tls: args.verify_tls,
        sni: None,
        guard: Some(guard),
        http2: false,
    };
    let live = args.live_authz()?;
    let stored: LiveAuthz = store.setting(AUTHZ_KEY)?;
    if !live.enabled {
        if stored.enabled {
            store.set_setting(AUTHZ_KEY, &LiveAuthz { enabled: false, ..stored })?;
        }
        let auth = crate::auth_cmd::maybe_session(project, args.auth.as_deref(), &upstream)?;
        return serve(project, &args, ca, info, upstream, auth, None, out).map(|_| ());
    }
    let profiles = crate::authz_cmd::require_profiles(project, &live.identities)?;
    let exclude = regex::Regex::new(&live.exclude).map_err(|e| Error::InvalidInput(format!("--authz-exclude: {e}")))?;
    let run_id = store.job_create("authz", "queued", &crate::jobs_cmd::child_args())?;
    LIVE_RUN.store(run_id, Ordering::SeqCst);
    store.set_setting(AUTHZ_KEY, &LiveAuthz { run_id: Some(run_id), ..live.clone() })?;
    // The run lasts as long as the proxy: it completes when the proxy stops, or stops
    // early on `job stop RUN` while the proxy carries on.
    crate::jobs_cmd::run_job(project, Some(run_id), |ctl| {
        // The --auth profile logs in too: the proxy and the tests share its session, so a
        // re-login by either is the other's as well.
        let needed: Vec<String> = live.identities.iter().chain(&args.auth).cloned().collect();
        let known = crate::authz_cmd::load_sessions(project, &profiles, &needed, &upstream)?;
        let find = |n: &String| known.iter().find(|s| &s.profile.name == n).cloned().expect("loaded above");
        let auth = args.auth.as_ref().map(find);
        let cfg = AuthzConfig {
            identities: live.identities.iter().map(find).collect(),
            anonymous: live.anonymous,
            owner: None,
            known: known.clone(),
            keep_cookies: live.keep_cookies.clone(),
            send: upstream.clone(),
            concurrency: 2,
            rate: live.rate,
        };
        let opts = LiveOptions { queue: live.queue, concurrency: 2, exclude };
        let summary =
            serve(project, &args, ca, info, upstream.clone(), auth, Some(LiveRun { run_id, cfg, opts, ctl }), out);
        // serve saved the --auth session.
        for s in &known {
            if live.identities.contains(&s.profile.name) && args.auth.as_ref() != Some(&s.profile.name) {
                s.save()?;
            }
        }
        summary
    })?;
    Ok(())
}

/// Whether this process may take over the record `s`: its own pid is its own state (unless
/// that is the same pid in another container), and so is the hold of the restart starting it.
fn replaceable(s: &Saved) -> bool {
    let restarting = std::env::var(RESTART_ENV).ok();
    (s.state.pid == std::process::id() && !process::elsewhere(s.pid_ns.as_deref()))
        || (s.restart.is_some() && s.restart == restarting)
}

/// Records this process as the proxy, unless another one got there first: the record has to
/// be empty, stale, or [`replaceable`], and still the same when it is written.
fn take_record(store: &Store, saved: &str) -> Result<(), Error> {
    let raw = store.meta_get(STATE_KEY)?;
    let free = match raw.as_deref().map(parse_state) {
        None | Some(None) => true,
        Some(Some(s)) => replaceable(&s) || (liveness(store, &s) == Liveness::Gone && replaced(store, &s).is_none()),
    };
    if free && store.meta_swap(STATE_KEY, raw.as_deref(), Some(saved))? {
        return Ok(());
    }
    Err(match recorded(store)? {
        Some((s, known)) => already_running(&s, known),
        None => Error::Conflict("another proxy for this project started at the same time; try again".into()),
    })
}

/// Clears the record of the proxy recorded as `me` as it exits, as written or as a stop marked
/// it, but not a restart's hold or another proxy's record.
fn release(store: &Store, me: &Saved) -> Result<(), Error> {
    let Some(now) = read_state(store)? else { return Ok(()) };
    let id = |s: &Saved| (s.state.pid, s.state.started.clone(), s.start_time, s.pid_ns.clone());
    if now.restart.is_none() && id(&now) == id(me) {
        store.meta_swap(STATE_KEY, Some(&now.raw), None)?;
    }
    Ok(())
}

/// Under an MCP tool call, refuses a listener other machines could reach: an agent could
/// otherwise open the person's proxy, with their auth profiles, to the network.
fn check_listen(addr: std::net::SocketAddr) -> Result<(), Error> {
    if crate::mcp::in_tool_call() && !addr.ip().is_loopback() {
        return Err(Error::InvalidInput(format!(
            "--listen {addr}: through MCP the proxy listens on loopback only; a person can choose another address \
             in the app or a terminal"
        )));
    }
    Ok(())
}

/// [`check_listen`] for a `--listen` given as an address, before anything starts. A name is
/// checked once the proxy has bound it (see `serve`).
fn check_listen_arg(listen: &str) -> Result<(), Error> {
    match listen.parse() {
        Ok(addr) => check_listen(addr),
        Err(_) => Ok(()),
    }
}

/// Why the address can't be bound, by error kind: the system's own text is localised on Windows.
/// Under an MCP tool call, refuses a proxy that sends the person's browsing anywhere but where
/// it was going: an agent's `--redirect` (or invisible mode, which picks the upstream from the
/// request) on the person's proxy would send everything they browse to an origin it chose.
fn check_routing(invisible: bool, redirect: bool) -> Result<(), Error> {
    if (invisible || redirect) && crate::mcp::in_tool_call() {
        return Err(Error::InvalidInput(
            "--invisible and --redirect aren't offered through MCP: they change where the person's browsing goes, \
             so a person chooses them (Settings › Proxy in the app, or a terminal)"
                .into(),
        ));
    }
    Ok(())
}

fn listen_error(addr: &str, e: &std::io::Error) -> Error {
    Error::Conflict(match e.kind() {
        std::io::ErrorKind::AddrInUse => {
            format!("cannot listen on {addr}: the port is already in use (by another program, or another project's proxy)")
        }
        std::io::ErrorKind::PermissionDenied => format!(
            "cannot listen on {addr}: permission denied (ports below 1024 usually need elevated privileges, and the system can reserve others)"
        ),
        _ => format!("cannot listen on {addr}: {e}"),
    })
}

/// Runs the proxy until it is asked to stop. Returns the live testing summary, if on.
#[allow(clippy::too_many_arguments)]
fn serve(
    project: &Path,
    args: &ProxyRunArgs,
    ca: CertAuthority,
    info: brainproxy_core::proxy::CaInfo,
    upstream: SendOptions,
    auth: Option<std::sync::Arc<brainproxy_core::auth::AuthSession>>,
    live: Option<LiveRun>,
    out: &Out,
) -> Result<Value, Error> {
    let store = Store::open(project)?;
    let redirect = args.redirect.as_deref().map(Target::from_url).transpose()?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        // Settled before it takes the address or the lock: a proxy that has given up waiting
        // holds neither while the one it goes back to starts.
        settle_own();
        let listener = tokio::net::TcpListener::bind(&args.listen).await.map_err(|e| listen_error(&args.listen, &e))?;
        let addr = listener.local_addr()?;
        check_listen(addr)?;
        let (authz, worker) = match live {
            Some(l) => {
                let (live, worker) = Live::start(project, l.run_id, l.cfg, l.opts, l.ctl)?;
                (Some(live), Some(worker))
            }
            None => (None, None),
        };
        let started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let state = ProxyState {
            pid: std::process::id(),
            listen: addr.to_string(),
            started: started.to_string(),
            ca_cert: info.cert_path.clone(),
            log: args.log.clone(),
            authz_run: authz.as_ref().map(|l| l.run_id()),
            args: crate::jobs_cmd::child_args(),
        };
        let lock = process::RunLock::acquire(&store, LOCK_NAME)?;
        let saved = Saved {
            state,
            start_time: process::start_time(std::process::id()),
            pid_ns: lock.as_ref().and_then(|_| process::pid_namespace()),
            restart: None,
            was: None,
            starting: None,
            stopping: false,
            raw: String::new(),
        };
        let raw = serde_json::to_string(&saved).unwrap_or_default();
        // A restart called off while this proxy started: it stays off.
        if std::env::var(RESTART_ENV).is_ok_and(|token| called_off(&store, &token)) {
            return Err(Error::Conflict(
                "the restart starting this proxy was called off by `brainproxy proxy stop`".into(),
            ));
        }
        take_record(&store, &raw)?;
        TOOK_RECORD.store(true, Ordering::SeqCst);
        let state = &saved.state;
        out.ok(state_json(state), || {
            format!("proxy listening on {}{}", listen_text(&state.listen), live_text(state.authz_run))
        });

        let shutdown = process::shutdown(&store, STOP_KEY);
        let opts = ProxyOptions {
            project: project.to_path_buf(),
            upstream,
            auth: auth.clone(),
            http2: !args.no_http2,
            invisible: args.invisible,
            redirect: redirect.clone(),
            authz,
        };
        let result = brainproxy_core::proxy::run(listener, std::sync::Arc::new(ca), opts, shutdown).await;
        // The proxy has recorded (and offered) everything by now.
        let summary = match worker {
            Some(w) => w.finish().await,
            None => Ok(Value::Null),
        };
        release(&store, &saved)?;
        if let Some(a) = &auth {
            a.save()?;
        }
        result?;
        summary
    })
}

/// The latest changes to what the proxy records that `scope show` lists, besides every one
/// through MCP or that narrowed recording.
const SCOPE_CHANGES_SHOWN: usize = 20;

pub fn scope(project: &Path, cmd: ScopeCmd, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    let mut scope: Scope = store.setting(SCOPE_KEY)?;
    match cmd {
        ScopeCmd::Show => {
            let changes = store.recording_changes()?;
            let mut data = json!(scope);
            data["recording_changes"] = json!(changes.shown(SCOPE_CHANGES_SHOWN));
            data["narrowed_by_agent"] = json!(changes.narrowed_by_agent());
            out.ok(data, || {
                let mut text = serde_json::to_string_pretty(&scope).unwrap_or_default();
                for c in changes.narrowed_by_agent() {
                    text.push_str(&format!("\nnot reviewed: {}", c.describe()));
                }
                if let Some(c) = changes.recent(1).first() {
                    text.push_str(&format!("\nlast change: {}", c.describe()));
                }
                text
            });
            return Ok(());
        }
        ScopeCmd::Set { include, exclude, record_out_of_scope } => {
            scope = Scope { include, exclude, record_out_of_scope };
        }
        ScopeCmd::Add { include, exclude } => {
            scope.include.extend(include);
            scope.exclude.extend(exclude);
        }
        ScopeCmd::Clear => scope = Scope::default(),
        ScopeCmd::Check { host } => {
            let allowed = scope.compile()?.allows(&host);
            out.ok(json!({"host": host, "in_scope": allowed}), || {
                format!("{host}: {}", if allowed { "in scope" } else { "out of scope" })
            });
            return Ok(());
        }
    }
    scope.compile()?; // Validate before saving.
                      // Logged with who changed it, against the scope as saved just before (see `save_scope`).
    store.save_scope(&scope)?;
    out.ok(json!(scope), || serde_json::to_string_pretty(&scope).unwrap_or_default());
    Ok(())
}

pub fn rules(project: &Path, cmd: RulesCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    let mut rules: Vec<Rule> = store.setting(RULES_KEY)?;
    let find = |rules: &mut Vec<Rule>, id: u32| -> Result<usize, Error> {
        rules.iter().position(|r| r.id == id).ok_or_else(|| Error::NotFound(format!("rule {id}")))
    };
    match cmd {
        RulesCmd::List => {
            out.ok(json!({"rules": rules}), || serde_json::to_string_pretty(&rules).unwrap_or_default());
            return Ok(());
        }
        RulesCmd::Add { location, pattern, replace, comment, disabled } => {
            let id = rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
            let rule = Rule {
                id,
                location: RuleLocation::parse(&location)?,
                pattern,
                replace,
                enabled: !disabled,
                comment,
                origin: Some(brainproxy_core::provenance::origin().to_string()),
            };
            brainproxy_core::proxy::config::validate_rule(&rule)?;
            rules.push(rule);
        }
        RulesCmd::Remove { id } => {
            let i = find(&mut rules, id)?;
            rules.remove(i);
        }
        RulesCmd::Enable { id } => {
            let i = find(&mut rules, id)?;
            brainproxy_core::proxy::config::validate_rule(&rules[i])?;
            // Whoever turns a rule on answers for what it changes from then on.
            if !rules[i].enabled {
                rules[i].origin = Some(brainproxy_core::provenance::origin().to_string());
            }
            rules[i].enabled = true;
        }
        RulesCmd::Disable { id } => {
            let i = find(&mut rules, id)?;
            rules[i].enabled = false;
        }
        RulesCmd::Clear => rules.clear(),
    }
    store.set_setting(RULES_KEY, &rules)?;
    out.ok(json!({"rules": rules}), || serde_json::to_string_pretty(&rules).unwrap_or_default());
    Ok(())
}

pub fn intercept(project: &Path, cmd: InterceptCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        InterceptCmd::Enable {
            requests,
            responses,
            ws_to_server,
            ws_to_client,
            host,
            path,
            method,
            timeout,
            timeout_action,
        } => {
            let settings = InterceptSettings {
                enabled: true,
                requests: requests || !(responses || ws_to_server || ws_to_client),
                responses,
                ws_to_server,
                ws_to_client,
                host,
                path,
                method,
                timeout_secs: timeout,
                timeout_action: match timeout_action {
                    TimeoutArg::Forward => TimeoutAction::Forward,
                    TimeoutArg::Drop => TimeoutAction::Drop,
                },
            };
            settings.compile()?;
            store.set_setting(INTERCEPT_KEY, &settings)?;
            let warning = running(&store)?.is_none().then_some("no proxy is running for this project");
            out.ok(json!({"settings": settings, "warning": warning}), || "intercept enabled".into());
        }
        InterceptCmd::Disable => {
            let mut settings: InterceptSettings = store.setting(INTERCEPT_KEY)?;
            settings.enabled = false;
            store.set_setting(INTERCEPT_KEY, &settings)?;
            out.ok(json!({"settings": settings}), || "intercept disabled".into());
        }
        InterceptCmd::Status => {
            let settings: InterceptSettings = store.setting(INTERCEPT_KEY)?;
            let pending = store.intercept_list(Some("pending"), u32::MAX)?.len();
            out.ok(json!({"settings": settings, "pending": pending}), || {
                format!("enabled: {}, pending: {pending}", settings.enabled)
            });
        }
        InterceptCmd::List { state, wait, limit } => {
            let state = match state {
                StateArg::Pending => Some("pending"),
                StateArg::Forwarded => Some("forwarded"),
                StateArg::Dropped => Some("dropped"),
                StateArg::Expired => Some("expired"),
                StateArg::All => None,
            };
            let started = Instant::now();
            let deadline = started + Duration::from_secs_f64(wait.max(0.0));
            let items = loop {
                let items = store.intercept_list(state, limit)?;
                if !items.is_empty() || Instant::now() >= deadline {
                    break items;
                }
                std::thread::sleep(Duration::from_millis(100));
            };
            let data = json!({"count": items.len(), "items": items, "waited_ms": started.elapsed().as_millis() as u64});
            out.ok(data, || {
                items
                    .iter()
                    .map(|i| format!("{:>6}  {:<8} {:<9} {:<7} {}", i.id, i.direction, i.state, i.method, i.url))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        InterceptCmd::Show { id, raw, max_body } => {
            let (entry, original, edited) = store.intercept_get(id)?;
            if raw {
                out.raw(&original);
                return Ok(());
            }
            let data = json!({
                "entry": entry,
                "message": body_value(&original, max_body),
                "edited": edited.as_deref().map(|e| body_value(e, max_body)),
            });
            out.ok(data, || String::from_utf8_lossy(&original).into_owned());
        }
        InterceptCmd::Forward { id, file, verbatim } => {
            let websocket = store.intercept_get(id)?.0.direction.starts_with("ws-");
            let edited = match file.as_deref() {
                None => None,
                Some(path) => {
                    let bytes = if path == "-" {
                        crate::read_input(None)?
                    } else {
                        std::fs::read(path).map_err(|e| Error::InvalidInput(format!("cannot read {path:?}: {e}")))?
                    };
                    let msg = RawRequest::from_bytes(bytes);
                    Some(
                        if verbatim || websocket { msg } else { msg.normalize_line_endings().update_content_length() }
                            .into_bytes(),
                    )
                }
            };
            let by = brainproxy_core::provenance::origin();
            store.intercept_resolve(id, "forwarded", edited.as_deref(), Some(by))?;
            out.ok(json!({"id": id, "state": "forwarded", "edited": edited.is_some(), "resolved_by": by}), || {
                format!("forwarded #{id}")
            });
        }
        InterceptCmd::Drop { id } => {
            let by = brainproxy_core::provenance::origin();
            store.intercept_resolve(id, "dropped", None, Some(by))?;
            out.ok(json!({"id": id, "state": "dropped", "resolved_by": by}), || format!("dropped #{id}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Error as IoError, ErrorKind};

    use super::*;

    fn conflict_text(kind: ErrorKind) -> String {
        match listen_error("127.0.0.1:80", &IoError::from(kind)) {
            Error::Conflict(text) => text,
            other => panic!("not a conflict: {other}"),
        }
    }

    #[test]
    fn listen_error_says_why_by_kind() {
        assert_eq!(
            conflict_text(ErrorKind::AddrInUse),
            "cannot listen on 127.0.0.1:80: the port is already in use (by another program, or another project's proxy)"
        );
        assert_eq!(
            conflict_text(ErrorKind::PermissionDenied),
            "cannot listen on 127.0.0.1:80: permission denied (ports below 1024 usually need elevated privileges, and the system can reserve others)"
        );
    }

    fn state_with(args: &[&str]) -> ProxyState {
        ProxyState {
            pid: 7,
            listen: "127.0.0.1:8080".into(),
            started: "0".into(),
            ca_cert: "/ca.pem".into(),
            log: None,
            authz_run: None,
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn previous_args_reads_what_the_proxy_runs_with() {
        let args = previous_args(&state_with(&[
            "proxy",
            "run",
            "--listen",
            "0.0.0.0:0",
            "--timeout",
            "12",
            "--log",
            "/x.log",
            "--auth=alice",
            "--invisible",
        ]))
        .unwrap();
        assert_eq!(args.listen, "0.0.0.0:0");
        assert_eq!(args.timeout, 12.0);
        assert_eq!(args.log, Some(PathBuf::from("/x.log")));
        assert_eq!(args.auth.as_deref(), Some("alice"));
        assert!(args.invisible && !args.verify_tls);
        // None recorded (an older version): the defaults.
        let args = previous_args(&state_with(&[])).unwrap();
        assert_eq!((args.listen.as_str(), args.timeout, args.auth), ("127.0.0.1:8080", 30.0, None));
    }

    #[test]
    fn previous_args_refuses_what_it_cannot_read() {
        for args in [&["proxy", "run", "--from-the-future"][..], &["scan", "active"]] {
            let Err(Error::Conflict(text)) = previous_args(&state_with(args)) else { panic!("{args:?} was read") };
            assert!(text.contains("can't restart the proxy"), "{text}");
        }
    }

    #[test]
    fn a_restart_hold_reads_back_with_its_raw_text() {
        let saved = Saved {
            state: state_with(&["proxy", "run"]),
            start_time: Some(1),
            pid_ns: None,
            restart: Some("7-1".into()),
            was: None,
            starting: None,
            stopping: false,
            raw: String::new(),
        };
        let raw = serde_json::to_string(&saved).unwrap();
        assert!(!raw.contains("\"raw\"") && !raw.contains("stopping"), "{raw}");
        let back = parse_state(&raw).unwrap();
        assert_eq!((back.restart.as_deref(), back.raw.as_str()), (Some("7-1"), raw.as_str()));
        let Error::Conflict(text) = already_running(&back, Liveness::Running) else { panic!() };
        assert!(text.starts_with("the proxy is being restarted (`brainproxy proxy restart`, pid 7)"), "{text}");
        // A record from before restarts were held has none.
        let old = r#"{"pid":7,"listen":"127.0.0.1:1","started":"0","ca_cert":"/x","log":null}"#;
        assert_eq!(parse_state(old).unwrap().restart, None);
    }

    /// A record for `pid`, as stored: a restart's hold if `restart` is given.
    fn record(pid: u32, restart: Option<&str>, was: Option<&Saved>) -> Saved {
        let saved = Saved {
            state: ProxyState { pid, ..state_with(&["proxy", "run"]) },
            start_time: process::start_time(pid),
            pid_ns: None,
            restart: restart.map(String::from),
            was: was.map(|w| w.raw.clone()),
            starting: None,
            stopping: false,
            raw: String::new(),
        };
        let raw = serde_json::to_string(&saved).unwrap();
        parse_state(&raw).unwrap()
    }

    fn put(store: &Store, s: &Saved) {
        store.meta_set(STATE_KEY, Some(&s.raw)).unwrap();
    }

    /// Pid 0 is never a process.
    const GONE: u32 = 0;

    #[test]
    fn a_proxy_clears_its_own_record_as_it_exits_even_once_a_stop_marked_it() {
        let store = Store::open_in_memory().unwrap();
        let me = record(std::process::id(), None, None);
        let stopping = parse_state(&serde_json::to_string(&Saved { stopping: true, ..me.clone() }).unwrap()).unwrap();
        assert!(stopping.raw.contains("\"stopping\":true"), "{}", stopping.raw);
        for (now, cleared) in [
            (&me, true),
            (&stopping, true),
            (&record(std::process::id(), Some("t"), Some(&me)), false),
            (&record(GONE, None, None), false),
        ] {
            put(&store, now);
            release(&store, &me).unwrap();
            assert_eq!(store.meta_get(STATE_KEY).unwrap().is_none(), cleared, "{}", now.raw);
        }
    }

    /// A stop under way refuses a restart, and the refusal says so.
    #[test]
    fn a_record_being_stopped_is_left_to_the_stop() {
        let me = record(std::process::id(), None, None);
        let Error::Conflict(text) = already_running(&Saved { stopping: true, ..me }, Liveness::Running) else {
            panic!()
        };
        assert!(text.starts_with("the proxy is being stopped (`brainproxy proxy stop`, pid "), "{text}");
    }

    /// A restart that went away while the proxy it was replacing still ran gives that proxy its
    /// record back, so that it can be seen and stopped. Gone too, the record is cleared.
    #[test]
    fn an_abandoned_restart_gives_the_record_back_to_a_proxy_still_running() {
        let store = Store::open_in_memory().unwrap();
        let old = record(std::process::id(), None, None);
        put(&store, &record(GONE, Some("t"), Some(&old)));
        // Nothing else takes it meanwhile.
        let Err(Error::Conflict(text)) = take_record(&store, "{}") else { panic!("taken") };
        assert!(text.starts_with("proxy already running on"), "{text}");
        put(&store, &record(GONE, Some("t"), Some(&old)));
        let (back, known) = recorded(&store).unwrap().expect("given back");
        assert_eq!((back.raw.as_str(), known), (old.raw.as_str(), Liveness::Running));
        assert_eq!(store.meta_get(STATE_KEY).unwrap(), Some(old.raw.clone()));

        put(&store, &record(GONE, Some("t"), Some(&record(GONE, None, None))));
        assert!(recorded(&store).unwrap().is_none());
        assert_eq!(store.meta_get(STATE_KEY).unwrap(), None);
    }

    /// A stop calls off a restart that holds the record, and is refused if the restart doesn't let
    /// go in time (here it never looks). Either way the call-off doesn't outlive the stop.
    #[test]
    fn a_stop_calls_off_a_restart_and_gives_up_on_one_that_holds_on() {
        let store = Store::open_in_memory().unwrap();
        assert!(call_off(&store, Duration::ZERO).unwrap().is_none());
        assert!(!ask_restart_to_give_up(&store).unwrap());
        let hold = record(std::process::id(), Some("t"), Some(&record(GONE, None, None)));
        put(&store, &hold);
        assert!(ask_restart_to_give_up(&store).unwrap());
        assert!(called_off(&store, "t") && !called_off(&store, "u"));
        let Err(Error::Conflict(text)) = call_off(&store, Duration::from_millis(100)) else { panic!("let go") };
        assert!(text.contains("being restarted") && text.contains("hasn't given up"), "{text}");
        assert_eq!(store.meta_get(STATE_KEY).unwrap(), Some(hold.raw.clone()));
        assert_eq!(store.meta_get(CANCEL_KEY).unwrap(), None);
    }

    /// `stop --pid` stops only that proxy, here: not another one, nor a restart's hold.
    #[test]
    fn a_stop_for_a_pid_leaves_any_other_proxy_alone() {
        let store = Store::open_in_memory().unwrap();
        let hold = record(std::process::id(), Some("t"), None);
        for now in [record(std::process::id(), None, None), hold] {
            put(&store, &now);
            let other = std::process::id() + 1;
            let Err(Error::NotFound(text)) = stop(&store, Some(other)) else { panic!("stopped") };
            assert!(text.starts_with(&format!("pid {other} isn't this project's proxy here")), "{text}");
            assert_eq!(store.meta_get(STATE_KEY).unwrap(), Some(now.raw.clone()));
            assert_eq!(store.meta_get(CANCEL_KEY).unwrap(), None);
        }
        let Err(Error::NotFound(_)) = stop(&store, Some(std::process::id())) else { panic!("a hold was stopped") };
        store.meta_set(STATE_KEY, None).unwrap();
        assert!(stop(&store, Some(1)).unwrap().proxy.is_none());
    }

    /// A hold lasts while the proxy it starts runs, also once the restart has gone, but not once
    /// that proxy has exited, even if nothing reaps it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_hold_lasts_while_its_proxy_starts_but_not_for_a_zombie() {
        let store = Store::open_in_memory().unwrap();
        let starting = |pid: u32| {
            let hold = Saved { starting: Some((pid, process::start_time(pid))), ..record(GONE, Some("t"), None) };
            parse_state(&serde_json::to_string(&hold).unwrap()).unwrap()
        };
        assert_eq!(liveness(&store, &starting(std::process::id())), Liveness::Running);
        assert!(restart_gone(&store, &starting(std::process::id())));
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let hold = starting(child.id());
        let deadline = Instant::now() + Duration::from_secs(5);
        while !process::exited(child.id()) {
            assert!(Instant::now() < deadline, "never exited");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(liveness(&store, &hold), Liveness::Gone);
        child.wait().unwrap();
    }

    /// A restart's hold that can't be verified points at the proxy's own `stop --forget`.
    #[test]
    fn an_unverified_hold_is_named_as_a_restart() {
        let Error::Conflict(text) = already_running(&record(7, Some("t"), None), Liveness::Unverified) else {
            panic!()
        };
        assert!(text.starts_with("can't verify the proxy restart recorded as pid 7"), "{text}");
        assert!(text.ends_with("`brainproxy proxy stop --forget` clears the record"), "{text}");
        let Error::Conflict(text) = already_running(&record(7, None, None), Liveness::Unverified) else { panic!() };
        assert!(text.starts_with("can't verify the proxy recorded as pid 7"), "{text}");
    }

    /// Going back waits no longer than a restart may, whatever the old proxy was started with.
    #[test]
    fn going_back_waits_no_longer_than_a_restart() {
        let back = back_args(&state_with(&["proxy", "run", "--listen", "0.0.0.0:0", "--wait", "3600"])).unwrap();
        assert_eq!((back.listen.as_str(), back.wait), ("127.0.0.1:8080", MAX_RESTART_WAIT));
        assert_eq!(back_args(&state_with(&["proxy", "run", "--wait=5"])).unwrap().wait, 5.0);
    }

    #[test]
    fn noted_keeps_the_kind() {
        let e = noted(Error::Conflict("cannot listen".into()), "the proxy was started again");
        assert_eq!(e.to_string(), "conflict: cannot listen; the proxy was started again");
        let e = noted(Error::Timeout(Duration::from_secs(1)), "it is off now");
        assert_eq!(e.to_string(), "conflict: timed out after 1s; it is off now");
    }

    #[test]
    fn connect_addr_replaces_only_a_whole_wildcard_host() {
        for (listen, addr) in [
            ("0.0.0.0:8080", "127.0.0.1:8080"),
            ("[::]:8080", "[::1]:8080"),
            ("10.0.0.0:8080", "10.0.0.0:8080"),
            ("100.0.0.0:80", "100.0.0.0:80"),
            ("10.0.0.0.0:8080", "10.0.0.0.0:8080"),
            ("[::ffff:0.0.0.0]:8080", "[::ffff:0.0.0.0]:8080"),
            ("[2001:db8::]:8080", "[2001:db8::]:8080"),
            ("127.0.0.1:8080", "127.0.0.1:8080"),
            ("8080", "8080"),
        ] {
            assert_eq!(connect_addr(listen), addr, "{listen}");
        }
    }

    #[test]
    fn listen_text_names_a_wildcard_address_and_where_to_connect() {
        assert_eq!(listen_text("127.0.0.1:8080"), "http://127.0.0.1:8080");
        assert_eq!(listen_text("0.0.0.0:8080"), "0.0.0.0:8080, every network interface (here: http://127.0.0.1:8080)");
        assert_eq!(listen_text("[::]:80"), "[::]:80, every network interface (here: http://[::1]:80)");
    }

    #[test]
    fn the_saved_setup_leaves_defaults_out() {
        let json = |s: &ProxySetup| serde_json::to_string(s).unwrap();
        assert_eq!(json(&ProxySetup::default()), "{}");
        let all = ProxySetup { network: NetworkArg::All, invisible: true, redirect: None };
        assert_eq!(json(&all), r#"{"network":"all","invisible":true}"#);
        assert_eq!(serde_json::from_str::<ProxySetup>(&json(&all)).unwrap(), all);
        assert!(serde_json::from_str::<ProxySetup>(r#"{"network":"ALL"}"#).is_err());
    }

    #[test]
    fn usage_hints_point_at_loopback_for_a_wildcard_listen_address() {
        let state = |listen: &str| ProxyState {
            pid: 1,
            listen: listen.into(),
            started: "0".into(),
            ca_cert: "ca.pem".into(),
            log: None,
            authz_run: None,
            args: vec![],
        };
        for (listen, url) in [
            ("127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("0.0.0.0:8080", "http://127.0.0.1:8080"),
            ("[::]:8080", "http://[::1]:8080"),
            ("[::1]:8080", "http://[::1]:8080"),
            ("10.0.0.5:8080", "http://10.0.0.5:8080"),
            ("10.0.0.0:8080", "http://10.0.0.0:8080"),
            ("100.0.0.0:80", "http://100.0.0.0:80"),
        ] {
            let hints = usage_hints(&state(listen));
            assert_eq!(hints["proxy_url"], url, "{listen}");
            for key in ["curl", "env", "chromium"] {
                let text = hints[key].as_str().unwrap();
                assert!(
                    text.contains(url) && !text.contains("//0.0.0.0") && !text.contains("[::]:"),
                    "{listen} {key}: {text}"
                );
            }
        }
    }

    #[test]
    fn listen_error_keeps_the_system_text_for_other_kinds() {
        let kind = ErrorKind::AddrNotAvailable;
        assert_eq!(conflict_text(kind), format!("cannot listen on 127.0.0.1:80: {}", IoError::from(kind)));
    }
}
