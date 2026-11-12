//! CLI for the intercepting proxy: CA, proxy lifecycle, scope, rules, intercept queue.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use brainproxy_core::authz::live::{Live, LiveOptions};
use brainproxy_core::authz::{AuthzConfig, ANONYMOUS, DEFAULT_EXCLUDE};
use brainproxy_core::http::{RawRequest, SendOptions, Target};
use brainproxy_core::jobs::{is_finished, JobControl};
use brainproxy_core::proxy::config::breaks_head;
use brainproxy_core::proxy::config::{
    InterceptSettings, LiveAuthz, Rule, RuleLocation, Scope, TimeoutAction, AUTHZ_KEY, INTERCEPT_KEY, RULES_KEY,
    RULE_IDS, SCOPE_KEY,
};
use brainproxy_core::proxy::{CertAuthority, ProxyOptions, ProxyState, STATE_KEY};
use brainproxy_core::rules::{Engine, MatchKind, ReplaceKind, RuleAction};
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
/// What was done in place of a restart that had gone before it started its new proxy: written by
/// its guard, or by its new proxy as that gives up, and shown by `proxy status` until a proxy
/// next takes the record (see [`note_gone`]).
const GONE_KEY: &str = "proxy.restart.gone";
/// How long a restart's guard keeps trying to read the store before it gives up (see [`guard`]).
const GUARD_RETRY: Duration = Duration::from_secs(30);
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
    /// Create the interception CA if missing (use --force to replace it; not through MCP).
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
        /// Overwrite an existing --out file (not through MCP).
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
    /// Live access-control testing: also send each in-scope GET request that carries
    /// credentials and got a 2xx that isn't a static asset or a skip path (authz skip list) as
    /// these auth profiles, and/or `anonymous` (no credentials), in the background.
    /// Comma-separated or repeatable. Results: authz matrix RUN.
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
    /// Live testing also tests static assets (stylesheets, scripts, images, fonts, media).
    #[arg(long)]
    authz_include_static: bool,
    /// Live testing also tests HEAD and OPTIONS requests, which have no body to compare
    /// (only the status says anything).
    #[arg(long)]
    authz_head_options: bool,
    /// Live testing also leaves out requests whose path or URL starts with this (* matches any
    /// characters, a trailing $ means it ends there), on top of the project's skip paths.
    /// Repeatable.
    #[arg(long, value_name = "PATTERN")]
    authz_skip_path: Vec<String>,
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
        let skip_paths = brainproxy_core::authz::noise::check_skip_paths(&self.authz_skip_path)
            .map_err(|e| Error::InvalidInput(format!("--authz-skip-path: {e}")))?;
        Ok(LiveAuthz {
            enabled: !self.authz.iter().all(|n| n.trim().is_empty()),
            anonymous: self.authz.iter().any(|n| n.trim() == ANONYMOUS),
            identities,
            rate: (self.authz_rate > 0.0).then_some(self.authz_rate),
            queue: self.authz_queue.max(1),
            exclude: self.authz_exclude.clone(),
            keep_cookies: self.authz_keep_cookie.clone(),
            include_static: self.authz_include_static,
            head_options: self.authz_head_options,
            skip_paths,
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

/// What a rule works on beyond its location, match and replacement: `rules add` saves it,
/// `rules test` tries it unsaved.
#[derive(clap::Args, Clone, Default)]
pub struct RuleOptions {
    /// How --match is read: a regex (the replacement may use $1), literal text (each occurrence
    /// is replaced with --replace as written), or whole (the whole value, when it equals --match).
    #[arg(long, value_parser = MatchKind::ALL.to_vec(), default_value = "regex")]
    pub match_kind: String,
    /// The header (with request-header or response-header) or query parameter (query-param) the
    /// rule works on: --match and --replace then act on its value, and --action says what to do.
    #[arg(long)]
    pub name: Option<String>,
    /// With --name: set (rewrite the value where --match matches; with no --match, set it, adding
    /// the header or parameter if there is none), add (another one, whatever is there), or
    /// remove (with --match: only where the value matches). Default set.
    #[arg(long, value_parser = RuleAction::ALL.to_vec())]
    pub action: Option<String>,
    /// Whose traffic the rule applies to, comma-separated: proxy, send (the app's Replay too),
    /// fuzz, scan (active scans and checks); a ws-message rule: ws-to-server, ws-to-client.
    /// Default: proxy (a ws-message rule: both directions).
    #[arg(long, value_delimiter = ',', value_parser = Engine::ALL.to_vec())]
    pub applies_to: Vec<String>,
    /// Only for targets whose host matches this regex (case-insensitive).
    #[arg(long)]
    pub host: Option<String>,
    /// Have a script make the replacement, in place of --replace: a JavaScript file that defines
    /// `replace(match, ctx)`. It is called for the matches of each message (match.text, and with
    /// a regex match.groups and match.named; ctx has the location, engine, host and the request
    /// or response) and returns the text to write, { base64 } for bytes, or null to leave a
    /// match as it is. This runs code from that file, with no file or network access, each call
    /// under a time limit; a script that fails leaves the message as it is. The file is pinned
    /// by its sha256: if it changes, the rule is skipped until it is added again. Not offered
    /// through MCP.
    ///
    /// With --location request the file defines `request(req, ctx)` instead: it is given the
    /// whole request (req.method, target, path, query, line, headers as [name, value] pairs,
    /// body, and bodyBase64 when the body isn't UTF-8; ctx has the engine, host and rule) and
    /// returns nothing to send it as it is, { request: { method, target, headers, body } } to
    /// send it changed, { block: "reason" } to not send it, or { response: { status, reason,
    /// headers, body } } to not send it and use that response as the server's. Nothing is sent
    /// for a blocked or answered request: no connection is opened.
    #[arg(long, value_name = "FILE", conflicts_with = "replace")]
    pub script: Option<PathBuf>,
    /// The sha256 the script file must have: the one of the text you read.
    #[arg(long, value_name = "HEX", requires = "script")]
    pub script_sha256: Option<String>,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum MessageArg {
    Request,
    Response,
    WsToServer,
    WsToClient,
}

#[derive(Subcommand)]
pub enum RulesCmd {
    /// List match-and-replace rules. Its JSON is what `rules import` reads.
    List,
    /// Add a rule. Locations: request-line, request-header, request-body, response-header and
    /// response-body match in the raw text (header rules match each header line; an empty --match
    /// adds --replace as a new header); method, path, query-param (--name), status and, with
    /// --name, request-header and response-header work on that one value; ws-message on the
    /// payload of WebSocket messages the proxy relays; request gives the whole request to a
    /// --script, which may change it, block it, or answer it itself so that nothing is sent.
    Add {
        #[arg(long, value_parser = RuleLocation::ALL.to_vec())]
        location: String,
        /// What to match: a regex (Rust syntax) unless --match-kind says otherwise. Empty: with a
        /// header location and no --name, "add header"; with a regex on request-line or a body,
        /// nothing; otherwise the whole value.
        #[arg(long = "match", default_value = "")]
        pattern: String,
        /// Replacement; $1-style group references allowed with a regex. Empty removes the match.
        #[arg(long, default_value = "")]
        replace: String,
        #[command(flatten)]
        options: RuleOptions,
        #[arg(long)]
        comment: Option<String>,
        /// Add the rule disabled.
        #[arg(long)]
        disabled: bool,
        /// The rule deliberately puts a host the scope doesn't list in the Host header, for a
        /// Host-header test. Through MCP such a rule is refused without it.
        #[arg(long)]
        host_header_test: bool,
    },
    Remove {
        id: u32,
    },
    Enable {
        id: u32,
        /// As for `rules add`: the rule puts a host the scope doesn't list in the Host header.
        #[arg(long)]
        host_header_test: bool,
    },
    Disable {
        id: u32,
    },
    /// Remove all rules.
    Clear,
    /// Try rules on a message without sending anything: prints the message after the rules and
    /// which rules changed it. The message is a raw request or response from FILE or stdin, or
    /// a history row's (--history: its request and its response). By default the enabled rules
    /// apply as --as would apply them; --rule picks saved rules (enabled or not, whatever they
    /// apply to), and --location with --match, --replace and the other `rules add` flags tries
    /// a rule that isn't saved.
    Test {
        /// File holding the message; '-' or omitted reads stdin (unless --history is given).
        /// Through MCP the message comes from stdin or --history.
        file: Option<String>,
        /// Test on this history row's request and response.
        #[arg(long)]
        history: Option<i64>,
        /// What FILE holds. Default: a response if it starts with "HTTP/", else a request.
        #[arg(long, value_enum)]
        message: Option<MessageArg>,
        /// The engine whose rules apply to a request or response.
        #[arg(long = "as", value_parser = ["proxy", "send", "fuzz", "scan"], default_value = "proxy")]
        engine: String,
        /// Only these saved rules (ids, comma-separated).
        #[arg(long = "rule", value_delimiter = ',')]
        rules: Vec<u32>,
        /// Try an unsaved rule with this location (after any --rule).
        #[arg(long, value_parser = RuleLocation::ALL.to_vec())]
        location: Option<String>,
        /// The unsaved rule's --match, as for `rules add`.
        #[arg(long = "match", default_value = "")]
        pattern: String,
        /// The unsaved rule's --replace, as for `rules add`.
        #[arg(long, default_value = "")]
        replace: String,
        #[command(flatten)]
        options: RuleOptions,
        /// The host the message is for, for rules with a --host condition. Default: the history
        /// row's, else the request's Host header.
        #[arg(long)]
        target_host: Option<String>,
        /// Print only the message after the rules (with --history: the request, or with
        /// --message response the response).
        #[arg(long)]
        raw: bool,
        #[arg(long, default_value_t = 65536)]
        max_body: usize,
    },
    /// Add rules from JSON, as `rules list` prints them. Each gets a new id and the importer's
    /// origin, and is checked as `rules add` checks it.
    Import {
        /// File holding the JSON; '-' or omitted reads stdin. Through MCP the rules come from stdin.
        file: Option<String>,
        /// Remove the rules there are first.
        #[arg(long)]
        replace: bool,
        /// Add them all disabled.
        #[arg(long)]
        disabled: bool,
        /// As for `rules add`, for every rule imported.
        #[arg(long)]
        host_header_test: bool,
    },
}

#[derive(Subcommand)]
pub enum InterceptCmd {
    /// Start holding matching messages in the queue. With no direction flag, requests are held.
    #[command(after_help = "--filter takes the query language of `history list --filter` (see `history list \
        --help`), asked about what is known when the message is held: a request is matched by itself (after \
        match-and-replace rules), a response by the request sent and the response, a WebSocket message by its \
        connection's handshake request. Response fields (status, length, duration, title, type, resp, \
        resp.body, body, resp.headers, resp.header.NAME) are refused unless only --responses is held; id, \
        error, note and tag are refused always. A bare word searches the URL (and the title of a response) and \
        matches the method. --host, --path and --method still apply: a message is held when all that are \
        given match. They read the request as the client sent it, the filter the request as it goes out. Enable replaces every setting, so pass the filter again each time (an empty one is none).")]
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
        /// Only hold messages whose exchange matches this query in the filter language of `history list
        /// --filter`, e.g. 'method=POST NOT path:/static'. Combines with --host, --path and --method.
        #[arg(long, value_name = "QUERY")]
        filter: Option<String>,
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
        /// --verbatim; a WebSocket message's payload is always taken as is. Through MCP only a file in the project's folder.
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        verbatim: bool,
        /// The replacement's Host header deliberately names a host the scope doesn't list (and the
        /// held request didn't), for a Host-header test. Through MCP such an edit is refused without it.
        #[arg(long)]
        host_header_test: bool,
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
            // Every client that trusts the person's CA would stop trusting the proxy.
            crate::mcp::check_force(force, "ca init", "the CA is kept; a person replaces it in a terminal")?;
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
            // Any file the server can write: an agent writes new files only.
            crate::mcp::check_force(force, "ca export", "write the certificate to a new file, or leave out --out")?;
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

/// A warning when the running proxy was started by a build older than the project's schema
/// (`started`: the schema it records, None from before it did): it goes on writing rows as
/// that build did, without what came since (who changed a request, for one).
fn outdated_text(started: Option<i64>, project: i64) -> Option<String> {
    let by = match started {
        Some(v) if v >= project => return None,
        Some(v) => format!("a brainproxy build for schema v{v}"),
        None => "an older brainproxy build".to_string(),
    };
    Some(format!(
        "the running proxy was started by {by}, and the project is at schema v{project}: it records less than \
         this version does (who changed a request, for one); restart it with brainproxy proxy restart"
    ))
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
            // A log that doesn't parse is reported, not allowed to hide the rest.
            let (changes, problem) = store.recording_changes_or_problem()?;
            let narrowed = changes.narrowed_by_agent();
            let rerouted = changes.rerouted_by_agent();
            // What was done for a restart that had gone before it started its new proxy.
            let gone = store.meta_get(GONE_KEY)?.and_then(|g| serde_json::from_str::<Value>(&g).ok());
            let authz = match state.as_ref().and_then(|s| s.authz_run) {
                Some(id) => {
                    let job = store.job_get(id)?;
                    json!({"run_id": id, "state": job["state"], "progress": job["progress"],
                        "next": format!("brainproxy authz matrix {id}")})
                }
                None => Value::Null,
            };
            let schema = store.schema_version()?;
            let outdated = state.as_ref().and_then(|s| outdated_text(s.schema, schema));
            let data = json!({
                "running": state.is_some(),
                "restarting": held,
                "proxy": state.as_ref().map(state_json),
                "other_pid_namespace": process::elsewhere(pid_ns.as_deref()),
                "unverified": unverified,
                "proxy_captures": captures,
                "pending_intercepts": pending,
                "intercept_enabled": intercept.enabled,
                "rules_enabled": rules.iter().filter(|r| r.enabled && !breaks_head(r)).count(),
                // Saved before line breaks in a head replacement were refused: left out.
                "rules_skipped": skipped_rules(&rules),
                "scope": scope,
                "recording_last_change": changes.recent(1).first(),
                "recording_narrowed_by_agent": narrowed,
                "routing_changed_by_agent": rerouted,
                // Polled by the app: the latest, and how many there are (`scope show` has them all).
                "recording_kept_changes": changes.kept().into_iter().take(STATUS_KEPT_SHOWN).collect::<Vec<_>>(),
                "recording_kept_total": changes.kept_total(),
                "recording_kept_dropped": changes.kept_dropped(),
                "recording_changes_problem": problem,
                "authz": authz,
                "restart_gone": gone,
                "proxy_outdated": outdated,
            });
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            let gone_note = gone.as_ref().map(|g| format!("\n{}", gone_text(g, now))).unwrap_or_default();
            let mut notes: String =
                narrowed.iter().chain(&rerouted).map(|c| format!("\nnot reviewed: {}", c.describe())).collect();
            if let Some(o) = &outdated {
                notes.push_str(&format!("\nwarning: {o}"));
            }
            if let Some(p) = &problem {
                notes.push_str(&format!("\nwarning: {p}"));
            }
            notes.push_str(&kept_dropped_note(&changes));
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
                status + &gone_note + &notes
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
            if args.authz_include_static {
                cmd.arg("--authz-include-static");
            }
            if args.authz_head_options {
                cmd.arg("--authz-head-options");
            }
            for p in &live.skip_paths {
                cmd.arg(format!("--authz-skip-path={p}"));
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
    // before that, which leaves the old proxy running, from one gone during it. Until it is
    // asked, the stop request reads as not yet made (see [`stop_pending`]).
    let pending = stop_pending(&token);
    if let Err(e) = store.meta_set(STOP_KEY, Some(&pending)).and_then(|()| mark_stopping(&store, &token)) {
        let _ = store.meta_swap(STOP_KEY, Some(&pending), None);
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
        Ok(s) => {
            note_gone(&store, &token, Ok(&s), "the restart's new proxy, as it gave up");
            format!(
                "the restart that started it had gone, so the proxy was started again on {} (pid {})",
                s.listen, s.pid
            )
        }
        Err(e2) => {
            let note = format!("the proxy couldn't be started again on {}: {e2}", back.listen);
            note_gone(&store, &token, Err(&note), "the restart's new proxy, as it gave up");
            format!("the restart that started it had gone, and {note}")
        }
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
/// and starts it again where it was, as the restart would have, and notes what it did (see
/// [`note_gone`]). Until then it is the hold's `starting`, so the hold lasts while it does that,
/// and a stop that calls the restart off stops it. It exits quietly once the restart has recorded
/// its proxy or let go of the record. A store it can't read for [`GUARD_RETRY`] ends it.
fn guard(project: &Path, home: &Path, out: &Out) -> Result<(), Error> {
    let (Ok(token), Ok(was)) = (std::env::var(RESTART_ENV), std::env::var(WAS_ENV)) else { return Ok(()) };
    let store = retrying(|| Store::open(project))?;
    // Taken as it starts, so that from another container the hold lasts while this runs (see
    // [`guard_held`]), and held until it exits. Without it (the guard of a restart just before
    // still exiting, say) this still stands by: only another container can't tell.
    let _lock = process::RunLock::acquire(&store, GUARD_LOCK).ok().flatten();
    let me = std::process::id();
    let old = parse_state(&was);
    let pending = stop_pending(&token);
    loop {
        let hold = retrying(|| read_state(&store))?;
        let Some(hold) = hold.filter(|s| s.restart.as_deref() == Some(token.as_str())) else { return Ok(()) };
        let recorded_me = match hold.starting {
            Some((pid, _)) if pid != me => return Ok(()),
            starting => starting.is_some(),
        };
        let step = match restart_gone(&store, &hold) {
            false => GuardStep::Wait,
            true => guard_step(GuardLook {
                restart_gone: true,
                recorded_me,
                stopping: hold.stopping,
                stop_requested: retrying(|| store.meta_get(STOP_KEY))?.as_deref() != Some(pending.as_str()),
                old_alive: old.as_ref().is_none_or(|o| liveness(&store, o) != Liveness::Gone),
            }),
        };
        match step {
            GuardStep::Wait => std::thread::sleep(Duration::from_millis(50)),
            // The restart hadn't asked the old proxy to stop: it runs as it was.
            GuardStep::GiveBack => {
                let _ = store.meta_swap(STOP_KEY, Some(&pending), None);
                return let_go_to(&store, &token, Some(&was));
            }
            GuardStep::Finish => break,
        }
    }
    let had_gone = "the restart had gone before it started the new proxy";
    // Left off, the proxy is noted as off, and why.
    let off = |e: Error, note: String| {
        note_gone(&store, &token, Err(&note), "the restart's guard");
        let _ = let_go(&store, &token);
        Err(noted(e, &format!("{had_gone}, and {note}")))
    };
    // `restart` read it before it held the record, so this doesn't happen.
    let Some(old) = old else {
        return off(Error::Conflict("the old proxy's record can't be read".into()), "the proxy is off".into());
    };
    // It may have exited already, or be on its way out.
    if let Err(e) = halt(&store, &old) {
        // It still runs: give it its record back.
        let_go_to(&store, &token, Some(&was))?;
        return Err(e);
    }
    let _ = store.meta_set(STOP_KEY, None);
    let back = match back_args(&old.state) {
        Ok(back) => back,
        Err(e) => return off(e, "the proxy is off".into()),
    };
    let again = match called_off(&store, &token) {
        false => back_to(project, home, &store, &token, &back),
        true => Err(Error::Conflict("called off by `brainproxy proxy stop`".into())),
    };
    match again {
        Ok(s) => {
            note_gone(&store, &token, Ok(&s), "the restart's guard");
            out.ok(json!({"restarted": {"pid": s.pid, "listen": s.listen}}), || {
                format!("{had_gone}, so the proxy was started again on {} (pid {})", s.listen, s.pid)
            });
            Ok(())
        }
        // Called off by `proxy stop`: the proxy stays off.
        Err(_) if called_off(&store, &token) => let_go(&store, &token),
        Err(e) => off(e, format!("the proxy couldn't be started again on {}", back.listen)),
    }
}

/// What a restart's guard sees on one look at a hold that is still its restart's and names no
/// other process as `starting` (see [`guard_step`]).
#[derive(Clone, Copy, Debug)]
struct GuardLook {
    /// The restart itself has gone.
    restart_gone: bool,
    /// The hold names this guard as `starting`.
    recorded_me: bool,
    /// The hold is marked `stopping`: the restart was about to ask the old proxy to stop.
    stopping: bool,
    /// The stop request no longer reads as not yet made (see [`stop_pending`]): the restart has
    /// asked the old proxy to stop, whether or not that proxy has taken the request yet.
    stop_requested: bool,
    /// The old proxy still runs.
    old_alive: bool,
}

/// What a restart's guard does next (see [`guard_step`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuardStep {
    /// The restart still runs: look again.
    Wait,
    /// The restart went before it asked the old proxy to stop: that one gets its record back.
    GiveBack,
    /// The restart went while it stopped the old proxy: finish that and start it again.
    Finish,
}

/// The guard's decision. The old proxy is only stopped and started again if the restart had
/// asked it to stop, or it has gone anyway: one the restart never asked runs as it was, and
/// only needs its record back.
fn guard_step(look: GuardLook) -> GuardStep {
    let GuardLook { restart_gone, recorded_me, stopping, stop_requested, old_alive } = look;
    if !restart_gone {
        GuardStep::Wait
    } else if recorded_me && stopping && (stop_requested || !old_alive) {
        GuardStep::Finish
    } else {
        GuardStep::GiveBack
    }
}

/// What the stop request ([`STOP_KEY`]) reads as from just before the restart whose token this
/// is marks its hold `stopping` until it asks the old proxy to stop: no proxy's pid, so no proxy
/// takes it. Asking replaces it with the pid, which the proxy clears as it takes it, so once
/// this is gone the old proxy was asked.
fn stop_pending(token: &str) -> String {
    format!("restart {token}: not asked yet")
}

/// `read` until it works, for up to [`GUARD_RETRY`]: through a store locked for a while, say.
fn retrying<T>(mut read: impl FnMut() -> Result<T, Error>) -> Result<T, Error> {
    let until = Instant::now() + GUARD_RETRY;
    loop {
        match read() {
            Err(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(200)),
            done => return done,
        }
    }
}

/// Notes in [`GONE_KEY`] that the restart whose token this is had gone before it started its new
/// proxy, and what `by` did in its place: started the old proxy again as it was (`back`), or
/// left it off, and why. With the time and the restart's origin, which this process shares.
fn note_gone(store: &Store, token: &str, back: Result<&ProxyState, &str>, by: &str) {
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let (proxy, note) = match back {
        Ok(s) => (json!({"pid": s.pid, "listen": s.listen}), None),
        Err(note) => (Value::Null, Some(note)),
    };
    let gone = json!({"at": at, "by": by, "restart_pid": restart_pid(token),
        "restart_origin": brainproxy_core::provenance::origin(), "proxy": proxy, "note": note});
    let _ = store.meta_set(GONE_KEY, Some(&gone.to_string()));
}

/// The pid of the restart whose token this is: its token starts with it.
fn restart_pid(token: &str) -> Option<u32> {
    token.split('-').next()?.parse().ok()
}

/// [`note_gone`]'s note as `proxy status` says it, `now` seconds after the Unix epoch.
fn gone_text(gone: &Value, now: u64) -> String {
    let ago = now.saturating_sub(gone["at"].as_u64().unwrap_or(now));
    let ago = match ago {
        0..=119 => format!("{ago} s ago"),
        120..=7199 => format!("{} min ago", ago / 60),
        _ => format!("{} h ago", ago / 3600),
    };
    let origin = brainproxy_core::provenance::describe(gone["restart_origin"].as_str());
    let restart = match gone["restart_pid"].as_u64() {
        Some(pid) => format!("a restart (pid {pid}, {origin})"),
        None => format!("a restart ({origin})"),
    };
    let what = match (&gone["proxy"]["pid"], gone["proxy"]["listen"].as_str()) {
        (Value::Number(pid), Some(listen)) => {
            format!(
                "{} started the proxy again on {listen} (pid {pid}) with its old options",
                gone["by"].as_str().unwrap_or("its guard")
            )
        }
        _ => format!("the proxy was left off: {}", gone["note"].as_str().unwrap_or("it couldn't be started again")),
    };
    format!("{ago}, {restart} had gone before it started its new proxy, and {what}")
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
        // Only a clean read says the restart has gone: one that fails is taken as still running.
        let restart_runs = match store.as_ref().map(|store| (store, read_state(store))) {
            Some((store, Ok(now))) => now.is_some_and(|now| now.restart == token && !restart_gone(store, &now)),
            _ => true,
        };
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
        // A proxied client's request goes out with its own Host; an agent's edits and rules
        // are checked when they are made.
        host: brainproxy_core::http::client::HostPolicy::Allow,
        stream: Default::default(),
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
        let skips = |paths: &[String]| {
            brainproxy_core::authz::noise::PathSkips::compile(paths)
                .map_err(|e| Error::InvalidInput(format!("authz skip paths: {e}")))
        };
        let saved: brainproxy_core::authz::noise::SavedSkips =
            Store::open(project)?.setting(brainproxy_core::authz::noise::SKIP_KEY)?;
        let opts = LiveOptions {
            queue: live.queue,
            concurrency: 2,
            exclude,
            include_static: live.include_static,
            head_options: live.head_options,
            skip_paths: skips(&live.skip_paths)?,
            saved_skips: skips(&saved.paths)?,
        };
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
        // What was done for a restart that had gone is shown until a proxy next takes the record.
        let _ = store.meta_set(GONE_KEY, None);
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
            schema: Some(brainproxy_core::store::SCHEMA_VERSION),
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

/// The kept changes `proxy status` lists, newest first, with a count of all of them.
const STATUS_KEPT_SHOWN: usize = 50;

/// A warning line when changes through MCP or narrowing ones were dropped: a flood of them.
fn kept_dropped_note(changes: &brainproxy_core::proxy::recording::Changes) -> String {
    match changes.kept_dropped() {
        0 => String::new(),
        n => format!(
            "\nwarning: {n} older changes made through MCP or narrowing recording were dropped from the log \
             ({} in all): that many changes is itself worth a look",
            changes.kept_total()
        ),
    }
}

pub fn scope(project: &Path, cmd: ScopeCmd, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    let scope: Scope = store.setting(SCOPE_KEY)?;
    match &cmd {
        ScopeCmd::Show => {
            let (changes, problem) = store.recording_changes_or_problem()?;
            let mut data = json!(scope);
            data["recording_changes"] = json!(changes.shown(SCOPE_CHANGES_SHOWN));
            data["narrowed_by_agent"] = json!(changes.narrowed_by_agent());
            data["routing_changed_by_agent"] = json!(changes.rerouted_by_agent());
            data["recording_changes_problem"] = json!(problem);
            data["recording_kept_dropped"] = json!(changes.kept_dropped());
            out.ok(data, || {
                let mut text = serde_json::to_string_pretty(&scope).unwrap_or_default();
                for c in changes.narrowed_by_agent().into_iter().chain(changes.rerouted_by_agent()) {
                    text.push_str(&format!("\nnot reviewed: {}", c.describe()));
                }
                if let Some(c) = changes.recent(1).first() {
                    text.push_str(&format!("\nlast change: {}", c.describe()));
                }
                if let Some(p) = &problem {
                    text.push_str(&format!("\nwarning: {p}"));
                }
                text.push_str(&kept_dropped_note(&changes));
                text
            });
            return Ok(());
        }
        ScopeCmd::Check { host } => {
            let allowed = scope.compile()?.allows(host);
            out.ok(json!({"host": host, "in_scope": allowed}), || {
                format!("{host}: {}", if allowed { "in scope" } else { "out of scope" })
            });
            return Ok(());
        }
        _ => {}
    }
    // Edited as saved when the change is logged, so a save by another process in between
    // isn't overwritten, and logged with who changed it (see `update_scope`).
    let scope = store.update_scope(|scope| {
        match cmd {
            ScopeCmd::Set { include, exclude, record_out_of_scope } => {
                *scope = Scope { include, exclude, record_out_of_scope };
            }
            ScopeCmd::Add { include, exclude } => {
                scope.include.extend(include);
                scope.exclude.extend(exclude);
            }
            ScopeCmd::Clear => *scope = Scope::default(),
            ScopeCmd::Show | ScopeCmd::Check { .. } => unreachable!("answered above"),
        }
        // Validate before saving.
        scope.compile().map(|_| ())
    })?;
    out.ok(json!(scope), || serde_json::to_string_pretty(&scope).unwrap_or_default());
    Ok(())
}

/// A request rule that is on: its script may block or answer requests, so through MCP it is
/// neither switched off nor removed (see [`crate::mcp::check_guard`]).
fn is_guard(rule: &Rule) -> bool {
    rule.enabled && rule.location == RuleLocation::Request
}

/// A rule from `rules add`'s flags (or `rules test`'s), not yet checked or given an id.
fn rule_from(
    location: &str,
    pattern: String,
    replace: String,
    options: RuleOptions,
    host_header_test: bool,
) -> Result<Rule, Error> {
    let mut applies_to = Vec::new();
    for e in &options.applies_to {
        let e = Engine::parse(e)?;
        if !applies_to.contains(&e) {
            applies_to.push(e);
        }
    }
    let script = match &options.script {
        Some(file) => {
            crate::mcp::check_script("--script")?;
            Some(brainproxy_core::hooks::ScriptRef::pin(file, options.script_sha256.as_deref())?)
        }
        None => None,
    };
    Ok(Rule {
        replacer: if script.is_some() { ReplaceKind::Script } else { ReplaceKind::Text },
        script,
        matcher: MatchKind::parse(&options.match_kind)?,
        name: options.name,
        action: options.action.as_deref().map(RuleAction::parse).transpose()?,
        applies_to,
        host: options.host.filter(|h| !h.is_empty()),
        origin: Some(brainproxy_core::provenance::origin().to_string()),
        host_header_test,
        ..Rule::new(0, RuleLocation::parse(location)?, &pattern, &replace)
    })
}

pub fn rules(project: &Path, cmd: RulesCmd, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    let mut rules: Vec<Rule> = store.setting(RULES_KEY)?;
    let find = |rules: &mut Vec<Rule>, id: u32| -> Result<usize, Error> {
        rules.iter().position(|r| r.id == id).ok_or_else(|| Error::NotFound(format!("rule {id}")))
    };
    let mut host_warning = None;
    // Rules switched on or off by this command.
    let mut touched = Vec::new();
    match cmd {
        RulesCmd::List => {
            let skipped = skipped_rules(&rules);
            let failures = rule_failures(&store, &rules);
            let data = json!({"rules": rules, "skipped": skipped, "failures": failures});
            out.ok(data, || {
                let mut text = serde_json::to_string_pretty(&rules).unwrap_or_default();
                for s in skipped.as_array().into_iter().flatten() {
                    text.push_str(&format!(
                        "\nwarning: rule {} is skipped: {}",
                        s["id"],
                        s["reason"].as_str().unwrap_or("")
                    ));
                }
                for f in failures.as_array().into_iter().flatten() {
                    text.push_str(&format!(
                        "\nwarning: rule {}'s script last failed {} ({}), leaving the message as it was: {}",
                        f["id"],
                        f["time"].as_str().unwrap_or(""),
                        f["engine"].as_str().unwrap_or(""),
                        f["error"].as_str().unwrap_or("")
                    ));
                }
                text
            });
            return Ok(());
        }
        RulesCmd::Test {
            file,
            history,
            message,
            engine,
            rules: picked,
            location,
            pattern,
            replace,
            options,
            target_host,
            raw,
            max_body,
        } => {
            let draft = location.map(|l| rule_from(&l, pattern, replace, options, false)).transpose()?;
            let test = RuleTest { file, history, message, engine: Engine::parse(&engine)?, picked, draft, target_host };
            return test_rules(&store, &rules, test, raw, max_body, out);
        }
        RulesCmd::Add { location, pattern, replace, options, comment, disabled, host_header_test } => {
            let mut rule = rule_from(&location, pattern, replace, options, host_header_test)?;
            rule.enabled = !disabled;
            rule.comment = comment;
            brainproxy_core::proxy::config::validate_rule(&rule)?;
            brainproxy_core::rules::verify_script(&rule)?;
            // Never one a removed rule had: an old history row's `edited_by` names it.
            rule.id = store.next_id(RULE_IDS, rules.iter().map(|r| r.id).max().unwrap_or(0))?;
            // A disabled rule changes nothing; enabling it is checked.
            if rule.enabled {
                host_warning = check_rule_host(&store, &rule, host_header_test, out)?;
            }
            rules.push(rule);
        }
        RulesCmd::Import { file, replace, disabled, host_header_test } => {
            let imported = read_rules(file.as_deref())?;
            if replace {
                if let Some(r) = rules.iter().find(|r| is_guard(r)) {
                    crate::mcp::check_guard(&format!("rules import --replace would remove rule {}", r.id))?;
                }
                rules.clear();
            }
            // Checked before any is given an id, so a bad one leaves the rules as they were.
            for rule in &imported {
                // A rule's script runs code: whoever brings it in must be a person, as for `rules add`.
                if rule.script.is_some() {
                    crate::mcp::check_script(&format!("rule {} of the import: a script rule", rule.id))?;
                }
                brainproxy_core::proxy::config::validate_rule(rule)
                    .and_then(|()| brainproxy_core::rules::verify_script(rule))
                    .map_err(|e| Error::InvalidInput(format!("rule {} of the import: {e}", rule.id)))?;
            }
            for mut rule in imported {
                let listed = rule.id;
                rule.enabled &= !disabled;
                // Whoever imports a rule answers for it, as whoever adds one does; and only the
                // command can say a Host it sets is meant, not the file.
                rule.origin = Some(brainproxy_core::provenance::origin().to_string());
                rule.host_header_test = host_header_test;
                rule.id = store.next_id(RULE_IDS, rules.iter().map(|r| r.id).max().unwrap_or(0))?;
                if rule.enabled {
                    let checked = Rule { id: listed, ..rule.clone() };
                    let warning = check_rule_host(&store, &checked, host_header_test, out)?;
                    host_warning = host_warning.or(warning);
                }
                rules.push(rule);
            }
        }
        RulesCmd::Remove { id } => {
            let i = find(&mut rules, id)?;
            if is_guard(&rules[i]) {
                crate::mcp::check_guard(&format!("rules remove {id}"))?;
            }
            rules.remove(i);
        }
        RulesCmd::Enable { id, host_header_test } => {
            let i = find(&mut rules, id)?;
            if rules[i].script.is_some() && !rules[i].enabled {
                crate::mcp::check_script(&format!("rules enable {id}: a script rule"))?;
            }
            brainproxy_core::proxy::config::validate_rule(&rules[i])?;
            touched.push(id);
            // Whoever turns a rule on answers for what it changes from then on.
            if !rules[i].enabled {
                brainproxy_core::rules::verify_script(&rules[i])?;
                host_warning = check_rule_host(&store, &rules[i], host_header_test, out)?;
                rules[i].origin = Some(brainproxy_core::provenance::origin().to_string());
                rules[i].host_header_test = host_header_test;
            }
            rules[i].enabled = true;
        }
        RulesCmd::Disable { id } => {
            let i = find(&mut rules, id)?;
            if is_guard(&rules[i]) {
                crate::mcp::check_guard(&format!("rules disable {id}"))?;
            }
            rules[i].enabled = false;
            touched.push(id);
        }
        RulesCmd::Clear => {
            if let Some(r) = rules.iter().find(|r| is_guard(r)) {
                crate::mcp::check_guard(&format!("rules clear would remove rule {}", r.id))?;
            }
            rules.clear();
        }
    }
    store.set_setting(RULES_KEY, &rules)?;
    // What a rule's script last failed on says nothing of a rule that is gone, or that was
    // switched off or on since.
    brainproxy_core::rules::forget_failures(&store, |id| rules.iter().any(|r| r.id == id) && !touched.contains(&id))?;
    let mut data = json!({"rules": rules, "skipped": skipped_rules(&rules), "failures": rule_failures(&store, &rules)});
    if let Some(w) = host_warning {
        data["host_warning"] = json!(w);
    }
    out.ok(data, || serde_json::to_string_pretty(&rules).unwrap_or_default());
    Ok(())
}

/// The rules in an import: a JSON list of rules, or what `rules list` prints (`{"rules": [...]}`,
/// alone or as a command's `data`). Through MCP it comes from the call's stdin: a file an agent
/// names could be any the server can read, and a refusal would quote it.
fn read_rules(file: Option<&str>) -> Result<Vec<Rule>, Error> {
    let bytes = match file {
        Some(path) if path != "-" => {
            if crate::mcp::in_tool_call() {
                return Err(Error::InvalidInput(
                    "rules import FILE: through MCP the rules come from the call's stdin".into(),
                ));
            }
            std::fs::read(path).map_err(|e| Error::InvalidInput(format!("cannot read rules file {path:?}: {e}")))?
        }
        _ => crate::read_input(None)?,
    };
    let bad = |e: serde_json::Error| Error::InvalidInput(format!("the import isn't a list of rules: {e}"));
    let value: Value = serde_json::from_slice(&bytes).map_err(bad)?;
    let list = match &value {
        Value::Array(_) => &value,
        v if v["rules"].is_array() => &v["rules"],
        v if v["data"]["rules"].is_array() => &v["data"]["rules"],
        _ => return Err(Error::InvalidInput("the import isn't a list of rules, nor what `rules list` prints".into())),
    };
    // A rule from another project has an id there; one written by hand may have none.
    let mut rules = Vec::new();
    for (i, item) in list.as_array().into_iter().flatten().enumerate() {
        let mut item = item.clone();
        if item.is_object() && item.get("id").is_none() {
            item["id"] = json!(i + 1);
        }
        rules.push(
            serde_json::from_value::<Rule>(item)
                .map_err(|e| Error::InvalidInput(format!("rule {} of the import: {e}", i + 1)))?,
        );
    }
    Ok(rules)
}

/// What `rules test` was asked to try, and on what.
struct RuleTest {
    file: Option<String>,
    history: Option<i64>,
    message: Option<MessageArg>,
    engine: Engine,
    picked: Vec<u32>,
    draft: Option<Rule>,
    target_host: Option<String>,
}

/// `rules test`: applies rules to a message and shows what they made of it. Nothing is sent
/// and nothing is saved.
fn test_rules(
    store: &Store,
    saved: &[Rule],
    test: RuleTest,
    raw: bool,
    max_body: usize,
    out: &Out,
) -> Result<(), Error> {
    use brainproxy_core::rules::{RuleSet, Ruled};
    if test.history.is_some() && test.file.is_some() {
        return Err(Error::InvalidInput("give FILE or --history, not both".into()));
    }
    if crate::mcp::in_tool_call() && test.file.as_deref().is_some_and(|f| f != "-") {
        return Err(Error::InvalidInput(
            "rules test FILE: through MCP the message comes from the call's stdin or from --history: the result \
             shows the file, so any file the server can read could be read back"
                .into(),
        ));
    }
    // The messages to try: (what it is, its bytes).
    let mut host = test.target_host.clone();
    let mut messages: Vec<(MessageArg, Vec<u8>)> = Vec::new();
    match test.history {
        Some(id) => {
            let item = store.get(id)?;
            host.get_or_insert(item.target.host.clone());
            // The request as it was before the rules of its day, if they changed it.
            let request = item.rule_edit.and_then(|e| e.original_request).unwrap_or(item.request);
            match test.message {
                Some(MessageArg::WsToServer | MessageArg::WsToClient) => {
                    return Err(Error::InvalidInput(
                        "--history tests a request and its response; a WebSocket message comes from FILE or stdin"
                            .into(),
                    ))
                }
                Some(MessageArg::Request) => messages.push((MessageArg::Request, request)),
                Some(MessageArg::Response) => messages.push((MessageArg::Response, item.response)),
                None => {
                    messages.push((MessageArg::Request, request));
                    if !item.response.is_empty() {
                        messages.push((MessageArg::Response, item.response));
                    }
                }
            }
        }
        None => {
            let bytes = match test.file.as_deref() {
                Some(path) if path != "-" => std::fs::read(path)
                    .map_err(|e| Error::InvalidInput(format!("cannot read message file {path:?}: {e}")))?,
                _ => crate::read_input(None)?,
            };
            let kind = test.message.unwrap_or(if bytes.starts_with(b"HTTP/") {
                MessageArg::Response
            } else {
                MessageArg::Request
            });
            // A head typed with bare line feeds is read as `send` reads a request's.
            let bytes = match kind {
                MessageArg::Request | MessageArg::Response => {
                    RawRequest::from_bytes(bytes).normalize_line_endings().into_bytes()
                }
                _ => bytes,
            };
            if kind == MessageArg::Request && host.is_none() {
                host = RawRequest::from_bytes(bytes.clone()).infer_target("https").ok().map(|t| t.host);
            }
            messages.push((kind, bytes));
        }
    }
    let host = host.unwrap_or_default();
    let engine_for = |kind: MessageArg| match kind {
        MessageArg::Request | MessageArg::Response => test.engine,
        MessageArg::WsToServer => Engine::WsToServer,
        MessageArg::WsToClient => Engine::WsToClient,
    };
    // The rules to try. Picked ones and an unsaved one are tried whatever they apply to and
    // whether or not they are enabled: they are what is being tested. Otherwise the engine's own.
    let chosen = !test.picked.is_empty() || test.draft.is_some();
    let mut tried: Vec<Rule> = Vec::new();
    for id in &test.picked {
        let rule = saved.iter().find(|r| r.id == *id).cloned().ok_or_else(|| Error::NotFound(format!("rule {id}")))?;
        // A picked rule is tried whether or not it is enabled: for a script rule a person
        // switched off, that would be an agent having its script run after all.
        if rule.script.is_some() && !rule.enabled {
            crate::mcp::check_script(&format!("rules test --rule {id}: a script rule that is switched off"))?;
        }
        tried.push(rule);
    }
    if let Some(draft) = test.draft {
        brainproxy_core::proxy::config::validate_rule(&draft)?;
        brainproxy_core::rules::verify_script(&draft)?;
        tried.push(draft);
    }
    if !chosen {
        // The engine's own: the enabled rules that list it (or, for a message, its direction).
        let engines: Vec<Engine> = messages.iter().map(|(kind, _)| engine_for(*kind)).collect();
        let applies = |r: &&Rule| r.enabled && r.engines().iter().any(|e| engines.contains(e));
        tried = saved.iter().filter(applies).cloned().collect();
    }
    // A rule whose script can't run now is left out as an engine leaves it out; one asked for
    // by id is what is being tested, so that is an error.
    let mut skipped = Vec::new();
    for rule in &tried {
        match brainproxy_core::rules::script_problem(rule) {
            Some(why) if chosen => return Err(Error::InvalidInput(format!("rule {}: {why}", rule.id))),
            Some(why) => skipped.push(json!({"id": rule.id, "reason": why})),
            None => {}
        }
    }
    let mut results = serde_json::Map::new();
    let mut texts = Vec::new();
    let mut first_bytes = None;
    // A response tested with its request is read as its answer: a HEAD's has no body to rule.
    let answered: Vec<u8> = messages
        .iter()
        .find(|(kind, _)| matches!(kind, MessageArg::Request))
        .map(|(_, bytes)| bytes.clone())
        .unwrap_or_default();
    for (kind, bytes) in messages {
        let engine = engine_for(kind);
        let rules: Vec<Rule> = tried
            .iter()
            .cloned()
            .map(|r| if chosen { Rule { enabled: true, applies_to: vec![engine], ..r } } else { r })
            // A chosen rule for the other kind of traffic (a WebSocket rule on a request) can't apply.
            .filter(|r| !chosen || (r.location == RuleLocation::WsMessage) == engine.is_ws())
            .collect();
        let set = RuleSet::compile(&rules)?;
        let ruled: Ruled = match kind {
            MessageArg::Request => set.request(engine, &host, bytes),
            MessageArg::Response => set.response(engine, &host, &answered, bytes),
            MessageArg::WsToServer | MessageArg::WsToClient => set.ws_message(engine, &host, &bytes),
        };
        let name = match kind {
            MessageArg::Request => "request",
            MessageArg::Response => "response",
            MessageArg::WsToServer | MessageArg::WsToClient => "message",
        };
        let mut result = json!({
            "changed": ruled.changed(),
            "rules": ruled.ids(),
            "result": body_value(&ruled.bytes, max_body),
        });
        if let Some(original) = &ruled.original {
            result["original"] = body_value(original, max_body);
        }
        // A rule whose script failed left the message as it was: said, not hidden in "unchanged".
        if !ruled.failed.is_empty() {
            result["errors"] = json!(ruled.failed);
        }
        // A request rule's script that blocked or answered it: the engine would send nothing.
        if let Some(stopped) = &ruled.stopped {
            result["stopped"] = match stopped.answer() {
                Some(response) => json!({"rule": stopped.id, "outcome": "answered", "response": body_value(response, max_body)}),
                None => json!({"rule": stopped.id, "outcome": "blocked", "reason": stopped.message()}),
            };
        }
        results.insert(name.to_string(), result);
        let mut by = match ruled.ids().as_slice() {
            [] => "unchanged".to_string(),
            ids => format!("changed by rule {}", ids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")),
        };
        for f in &ruled.failed {
            by.push_str(&format!("; rule {}'s script failed ({})", f.id, f.error));
        }
        if let Some(stopped) = &ruled.stopped {
            by.push_str(&format!("; {}, so nothing would be sent", stopped.message()));
            if let Some(response) = stopped.answer() {
                by.push_str(&format!(
                    "\nits response:\n{}",
                    crate::output::escape_lines(&String::from_utf8_lossy(response))
                ));
            }
        }
        texts.push(format!("{name}: {by}\n{}", crate::output::escape_lines(&String::from_utf8_lossy(&ruled.bytes))));
        first_bytes.get_or_insert(ruled.bytes);
    }
    if raw {
        out.raw(&first_bytes.unwrap_or_default());
        return Ok(());
    }
    let mut data = Value::Object(results);
    data["host"] = json!(host);
    data["tried"] = json!(tried.iter().map(|r| r.id).collect::<Vec<_>>());
    if !skipped.is_empty() {
        data["skipped"] = json!(skipped);
    }
    out.ok(data, || texts.join("\n\n"));
    Ok(())
}

/// The last failure noted for each rule's script, for the rules there are (see
/// [`brainproxy_core::rules::RULE_FAILURES`]): `[{"id", "error", "time", "engine"}]`.
fn rule_failures(store: &Store, rules: &[Rule]) -> Value {
    let noted = brainproxy_core::rules::noted_failures(store);
    let failures = rules.iter().filter_map(|r| {
        let mut f = noted.get(r.id.to_string())?.clone();
        f["id"] = json!(r.id);
        Some(f)
    });
    Value::Array(failures.collect())
}

/// The rules the proxy leaves out when it loads them (see [`breaks_head`], and for a rule's
/// script [`script_problem`]), with why.
///
/// [`script_problem`]: brainproxy_core::rules::script_problem
fn skipped_rules(rules: &[Rule]) -> Value {
    let skipped = rules.iter().filter_map(|r| {
        let reason = if breaks_head(r) {
            "its replacement holds a line break or NUL, which would start another header".to_string()
        } else {
            brainproxy_core::rules::script_problem(r).filter(|_| r.enabled)?
        };
        Some(json!({"id": r.id, "reason": reason}))
    });
    Value::Array(skipped.collect())
}

/// Checks a request rule about to take effect for a Host the scope doesn't list that it would put
/// on requests (see [`rule_host`]), as `send` checks a request's.
fn check_rule_host(store: &Store, rule: &Rule, test: bool, out: &Out) -> Result<Option<String>, Error> {
    let guard = store.guard()?;
    // Names the engagement lists, for requests the rule may rewrite: a wildcard as one of its hosts.
    let names: Vec<String> = store
        .engagement()?
        .map(|s| s.include)
        .unwrap_or_default()
        .iter()
        .filter(|e| !e.contains('/'))
        .filter_map(|e| Target::from_url(&e.replacen("*.", "www.", 1)).ok())
        .map(|t| t.host)
        .collect();
    crate::mcp::check_host_setting(&format!("rule {}", rule.id), rule_host(&guard, &names, rule), test, out)
}

/// The Host the scope doesn't list that a request rule would put on requests: one its
/// replacement writes (a Host header's line or value, or an absolute URL in the request line or
/// path), or one it makes of the Host of a request to one of `names`. A rule can match anything,
/// so this is no proof: a rule that rewrites only requests these don't look like isn't caught.
fn rule_host(guard: &std::sync::Arc<brainproxy_core::guard::Guard>, names: &[String], rule: &Rule) -> Option<String> {
    use brainproxy_core::http::client::unlisted_host;
    let replace = rule.replace.trim();
    // A URL in what is written into the request line.
    let url_host = || {
        replace.find("://").and_then(|at| {
            let start = replace[..at].rfind(' ').map_or(0, |i| i + 1);
            let url = replace[start..].split(' ').next().unwrap_or_default();
            match Target::from_url(url) {
                Ok(t) => unlisted_host(Some(guard), &t.host),
                Err(_) => Some(url.to_string()),
            }
        })
    };
    // What the rule makes of the request, for a part of the request line that would no longer be one part.
    let made = || Some(format!("(what the rule makes of the request: {replace:?})"));
    let removes = rule.action == Some(RuleAction::Remove);
    let written = match (rule.location, rule.name.as_deref()) {
        // A named header's value: only the Host header's can name a host. The replacement is
        // the whole value when nothing is matched (or the whole value is); what a match in the
        // value leaves of it is seen below, on requests to the hosts the engagement lists.
        (RuleLocation::RequestHeader, Some(name)) => {
            if !name.eq_ignore_ascii_case("host") || removes {
                return None;
            }
            let whole = rule.pattern.is_empty() || rule.matcher == MatchKind::Whole;
            whole.then(|| unlisted_host(Some(guard), replace)).flatten()
        }
        (RuleLocation::RequestHeader, None) => replace
            .split_once(':')
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
            .and_then(|(_, v)| unlisted_host(Some(guard), v)),
        (RuleLocation::RequestLine | RuleLocation::Path, _) => url_host(),
        // A space would make the method or a parameter the start of another target.
        (RuleLocation::Method | RuleLocation::QueryParam, _) if !removes => {
            url_host().or_else(|| replace.contains(' ').then(made).flatten())
        }
        _ => return None,
    };
    if written.is_some() {
        return written;
    }
    // A name or request target the rule takes from the request (`$1`) can be anything, a Host
    // too ("^X-Zz: (.*)$" to "Hos$1"); so can a name that is the start of "Host".
    let capture = regex::Regex::new(r"\$(\d|\{|[A-Za-z_])").expect("valid");
    let copied = match rule.location {
        _ if rule.matcher != MatchKind::Regex && rule.location != RuleLocation::RequestHeader => false,
        // A part of the Host's value the rule takes from the request can be any host.
        RuleLocation::RequestHeader if rule.name.is_some() => {
            rule.matcher == MatchKind::Regex && capture.is_match(replace)
        }
        RuleLocation::RequestHeader => {
            let name = replace.split_once(':').map_or(replace, |(k, _)| k).trim();
            let host_start = !name.is_empty() && "host".starts_with(&name.to_ascii_lowercase());
            (rule.matcher == MatchKind::Regex && capture.is_match(name)) || host_start
        }
        // A parameter's value is never where the target starts.
        RuleLocation::QueryParam => false,
        _ => capture.find_iter(replace).any(|m| m.start() == 0 || replace[..m.start()].ends_with(' ')),
    };
    if copied {
        return made();
    }
    let compiled = brainproxy_core::proxy::config::compile_rules(&[Rule { enabled: true, ..rule.clone() }]).ok()?;
    let opts = SendOptions { guard: Some(guard.clone()), ..Default::default() };
    names.iter().find_map(|name| {
        let host = if name.contains(':') { format!("[{name}]") } else { name.clone() };
        let probe = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes();
        let target = Target { scheme: "https".into(), host: name.clone(), port: 443 };
        let ruled = brainproxy_core::proxy::config::apply_request_rules(&compiled, probe);
        opts.foreign_host(&ruled, &target)
    })
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
            filter,
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
                filter: filter.filter(|f| !f.trim().is_empty()),
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
        InterceptCmd::Forward { id, file, verbatim, host_header_test } => {
            // The edit is forwarded as it is, and recorded: through MCP only a file in the
            // project's folder, checked before anything else.
            let file = file
                .map(|f| crate::mcp::local_file_arg(project, "--file", &f, "pass the edit on stdin (-)"))
                .transpose()?;
            let (entry, original, _) = store.intercept_get(id)?;
            let websocket = entry.direction.starts_with("ws-");
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
            // The proxy sends an edited request where the held one was going, so a Host the edit
            // brings in is checked as `send` checks one; a Host the client sent stays as it was.
            let mut host_warning = None;
            if let (Some(e), "request") = (&edited, entry.direction.as_str()) {
                let target = Target::from_url(&entry.url)?;
                let opts = SendOptions { guard: Some(store.guard()?), ..Default::default() };
                let before = opts.foreign_hosts(&original, &target);
                if let Some(new) = opts.foreign_hosts(e, &target).into_iter().find(|h| !before.contains(h)) {
                    host_warning = crate::mcp::check_host_setting("the edit", Some(new), host_header_test, out)?;
                }
            }
            let by = brainproxy_core::provenance::origin();
            store.intercept_resolve(id, "forwarded", edited.as_deref(), Some(by))?;
            let mut data = json!({"id": id, "state": "forwarded", "edited": edited.is_some(), "resolved_by": by});
            if let Some(w) = host_warning {
                data["host_warning"] = json!(w);
            }
            out.ok(data, || format!("forwarded #{id}"));
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
            schema: Some(brainproxy_core::store::SCHEMA_VERSION),
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

    /// The guard waits while the restart runs. Once it has gone, the guard stops the old proxy
    /// and starts it again only if the restart had asked it to stop, or it has gone anyway; else
    /// the old proxy gets its record back.
    #[test]
    fn the_guard_only_starts_the_proxy_again_if_the_restart_had_asked_it_to_stop() {
        for bits in 0..32u8 {
            let bit = |i: u8| bits & (1 << i) != 0;
            let look = GuardLook {
                restart_gone: bit(0),
                recorded_me: bit(1),
                stopping: bit(2),
                stop_requested: bit(3),
                old_alive: bit(4),
            };
            let want = match look {
                GuardLook { restart_gone: false, .. } => GuardStep::Wait,
                // Gone before it recorded its guard, or before it marked the stop: nothing stopped.
                GuardLook { recorded_me: false, .. } | GuardLook { stopping: false, .. } => GuardStep::GiveBack,
                // Marked, but gone before it asked: the old proxy runs as it was.
                GuardLook { stop_requested: false, old_alive: true, .. } => GuardStep::GiveBack,
                _ => GuardStep::Finish,
            };
            assert_eq!(guard_step(look), want, "{look:?}");
        }
    }

    /// The stop request reads as not yet made until a pid replaces it, and no proxy takes it.
    #[test]
    fn a_pending_stop_request_names_no_proxy() {
        let pending = stop_pending("7-1");
        assert_ne!(stop_pending("7-2"), pending);
        assert!(pending.parse::<u32>().is_err(), "{pending}");
        assert_eq!(restart_pid("7-1"), Some(7));
        assert_eq!(restart_pid("x"), None);
    }

    /// What was done for a restart that had gone is noted, and said with its time and origin.
    #[test]
    fn a_restart_that_had_gone_is_noted() {
        let store = Store::open_in_memory().unwrap();
        let state = ProxyState { pid: 9, ..state_with(&["proxy", "run"]) };
        note_gone(&store, "7-1", Ok(&state), "the restart's guard");
        let gone: Value = serde_json::from_str(&store.meta_get(GONE_KEY).unwrap().unwrap()).unwrap();
        assert_eq!((&gone["restart_pid"], &gone["proxy"]["pid"], &gone["note"]), (&json!(7), &json!(9), &Value::Null));
        assert_eq!(gone["restart_origin"], brainproxy_core::provenance::origin());
        let at = gone["at"].as_u64().unwrap();
        let text = gone_text(&gone, at + 300);
        assert!(text.starts_with("5 min ago, a restart (pid 7, "), "{text}");
        assert!(
            text.ends_with(
                "the restart's guard started the proxy again on 127.0.0.1:8080 (pid 9) with its old options"
            ),
            "{text}"
        );

        note_gone(&store, "7-1", Err("the proxy couldn't be started again on 127.0.0.1:8080"), "the restart's guard");
        let gone: Value = serde_json::from_str(&store.meta_get(GONE_KEY).unwrap().unwrap()).unwrap();
        assert_eq!(gone["proxy"], Value::Null);
        let text = gone_text(&gone, gone["at"].as_u64().unwrap());
        assert!(text.starts_with("0 s ago, "), "{text}");
        assert!(
            text.ends_with("the proxy was left off: the proxy couldn't be started again on 127.0.0.1:8080"),
            "{text}"
        );
    }

    /// The guard tries a failing read again for a while, and gets what works.
    #[test]
    fn the_guard_reads_again_after_a_failure() {
        let mut tries = 0;
        let got = retrying(|| {
            tries += 1;
            if tries < 3 {
                Err(Error::Conflict("locked".into()))
            } else {
                Ok(tries)
            }
        });
        assert_eq!(got.unwrap(), 3);
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
    fn a_proxy_older_than_the_project_schema_is_warned_about() {
        assert_eq!(outdated_text(Some(19), 19), None);
        assert_eq!(outdated_text(Some(20), 19), None);
        let older = outdated_text(Some(18), 19).unwrap();
        assert!(older.starts_with("the running proxy was started by a brainproxy build for schema v18"), "{older}");
        assert!(older.ends_with("brainproxy proxy restart"), "{older}");
        // One from before the proxy kept it says nothing of its schema.
        assert!(outdated_text(None, 19)
            .unwrap()
            .contains("by an older brainproxy build, and the project is at schema v19"));
        // What an older build wrote still reads.
        let old: ProxyState =
            serde_json::from_str(r#"{"pid":1,"listen":"127.0.0.1:1","started":"0","ca_cert":"c","log":null}"#).unwrap();
        assert_eq!(old.schema, None);
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
            schema: None,
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
