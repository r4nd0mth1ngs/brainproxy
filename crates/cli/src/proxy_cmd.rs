//! CLI for the intercepting proxy: CA, proxy lifecycle, scope, rules, intercept queue.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use brainproxy_core::http::{RawRequest, SendOptions};
use brainproxy_core::proxy::config::{
    InterceptSettings, Rule, RuleLocation, Scope, TimeoutAction, INTERCEPT_KEY, RULES_KEY, SCOPE_KEY,
};
use brainproxy_core::proxy::{CertAuthority, ProxyOptions, ProxyState, STATE_KEY};
use brainproxy_core::store::{HistoryFilter, Store};
use brainproxy_core::{codec, Error};
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};

use crate::output::{body_value, Out};

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
        /// Write to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Print the certificate itself rather than the JSON envelope.
        #[arg(long)]
        raw: bool,
    },
    /// Add the CA to the system trust store (Debian/Kali: update-ca-certificates). Needs root.
    InstallSystem,
}

#[derive(Subcommand)]
pub enum ProxyCmd {
    /// Start the proxy in the background and return once it is listening.
    Start(ProxyRunArgs),
    /// Run the proxy in the foreground until SIGINT/SIGTERM.
    Run(ProxyRunArgs),
    /// Stop the background proxy for this project.
    Stop,
    /// Show whether a proxy is running, with capture and intercept counts.
    Status,
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
    /// Seconds `start` waits for the proxy to come up.
    #[arg(long, default_value_t = 10.0)]
    wait: f64,
    /// Log file for `start` (default: next to the project file).
    #[arg(long)]
    log: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum ScopeCmd {
    /// Show the current scope.
    Show,
    /// Replace the scope. Patterns are case-insensitive regexes matched against host names.
    Set {
        #[arg(long)]
        include: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
        /// Also record out-of-scope traffic (it is never intercepted or modified).
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
    /// Start holding matching messages in the queue. With neither flag, requests are held.
    Enable {
        #[arg(long)]
        requests: bool,
        #[arg(long)]
        responses: bool,
        /// Only hold messages for hosts matching this regex.
        #[arg(long)]
        host: Option<String>,
        /// Only hold messages for paths matching this regex.
        #[arg(long)]
        path: Option<String>,
        /// Only hold these methods (regex alternation, e.g. "POST|PUT").
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
        /// Replacement message file ('-' for stdin). Line endings and Content-Length are fixed unless --verbatim.
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        verbatim: bool,
    },
    /// Drop a held message; the client receives a 502.
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

/// Where the CA and other per-user data live.
pub fn resolve_home(home: Option<PathBuf>) -> PathBuf {
    home.or_else(|| std::env::var_os("XDG_DATA_HOME").map(|d| PathBuf::from(d).join("brainproxy")))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/brainproxy")))
        .unwrap_or_else(|| PathBuf::from(".brainproxy"))
}

fn ca_dir(home: &Path) -> PathBuf {
    home.join("ca")
}

fn load_ca(home: &Path) -> Result<(CertAuthority, brainproxy_core::proxy::CaInfo), Error> {
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
        CaCmd::Export { der, out: path, raw } => {
            let (ca, info) = load_ca(home)?;
            let bytes = if der { ca.cert_der().to_vec() } else { ca.cert_pem().as_bytes().to_vec() };
            if let Some(path) = path {
                std::fs::write(&path, &bytes)?;
                out.ok(json!({"path": path, "format": if der { "der" } else { "pem" }}), || {
                    format!("wrote {}", path.display())
                });
            } else if raw || der {
                out.raw(&bytes);
            } else {
                let data =
                    json!({"cert_path": info.cert_path, "pem": ca.cert_pem(), "sha256": fingerprint(ca.cert_der())});
                out.ok(data, || ca.cert_pem().to_string());
            }
        }
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

fn read_state(store: &Store) -> Result<Option<ProxyState>, Error> {
    Ok(store.meta_get(STATE_KEY)?.and_then(|s| serde_json::from_str(&s).ok()))
}

pub(crate) fn alive(pid: u32) -> bool {
    // Signal 0 checks for existence without delivering anything.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The running proxy for this project, clearing stale state left by a crash.
fn running(store: &Store) -> Result<Option<ProxyState>, Error> {
    match read_state(store)? {
        Some(s) if alive(s.pid) => Ok(Some(s)),
        Some(_) => {
            store.meta_set(STATE_KEY, None)?;
            Ok(None)
        }
        None => Ok(None),
    }
}

fn usage_hints(state: &ProxyState) -> Value {
    let url = format!("http://{}", state.listen);
    let ca = state.ca_cert.display();
    json!({
        "proxy_url": url,
        "curl": format!("curl --noproxy '' -x {url} --cacert {ca} https://TARGET/"),
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
        ProxyCmd::Run(args) => run_foreground(project, home, args, out),
        ProxyCmd::Stop => {
            let store = Store::open(project)?;
            let state = running(&store)?.ok_or_else(|| Error::NotFound("no proxy running for this project".into()))?;
            unsafe { libc::kill(state.pid as libc::pid_t, libc::SIGTERM) };
            let deadline = Instant::now() + Duration::from_secs(5);
            while alive(state.pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            let forced = alive(state.pid);
            if forced {
                unsafe { libc::kill(state.pid as libc::pid_t, libc::SIGKILL) };
            }
            store.meta_set(STATE_KEY, None)?;
            out.ok(json!({"stopped": state.pid, "forced": forced}), || format!("stopped proxy (pid {})", state.pid));
            Ok(())
        }
        ProxyCmd::Status => {
            let store = Store::open(project)?;
            let state = running(&store)?;
            let captures = store.list(&HistoryFilter { source: Some("proxy".into()), ..Default::default() })?.len();
            let pending = store.intercept_list(Some("pending"), u32::MAX)?.len();
            let intercept: InterceptSettings = store.setting(INTERCEPT_KEY)?;
            let rules: Vec<Rule> = store.setting(RULES_KEY)?;
            let scope: Scope = store.setting(SCOPE_KEY)?;
            let data = json!({
                "running": state.is_some(),
                "proxy": state.as_ref().map(state_json),
                "proxy_captures": captures,
                "pending_intercepts": pending,
                "intercept_enabled": intercept.enabled,
                "rules_enabled": rules.iter().filter(|r| r.enabled).count(),
                "scope": scope,
            });
            out.ok(data, || match &state {
                Some(s) => format!("running on {} (pid {}), {captures} captures, {pending} pending", s.listen, s.pid),
                None => "not running".into(),
            });
            Ok(())
        }
    }
}

fn start(project: &Path, home: &Path, args: ProxyRunArgs, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    if let Some(s) = running(&store)? {
        return Err(Error::Conflict(format!("proxy already running on {} (pid {})", s.listen, s.pid)));
    }
    load_ca(home)?; // Surface CA and scope problems here rather than in the log.
    store.guard()?;
    let project = std::fs::canonicalize(project)?;
    let log = args.log.clone().unwrap_or_else(|| project.with_extension("proxy.log"));
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    let log_start = log_file.metadata()?.len() as usize;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg("--project")
        .arg(&project)
        .arg("--home")
        .arg(home)
        .args(["--format", "json", "proxy", "run", "--listen", &args.listen])
        .args(["--timeout", &args.timeout.to_string()])
        .arg("--log")
        .arg(&log);
    if args.verify_tls {
        cmd.arg("--verify-tls");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::from(log_file.try_clone()?)).stderr(Stdio::from(log_file)).spawn()?;

    let deadline = Instant::now() + Duration::from_secs_f64(args.wait.max(0.1));
    loop {
        if let Some(status) = child.try_wait()? {
            let log_text = std::fs::read(&log).unwrap_or_default();
            let new = String::from_utf8_lossy(log_text.get(log_start..).unwrap_or_default()).into_owned();
            // Pass the child's own error envelope through when there is one.
            let child_error = new.lines().rev().find_map(|l| {
                let v: Value = serde_json::from_str(l).ok()?;
                let e = v.get("error")?;
                Some((e["kind"].as_str()?.to_string(), e["message"].as_str()?.to_string()))
            });
            return Err(match child_error {
                Some((kind, message)) if kind == "conflict" => {
                    Error::Conflict(message.trim_start_matches("conflict: ").to_string())
                }
                Some((_, message)) => Error::InvalidInput(message),
                None => Error::InvalidInput(format!("proxy exited ({status}): {}", new.trim())),
            });
        }
        if let Some(state) = read_state(&store)?.filter(|s| s.pid == child.id()) {
            out.ok(state_json(&state), || format!("proxy listening on http://{} (pid {})", state.listen, state.pid));
            return Ok(());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return Err(Error::Timeout(Duration::from_secs_f64(args.wait)));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn run_foreground(project: &Path, home: &Path, args: ProxyRunArgs, out: &Out) -> Result<(), Error> {
    let (ca, info) = load_ca(home)?;
    let store = Store::open(project)?;
    if let Some(s) = running(&store)?.filter(|s| s.pid != std::process::id()) {
        return Err(Error::Conflict(format!("proxy already running on {} (pid {})", s.listen, s.pid)));
    }
    // Fail before listening if there is no scope; the scope can't change while we run.
    let guard = store.guard()?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(&args.listen)
            .await
            .map_err(|e| Error::Conflict(format!("cannot listen on {}: {e}", args.listen)))?;
        let addr = listener.local_addr()?;
        let started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let state = ProxyState {
            pid: std::process::id(),
            listen: addr.to_string(),
            started: started.to_string(),
            ca_cert: info.cert_path.clone(),
            log: args.log.clone(),
        };
        store.meta_set(STATE_KEY, Some(&serde_json::to_string(&state).unwrap_or_default()))?;
        out.ok(state_json(&state), || format!("proxy listening on http://{addr}"));

        let shutdown = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;
        };
        let opts = ProxyOptions {
            project: project.to_path_buf(),
            upstream: SendOptions {
                timeout: Duration::from_secs_f64(args.timeout.max(0.001)),
                verify_tls: args.verify_tls,
                sni: None,
                guard: Some(guard),
            },
        };
        let result = brainproxy_core::proxy::run(listener, std::sync::Arc::new(ca), opts, shutdown).await;
        if read_state(&store)?.is_some_and(|s| s.pid == std::process::id()) {
            store.meta_set(STATE_KEY, None)?;
        }
        result
    })
}

pub fn scope(project: &Path, cmd: ScopeCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    let mut scope: Scope = store.setting(SCOPE_KEY)?;
    match cmd {
        ScopeCmd::Show => {}
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
    store.set_setting(SCOPE_KEY, &scope)?;
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
            let rule =
                Rule { id, location: RuleLocation::parse(&location)?, pattern, replace, enabled: !disabled, comment };
            brainproxy_core::proxy::config::compile_rules(std::slice::from_ref(&rule))?;
            rules.push(rule);
        }
        RulesCmd::Remove { id } => {
            let i = find(&mut rules, id)?;
            rules.remove(i);
        }
        RulesCmd::Enable { id } => {
            let i = find(&mut rules, id)?;
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
        InterceptCmd::Enable { requests, responses, host, path, method, timeout, timeout_action } => {
            let settings = InterceptSettings {
                enabled: true,
                requests: requests || !responses,
                responses,
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
            let edited = match file.as_deref() {
                None => None,
                Some(path) => {
                    let bytes = if path == "-" {
                        crate::read_input(None)?
                    } else {
                        std::fs::read(path).map_err(|e| Error::InvalidInput(format!("cannot read {path:?}: {e}")))?
                    };
                    let msg = RawRequest::from_bytes(bytes);
                    Some(if verbatim { msg } else { msg.normalize_line_endings().update_content_length() }.into_bytes())
                }
            };
            store.intercept_resolve(id, "forwarded", edited.as_deref())?;
            out.ok(json!({"id": id, "state": "forwarded", "edited": edited.is_some()}), || format!("forwarded #{id}"));
        }
        InterceptCmd::Drop { id } => {
            store.intercept_resolve(id, "dropped", None)?;
            out.ok(json!({"id": id, "state": "dropped"}), || format!("dropped #{id}"));
        }
    }
    Ok(())
}
