//! `oob`: the out-of-band interaction listener (lifecycle), manual payloads,
//! and polling for interactions. See docs/OOB.md.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use brainproxy_core::oob::server::{serve, ServeOptions};
use brainproxy_core::oob::{self, Endpoint, OobState, STATE_KEY};
use brainproxy_core::scan::active;
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::output::Out;
use crate::process::{self, start_time, Liveness};

/// `oob stop` asks the listener to exit through this key (see `process::shutdown`).
const STOP_KEY: &str = "oob.stop";
const LOCK_NAME: &str = "oob";

#[derive(Subcommand)]
pub enum OobCmd {
    /// Start the listener in the background and return once it is listening.
    Start(OobRunArgs),
    /// Run the listener in the foreground until SIGINT/SIGTERM.
    Run(OobRunArgs),
    /// Stop the background listener for this project.
    Stop {
        /// Only clear a record that can't be verified (its lock file isn't readable from this
        /// container). Nothing is signalled, and a listener known to be running is left alone.
        #[arg(long)]
        forget: bool,
    },
    /// Whether the listener runs, its public endpoint, and payload/interaction counts.
    Status,
    /// Issue payloads for manual testing (blind SSRF, XXE, command injection, ...).
    #[command(after_help = "Put `host` or `url` in the attack, then `oob poll --token TOKEN --wait 30`.")]
    Payload {
        /// Free-text note stored with the payload (e.g. where it was injected).
        #[arg(long)]
        note: Option<String>,
        /// URL or host of the target that will call back: when the public host was
        /// guessed, the local address routing to it is used.
        #[arg(long)]
        target: Option<String>,
        /// Number of payloads (1-100).
        #[arg(long, default_value_t = 1)]
        count: usize,
    },
    /// List received interactions. Also raises findings for interactions with
    /// active-scan payloads that arrived after the scan ended.
    Poll {
        /// Only interactions carrying this token.
        #[arg(long)]
        token: Option<String>,
        /// Only interactions with an id greater than this (use `next_since` from the last poll).
        #[arg(long, default_value_t = 0)]
        since: i64,
        /// Seconds to wait for at least one matching interaction.
        #[arg(long, default_value_t = 0.0)]
        wait: f64,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Bytes of each interaction's raw data to include.
        #[arg(long, default_value_t = 2000)]
        max_raw: usize,
    },
}

#[derive(clap::Args, Clone)]
pub struct OobRunArgs {
    /// TCP address for HTTP/LDAP/TLS callbacks; all interfaces by default so targets can
    /// reach it. Port 0 picks a free port.
    #[arg(long, default_value = "0.0.0.0:8880")]
    listen: String,
    /// UDP address for the DNS server (e.g. 0.0.0.0:53); needs --domain.
    #[arg(long)]
    dns_listen: Option<String>,
    /// Domain delegated to (or wildcard-pointed at) this host; payload hosts become <token>.<domain>.
    #[arg(long)]
    domain: Option<String>,
    /// Host or IP targets use to reach the TCP listener (default: the listen IP, or this
    /// machine's outbound address when listening on all interfaces). Set it behind NAT.
    #[arg(long)]
    public_host: Option<String>,
    /// Port targets use to reach the TCP listener (default: the listen port).
    #[arg(long)]
    public_port: Option<u16>,
    /// Address returned for DNS A/AAAA queries under --domain (default: --public-host if it is an IP).
    #[arg(long)]
    public_ip: Option<IpAddr>,
    /// Seconds `start` waits for the listener to come up.
    #[arg(long, default_value_t = 10.0)]
    wait: f64,
    /// Log file for `start` (default: next to the project file).
    #[arg(long)]
    log: Option<PathBuf>,
}

/// The saved state and what is known about it, clearing stale state left by a crash.
fn recorded(store: &Store) -> Result<Option<(OobState, Liveness)>, Error> {
    let Some(s) = oob::read_state(store)? else { return Ok(None) };
    match process::liveness(store, LOCK_NAME, s.pid, s.start_time, s.pid_ns.as_deref()) {
        Liveness::Gone => {
            store.meta_set(STATE_KEY, None)?;
            Ok(None)
        }
        known => Ok(Some((s, known))),
    }
}

/// The running listener for this project, clearing stale state left by a crash.
pub(crate) fn running(store: &Store) -> Result<Option<OobState>, Error> {
    Ok(recorded(store)?.filter(|(_, known)| *known == Liveness::Running).map(|(s, _)| s))
}

/// Stops this project's listener if one runs: its pid, and whether it had to be killed.
pub(crate) fn stop(store: &Store) -> Result<Option<(u32, bool)>, Error> {
    let Some((state, _)) = recorded(store)? else { return Ok(None) };
    process::request_stop(store, STOP_KEY, state.pid)?;
    let wait = std::time::Duration::from_secs(5);
    let forced = if process::elsewhere(state.pid_ns.as_deref()) {
        process::await_exit_elsewhere(store, LOCK_NAME, STATE_KEY, state.pid, wait)?;
        false
    } else {
        process::terminate(state.pid, state.start_time, "OOB listener", wait)?
    };
    store.meta_set(STATE_KEY, None)?;
    store.meta_set(STOP_KEY, None)?;
    Ok(Some((state.pid, forced)))
}

/// Clears a record that can't be verified: its pid, or `None` if there is no record.
fn forget(store: &Store) -> Result<Option<u32>, Error> {
    let Some((state, known)) = recorded(store)? else { return Ok(None) };
    if known == Liveness::Running {
        return Err(Error::Conflict(format!(
            "the OOB listener is running ({}), so its record stays; use `brainproxy oob stop`",
            process::pid_text(state.pid, state.pid_ns.as_deref())
        )));
    }
    store.meta_set(STATE_KEY, None)?;
    store.meta_set(STOP_KEY, None)?;
    Ok(Some(state.pid))
}

fn already_running(s: &OobState, known: Liveness) -> Error {
    if known == Liveness::Unverified {
        return Error::Conflict(process::unverified_text(LOCK_NAME, s.pid));
    }
    let pid = process::pid_text(s.pid, s.pid_ns.as_deref());
    Error::Conflict(format!("OOB listener already running on {} ({pid})", s.tcp_listen))
}

fn not_running() -> Error {
    Error::NotFound("no OOB listener running for this project (start one with `brainproxy oob start`)".into())
}

fn state_json(s: &OobState) -> Value {
    let example = s.endpoint.payload_for("bpEXAMPLETOKEN".into());
    let mut v = json!(s);
    v["payload_example"] = json!({"host": example.host, "url": example.url, "dns": example.dns});
    v["warning"] = json!(exposure_warning(s));
    v
}

/// Listening on all interfaces is the default (targets must reach us), so say so.
fn exposure_warning(s: &OobState) -> Option<String> {
    let all = s.tcp_listen.parse::<std::net::SocketAddr>().is_ok_and(|a| a.ip().is_unspecified())
        || s.dns_listen
            .as_deref()
            .and_then(|d| d.parse::<std::net::SocketAddr>().ok())
            .is_some_and(|a| a.ip().is_unspecified());
    all.then(|| {
        "listening on all interfaces: anyone who can reach this host can connect. Only callbacks carrying a \
         registered token are stored; pass --listen 127.0.0.1:8880 (or a firewall) to limit who can reach it"
            .into()
    })
}

pub fn oob(project: &Path, cmd: OobCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        OobCmd::Start(args) => start(project, args, out),
        OobCmd::Run(args) => run_foreground(project, args, out),
        OobCmd::Stop { forget: true } => {
            let store = Store::open(project)?;
            let pid =
                forget(&store)?.ok_or_else(|| Error::NotFound("no OOB listener recorded for this project".into()))?;
            out.ok(json!({"forgotten": pid}), || format!("cleared the record of the OOB listener (pid {pid})"));
            Ok(())
        }
        OobCmd::Stop { forget: false } => {
            let store = Store::open(project)?;
            let (pid, forced) = stop(&store)?.ok_or_else(not_running)?;
            out.ok(json!({"stopped": pid, "forced": forced}), || format!("stopped OOB listener (pid {pid})"));
            Ok(())
        }
        OobCmd::Status => {
            let store = Store::open(project)?;
            let (saved, known) = recorded(&store)?.unzip();
            let unverified = saved.as_ref().filter(|_| known == Some(Liveness::Unverified)).map(|s| {
                json!({"pid": s.pid, "tcp_listen": s.tcp_listen,
                    "reason": process::unverified_text(LOCK_NAME, s.pid),
                    "next": "brainproxy oob stop --forget"})
            });
            let state = saved.filter(|_| known == Some(Liveness::Running));
            let (payloads, interactions, unmatched, dropped) = store.oob_counts()?;
            let data = json!({
                "running": state.is_some(),
                "listener": state.as_ref().map(state_json),
                "other_pid_namespace": state.as_ref().is_some_and(|s| process::elsewhere(s.pid_ns.as_deref())),
                "unverified": unverified,
                "payloads": payloads,
                "interactions": interactions,
                "unmatched_interactions": unmatched,
                "dropped_interactions": dropped,
                "caps": {"interactions": oob::MAX_INTERACTIONS, "per_token": oob::MAX_PER_TOKEN},
            });
            out.ok(data, || match &state {
                Some(s) => format!(
                    "listening on {} ({}), {payloads} payloads, {interactions} interactions",
                    s.tcp_listen,
                    process::pid_text(s.pid, s.pid_ns.as_deref())
                ),
                None => match &unverified {
                    Some(u) => format!(
                        "{}; {payloads} payloads, {interactions} interactions",
                        u["reason"].as_str().unwrap_or_default()
                    ),
                    None => format!("not running; {payloads} payloads, {interactions} interactions"),
                },
            });
            Ok(())
        }
        OobCmd::Payload { note, target, count } => {
            if !(1..=100).contains(&count) {
                return Err(Error::InvalidInput("--count must be 1-100".into()));
            }
            let store = Store::open(project)?;
            let state = running(&store)?.ok_or_else(not_running)?;
            let endpoint = match &target {
                Some(t) => {
                    let t = brainproxy_core::http::Target::from_url(t)?;
                    state.endpoint.for_target(&t.host, t.port)
                }
                None => state.endpoint.clone(),
            };
            let mut payloads = Vec::new();
            for _ in 0..count {
                let p = endpoint.payload()?;
                store.oob_add_manual_payload(&p.token, note.as_deref())?;
                let mut examples = json!({
                    "curl": format!("curl {}", p.url),
                    "log4j": format!("${{jndi:ldap://{}/{}}}", p.host, p.token),
                    "xxe": format!("<!DOCTYPE x [<!ENTITY e SYSTEM \"{}\">]><x>&e;</x>", p.url),
                });
                if p.dns {
                    examples["nslookup"] = json!(format!("nslookup {}", p.host));
                }
                let mut v = json!(p);
                v["examples"] = examples;
                payloads.push(v);
            }
            let first = payloads[0]["token"].as_str().unwrap_or("").to_string();
            let data = json!({
                "payloads": payloads,
                "hint": format!("brainproxy oob poll --token {first} --wait 30"),
            });
            out.ok(data.clone(), || {
                data["payloads"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|p| format!("{}  {}", p["host"].as_str().unwrap_or(""), p["url"].as_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(())
        }
        OobCmd::Poll { token, since, wait, limit, max_raw } => {
            let mut store = Store::open(project)?;
            let token = token.map(|t| t.to_ascii_lowercase());
            if let Some(t) = &token {
                if !store.oob_token_exists(t)? {
                    return Err(Error::NotFound(format!("OOB payload {t}")));
                }
            }
            let limit = limit.clamp(1, 1000);
            let deadline = Instant::now() + Duration::from_secs_f64(wait.max(0.0));
            let mut correlated = oob::Correlation::default();
            let rows = loop {
                let c = oob::correlate(&mut store, active::alert_def)?;
                correlated.interactions += c.interactions;
                correlated.matched += c.matched;
                correlated.new_findings += c.new_findings;
                correlated.raised.extend(c.raised);
                let rows = store.oob_interactions(since, token.as_deref(), limit, max_raw)?;
                if !rows.is_empty() || Instant::now() >= deadline {
                    break rows;
                }
                std::thread::sleep(Duration::from_millis(250));
            };
            let next_since = rows.last().and_then(|r| r["id"].as_i64()).unwrap_or(since);
            let data = json!({
                "interactions": rows,
                "count": rows.len(),
                "truncated": rows.len() == limit,
                "next_since": next_since,
                "listener_running": running(&store)?.is_some(),
                "scan_findings": {"matched": correlated.matched, "new_findings": correlated.new_findings},
            });
            out.ok(data, || {
                if rows.is_empty() {
                    return "no interactions".into();
                }
                rows.iter()
                    .map(|r| {
                        format!(
                            "{:>5}  {:<5} {:<22} {}",
                            r["id"],
                            r["protocol"].as_str().unwrap_or(""),
                            r["remote"].as_str().unwrap_or(""),
                            r["summary"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(())
        }
    }
}

fn start(project: &Path, args: OobRunArgs, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    if let Some((s, known)) = recorded(&store)? {
        return Err(already_running(&s, known));
    }
    let project = std::fs::canonicalize(project)?;
    let log = args.log.clone().unwrap_or_else(|| project.with_extension("oob.log"));
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    let log_start = log_file.metadata()?.len() as usize;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg("--project").arg(&project).args(["--format", "json", "oob", "run", "--listen", &args.listen]);
    for (flag, v) in [
        ("--dns-listen", args.dns_listen.clone()),
        ("--domain", args.domain.clone()),
        ("--public-host", args.public_host.clone()),
        ("--public-port", args.public_port.map(|p| p.to_string())),
        ("--public-ip", args.public_ip.map(|p| p.to_string())),
    ] {
        if let Some(v) = v {
            cmd.args([flag, &v]);
        }
    }
    cmd.arg("--log").arg(&log);
    process::detach(&mut cmd);
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::from(log_file.try_clone()?)).stderr(Stdio::from(log_file)).spawn()?;
    let deadline = Instant::now() + Duration::from_secs_f64(args.wait.max(0.1));
    loop {
        if let Some(status) = child.try_wait()? {
            let text = std::fs::read(&log).unwrap_or_default();
            let new = String::from_utf8_lossy(text.get(log_start..).unwrap_or_default()).into_owned();
            return Err(crate::jobs_cmd::child_failure("OOB listener", status, &new));
        }
        if let Some(state) = oob::read_state(&store)?.filter(|s| s.pid == child.id()) {
            out.ok(state_json(&state), || {
                let host = state.endpoint.payload_for("bpEXAMPLETOKEN".into()).host;
                let mut t = format!("OOB listener on {} (pid {}), payload host {host}", state.tcp_listen, state.pid);
                if let Some(w) = exposure_warning(&state) {
                    t.push_str(&format!("\nwarning: {w}"));
                }
                t
            });
            return Ok(());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return Err(Error::Timeout(Duration::from_secs_f64(args.wait)));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// This machine's address on the default route. A UDP `connect` only picks a
/// route; nothing is sent.
fn outbound_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    s.local_addr().ok().map(|a| a.ip()).filter(|ip| !ip.is_unspecified())
}

fn check_domain(d: &str) -> Result<String, Error> {
    let d = d.trim_matches('.').to_ascii_lowercase();
    let ok = !d.is_empty()
        && d.len() <= 200
        && d.split('.')
            .all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if ok {
        Ok(d)
    } else {
        Err(Error::InvalidInput(format!("invalid --domain {d:?}")))
    }
}

fn run_foreground(project: &Path, args: OobRunArgs, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    // Its own pid is its own state, unless that is the same pid in another container.
    let me = std::process::id();
    if let Some((s, known)) = recorded(&store)?.filter(|(s, _)| s.pid != me || process::elsewhere(s.pid_ns.as_deref()))
    {
        return Err(already_running(&s, known));
    }
    let domain = args.domain.as_deref().map(check_domain).transpose()?;
    if args.dns_listen.is_some() && domain.is_none() {
        return Err(Error::InvalidInput("--dns-listen needs --domain".into()));
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        let tcp = tokio::net::TcpListener::bind(&args.listen)
            .await
            .map_err(|e| Error::Conflict(format!("cannot listen on {}: {e}", args.listen)))?;
        let dns = match &args.dns_listen {
            Some(a) => Some(
                tokio::net::UdpSocket::bind(a)
                    .await
                    .map_err(|e| Error::Conflict(format!("cannot listen on udp {a}: {e}")))?,
            ),
            None => None,
        };
        let addr = tcp.local_addr()?;
        let public_host = match &args.public_host {
            Some(h) => h.trim_matches(['[', ']']).to_string(),
            None if !addr.ip().is_unspecified() => addr.ip().to_string(),
            None => outbound_ip()
                .ok_or_else(|| Error::InvalidInput("cannot determine this host's address; pass --public-host".into()))?
                .to_string(),
        };
        let public_ip = args.public_ip.or_else(|| public_host.parse().ok());
        let endpoint = Endpoint {
            domain: domain.clone(),
            public_host,
            public_port: args.public_port.unwrap_or(addr.port()),
            auto_host: args.public_host.is_none() && addr.ip().is_unspecified(),
        };
        let started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let lock = process::RunLock::acquire(&store, LOCK_NAME)?;
        let state = OobState {
            pid: std::process::id(),
            started: started.to_string(),
            tcp_listen: addr.to_string(),
            dns_listen: dns.as_ref().and_then(|d| d.local_addr().ok()).map(|a| a.to_string()),
            public_ip: public_ip.map(|i| i.to_string()),
            endpoint,
            log: args.log.clone(),
            start_time: start_time(std::process::id()),
            pid_ns: lock.as_ref().and_then(|_| process::pid_namespace()),
        };
        store.meta_set(STATE_KEY, Some(&serde_json::to_string(&state).unwrap_or_default()))?;
        out.ok(state_json(&state), || match exposure_warning(&state) {
            Some(w) => format!("OOB listener on {addr}\nwarning: {w}"),
            None => format!("OOB listener on {addr}"),
        });

        let shutdown = process::shutdown(&store, STOP_KEY);
        let opts = ServeOptions { project: project.to_path_buf(), domain, public_ip };
        let result = serve(tcp, dns, opts, shutdown).await;
        if oob::read_state(&store)?
            .is_some_and(|s| s.pid == std::process::id() && !process::elsewhere(s.pid_ns.as_deref()))
        {
            store.meta_set(STATE_KEY, None)?;
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_validation() {
        assert_eq!(check_domain("OOB.Example.com.").unwrap(), "oob.example.com");
        assert!(check_domain("a..b").is_err());
        assert!(check_domain("evil.com/x").is_err());
        assert!(check_domain("").is_err());
    }
}
