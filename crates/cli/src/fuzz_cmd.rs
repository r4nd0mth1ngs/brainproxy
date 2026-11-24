//! CLI for the fuzzer (Intruder) and comparer.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use brainproxy_core::diff::{diff, DiffMode};
use brainproxy_core::fuzz::{self, EngineConfig, Mode, Outcome, Plan, StoreMode, Template};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};

use crate::output::Out;
use crate::process::{self, Liveness};
use crate::request_args::RequestArgs;

#[derive(Subcommand)]
pub enum FuzzCmd {
    /// Run an attack. Mark payload positions in the request with §value§.
    #[command(after_help = "Modes: sniper (1 set; each position in turn), battering-ram (1 set; same payload \
        everywhere), pitchfork (1 set per position, in step), cluster-bomb (1 set per position, every combination).\n\
        Payload sources (-p, one per set, in position order): list:a,b,c | file:PATH | file:- | range:1-100[:step] | \
        wordlist:NAME (built-in: sqli, xss, path-traversal, content-discovery, ...; see `wordlists list`).\n\
        Generated: null:N (empty) | dates:FROM..TO[:STEP][:FORMAT] (e.g. dates:2024-01-01..2024-12-31:1d:%Y%m%d) | \
        brute:CHARSET:MIN-MAX (e.g. brute:a-z0-9:1-4; at most 10,000,000, made as sent) | case:WORD | \
        subst:WORD[:MAP] (default a=4@,e=3,i=1!,o=0,s=5$) | bitflip[:VALUE] (default: the position's value) | \
        usernames:list:John Smith,Ann Lee | usernames:file:PATH.\n\
        copy:N is position N's value in the same request (pitchfork, cluster-bomb). extract[:FIRST] is recursive \
        grep: each request gets what --extract captured from the previous response (needs --extract; one request at \
        a time; ends with outcome extract-ended when nothing is captured; extract sets alone need --max-requests).\n\
        oob:N[:host|url] makes N OOB payloads tied to the run (needs `oob start`). script:FILE takes the payloads \
        that file's payloads(ctx) returns (ctx.set, ctx.position, ctx.default, ctx.page); not offered through MCP.\n\
        Processing (--process, applied left to right): url, url-all, base64, base64url, hex, html, gzip, zlib, \
        deflate, md5, sha1, sha256, sha512, upper, lower, prefix:TEXT, suffix:TEXT, script:FILE. Prefix with N= to apply to set N only (e.g. 2=base64).\n\
        script:FILE passes each payload through that JavaScript file's process(payload, ctx) (ctx.set, ctx.index, and \
        ctx.base64 for a payload that isn't text), which returns the payload to send: a string, { base64 }, or null to \
        keep it. This runs code from that file, with no file or network access; a payload it fails on stops the run \
        before it starts. Not offered through MCP.\n\
        Results: the summary lists the baseline response shape, outliers (rare status+word-count shapes), and \
        matches. All results are in the fuzz_results table. `fuzz pause` and `fuzz resume` hold a run and let it \
        go on; `fuzz resume` also relaunches a stopped or failed run, sending what it has no results for.")]
    Run(Box<RunArgs>),
    /// Progress and triage summary of a run (baseline, outliers, matches, errors).
    Status {
        run: i64,
        /// Maximum outliers/matches to list.
        #[arg(long, default_value_t = 20)]
        top: usize,
    },
    /// List results of a run.
    Results {
        run: i64,
        /// Only matched results.
        #[arg(long)]
        matched: bool,
        /// Only results after this index (for paging).
        #[arg(long)]
        after: Option<i64>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// List fuzz runs.
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Ask a running or paused attack to stop (it finishes in-flight requests).
    Stop {
        run: i64,
        /// Only mark failed a run that can't be verified (its lock file isn't readable from
        /// this container). Nothing is signalled, and a run known to be running is left alone.
        #[arg(long)]
        forget: bool,
    },
    /// Pause a running attack: requests in flight finish and no new ones start until
    /// `fuzz resume`.
    Pause { run: i64 },
    /// Resume a paused attack, or relaunch a stopped or failed one in the background, sending
    /// only the requests it has no results for. A run with a set from stdin, an oob: or script:
    /// set, or a payload file that changed since it started can't be relaunched.
    Resume { run: i64 },
}

#[derive(clap::Args)]
pub struct RunArgs {
    #[command(flatten)]
    req: RequestArgs,

    #[arg(long, default_value = "sniper", value_parser = Mode::ALL.to_vec())]
    mode: String,
    /// Payload source for the next set (repeat for pitchfork/cluster-bomb); file:- reads stdin.
    /// Through MCP a file:PATH is read only from the project's folder.
    #[arg(short = 'p', long = "payloads", required = true)]
    payloads: Vec<String>,
    /// Processing chain for payloads, e.g. "url", "2=prefix:admin,base64" or "script:sign.js,url".
    /// Repeatable.
    #[arg(long)]
    process: Vec<String>,
    /// Position marker placed on both sides of each position.
    #[arg(long, default_value = fuzz::DEFAULT_MARKER)]
    marker: String,

    /// Concurrent connections.
    #[arg(short = 'c', long, default_value_t = 10)]
    concurrency: usize,
    /// Maximum requests per second across all connections.
    #[arg(long)]
    rate: Option<f64>,
    /// Stop after this many requests.
    #[arg(long)]
    max_requests: Option<u64>,
    /// Fuzz logged in with this auth profile; re-logs in when the session is lost.
    /// Cookies holding a payload marker keep the payload.
    #[arg(long, value_name = "NAME")]
    auth: Option<String>,

    /// Regex (Rust syntax) marking a result as matched when found in the response. Repeatable.
    #[arg(long)]
    grep: Vec<String>,
    /// Regex whose first capture group (or whole match) is saved per result.
    #[arg(long)]
    extract: Option<String>,
    /// Comma-separated statuses that mark a result as matched.
    #[arg(long, value_delimiter = ',')]
    match_status: Vec<u16>,
    /// Stop the attack at the first match.
    #[arg(long)]
    stop_on_match: bool,
    /// Insert payloads byte for byte. By default, payloads placed in the request line or a
    /// form-encoded body get what isn't URL-safe percent-encoded (spaces, quotes, <>, #,
    /// non-ASCII); & = ' ; and existing %XX are kept.
    #[arg(long)]
    no_encode: bool,
    /// Which exchanges go into history (results always go into fuzz_results). Through MCP,
    /// only `all`: an agent's requests are always recorded.
    #[arg(long, value_enum, default_value = "all")]
    store: StoreArg,

    /// Return immediately with the run id; poll with `fuzz status RUN`.
    #[arg(long)]
    background: bool,
    /// Maximum outliers/matches in the summary.
    #[arg(long, default_value_t = 20)]
    top: usize,
    #[arg(long, hide = true)]
    attach_run: Option<i64>,
    /// With --attach-run: the run is being resumed, so the requests it has results for are skipped.
    #[arg(long, hide = true, requires = "attach_run")]
    resume: bool,
    /// Request file a --background parent wrote for its child (read, then deleted).
    #[arg(long, hide = true)]
    attach_request: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum StoreArg {
    All,
    Matches,
    None,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum DiffModeArg {
    Lines,
    Words,
    Bytes,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum DiffPart {
    Request,
    Response,
    ResponseBody,
}

#[derive(clap::Args)]
pub struct DiffArgs {
    /// History id of the first message.
    a: i64,
    /// History id of the second message.
    b: i64,
    #[arg(long, value_enum, default_value = "response")]
    part: DiffPart,
    #[arg(long, value_enum, default_value = "lines")]
    mode: DiffModeArg,
    /// Maximum changes to list.
    #[arg(long, default_value_t = 200)]
    max_changes: usize,
    /// Context lines in the unified diff.
    #[arg(long, default_value_t = 2)]
    context: usize,
}

pub fn fuzz_cmd(project: &Path, home: &Path, cmd: FuzzCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        FuzzCmd::Run(args) => run(project, home, *args, out),
        FuzzCmd::Status { run, top } => {
            let store = Store::open(project)?;
            reap_if_dead(&store, run)?;
            let mut summary = store.fuzz_summary(run, top)?;
            summary["run"]["other_pid_namespace"] = json!(process::work_elsewhere(&store, &lock_name(run)));
            let live = matches!(summary["run"]["state"].as_str(), Some("running" | "paused" | "stopping"));
            let pid = summary["run"]["pid"].as_u64().filter(|_| live).map(|p| p as u32);
            if let Some(pid) =
                pid.filter(|&pid| process::work_liveness(&store, &lock_name(run), pid) == Liveness::Unverified)
            {
                summary["run"]["unverified"] = json!({
                    "reason": process::work_unverified_text("fuzz", run, pid),
                    "next": format!("brainproxy fuzz stop --forget {run}"),
                });
            }
            out.ok(summary.clone(), || text_summary(&summary));
            Ok(())
        }
        FuzzCmd::Results { run, matched, after, limit } => {
            let store = Store::open(project)?;
            store.fuzz_state(run)?;
            let r = store.query(
                "SELECT idx, position, payloads, status, length, words, lines, duration_ms, matched, grep, extract,
                    error, history_id
                 FROM fuzz_results WHERE run_id = ?1 AND (?2 = 0 OR matched = 1) AND idx > ?3 ORDER BY idx",
                &[run.to_string(), (matched as i32).to_string(), after.unwrap_or(-1).to_string()],
                limit,
                1000,
            )?;
            out.ok(json!(r), || {
                r.rows
                    .iter()
                    .map(|row| row.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\t"))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(())
        }
        FuzzCmd::List { limit } => {
            let store = Store::open(project)?;
            let r = store.query(
                "SELECT id, time, state, mode, target, total, done, matched, errors FROM fuzz_runs ORDER BY id DESC",
                &[],
                limit,
                500,
            )?;
            out.ok(json!(r), || {
                r.rows
                    .iter()
                    .map(|row| row.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\t"))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(())
        }
        FuzzCmd::Stop { run, forget: true } => {
            let store = Store::open(project)?;
            let state = store.fuzz_state(run)?;
            if !matches!(state.as_str(), "running" | "paused" | "stopping" | "queued") {
                return Err(Error::Conflict(format!("fuzz run {run} is {state}")));
            }
            let pid = store.fuzz_run(run)?["pid"].as_u64().map(|p| p as u32);
            if let Some(pid) =
                pid.filter(|&pid| process::work_liveness(&store, &lock_name(run), pid) == Liveness::Running)
            {
                return Err(Error::Conflict(format!(
                    "fuzz run {run} is running ({}), so it stays; use `brainproxy fuzz stop {run}`",
                    process::work_pid_text(&store, &lock_name(run), pid)
                )));
            }
            store.fuzz_set_state(run, "failed", None, Some("cleared with `fuzz stop --forget`"), true)?;
            process::forget_work_lock(&store, &lock_name(run));
            out.ok(json!({"run": run, "state": "failed", "forgotten": true}), || format!("marked run {run} failed"));
            Ok(())
        }
        FuzzCmd::Stop { run, forget: false } => {
            let store = Store::open(project)?;
            if !store.fuzz_transition(run, &["running", "paused", "queued"], "stopping")? {
                return Err(Error::Conflict(format!("fuzz run {run} is {}", store.fuzz_state(run)?)));
            }
            out.ok(json!({"run": run, "state": "stopping"}), || format!("stopping run {run}"));
            Ok(())
        }
        FuzzCmd::Pause { run } => {
            let store = Store::open(project)?;
            reap_if_dead(&store, run)?;
            if !store.fuzz_transition(run, &["running"], "paused")? {
                let state = store.fuzz_state(run)?;
                return Err(Error::Conflict(format!("fuzz run {run} is {state}; only a running run pauses")));
            }
            out.ok(json!({"run": run, "state": "paused"}), || format!("paused run {run}"));
            Ok(())
        }
        FuzzCmd::Resume { run } => resume(project, home, run, out),
    }
}

/// A fuzz run's lock file (see `process::work_lock`).
pub(crate) fn lock_name(run: i64) -> String {
    format!("fuzz-{run}")
}

/// Marks a run whose process died as failed.
fn reap_if_dead(store: &Store, run: i64) -> Result<(), Error> {
    let live = |s: &str| matches!(s, "running" | "paused" | "stopping");
    let info = store.fuzz_run(run)?;
    if !live(info["state"].as_str().unwrap_or("")) {
        return Ok(());
    }
    let Some(pid) = info["pid"].as_u64() else { return Ok(()) };
    let name = lock_name(run);
    // It may have finished, and exited, since the state above was read.
    if process::work_gone(store, &name, pid as u32) && live(&store.fuzz_state(run)?) {
        store.fuzz_set_state(run, "failed", None, Some("fuzz process exited unexpectedly"), true)?;
        process::forget_work_lock(store, &name);
    }
    Ok(())
}

fn text_summary(s: &Value) -> String {
    let run = &s["run"];
    let mut lines = vec![format!(
        "run {} [{}] {} {}/{} done, {} matched, {} errors",
        run["id"],
        run["state"].as_str().unwrap_or(""),
        run["mode"].as_str().unwrap_or(""),
        run["done"],
        run["total"],
        run["matched"],
        run["errors"]
    )];
    if let Some(b) = s["baseline"].as_object() {
        lines.push(format!("baseline: status {} words {} ({}x)", b["status"], b["words"], b["count"]));
    }
    for o in s["outliers"]["items"].as_array().into_iter().flatten() {
        lines.push(format!(
            "outlier idx {} payloads {} -> {} {}B {}w (history {})",
            o["idx"], o["payloads"], o["status"], o["length"], o["words"], o["history_id"]
        ));
    }
    for m in s["matches"].as_array().into_iter().flatten() {
        lines.push(format!(
            "match idx {} payloads {} -> {} grep {} extract {}",
            m["idx"], m["payloads"], m["status"], m["grep"], m["extract"]
        ));
    }
    lines.join("\n")
}

/// A payload source as it is loaded: through MCP a `file:PATH` names the file it resolves to
/// inside the project's folder, and one elsewhere is refused (see
/// [`crate::mcp::local_document`]), as each line goes on the wire and into history.
fn payload_source(project: &Path, spec: &str) -> Result<String, Error> {
    let Some(path) = fuzz::source_file(spec) else { return Ok(spec.to_string()) };
    let kind = &spec[..spec.len() - path.len()];
    Ok(format!(
        "{kind}{}",
        crate::mcp::local_file_arg(
            project,
            &format!("--payloads {kind}"),
            path,
            "pass the payloads on stdin (file:-), or use list:, range: or wordlist:",
        )?
    ))
}

fn run(project: &Path, home: &Path, mut args: RunArgs, out: &Out) -> Result<(), Error> {
    match args.store {
        StoreArg::All => {}
        StoreArg::Matches => crate::mcp::check_records_all("--store matches")?,
        StoreArg::None => crate::mcp::check_records_all("--store none")?,
    }
    let mode = Mode::parse(&args.mode)?;
    crate::request_args::check_rate("--rate", args.rate)?;
    let stdin_payloads = args.payloads.iter().filter(|p| *p == "file:-").count();
    if stdin_payloads > 1 || (stdin_payloads == 1 && args.req.reads_stdin()) {
        return Err(Error::InvalidInput(
            "only one input can come from stdin (request template or one payload set)".into(),
        ));
    }
    if args.background && stdin_payloads > 0 {
        return Err(Error::InvalidInput("--background can't read payloads from stdin; use files".into()));
    }
    // The caller's FILE, before a --background child's own request file takes its place.
    args.req.resolve_file(project)?;
    let mut payload_specs = Vec::with_capacity(args.payloads.len());
    for spec in &args.payloads {
        payload_specs.push(payload_source(project, spec)?);
    }
    if let Some(why) = args.resume.then(|| not_resumable(&payload_specs)).flatten() {
        return Err(Error::Conflict(format!("this run can't be resumed: {why}")));
    }
    // Recorded, so a resumed run can tell its sets are the ones it started with.
    let payload_sha256 = payload_hashes(&payload_specs, None)?;
    // A request read from stdin is handed to the --background child in a file.
    let stdin_request = args.background && args.req.reads_stdin();
    if let Some(path) = &args.attach_request {
        args.req.file = Some(path.clone());
    }
    let prepared = args.req.prepare(Some(&args.marker));
    if let Some(path) = &args.attach_request {
        let _ = std::fs::remove_file(path);
    }
    let (req, target) = prepared?;
    let guard = crate::project_guard(project)?;
    crate::require_in_scope(&guard, &target)?;
    let opts = args.req.send_options(guard.clone())?;
    // So is a server name the scope doesn't list, before a row could say it was sent.
    opts.check_sni(&target)?;
    // And, through MCP, a Host the scope doesn't list unless it is a stated Host-header test. A
    // payload position in the Host is one: its marker, shown as the default's, is never a host.
    let marked = String::from_utf8_lossy(req.as_bytes()).replace(&args.marker, fuzz::DEFAULT_MARKER);
    let mut host_warning =
        crate::mcp::check_host_header(&opts, marked.as_bytes(), &target, args.req.host_header_test, out)?;
    // Every request is checked again as it goes out, payloads in: one that names another host
    // (a payload in a header's name that makes it a Host, say) is refused there through MCP.
    let head = String::from_utf8_lossy(brainproxy_core::http::request::split_head_body(marked.as_bytes()).0);
    let template = Template::parse(req.as_bytes(), &args.marker)?;
    // How many positions are in the head (they come first), and whether payloads there are
    // URL-encoded: a raw CR or LF there would start another header line (a Host, say).
    let head_positions = head.matches(fuzz::DEFAULT_MARKER).count() / 2;
    let encode = !args.no_encode && !args.req.verbatim;
    let raw_in_head = template.url_positions().iter().take(head_positions).any(|url| !(encode && *url));

    let mut stdin = || crate::read_input(None);
    let mut sets = Vec::new();
    // OOB tokens put in payloads (set and payload, from 1), registered once the run has an id.
    let mut oob_tokens: Vec<(usize, usize, String)> = Vec::new();
    // The scripts that made sets, as they were read: the run's record says what made them.
    let mut payload_scripts = Vec::new();
    for (i, spec) in payload_specs.iter().enumerate() {
        let set = match spec.split_once(':') {
            Some(("oob", arg)) => {
                let (n, form) = fuzz::parse_oob(arg)?;
                let state = crate::oob_cmd::running(&Store::open(project)?)?.ok_or_else(|| {
                    Error::NotFound(
                        "an oob: payload set needs this project's OOB listener (start one with `brainproxy oob start`)"
                            .into(),
                    )
                })?;
                let endpoint = state.endpoint.for_target(&target.host, target.port);
                let mut payloads = Vec::new();
                for k in 0..n as usize {
                    let p = endpoint.payload()?;
                    payloads.push(match form {
                        fuzz::OobForm::Host => p.host.into_bytes(),
                        fuzz::OobForm::Url => p.url.into_bytes(),
                    });
                    oob_tokens.push((i + 1, k + 1, p.token));
                }
                fuzz::Set::List(payloads)
            }
            Some(("script", file)) => {
                // Before the file is so much as read: a script is a person's to name.
                crate::mcp::check_script("--payloads script:FILE")?;
                // A set for one position is told that position and its value in the template.
                let position = match mode {
                    Mode::Pitchfork | Mode::ClusterBomb => Some(i),
                    _ => (template.positions() == 1).then_some(0),
                };
                let default = position.and_then(|p| template.defaults().get(p)).map(Vec::as_slice);
                let (script, set) = fuzz::script_set(file, i + 1, position, default)?;
                payload_scripts.push(script);
                set
            }
            _ => fuzz::load_payloads(spec, &mut stdin)?,
        };
        sets.push(set);
    }
    // The scripts the chains name, as they were read: the run's record says what processed it.
    let mut scripts = Vec::new();
    for chain in &args.process {
        let (which, chain) =
            match chain.split_once('=').filter(|(n, _)| n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty()) {
                Some((n, c)) => (Some(n.parse::<usize>().unwrap_or(0)), c),
                None => (None, chain.as_str()),
            };
        // Before the file is so much as read: a script is a person's to name.
        if fuzz::names_script(chain) {
            crate::mcp::check_script("--process script:FILE")?;
        }
        let chain = fuzz::Chain::parse(chain)?;
        scripts.extend(chain.scripts().into_iter().cloned());
        if let Some(n) = which.filter(|n| *n == 0 || *n > args.payloads.len()) {
            return Err(Error::InvalidInput(format!("--process {n}=...: there is no payload set {n}")));
        }
        for (i, set) in sets.iter_mut().enumerate() {
            // A chain for every set passes over copies, which are another position's value as sent.
            if which.is_none_or(|n| n == i + 1) && !(which.is_none() && matches!(set, fuzz::Set::Copy(_))) {
                chain.apply_set(i + 1, set)?;
            }
        }
    }
    // A raw line break in the head is a CRLF-injection test a person may run; it can also start a
    // Host header, so through MCP it needs --host-header-test as a foreign Host does.
    if raw_in_head && sets.iter().any(fuzz::Set::may_break_line) && host_warning.is_none() {
        let what = "(a payload with a line break, unencoded in the head)".to_string();
        host_warning = crate::mcp::check_host_setting("fuzz run", Some(what), args.req.host_header_test, out)?;
    }
    let plan = Plan::new(mode, &template, sets)?;
    if !plan.bounded() && args.max_requests.is_none() {
        return Err(Error::InvalidInput(
            "every payload set is extract:, so the run has no end of its own; give --max-requests".into(),
        ));
    }
    if plan.feedback() && args.extract.is_none() {
        return Err(Error::InvalidInput(
            "an extract: set sends what --extract captured from the previous response; give --extract REGEX".into(),
        ));
    }
    // Each response feeds the next request, so they go one at a time; the record says so.
    let concurrency = if plan.feedback() { 1 } else { args.concurrency.clamp(1, 1000) };
    let total = args.max_requests.map_or(plan.total(), |m| m.min(plan.total()));

    let mut config = json!({
        "mode": args.mode,
        "payloads": args.payloads,
        "process": args.process,
        "marker": args.marker,
        "concurrency": concurrency,
        "rate": args.rate,
        "grep": args.grep,
        "extract": args.extract,
        "match_status": args.match_status,
        "stop_on_match": args.stop_on_match,
        "store": match args.store { StoreArg::All => "all", StoreArg::Matches => "matches", StoreArg::None => "none" },
        // What `fuzz resume` needs to start the run again as it was.
        "max_requests": args.max_requests,
        "auth": args.auth,
        "no_encode": args.no_encode,
        "send": {
            "timeout": args.req.timeout,
            "verify_tls": args.req.verify_tls,
            "sni": args.req.sni,
            "http2": args.req.http2,
            "http3": args.req.http3,
            "host_header_test": args.req.host_header_test,
            "verbatim": args.req.verbatim,
        },
        "payload_sha256": payload_sha256,
        "cwd": std::env::current_dir().ok().and_then(|d| d.to_str().map(String::from)),
    });
    if !scripts.is_empty() {
        config["process_scripts"] = json!(scripts);
    }
    if !payload_scripts.is_empty() {
        config["payload_scripts"] = json!(payload_scripts);
    }
    // Through MCP a file: source names the file it resolved to: a resume reads that one.
    if payload_specs != args.payloads {
        config["payload_sources"] = json!(payload_specs);
    }
    if plan.feedback() {
        config["note"] = json!(
            "an extract: set sends what --extract captured from each response in the next request, so requests go \
             one at a time"
        );
    }
    let store = Store::open(project)?;
    let feedback = plan.feedback();
    // A resumed run sends what it has no results for, from sets that are still the ones it had.
    let (skip, last_extract) = match args.attach_run.filter(|_| args.resume) {
        Some(id) => {
            let was = store.fuzz_run(id)?["config"].clone();
            check_hashes(id, &payload_sha256, &was)?;
            if json!(scripts) != was["process_scripts"] && !(scripts.is_empty() && was["process_scripts"].is_null()) {
                return Err(Error::Conflict(format!(
                    "fuzz run {id} can't be resumed: its --process scripts changed since it started"
                )));
            }
            let last = if feedback { store.fuzz_last_extract(id)? } else { None };
            (store.fuzz_done_indexes(id)?, last)
        }
        None => Default::default(),
    };

    if args.background {
        let run_id = store.fuzz_create(
            "queued",
            &args.mode,
            &target.origin(),
            template.positions(),
            total,
            &config,
            req.as_bytes(),
        )?;
        let request = stdin_request.then(|| req.as_bytes());
        return spawn_background(project, home, run_id, request, &store, host_warning, out);
    }

    let run_id = match args.attach_run {
        Some(id) => id,
        None => store.fuzz_create(
            "running",
            &args.mode,
            &target.origin(),
            template.positions(),
            total,
            &config,
            req.as_bytes(),
        )?,
    };
    // A foreground run; a `--background` child already has its parent's.
    let name = lock_name(run_id);
    let _lock = process::work_lock(&store, &name);
    store.fuzz_set_state(run_id, "running", Some(std::process::id()), None, false)?;
    let finish = |state: &str, error: Option<&str>| {
        store.fuzz_set_state(run_id, state, None, error, true)?;
        process::forget_work_lock(&store, &name);
        Ok::<_, Error>(())
    };
    // Registered by the process that sends them (a --background parent's are never sent), with
    // the run's id, so an interaction says which run and payload called back.
    for (set, k, token) in &oob_tokens {
        if let Err(e) = store.oob_add_fuzz_payload(token, &format!("fuzz run {run_id}, set {set} payload {k}"), &target)
        {
            finish("failed", Some(&e.to_string()))?;
            return Err(e);
        }
    }

    let send = args.req.send_options(guard)?;
    let auth = match crate::auth_cmd::maybe_session(project, args.auth.as_deref(), &send) {
        Ok(a) => a,
        Err(e) => {
            finish("failed", Some(&e.to_string()))?;
            return Err(e);
        }
    };
    let client = brainproxy_core::http::Client::new(send.clone());
    let engine_cfg = EngineConfig {
        concurrency,
        rate: args.rate,
        send,
        grep: args.grep.clone(),
        extract: args.extract.clone(),
        match_status: args.match_status.clone(),
        stop_on_match: args.stop_on_match,
        store: match args.store {
            StoreArg::All => StoreMode::All,
            StoreArg::Matches => StoreMode::Matches,
            StoreArg::None => StoreMode::None,
        },
        update_content_length: !args.req.verbatim,
        encode_payloads: !args.no_encode && !args.req.verbatim,
        max_requests: args.max_requests,
        auth: auth.clone(),
        client: Some(client.clone()),
        last_extract,
        skip,
    };
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let started = Instant::now();
    let result = rt.block_on(fuzz::run(project, run_id, template, plan, target, engine_cfg));
    if let Some(a) = &auth {
        a.save()?;
    }
    match result {
        Ok(outcome) => {
            finish(if outcome == Outcome::Stopped { "stopped" } else { "completed" }, None)?;
            let mut summary = store.fuzz_summary(run_id, args.top)?;
            summary["outcome"] = json!(outcome);
            summary["elapsed_ms"] = json!(started.elapsed().as_millis() as u64);
            if let Some(w) = host_warning {
                summary["host_warning"] = json!(w);
            }
            let notes = crate::mcp::h3_notes([&client], out);
            if !notes.is_empty() {
                summary["http3_notes"] = json!(notes);
            }
            out.ok(summary.clone(), || text_summary(&summary));
            Ok(())
        }
        Err(e) => {
            finish("failed", Some(&e.to_string()))?;
            Err(e)
        }
    }
}

fn spawn_background(
    project: &Path,
    home: &Path,
    run_id: i64,
    request: Option<&[u8]>,
    store: &Store,
    host_warning: Option<String>,
    out: &Out,
) -> Result<(), Error> {
    let mut options = vec!["--attach-run".to_string(), run_id.to_string()];
    if let Some(bytes) = request {
        options.push(format!("--attach-request={}", request_file(project, run_id, bytes)?.display()));
    }
    let argv = crate::jobs_cmd::with_options(crate::jobs_cmd::child_args(), options);
    let log = start_child(project, home, run_id, &argv, None, store)?;
    let info = store.fuzz_run(run_id)?;
    let mut data = json!({
        "run": info,
        "log": log,
        "next": format!("brainproxy fuzz status {run_id}   (or: fuzz stop {run_id})"),
    });
    if let Some(w) = host_warning {
        data["host_warning"] = json!(w);
    }
    out.ok(data, || format!("fuzz run {run_id} started in the background"));
    Ok(())
}

/// Writes a request for a child to read (and delete) with --attach-request.
fn request_file(project: &Path, run_id: i64, bytes: &[u8]) -> Result<std::path::PathBuf, Error> {
    let path = std::fs::canonicalize(project)?.with_extension(format!("fuzz-{run_id}.req"));
    std::io::Write::write_all(&mut process::private_file(&path, false)?, bytes)?;
    Ok(path)
}

/// Starts the process that runs a queued run, `brainproxy <argv>` in `cwd` (this one's by
/// default), and waits for it to take the run up. Returns its log file.
fn start_child(
    project: &Path,
    home: &Path,
    run_id: i64,
    argv: &[String],
    cwd: Option<&Path>,
    store: &Store,
) -> Result<std::path::PathBuf, Error> {
    let project = std::fs::canonicalize(project)?;
    let log = project.with_extension(format!("fuzz-{run_id}.log"));
    let log_file = process::private_file(&log, true)?;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg("--project").arg(&project).arg("--home").arg(home).args(["--format", "json"]).args(argv);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    brainproxy_core::provenance::pass_on(&mut cmd);
    process::detach(&mut cmd);
    let stdin = process::work_lock_stdin(store, &lock_name(run_id));
    let mut child =
        cmd.stdin(stdin).stdout(Stdio::from(log_file.try_clone()?)).stderr(Stdio::from(log_file)).spawn()?;
    // Our copy of the lock goes with it: the child's is the one that counts.
    drop(cmd);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state = store.fuzz_state(run_id)?;
        if state != "queued" {
            break;
        }
        if let Some(status) = child.try_wait()? {
            let msg = std::fs::read_to_string(&log).unwrap_or_default();
            store.fuzz_set_state(run_id, "failed", None, Some(msg.trim()), true)?;
            process::forget_work_lock(store, &lock_name(run_id));
            return Err(crate::jobs_cmd::child_failure("fuzz process", status, &msg));
        }
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(log)
}

/// Why a run with these payload sources can't be relaunched, if it can't.
fn not_resumable(specs: &[String]) -> Option<String> {
    specs.iter().enumerate().find_map(|(i, spec)| {
        let n = i + 1;
        match spec.split_once(':').map(|(kind, _)| kind) {
            _ if spec == "file:-" => Some(format!("payload set {n} was read from stdin, which can't be read again")),
            Some("oob") => Some(format!(
                "payload set {n} is OOB tokens, each tied to the request that carried it; new tokens would be other \
                 payloads"
            )),
            Some("script") => Some(format!(
                "payload set {n} was made by a script, which needn't make the same set again (index for index)"
            )),
            _ => None,
        }
    })
}

/// The SHA-256 of each payload file the sources read, by set number (from 1). A relative path
/// is taken from `cwd` when given.
fn payload_hashes(specs: &[String], cwd: Option<&Path>) -> Result<serde_json::Map<String, Value>, Error> {
    let mut out = serde_json::Map::new();
    for (i, spec) in specs.iter().enumerate() {
        let Some(path) = fuzz::source_file(spec) else { continue };
        let path = cwd.map_or_else(|| Path::new(path).to_path_buf(), |dir| dir.join(path));
        let data =
            std::fs::read(&path).map_err(|e| Error::InvalidInput(format!("payload file {}: {e}", path.display())))?;
        out.insert((i + 1).to_string(), json!(brainproxy_core::fetch::sha256_hex(&data)));
    }
    Ok(out)
}

/// Refuses to resume run `run` when a payload file's hash isn't the one recorded at its start:
/// the set would be another, and its indexes other payloads.
fn check_hashes(run: i64, now: &serde_json::Map<String, Value>, config: &Value) -> Result<(), Error> {
    for (set, was) in config["payload_sha256"].as_object().into_iter().flatten() {
        if now.get(set) != Some(was) {
            return Err(Error::Conflict(format!(
                "fuzz run {run} can't be resumed: the file of payload set {set} changed since the run started"
            )));
        }
    }
    Ok(())
}

/// `fuzz resume`: lets a paused run go on, or relaunches a stopped or failed one.
fn resume(project: &Path, home: &Path, run: i64, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    reap_if_dead(&store, run)?;
    let info = store.fuzz_run(run)?;
    let state = info["state"].as_str().unwrap_or("").to_string();
    if state == "paused" {
        if !store.fuzz_transition(run, &["paused"], "running")? {
            return Err(Error::Conflict(format!("fuzz run {run} is {}", store.fuzz_state(run)?)));
        }
        out.ok(json!({"run": run, "state": "running"}), || format!("resumed run {run}"));
        return Ok(());
    }
    if state != "stopped" && state != "failed" {
        return Err(Error::Conflict(format!(
            "fuzz run {run} is {state}; a paused, stopped or failed run can be resumed"
        )));
    }
    let config = &info["config"];
    let Some(cwd) = config["cwd"].as_str() else {
        return Err(Error::Conflict(format!(
            "fuzz run {run} was started by an earlier brainproxy, which didn't record what resuming it needs"
        )));
    };
    let strings = |key: &str| -> Vec<String> {
        config[key].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect()
    };
    // The files the run read, as they resolved when it started (through MCP, in the project's folder).
    let payloads = match strings("payload_sources") {
        sources if sources.is_empty() => strings("payloads"),
        sources => sources,
    };
    if let Some(why) = not_resumable(&payloads) {
        return Err(Error::Conflict(format!("fuzz run {run} can't be resumed: {why}")));
    }
    // What the relaunched run does is checked as when it started, through MCP as well.
    if config["process_scripts"].as_array().is_some_and(|s| !s.is_empty()) {
        crate::mcp::check_script("resuming a run whose --process runs a script")?;
    }
    if config["store"] != "all" {
        let store_mode = config["store"].as_str().unwrap_or("");
        crate::mcp::check_records_all(&format!("resuming a run with --store {store_mode}"))?;
    }
    let mut resolved = Vec::new();
    for spec in &payloads {
        resolved.push(payload_source(project, spec)?);
    }
    check_hashes(run, &payload_hashes(&resolved, Some(Path::new(cwd)))?, config)?;

    let mut argv: Vec<String> = ["fuzz", "run", "--resume", "--attach-run"].map(String::from).to_vec();
    argv.push(run.to_string());
    let text = |v: &Value| v.as_str().map(String::from).unwrap_or_else(|| v.to_string());
    let mut flag = |name: &str, v: &Value| {
        if !v.is_null() && *v != false {
            argv.push(if *v == true { format!("--{name}") } else { format!("--{name}={}", text(v)) });
        }
    };
    flag("target", &info["target"]);
    for key in ["mode", "marker", "concurrency", "rate", "max_requests", "auth", "extract", "store"] {
        flag(&key.replace('_', "-"), &config[key]);
    }
    for key in ["stop_on_match", "no_encode"] {
        flag(&key.replace('_', "-"), &config[key]);
    }
    for spec in &payloads {
        flag("payloads", &json!(spec));
    }
    for key in ["process", "grep"] {
        for v in config[key].as_array().into_iter().flatten() {
            flag(key, v);
        }
    }
    let statuses: Vec<String> = config["match_status"].as_array().into_iter().flatten().map(text).collect();
    if !statuses.is_empty() {
        flag("match-status", &json!(statuses.join(",")));
    }
    for (key, v) in config["send"].as_object().into_iter().flatten() {
        flag(&key.replace('_', "-"), v);
    }

    let (done, total) = (info["done"].as_u64().unwrap_or(0), info["total"].as_u64().unwrap_or(0));
    if !store.fuzz_requeue(run)? {
        return Err(Error::Conflict(format!("fuzz run {run} is {}", store.fuzz_state(run)?)));
    }
    let started = request_file(project, run, &store.fuzz_template(run)?).and_then(|path| {
        argv.push(format!("--attach-request={}", path.display()));
        start_child(project, home, run, &argv, Some(Path::new(cwd)).filter(|d| d.is_dir()), &store)
    });
    let log = match started {
        Ok(log) => log,
        Err(e) => {
            // Back as it was, so it can be resumed once what failed is put right.
            store.fuzz_set_state(run, "failed", None, Some(&e.to_string()), true)?;
            return Err(e);
        }
    };
    let state = store.fuzz_state(run)?;
    let remaining = total.saturating_sub(done);
    out.ok(json!({"run": run, "state": state, "resumed_from": done, "remaining": remaining, "log": log}), || {
        format!("resumed run {run} in the background: {remaining} of {total} requests left")
    });
    Ok(())
}

pub fn diff_cmd(project: &Path, args: DiffArgs, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    let part = |id: i64| -> Result<Vec<u8>, Error> {
        let item = store.get(id)?;
        Ok(match args.part {
            DiffPart::Request => item.request,
            DiffPart::Response => item.response,
            DiffPart::ResponseBody => item.resp_body.unwrap_or_default(),
        })
    };
    let (a, b) = (part(args.a)?, part(args.b)?);
    let mode = match args.mode {
        DiffModeArg::Lines => DiffMode::Lines,
        DiffModeArg::Words => DiffMode::Words,
        DiffModeArg::Bytes => DiffMode::Bytes,
    };
    let d = diff(&a, &b, mode, args.max_changes, args.context);
    let mut data = json!(d);
    data["a"] = json!({"id": args.a, "length": a.len()});
    data["b"] = json!({"id": args.b, "length": b.len()});
    out.ok(data, || match &d.unified {
        Some(u) => u.clone(),
        None if d.identical => "identical".into(),
        None => d
            .changes
            .iter()
            .map(|c| format!("{} {:?}", if c.op == "delete" { "-" } else { "+" }, c.text))
            .collect::<Vec<_>>()
            .join("\n"),
    });
    Ok(())
}

#[derive(Subcommand)]
pub enum WordlistsCmd {
    /// The built-in lists: name, description, caution, entry count, source, and license.
    List,
    /// Print a list's entries.
    Show {
        name: String,
        /// One entry per line, no envelope.
        #[arg(long)]
        raw: bool,
        /// Maximum entries in JSON output (0 = all).
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
}

pub fn wordlists(cmd: WordlistsCmd, out: &Out) -> Result<(), Error> {
    use brainproxy_core::wordlists;
    let manifest = wordlists::manifest();
    let describe = |name: &str| {
        let l = &manifest["lists"][name];
        let sources: Vec<Value> = l["sources"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|s| {
                let src = &manifest["sources"][s["source"].as_str().unwrap_or_default()];
                json!({"repo": src["repo"], "path": s["path"], "commit": src["commit"], "license": src["license"]})
            })
            .collect();
        json!({
            "name": name,
            "payload": format!("wordlist:{name}"),
            "description": l["description"],
            "caution": l["caution"],
            "count": l["count"],
            "sources": sources,
        })
    };
    match cmd {
        WordlistsCmd::List => {
            let lists: Vec<Value> = wordlists::names().map(describe).collect();
            out.ok(json!({"lists": lists, "hint": "Use as a payload source: fuzz run -p wordlist:NAME"}), || {
                lists
                    .iter()
                    .map(|l| {
                        format!(
                            "{:<18} {:>6}  {}",
                            l["name"].as_str().unwrap_or(""),
                            l["count"],
                            l["description"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        WordlistsCmd::Show { name, raw, limit } => {
            let entries: Vec<&str> = wordlists::get(&name)
                .ok_or_else(|| Error::NotFound(format!("wordlist {name:?}; see `brainproxy wordlists list`")))?
                .collect();
            if raw {
                out.raw(format!("{}\n", entries.join("\n")).as_bytes());
                return Ok(());
            }
            let shown = if limit == 0 { entries.len() } else { limit.min(entries.len()) };
            let mut data = describe(&name);
            data["entries"] = json!(&entries[..shown]);
            data["truncated"] = json!(shown < entries.len());
            out.ok(data, || entries.join("\n"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_with_sets_that_cant_be_made_again_dont_resume() {
        let why = |specs: &[&str]| not_resumable(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(why(&["list:a", "file:/w.txt", "brute:ab:1-3", "extract", "copy:1"]), None);
        assert!(why(&["list:a", "file:-"]).unwrap().starts_with("payload set 2 was read from stdin"));
        assert!(why(&["oob:3"]).unwrap().contains("OOB tokens"));
        assert!(why(&["list:a", "script:gen.js"]).unwrap().contains("made by a script"));
    }
}
