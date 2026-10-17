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
use crate::request_args::RequestArgs;

#[derive(Subcommand)]
pub enum FuzzCmd {
    /// Run an attack. Mark payload positions in the request with §value§.
    #[command(after_help = "Modes: sniper (1 set; each position in turn), battering-ram (1 set; same payload \
        everywhere), pitchfork (1 set per position, in step), cluster-bomb (1 set per position, every combination).\n\
        Payload sources (-p, one per set, in position order): list:a,b,c | file:PATH | file:- | range:1-100[:step].\n\
        Processing (--process, applied left to right): url, url-all, base64, base64url, hex, html, md5, sha1, sha256, \
        sha512, upper, lower, prefix:TEXT, suffix:TEXT. Prefix with N= to apply to set N only (e.g. 2=base64).\n\
        Results: the summary lists the baseline response shape, outliers (rare status+word-count shapes), and \
        matches. All results are in the fuzz_results table.")]
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
    /// Ask a running attack to stop (it finishes in-flight requests).
    Stop { run: i64 },
}

#[derive(clap::Args)]
pub struct RunArgs {
    #[command(flatten)]
    req: RequestArgs,

    #[arg(long, default_value = "sniper", value_parser = Mode::ALL.to_vec())]
    mode: String,
    /// Payload source for the next set (repeat for pitchfork/cluster-bomb).
    #[arg(short = 'p', long = "payloads", required = true)]
    payloads: Vec<String>,
    /// Processing chain for payloads, e.g. "url" or "2=prefix:admin,base64". Repeatable.
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
    /// Which exchanges go into history (results always go into fuzz_results).
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
            let summary = store.fuzz_summary(run, top)?;
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
        FuzzCmd::Stop { run } => {
            let store = Store::open(project)?;
            let state = store.fuzz_state(run)?;
            if state != "running" && state != "queued" {
                return Err(Error::Conflict(format!("fuzz run {run} is {state}")));
            }
            store.fuzz_set_state(run, "stopping", None, None, false)?;
            out.ok(json!({"run": run, "state": "stopping"}), || format!("stopping run {run}"));
            Ok(())
        }
    }
}

/// Marks a run whose process died as failed.
fn reap_if_dead(store: &Store, run: i64) -> Result<(), Error> {
    let info = store.fuzz_run(run)?;
    let state = info["state"].as_str().unwrap_or("");
    if matches!(state, "running" | "stopping") {
        if let Some(pid) = info["pid"].as_u64() {
            if !crate::proxy_cmd::alive(pid as u32) {
                store.fuzz_set_state(run, "failed", None, Some("fuzz process exited unexpectedly"), true)?;
            }
        }
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

fn run(project: &Path, home: &Path, args: RunArgs, out: &Out) -> Result<(), Error> {
    let mode = Mode::parse(&args.mode)?;
    let stdin_payloads = args.payloads.iter().filter(|p| *p == "file:-").count();
    if stdin_payloads > 1 || (stdin_payloads == 1 && args.req.reads_stdin()) {
        return Err(Error::InvalidInput(
            "only one input can come from stdin (request template or one payload set)".into(),
        ));
    }
    if args.background && (stdin_payloads > 0 || args.req.reads_stdin()) {
        return Err(Error::InvalidInput("--background can't read stdin; use files".into()));
    }

    let (req, target) = args.req.prepare(Some(&args.marker))?;
    let guard = crate::project_guard(project)?;
    crate::require_in_scope(&guard, &target)?;
    let template = Template::parse(req.as_bytes(), &args.marker)?;

    let mut stdin = || crate::read_input(None);
    let mut sets = Vec::new();
    for spec in &args.payloads {
        sets.push(fuzz::load_payloads(spec, &mut stdin)?);
    }
    for chain in &args.process {
        let (which, chain) =
            match chain.split_once('=').filter(|(n, _)| n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty()) {
                Some((n, c)) => (Some(n.parse::<usize>().unwrap_or(0)), c),
                None => (None, chain.as_str()),
            };
        for (i, set) in sets.iter_mut().enumerate() {
            if which.is_none_or(|n| n == i + 1) {
                for p in set.iter_mut() {
                    *p = fuzz::process(chain, p)?;
                }
            }
        }
        if let Some(n) = which.filter(|n| *n == 0 || *n > args.payloads.len()) {
            return Err(Error::InvalidInput(format!("--process {n}=...: there is no payload set {n}")));
        }
    }
    let plan = Plan::new(mode, &template, sets)?;
    let total = args.max_requests.map_or(plan.total(), |m| m.min(plan.total()));

    let config = json!({
        "mode": args.mode,
        "payloads": args.payloads,
        "process": args.process,
        "marker": args.marker,
        "concurrency": args.concurrency,
        "rate": args.rate,
        "grep": args.grep,
        "extract": args.extract,
        "match_status": args.match_status,
        "stop_on_match": args.stop_on_match,
        "store": match args.store { StoreArg::All => "all", StoreArg::Matches => "matches", StoreArg::None => "none" },
    });
    let store = Store::open(project)?;

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
        return spawn_background(project, home, run_id, &store, out);
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
    store.fuzz_set_state(run_id, "running", Some(std::process::id()), None, false)?;

    let send = args.req.send_options(guard);
    let auth = match crate::auth_cmd::maybe_session(project, args.auth.as_deref(), &send) {
        Ok(a) => a,
        Err(e) => {
            store.fuzz_set_state(run_id, "failed", None, Some(&e.to_string()), true)?;
            return Err(e);
        }
    };
    let engine_cfg = EngineConfig {
        concurrency: args.concurrency.clamp(1, 1000),
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
        max_requests: args.max_requests,
        auth: auth.clone(),
    };
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let started = Instant::now();
    let result = rt.block_on(fuzz::run(project, run_id, template, plan, target, engine_cfg));
    if let Some(a) = &auth {
        a.save()?;
    }
    match result {
        Ok(outcome) => {
            let state = if outcome == Outcome::Stopped { "stopped" } else { "completed" };
            store.fuzz_set_state(run_id, state, None, None, true)?;
            let mut summary = store.fuzz_summary(run_id, args.top)?;
            summary["outcome"] = json!(outcome);
            summary["elapsed_ms"] = json!(started.elapsed().as_millis() as u64);
            out.ok(summary.clone(), || text_summary(&summary));
            Ok(())
        }
        Err(e) => {
            store.fuzz_set_state(run_id, "failed", None, Some(&e.to_string()), true)?;
            Err(e)
        }
    }
}

fn spawn_background(project: &Path, home: &Path, run_id: i64, store: &Store, out: &Out) -> Result<(), Error> {
    let project = std::fs::canonicalize(project)?;
    let log = project.with_extension(format!("fuzz-{run_id}.log"));
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    let argv = crate::jobs_cmd::child_args();
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg("--project").arg(&project).arg("--home").arg(home).args(["--format", "json"]).args(&argv);
    cmd.arg("--attach-run").arg(run_id.to_string());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::from(log_file.try_clone()?)).stderr(Stdio::from(log_file)).spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state = store.fuzz_state(run_id)?;
        if state != "queued" {
            break;
        }
        if let Some(status) = child.try_wait()? {
            let msg = std::fs::read_to_string(&log).unwrap_or_default();
            store.fuzz_set_state(run_id, "failed", None, Some(msg.trim()), true)?;
            return Err(Error::InvalidInput(format!("fuzz process exited ({status}): {}", msg.trim())));
        }
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let info = store.fuzz_run(run_id)?;
    let data = json!({
        "run": info,
        "log": log,
        "next": format!("brainproxy fuzz status {run_id}   (or: fuzz stop {run_id})"),
    });
    out.ok(data, || format!("fuzz run {run_id} started in the background"));
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
