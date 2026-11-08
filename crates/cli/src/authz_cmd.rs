//! `authz`: access-control testing. Recorded requests are sent again as other identities
//! (auth profiles) and without a session, and each response is compared with the
//! owner's.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use brainproxy_core::apiimport::api;
use brainproxy_core::auth::{AuthProfile, AuthSession};
use brainproxy_core::authz::{self, AuthzConfig, AuthzTarget, ANONYMOUS, DEFAULT_EXCLUDE, SAFE_METHODS};
use brainproxy_core::http::{Client, RawRequest, SendOptions, Target};
use brainproxy_core::jobs::is_finished;
use brainproxy_core::scan::Message;
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};

use crate::output::Out;

#[derive(Subcommand)]
pub enum AuthzCmd {
    /// Send recorded requests again as other identities and without a session, and
    /// compare each response with the owner's (broken access control, IDOR).
    #[command(after_help = "Each request is re-sent as the identity that made it (twice: what changes between \
        the two is ignored), then without credentials, then as every --as identity. Verdicts: enforced \
        (refused), bypass (the owner's data came back), public (also without a session), different (e.g. the \
        identity's own data), inconclusive (nothing to compare: an empty body, or HEAD or OPTIONS). Bypasses of medium or high confidence are also findings (source authz). The \
        owner is found from the auth placeholders or session values in the request; --owner sets it. Only \
        GET, HEAD and OPTIONS requests that carry credentials are picked from history unless \
        --include-methods or --history-id says otherwise; a GraphQL mutation needs MUTATION as well as its method.")]
    Run(Box<RunArgs>),
    /// Result rows of a run: one per request and identity.
    Results {
        /// Run id (from `authz run` or `authz list`).
        run: i64,
        #[arg(long, value_enum)]
        verdict: Option<VerdictArg>,
        /// Only rows for this identity (an auth profile or `anonymous`).
        #[arg(long)]
        identity: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// A run as a table: one row per request, one cell per identity.
    Matrix {
        /// Run id.
        run: i64,
        /// Maximum requests.
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Recent runs with their verdict counts.
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum VerdictArg {
    Baseline,
    Enforced,
    Bypass,
    Public,
    Different,
    Inconclusive,
    Error,
    Skipped,
}

impl VerdictArg {
    fn as_str(self) -> &'static str {
        match self {
            VerdictArg::Baseline => "baseline",
            VerdictArg::Enforced => "enforced",
            VerdictArg::Bypass => "bypass",
            VerdictArg::Public => "public",
            VerdictArg::Different => "different",
            VerdictArg::Inconclusive => "inconclusive",
            VerdictArg::Error => "error",
            VerdictArg::Skipped => "skipped",
        }
    }
}

#[derive(clap::Args)]
pub struct RunArgs {
    /// URLs to test with GET (needs --owner). Without URLs, --history-id, --where or --tag,
    /// every proxied/sent/crawled/imported request in history that carries credentials.
    urls: Vec<String>,
    /// Auth profile to send each request as. Repeatable or comma-separated.
    #[arg(long = "as", value_name = "NAME", value_delimiter = ',')]
    identities: Vec<String>,
    /// Auth profile that made the requests (the baseline). Default: worked out per
    /// request; requests whose owner isn't known are re-sent with their own credentials.
    #[arg(long, value_name = "NAME")]
    owner: Option<String>,
    /// Don't send the requests without credentials (the anonymous control).
    #[arg(long)]
    no_anonymous: bool,
    /// History entry to test, also without credentials. Its method needs --include-methods
    /// unless GET, HEAD or OPTIONS, and a path matching --exclude is refused. Repeatable.
    #[arg(long = "history-id")]
    history_ids: Vec<i64>,
    /// SQL condition selecting history rows, e.g. "host = 'app.test' AND path LIKE '/api/%'".
    #[arg(long = "where")]
    where_sql: Option<String>,
    /// Only history rows with this tag.
    #[arg(long)]
    tag: Option<String>,
    /// Also replay requests from history with these methods (comma-separated, or `all`).
    /// They may change data, now as another user. GraphQL mutations are MUTATION, whatever
    /// their method.
    #[arg(long, value_delimiter = ',', value_name = "METHODS")]
    include_methods: Vec<String>,
    /// Regex on the path of requests from history not to replay.
    #[arg(long, default_value = DEFAULT_EXCLUDE)]
    exclude: String,
    /// Cookie that isn't a credential and stays on the request (e.g. a locale). Repeatable
    /// or comma-separated. Every other cookie is removed before sending as another identity.
    #[arg(long = "keep-cookie", value_delimiter = ',', value_name = "NAME")]
    keep_cookies: Vec<String>,
    /// Maximum distinct requests.
    #[arg(long, default_value_t = 200)]
    max_requests: usize,
    /// Requests tested at once.
    #[arg(short = 'c', long, default_value_t = 5)]
    concurrency: usize,
    /// Maximum requests per second.
    #[arg(long)]
    rate: Option<f64>,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    #[arg(long)]
    verify_tls: bool,
    /// Send over HTTP/2 (ALPN h2 for https, prior knowledge for http).
    #[arg(long)]
    http2: bool,
    /// Run detached; returns a run id for `job wait|status|stop` and `authz results`.
    #[arg(long)]
    background: bool,
    #[arg(long, hide = true)]
    job_id: Option<i64>,
}

pub fn authz(project: &Path, home: &Path, cmd: AuthzCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        AuthzCmd::Run(args) => run(project, home, *args, out),
        AuthzCmd::Results { run, verdict, identity, limit } => {
            let store = Store::open(project)?;
            require_run(&store, run)?;
            let rows = store.authz_results(run, verdict.map(VerdictArg::as_str), identity.as_deref(), limit)?;
            out.ok(json!({"run_id": run, "results": rows}), || {
                rows.iter().map(result_line).collect::<Vec<_>>().join("\n")
            });
            Ok(())
        }
        AuthzCmd::Matrix { run, limit } => {
            let store = Store::open(project)?;
            require_run(&store, run)?;
            let m = store.authz_matrix(run, limit)?;
            out.ok(m.clone(), || matrix_text(&m));
            Ok(())
        }
        AuthzCmd::List { limit } => {
            let store = Store::open(project)?;
            // A run whose process died (a killed proxy) isn't live any more.
            for r in store.authz_runs(limit)? {
                if let Some(id) = r["run_id"].as_i64().filter(|_| !is_finished(r["state"].as_str().unwrap_or(""))) {
                    crate::jobs_cmd::reap(project, &store, id)?;
                }
            }
            let runs = store.authz_runs(limit)?;
            out.ok(json!({"runs": runs}), || {
                runs.iter()
                    .map(|r| {
                        format!(
                            "{:>4}  {:<10} {}  {}",
                            r["run_id"],
                            r["state"].as_str().unwrap_or(""),
                            r["time"].as_str().unwrap_or(""),
                            r["verdicts"]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(())
        }
    }
}

fn require_run(store: &Store, run: i64) -> Result<(), Error> {
    if store.authz_run_exists(run)? {
        Ok(())
    } else {
        Err(Error::NotFound(format!("authz run {run}")))
    }
}

fn run(project: &Path, home: &Path, args: RunArgs, out: &Out) -> Result<(), Error> {
    let guard = crate::project_guard(project)?;
    let exclude = regex::Regex::new(&args.exclude).map_err(|e| Error::InvalidInput(format!("--exclude: {e}")))?;
    let anonymous = !args.no_anonymous;
    let identities: Vec<String> = {
        let mut seen = HashSet::new();
        args.identities.iter().filter(|n| n.as_str() != ANONYMOUS && seen.insert(n.to_string())).cloned().collect()
    };
    if args.owner.as_deref() == Some(ANONYMOUS) {
        return Err(Error::InvalidInput("--owner must be an auth profile, not anonymous".into()));
    }
    if identities.is_empty() && !anonymous {
        return Err(Error::InvalidInput("nothing to compare: pass --as NAME or drop --no-anonymous".into()));
    }
    if !args.urls.is_empty() && args.owner.is_none() {
        return Err(Error::InvalidInput("URLs need --owner: the profile whose response is the baseline".into()));
    }
    let profiles = require_profiles(project, identities.iter().chain(&args.owner))?;
    for u in &args.urls {
        crate::require_in_scope(&guard, &Target::from_url(u)?)?;
    }
    if args.background {
        return crate::jobs_cmd::spawn_background("authz", project, home, out);
    }
    let send = SendOptions {
        timeout: Duration::from_secs_f64(args.timeout.max(0.1)),
        verify_tls: args.verify_tls,
        sni: None,
        guard: Some(guard.clone()),
        http2: args.http2,
        host: brainproxy_core::http::client::HostPolicy::for_process(false),
    };
    let (targets, skipped) = select(project, &args, &exclude, &guard)?;
    if targets.is_empty() {
        return Err(Error::InvalidInput(
            "no requests to test: pass URLs with --owner, --history-id, --where, or --tag, or browse/send the \
             target logged in first"
                .into(),
        ));
    }

    // Sessions: the identities and owner log in now if they need to. Other profiles
    // only help to work out who made a request and which credentials to remove; one
    // named by a request's auth placeholders logs in too, since it sends the baseline.
    let mut needed: Vec<String> = identities.iter().chain(&args.owner).cloned().collect();
    for t in &targets {
        for n in authz::placeholder_profiles(&t.request) {
            if profiles.contains(&n) && !needed.contains(&n) {
                needed.push(n);
            }
        }
    }
    let known = load_sessions(project, &profiles, &needed, &send)?;
    let find = |n: &str| known.iter().find(|s| s.profile.name == n).cloned().expect("loaded above");
    let cfg = AuthzConfig {
        identities: identities.iter().map(|n| find(n)).collect(),
        anonymous,
        owner: args.owner.as_deref().map(find),
        known: known.clone(),
        keep_cookies: args.keep_cookies.clone(),
        send,
        concurrency: args.concurrency.clamp(1, 50),
        rate: args.rate,
    };

    let job_id = match args.job_id {
        Some(id) => id,
        None => Store::open(project)?.job_create("authz", "queued", &crate::jobs_cmd::child_args())?,
    };
    let result = crate::jobs_cmd::run_job(project, Some(job_id), |ctl| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let summary = rt.block_on(authz::run(project, job_id, targets, cfg, ctl));
        for s in &known {
            if needed.contains(&s.profile.name) {
                s.save()?;
            }
        }
        let summary = summary?;
        let store = Store::open(project)?;
        let bypasses = store.authz_results(job_id, Some("bypass"), None, 20)?;
        let mut v = json!(summary);
        v["skipped"] = skipped.clone();
        v["bypasses"] = json!(bypasses);
        v["hint"] = json!(format!(
            "Table: brainproxy authz matrix {job_id}; bypasses: brainproxy authz results {job_id} --verdict bypass; \
             compare a pair: brainproxy diff BASELINE_HISTORY_ID HISTORY_ID --part response-body; findings: \
             brainproxy findings list --source authz"
        ));
        Ok(v)
    })?;
    out.ok(result.clone(), || summary_text(&result));
    Ok(())
}

/// The stored auth profile names; fails naming the first of `names` that isn't one.
pub(crate) fn require_profiles<'a>(
    project: &Path,
    names: impl IntoIterator<Item = &'a String>,
) -> Result<Vec<String>, Error> {
    let profiles: Vec<String> = Store::open(project)?.auth_list()?.into_iter().map(|(p, _)| p.name).collect();
    for name in names {
        if !profiles.contains(name) {
            return Err(Error::NotFound(format!("auth profile {name} (see auth list)")));
        }
    }
    Ok(profiles)
}

/// A session for each of `profiles`: those in `needed` log in now if they need to. The
/// others only help to work out who made a request and which credentials to remove.
pub(crate) fn load_sessions(
    project: &Path,
    profiles: &[String],
    needed: &[String],
    send: &SendOptions,
) -> Result<Vec<Arc<AuthSession>>, Error> {
    let mut known = Vec::new();
    for name in profiles {
        let s = if needed.contains(name) {
            crate::auth_cmd::load_session(project, name, send.clone())?
        } else {
            match AuthSession::load(project, name, Client::new(send.clone())) {
                Ok(s) => Arc::new(s),
                Err(_) => continue,
            }
        };
        known.push(s);
    }
    Ok(known)
}

/// Picks and de-duplicates the requests to test; returns them with the numbers skipped
/// and why.
fn select(
    project: &Path,
    args: &RunArgs,
    exclude: &regex::Regex,
    guard: &brainproxy_core::guard::Guard,
) -> Result<(Vec<AuthzTarget>, Value), Error> {
    // Its method, and MUTATION too for a GraphQL mutation, as in a scan.
    let missing = |request: &[u8]| api::missing_opt_in(request, SAFE_METHODS, &args.include_methods);
    let mut targets = Vec::new();
    for u in &args.urls {
        let (req, target) = RawRequest::build("GET", u, &[], b"")?;
        if let Some(method) = missing(req.as_bytes()) {
            return Err(Error::InvalidInput(format!(
                "--url {u} is a {method} request, and replaying it as each identity can change or delete data; \
                 add --include-methods {method} to test it"
            )));
        }
        targets.push((true, AuthzTarget { history_id: None, target, request: req.into_bytes() }));
    }
    let mut ids: Vec<(i64, bool)> = args.history_ids.iter().map(|id| (*id, true)).collect();
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    if let Some(w) = &args.where_sql {
        conditions.push(format!("({w})"));
    }
    if let Some(t) = &args.tag {
        params.push(t.clone());
        conditions.push(format!("EXISTS (SELECT 1 FROM json_each(history.tags) WHERE value = ?{})", params.len()));
    }
    if conditions.is_empty() && args.urls.is_empty() && args.history_ids.is_empty() {
        conditions.push("source IN ('proxy', 'send', 'crawl', 'import')".into());
    }
    if !conditions.is_empty() {
        let ro = Store::open_read_only(project)?;
        let sql =
            format!("SELECT id FROM history WHERE {} AND status IS NOT NULL ORDER BY id", conditions.join(" AND "));
        let r = ro.query(&sql, &params, 100_000, 50)?;
        ids.extend(r.rows.iter().filter_map(|row| row[0].as_i64()).map(|id| (id, false)));
    }
    let store = Store::open(project)?;
    let profiles: Vec<AuthProfile> = store.auth_list()?.into_iter().map(|(p, _)| p).collect();
    let (mut out_of_scope, mut methods, mut excluded, mut no_credentials) = (0, 0, 0, 0);
    for (id, explicit) in ids {
        let item = store.get(id)?;
        if !guard.may_allow(&item.target.host, item.target.port) {
            out_of_scope += 1;
            continue;
        }
        let path = Message::from_exchange(id, &item.target, &item.request, b"").path;
        // Naming a request isn't consent to replay what it changes, or to log every identity out:
        // a named one that would be skipped is refused before anything is sent.
        if let Some(method) = missing(&item.request) {
            if explicit {
                return Err(Error::InvalidInput(format!(
                    "--history-id {id} is a {method} request, and replaying it as each identity can change or \
                     delete data; add --include-methods {method} to test it"
                )));
            }
            methods += 1;
            continue;
        }
        if exclude.is_match(&path) {
            if explicit {
                return Err(Error::InvalidInput(format!(
                    "--history-id {id}: {path} matches --exclude (logout paths), and replaying it can end the \
                     identities' sessions; give --exclude a pattern it doesn't match to test it"
                )));
            }
            excluded += 1;
            continue;
        }
        if !explicit && !authz::has_credentials(&item.request, &profiles) {
            no_credentials += 1;
            continue;
        }
        targets.push((explicit, AuthzTarget { history_id: Some(id), target: item.target, request: item.request }));
    }
    // One test per method, URL and body.
    let mut seen = HashSet::new();
    let mut duplicates = 0;
    targets.retain(|(_, t)| {
        let head = RawRequest::from_bytes(t.request.clone()).head().ok();
        let line = head.map(|h| format!("{} {}", h.method, h.target)).unwrap_or_default();
        let body = RawRequest::from_bytes(t.request.clone()).body().to_vec();
        let new = seen.insert((t.target.origin(), line, body));
        if !new {
            duplicates += 1;
        }
        new
    });
    let over = targets.len().saturating_sub(args.max_requests);
    targets.truncate(args.max_requests);
    let mut skipped = json!({});
    for (k, n) in [
        ("out_of_scope", out_of_scope),
        ("methods", methods),
        ("excluded_paths", excluded),
        ("no_credentials", no_credentials),
        ("duplicates", duplicates),
        ("over_max_requests", over),
    ] {
        if n > 0 {
            skipped[k] = json!(n);
        }
    }
    if methods > 0 {
        skipped["methods_hint"] = json!(
            "Only GET, HEAD and OPTIONS are replayed from history; --include-methods POST,PUT (or all) adds others, \
             and MUTATION adds GraphQL mutations."
        );
    }
    Ok((targets.into_iter().map(|(_, t)| t).collect(), skipped))
}

fn result_line(r: &Value) -> String {
    let s = |k: &str| r[k].as_str().unwrap_or("").to_string();
    let conf = r["confidence"].as_str().map(|c| format!(" ({c})")).unwrap_or_default();
    let detail = if s("evidence").is_empty() { s("reason") } else { s("evidence") };
    format!(
        "{:>5}  {:<12} {:<10}{:<9} {:>4} {} {}  [{}]",
        r["history_id"].as_i64().map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
        s("identity"),
        s("verdict"),
        conf,
        r["status"].as_i64().map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
        s("method"),
        s("url"),
        detail
    )
}

fn matrix_text(m: &Value) -> String {
    let identities: Vec<&str> = m["identities"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let mut lines =
        vec![format!("{:<10} {}  request", "owner", identities.iter().map(|i| format!("{i:<14}")).collect::<String>())];
    for r in m["requests"].as_array().into_iter().flatten() {
        let cells: String = identities
            .iter()
            .map(|i| {
                let c = &r["cells"][*i];
                let v = match (c["verdict"].as_str(), c["confidence"].as_str()) {
                    (Some(v), Some(conf)) => format!("{v}:{conf}"),
                    (Some(v), None) => v.to_string(),
                    _ => "-".into(),
                };
                format!("{v:<14}")
            })
            .collect();
        let skipped = r["skipped"].as_str().map(|s| format!("  ({s})")).unwrap_or_default();
        lines.push(format!(
            "{:<10} {cells}  {} {}{skipped}",
            r["owner"].as_str().unwrap_or(""),
            r["method"].as_str().unwrap_or(""),
            r["url"].as_str().unwrap_or("")
        ));
    }
    lines.join("\n")
}

fn summary_text(v: &Value) -> String {
    let mut lines = vec![format!(
        "authz run {}: {} requests, {} sent, {} new findings; verdicts {}",
        v["run_id"], v["requests"], v["sent"], v["new_findings"], v["verdicts"]
    )];
    for b in v["bypasses"].as_array().into_iter().flatten() {
        lines.push(format!("  {}", result_line(b)));
    }
    if v["skipped"].as_object().is_some_and(|o| !o.is_empty()) {
        lines.push(format!("skipped: {}", v["skipped"]));
    }
    lines.push(v["hint"].as_str().unwrap_or("").to_string());
    lines.join("\n")
}
