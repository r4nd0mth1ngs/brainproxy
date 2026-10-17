//! `import openapi|postman|graphql`: build requests from an API description,
//! send them (in scope only) and record them as history source "import".

use std::path::Path;
use std::time::Duration;

use brainproxy_core::apiimport::{self, graphql, openapi, postman, ApiRequest, Built, RunConfig};
use brainproxy_core::auth::AuthSession;
use brainproxy_core::capture::decode_body;
use brainproxy_core::http::request::split_head_body;
use brainproxy_core::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::output::{body_value, Out};

#[derive(Subcommand)]
pub enum ImportCmd {
    /// OpenAPI 3.x or Swagger 2.0 document (JSON or YAML): one request per operation.
    #[command(after_help = "Parameters get their example, default, or first enum value, else a typed default \
        (1, 1.5, true, \"test\", or a value matching the format). Servers: the operation's, the path's, then the \
        document's first server (Swagger: schemes/host/basePath); relative servers resolve against the spec URL, \
        or need --base-url. DELETE operations are skipped unless --include-destructive.")]
    Openapi(DocArgs),
    /// Postman collection v2.0/v2.1: one request per item, {{variables}} substituted.
    #[command(after_help = "Variables come from the collection's `variable` list and --var. Bearer, basic, and \
        API key auth from the collection, folder, or item is applied when its values are known. Items whose host \
        is an unresolved variable need --var or --base-url. DELETE items are skipped unless --include-destructive.")]
    Postman(DocArgs),
    /// GraphQL endpoint: introspect it (or read --schema) and send one operation per query field.
    #[command(after_help = "Arguments are sent as variables with typed defaults (Int 1, Float 1.5, String \"test\", \
        ID \"1\", first enum value, input objects filled in), so `scan active` injects into them as JSON values. \
        Mutations are only sent with --include-destructive.")]
    Graphql(GraphqlArgs),
}

#[derive(clap::Args)]
pub struct DocArgs {
    /// Document file, '-' for stdin, or an http(s) URL (fetched in scope, recorded in history).
    source: String,
    /// Send to this server instead: scheme://host[:port] replaces the origin; with a path, the whole base.
    #[arg(long)]
    base_url: Option<String>,
    /// Postman variable, NAME=VALUE. Repeatable.
    #[arg(long = "var", value_name = "NAME=VALUE")]
    vars: Vec<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(clap::Args)]
pub struct GraphqlArgs {
    /// GraphQL endpoint URL.
    url: String,
    /// Introspection result (JSON file or '-') instead of querying the endpoint.
    #[arg(long, value_name = "FILE")]
    schema: Option<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(clap::Args)]
pub struct Common {
    /// Header for every request (and the spec fetch), e.g. "Authorization: Bearer ...". Repeatable.
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// Send logged in with this auth profile; re-logs in when the session is lost.
    #[arg(long, value_name = "NAME")]
    auth: Option<String>,
    /// Also send DELETE requests and GraphQL mutations.
    #[arg(long)]
    include_destructive: bool,
    /// Only build and list the requests; send nothing (except fetching the spec/introspection).
    #[arg(long)]
    dry_run: bool,
    /// Maximum requests sent.
    #[arg(long, default_value_t = 1000)]
    max_requests: usize,
    /// Requests listed in the output.
    #[arg(long, default_value_t = 100)]
    limit: usize,
    /// Maximum body characters per request in --dry-run output.
    #[arg(long, default_value_t = 2000)]
    max_body: usize,
    #[arg(short = 'c', long, default_value_t = 10)]
    concurrency: usize,
    /// Maximum requests per second.
    #[arg(long)]
    rate: Option<f64>,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    #[arg(long)]
    verify_tls: bool,
    /// Run detached; returns a job id for `job wait|status|stop`.
    #[arg(long)]
    background: bool,
    #[arg(long, hide = true)]
    job_id: Option<i64>,
}

pub fn import(project: &Path, home: &Path, cmd: ImportCmd, out: &Out) -> Result<(), Error> {
    let (kind, c, stdin) = match &cmd {
        ImportCmd::Openapi(a) => ("openapi", &a.common, a.source == "-"),
        ImportCmd::Postman(a) => ("postman", &a.common, a.source == "-"),
        ImportCmd::Graphql(a) => ("graphql", &a.common, a.schema.as_deref() == Some("-")),
    };
    let guard = crate::project_guard(project)?;
    let remote = match &cmd {
        ImportCmd::Openapi(a) | ImportCmd::Postman(a) => is_url(&a.source).then_some(a.source.as_str()),
        ImportCmd::Graphql(a) => Some(a.url.as_str()),
    };
    if let Some(u) = remote {
        crate::require_in_scope(&guard, &Target::from_url(u)?)?;
    }
    if c.background {
        if stdin {
            return Err(Error::InvalidInput("--background can't read stdin; pass a file".into()));
        }
        return crate::jobs_cmd::spawn_background("import", project, home, out);
    }
    let headers = c.headers.iter().map(|h| crate::request_args::parse_header(h)).collect::<Result<Vec<_>, _>>()?;
    let send = SendOptions {
        timeout: Duration::from_secs_f64(c.timeout.max(0.1)),
        verify_tls: c.verify_tls,
        sni: None,
        guard: Some(guard),
        http2: false,
    };
    let auth = crate::auth_cmd::maybe_session(project, c.auth.as_deref(), &send)?;
    let fetch = Fetcher { project, send: &send, auth: auth.as_deref(), headers: &headers };

    let built = match &cmd {
        ImportCmd::Openapi(a) => {
            let (text, spec_url) = fetch.document(&a.source)?;
            let doc = apiimport::parse_document(&text)?;
            openapi::build(&doc, &openapi::Options { base_url: a.base_url.clone(), spec_url })?
        }
        ImportCmd::Postman(a) => {
            let (text, _) = fetch.document(&a.source)?;
            let vars = a
                .vars
                .iter()
                .map(|v| {
                    v.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .ok_or_else(|| Error::InvalidInput(format!("--var {v:?} must look like NAME=VALUE")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            postman::build(
                &apiimport::parse_document(&text)?,
                &postman::Options { base_url: a.base_url.clone(), vars },
            )?
        }
        ImportCmd::Graphql(a) => {
            let text = match &a.schema {
                Some(s) => read_local(s)?,
                None => fetch.introspect(&a.url)?,
            };
            graphql::build(&apiimport::parse_document(&text)?, &a.url, c.include_destructive)?
        }
    };
    let Built { mut requests, mut warnings } = built;
    let total = requests.len();
    requests.retain(|r| match apiimport::build_raw(r, &headers) {
        Ok(_) => true,
        Err(e) => {
            warnings.push(format!("{}: {e}", r.name));
            false
        }
    });
    let before = requests.len();
    if !c.include_destructive {
        requests.retain(|r| r.method != "DELETE");
    }
    let skipped_destructive = before - requests.len();
    let over_limit = requests.len().saturating_sub(c.max_requests);
    requests.truncate(c.max_requests);

    let mut result = json!({
        "kind": kind,
        "built": total,
        "skipped_destructive": skipped_destructive,
        "skipped_over_limit": over_limit,
        "warnings": warnings,
    });
    if c.dry_run {
        result["requests_truncated"] = json!(requests.len() > c.limit);
        result["requests"] = json!(requests.iter().take(c.limit).map(|r| describe(r, c.max_body)).collect::<Vec<_>>());
        result["hint"] = json!("Run again without --dry-run to send and record them for `scan active`.");
        out.ok(result.clone(), || text(&result));
        return Ok(());
    }
    if requests.is_empty() {
        return Err(Error::InvalidInput(format!(
            "no requests to send from the {kind} source{}",
            warnings_hint(&result["warnings"])
        )));
    }
    let cfg = RunConfig {
        send: send.clone(),
        headers,
        concurrency: c.concurrency.clamp(1, 200),
        rate: c.rate,
        auth: auth.clone(),
        list_limit: c.limit,
    };
    let summary = crate::jobs_cmd::run_job(project, c.job_id, |ctl| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let s = rt.block_on(apiimport::run(project, requests, cfg, ctl));
        if let Some(a) = &auth {
            a.save()?;
        }
        let mut v = json!(s?);
        for (k, val) in result.as_object().into_iter().flatten() {
            v[k] = val.clone();
        }
        v["hint"] = json!(
            "Imported requests are history source 'import': `scan active` attacks them by default \
             (or --where \"source = 'import'\"); fuzz one with `history show ID --part request --raw`."
        );
        Ok(v)
    })?;
    out.ok(summary.clone(), || text(&summary));
    Ok(())
}

fn warnings_hint(w: &Value) -> String {
    match w.as_array().and_then(|a| a.first()) {
        Some(first) => format!(" (first warning: {})", first.as_str().unwrap_or("")),
        None => String::new(),
    }
}

fn describe(r: &ApiRequest, max_body: usize) -> Value {
    json!({
        "name": r.name,
        "method": r.method,
        "url": r.url,
        "headers": r.headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>(),
        "body": body_value(&r.body, max_body),
    })
}

fn text(v: &Value) -> String {
    let mut lines = vec![format!(
        "{}: built {} requests, sent {}, skipped {} destructive, {} out of scope, {} new findings",
        v["kind"].as_str().unwrap_or(""),
        v["built"],
        v.get("sent").cloned().unwrap_or(json!(0)),
        v["skipped_destructive"],
        v.get("skipped_out_of_scope").cloned().unwrap_or(json!(0)),
        v.get("new_findings").cloned().unwrap_or(json!(0)),
    )];
    for r in v["requests"].as_array().into_iter().flatten() {
        lines.push(format!(
            "  {:<7} {:<5} {}  ({})",
            r["method"].as_str().unwrap_or(""),
            r.get("status").map(|s| s.to_string()).unwrap_or_default().replace("null", "err"),
            r["url"].as_str().unwrap_or(""),
            r["name"].as_str().unwrap_or("")
        ));
    }
    for w in v["warnings"].as_array().into_iter().flatten().take(20) {
        lines.push(format!("  warning: {}", w.as_str().unwrap_or("")));
    }
    lines.join("\n")
}

fn is_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://")
}

fn read_local(source: &str) -> Result<String, Error> {
    let bytes = if source == "-" {
        crate::read_input(None)?
    } else {
        let meta =
            std::fs::metadata(source).map_err(|e| Error::InvalidInput(format!("cannot read {source:?}: {e}")))?;
        if meta.len() as usize > apiimport::MAX_DOCUMENT {
            return Err(Error::InvalidInput(format!(
                "{source:?} is larger than {} MiB",
                apiimport::MAX_DOCUMENT >> 20
            )));
        }
        std::fs::read(source).map_err(|e| Error::InvalidInput(format!("cannot read {source:?}: {e}")))?
    };
    String::from_utf8(bytes).map_err(|_| Error::InvalidInput(format!("{source:?} is not UTF-8 text")))
}

/// Fetches specs and introspection results through the guarded client.
struct Fetcher<'a> {
    project: &'a Path,
    send: &'a SendOptions,
    auth: Option<&'a AuthSession>,
    headers: &'a [(String, String)],
}

impl Fetcher<'_> {
    /// Returns the document text and, for URLs, the URL it came from.
    fn document(&self, source: &str) -> Result<(String, Option<String>), Error> {
        if !is_url(source) {
            return Ok((read_local(source)?, None));
        }
        let body = self.fetch("GET", source, &[], b"")?;
        Ok((body, Some(source.to_string())))
    }

    fn introspect(&self, url: &str) -> Result<String, Error> {
        let ct = [("Content-Type".to_string(), "application/json".to_string())];
        self.fetch("POST", url, &ct, &graphql::introspection_body())
    }

    fn fetch(&self, method: &str, url: &str, extra: &[(String, String)], body: &[u8]) -> Result<String, Error> {
        let mut headers = extra.to_vec();
        headers.extend(self.headers.iter().cloned());
        let (req, target): (RawRequest, Target) = RawRequest::build(method, url, &headers, body)?;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let ex = match self.auth {
            Some(a) => rt.block_on(a.send(&req, &target))?,
            None => rt.block_on(Client::new(self.send.clone()).send(&req, &target))?,
        };
        Store::open(self.project)?.record_exchange(apiimport::SOURCE, &ex)?;
        let head = parse_response_head(&ex.response)?;
        let body = decode_body(&head.headers, split_head_body(&ex.response).1);
        if body.len() > apiimport::MAX_DOCUMENT {
            return Err(Error::InvalidInput(format!("{url} returned more than {} MiB", apiimport::MAX_DOCUMENT >> 20)));
        }
        let text = String::from_utf8_lossy(&body).into_owned();
        // GraphQL servers often answer errors with 200 or 400 + a JSON body; let the parser report those.
        let graphql_error = method == "POST" && text.trim_start().starts_with('{');
        if !(200..300).contains(&head.status) && !graphql_error {
            return Err(Error::InvalidInput(format!("{method} {url} returned HTTP {}", head.status)));
        }
        Ok(text)
    }
}
