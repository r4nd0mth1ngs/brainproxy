//! `import api|openapi|postman|graphql|har`: build requests from an API description or a
//! HAR file, send them (in scope only) and record them as history source "import".

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use brainproxy_core::apiimport::{self, api, graphql, har, openapi, postman, ApiRequest, Built, RunConfig};
use brainproxy_core::auth::{Attempt, AuthSession};
use brainproxy_core::capture::decode_body;
use brainproxy_core::guard::Guard;
use brainproxy_core::http::request::split_head_body;
use brainproxy_core::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use brainproxy_core::session::Tool;
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::output::{body_value, Out};

#[derive(Subcommand)]
pub enum ImportCmd {
    /// An API description, its format detected: OpenAPI 3.x, Swagger 2.0, Postman v2.0/v2.1, a GraphQL
    /// schema file or introspection result (--graphql introspects a URL), or a HAR file.
    /// `--dry-run` is the preview: every request built, and which would go out.
    #[command(after_help = "Sends GET, HEAD, OPTIONS, and POST; --include-methods opts in to others, and to GraphQL \
        mutations as MUTATION. A GraphQL schema file needs --base-url, the endpoint. Credentials \
        in the document are never sent or stored, only listed under `credentials`: use `auth add` and --auth \
        for them. Indexes for --only count the built requests in document order, so they hold for one document \
        and one set of options; --expect-sha256 proves the document is the one previewed. A HAR file: see \
        `import har`.")]
    Api(ApiArgs),
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
    /// HAR 1.2 file (a browser's or proxy's recording): one request per entry, as recorded,
    /// under `import api`'s rules. `--dry-run` is the preview.
    #[command(after_help = "Each entry's method, URL, headers, cookies, query and body (text, form or multipart \
        params) is sent again, and the live response recorded; the HAR's responses are not read or stored. Left \
        out, and counted in `warnings`: static assets (scripts, styles, images, fonts, media; --keep-static keeps \
        them), repeats of an earlier entry's method, URL and body, WebSocket handshakes, and URLs that aren't \
        http(s). Entries out of scope are listed with excluded_reason \"scope\" and never sent. The recorded \
        Cookie, Authorization and other credential headers, and credentials in URLs and bodies, are left out \
        and listed under `credentials` by name; --keep-credentials sends the headers as recorded (never shown). \
        Sends GET, HEAD, OPTIONS and POST; --include-methods opts in to others and to GraphQL mutations (MUTATION). \
        `import api` and `scan active --api` take a HAR file too. Up to 256 MiB.")]
    Har(HarArgs),
}

#[derive(clap::Args)]
pub struct DocArgs {
    /// Document file, '-' for stdin, or an http(s) URL (fetched in scope and recorded in history).
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
pub struct ApiArgs {
    #[command(flatten)]
    doc: DocArgs,
    /// Also send these methods (comma-separated, or `all`). By default GET, HEAD, OPTIONS, and POST.
    #[arg(long, value_delimiter = ',', value_name = "METHODS")]
    include_methods: Vec<String>,
    /// Only the requests at these indexes (comma-separated), as the preview numbers them.
    #[arg(long, value_delimiter = ',', value_name = "INDEXES")]
    only: Option<Vec<usize>>,
    /// Use the document's Nth server (from 0, see `servers`) instead of the first. Operation
    /// and path servers still win; --base-url overrides everything.
    #[arg(long, value_name = "N")]
    server: Option<usize>,
    /// Refuse a document whose sha256 isn't this: it proves the file is the one previewed.
    #[arg(long, value_name = "HEX")]
    expect_sha256: Option<String>,
    /// A Postman environment file, for the collection's variables. Those marked secret or
    /// that look like credentials are withheld; --var goes on top.
    #[arg(long, value_name = "FILE")]
    environment: Option<String>,
    /// Refuse an environment file whose sha256 isn't this.
    #[arg(long, value_name = "HEX", requires = "environment")]
    expect_environment_sha256: Option<String>,
    /// SOURCE is a GraphQL endpoint: introspect it instead of fetching a document.
    #[arg(long)]
    graphql: bool,
    /// List the text of each Postman pre-request script in the preview.
    #[arg(long)]
    show_scripts: bool,
    #[command(flatten)]
    har: HarFlags,
    /// `import har`: refuse any other format.
    #[arg(skip)]
    require_har: bool,
}

/// What only a HAR file takes.
#[derive(clap::Args)]
pub struct HarFlags {
    /// HAR files: keep scripts, styles, images, fonts and media, which are left out by default.
    #[arg(long)]
    pub(crate) keep_static: bool,
    /// HAR files: send the recorded Cookie, Authorization and other credential headers as recorded,
    /// instead of leaving them out. They are still listed under `credentials`, and never shown.
    #[arg(long)]
    pub(crate) keep_credentials: bool,
}

impl HarFlags {
    pub(crate) fn options(&self) -> api::HarOptions {
        api::HarOptions { keep_static: self.keep_static, keep_credentials: self.keep_credentials }
    }
}

#[derive(clap::Args)]
pub struct HarArgs {
    /// HAR file, '-' for stdin, or an http(s) URL (fetched in scope; the file itself isn't recorded).
    source: String,
    /// Send to this server instead: scheme://host[:port] replaces the origin; with a path, the whole base.
    #[arg(long)]
    base_url: Option<String>,
    /// Also send these methods (comma-separated, or `all`). By default GET, HEAD, OPTIONS, and POST.
    #[arg(long, value_delimiter = ',', value_name = "METHODS")]
    include_methods: Vec<String>,
    /// Only the requests at these indexes (comma-separated), as the preview numbers them.
    #[arg(long, value_delimiter = ',', value_name = "INDEXES")]
    only: Option<Vec<usize>>,
    /// Refuse a file whose sha256 isn't this: it proves the file is the one previewed.
    #[arg(long, value_name = "HEX")]
    expect_sha256: Option<String>,
    #[command(flatten)]
    har: HarFlags,
    #[command(flatten)]
    common: Common,
}

impl From<HarArgs> for ApiArgs {
    fn from(h: HarArgs) -> Self {
        ApiArgs {
            doc: DocArgs { source: h.source, base_url: h.base_url, vars: vec![], common: h.common },
            include_methods: h.include_methods,
            only: h.only,
            server: None,
            expect_sha256: h.expect_sha256,
            environment: None,
            expect_environment_sha256: None,
            graphql: false,
            show_scripts: false,
            har: h.har,
            require_har: true,
        }
    }
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
    // `import har` is `import api` for a HAR file only.
    let cmd = match cmd {
        ImportCmd::Har(h) => ImportCmd::Api(h.into()),
        other => other,
    };
    let (kind, c, stdin) = match &cmd {
        ImportCmd::Api(a) => ("api", &a.doc.common, a.doc.source == "-"),
        ImportCmd::Openapi(a) => ("openapi", &a.common, a.source == "-"),
        ImportCmd::Postman(a) => ("postman", &a.common, a.source == "-"),
        ImportCmd::Graphql(a) => ("graphql", &a.common, a.schema.as_deref() == Some("-")),
        ImportCmd::Har(_) => unreachable!("made an `import api` above"),
    };
    if let ImportCmd::Api(a) = &cmd {
        api::check_source(&a.doc.source)?;
    }
    let guard = crate::project_guard(project)?;
    let remote = match &cmd {
        ImportCmd::Api(a) => is_url(&a.doc.source).then_some(a.doc.source.as_str()),
        ImportCmd::Openapi(a) | ImportCmd::Postman(a) => is_url(&a.source).then_some(a.source.as_str()),
        ImportCmd::Graphql(a) => Some(a.url.as_str()),
        ImportCmd::Har(_) => unreachable!("made an `import api` above"),
    };
    if let Some(u) = remote {
        crate::require_in_scope(&guard, &Target::from_url(u)?)?;
    }
    if c.background {
        if stdin {
            return Err(Error::InvalidInput("--background can't read stdin; pass a file".into()));
        }
        if let ImportCmd::Api(a) = &cmd {
            check_background_args(&parse_vars(&a.doc.vars)?, &c.headers)?;
            if let Some(b) = &a.doc.base_url {
                api::check_base_url(b)?;
            }
            // A local file can be checked now, so the caller gets the error and not a failed job.
            if remote.is_none() {
                if a.graphql {
                    return Err(Error::InvalidInput("--graphql needs the endpoint's http(s) URL".into()));
                }
                let loaded = api::load(&read_local(project, &a.doc.source)?, &a.options(project)?)?;
                check_background_doc(&loaded)?;
                loaded.check_runnable(&loaded.plan(&a.selection(), &guard)?)?;
            } else {
                let headers =
                    c.headers.iter().map(|h| crate::request_args::parse_header(h)).collect::<Result<Vec<_>, _>>()?;
                let from = RemoteFetch {
                    auth: c.auth.as_deref(),
                    headers: &headers,
                    tool: Tool::Crawl,
                    timeout: c.timeout,
                    verify_tls: c.verify_tls,
                    graphql: a.graphql,
                };
                check_remote_vars(project, &guard, &a.doc.source, a.options(project)?, from)?;
            }
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
        host: brainproxy_core::http::client::HostPolicy::for_process(false),
    };
    let auth = crate::auth_cmd::maybe_session(project, c.auth.as_deref(), &send)?;
    let fetch = Fetcher { project, send: &send, auth: auth.as_deref(), headers: &headers, tool: Tool::Crawl };
    if let ImportCmd::Api(a) = &cmd {
        return import_api(project, a, &fetch, auth.clone(), &headers, out);
    }

    let built = match &cmd {
        ImportCmd::Api(_) | ImportCmd::Har(_) => unreachable!("handled above"),
        ImportCmd::Openapi(a) => {
            let (text, spec_url) = fetch.document(&a.source)?;
            let doc = parse_doc(&text)?;
            openapi::build(&doc, &openapi::Options { base_url: a.base_url.clone(), spec_url, ..Default::default() })?
        }
        ImportCmd::Postman(a) => {
            let (text, _) = fetch.document(&a.source)?;
            let vars = parse_vars(&a.vars)?;
            postman::build(
                &parse_doc(&text)?,
                &postman::Options { base_url: a.base_url.clone(), vars, ..Default::default() },
            )?
        }
        ImportCmd::Graphql(a) => {
            let text = match &a.schema {
                Some(s) => read_local(project, s)?,
                None => fetch.introspect(&a.url)?,
            };
            graphql::build(&parse_doc(&text)?, &a.url, c.include_destructive)?
        }
    };
    let Built { mut requests, mut warnings, .. } = built;
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
        tool: Tool::Crawl,
        stage: None,
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

impl ApiArgs {
    fn options(&self, project: &Path) -> Result<api::Options, Error> {
        Ok(api::Options {
            base_url: self.doc.base_url.clone(),
            server: self.server,
            vars: parse_vars(&self.doc.vars)?,
            expect_sha256: self.expect_sha256.clone(),
            environment: self.environment.as_deref().map(|e| read_environment(project, e)).transpose()?,
            expect_environment_sha256: self.expect_environment_sha256.clone(),
            spec_url: None,
            har: self.har.options(),
            require_har: self.require_har,
        })
    }

    fn selection(&self) -> api::Selection {
        let mut include_methods = self.include_methods.clone();
        if self.doc.common.include_destructive {
            include_methods.extend(["DELETE".into(), api::MUTATION.into()]);
        }
        selection(&include_methods, self.only.clone())
    }
}

/// `import api`, once the arguments are checked.
fn import_api(
    project: &Path,
    a: &ApiArgs,
    fetch: &Fetcher<'_>,
    auth: Option<std::sync::Arc<AuthSession>>,
    headers: &[(String, String)],
    out: &Out,
) -> Result<(), Error> {
    let c = &a.doc.common;
    let guard = fetch.send.guard.clone().ok_or_else(|| Error::OutOfScope("no scope set".into()))?;
    let loaded = if a.graphql {
        load_graphql_endpoint(fetch, &a.doc.source, a.options(project)?)?
    } else {
        // Read once: the script text must come from the document the preview is of.
        let (text, spec_url) = fetch.document(&a.doc.source)?;
        let mut loaded = api::load(&text, &api::Options { spec_url, ..a.options(project)? })?;
        if a.show_scripts {
            api::add_script_text(&mut loaded, &text);
        }
        loaded
    };
    let plan = loaded.plan(&a.selection(), &guard)?;
    let preview = loaded.preview(&plan, c.limit);
    let bodies: Vec<Value> = preview.requests.iter().map(|r| body_value(&r.body, c.max_body)).collect();
    let mut result = json!(preview);
    if c.dry_run {
        for (row, body) in result["requests"].as_array_mut().into_iter().flatten().zip(bodies) {
            row["body"] = body;
        }
        result["hint"] = json!(if loaded.base_url_required {
            "Some operations have no server: pass --base-url and preview again."
        } else {
            "Run again without --dry-run to send the included requests and record them for `scan active`."
        });
        out.ok(result.clone(), || text(&result));
        return Ok(());
    }
    loaded.check_runnable(&plan)?;
    let (requests, over_limit) = plan.to_send(c.max_requests);
    let cfg = RunConfig {
        send: fetch.send.clone(),
        headers: headers.to_vec(),
        concurrency: c.concurrency.clamp(1, 200),
        rate: c.rate,
        auth: auth.clone(),
        list_limit: c.limit,
        tool: Tool::Crawl,
        stage: None,
    };
    let summary = crate::jobs_cmd::run_job(project, c.job_id, |ctl| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let s = rt.block_on(apiimport::run(project, requests, cfg, ctl));
        if let Some(a) = &auth {
            a.save()?;
        }
        let s = s?;
        s.check_any_in_scope()?;
        let mut v = json!(s);
        for (k, val) in result.as_object().into_iter().flatten().filter(|(k, _)| !k.starts_with("requests")) {
            v[k] = val.clone();
        }
        v["skipped_over_limit"] = json!(over_limit);
        v["hint"] = json!("Imported requests are history source 'import'; `scan active --api` attacks exactly these.");
        Ok(v)
    })?;
    out.ok(summary.clone(), || text(&summary));
    Ok(())
}

/// Reads and builds an `import api` document, recording where it came from.
pub(crate) fn load_api(fetch: &Fetcher<'_>, source: &str, mut opts: api::Options) -> Result<api::Loaded, Error> {
    let (text, spec_url) = fetch.document(source)?;
    opts.spec_url = spec_url;
    api::load(&text, &opts)
}

/// Builds requests from what a GraphQL endpoint says of itself, when it will.
pub(crate) fn load_graphql_endpoint(
    fetch: &Fetcher<'_>,
    url: &str,
    mut opts: api::Options,
) -> Result<api::Loaded, Error> {
    if !is_url(url) {
        return Err(Error::InvalidInput(
            "--graphql needs the endpoint's http(s) URL; a schema file goes without it".into(),
        ));
    }
    let text = fetch.introspect(url).map_err(|e| {
        Error::InvalidInput(format!(
            "the endpoint wouldn't describe itself ({e}). If introspection is off or needs a login, use a schema file \
             with --base-url, or --auth"
        ))
    })?;
    opts.spec_url = Some(url.to_string());
    api::load(&text, &opts)
}

/// Reads an environment file. A path, never a URL: it holds secrets. Through MCP only a file
/// in the project's folder (see [`crate::mcp::local_document`]).
pub(crate) fn read_environment(project: &Path, path: &str) -> Result<String, Error> {
    if is_url(path) || path == "-" {
        return Err(Error::InvalidInput("--environment must be a local file".into()));
    }
    let file = crate::mcp::local_document(project, "--environment", path)?;
    std::fs::read_to_string(file).map_err(|_| Error::InvalidInput(format!("can't read the environment file {path:?}")))
}

pub(crate) fn selection(include_methods: &[String], only: Option<Vec<usize>>) -> api::Selection {
    api::Selection { include_methods: include_methods.iter().map(|m| m.trim().to_ascii_uppercase()).collect(), only }
}

pub(crate) fn parse_vars(vars: &[String]) -> Result<Vec<(String, String)>, Error> {
    vars.iter()
        .map(|v| {
            // Not the whole argument: its value may be a credential.
            let name = v.split('=').next().unwrap_or_default();
            v.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| Error::InvalidInput(format!("--var {name:?} must look like NAME=VALUE")))
        })
        .collect()
}

/// The job table stores a background job's arguments, so credentials can't be among them.
pub(crate) fn check_background_args(vars: &[(String, String)], headers: &[String]) -> Result<(), Error> {
    if let Some((k, _)) = vars.iter().find(|(k, _)| apiimport::looks_secret(k)) {
        return Err(Error::InvalidInput(format!(
            "--var {k} looks like a credential and --background would store it with the job; use an auth profile"
        )));
    }
    for h in headers {
        let name = h.split(':').next().unwrap_or_default().trim();
        if apiimport::looks_secret(name) {
            return Err(Error::InvalidInput(format!(
                "-H {name} looks like a credential and --background would store it with the job; use an auth profile"
            )));
        }
    }
    Ok(())
}

/// As `check_background_args`, for a --var only the document shows to be a credential.
pub(crate) fn check_background_doc(loaded: &api::Loaded) -> Result<(), Error> {
    match loaded.variables.iter().find(|v| v.secret && v.source == "cli") {
        Some(v) => Err(Error::InvalidInput(format!(
            "--var {} holds a credential in this document and --background would store it with the job; use an auth profile",
            v.name
        ))),
        None => Ok(()),
    }
}

/// How the command itself would fetch a remote document.
pub(crate) struct RemoteFetch<'a> {
    pub auth: Option<&'a str>,
    pub headers: &'a [(String, String)],
    pub tool: Tool,
    pub timeout: f64,
    pub verify_tls: bool,
    /// The source is a GraphQL endpoint, where --var doesn't apply.
    pub graphql: bool,
}

/// Which `--var` may go in the job table depends on the document, so a remote one that
/// has any is fetched first (not kept), and a fetch that fails refuses them too.
pub(crate) fn check_remote_vars(
    project: &Path,
    guard: &Arc<Guard>,
    source: &str,
    opts: api::Options,
    from: RemoteFetch<'_>,
) -> Result<(), Error> {
    if opts.vars.is_empty() || from.graphql {
        return Ok(());
    }
    let send = SendOptions {
        timeout: Duration::from_secs_f64(from.timeout.max(0.1)),
        verify_tls: from.verify_tls,
        sni: None,
        guard: Some(guard.clone()),
        http2: false,
        host: brainproxy_core::http::client::HostPolicy::for_process(false),
    };
    let auth = crate::auth_cmd::maybe_session(project, from.auth, &send)?;
    let fetch = Fetcher { project, send: &send, auth: auth.as_deref(), headers: from.headers, tool: from.tool };
    check_background_doc(&load_api(&fetch, source, opts)?)
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
        v.get("skipped_destructive").cloned().unwrap_or(json!(0)),
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
    for r in v["skipped"].as_array().into_iter().flatten().take(20) {
        lines.push(format!(
            "  skipped: {}: {}",
            r["operation"].as_str().unwrap_or(""),
            r["reason"].as_str().unwrap_or("")
        ));
    }
    for w in v["warnings"].as_array().into_iter().flatten().take(20) {
        lines.push(format!("  warning: {}", w.as_str().unwrap_or("")));
    }
    lines.join("\n")
}

pub(crate) fn is_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://")
}

/// Parses a document. Through MCP a parse error says only where (line and column), never
/// quoting the text: an agent could otherwise read a file of secrets back line by line.
fn parse_doc(text: &str) -> Result<serde_json::Value, Error> {
    if crate::mcp::in_tool_call() {
        apiimport::parse_document_unquoted(text)
    } else {
        apiimport::parse_document(text)
    }
}

/// Reads a local document, or stdin for `-`. Through MCP only a file in the project's folder
/// (see [`crate::mcp::local_document`]).
pub(crate) fn read_local(project: &Path, source: &str) -> Result<String, Error> {
    let bytes = if source == "-" {
        crate::read_input(None)?
    } else {
        let path = crate::mcp::local_document(project, "the document", source)?;
        let meta = std::fs::metadata(&path).map_err(|e| Error::InvalidInput(format!("cannot read {source:?}: {e}")))?;
        // A HAR file may be larger than other documents; `api::load` holds those to their limit.
        if meta.len() as usize > har::MAX_HAR {
            return Err(Error::InvalidInput(format!("{source:?} is larger than {} MiB", har::MAX_HAR >> 20)));
        }
        std::fs::read(&path).map_err(|e| Error::InvalidInput(format!("cannot read {source:?}: {e}")))?
    };
    String::from_utf8(bytes).map_err(|_| Error::InvalidInput(format!("{source:?} is not UTF-8 text")))
}

/// Fetches specs and introspection results through the guarded client. Each fetch is
/// recorded in history (source `import`) as it is sent, like any other request: the row is
/// written before it goes out and completed when it is answered or fails.
pub(crate) struct Fetcher<'a> {
    pub project: &'a Path,
    pub send: &'a SendOptions,
    pub auth: Option<&'a AuthSession>,
    pub headers: &'a [(String, String)],
    /// Whose session rules apply to the fetch.
    pub tool: Tool,
}

impl Fetcher<'_> {
    /// Returns the document text and, for URLs, the URL it came from.
    fn document(&self, source: &str) -> Result<(String, Option<String>), Error> {
        if !is_url(source) {
            return Ok((read_local(self.project, source)?, None));
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
        let client = Client::new(self.send.clone());
        let mut log = crate::sent::SentLog::open(self.project, apiimport::SOURCE, false)?
            .without_response_body(brainproxy_core::sent::DOCUMENT_OMITTED);
        // Each request (a lost session's retry too) is on record before it goes out. `open` is
        // the one out and unanswered; a row answered already is never rewritten.
        let mut open: Option<(i64, Vec<u8>)> = None;
        let sent = {
            let (log, open) = (&mut log, &mut open);
            let sending = |log: &mut crate::sent::SentLog, open: &mut Option<_>, r: &RawRequest| {
                let recorded = client.recorded_request(r, &target)?;
                *open = Some((log.pending(&target, &recorded)?, recorded));
                Ok::<_, Error>(())
            };
            match self.auth {
                Some(a) => {
                    let watch = |at: Attempt<'_>| match at {
                        Attempt::Sending(r) => sending(log, open, r),
                        Attempt::Answered(ex) => match open.take() {
                            Some((id, _)) => log.answered(id, ex),
                            None => Ok(()),
                        },
                    };
                    rt.block_on(a.send_as_watched(self.tool, &req, &target, watch))
                }
                None => {
                    sending(log, open, &req)?;
                    let r = rt.block_on(client.send(&req, &target));
                    if let Ok(ex) = &r {
                        if let Some((id, _)) = open.take() {
                            log.answered(id, ex)?;
                        }
                    }
                    r
                }
            }
        };
        let ex = match (sent, open) {
            (Ok(ex), None) => ex,
            (Ok(_), Some(_)) => unreachable!("an answer completes its row"),
            (Err(e), Some((id, recorded))) => {
                log.failed(id, &target, &recorded, &e.to_string())?;
                return Err(e);
            }
            (Err(e), None) => return Err(e),
        };
        let head = parse_response_head(&ex.response)?;
        let body = decode_body(&head.headers, split_head_body(&ex.response).1);
        if body.len() > har::MAX_HAR {
            return Err(Error::InvalidInput(format!("{url} returned more than {} MiB", har::MAX_HAR >> 20)));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_stay_out_of_arguments_and_messages() {
        assert!(api::check_source("spec.yaml").is_ok() && api::check_source("https://a.test/spec?v=1").is_ok());
        let e = api::check_source("https://u:SECRET@a.test/spec").unwrap_err().to_string();
        assert!(!e.contains("SECRET"), "{e}");
        let e = api::check_source("https://a.test/spec?api_key=SECRET").unwrap_err().to_string();
        assert!(e.contains("api_key") && !e.contains("SECRET"), "{e}");
        let vars = parse_vars(&["tenant=a".into()]).unwrap();
        assert!(check_background_args(&vars, &["X-Trace: 1".into()]).is_ok());
        let vars = parse_vars(&["apiKey=SECRET".into()]).unwrap();
        let e = check_background_args(&vars, &[]).unwrap_err().to_string();
        assert!(e.contains("apiKey") && !e.contains("SECRET"), "{e}");
        let e = check_background_args(&[], &["Authorization: SECRET".into()]).unwrap_err().to_string();
        assert!(e.contains("Authorization") && !e.contains("SECRET"), "{e}");
        assert!(!parse_vars(&["noequals".into()]).is_ok());
    }
}
