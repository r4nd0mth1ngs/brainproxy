//! brainproxy CLI. Every feature is reachable non-interactively; see
//! `brainproxy capabilities` for the machine-readable command list.

mod capabilities;
mod output;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use brainproxy_core::capture::decode_body;
use brainproxy_core::codec;
use brainproxy_core::http::request::split_head_body;
use brainproxy_core::http::{parse_response_head, Client, RawRequest, SendOptions, Target};
use brainproxy_core::store::{self, HistoryFilter, Store};
use brainproxy_core::Error;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};

use output::{body_value, Format, Out};

#[derive(Parser)]
#[command(name = "brainproxy", version, about = "AI-first, non-interactive web security testing toolkit")]
struct Cli {
    /// Project file (SQLite). Created on first use.
    #[arg(long, global = true, env = "BRAINPROXY_PROJECT", default_value = "brainproxy.bpdb")]
    project: PathBuf,

    /// Output format.
    #[arg(long, global = true, env = "BRAINPROXY_FORMAT", value_enum, default_value = "auto")]
    format: Format,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Describe every command, flag, exit code, and convention as JSON.
    Capabilities {
        /// Only describe this command, e.g. "send" or "history list".
        command: Vec<String>,
    },

    /// Describe the capture database: tables, columns, SQL functions, and example queries.
    Schema,

    /// Run one read-only SQL statement against the capture database.
    #[command(after_help = "The database is opened read-only, so any SQL is safe. Run `schema` for the \
        tables, columns, helper functions (header, regexp, regexp_extract), and example queries.")]
    Query(QueryArgs),

    /// Manage the project file.
    #[command(subcommand)]
    Project(ProjectCmd),

    /// Send one HTTP request and record it in history (Repeater).
    #[command(after_help = "Request sources, in order: --url (build a request like curl), FILE, or stdin. \
        Raw requests are sent byte-for-byte after optional line-ending normalization and Content-Length update.")]
    Send(SendArgs),

    /// Browse recorded requests and responses.
    #[command(subcommand)]
    History(HistoryCmd),

    /// Encode input. Chain encodings with commas, applied left to right (e.g. url,base64).
    Encode(CodecArgs),

    /// Decode input. Chain decodings with commas, applied left to right.
    Decode(CodecArgs),

    /// Hash input.
    Hash(CodecArgs),
}

#[derive(Subcommand)]
enum ProjectCmd {
    /// Create the project file if missing and report its location.
    Init,
    /// Show project statistics.
    Info,
}

#[derive(clap::Args)]
struct SendArgs {
    /// Raw HTTP request file; '-' or omitted reads stdin (unless --url is given).
    file: Option<String>,

    /// Build the request from a URL instead of a raw file.
    #[arg(long)]
    url: Option<String>,
    /// Method for --url.
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,
    /// Header for --url requests, or set on a raw request ("Name: value"). Repeatable.
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// Body for --url requests.
    #[arg(short = 'd', long)]
    data: Option<String>,

    /// Where to send a raw request (scheme://host[:port]). Defaults to the Host header.
    #[arg(long)]
    target: Option<String>,
    /// Scheme used with the Host header when --target is not given.
    #[arg(long, default_value = "https", value_parser = ["http", "https"])]
    scheme: String,
    /// Remove a header from the request. Repeatable.
    #[arg(long)]
    remove_header: Vec<String>,
    /// Send bytes exactly as given: no line-ending normalization, no Content-Length update.
    #[arg(long)]
    verbatim: bool,

    /// Timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    /// Verify the server certificate (off by default, as with most intercepting tools).
    #[arg(long)]
    verify_tls: bool,
    /// Override the TLS SNI host name.
    #[arg(long)]
    sni: Option<String>,
    /// Don't record the exchange in history.
    #[arg(long)]
    no_store: bool,
    /// Maximum response body bytes to include in output.
    #[arg(long, default_value_t = 65536)]
    max_body: usize,
    /// Include the request as sent in the output.
    #[arg(long)]
    show_request: bool,
    /// Print the raw response bytes instead of structured output.
    #[arg(long)]
    raw: bool,
}

#[derive(clap::Args)]
struct QueryArgs {
    /// SQL statement; '-' or omitted reads stdin.
    sql: Option<String>,
    /// Bind a value to ?1, ?2, ... in order. Repeatable. Avoids quoting problems.
    #[arg(short = 'p', long = "param")]
    params: Vec<String>,
    /// Maximum rows to return; `truncated` is true when more exist.
    #[arg(long, default_value_t = 200)]
    limit: usize,
    /// Maximum bytes per cell before it is cut off.
    #[arg(long, default_value_t = 2000)]
    max_cell: usize,
    /// rows: {columns, rows:[[...]]} (compact). objects: rows as [{column: value}].
    #[arg(long, value_enum, default_value = "rows")]
    shape: Shape,
}

#[derive(Clone, Copy, ValueEnum)]
enum Shape {
    Rows,
    Objects,
}

#[derive(Subcommand)]
enum HistoryCmd {
    /// List history entries (metadata only).
    List {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        status: Option<u16>,
        /// Tool that produced the entry (e.g. send, proxy).
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        /// Substring to search for in raw requests and responses.
        #[arg(long)]
        contains: Option<String>,
        /// Only entries with an id greater than this (for incremental polling).
        #[arg(long)]
        after: Option<i64>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Show one entry with its request and response.
    Show {
        id: i64,
        /// Which part to print with --raw. response-body is decoded (no chunking or compression).
        #[arg(long, value_enum, default_value = "response")]
        part: Part,
        /// Print the selected part as raw bytes (pipe a request back into `send`).
        #[arg(long)]
        raw: bool,
        /// Maximum body bytes to include in structured output.
        #[arg(long, default_value_t = 65536)]
        max_body: usize,
    },
    /// Attach a note to an entry; omit TEXT to clear it.
    Note { id: i64, text: Option<String> },
    /// Add or remove tags on an entry.
    Tag {
        id: i64,
        /// Tag to add. Repeatable.
        #[arg(long)]
        add: Vec<String>,
        /// Tag to remove. Repeatable.
        #[arg(long)]
        remove: Vec<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Part {
    Request,
    Response,
    ResponseBody,
}

#[derive(clap::Args)]
struct CodecArgs {
    /// Comma-separated codec chain (see `capabilities` for names).
    kind: String,
    /// Input text; '-' or omitted reads stdin.
    input: Option<String>,
    /// Print the raw result bytes with no envelope or trailing newline.
    #[arg(long)]
    raw: bool,
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let cli = match Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                e.exit();
            }
            let out = Out { format: Format::sniff(&argv), command: argv.get(1).cloned().unwrap_or_default() };
            if out.json() {
                out.error("usage", e.render().to_string().trim());
            } else {
                let _ = e.print();
            }
            std::process::exit(2);
        }
    };
    let out = Out { format: cli.format.resolve(), command: command_name(&cli.command) };
    if let Err(e) = run(cli, &out) {
        out.error(e.kind(), &e.to_string());
        std::process::exit(e.exit_code());
    }
}

fn command_name(cmd: &Cmd) -> String {
    match cmd {
        Cmd::Capabilities { .. } => "capabilities",
        Cmd::Schema => "schema",
        Cmd::Query(_) => "query",
        Cmd::Project(ProjectCmd::Init) => "project init",
        Cmd::Project(ProjectCmd::Info) => "project info",
        Cmd::Send(_) => "send",
        Cmd::History(HistoryCmd::List { .. }) => "history list",
        Cmd::History(HistoryCmd::Show { .. }) => "history show",
        Cmd::History(HistoryCmd::Note { .. }) => "history note",
        Cmd::History(HistoryCmd::Tag { .. }) => "history tag",
        Cmd::Encode(_) => "encode",
        Cmd::Decode(_) => "decode",
        Cmd::Hash(_) => "hash",
    }
    .to_string()
}

fn run(cli: Cli, out: &Out) -> Result<(), Error> {
    match cli.command {
        Cmd::Capabilities { command } => {
            let v = if command.is_empty() {
                capabilities::describe(&Cli::command())
            } else {
                let path = command.join(" ");
                capabilities::describe_one(&Cli::command(), &path)
                    .ok_or_else(|| Error::NotFound(format!("command {path:?}")))?
            };
            out.ok(v.clone(), || serde_json::to_string_pretty(&v).unwrap_or_default());
        }
        Cmd::Schema => {
            let v = schema_json();
            out.ok(v.clone(), || serde_json::to_string_pretty(&v).unwrap_or_default());
        }
        Cmd::Query(args) => query(&cli.project, args, out)?,
        Cmd::Project(cmd) => {
            let store = Store::open(&cli.project)?;
            let path = std::fs::canonicalize(&cli.project).unwrap_or(cli.project.clone());
            let count = store.count()?;
            let data = json!({"path": path, "history_count": count});
            match cmd {
                ProjectCmd::Init => out.ok(data, || format!("project ready: {}", path.display())),
                ProjectCmd::Info => out.ok(data, || format!("{}\nhistory entries: {count}", path.display())),
            }
        }
        Cmd::Send(args) => send(&cli.project, args, out)?,
        Cmd::History(cmd) => history(&cli.project, cmd, out)?,
        Cmd::Encode(a) => codec_cmd(a, out, codec::encode)?,
        Cmd::Decode(a) => codec_cmd(a, out, codec::decode)?,
        Cmd::Hash(a) => codec_cmd(a, out, |k, b| codec::hash(k, b).map(String::into_bytes))?,
    }
    Ok(())
}

fn read_input(arg: Option<&str>) -> Result<Vec<u8>, Error> {
    match arg {
        Some(s) if s != "-" => Ok(s.as_bytes().to_vec()),
        _ => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn parse_header(h: &str) -> Result<(String, String), Error> {
    h.split_once(':')
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .ok_or_else(|| Error::InvalidInput(format!("header {h:?} must look like 'Name: value'")))
}

fn send(project: &Path, args: SendArgs, out: &Out) -> Result<(), Error> {
    let headers = args.headers.iter().map(|h| parse_header(h)).collect::<Result<Vec<_>, _>>()?;

    let (mut req, inferred) = if let Some(url) = &args.url {
        let (req, target) =
            RawRequest::build(&args.method, url, &headers, args.data.as_deref().unwrap_or("").as_bytes())?;
        (req, Some(target))
    } else {
        let bytes = match args.file.as_deref() {
            Some(path) if path != "-" => std::fs::read(path)
                .map_err(|e| Error::InvalidInput(format!("cannot read request file {path:?}: {e}")))?,
            _ => read_input(None)?,
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Err(Error::InvalidInput("empty request; pass a FILE, stdin, or --url".into()));
        }
        let mut req = RawRequest::from_bytes(bytes);
        if !args.verbatim {
            req = req.normalize_line_endings();
        }
        for (k, v) in &headers {
            req = req.set_header(k, v);
        }
        (req, None)
    };
    for name in &args.remove_header {
        req = req.remove_header(name);
    }
    if !args.verbatim {
        req = req.update_content_length();
    }

    let target = match (&args.target, inferred) {
        (Some(t), _) => Target::from_url(t)?,
        (None, Some(t)) => t,
        (None, None) => req.infer_target(&args.scheme)?,
    };

    let client = Client::new(SendOptions {
        timeout: Duration::from_secs_f64(args.timeout.max(0.001)),
        verify_tls: args.verify_tls,
        sni: args.sni.clone(),
    });
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(Error::Io)?;
    let result = rt.block_on(client.send(&req, &target));

    let store = if args.no_store { None } else { Some(Store::open(project)?) };
    let ex = match result {
        Ok(ex) => ex,
        Err(e) => {
            if let Some(s) = &store {
                s.record_failure("send", &target, req.as_bytes(), &e.to_string())?;
            }
            return Err(e);
        }
    };
    let id = match &store {
        Some(s) => Some(s.record_exchange("send", &ex)?),
        None => None,
    };

    if args.raw {
        out.raw(&ex.response);
        return Ok(());
    }
    let mut data = exchange_json(id, &target, &ex.request, &ex.response, Some(ex.duration_ms), args.max_body);
    if args.show_request {
        data["request"] = body_value(&ex.request, args.max_body);
    }
    out.ok(data, || text_exchange(id, &ex.response, ex.duration_ms));
    Ok(())
}

fn query(project: &Path, args: QueryArgs, out: &Out) -> Result<(), Error> {
    let sql = String::from_utf8(read_input(args.sql.as_deref())?)
        .map_err(|_| Error::InvalidInput("SQL must be UTF-8".into()))?;
    // Make sure the project exists and is migrated before opening it read-only.
    drop(Store::open(project)?);
    let store = Store::open_read_only(project)?;
    let r = store.query(sql.trim(), &args.params, args.limit, args.max_cell)?;
    let data = match args.shape {
        Shape::Rows => json!(r),
        Shape::Objects => {
            let rows: Vec<Value> = r
                .rows
                .iter()
                .map(|row| Value::Object(r.columns.iter().cloned().zip(row.iter().cloned()).collect()))
                .collect();
            json!({"rows": rows, "row_count": r.row_count, "truncated": r.truncated})
        }
    };
    out.ok(data, || {
        let cell = |v: &Value| match v {
            Value::String(s) => s.replace(['\t', '\n', '\r'], " "),
            Value::Null => "NULL".into(),
            other => other.to_string(),
        };
        let mut lines = vec![r.columns.join("\t")];
        lines.extend(r.rows.iter().map(|row| row.iter().map(cell).collect::<Vec<_>>().join("\t")));
        if r.truncated {
            lines.push(format!("... more rows; raise --limit (showing {})", r.row_count));
        }
        lines.join("\n")
    });
    Ok(())
}

fn schema_json() -> Value {
    let cols = |list: &[(&str, &str, &str)]| -> Vec<Value> {
        list.iter().map(|(n, t, d)| json!({"name": n, "type": t, "description": d})).collect()
    };
    json!({
        "tables": [
            {"name": "history", "description": "One row per request sent or proxied.", "columns": cols(store::HISTORY_COLUMNS)},
            {"name": "history_fts", "description": "FTS5 full-text index over url, req_headers, req_body_text, resp_headers, resp_body_text. rowid = history.id. Query with: WHERE history_fts MATCH 'term'."},
        ],
        "functions": store::FUNCTIONS.iter().map(|(sig, d)| json!({"signature": sig, "description": d})).collect::<Vec<_>>(),
        "examples": store::EXAMPLES.iter().map(|(t, q)| json!({"title": t, "sql": q})).collect::<Vec<_>>(),
        "notes": [
            "query opens the database read-only; writes fail.",
            "Prefer *_text columns for searching; they are NULL for binary bodies.",
            "Bind values with -p/--param and ?1, ?2 instead of quoting them into SQL.",
        ],
    })
}

fn response_json(response: &[u8], max_body: usize) -> Value {
    let Ok(head) = parse_response_head(response) else {
        return json!({"parse_error": true, "raw": body_value(response, max_body)});
    };
    let body = decode_body(&head.headers, split_head_body(response).1);
    json!({
        "status": head.status,
        "reason": head.reason,
        "headers": head.headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>(),
        "body": body_value(&body, max_body),
        "raw_length": response.len(),
    })
}

fn exchange_json(
    id: Option<i64>,
    target: &Target,
    request: &[u8],
    response: &[u8],
    duration_ms: Option<u64>,
    max_body: usize,
) -> Value {
    let url = RawRequest::from_bytes(request.to_vec())
        .head()
        .map(|h| if h.target.contains("://") { h.target } else { format!("{}{}", target.origin(), h.target) })
        .unwrap_or_else(|_| target.origin());
    json!({
        "id": id,
        "url": url,
        "duration_ms": duration_ms,
        "response": response_json(response, max_body),
    })
}

fn text_exchange(id: Option<i64>, response: &[u8], ms: u64) -> String {
    let status =
        parse_response_head(response).map(|h| format!("{} {}", h.status, h.reason)).unwrap_or_else(|_| "?".into());
    let id = id.map(|i| format!("#{i} ")).unwrap_or_default();
    format!("{id}{status} ({} bytes, {ms} ms)\n\n{}", response.len(), String::from_utf8_lossy(response))
}

fn history(project: &Path, cmd: HistoryCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        HistoryCmd::List { host, method, status, source, tag, contains, after, limit } => {
            let items = store.list(&HistoryFilter {
                host,
                method,
                status,
                source,
                tag,
                contains,
                after_id: after,
                limit: Some(limit),
            })?;
            let data = json!({"count": items.len(), "items": items});
            out.ok(data, || {
                items
                    .iter()
                    .map(|e| {
                        let status = e.status.map(|s| s.to_string()).unwrap_or_else(|| "ERR".into());
                        let len = e.resp_body_length.unwrap_or(0);
                        format!("{:>6}  {:<4} {:<7} {}  {len}B", e.id, status, e.method, e.url)
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        HistoryCmd::Show { id, part, raw, max_body } => {
            let item = store.get(id)?;
            if raw {
                let bytes = match part {
                    Part::Request => item.request,
                    Part::Response => item.response,
                    Part::ResponseBody => item.resp_body.unwrap_or_default(),
                };
                out.raw(&bytes);
                return Ok(());
            }
            let mut data = exchange_json(
                Some(id),
                &item.target,
                &item.request,
                &item.response,
                item.entry.duration_ms.map(|d| d as u64),
                max_body,
            );
            data["request"] = body_value(&item.request, max_body);
            data["entry"] = json!(item.entry);
            out.ok(data, || {
                format!("{}\n\n{}", String::from_utf8_lossy(&item.request), String::from_utf8_lossy(&item.response))
            });
        }
        HistoryCmd::Note { id, text } => {
            store.set_note(id, text.as_deref())?;
            out.ok(json!({"id": id, "note": text}), || format!("note updated on #{id}"));
        }
        HistoryCmd::Tag { id, add, remove } => {
            let tags = store.update_tags(id, &add, &remove)?;
            out.ok(json!({"id": id, "tags": tags}), || format!("#{id} tags: {}", tags.join(", ")));
        }
    }
    Ok(())
}

fn codec_cmd(a: CodecArgs, out: &Out, f: impl Fn(&str, &[u8]) -> Result<Vec<u8>, Error>) -> Result<(), Error> {
    let input = read_input(a.input.as_deref())?;
    let mut value = input;
    for kind in a.kind.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        value = f(kind, &value)?;
    }
    if a.raw {
        out.raw(&value);
        return Ok(());
    }
    let data = json!({"chain": a.kind, "output": body_value(&value, usize::MAX)});
    out.ok(data, || String::from_utf8_lossy(&value).into_owned());
    Ok(())
}
