//! Braintruder CLI. Every feature is reachable non-interactively; see
//! `braintruder capabilities` for the machine-readable command list.

mod capabilities;
mod output;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use braintruder_core::codec;
use braintruder_core::http::{dechunk, parse_response_head, Client, RawRequest, SendOptions, Target};
use braintruder_core::store::{HistoryFilter, Store};
use braintruder_core::Error;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};

use output::{body_value, Format, Out};

#[derive(Parser)]
#[command(name = "braintruder", version, about = "AI-first, non-interactive web security testing toolkit")]
struct Cli {
    /// Project file (SQLite). Created on first use.
    #[arg(long, global = true, env = "BRAINTRUDER_PROJECT", default_value = "braintruder.btdb")]
    project: PathBuf,

    /// Output format.
    #[arg(long, global = true, env = "BRAINTRUDER_FORMAT", value_enum, default_value = "auto")]
    format: Format,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Describe every command, flag, exit code, and convention as JSON.
    Capabilities,

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
    /// Print the raw response bytes instead of structured output.
    #[arg(long)]
    raw: bool,
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
        /// Which part to print with --raw.
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
        Cmd::Capabilities => "capabilities",
        Cmd::Project(ProjectCmd::Init) => "project init",
        Cmd::Project(ProjectCmd::Info) => "project info",
        Cmd::Send(_) => "send",
        Cmd::History(HistoryCmd::List { .. }) => "history list",
        Cmd::History(HistoryCmd::Show { .. }) => "history show",
        Cmd::History(HistoryCmd::Note { .. }) => "history note",
        Cmd::Encode(_) => "encode",
        Cmd::Decode(_) => "decode",
        Cmd::Hash(_) => "hash",
    }
    .to_string()
}

fn run(cli: Cli, out: &Out) -> Result<(), Error> {
    match cli.command {
        Cmd::Capabilities => {
            let v = capabilities::describe(&Cli::command());
            out.ok(v.clone(), || serde_json::to_string_pretty(&v).unwrap_or_default());
        }
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
    let data = exchange_json(id, &target, &ex.request, &ex.response, Some(ex.duration_ms), args.max_body);
    out.ok(data, || text_exchange(id, &ex.response, ex.duration_ms));
    Ok(())
}

fn response_json(response: &[u8], max_body: usize) -> Value {
    let Ok(head) = parse_response_head(response) else {
        return json!({"parse_error": true, "raw": body_value(response, max_body)});
    };
    let (_, body) = braintruder_core::http::request::split_head_body(response);
    let chunked = head.header("transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false);
    let body = if chunked { dechunk(body) } else { body.to_vec() };
    json!({
        "status": head.status,
        "reason": head.reason,
        "version": head.version,
        "headers": head.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "body": body_value(&body, max_body),
        "length": response.len(),
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
    json!({
        "id": id,
        "target": target.origin(),
        "duration_ms": duration_ms,
        "request": body_value(request, max_body),
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
        HistoryCmd::List { host, method, status, source, contains, after, limit } => {
            let items = store.list(&HistoryFilter {
                host,
                method,
                status,
                source,
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
                        format!(
                            "{:>6}  {:<4} {:<7} {}://{}:{}{}  {}B",
                            e.id, status, e.method, e.scheme, e.host, e.port, e.path, e.response_length
                        )
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
                    Part::ResponseBody => {
                        let (_, body) = braintruder_core::http::request::split_head_body(&item.response);
                        let chunked = parse_response_head(&item.response)
                            .ok()
                            .and_then(|h| {
                                h.header("transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked"))
                            })
                            .unwrap_or(false);
                        if chunked {
                            dechunk(body)
                        } else {
                            body.to_vec()
                        }
                    }
                };
                out.raw(&bytes);
                return Ok(());
            }
            let target =
                Target { scheme: item.entry.scheme.clone(), host: item.entry.host.clone(), port: item.entry.port };
            let mut data = exchange_json(
                Some(id),
                &target,
                &item.request,
                &item.response,
                item.entry.duration_ms.map(|d| d as u64),
                max_body,
            );
            data["entry"] = json!(item.entry);
            out.ok(data, || {
                format!("{}\n\n{}", String::from_utf8_lossy(&item.request), String::from_utf8_lossy(&item.response))
            });
        }
        HistoryCmd::Note { id, text } => {
            store.set_note(id, text.as_deref())?;
            out.ok(json!({"id": id, "note": text}), || format!("note updated on #{id}"));
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
