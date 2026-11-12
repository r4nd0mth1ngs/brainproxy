//! brainproxy CLI. Every feature is reachable non-interactively; see
//! `brainproxy capabilities` for the machine-readable command list.

mod active_cmd;
mod auth_cmd;
mod authz_cmd;
mod browser_cmd;
mod capabilities;
mod checks_cmd;
mod compare_cmd;
mod connection_cmd;
mod crawl_cmd;
mod engagement_cmd;
mod filters_cmd;
mod fuzz_cmd;
mod history_export;
mod import_cmd;
mod jobs_cmd;
mod mcp;
mod oob_cmd;
mod output;
mod policy_cmd;
mod process;
mod project_cmd;
mod proxy_cmd;
mod replay_cmd;
mod report_cmd;
mod request_args;
mod retest_cmd;
mod scan_cmd;
mod sent;
mod sse_cmd;
mod update_cmd;
mod ws_cmd;

use std::io::Read;
use std::path::{Path, PathBuf};

use brainproxy_core::auth::Attempt;
use brainproxy_core::capture::decode_body;
use brainproxy_core::codec;
use brainproxy_core::http::request::split_head_body;
use brainproxy_core::http::{parse_response_head, Client, RawRequest, Target};
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

    /// Directory for per-user data such as the CA (default: ~/.local/share/brainproxy).
    #[arg(long, global = true, env = "BRAINPROXY_HOME")]
    home: Option<PathBuf>,

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

    /// Engagement scope: set once with `engagement start`; every outbound request must match it.
    #[command(subcommand)]
    Engagement(engagement_cmd::EngagementCmd),

    /// Login profiles and sessions; use one with `--auth NAME` on send, fuzz, crawl, scan active, proxy.
    #[command(subcommand)]
    Auth(auth_cmd::AuthCmd),

    /// Access-control testing: re-send recorded requests as other auth profiles and without
    /// a session, and compare with the owner's responses (IDOR, missing authorization).
    #[command(subcommand)]
    Authz(authz_cmd::AuthzCmd),

    /// Manage the project file.
    #[command(subcommand)]
    Project(project_cmd::ProjectCmd),

    /// Send an HTTP request or race a group, recording it in history (Repeater).
    #[command(after_help = "Request sources, in order: --url (build a request like curl), FILE, or stdin. \
        Raw requests are sent byte-for-byte after optional line-ending normalization and Content-Length update.")]
    Send(SendArgs),

    /// Replay tabs saved in the project, which the app restores when the project opens.
    #[command(subcommand)]
    Replay(replay_cmd::ReplayCmd),

    /// Run the intercepting proxy (background by default) and see its status.
    #[command(subcommand)]
    Proxy(proxy_cmd::ProxyCmd),

    /// Manage the interception CA that clients must trust.
    #[command(subcommand)]
    Ca(proxy_cmd::CaCmd),

    /// Open a locally installed browser through the proxy, in its own profile.
    #[command(subcommand)]
    Browser(browser_cmd::BrowserCmd),

    /// Connection options for every outbound request: upstream proxies (HTTP/SOCKS5), host overrides,
    /// client TLS certificates, and the proxy's TLS pass-through hosts.
    #[command(subcommand)]
    Connection(connection_cmd::ConnectionCmd),

    /// Which hosts the proxy intercepts, modifies, and records.
    #[command(subcommand)]
    Scope(proxy_cmd::ScopeCmd),

    /// Match-and-replace rules: applied to in-scope proxy traffic and, where a rule says so, to send, fuzz and scan requests
    /// and to WebSocket messages; `rules test` tries them without sending anything.
    #[command(subcommand)]
    Rules(proxy_cmd::RulesCmd),

    /// Hold proxied requests/responses in a queue to inspect, edit, forward, or drop.
    #[command(
        subcommand,
        after_help = "Typical loop: `intercept enable`, then `intercept list --wait 30`, \
        `intercept show ID --raw > msg.http`, edit, `intercept forward ID --file msg.http` (or `drop ID`)."
    )]
    Intercept(proxy_cmd::InterceptCmd),

    /// WebSocket connections and messages recorded by the proxy, and replay (`ws send`).
    #[command(
        subcommand,
        after_help = "The proxy records every WebSocket connection it relays (the upgrade request is a history \
        entry). Hold messages with `intercept enable --ws-to-server/--ws-to-client`. Search payloads with \
        `query` (tables ws_connections, ws_messages, ws_messages_fts)."
    )]
    Ws(ws_cmd::WsCmd),

    /// Server-sent events: the event streams the proxy relayed or `send` read, and their events.
    #[command(
        subcommand,
        after_help = "A response with Content-Type text/event-stream is a stream of events that may never end. The \
        proxy relays one to the client as it arrives and records it (the request and response are a history entry, \
        which gets the body when the stream ends); `send` reads one for --stream-wait seconds or --max-events \
        events. A stream stores up to 4 MiB of body and 10000 events: one that goes over is marked truncated at once. \
        Search events with `query` (tables sse_streams, sse_events, sse_events_fts)."
    )]
    Sse(sse_cmd::SseCmd),

    /// Intruder-style fuzzing: payload positions, four attack modes, grep/extract, outlier summary.
    #[command(subcommand)]
    Fuzz(fuzz_cmd::FuzzCmd),

    /// Spider a site: links, forms, redirects, robots.txt, sitemap.xml. Results go to history.
    Crawl(crawl_cmd::CrawlArgs),

    /// Import an API description (OpenAPI/Swagger, Postman, GraphQL) as scan targets: requests are
    /// built with example values, sent in scope, and recorded as history source 'import'.
    #[command(subcommand)]
    Import(import_cmd::ImportCmd),

    /// Out-of-band callback listener (HTTP/LDAP/TLS/DNS) to confirm blind issues; payloads and polling.
    #[command(
        subcommand,
        after_help = "Active rules with out-of-band checks (Log4Shell 40043, SSRF 40046, XXE 90023, blind SSTI 90036) use the \
        listener automatically while it runs. Behind NAT set --public-host/--public-port (and --domain with \
        --dns-listen for DNS callbacks)."
    )]
    Oob(oob_cmd::OobCmd),

    /// Declarative checks: Nuclei HTTP templates and your own YAML checks, run with `scan active --checks`.
    #[command(
        subcommand,
        after_help = "Checks use the HTTP subset of the Nuclei template format plus brainproxy extensions \
        (scope: host|request|param, inject, matcher part baseline_body); see docs/CHECKS.md. Templates outside \
        the subset are listed as not loaded, never half-run. Put your own checks in <home>/checks/local."
    )]
    Checks(checks_cmd::ChecksCmd),

    /// Newer brainproxy releases: check GitHub, download the installer or binary (verified).
    #[command(subcommand)]
    Update(update_cmd::UpdateCmd),

    /// Background jobs (crawl/scan/import --background): list, status, wait, stop.
    #[command(subcommand)]
    Job(jobs_cmd::JobCmd),

    /// Scanners: active scan, passive scan, rules, enable/disable.
    #[command(subcommand)]
    Scan(scan_cmd::ScanCmd),

    /// Findings from the scanners or added by hand: grouped by alert type, per instance, details, triage.
    #[command(subcommand)]
    Findings(scan_cmd::FindingsCmd),

    /// Generate a report from findings: json, markdown, html (self-contained), sarif (2.1.0), pdf,
    /// docx, csv, junit or defectdojo.
    #[command(after_help = "Findings are grouped by alert type with description, solution, references, and the \
        request/response from history as evidence. False positives are left out unless --state asks for them. \
        Use --output FILE for large reports; stdout then only gets a summary.")]
    Report(report_cmd::ReportArgs),

    /// The executive summary at the top of reports: drafted (often by an agent), then reviewed
    /// by a person.
    #[command(subcommand, name = "report-summary")]
    ReportSummary(report_cmd::SummaryCmd),

    /// Saved report layouts (preset, sections, branding) for `report --profile NAME`.
    #[command(subcommand, name = "report-profile")]
    ReportProfile(report_cmd::ProfileCmd),

    /// Compare two history entries (Comparer): line, word, or byte diff.
    Diff(fuzz_cmd::DiffArgs),

    /// Browse recorded requests and responses.
    #[command(subcommand)]
    History(HistoryCmd),

    /// Built-in payload and word lists for fuzzing (fuzz run -p wordlist:NAME).
    #[command(subcommand)]
    Wordlists(fuzz_cmd::WordlistsCmd),

    /// Encode input. Chain encodings with commas, applied left to right (e.g. url,base64).
    Encode(CodecArgs),

    /// Decode input. Chain decodings with commas, applied left to right. `auto` finds and
    /// undoes the layers itself (URL, base64, hex, HTML, JWT, gzip, zlib); `steps` lists them
    /// and `stopped` says why it stopped. Binary output: use --raw.
    Decode(CodecArgs),

    /// Hash input.
    Hash(CodecArgs),

    /// MCP server: the CLI's commands as tools for AI agents (stdio, JSON-RPC 2.0).
    #[command(subcommand)]
    Mcp(mcp::McpCmd),

    #[command(hide = true)]
    Engage,
}

#[derive(clap::Args)]
struct SendArgs {
    #[command(flatten)]
    req: request_args::RequestArgs,

    /// Additional raw request file in the race group. Repeatable; '-' reads stdin once.
    /// Defaults --race to 1. All requests must resolve to the same origin.
    #[arg(long, value_name = "FILE")]
    also: Vec<String>,

    /// Race mode: send each group member N times at once (G*N total), in blocking order. HTTP/1.1: one connection per copy, releasing
    /// the last byte of every request together (last-byte sync). With --http2: one
    /// connection, final frames released in one packet (single-packet attack, total <= 100).
    /// Rows are tagged race:ID, race-sync:..., race-pos:I/N (and race-partial).
    #[arg(long, value_name = "N")]
    race: Option<usize>,
    /// Send with this auth profile's session (cookies/headers; re-login if logged out).
    #[arg(long, value_name = "NAME")]
    auth: Option<String>,
    /// Keep no content in history: each row has only the request line (method, URL), the
    /// time, and the target; its error starts "not stored (--no-store)".
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
    /// Seconds to read an event stream (a text/event-stream response, which may never end)
    /// before stopping, from its head (at most 86400, a day). What arrived is the response.
    /// Not with a race, which reads whole responses.
    #[arg(long, default_value_t = 5.0, value_name = "SECONDS", conflicts_with_all = ["race", "also"])]
    stream_wait: f64,
    /// Stop reading an event stream once this many events have arrived (events that arrive
    /// together with the last one are read too). Not with a race.
    #[arg(long, default_value_t = 100, value_name = "N", value_parser = clap::value_parser!(u32).range(1..),
        conflicts_with_all = ["race", "also"])]
    max_events: u32,
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
    #[command(after_help = filter_notes())]
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
        /// Who or what recorded the entry: gui (the desktop app), cli (a terminal or script), mcp (an
        /// agent through MCP), or unknown (recorded before brainproxy kept it).
        #[arg(long, value_parser = ["gui", "cli", "mcp", "unknown"])]
        origin: Option<String>,
        /// Text to search for in raw requests and responses, and in their decoded bodies (gzip,
        /// deflate, br, chunked). Case-sensitive and literal: the bytes must match as stored,
        /// so URL-encoded (a%40b.com) or JSON-escaped text and HTTP/2's lower-case header names
        /// are searched as they appear.
        #[arg(long)]
        contains: Option<String>,
        /// A query in the filter language, e.g. 'status:5xx AND resp.body:"stack trace"' or
        /// 'host:api.test method=POST NOT path:/health'. FIELD:VALUE contains (ASCII letters in any case),
        /// = equals, != differs, ~ and !~ match a regex, < <= > >= compare numbers and times,
        /// FIELD:* is present; a bare word searches the URL and title. Terms side by side must
        /// all match; AND, OR, NOT (in any case) and parentheses combine them. Fields: see the notes.
        #[arg(long)]
        filter: Option<String>,
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
    /// Export entries as a file another tool reads: HAR 1.2. Chosen as `history list` chooses
    /// them (oldest first, up to --limit), with session secrets masked as in reports.
    #[command(after_help = "Masked by default, as `report` masks them: cookie values, Authorization \
        credentials, API-key headers, token and password parameters in URLs and bodies, JWTs, the project's \
        auth profile secrets, and each such value wherever else it appears; bodies that aren't text are left \
        out (they can't be searched). --no-redact keeps everything as recorded, binary bodies as base64. Each \
        entry's `_brainproxy` holds its history id and source. Without --output the HAR is printed (in JSON \
        mode, under `data.har`). `import har` reads the file back, in this project or another.")]
    Export(history_export::ExportArgs),
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
    /// Saved Traffic filters, kept in the project (the app offers them in Traffic).
    #[command(subcommand)]
    Filters(filters_cmd::FiltersCmd),
}

#[derive(Clone, Copy, ValueEnum)]
enum Part {
    Request,
    Response,
    ResponseBody,
    /// The request before match-and-replace rules changed it (empty when none did).
    OriginalRequest,
    /// The response after match-and-replace rules changed it (empty when none did).
    ModifiedResponse,
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
    // A Postman script signer's run, in a process of its own (see sign_script). Not a
    // command: nothing lists it, and it speaks JSON on stdin and stdout only.
    if argv.get(1).map(String::as_str) == Some("__sign-script") {
        std::process::exit(brainproxy_core::sign_script::child_main());
    }
    if let Ok(exe) = std::env::current_exe() {
        brainproxy_core::sign_script::set_runner(exe, &["__sign-script"]);
    }
    // A last-byte race opens a connection per request; don't stop at a low default soft limit.
    brainproxy_core::race::raise_fd_limit();
    // The command runs on a thread of a known stack size, not the main thread's, which the
    // platform sets: 1 MiB on Windows, too little for clap's parser of every command once a
    // command parses the command line again (`findings compare --scan` reads a scan's).
    let ran = std::thread::Builder::new().name("main".into()).stack_size(STACK).spawn(move || cli_main(argv));
    match ran.map(|t| t.join()) {
        Ok(Ok(())) => {}
        // The panic was printed already; exit as Rust does for one on the main thread.
        Ok(Err(_)) => std::process::exit(101),
        Err(e) => {
            eprintln!("brainproxy: can't start: {e}");
            std::process::exit(1);
        }
    }
}

/// The stack the command runs with: as much as Linux gives a main thread.
const STACK: usize = 8 << 20;

fn cli_main(argv: Vec<String>) {
    let cli = match Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                e.exit();
            }
            let out = Out::new(Format::sniff(&argv), argv.get(1).cloned().unwrap_or_default());
            // `mcp serve` owns stdout for JSON-RPC, so its usage errors go to stderr too.
            let mcp_serve = argv.windows(2).any(|w| w[0] == "mcp" && w[1] == "serve");
            if out.json() && !mcp_serve {
                out.error("usage", e.render().to_string().trim());
            } else {
                let _ = e.print();
            }
            std::process::exit(2);
        }
    };
    // `mcp serve` owns stdout for JSON-RPC: its own error goes to stderr, never as an envelope.
    let format = if matches!(cli.command, Cmd::Mcp(_)) { Format::Text } else { cli.format.resolve() };
    let out = Out::new(format, command_name(&cli.command));
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
        Cmd::Project(c) => match c {
            project_cmd::ProjectCmd::Init => "project init",
            project_cmd::ProjectCmd::Info => "project info",
            project_cmd::ProjectCmd::Save { .. } => "project save",
            project_cmd::ProjectCmd::Stop => "project stop",
        },
        Cmd::Send(_) => "send",
        Cmd::Replay(replay_cmd::ReplayCmd::Tabs(c)) => match c {
            replay_cmd::TabsCmd::List { .. } => "replay tabs list",
            replay_cmd::TabsCmd::Save { .. } => "replay tabs save",
        },
        Cmd::History(HistoryCmd::List { .. }) => "history list",
        Cmd::History(HistoryCmd::Show { .. }) => "history show",
        Cmd::History(HistoryCmd::Export(_)) => "history export",
        Cmd::History(HistoryCmd::Note { .. }) => "history note",
        Cmd::History(HistoryCmd::Tag { .. }) => "history tag",
        Cmd::History(HistoryCmd::Filters(filters_cmd::FiltersCmd::List)) => "history filters list",
        Cmd::History(HistoryCmd::Filters(filters_cmd::FiltersCmd::Save { .. })) => "history filters save",
        Cmd::Proxy(c) => match c {
            proxy_cmd::ProxyCmd::Start(_) => "proxy start",
            proxy_cmd::ProxyCmd::Run(_) => "proxy run",
            proxy_cmd::ProxyCmd::Stop { .. } => "proxy stop",
            proxy_cmd::ProxyCmd::Restart(_) => "proxy restart",
            proxy_cmd::ProxyCmd::Status => "proxy status",
            proxy_cmd::ProxyCmd::Setup(proxy_cmd::SetupCmd::Show) => "proxy setup show",
            proxy_cmd::ProxyCmd::Setup(proxy_cmd::SetupCmd::Set { .. }) => "proxy setup set",
        },
        Cmd::Ca(_) => "ca",
        Cmd::Browser(browser_cmd::BrowserCmd::List) => "browser list",
        Cmd::Browser(browser_cmd::BrowserCmd::Open { .. }) => "browser open",
        Cmd::Fuzz(c) => match c {
            fuzz_cmd::FuzzCmd::Run(_) => "fuzz run",
            fuzz_cmd::FuzzCmd::Status { .. } => "fuzz status",
            fuzz_cmd::FuzzCmd::Results { .. } => "fuzz results",
            fuzz_cmd::FuzzCmd::List { .. } => "fuzz list",
            fuzz_cmd::FuzzCmd::Stop { .. } => "fuzz stop",
        },
        Cmd::Diff(_) => "diff",
        Cmd::Ws(c) => match c {
            ws_cmd::WsCmd::List { .. } => "ws list",
            ws_cmd::WsCmd::Show { .. } => "ws show",
            ws_cmd::WsCmd::Messages { .. } => "ws messages",
            ws_cmd::WsCmd::Send(_) => "ws send",
        },
        Cmd::Sse(c) => match c {
            sse_cmd::SseCmd::List { .. } => "sse list",
            sse_cmd::SseCmd::Show { .. } => "sse show",
            sse_cmd::SseCmd::Events { .. } => "sse events",
            sse_cmd::SseCmd::Event { .. } => "sse event",
        },
        Cmd::Scan(_) => "scan",
        Cmd::Crawl(_) => "crawl",
        Cmd::Import(c) => match c {
            import_cmd::ImportCmd::Api(_) => "import api",
            import_cmd::ImportCmd::Openapi(_) => "import openapi",
            import_cmd::ImportCmd::Postman(_) => "import postman",
            import_cmd::ImportCmd::Graphql(_) => "import graphql",
            import_cmd::ImportCmd::Har(_) => "import har",
        },
        Cmd::Engagement(_) => "engagement",
        Cmd::Auth(c) => match c {
            auth_cmd::AuthCmd::Add(_) => "auth add",
            auth_cmd::AuthCmd::Login { .. } => "auth login",
            auth_cmd::AuthCmd::Status { .. } => "auth status",
            auth_cmd::AuthCmd::Headers { .. } => "auth headers",
            auth_cmd::AuthCmd::List => "auth list",
            auth_cmd::AuthCmd::Show { .. } => "auth show",
            auth_cmd::AuthCmd::Remove { .. } => "auth remove",
            auth_cmd::AuthCmd::Oauth(auth_cmd::OauthCmd::Authorize { .. }) => "auth oauth authorize",
            auth_cmd::AuthCmd::Oauth(auth_cmd::OauthCmd::Discover { .. }) => "auth oauth discover",
            auth_cmd::AuthCmd::Record(auth_cmd::RecordCmd::Start { .. }) => "auth record start",
            auth_cmd::AuthCmd::Record(auth_cmd::RecordCmd::Finish { .. }) => "auth record finish",
            auth_cmd::AuthCmd::Macro(c) => match c {
                auth_cmd::MacroCmd::Add { .. } => "auth macro add",
                auth_cmd::MacroCmd::List { .. } => "auth macro list",
                auth_cmd::MacroCmd::Show { .. } => "auth macro show",
                auth_cmd::MacroCmd::Run { .. } => "auth macro run",
                auth_cmd::MacroCmd::Remove { .. } => "auth macro remove",
            },
            auth_cmd::AuthCmd::Rule(c) => match c {
                auth_cmd::RuleCmd::Add { .. } => "auth rule add",
                auth_cmd::RuleCmd::List { .. } => "auth rule list",
                auth_cmd::RuleCmd::Remove { .. } => "auth rule remove",
            },
            auth_cmd::AuthCmd::Sign(c) => match c {
                auth_cmd::SignCmd::Add(_) => "auth sign add",
                auth_cmd::SignCmd::List { .. } => "auth sign list",
                auth_cmd::SignCmd::Remove { .. } => "auth sign remove",
            },
        },
        Cmd::Authz(c) => match c {
            authz_cmd::AuthzCmd::Run(_) => "authz run",
            authz_cmd::AuthzCmd::Results { .. } => "authz results",
            authz_cmd::AuthzCmd::Matrix { .. } => "authz matrix",
            authz_cmd::AuthzCmd::List { .. } => "authz list",
            authz_cmd::AuthzCmd::Skip(c) => match c {
                authz_cmd::SkipCmd::List => "authz skip list",
                authz_cmd::SkipCmd::Add { .. } => "authz skip add",
                authz_cmd::SkipCmd::Remove { .. } => "authz skip remove",
                authz_cmd::SkipCmd::Set { .. } => "authz skip set",
            },
        },
        Cmd::Job(_) => "job",
        Cmd::Oob(c) => match c {
            oob_cmd::OobCmd::Start(_) => "oob start",
            oob_cmd::OobCmd::Run(_) => "oob run",
            oob_cmd::OobCmd::Stop { .. } => "oob stop",
            oob_cmd::OobCmd::Status => "oob status",
            oob_cmd::OobCmd::Payload { .. } => "oob payload",
            oob_cmd::OobCmd::Poll { .. } => "oob poll",
        },
        Cmd::Checks(c) => match c {
            checks_cmd::ChecksCmd::List(_) => "checks list",
            checks_cmd::ChecksCmd::Validate { .. } => "checks validate",
            checks_cmd::ChecksCmd::Update(_) => "checks update",
            checks_cmd::ChecksCmd::Status => "checks status",
            checks_cmd::ChecksCmd::Feed(_) => "checks feed",
        },
        Cmd::Update(c) => match c {
            update_cmd::UpdateCmd::Check { .. } => "update check",
            update_cmd::UpdateCmd::Download { .. } => "update download",
        },
        Cmd::Findings(_) => "findings",
        Cmd::Report(_) => "report",
        Cmd::ReportProfile(_) => "report-profile",
        Cmd::ReportSummary(_) => "report-summary",
        Cmd::Scope(_) => "scope",
        Cmd::Connection(c) => match c {
            connection_cmd::ConnectionCmd::Show => "connection show",
            connection_cmd::ConnectionCmd::Route { .. } => "connection route",
            connection_cmd::ConnectionCmd::Upstream(_) => "connection upstream",
            connection_cmd::ConnectionCmd::Hosts(_) => "connection hosts",
            connection_cmd::ConnectionCmd::Cert(_) => "connection cert",
            connection_cmd::ConnectionCmd::Passthrough(_) => "connection passthrough",
            connection_cmd::ConnectionCmd::Clear => "connection clear",
            connection_cmd::ConnectionCmd::Review { .. } => "connection review",
        },
        Cmd::Rules(_) => "rules",
        Cmd::Intercept(_) => "intercept",
        Cmd::Wordlists(fuzz_cmd::WordlistsCmd::List) => "wordlists list",
        Cmd::Wordlists(fuzz_cmd::WordlistsCmd::Show { .. }) => "wordlists show",
        Cmd::Encode(_) => "encode",
        Cmd::Decode(_) => "decode",
        Cmd::Hash(_) => "hash",
        Cmd::Mcp(_) => "mcp serve",
        Cmd::Engage => "engage",
    }
    .to_string()
}

fn run(cli: Cli, out: &Out) -> Result<(), Error> {
    // Passive scanning, wherever it runs, includes the feed's and your passive checks.
    brainproxy_core::scan::passive::use_checks_from(&proxy_cmd::resolve_home(cli.home.clone()));
    brainproxy_core::data::set_home(&proxy_cmd::resolve_home(cli.home.clone()));
    // A profile that logs in with a browser finds one, and the CA its traffic is opened with, here.
    let home = proxy_cmd::resolve_home(cli.home.clone());
    brainproxy_core::browser_login::set_launcher(move || {
        Ok(brainproxy_core::browser_login::Launcher {
            browser: browser_cmd::chromium(None).map_err(|e| match e {
                Error::NotFound(_) => Error::NotFound(
                    "a Chromium-based browser to replay this profile's login in (Chrome, Chromium, Edge or Brave; see \
                     `brainproxy browser list`)"
                        .into(),
                ),
                e => e,
            })?,
            ca: std::sync::Arc::new(proxy_cmd::load_ca(&home)?.0),
        })
    });
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
        Cmd::Project(cmd) => project_cmd::project(&cli.project, cmd, out)?,
        Cmd::Send(args) => send(&cli.project, args, out)?,
        Cmd::Replay(cmd) => replay_cmd::replay(&cli.project, cmd, out)?,
        Cmd::History(cmd) => history(&cli.project, cmd, out)?,
        Cmd::Proxy(cmd) => proxy_cmd::proxy(&cli.project, &proxy_cmd::resolve_home(cli.home), cmd, out)?,
        Cmd::Ca(cmd) => proxy_cmd::ca(&proxy_cmd::resolve_home(cli.home), cmd, out)?,
        Cmd::Browser(cmd) => browser_cmd::browser(&cli.project, &proxy_cmd::resolve_home(cli.home), cmd, out)?,
        Cmd::Fuzz(cmd) => fuzz_cmd::fuzz_cmd(&cli.project, &proxy_cmd::resolve_home(cli.home), cmd, out)?,
        Cmd::Diff(args) => fuzz_cmd::diff_cmd(&cli.project, args, out)?,
        Cmd::Ws(cmd) => ws_cmd::ws(&cli.project, cmd, out)?,
        Cmd::Sse(cmd) => sse_cmd::sse(&cli.project, cmd, out)?,
        Cmd::Scan(cmd) => scan_cmd::scan(&cli.project, &proxy_cmd::resolve_home(cli.home), cmd, out)?,
        Cmd::Crawl(args) => crawl_cmd::crawl(&cli.project, &proxy_cmd::resolve_home(cli.home), args, out)?,
        Cmd::Import(cmd) => import_cmd::import(&cli.project, &proxy_cmd::resolve_home(cli.home), cmd, out)?,
        Cmd::Job(cmd) => jobs_cmd::job(&cli.project, cmd, out)?,
        Cmd::Checks(cmd) => checks_cmd::checks_cmd(&cli.project, &proxy_cmd::resolve_home(cli.home), cmd, out)?,
        Cmd::Oob(cmd) => oob_cmd::oob(&cli.project, cmd, out)?,
        Cmd::Update(cmd) => update_cmd::update(cmd, out)?,
        Cmd::Engagement(cmd) => engagement_cmd::engagement(&cli.project, cmd, out)?,
        Cmd::Auth(cmd) => auth_cmd::auth(&cli.project, &proxy_cmd::resolve_home(cli.home), cmd, out)?,
        Cmd::Authz(cmd) => authz_cmd::authz(&cli.project, &proxy_cmd::resolve_home(cli.home), cmd, out)?,
        Cmd::Findings(cmd) => scan_cmd::findings(&cli.project, cmd, out)?,
        Cmd::Report(args) => report_cmd::report(&cli.project, args, out)?,
        Cmd::ReportProfile(cmd) => report_cmd::profile(&cli.project, cmd, out)?,
        Cmd::ReportSummary(cmd) => report_cmd::summary(&cli.project, cmd, out)?,
        Cmd::Scope(cmd) => proxy_cmd::scope(&cli.project, cmd, out)?,
        Cmd::Connection(cmd) => connection_cmd::connection(&cli.project, cmd, out)?,
        Cmd::Rules(cmd) => proxy_cmd::rules(&cli.project, cmd, out)?,
        Cmd::Intercept(cmd) => proxy_cmd::intercept(&cli.project, cmd, out)?,
        Cmd::Wordlists(cmd) => fuzz_cmd::wordlists(cmd, out)?,
        Cmd::Encode(a) => codec_cmd(a, out, codec::encode)?,
        Cmd::Decode(a) => decode_cmd(a, out)?,
        Cmd::Hash(a) => codec_cmd(a, out, |k, b| codec::hash(k, b).map(String::into_bytes))?,
        Cmd::Mcp(mcp::McpCmd::Serve(args)) => mcp::serve(Cli::command(), &cli.project, cli.home.as_deref(), args)?,
        // For Jean-Luc Picard.
        Cmd::Engage => out.ok(json!({"order": "Make it so."}), || "Make it so.".into()),
    }
    Ok(())
}

/// The scope guard every outbound request must pass (system + engagement scope).
fn project_guard(project: &Path) -> Result<std::sync::Arc<brainproxy_core::guard::Guard>, Error> {
    Store::open(project)?.guard()
}

/// Fails with out_of_scope unless `target` passes the guard (resolving DNS like a real request).
pub(crate) fn require_in_scope(guard: &brainproxy_core::guard::Guard, target: &Target) -> Result<(), Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Io)?
        .block_on(guard.resolve(&target.host, target.port))
        .map(|_| ())
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

fn send(project: &Path, mut args: SendArgs, out: &Out) -> Result<(), Error> {
    mcp::check_no_store(args.no_store)?;
    mcp::check_request_files(&args.also)?;
    args.req.resolve_file(project)?;
    let stdin_count = usize::from(args.req.reads_stdin()) + args.also.iter().filter(|f| *f == "-").count();
    if stdin_count > 1 {
        return Err(Error::InvalidInput("stdin may be read only once across the primary request and --also".into()));
    }
    let primary = args.req.prepare(None)?;
    let mut group = vec![primary];
    for file in &args.also {
        let mut input = args.req.clone();
        input.url = None;
        input.file = Some(file.clone());
        // A URL primary also supplies the default scheme for raw group members.
        input.scheme = group[0].1.scheme.clone();
        group.push(input.prepare(None)?);
    }
    let h2 =
        args.req.http2 || group.iter().any(|(r, _)| r.head().is_ok_and(|h| h.version.eq_ignore_ascii_case("HTTP/2")));
    let count = args.race.or_else(|| (!args.also.is_empty()).then_some(1));
    if let Some(n) = count {
        // Refused before anything is sent, a login included.
        check_race_count(n, group.len(), h2)?;
    }
    let guard = project_guard(project)?;
    // The request line's HTTP/2, if any, is honoured by the race itself (single_packet opens its
    // own HTTP/2 connection); it must not be forced onto send_opts, or an --auth login (and a
    // non-race send) would be pushed onto HTTP/2 too.
    if !(0.0..=ws_cmd::MAX_WAIT_SECS).contains(&args.stream_wait) {
        return Err(Error::InvalidInput(format!("--stream-wait: 0 to {} seconds", ws_cmd::MAX_WAIT_SECS)));
    }
    let mut send_opts = args.req.send_options(guard.clone());
    send_opts.stream = brainproxy_core::sse::StreamLimits {
        wait: std::time::Duration::from_secs_f64(args.stream_wait),
        max_events: args.max_events as usize,
    };
    let mut host_warning = None;
    for (req, target) in &group {
        require_in_scope(&guard, target)?;
        send_opts.check_sni(target)?;
        let warning = mcp::check_host_header(&send_opts, req.as_bytes(), target, args.req.host_header_test, out)?;
        host_warning = host_warning.or(warning);
    }
    // Match-and-replace rules that list send apply to each request as given, before a session
    // is applied to it (the proxy's order). The checks above were of the request as given; the
    // client checks what goes out.
    let rules =
        brainproxy_core::rules::EngineRules::load(&Store::open(project)?, brainproxy_core::rules::Engine::Send)?;
    let mut ruled = Vec::new();
    if let Some(rules) = &rules {
        for (req, target) in group.iter_mut() {
            let r = rules.request(&send_opts, target, req.as_bytes().to_vec())?;
            *req = RawRequest::from_bytes(r.bytes.clone());
            ruled.push(r);
        }
    }
    // A request rule's script that blocked or answered a request: nothing of it is sent. A race
    // sends its requests together, so one it stopped stops the race, before any row is written.
    if let Some((i, stopped)) = ruled.iter().enumerate().find_map(|(i, r)| Some((i, r.stopped.as_ref()?))) {
        if count.is_some() {
            return Err(Error::Blocked(format!("request {i} of the race: {}; nothing was sent", stopped.message())));
        }
    }
    let target = group[0].1.clone();
    for (i, (_, other)) in group.iter().enumerate().skip(1) {
        if other != &target {
            return Err(Error::InvalidInput(format!(
                "race group requires the same origin: request 0 is {}, request {i} is {}",
                target.origin(),
                other.origin()
            )));
        }
    }
    let session = auth_cmd::maybe_session(project, args.auth.as_deref(), &send_opts)?;
    if let Some(s) = session.as_ref().filter(|_| args.no_store) {
        s.keep_no_content();
    }
    let client = Client::new(send_opts);
    if let Some(n) = count {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(Error::Io)?;
        let mut requests = Vec::with_capacity(group.len());
        for (req, target) in group {
            let req = match &session {
                Some(s) => RawRequest::from_bytes(
                    rt.block_on(s.prepare(brainproxy_core::session::Tool::Send, &target, req.as_bytes(), &[], &[]))
                        .request,
                ),
                None => req,
            };
            requests.push(req);
        }
        if let Some(session) = &session {
            session.save()?;
        }
        return race(project, &args, requests, (rules.as_ref(), &ruled), target, client, n, h2, host_warning, out);
    }
    let req = group.remove(0).0;
    let mut log = sent::SentLog::open(project, "send", args.no_store)?.sent_by(&client);
    if let Some(r) = ruled.first() {
        log.ruled(r);
    }
    if let Some(stopped) = ruled.first().and_then(|r| r.stopped.as_ref()) {
        // Not sent, and no session is applied (a re-login would send): its row says why.
        let recorded = client.recorded_request(&req, &target)?;
        let id = log.pending(&target, &recorded)?;
        let Some(response) = stopped.answer() else {
            let why = stopped.message();
            log.failed(id, &target, &recorded, &why)?;
            return Err(Error::Blocked(format!("{why}; nothing was sent (history #{id})")));
        };
        let ex = brainproxy_core::http::client::Exchange {
            target: target.clone(),
            request: recorded,
            response: response.to_vec(),
            duration_ms: 0,
            sni: None,
            stream: None,
        };
        log.answered(id, &ex)?;
        if args.raw {
            out.raw(&ex.response);
            return Ok(());
        }
        let mut data = exchange_json(Some(id), &target, &ex.request, &ex.response, Some(0), args.max_body);
        if args.show_request {
            data["request"] = body_value(&ex.request, args.max_body);
        }
        data["answered_by"] = json!({"rule": stopped.id, "note": stopped.message()});
        data["rules"] = json!({"request": ruled[0].ids(), "response": []});
        if !ruled[0].failed.is_empty() {
            data["rule_errors"] = json!(ruled[0].failed);
        }
        let note = stopped.message();
        out.ok(data, || format!("{note}\n\n{}", text_exchange(Some(id), &ex.response, 0)));
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(Error::Io)?;
    // Each request is on record (its row and the bytes recorded) before it goes out. `open`
    // is the one out and unanswered; a row answered already is never rewritten.
    let mut rows: Vec<i64> = Vec::new();
    let mut open: Option<(i64, Vec<u8>)> = None;
    let result = {
        let (log, rows, open) = (&mut log, &mut rows, &mut open);
        let sending = async {
            let sending = |log: &mut sent::SentLog, rows: &mut Vec<i64>, open: &mut Option<_>, r: &RawRequest| {
                let recorded = client.recorded_request(r, &target)?;
                let id = log.pending(&target, &recorded)?;
                rows.push(id);
                *open = Some((id, recorded));
                Ok::<_, Error>(())
            };
            match &session {
                Some(s) => {
                    let watch = |a: Attempt<'_>| match a {
                        Attempt::Sending(r) => sending(log, rows, open, r),
                        Attempt::Answered(ex) => match open.take() {
                            Some((id, _)) => log.answered(id, ex),
                            None => Ok(()),
                        },
                    };
                    s.send_as_watched(brainproxy_core::session::Tool::Send, &req, &target, watch).await
                }
                None => {
                    sending(log, rows, open, &req)?;
                    let ex = client.send(&req, &target).await?;
                    if let Some((id, _)) = open.take() {
                        log.answered(id, &ex)?;
                    }
                    Ok(ex)
                }
            }
        };
        rt.block_on(async {
            tokio::select! {
                r = sending => Some(r),
                _ = process::interrupted() => None,
            }
        })
    };
    // Rows first: a failure saving the session mustn't leave one pending.
    // An answered request's row is complete already.
    let outcome = match (result, open) {
        (Some(Ok(ex)), None) => Ok((*rows.last().expect("every request is recorded before it is sent"), ex)),
        (Some(Ok(_)), Some(_)) => unreachable!("an answer completes its row"),
        (Some(Err(e)), Some((id, recorded))) => log.failed(id, &target, &recorded, &e.to_string()).and(Err(e)),
        (Some(Err(e)), None) => Err(e),
        (None, Some((id, recorded))) => {
            log.failed(id, &target, &recorded, sent::CANCELLED).and(Err(sent::cancelled(&rows)))
        }
        (None, None) => Err(sent::cancelled(&rows)),
    };
    let saved = session.as_ref().map(|s| s.save()).transpose();
    let (id, mut ex) = outcome?;
    // The row keeps the response as received and, beside it, what the rules made of it, which
    // is what is shown. An event stream's response gets the header rules only, as the proxy's.
    let mut response_rules = Vec::new();
    let mut rule_errors = ruled.first().map(|r| r.failed.clone()).unwrap_or_default();
    let mut unkept = None;
    if let Some(rules) = &rules {
        let received = std::mem::take(&mut ex.response);
        let r = match ex.stream {
            Some(_) => rules.response_head(&target, received),
            None => rules.response(&target, &ex.request, received),
        };
        // The request went out and its row is complete: failing now would hide the answer.
        unkept = log.ruled_response(id, &r).err();
        response_rules = r.ids();
        rule_errors.extend(r.failed);
        ex.response = r.bytes;
    }
    let request_rules = ruled.first().map(|r| r.ids()).unwrap_or_default();
    let unkept =
        unkept.map(|e| format!("history #{id} keeps the response as received, but not what the rules made of it: {e}"));
    // An event stream's events are listed with its row (`sse events`); without the row's
    // content there is nothing to list them with.
    let stream_id = match &ex.stream {
        Some(read) if !args.no_store => {
            let url = exchange_url(&target, &ex.request);
            Some(log.store.sse_record_read(id, "send", &url, &target.host, read)?)
        }
        _ => None,
    };
    let new_findings = log.scan(&rows)?;
    let id = Some(id);
    let host_warning =
        mcp::sent_host_warning([&client].into_iter().chain(session.as_deref().map(|s| s.client())), host_warning, out);

    if args.raw {
        out.raw(&ex.response);
        return Ok(());
    }
    let mut data = exchange_json(id, &target, &ex.request, &ex.response, Some(ex.duration_ms), args.max_body);
    if args.show_request {
        data["request"] = body_value(&ex.request, args.max_body);
    }
    if new_findings > 0 {
        data["new_findings"] = json!(new_findings);
    }
    if let Err(e) = saved {
        data["warning"] = json!(format!("the session's state wasn't saved: {e}"));
    } else if let Some(warning) = unkept {
        data["warning"] = json!(warning);
    }
    if let Some(w) = host_warning {
        data["host_warning"] = json!(w);
    }
    if !request_rules.is_empty() || !response_rules.is_empty() {
        data["rules"] = json!({"request": request_rules, "response": response_rules});
    }
    // A rule whose script failed left the request or the response as it was.
    if !rule_errors.is_empty() {
        data["rule_errors"] = json!(rule_errors);
    }
    if let Some(read) = &ex.stream {
        data["stream"] = sse_cmd::read_json(read, stream_id, args.max_body);
    }
    out.ok(data, || {
        let text = text_exchange(id, &ex.response, ex.duration_ms);
        match &ex.stream {
            Some(read) => format!("{}\n\n{}", text.trim_end(), sse_cmd::read_text(read, args.max_body)),
            None => text,
        }
    });
    Ok(())
}

/// Files kept free beyond a last-byte race's connections: the project database, the runtime,
/// name lookups and TLS roots.
const RACE_FD_RESERVE: usize = 64;

/// Refuses race totals the CLI can't run: 1 to 1000, at most 100 single-packet, and for
/// last-byte sync (a connection each) no more than the open-file limit leaves room for.
fn check_race_count(copies: usize, group: usize, h2: bool) -> Result<(), Error> {
    if !(1..=1000).contains(&copies) {
        return Err(Error::InvalidInput("--race must be between 1 and 1000".into()));
    }
    let n = copies.checked_mul(group).ok_or_else(|| Error::InvalidInput("race group total overflows".into()))?;
    if n > 1000 {
        return Err(Error::InvalidInput("race group total (requests * --race) must be at most 1000".into()));
    }
    let max = brainproxy_core::race::SINGLE_PACKET_MAX;
    if h2 && n > max {
        return Err(Error::InvalidInput(format!("single-packet races take 1 to {max} requests")));
    }
    if let Some((limit, open)) = brainproxy_core::race::fd_usage().filter(|_| !h2) {
        let room = limit.saturating_sub(open + RACE_FD_RESERVE);
        if n > room {
            return Err(Error::InvalidInput(format!(
                "race total {n} ({group} requests x {copies}) needs {n} connections, but the open-file limit ({limit}) leaves room for {room}; \
                 lower --race or raise the limit (ulimit -n)"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn race(
    project: &Path,
    args: &SendArgs,
    group: Vec<RawRequest>,
    (rules, ruled): (Option<&brainproxy_core::rules::EngineRules>, &[brainproxy_core::rules::Ruled]),
    target: Target,
    client: Client,
    copies: usize,
    h2: bool,
    host_warning: Option<String>,
    out: &Out,
) -> Result<(), Error> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(Error::Io)?;
    // Every copy is on record before any goes out, each row saying which race it is in, how,
    // and where: see race::row_tags.
    let race_id = brainproxy_core::race::new_race_id()?;
    let sync = if h2 { "single-packet" } else { "last-byte" };
    let n = group.len() * copies;
    let recorded = group.iter().map(|req| client.recorded_request(req, &target)).collect::<Result<Vec<_>, _>>()?;
    let descriptions: Vec<Value> = group
        .iter()
        .enumerate()
        .map(|(i, req)| {
            let line = String::from_utf8_lossy(req.as_bytes()).lines().next().unwrap_or("").to_string();
            json!({"index": i, "request_line": line})
        })
        .collect();
    let mut log = sent::SentLog::open(project, "race", args.no_store)?.sent_by(&client);
    let mut ids = Vec::with_capacity(n);
    for (member, bytes) in recorded.iter().enumerate() {
        // A member match-and-replace rules changed says so on its rows.
        log.ruled(ruled.get(member).unwrap_or(&Default::default()));
        ids.extend(log.pending_many(&target, bytes, copies, |i| {
            brainproxy_core::race::row_tags(&race_id, sync, false, member * copies + i, n)
        })?);
    }
    log.ruled(&Default::default());
    let requests = group.iter().flat_map(|req| std::iter::repeat_n(req.as_bytes().to_vec(), copies)).collect();
    let racing = async {
        if h2 {
            brainproxy_core::race::single_packet(&client, &target, requests)
                .await
                .map(|run| (run.results, "single-packet", Some(run.synced)))
        } else {
            Ok((brainproxy_core::race::last_byte_sync(&client, &target, requests).await, "last-byte", None))
        }
    };
    let outcome = rt.block_on(async {
        tokio::select! {
            r = racing => Some(r),
            _ = process::interrupted() => None,
        }
    });
    // Every row is completed before a store error is reported, so none stays pending.
    let mut store_error = None;
    let mut done = |r: Result<(), Error>| {
        if let Err(e) = r {
            store_error.get_or_insert(e);
        }
    };
    let (results, sync, synced) = match outcome {
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            for (i, id) in ids.iter().enumerate() {
                done(log.failed(*id, &target, &recorded[i / copies], &e.to_string()));
            }
            return Err(store_error.unwrap_or(e));
        }
        None => {
            for (i, id) in ids.iter().enumerate() {
                done(log.failed(*id, &target, &recorded[i / copies], sent::CANCELLED));
            }
            return Err(store_error.unwrap_or_else(|| sent::cancelled(&ids)));
        }
    };
    // Not every final frame went out together: every row says so.
    let partial = synced.is_some_and(|s| s < n);
    if partial {
        done(log.store.add_recorded_tags(&ids, &["race-partial".to_string()]));
    }
    let mut items = Vec::new();
    let mut shapes: std::collections::BTreeMap<String, usize> = Default::default();
    for (i, (r, &id)) in results.iter().zip(&ids).enumerate() {
        match r {
            Ok(ex) => {
                done(log.answered(id, ex));
                // As for one send: the row keeps the response as received and, beside it, what
                // the rules made of it, which is what the race's results go by.
                let after = rules
                    .filter(|rules| rules.rewrites_responses(&target))
                    .map(|rules| rules.response(&target, &ex.request, ex.response.clone()))
                    .filter(|after| after.changed());
                if let Some(after) = &after {
                    done(log.ruled_response(id, after));
                }
                let response = after.as_ref().map_or(&ex.response, |after| &after.bytes);
                let head = parse_response_head(response).ok();
                let body = head.as_ref().map(|h| decode_body(&h.headers, split_head_body(response).1));
                let status = head.as_ref().map(|h| h.status);
                let length = body.as_ref().map(|b| b.len());
                *shapes.entry(format!("{} {}B", status.unwrap_or(0), length.unwrap_or(0))).or_default() += 1;
                items.push(json!({"id": id, "status": status, "length": length, "duration_ms": ex.duration_ms}));
            }
            Err(e) => {
                done(log.failed(id, &target, &recorded[i / copies], &e.to_string()));
                *shapes.entry(format!("error: {}", e.kind())).or_default() += 1;
                items.push(json!({"id": id, "error": e.to_string(), "kind": e.kind()}));
            }
        }
        let item = items.last_mut().expect("one item per result");
        item["request"] = json!(i / copies);
        item["request_line"] = descriptions[i / copies]["request_line"].clone();
    }
    if let Some(e) = store_error {
        return Err(e);
    }
    let new_findings = log.scan(&ids)?;
    let host_warning = mcp::sent_host_warning([&client], host_warning, out);
    let mut data = json!({
        "race": copies,
        "race_id": race_id,
        "sync": sync,
        "synced": synced,
        "target": target.origin(),
        "distinct_responses": shapes,
        "results": items,
        "hint": "Different statuses/lengths for identical requests suggest a race window; inspect with history show ID or diff ID1 ID2. duration_ms counts from the release of the final bytes. Every recorded row is tagged race:RACE_ID.",
    });
    // A rule whose script failed left that member's request as it was.
    let rule_errors: Vec<Value> = ruled
        .iter()
        .enumerate()
        .flat_map(|(i, r)| r.failed.iter().map(move |f| json!({"request": i, "id": f.id, "error": f.error})))
        .collect();
    if !rule_errors.is_empty() {
        data["rule_errors"] = json!(rule_errors);
    }
    if group.len() > 1 {
        data["requests"] = json!(descriptions);
        data["total"] = json!(n);
        data["hint"] = json!("Compare responses within each request index; different group members may normally return different responses. Inspect history show ID or diff ID1 ID2. duration_ms counts from the release of the final bytes; rows are tagged race:RACE_ID.");
    }
    // Keep the full group output even when the one HTTP/2 connection fails.
    if let (true, Some(Err(e))) = (h2 && results.iter().all(|r| r.is_err()), results.first()) {
        let rows = ids.iter().map(|id| format!("#{id}")).collect::<Vec<_>>().join(", ");
        out.error_with(e.kind(), &format!("{e} (every copy failed; history {rows})"), data);
        std::process::exit(e.exit_code());
    }
    if new_findings > 0 {
        data["new_findings"] = json!(new_findings);
    }
    if let Some(w) = host_warning {
        data["host_warning"] = json!(w);
    }
    out.ok(data.clone(), || {
        let mut lines: Vec<String> = shapes.iter().map(|(k, v)| format!("{v:>5}  {k}")).collect();
        let note = if partial { ", partial" } else { "" };
        lines.insert(0, format!("race x{n} ({sync}{note}) -> {}  [tag race:{race_id}]", target.origin()));
        if group.len() > 1 {
            for (i, description) in descriptions.iter().enumerate() {
                lines.push(format!("request {i} x{copies}: {}", description["request_line"].as_str().unwrap_or("")));
                for item in &items[i * copies..(i + 1) * copies] {
                    lines.push(format!(
                        "  #{}  {}",
                        item["id"],
                        if item["error"].is_string() {
                            item["error"].as_str().unwrap().to_string()
                        } else {
                            format!("{} {}B", item["status"], item["length"])
                        }
                    ));
                }
            }
        }
        lines.join("\n")
    });
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
            {"name": "history", "description": "One row per request: source is send, race, proxy, fuzz, crawl, crawl-browser, import, scan, or ws (ws send handshakes).", "columns": cols(store::HISTORY_COLUMNS)},
            {"name": "ws_connections", "description": "WebSocket connections the proxy relayed (source proxy) or ws send opened (source replay). Join history ON history.id = history_id for the upgrade request.", "columns": cols(brainproxy_core::ws::db::CONNECTION_COLUMNS)},
            {"name": "ws_messages", "description": "One row per WebSocket message (control frames included), payload decompressed. Join ws_connections ON ws_connections.id = connection_id.", "columns": cols(brainproxy_core::ws::db::MESSAGE_COLUMNS)},
            {"name": "sse_streams", "description": "Event streams (text/event-stream responses) the proxy relayed (source proxy) or send read (source send). Join history ON history.id = history_id for the request and response.", "columns": cols(brainproxy_core::sse::db::STREAM_COLUMNS)},
            {"name": "sse_events", "description": "One row per server-sent event. Join sse_streams ON sse_streams.id = stream_id.", "columns": cols(brainproxy_core::sse::db::EVENT_COLUMNS)},
            {"name": "intercepts", "description": "Proxy intercept queue (manage with the intercept command).", "columns": cols(store::INTERCEPT_COLUMNS)},
            {"name": "fuzz_runs", "description": "One row per fuzz attack.", "columns": cols(store::FUZZ_RUN_COLUMNS)},
            {"name": "fuzz_results", "description": "One row per fuzz request. Join history ON history.id = fuzz_results.history_id.", "columns": cols(store::FUZZ_RESULT_COLUMNS)},
            {"name": "findings", "description": "Findings from the scanners or added by hand (source manual), de-duplicated (hits counts repeats). Join finding_types ON alert_ref for description/solution.", "columns": cols(brainproxy_core::scan::findings_db::FINDING_COLUMNS)},
            {"name": "issues", "description": "Root causes: one alert type on one host, holding the findings (instances) it was seen at. Join findings ON findings.issue_id = issues.id.", "columns": cols(brainproxy_core::scan::issues::ISSUE_COLUMNS)},
            {"name": "finding_events", "description": "Each finding's timeline: created, state and note changes, retests, regressions, moves between issues, removals, with who and when.", "columns": cols(brainproxy_core::scan::issues::EVENT_COLUMNS)},
            {"name": "scan_observations", "description": "What each completed active scan saw of the findings it covered: new, still or gone. Join jobs ON jobs.id = job_id.", "columns": cols(brainproxy_core::scan::issues::OBSERVATION_COLUMNS)},
            {"name": "report_profiles", "description": "Saved report layouts (`report-profile save`), used with `report --profile NAME`.", "columns": cols(brainproxy_core::scan::layout::PROFILE_COLUMNS)},
            {"name": "finding_types", "description": "Description, solution, refs (JSON), and tags (JSON) per alert_ref, and who wrote the text of a title added by hand.", "columns": cols(brainproxy_core::scan::findings_db::FINDING_TYPE_COLUMNS)},
            {"name": "rule_edits", "description": "What match-and-replace rules changed in a history row's exchange: the request before them and the response after (see history show).", "columns": cols(store::RULE_EDIT_COLUMNS)},
            {"name": "setting_changes", "description": "Who saved which setting (scope, rules, intercept, connection, ...) and when; the values themselves are not logged.", "columns": cols(store::SETTING_CHANGE_COLUMNS)},
            {"name": "auth_profiles", "description": "Login profiles (profile JSON) and their stored session state (state JSON: cookies, token, logged_in). Not readable with query (it holds secrets); use auth list / auth show (redacted), which also say who saved the profile (profile.origin), its rules and macros (origin), and its session (session_origin)."},
            {"name": "authz_results", "description": "Access-control test results: one row per request and identity (authz run). Join history ON history.id = authz_results.history_id (or baseline_history_id).", "columns": cols(brainproxy_core::authz::AUTHZ_RESULT_COLUMNS)},
            {"name": "jobs", "description": "Background jobs (crawl, active scan, authz run).", "columns": cols(brainproxy_core::jobs::JOB_COLUMNS)},
            {"name": "oob_payloads", "description": "Out-of-band payload tokens: from active rules (source scan) or `oob payload` (manual).", "columns": cols(brainproxy_core::oob::PAYLOAD_COLUMNS)},
            {"name": "oob_interactions", "description": "Interactions received by the OOB listener. Join oob_payloads ON token.", "columns": cols(brainproxy_core::oob::INTERACTION_COLUMNS)},
            {"name": "history_fts", "description": "FTS5 full-text index over url, req_headers, req_body_text, resp_headers, resp_body_text. rowid = history.id. Query with: WHERE history_fts MATCH 'term'."},
            {"name": "ws_messages_fts", "description": "FTS5 full-text index over ws_messages.payload_text. rowid = ws_messages.id. Query with: WHERE ws_messages_fts MATCH 'term'."},
            {"name": "sse_events_fts", "description": "FTS5 full-text index over sse_events.data. rowid = sse_events.id. Query with: WHERE sse_events_fts MATCH 'term'."},
        ],
        "functions": store::FUNCTIONS.iter().map(|(sig, d)| json!({"signature": sig, "description": d})).collect::<Vec<_>>(),
        "examples": store::EXAMPLES.iter().map(|(t, q)| json!({"title": t, "sql": q})).collect::<Vec<_>>(),
        "notes": [
            "query opens the database read-only; writes fail.",
            "Prefer *_text columns for searching; they are NULL for binary bodies.",
            "Bind values with -p/--param and ?1, ?2 instead of quoting them into SQL. Values that are plain integers (42, -7) bind as integers; anything else (including 007) binds as text.",
        ],
    })
}

fn response_json(response: &[u8], max_body: usize) -> Value {
    if response.is_empty() {
        // No response was recorded (connection error, timeout); the entry's `error` says why.
        return Value::Null;
    }
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
    json!({
        "id": id,
        "url": exchange_url(target, request),
        "duration_ms": duration_ms,
        "response": response_json(response, max_body),
    })
}

/// History row `id` as [`exchange_json`] with its request, for a command that shows what a
/// row opened (a WebSocket connection, an event stream); null when there is no such row.
pub(crate) fn recorded_exchange_json(store: &Store, id: Option<i64>, max_body: usize) -> Value {
    let Some(Ok(item)) = id.map(|id| store.get(id)) else { return Value::Null };
    let ms = item.entry.duration_ms.map(|d| d as u64);
    let mut v = exchange_json(Some(item.entry.id), &item.target, &item.request, &item.response, ms, max_body);
    v["request"] = body_value(&item.request, max_body);
    v
}

/// The URL `request` asks `target` for.
fn exchange_url(target: &Target, request: &[u8]) -> String {
    RawRequest::from_bytes(request.to_vec())
        .head()
        .map(|h| if h.target.contains("://") { h.target } else { format!("{}{}", target.origin(), h.target) })
        .unwrap_or_else(|_| target.origin())
}

fn text_exchange(id: Option<i64>, response: &[u8], ms: u64) -> String {
    let status =
        parse_response_head(response).map(|h| format!("{} {}", h.status, h.reason)).unwrap_or_else(|_| "?".into());
    let id = id.map(|i| format!("#{i} ")).unwrap_or_default();
    format!("{id}{status} ({} bytes, {ms} ms)\n\n{}", response.len(), String::from_utf8_lossy(response))
}

/// The `history list` notes: the filter language's fields, from the parser's own list.
fn filter_notes() -> String {
    let fields: Vec<String> =
        brainproxy_core::filter::FIELDS.iter().map(|(name, about)| format!("{name} ({about})")).collect();
    format!(
        "--filter fields: {}. Status classes: status:5xx. Values with spaces or ( ) go in double quotes \
         (\\\" and \\\\ inside); a quoted word is searched as text, so \"status:500\" finds that text. \
         Regexes are Rust syntax, case-sensitive unless they start with (?i); on req, resp and the bodies they \
         read bytes. A header term matches when any value of a repeated header does (!= and !~ when none \
         does), and req.header.NAME:* finds an empty header too. Times compare as instants \
         (time>=2026-11-08T12:00:00Z, or an offset); time:DATE is a prefix. NOT status:500 keeps requests \
         with no response. --filter combines with the other options, all of which must match.",
        fields.join("; ")
    )
}

fn history(project: &Path, cmd: HistoryCmd, out: &Out) -> Result<(), Error> {
    if let HistoryCmd::Export(a) = cmd {
        return history_export::export(project, a, out);
    }
    if let HistoryCmd::Filters(cmd) = cmd {
        return filters_cmd::filters(project, cmd, out);
    }
    let store = Store::open(project)?;
    match cmd {
        HistoryCmd::Export(_) => unreachable!("handled above"),
        HistoryCmd::List { host, method, status, source, tag, origin, contains, filter, after, limit } => {
            let items = store.list(&HistoryFilter {
                host,
                method,
                status,
                source,
                tag,
                origin,
                contains,
                filter,
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
                        let origin = e.origin.as_deref().unwrap_or("unknown");
                        let mut by: Vec<&str> =
                            e.edited_by.iter().map(|x| x.by.as_deref().unwrap_or("unknown")).collect();
                        by.dedup();
                        let edited =
                            if by.is_empty() { String::new() } else { format!("  edited by {}", by.join(",")) };
                        format!("{:>6}  {:<4} {:<7} {}  {len}B  {origin}{edited}", e.id, status, e.method, e.url)
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
                    Part::OriginalRequest => item.rule_edit.and_then(|e| e.original_request).unwrap_or_default(),
                    Part::ModifiedResponse => item.rule_edit.and_then(|e| e.modified_response).unwrap_or_default(),
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
            data["origin_text"] = json!(recorded_text(&item.entry));
            // What match-and-replace rules changed: the row has the request sent and the
            // response received; these are the request before them and the response after.
            let edit = item.rule_edit.clone().unwrap_or_default();
            if let Some(original) = &edit.original_request {
                data["original_request"] = body_value(original, max_body);
            }
            if let Some(modified) = &edit.modified_response {
                data["modified_response"] = body_value(modified, max_body);
                data["response_edits"] = json!(edit.response_edits);
            }
            // An event stream's events are listed by its stream id (`sse events`).
            let stream = store.sse_stream_of(id)?;
            if let Some(s) = &stream {
                data["stream"] = json!(s);
            }
            out.ok(data, || {
                let e = &item.entry;
                let mut about = vec![format!("#{id} {} {}", e.source, recorded_text(e))];
                if let Some(a) = &e.client_addr {
                    about.push(format!("sent by proxy client {a}"));
                }
                about.extend(e.edited_by.iter().map(|x| x.describe()));
                if let Some(n) = &e.sni {
                    about.push(format!("TLS server name (SNI) {n}"));
                }
                if e.note.is_some() || e.note_origin.is_some() {
                    about.push(format!("note set {}", brainproxy_core::provenance::describe(e.note_origin.as_deref())));
                }
                about.extend(edit.response_edits.iter().map(|x| format!("response {}", x.describe())));
                if let Some(s) = &stream {
                    let cut = if s.truncated { ", truncated" } else { "" };
                    about.push(format!("event stream #{} ({}, {} events{cut})", s.id, s.state, s.events));
                }
                let mut text = format!(
                    "{}\n\n{}\n\n{}",
                    about.join(" · "),
                    String::from_utf8_lossy(&item.request),
                    String::from_utf8_lossy(&item.response)
                );
                if let Some(original) = &edit.original_request {
                    text.push_str(&format!(
                        "\n\n--- request before match-and-replace rules ---\n{}",
                        String::from_utf8_lossy(original)
                    ));
                }
                if let Some(modified) = &edit.modified_response {
                    text.push_str(&format!(
                        "\n\n--- response after match-and-replace rules ---\n{}",
                        String::from_utf8_lossy(modified)
                    ));
                }
                text
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
        HistoryCmd::Filters(_) => unreachable!("handled above"),
    }
    Ok(())
}

/// Who recorded an entry, in words. The proxy's origin is whoever started the proxy: the
/// request came from its client, so a row must not read as if that person or agent sent it.
fn recorded_text(e: &brainproxy_core::store::HistoryEntry) -> String {
    let by = brainproxy_core::provenance::describe(e.origin.as_deref());
    if e.source == "proxy" && e.origin.is_some() {
        format!("recorded by a proxy started {by}")
    } else {
        format!("recorded {by}")
    }
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

/// `decode`: like `codec_cmd`, plus `steps`, the decodings applied with each `auto`
/// expanded to what it found, so the chain can be replayed or edited one step at a time,
/// and `stopped`, why the last `auto` stopped.
fn decode_cmd(a: CodecArgs, out: &Out) -> Result<(), Error> {
    let mut value = read_input(a.input.as_deref())?;
    let mut steps: Vec<&str> = Vec::new();
    let mut stopped = None;
    for kind in a.kind.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        if kind == "auto" {
            let found = codec::smart_decode(&value);
            steps.extend(found.steps);
            value = found.output;
            stopped = Some(found.stopped.to_json());
        } else {
            value = codec::decode(kind, &value)?;
            steps.push(kind);
        }
    }
    if a.raw {
        out.raw(&value);
        return Ok(());
    }
    let mut data = json!({"chain": a.kind, "steps": steps, "output": body_value(&value, usize::MAX)});
    if let Some(stopped) = stopped {
        data["stopped"] = stopped;
    }
    out.ok(data, || String::from_utf8_lossy(&value).into_owned());
    Ok(())
}
