//! `poc csrf` and `poc clickjacking`: proof-of-concept pages from a recorded request (see
//! `brainproxy_core::poc`). Nothing is sent; the project is only read.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use brainproxy_core::http::client::final_response;
use brainproxy_core::http::{parse_response_head, RawRequest, ResponseHead, Target};
use brainproxy_core::poc::{self, ClickjackingOptions, CsrfOptions, Technique};
use brainproxy_core::store::{HistoryFilter, Store};
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::output::Out;

const OPENED: &str = "Nothing is sent: opening the page in a browser sends its requests from that browser straight to \
    the target, outside brainproxy's scope checks (unless the browser uses the proxy).";

#[derive(Subcommand)]
pub enum PocCmd {
    /// Write a CSRF proof-of-concept page that sends a recorded request from the visitor's
    /// browser, with its cookies: an HTML form, or fetch.
    #[command(after_help = "Recorded values are written into the page: anti-CSRF tokens are kept (with a warning \
        naming them; --drop-param NAME leaves one out), and a field whose name looks secret (password, token, \
        session...) gets a warning. A urlencoded or GET request becomes hidden inputs; multipart a multipart form \
        (file parts only with --technique fetch); JSON and other bodies go as text/plain. Warnings say what a page \
        on another site can't do as the request did: another method or a custom header (a CORS preflight, see rule \
        40040), and SameSite cookies, read from the Set-Cookie headers recorded for the host. Nothing is sent: \
        opening the page in a browser sends the request from that browser straight to the target, outside \
        brainproxy's scope checks (unless the browser uses the proxy).")]
    Csrf(CsrfArgs),
    /// Write a clickjacking proof-of-concept page: the URL in a frame over a decoy button, with
    /// an opacity slider and the decoy's position to line it up.
    #[command(after_help = "framing says whether the recorded response lets another site frame it \
        (X-Frame-Options, Content-Security-Policy frame-ancestors; blocked is null with no recorded response). \
        Nothing is sent: opening the page in a browser loads the URL from that browser, outside brainproxy's scope \
        checks (unless the browser uses the proxy).")]
    Clickjacking(ClickjackingArgs),
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum TechniqueArg {
    Form,
    Fetch,
}

#[derive(clap::Args)]
#[command(group(clap::ArgGroup::new("request").required(true).args(["history_id", "file"])))]
pub struct CsrfArgs {
    /// The recorded request: its history id.
    #[arg(long)]
    pub history_id: Option<i64>,
    /// A raw request file instead ('-' reads stdin), sent to --target. Through MCP only a file
    /// in the project's folder.
    #[arg(long, requires = "target")]
    pub file: Option<String>,
    /// Where the --file request goes (scheme://host[:port]).
    #[arg(long, requires = "file")]
    pub target: Option<String>,
    /// form: an HTML form (a top-level navigation); fetch: a script, which can also send other
    /// methods (after a CORS preflight) and multipart file parts.
    #[arg(long, value_enum, default_value = "form")]
    pub technique: TechniqueArg,
    /// The page sends the request as soon as it opens.
    #[arg(long)]
    pub auto_submit: bool,
    /// Leave parameter NAME out of the page (a form field, query parameter or top-level JSON
    /// member), such as an anti-CSRF token. Repeatable.
    #[arg(long = "drop-param", value_name = "NAME")]
    pub drop_param: Vec<String>,
    /// Write the page to FILE (stdout then gets a summary).
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Overwrite an existing --output file (not through MCP).
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::Args)]
#[command(group(clap::ArgGroup::new("page").required(true).args(["history_id", "url"])))]
pub struct ClickjackingArgs {
    /// The recorded request whose URL is framed: its history id.
    #[arg(long)]
    pub history_id: Option<i64>,
    /// The URL to frame instead; its newest recorded response, if any, gives the framing.
    #[arg(long)]
    pub url: Option<String>,
    /// The frame's opacity at first, 0 (invisible) to 1.
    #[arg(long, default_value_t = 0.5)]
    pub opacity: f64,
    /// The decoy button's text.
    #[arg(long, default_value = "Click me")]
    pub decoy: String,
    /// Write the page to FILE (stdout then gets a summary).
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Overwrite an existing --output file (not through MCP).
    #[arg(long)]
    pub force: bool,
}

pub fn poc(project: &Path, cmd: PocCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        PocCmd::Csrf(args) => csrf(project, args, out),
        PocCmd::Clickjacking(args) => clickjacking(project, args, out),
    }
}

/// Set-Cookie values recorded from `host`'s responses, oldest first (the newest 200 that set any).
fn recorded_set_cookies(store: &Store, host: &str) -> Result<Vec<String>, Error> {
    let f = HistoryFilter {
        host: Some(host.to_string()),
        contains: Some("set-cookie".into()),
        ignore_case: true,
        ..Default::default()
    };
    let rows = store.list(&f)?;
    let mut out = Vec::new();
    for e in rows.iter().rev().take(200).rev() {
        let item = store.get(e.id)?;
        if let Some(head) = response_head(&item.response) {
            out.extend(head.headers.into_iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v));
        }
    }
    Ok(out)
}

fn response_head(response: &[u8]) -> Option<ResponseHead> {
    if response.is_empty() {
        return None;
    }
    parse_response_head(final_response(response)).ok()
}

/// The project, if it exists: --file and --url make a page without one.
fn existing_store(project: &Path) -> Result<Option<Store>, Error> {
    if project.exists() {
        Store::open(project).map(Some)
    } else {
        Ok(None)
    }
}

fn csrf(project: &Path, mut args: CsrfArgs, out: &Out) -> Result<(), Error> {
    // Any file the server can write: an agent writes new files only.
    crate::mcp::check_force(args.force, "poc csrf", "write the page to a new file, or leave out --output")?;
    if let Some(file) = &args.file {
        args.file = Some(crate::mcp::local_file_arg(
            project,
            "--file",
            file,
            "pass the request on stdin (-), or name it with --history-id",
        )?);
    }
    let (request, target, history_id, store) = match (args.history_id, &args.file, &args.target) {
        (Some(id), _, _) => {
            let store = Store::open(project)?;
            let item = store.get(id)?;
            (RawRequest::from_bytes(item.request), item.target, Some(id), Some(store))
        }
        (None, Some(file), Some(target)) => {
            let bytes = match file.as_str() {
                "-" => crate::read_input(None)?,
                path => std::fs::read(path)
                    .map_err(|e| Error::InvalidInput(format!("cannot read request file {path:?}: {e}")))?,
            };
            if bytes.iter().all(u8::is_ascii_whitespace) {
                return Err(Error::InvalidInput("empty request; pass a request file or stdin".into()));
            }
            let req = RawRequest::from_bytes(bytes).normalize_line_endings();
            (req, Target::from_url(target)?, None, existing_store(project)?)
        }
        _ => return Err(Error::InvalidInput("name the request: --history-id ID, or --file FILE with --target".into())),
    };
    let set_cookies = match &store {
        Some(s) => recorded_set_cookies(s, &target.host)?,
        None => Vec::new(),
    };
    let opts = CsrfOptions {
        technique: match args.technique {
            TechniqueArg::Form => Technique::Form,
            TechniqueArg::Fetch => Technique::Fetch,
        },
        auto_submit: args.auto_submit,
        drop_params: args.drop_param.clone(),
        set_cookies,
    };
    let page = poc::csrf(&request, &target, &opts)?;
    if let Some(path) = &args.output {
        crate::output::write_file(path, page.html.as_bytes(), args.force)?;
    }
    let data = json!({
        "kind": "csrf",
        "history_id": history_id,
        "method": page.method,
        "action": page.action,
        "encoding": page.encoding,
        "technique": page.technique,
        "fields": page.fields,
        "auto_submit": page.auto_submit,
        "warnings": page.warnings,
        "html": page.html,
        "path": args.output.as_ref().map(|p| p.display().to_string()),
    });
    let summary = format!("CSRF page: {} {}", page.method, page.action);
    print(out, data, &page.warnings, &page.html, args.output.as_deref(), summary);
    Ok(())
}

fn clickjacking(project: &Path, args: ClickjackingArgs, out: &Out) -> Result<(), Error> {
    crate::mcp::check_force(args.force, "poc clickjacking", "write the page to a new file, or leave out --output")?;
    let (url, item, history_id, store) = match (args.history_id, &args.url) {
        (Some(id), _) => {
            let store = Store::open(project)?;
            let item = store.get(id)?;
            (item.entry.url.clone(), Some(item), Some(id), Some(store))
        }
        (None, Some(url)) => {
            let store = existing_store(project)?;
            let host = Target::from_url(url)?.host;
            // The newest exchange for this URL, as written or as the parser writes it.
            let item = match &store {
                Some(s) => {
                    let rows = s.list(&HistoryFilter { host: Some(host), ..Default::default() })?;
                    match rows.iter().rev().find(|e| poc::same_url(&e.url, url) && e.status.is_some()) {
                        Some(e) => Some(s.get(e.id)?),
                        None => None,
                    }
                }
                None => None,
            };
            let id = item.as_ref().map(|i| i.entry.id);
            (url.clone(), item, id, store)
        }
        _ => return Err(Error::InvalidInput("name the page: --history-id ID, or --url URL".into())),
    };
    let head = item.as_ref().and_then(|i| response_head(&i.response));
    let cookies = item
        .as_ref()
        .and_then(|i| RawRequest::from_bytes(i.request.clone()).head().ok())
        .and_then(|h| h.headers.into_iter().find(|(k, _)| k.eq_ignore_ascii_case("cookie")).map(|(_, v)| v))
        .map(|c| poc::cookie_names(&c))
        .unwrap_or_default();
    let set_cookies = match (&store, &item) {
        (Some(s), Some(i)) => recorded_set_cookies(s, &i.target.host)?,
        _ => Vec::new(),
    };
    let opts = ClickjackingOptions { opacity: args.opacity, decoy: args.decoy.clone(), cookies, set_cookies };
    let page = poc::clickjacking(&url, head.as_ref(), &opts)?;
    if let Some(path) = &args.output {
        crate::output::write_file(path, page.html.as_bytes(), args.force)?;
    }
    let data = json!({
        "kind": "clickjacking",
        "history_id": history_id,
        "url": page.url,
        "framing": page.framing,
        "warnings": page.warnings,
        "html": page.html,
        "path": args.output.as_ref().map(|p| p.display().to_string()),
    });
    let summary = format!(
        "clickjacking page for {}{}",
        page.url,
        match page.framing.blocked {
            Some(true) => " (the response says it can't be framed)",
            Some(false) => "",
            None => " (no recorded response)",
        }
    );
    print(out, data, &page.warnings, &page.html, args.output.as_deref(), summary);
    Ok(())
}

/// JSON: the envelope. Text: the page itself (or, with --output, a line saying where it went),
/// with the warnings on stderr. On a terminal, control characters from the target are escaped.
fn print(out: &Out, data: Value, warnings: &[String], html: &str, output: Option<&Path>, summary: String) {
    if !out.json() {
        for w in warnings {
            eprintln!("warning: {}", crate::output::escape_controls(w));
        }
        eprintln!("note: {OPENED}");
    }
    out.ok(data, || match output {
        Some(path) => {
            crate::output::escape_controls(&format!("{summary}; wrote it to {}", path.display())).into_owned()
        }
        None if std::io::stdout().is_terminal() => {
            html.lines().map(|l| crate::output::escape_controls(l).into_owned()).collect::<Vec<_>>().join("\n")
        }
        None => html.to_string(),
    });
}
