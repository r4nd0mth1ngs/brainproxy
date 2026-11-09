//! `history export har`: history rows, chosen as `history list` chooses them, as a HAR 1.2
//! file, with session secrets masked as reports mask them.

use std::path::{Path, PathBuf};

use brainproxy_core::har_export;
use brainproxy_core::store::{HistoryFilter, Store};
use brainproxy_core::Error;
use clap::ValueEnum;
use serde_json::json;

use crate::output::Out;

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportKind {
    /// HAR 1.2 (HTTP Archive), as browsers and proxies read and write it.
    Har,
}

#[derive(clap::Args)]
pub struct ExportArgs {
    /// Export format.
    #[arg(value_enum, default_value = "har")]
    kind: ExportKind,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    method: Option<String>,
    #[arg(long)]
    status: Option<u16>,
    /// Tool that produced the entry (e.g. send, proxy, import).
    #[arg(long)]
    source: Option<String>,
    #[arg(long)]
    tag: Option<String>,
    /// Who or what recorded the entry: gui, cli, mcp, or unknown.
    #[arg(long, value_parser = ["gui", "cli", "mcp", "unknown"])]
    origin: Option<String>,
    /// Text the raw request or response, or a decoded body, contains (case-sensitive, literal).
    #[arg(long)]
    contains: Option<String>,
    /// A query in the filter language, as `history list --filter` takes it.
    #[arg(long)]
    filter: Option<String>,
    /// Only entries with an id greater than this.
    #[arg(long)]
    after: Option<i64>,
    /// Maximum entries, oldest first; `truncated` says when more matched.
    #[arg(long, default_value_t = 1000)]
    limit: u32,
    /// Write the file here; stdout then gets a short summary. An existing file is kept unless --force.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Overwrite an existing --output file (not through MCP).
    #[arg(long)]
    force: bool,
    /// Keep session cookies, credentials and tokens as recorded, and bodies that aren't text.
    /// By default they are masked as [redacted], as in reports, and such bodies left out.
    #[arg(long)]
    no_redact: bool,
    /// Mask VALUE too, wherever it appears, in any encoding and ASCII case (at least 6
    /// characters; repeatable).
    #[arg(long, value_name = "VALUE", conflicts_with = "no_redact")]
    mask: Vec<String>,
}

pub fn export(project: &Path, a: ExportArgs, out: &Out) -> Result<(), Error> {
    let ExportKind::Har = a.kind;
    crate::report_cmd::check_mask(&a.mask)?;
    crate::mcp::check_force(a.force, "history export", "write to a new file, or leave out --output")?;
    let store = Store::open(project)?;
    let rows = store.list(&HistoryFilter {
        host: a.host,
        method: a.method,
        status: a.status,
        source: a.source,
        tag: a.tag,
        origin: a.origin,
        contains: a.contains,
        filter: a.filter,
        after_id: a.after,
        limit: Some(a.limit.saturating_add(1)),
    })?;
    let truncated = rows.len() > a.limit as usize;
    let ids: Vec<i64> = rows.iter().take(a.limit as usize).map(|e| e.id).collect();
    let x = har_export::export(&store, &ids, &har_export::Options { redact: !a.no_redact, mask: a.mask })?;
    let pretty = |har: &serde_json::Value| serde_json::to_string_pretty(har).map_err(|e| Error::Io(e.into()));
    let mut summary = json!({
        "kind": "har",
        "entries": x.entries,
        "truncated": truncated,
        "redacted": if a.no_redact { None } else { Some(x.redacted) },
        "binary_bodies_left_out": x.binary_bodies_left_out,
    });
    if let Some(path) = a.output {
        let text = pretty(&x.har)?;
        crate::output::write_file(&path, text.as_bytes(), a.force)?;
        summary["path"] = json!(path.display().to_string());
        summary["bytes"] = json!(text.len());
        out.ok(summary.clone(), || {
            let more = if truncated { " (more matched: raise --limit)" } else { "" };
            format!("wrote {} entries to {}{more}", x.entries, path.display())
        });
    } else if out.json() {
        summary["har"] = x.har;
        out.ok(summary, String::new);
    } else {
        out.raw(pretty(&x.har)?.as_bytes());
    }
    Ok(())
}
