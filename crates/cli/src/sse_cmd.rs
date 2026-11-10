//! Server-sent events: the event streams (`text/event-stream` responses) the proxy relayed or
//! `send` read, and their events.

use std::path::Path;

use brainproxy_core::sse::db::{EventFilter, SseEvent, StreamFilter};
use brainproxy_core::sse::{Event, StreamRead};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};

use crate::output::{body_value, escape_controls, Out};

#[derive(Subcommand)]
pub enum SseCmd {
    /// List recorded event streams (proxied, and read by `send`), oldest first.
    List {
        #[arg(long)]
        host: Option<String>,
        /// proxy (browser traffic) or send (a stream `send` read).
        #[arg(long)]
        source: Option<String>,
        #[arg(long, value_enum)]
        state: Option<StreamState>,
        /// Only streams with an id greater than this (for incremental polling).
        #[arg(long)]
        after: Option<i64>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// The newest --limit streams (still listed oldest first) instead of the oldest.
        #[arg(long)]
        newest: bool,
    },
    /// Show one stream: URL, request and response head, how it ended, event counts by type.
    Show {
        /// Stream id (sse list).
        id: i64,
        /// Maximum body bytes of the request and response to include.
        #[arg(long, default_value_t = 65536)]
        max_body: usize,
    },
    /// List a stream's events in order, with their data.
    Events {
        /// Stream id (sse list).
        stream: i64,
        /// Only events of this type (the `event` field; `message` when an event names none).
        #[arg(long)]
        event: Option<String>,
        /// Only events whose data contains this text.
        #[arg(long)]
        contains: Option<String>,
        /// Only events with an id greater than this (for incremental polling).
        #[arg(long)]
        after: Option<i64>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// Maximum data bytes per event in the output.
        #[arg(long, default_value_t = 4096)]
        max_body: usize,
    },
    /// Show one event: its type, id, retry, arrival time and data.
    Event {
        /// Event id (sse events).
        id: i64,
        /// Print the data only, as it is. Not through MCP, where an event comes in the
        /// envelope that marks it as content from the target.
        #[arg(long)]
        raw: bool,
        /// Maximum data bytes to include.
        #[arg(long, default_value_t = 65536)]
        max_body: usize,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum StreamState {
    Open,
    Closed,
}

pub fn sse(project: &Path, cmd: SseCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        SseCmd::List { host, source, state, after, limit, newest } => {
            let state = state.map(|s| match s {
                StreamState::Open => "open".to_string(),
                StreamState::Closed => "closed".to_string(),
            });
            let items = store.sse_streams(&StreamFilter { host, source, state, after_id: after, limit, newest })?;
            out.ok(json!({"count": items.len(), "items": items}), || {
                items
                    .iter()
                    .map(|s| {
                        let cut = if s.truncated { " (truncated)" } else { "" };
                        format!(
                            "{:>6}  {:<6} {:<5} {:>5} events{cut}  {}",
                            s.id,
                            s.state,
                            s.source,
                            s.events,
                            escape_controls(&s.url)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        SseCmd::Show { id, max_body } => {
            let s = store.sse_stream(id)?;
            let exchange = crate::recorded_exchange_json(&store, s.history_id, max_body);
            let counts: Vec<Value> =
                store.sse_event_counts(id)?.into_iter().map(|(e, n)| json!({"event": e, "count": n})).collect();
            let text = format!(
                "#{} {} {} ({}, {} events{}){}",
                s.id,
                s.state,
                escape_controls(&s.url),
                s.source,
                s.events,
                if s.truncated { ", truncated" } else { "" },
                s.error.as_deref().map(|e| format!(": {}", escape_controls(e))).unwrap_or_default()
            );
            out.ok(json!({"stream": s, "exchange": exchange, "event_counts": counts}), || text);
        }
        SseCmd::Events { stream, event, contains, after, limit, max_body } => {
            let s = store.sse_stream(stream)?;
            let items = store.sse_events(stream, &EventFilter { event, contains, after_id: after, limit })?;
            let values: Vec<Value> = items.iter().map(|e| stored_json(e, max_body)).collect();
            let data = json!({
                "stream_id": stream,
                "state": s.state,
                "truncated": s.truncated,
                "count": items.len(),
                "items": values,
            });
            out.ok(data, || {
                items
                    .iter()
                    .map(|e| text_line(Some(e.id), &e.event, e.event_id.as_deref(), e.data.as_deref(), max_body))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        SseCmd::Event { id, raw, max_body } => {
            if raw && crate::mcp::in_tool_call() {
                return Err(Error::InvalidInput(
                    "--raw: through MCP an event comes in the envelope that marks it as content from the target; \
                     raise --max-body for more of its data"
                        .into(),
                ));
            }
            let e = store.sse_event(id)?;
            if raw {
                out.raw(e.data.as_deref().unwrap_or_default().as_bytes());
                return Ok(());
            }
            out.ok(stored_json(&e, max_body), || {
                let mut about = format!("#{} stream {} {} {}", e.id, e.stream_id, e.time, escape_controls(&e.event));
                if let Some(event_id) = &e.event_id {
                    about.push_str(&format!(" id {}", escape_controls(event_id)));
                }
                if let Some(retry) = e.retry {
                    about.push_str(&format!(" retry {retry} ms"));
                }
                match &e.data {
                    Some(d) => {
                        let mut end = d.len().min(max_body);
                        while !d.is_char_boundary(end) {
                            end -= 1;
                        }
                        let more = d.len() - end;
                        let cut = if more > 0 {
                            format!("\n… ({more} more bytes; raise --max-body)")
                        } else {
                            String::new()
                        };
                        format!("{about}\n\n{}{cut}", crate::output::escape_lines(&d[..end]))
                    }
                    None => format!("{about}\n(no data: a browser dispatches no event for it)"),
                }
            });
        }
    }
    Ok(())
}

/// A stored event as JSON: `data` is null for a block without a data line.
fn stored_json(e: &SseEvent, max_body: usize) -> Value {
    let mut v = json!(e);
    v["data"] = e.data.as_deref().map_or(Value::Null, |d| body_value(d.as_bytes(), max_body));
    v
}

fn text_line(id: Option<i64>, event: &str, event_id: Option<&str>, data: Option<&str>, max: usize) -> String {
    let data = data.unwrap_or("(no data)");
    let mut end = data.len().min(max);
    while !data.is_char_boundary(end) {
        end -= 1;
    }
    let id = id.map(|i| format!("{i:>6}  ")).unwrap_or_default();
    let event_id = event_id.map(|i| format!(" id={}", escape_controls(i))).unwrap_or_default();
    format!("{id}{:<10}{event_id} {}", escape_controls(event), escape_controls(&data[..end]))
}

/// What `send` says of an event stream it read: its events (not yet stored, so without ids),
/// why reading stopped, and whether it went over what a stream may store.
pub fn read_json(read: &StreamRead, stream_id: Option<i64>, max_body: usize) -> Value {
    let event = |e: &Event| {
        json!({
            "time": e.time,
            "event": e.event,
            "event_id": e.event_id,
            "data": e.data.as_deref().map_or(Value::Null, |d| body_value(d.as_bytes(), max_body)),
            "retry": e.retry,
        })
    };
    json!({
        "stream_id": stream_id,
        "stopped": read.stopped.as_str(),
        "truncated": read.truncated,
        "note": read.note,
        "count": read.events.len(),
        "events": read.events.iter().map(event).collect::<Vec<_>>(),
    })
}

/// [`read_json`] for a terminal: a line saying why reading stopped, then a line per event.
pub fn read_text(read: &StreamRead, max_body: usize) -> String {
    let mut lines = vec![format!(
        "event stream: {} events, stopped: {}{}{}",
        read.events.len(),
        read.stopped.as_str(),
        if read.truncated { ", truncated" } else { "" },
        read.note.as_deref().map(|n| format!(" ({})", escape_controls(n))).unwrap_or_default()
    )];
    lines.extend(
        read.events.iter().map(|e| text_line(None, &e.event, e.event_id.as_deref(), e.data.as_deref(), max_body)),
    );
    lines.join("\n")
}
