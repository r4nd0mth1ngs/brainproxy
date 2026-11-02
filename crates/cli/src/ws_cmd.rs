//! WebSocket history and replay: connections recorded by the proxy (or `ws send`), their
//! messages, and new connections that replay a handshake and send messages.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use brainproxy_core::capture::Capture;
use brainproxy_core::http::{Client, RawRequest, SendOptions, Target};
use brainproxy_core::store::Store;
use brainproxy_core::ws::db::{ConnectionFilter, MessageFilter, WsEvent};
use brainproxy_core::ws::{self, client, opcode_from_name, Direction, Message};
use brainproxy_core::{codec, Error};
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};

use crate::output::{body_value, Out};

#[derive(Subcommand)]
pub enum WsCmd {
    /// List recorded WebSocket connections (proxied and replayed), oldest first.
    List {
        #[arg(long)]
        host: Option<String>,
        /// proxy (browser traffic) or replay (ws send).
        #[arg(long)]
        source: Option<String>,
        #[arg(long, value_enum)]
        state: Option<ConnState>,
        /// Only connections with an id greater than this (for incremental polling).
        #[arg(long)]
        after: Option<i64>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// The newest --limit connections (still listed oldest first) instead of the oldest.
        #[arg(long)]
        newest: bool,
    },
    /// Show one connection: URL, upgrade request and response, how it closed, message counts.
    Show {
        id: i64,
        /// Maximum body bytes of the upgrade request and response to include.
        #[arg(long, default_value_t = 65536)]
        max_body: usize,
    },
    /// List a connection's messages in order, with their payloads.
    Messages {
        /// Connection id (ws list).
        connection: i64,
        #[arg(long, value_enum)]
        direction: Option<DirArg>,
        #[arg(long, value_enum)]
        opcode: Option<OpArg>,
        /// Only messages whose payload contains this text.
        #[arg(long)]
        contains: Option<String>,
        /// Only messages with an id greater than this (for incremental polling).
        #[arg(long)]
        after: Option<i64>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// Maximum payload bytes per message in the output.
        #[arg(long, default_value_t = 4096)]
        max_body: usize,
    },
    /// Replay: open a new connection with a recorded (or new) handshake, send messages, and
    /// print what comes back.
    #[command(after_help = "Handshake sources, in order: --from CONN (a recorded connection), --history ID (an \
        upgrade request in history), --url ws(s)://..., --input-json, FILE, or stdin. A new Sec-WebSocket-Key is always used; \
        -H and --remove-header change the handshake. Messages go out in order: --resend ones first, then \
        --message ones, then --input-json ones. Replies are collected until --until matches, --max-messages arrive, the server closes, \
        or --wait seconds pass after the last message; the connection is then closed. Everything is recorded \
        (history source ws, connection source replay) unless --no-store.")]
    Send(Box<SendArgs>),
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ConnState {
    Open,
    Closed,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum DirArg {
    ToServer,
    ToClient,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum OpArg {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

#[derive(clap::Args)]
pub struct SendArgs {
    /// Raw handshake request file; '-' or omitted reads stdin (unless --from, --history or --url is given).
    file: Option<String>,
    /// Replay the handshake of this recorded connection (see `ws list`).
    #[arg(long, value_name = "CONN")]
    from: Option<i64>,
    /// Replay this history entry's request as the handshake.
    #[arg(long, value_name = "ID")]
    history: Option<i64>,
    /// Connect to this ws:// or wss:// URL with a new handshake.
    #[arg(long)]
    url: Option<String>,
    /// Where to send a raw handshake (http(s):// or ws(s)://host[:port]). Defaults to the Host header.
    #[arg(long)]
    target: Option<String>,
    /// Scheme used with the Host header when --target is not given.
    #[arg(long, default_value = "https", value_parser = ["http", "https"])]
    scheme: String,
    /// Set a header on the handshake ("Name: value"). Repeatable.
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// Remove a header from the handshake. Repeatable.
    #[arg(long)]
    remove_header: Vec<String>,
    /// Message to send (a text frame). Repeatable; sent in order. On the command line it is visible in
    /// the process list and limited in size; --input-json has neither problem.
    #[arg(short = 'm', long = "message")]
    messages: Vec<String>,
    /// Read JSON from stdin: {"messages": ["text", ...], "handshake": "GET / HTTP/1.1..."}. Both are
    /// optional; messages go out after --resend and --message ones.
    #[arg(long, conflicts_with = "file")]
    input_json: bool,
    /// Send each --message as a binary frame; the values are base64.
    #[arg(long)]
    binary: bool,
    /// Send a recorded message again (same opcode and payload). Repeatable.
    #[arg(long, value_name = "MESSAGE_ID")]
    resend: Vec<i64>,
    /// Seconds to keep listening after the last message is sent.
    #[arg(long, default_value_t = 5.0)]
    wait: f64,
    /// Stop listening as soon as a received text or binary message matches this regex.
    #[arg(long)]
    until: Option<String>,
    /// Stop listening after this many text or binary messages.
    #[arg(long, default_value_t = 100)]
    max_messages: usize,
    /// Apply this auth profile's session to the handshake (cookies/headers; re-login if logged out).
    #[arg(long, value_name = "NAME")]
    auth: Option<String>,
    /// Don't record the connection.
    #[arg(long)]
    no_store: bool,
    /// Maximum payload bytes per message in the output.
    #[arg(long, default_value_t = 4096)]
    max_body: usize,
    /// Seconds the handshake, and sending the messages, may take.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    /// Verify the server certificate.
    #[arg(long)]
    verify_tls: bool,
    /// Override the TLS SNI host name.
    #[arg(long)]
    sni: Option<String>,
}

pub fn ws(project: &Path, cmd: WsCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        WsCmd::List { host, source, state, after, limit, newest } => {
            let store = Store::open(project)?;
            let state = state.map(|s| match s {
                ConnState::Open => "open".to_string(),
                ConnState::Closed => "closed".to_string(),
            });
            let items =
                store.ws_connections(&ConnectionFilter { host, source, state, after_id: after, limit, newest })?;
            let data = json!({"count": items.len(), "items": items});
            out.ok(data, || {
                items
                    .iter()
                    .map(|c| format!("{:>6}  {:<6} {:<7} {:>5} msgs  {}", c.id, c.state, c.source, c.messages, c.url))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        WsCmd::Show { id, max_body } => {
            let store = Store::open(project)?;
            let c = store.ws_connection(id)?;
            let handshake = match c.history_id.map(|h| store.get(h)) {
                Some(Ok(item)) => {
                    let mut v = crate::exchange_json(
                        Some(item.entry.id),
                        &item.target,
                        &item.request,
                        &item.response,
                        item.entry.duration_ms.map(|d| d as u64),
                        max_body,
                    );
                    v["request"] = body_value(&item.request, max_body);
                    v
                }
                _ => Value::Null,
            };
            let counts: Vec<Value> = store
                .ws_message_counts(id)?
                .into_iter()
                .map(|(d, o, n)| json!({"direction": d, "opcode": o, "count": n}))
                .collect();
            let text = format!(
                "#{} {} {} ({}, {} messages){}",
                c.id,
                c.state,
                c.url,
                c.source,
                c.messages,
                c.close_code.map(|code| format!(", closed {code}")).unwrap_or_default()
            );
            out.ok(json!({"connection": c, "handshake": handshake, "message_counts": counts}), || text);
        }
        WsCmd::Messages { connection, direction, opcode, contains, after, limit, max_body } => {
            let store = Store::open(project)?;
            let direction = direction.map(|d| dir_name(d).to_string());
            let opcode = opcode.map(|o| op_name(o).to_string());
            let items = store
                .ws_messages(connection, &MessageFilter { direction, opcode, contains, after_id: after, limit })?;
            let values: Vec<Value> = items
                .iter()
                .map(|m| {
                    let mut v = json!(m);
                    v["payload"] = body_value(&m.payload, max_body);
                    v
                })
                .collect();
            out.ok(json!({"connection_id": connection, "count": items.len(), "items": values}), || {
                items
                    .iter()
                    .map(|m| text_line(m.id, &m.direction, &m.opcode, &m.payload, max_body))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        WsCmd::Send(args) => send(project, *args, out)?,
    }
    Ok(())
}

fn dir_name(d: DirArg) -> &'static str {
    match d {
        DirArg::ToServer => Direction::ToServer.as_str(),
        DirArg::ToClient => Direction::ToClient.as_str(),
    }
}

fn op_name(o: OpArg) -> &'static str {
    match o {
        OpArg::Text => "text",
        OpArg::Binary => "binary",
        OpArg::Close => "close",
        OpArg::Ping => "ping",
        OpArg::Pong => "pong",
    }
}

fn text_line(id: i64, direction: &str, opcode: &str, payload: &[u8], max: usize) -> String {
    let arrow = if direction == "to-server" { "->" } else { "<-" };
    let shown = String::from_utf8_lossy(&payload[..payload.len().min(max)]).replace(['\n', '\r'], " ");
    let id = if id > 0 { format!("{id:>6}  ") } else { String::new() };
    format!("{id}{arrow} {opcode:<6} {shown}")
}

/// ws:// and wss:// as the http(s) origin the handshake goes to.
fn http_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = url.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        url.to_string()
    }
}

/// What `--input-json` reads from stdin.
#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    handshake: Option<String>,
    #[serde(default)]
    messages: Vec<String>,
}

/// The handshake to send and where to, from the first source given.
fn handshake_source(store: &Store, args: &SendArgs, input: &Input) -> Result<(RawRequest, Target), Error> {
    let headers = args.headers.iter().map(|h| crate::request_args::parse_header(h)).collect::<Result<Vec<_>, _>>()?;
    let history =
        match (args.from, args.history) {
            (Some(conn), _) => Some(store.ws_connection(conn)?.history_id.ok_or_else(|| {
                Error::NotFound(format!("WebSocket connection {conn} has no recorded upgrade request"))
            })?),
            (None, h) => h,
        };
    let (mut req, inferred) = if let Some(id) = history {
        let item = store.get(id)?;
        (RawRequest::from_bytes(item.request), Some(item.target))
    } else if let Some(url) = &args.url {
        let (req, target) = RawRequest::build("GET", &http_url(url), &[], b"")?;
        (req, Some(target))
    } else {
        let bytes = match args.file.as_deref() {
            _ if args.input_json => input.handshake.clone().unwrap_or_default().into_bytes(),
            Some(path) if path != "-" => std::fs::read(path)
                .map_err(|e| Error::InvalidInput(format!("cannot read handshake file {path:?}: {e}")))?,
            _ => crate::read_input(None)?,
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Err(Error::InvalidInput("empty handshake; pass --from, --history, --url, a FILE, or stdin".into()));
        }
        (RawRequest::from_bytes(bytes).normalize_line_endings(), None)
    };
    for (k, v) in &headers {
        req = req.set_header(k, v);
    }
    for name in &args.remove_header {
        req = req.remove_header(name);
    }
    let target = match (&args.target, inferred) {
        (Some(t), _) => Target::from_url(&http_url(t))?,
        (None, Some(t)) => t,
        (None, None) => req.infer_target(&args.scheme)?,
    };
    Ok((client::handshake(req), target))
}

/// The messages to send, --resend ones first.
fn outgoing(store: &Store, args: &SendArgs, input: &Input) -> Result<Vec<(u8, Vec<u8>)>, Error> {
    let mut list = Vec::new();
    for id in &args.resend {
        let m = store.ws_message(*id)?;
        list.push((opcode_from_name(&m.opcode)?, m.payload));
    }
    for m in &args.messages {
        list.push(if args.binary {
            (ws::OP_BINARY, codec::decode("base64", m.as_bytes())?)
        } else {
            (ws::OP_TEXT, m.as_bytes().to_vec())
        });
    }
    list.extend(input.messages.iter().map(|m| (ws::OP_TEXT, m.as_bytes().to_vec())));
    Ok(list)
}

fn send(project: &Path, args: SendArgs, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    let input = if args.input_json {
        serde_json::from_slice(&crate::read_input(None)?)
            .map_err(|e| Error::InvalidInput(format!("--input-json: {e}")))?
    } else {
        Input::default()
    };
    let (handshake, target) = handshake_source(&store, &args, &input)?;
    let messages = outgoing(&store, &args, &input)?;
    let until = args
        .until
        .as_deref()
        .map(regex::bytes::Regex::new)
        .transpose()
        .map_err(|e| Error::InvalidInput(format!("--until: {e}")))?;
    let guard = store.guard()?;
    // Refuse out-of-scope targets up front, before any connection is attempted.
    crate::require_in_scope(&guard, &target)?;
    let send_opts = SendOptions {
        guard: Some(guard),
        timeout: Duration::from_secs_f64(args.timeout.max(0.001)),
        verify_tls: args.verify_tls,
        sni: args.sni.clone(),
        http2: false,
    };
    let session = crate::auth_cmd::maybe_session(project, args.auth.as_deref(), &send_opts)?;
    let client = Client::new(send_opts);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(Error::Io)?;
    let opts = client::Options {
        wait: Duration::from_secs_f64(args.wait.max(0.0)),
        until,
        max_messages: args.max_messages.max(1),
        write_timeout: Duration::from_secs_f64(args.timeout.max(0.001)),
    };

    let (sent, opened) = rt.block_on(async {
        let mut sent = match &session {
            Some(s) => RawRequest::from_bytes(s.apply_to(handshake.as_bytes(), &[], &target)),
            None => handshake.clone(),
        };
        let generation = session.as_ref().map(|s| s.generation()).unwrap_or(0);
        let mut opened = client::open(&client, &target, &sent).await;
        if let (Some(s), Ok(Err((response, _)))) = (&session, &opened) {
            s.observe(response);
            // Session lost: log in again and retry with the new session.
            if s.is_logged_out(response) && s.relogin(generation).await {
                sent = client::handshake(RawRequest::from_bytes(s.apply_to(handshake.as_bytes(), &[], &target)));
                opened = client::open(&client, &target, &sent).await;
            }
        }
        (sent, opened)
    });
    if let Some(s) = &session {
        s.save()?;
    }
    let mut store = if args.no_store { None } else { Some(store) };
    let opened = match opened {
        Ok(o) => o,
        Err(e) => {
            if let Some(s) = &store {
                s.record_failure("ws", &target, sent.as_bytes(), &e.to_string())?;
            }
            return Err(e);
        }
    };
    let opened = match opened {
        Ok(o) => o,
        Err((response, ms)) => {
            let capture = Capture::new("ws", &target, sent.as_bytes(), Some(&response), Some(ms as i64), None);
            let id = store.as_ref().map(|s| s.record(&capture)).transpose()?;
            let mut data = crate::exchange_json(id, &target, sent.as_bytes(), &response, Some(ms), args.max_body);
            data["upgraded"] = json!(false);
            data["hint"] = json!("The server did not switch protocols (no 101 with Upgrade: websocket); see response.");
            out.ok(data, || format!("not upgraded\n\n{}", String::from_utf8_lossy(&response)));
            return Ok(());
        }
    };
    let (response, duration_ms, accept_ok) = (opened.response.clone(), opened.duration_ms, opened.accept_ok);
    let outcome = rt.block_on(client::talk(opened, &messages, &opts));
    let url =
        ws::ws_url(&format!("{}{}", target.origin(), sent.head().map(|h| h.target).unwrap_or_else(|_| "/".into())));

    let (mut connection_id, mut history_id, mut ids) = (None, None, Vec::new());
    if let Some(s) = store.as_mut() {
        let capture = Capture::new("ws", &target, sent.as_bytes(), Some(&response), Some(duration_ms as i64), None);
        let mut events = vec![WsEvent::Open {
            key: 0,
            capture: Box::new(capture),
            source: "replay",
            url: url.clone(),
            time: ws::now_iso(),
        }];
        events.extend(outcome.events.iter().map(|e| WsEvent::Message {
            key: 0,
            direction: e.direction,
            message: e.message.clone(),
            intercept: None,
        }));
        events.push(WsEvent::Close {
            key: 0,
            time: ws::now_iso(),
            code: outcome.close_code,
            reason: outcome.close_reason.clone(),
            error: outcome.error.clone(),
        });
        let mut keys = HashMap::new();
        s.ws_record(&events[..1], &mut keys)?;
        let conn = keys[&0];
        s.ws_record(&events[1..], &mut keys)?;
        let c = s.ws_connection(conn)?;
        let filter = MessageFilter { limit: outcome.events.len() as u32, ..Default::default() };
        ids = s.ws_messages(conn, &filter)?.into_iter().map(|m| m.id).collect();
        connection_id = Some(conn);
        history_id = c.history_id;
    }

    let received = outcome.events.iter().filter(|e| e.direction == Direction::ToClient && e.message.is_data()).count();
    let items: Vec<Value> = outcome
        .events
        .iter()
        .enumerate()
        .map(|(i, e)| message_json(ids.get(i).copied(), e.direction, &e.message, e.elapsed_ms, args.max_body))
        .collect();
    let head =
        brainproxy_core::http::parse_response_head(brainproxy_core::http::client::final_response(&response)).ok();
    let data = json!({
        "connection_id": connection_id,
        "history_id": history_id,
        "url": url,
        "upgraded": true,
        "accept_ok": accept_ok,
        "extensions": head.as_ref().and_then(|h| h.header("sec-websocket-extensions")),
        "protocol": head.as_ref().and_then(|h| h.header("sec-websocket-protocol")),
        "handshake_ms": duration_ms,
        "stopped": outcome.stopped,
        "received": received,
        "close": {"code": outcome.close_code, "reason": outcome.close_reason},
        "error": outcome.error,
        "messages": items,
    });
    out.ok(data, || {
        let mut lines = vec![format!(
            "{}{url} (stopped: {}, {received} received)",
            connection_id.map(|c| format!("#{c} ")).unwrap_or_default(),
            outcome.stopped
        )];
        lines.extend(outcome.events.iter().enumerate().map(|(i, e)| {
            let opcode = ws::opcode_name(e.message.opcode);
            text_line(ids.get(i).copied().unwrap_or(0), e.direction.as_str(), opcode, &e.message.payload, args.max_body)
        }));
        lines.join("\n")
    });
    Ok(())
}

fn message_json(id: Option<i64>, direction: Direction, m: &Message, elapsed_ms: u64, max_body: usize) -> Value {
    let (code, reason) = m.close_info();
    let mut v = json!({
        "id": id,
        "direction": direction.as_str(),
        "opcode": ws::opcode_name(m.opcode),
        "elapsed_ms": elapsed_ms,
        "compressed": m.compressed,
        "payload": body_value(&m.payload, max_body),
    });
    if code.is_some() {
        v["close"] = json!({"code": code, "reason": reason});
    }
    v
}
