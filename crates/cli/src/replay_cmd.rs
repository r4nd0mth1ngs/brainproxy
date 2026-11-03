//! `replay tabs`: the Replay tabs the app shows, kept in the project file so they come back
//! when it is opened again and travel with it. Only what was typed is kept (title, target,
//! request or handshake and messages, per-tab settings), never responses. Requests are
//! stored as given, auth placeholders (`«auth:...»`) included; nothing here sends anything.

use std::io::Read;
use std::path::Path;

use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::output::{escape_controls, Out};
use crate::ws_cmd::MAX_WAIT_SECS;

/// The meta key holding the saved set (JSON): `{"v", "rev", "tabs", "active"}`.
const KEY: &str = "replay.tabs";
/// Format of the saved set. A build refuses to save over a newer one, whose fields it would drop.
const VERSION: u64 = 1;
/// Largest saved set, in bytes of JSON.
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_TABS: usize = 500;
const MAX_TITLE: usize = 200;
const MAX_TARGET: usize = 2048;
const MAX_UNTIL: usize = 1000;

#[derive(Subcommand)]
pub enum ReplayCmd {
    /// Replay tabs saved in the project (the app restores them when the project opens).
    #[command(subcommand)]
    Tabs(TabsCmd),
}

#[derive(Subcommand)]
pub enum TabsCmd {
    /// List the saved Replay tabs: title, target, and the request or handshake and messages.
    #[command(after_help = "Tabs are numbered from 0 (the index in `tabs`, as `active` counts). rev goes up \
        with every save; `save --if-revision` checks it. Requests are listed as stored, so a live Cookie or \
        Authorization typed into a tab is listed in full.")]
    List {
        /// Each tab's index, kind, title, target and sizes, without its request or messages.
        #[arg(long, conflicts_with = "index")]
        summary: bool,
        /// Only the tab at this index (from 0), in full.
        #[arg(long, value_name = "N")]
        index: Option<usize>,
    },
    /// Replace the saved Replay tabs with the JSON on stdin (or add to them with --append).
    #[command(after_help = "Reads JSON from stdin: {\"tabs\": [{\"kind\": \"http\", \"title\": \"login\", \
        \"target\": \"https://app.example.com\", \"request\": \"POST /login HTTP/1.1\\nHost: ...\"}, \
        {\"kind\": \"ws\", \"title\": \"feed\", \"target\": \"wss://app.example.com\", \"request\": \"GET /ws HTTP/1.1\\n...\", \
        \"messages\": [\"{\\\"op\\\":\\\"sub\\\"}\"], \"wait\": 3, \"until\": \"done\"}], \"active\": 0}. \
        kind is http (default) or ws; binary marks an http request held one character per byte; messages, \
        wait (seconds, at most 86400) and until (regex) are for ws tabs; active is the index of the tab shown \
        (with --append, among the tabs given). Text is stored as given, auth placeholders included: write \
        «auth:...» placeholders rather than live cookies or tokens. Responses are never stored. At most 500 tabs \
        and 16 MB. An empty list leaves no tabs. Through MCP only --append is allowed, so an agent can't remove \
        a person's tabs. Nothing is sent: Replay sends a tab when someone presses Send.")]
    Save {
        /// Add the tabs after the saved ones instead of replacing them.
        #[arg(long)]
        append: bool,
        /// Save only if the saved set is still at this revision (`rev` from list or save; 0 when none
        /// was saved); otherwise fail with a conflict and change nothing.
        #[arg(long, value_name = "REV")]
        if_revision: Option<u64>,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    #[default]
    Http,
    Ws,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tab {
    #[serde(default)]
    kind: Kind,
    #[serde(default)]
    title: String,
    #[serde(default)]
    target: String,
    /// The raw request, or a WebSocket tab's handshake.
    request: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    binary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    messages: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wait: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    until: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tabs {
    tabs: Vec<Tab>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active: Option<usize>,
}

pub fn replay(project: &Path, cmd: ReplayCmd, out: &Out) -> Result<(), Error> {
    let ReplayCmd::Tabs(cmd) = cmd;
    match cmd {
        TabsCmd::List { summary, index } => {
            let saved = load(&Store::open(project)?)?;
            let tabs = saved["tabs"].as_array().cloned().unwrap_or_default();
            let rev = saved["rev"].as_u64().unwrap_or(0);
            // The app shows a newer format's tabs but doesn't save over them.
            let v = saved["v"].as_u64().unwrap_or(VERSION);
            // Typed or prepared by someone else: shown escaped, stored and in JSON as is.
            let line = |i: usize, t: &Value| {
                let kind = escape_controls(t["kind"].as_str().unwrap_or("http"));
                let title = escape_controls(t["title"].as_str().unwrap_or_default());
                let target = escape_controls(t["target"].as_str().unwrap_or_default());
                format!("{i:>3}  {kind:<4}  {title}  {target}")
            };
            if let Some(i) = index {
                let tab = tabs.get(i).ok_or_else(|| {
                    Error::NotFound(format!("Replay tab {i}: there are {} (numbered from 0)", tabs.len()))
                })?;
                let data = json!({"count": tabs.len(), "rev": rev, "v": v, "index": i, "tab": tab});
                out.ok(data, || {
                    let mut lines = vec![line(i, tab)];
                    let text = tab["request"].as_str().unwrap_or_default();
                    lines.extend(text.split('\n').map(|l| escape_controls(l.trim_end_matches('\r')).into_owned()));
                    for m in tab["messages"].as_array().into_iter().flatten() {
                        lines.push(format!("--- {}", escape_controls(m.as_str().unwrap_or_default())));
                    }
                    lines.join("\n")
                });
                return Ok(());
            }
            let listed: Vec<Value> = if summary {
                tabs.iter()
                    .enumerate()
                    .map(|(i, t)| {
                        let mut s = json!({"index": i, "kind": t["kind"], "title": t["title"], "target": t["target"],
                            "request_bytes": t["request"].as_str().map_or(0, str::len)});
                        if let Some(m) = t["messages"].as_array() {
                            s["messages"] = json!(m.len());
                        }
                        s
                    })
                    .collect()
            } else {
                tabs.clone()
            };
            let data = json!({"count": tabs.len(), "active": saved["active"], "rev": rev, "v": v, "tabs": listed});
            out.ok(data, || {
                if tabs.is_empty() {
                    return "no saved Replay tabs".into();
                }
                tabs.iter().enumerate().map(|(i, t)| line(i, t)).collect::<Vec<_>>().join("\n")
            });
        }
        TabsCmd::Save { append, if_revision } => {
            if crate::mcp::in_tool_call() && !append {
                return Err(Error::InvalidInput(
                    "through MCP Replay tabs can only be added (append: true), so an agent can't remove the ones a \
                     person keeps; replacing them is for the app or a terminal"
                        .into(),
                ));
            }
            let mut input = Vec::new();
            std::io::stdin().take(MAX_BYTES as u64 + 1).read_to_end(&mut input)?;
            let set = parse(&input)?;
            let given = set.tabs.len();
            let mut store = Store::open(project)?;
            let (count, bytes, rev) = store.meta_update(KEY, |old| {
                let (rev, before, active) = current(old.as_deref(), append || if_revision.is_some())?;
                if let Some(want) = if_revision.filter(|w| *w != rev) {
                    return Err(Error::Conflict(format!(
                        "the saved Replay tabs are at revision {rev}, not {want}: they were saved from elsewhere \
                         meanwhile; list them again"
                    )));
                }
                let (before, active) = if append { (before, active) } else { (Vec::new(), None) };
                let (json, count) = build(set, before, active, rev + 1)?;
                let len = json.len();
                Ok((Some(json), (count, len, rev + 1)))
            })?;
            let mut data = json!({"count": count, "bytes": bytes, "rev": rev});
            if append {
                data["added"] = json!(given);
            }
            out.ok(data, || {
                let s = |n: usize| if n == 1 { "" } else { "s" };
                if append {
                    format!("added {given} Replay tab{} ({count} saved)", s(given))
                } else {
                    format!("saved {count} Replay tab{}", s(count))
                }
            });
        }
    }
    Ok(())
}

/// The saved set as stored, or an empty one. Not re-validated, so a set saved by a newer
/// version still lists.
fn load(store: &Store) -> Result<Value, Error> {
    match store.meta_get(KEY)? {
        Some(s) => serde_json::from_str(&s)
            .map_err(|e| Error::InvalidInput(format!("the saved Replay tabs are not valid JSON ({e}); save new ones"))),
        None => Ok(json!({"tabs": []})),
    }
}

/// The stored set's revision, tabs and active tab, for a save over it. Refuses a set of a newer
/// format, and a broken one when it is to be kept (`keep`: appending or checking the revision).
fn current(stored: Option<&str>, keep: bool) -> Result<(u64, Vec<Value>, Option<usize>), Error> {
    let Some(s) = stored else { return Ok((0, Vec::new(), None)) };
    let v: Value = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(_) if !keep => return Ok((0, Vec::new(), None)),
        Err(e) => {
            return Err(Error::InvalidInput(format!(
                "the saved Replay tabs are not valid JSON ({e}); save new ones without --append or --if-revision"
            )))
        }
    };
    let version = v["v"].as_u64().unwrap_or(1);
    if version > VERSION {
        return Err(Error::Conflict(format!(
            "the saved Replay tabs were saved by a newer brainproxy (format {version}, this one writes {VERSION}), \
             which keeps things this one would drop; update brainproxy to change them"
        )));
    }
    let tabs = v["tabs"].as_array().cloned().unwrap_or_default();
    let active = v["active"].as_u64().map(|a| a as usize).filter(|a| *a < tabs.len());
    Ok((v["rev"].as_u64().unwrap_or(0), tabs, active))
}

/// Checks a set to save. Returns it as given; [`build`] makes what is stored.
fn parse(input: &[u8]) -> Result<Tabs, Error> {
    if input.len() > MAX_BYTES {
        return Err(too_big());
    }
    let set: Tabs = serde_json::from_slice(input).map_err(|e| Error::InvalidInput(format!("Replay tabs: {e}")))?;
    if set.tabs.len() > MAX_TABS {
        return Err(Error::InvalidInput(format!(
            "{} Replay tabs; at most {MAX_TABS} can be saved, close some",
            set.tabs.len()
        )));
    }
    if let Some(a) = set.active.filter(|a| *a >= set.tabs.len()) {
        return Err(Error::InvalidInput(format!("active is {a}, but there are {} tabs", set.tabs.len())));
    }
    for (i, t) in set.tabs.iter().enumerate() {
        let bad = |what: String| Error::InvalidInput(format!("Replay tab {i} ({:?}): {what}", t.title));
        if t.title.chars().count() > MAX_TITLE {
            return Err(bad(format!("title is longer than {MAX_TITLE} characters")));
        }
        if t.target.chars().count() > MAX_TARGET {
            return Err(bad(format!("target is longer than {MAX_TARGET} characters")));
        }
        match t.kind {
            Kind::Http if t.messages.is_some() || t.wait.is_some() || t.until.is_some() => {
                return Err(bad("messages, wait and until are for WebSocket tabs (kind ws)".into()));
            }
            Kind::Ws if t.binary => return Err(bad("WebSocket tabs hold text only, not binary".into())),
            _ => {}
        }
        // `ws send` holds the connection this long once someone presses Send.
        if t.wait.is_some_and(|w| !(0.0..=MAX_WAIT_SECS).contains(&w)) {
            return Err(bad(format!("wait must be from 0 to {MAX_WAIT_SECS} seconds")));
        }
        if t.until.as_ref().is_some_and(|u| u.chars().count() > MAX_UNTIL) {
            return Err(bad(format!("until is longer than {MAX_UNTIL} characters")));
        }
    }
    Ok(set)
}

/// The set to store as compact JSON, with its tab count: `set` after the tabs `before` (kept
/// by an append), at revision `rev`. `set.active` counts among its own tabs; without it
/// `active` (among `before`) stays.
fn build(set: Tabs, before: Vec<Value>, active: Option<usize>, rev: u64) -> Result<(String, usize), Error> {
    let count = before.len() + set.tabs.len();
    if count > MAX_TABS {
        return Err(Error::InvalidInput(format!(
            "{count} Replay tabs with the saved ones; at most {MAX_TABS} can be saved, remove some first"
        )));
    }
    let active = set.active.map(|a| a + before.len()).or(active);
    let mut tabs = before;
    for t in set.tabs {
        tabs.push(serde_json::to_value(t).map_err(|e| Error::InvalidInput(e.to_string()))?);
    }
    let mut stored = json!({"v": VERSION, "rev": rev, "tabs": tabs});
    if let Some(a) = active {
        stored["active"] = json!(a);
    }
    let json = serde_json::to_string(&stored).map_err(|e| Error::InvalidInput(e.to_string()))?;
    if json.len() > MAX_BYTES {
        return Err(too_big());
    }
    Ok((json, count))
}

fn too_big() -> Error {
    Error::InvalidInput(format!(
        "Replay tabs are over {} MB, the most a project keeps; close some tabs or shorten large requests",
        MAX_BYTES / (1024 * 1024)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a first save of `input` stores.
    fn save(input: &[u8]) -> Result<(String, usize), Error> {
        build(parse(input)?, Vec::new(), None, 1)
    }

    fn err(input: &str) -> String {
        save(input.as_bytes()).unwrap_err().to_string()
    }

    #[test]
    fn keeps_text_as_typed() {
        let req = "GET /?k=«auth:app:query:k» HTTP/1.1\r\nHost: a.test\r\nX: \u{1}é\r\n\r\n";
        let input = json!({"tabs": [
            {"title": "1", "target": "https://a.test", "request": req, "binary": true},
            {"kind": "ws", "title": "WS 2", "target": "wss://a.test", "request": "GET /ws HTTP/1.1\n\n",
             "messages": ["{\"op\":\"x\"}", "«auth:app:header:X»"], "wait": 2.5, "until": "done|("},
        ], "active": 1})
        .to_string();
        let (json, count) = save(input.as_bytes()).unwrap();
        assert_eq!(count, 2);
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["tabs"][0]["request"], req);
        assert_eq!(v["tabs"][0]["kind"], "http");
        assert_eq!(v["tabs"][0]["binary"], true);
        assert!(v["tabs"][0].get("messages").is_none());
        assert_eq!(v["tabs"][1]["messages"][1], "«auth:app:header:X»");
        // A half-typed regex is kept: it is only checked when the tab is sent.
        assert_eq!(v["tabs"][1]["until"], "done|(");
        assert!(v["tabs"][1].get("binary").is_none());
        assert_eq!(v["active"], 1);
    }

    #[test]
    fn rejects_bad_sets() {
        assert!(err("not json").contains("Replay tabs"));
        assert!(err(r#"{"tabs": [{"title": "x"}]}"#).contains("request"));
        assert!(err(r#"{"tabs": [{"request": "", "response": "HTTP/1.1 200"}]}"#).contains("unknown field"));
        assert!(err(r#"{"tabs": [{"request": "", "kind": "grpc"}]}"#).contains("unknown variant"));
        assert!(err(r#"{"tabs": [{"request": "", "messages": ["a"]}]}"#).contains("WebSocket tabs"));
        assert!(err(r#"{"tabs": [{"request": "", "kind": "ws", "binary": true}]}"#).contains("text only"));
        assert!(err(r#"{"tabs": [{"request": "", "kind": "ws", "wait": -1}]}"#).contains("wait"));
        // Send would hold the connection for ages (or panic making the duration).
        assert!(
            err(r#"{"tabs": [{"request": "", "kind": "ws", "wait": 1e300}]}"#).contains("wait must be from 0 to 86400")
        );
        assert!(err(r#"{"tabs": [{"request": "", "kind": "ws", "wait": 86400.5}]}"#).contains("wait"));
        assert!(err(r#"{"tabs": [{"request": ""}], "active": 1}"#).contains("active is 1"));
        let long = json!({"tabs": [{"request": "", "title": "t".repeat(MAX_TITLE + 1)}]}).to_string();
        assert!(err(&long).contains("title"));
        let many = json!({"tabs": (0..=MAX_TABS).map(|_| json!({"request": ""})).collect::<Vec<_>>()}).to_string();
        assert!(err(&many).contains("at most 500"));
    }

    #[test]
    fn caps_the_size() {
        let big = json!({"tabs": [{"request": "a".repeat(MAX_BYTES)}]}).to_string();
        assert!(err(&big).contains("over 16 MB"), "{}", err(&big));
        let fits = json!({"tabs": [{"request": "a".repeat(MAX_BYTES - 100)}]}).to_string();
        assert_eq!(save(fits.as_bytes()).unwrap().1, 1);
    }

    #[test]
    fn the_cap_counts_what_is_stored() {
        // Under the cap as sent, over it once the left-out kind, title and target are filled in.
        let per_tab = (MAX_BYTES - 1000) / MAX_TABS - r#"{"request":""},"#.len();
        let tab = format!(r#"{{"request":"{}"}}"#, "a".repeat(per_tab));
        let input = format!(r#"{{"tabs":[{}]}}"#, vec![tab; MAX_TABS].join(","));
        assert!(input.len() <= MAX_BYTES);
        assert!(err(&input).contains("over 16 MB"), "{}", err(&input));
    }

    #[test]
    fn limits_are_inclusive_and_count_characters() {
        let ok = |v: Value| save(v.to_string().as_bytes()).map(|(_, n)| n).map_err(|e| e.to_string());
        let all = json!({"tabs": (0..MAX_TABS).map(|_| json!({"request": ""})).collect::<Vec<_>>()});
        assert_eq!(ok(all), Ok(MAX_TABS));
        // Characters, not bytes: 200 two-byte characters are a 200-character title.
        assert_eq!(ok(json!({"tabs": [{"request": "", "title": "é".repeat(MAX_TITLE)}]})), Ok(1));
        assert_eq!(ok(json!({"tabs": [{"request": "", "target": "t".repeat(MAX_TARGET)}]})), Ok(1));
        let e = ok(json!({"tabs": [{"request": "", "target": "t".repeat(MAX_TARGET + 1)}]})).unwrap_err();
        assert!(e.contains("target is longer"), "{e}");
        assert_eq!(ok(json!({"tabs": [{"kind": "ws", "request": "", "until": "u".repeat(MAX_UNTIL)}]})), Ok(1));
        let e = ok(json!({"tabs": [{"kind": "ws", "request": "", "until": "u".repeat(MAX_UNTIL + 1)}]})).unwrap_err();
        assert!(e.contains("until is longer"), "{e}");
    }

    #[test]
    fn edge_values() {
        // JSON.stringify writes NaN and Infinity as null: no wait, which is fine.
        let (json, _) = save(br#"{"tabs": [{"kind": "ws", "request": "", "wait": null, "messages": []}]}"#).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v["tabs"][0].get("wait").is_none(), "{v}");
        assert_eq!(v["tabs"][0]["messages"], json!([]));
        let (json, _) = save(br#"{"tabs": [{"kind": "ws", "request": "", "wait": 0}]}"#).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&json).unwrap()["tabs"][0]["wait"], 0.0);
        let (json, _) = save(br#"{"tabs": [{"kind": "ws", "request": "", "wait": 86400}]}"#).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&json).unwrap()["tabs"][0]["wait"], 86400.0);
        // Defaults are filled in and an unset binary is left out.
        let (json, count) = save(br#"{"tabs": [{"request": "x", "binary": false}]}"#).unwrap();
        assert_eq!(count, 1);
        assert_eq!(json, r#"{"v":1,"rev":1,"tabs":[{"kind":"http","title":"","target":"","request":"x"}]}"#);
        // Nothing open: nothing can be active.
        assert_eq!(save(br#"{"tabs": []}"#).unwrap(), (r#"{"v":1,"rev":1,"tabs":[]}"#.to_string(), 0));
        assert!(err(r#"{"tabs": [], "active": 0}"#).contains("active is 0"));
        assert!(err(r#"{"tabs": [{"request": ""}], "active": -1}"#).contains("Replay tabs"));
        assert!(err(r#"{"tabs": [], "responses": []}"#).contains("unknown field"));
        assert!(err(r#"{"active": 0}"#).contains("tabs"));
        assert!(err(r#"{"tabs": [{"request": "", "kind": "WS"}]}"#).contains("unknown variant"));
        assert!(err(r#"{"tabs": [{"request": "", "wait": 1}]}"#).contains("WebSocket tabs"));
        assert!(err(r#"{"tabs": [{"request": "", "until": "x"}]}"#).contains("WebSocket tabs"));
        assert!(err(r#"{"tabs": [{"request": 1}]}"#).contains("Replay tabs"));
    }

    #[test]
    fn an_error_shows_a_title_escaped() {
        // A title from target traffic can't write terminal escapes into the error.
        let e =
            err(&json!({"tabs": [{"request": "", "title": "\u{1b}[2Jx", "kind": "ws", "binary": true}]}).to_string());
        assert!(!e.contains('\u{1b}'), "{e:?}");
        assert!(e.contains(r"\u{1b}[2Jx"), "{e}");
    }

    #[test]
    fn load_lists_newer_sets_and_reports_broken_ones() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(load(&store).unwrap(), json!({"tabs": []}));
        // Saved by a newer version: listed as stored, not re-checked.
        let newer = json!({"tabs": [{"kind": "grpc", "request": "", "extra": 1}], "active": 0, "v": 2});
        store.meta_set(KEY, Some(&newer.to_string())).unwrap();
        assert_eq!(load(&store).unwrap(), newer);
        store.meta_set(KEY, Some("{")).unwrap();
        let e = load(&store).unwrap_err().to_string();
        assert!(e.contains("not valid JSON") && e.contains("save new ones"), "{e}");
    }

    #[test]
    fn append_keeps_the_saved_tabs_and_their_active_one() {
        let saved = json!({"v": 1, "rev": 4, "tabs": [{"kind": "http", "request": "a"}, {"request": "b", "later": 1}],
            "active": 1})
        .to_string();
        let (rev, before, active) = current(Some(&saved), true).unwrap();
        assert_eq!((rev, before.len(), active), (4, 2, Some(1)));
        // Kept as stored, a newer field included; the active tab stays unless the new set names one.
        let (json, count) =
            build(parse(br#"{"tabs": [{"request": "c"}]}"#).unwrap(), before.clone(), active, 5).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!((count, &v["rev"], &v["active"]), (3, &json!(5), &json!(1)));
        assert_eq!(v["tabs"][1]["later"], 1);
        assert_eq!(v["tabs"][2]["request"], "c");
        let (json, _) =
            build(parse(br#"{"tabs": [{"request": "c"}], "active": 0}"#).unwrap(), before, active, 5).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&json).unwrap()["active"], 2);
        // The cap counts the saved tabs too.
        let full = vec![json!({"request": ""}); MAX_TABS];
        let e = build(parse(br#"{"tabs": [{"request": ""}]}"#).unwrap(), full, None, 1).unwrap_err().to_string();
        assert!(e.contains("501 Replay tabs with the saved ones"), "{e}");
    }

    #[test]
    fn a_save_refuses_newer_and_broken_sets_it_would_lose() {
        assert_eq!(current(None, true).unwrap(), (0, Vec::new(), None));
        // Before revisions: revision 0; an active past the end is dropped.
        let (rev, tabs, active) = current(Some(r#"{"tabs": [{"request": ""}], "active": 3}"#), true).unwrap();
        assert_eq!((rev, tabs.len(), active), (0, 1, None));
        let newer = json!({"v": 2, "rev": 9, "tabs": []}).to_string();
        let e = current(Some(&newer), false).unwrap_err();
        assert_eq!(e.kind(), "conflict");
        assert!(e.to_string().contains("newer brainproxy (format 2"), "{e}");
        // A broken set can only be replaced outright.
        assert_eq!(current(Some("{"), false).unwrap(), (0, Vec::new(), None));
        assert!(current(Some("{"), true).unwrap_err().to_string().contains("without --append"));
    }
}
