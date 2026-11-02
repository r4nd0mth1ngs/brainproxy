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

/// The meta key holding the saved set (JSON); absent when there are no tabs.
const KEY: &str = "replay.tabs";
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
    List,
    /// Replace the saved Replay tabs with the JSON on stdin; an empty list removes them.
    #[command(after_help = "Reads JSON from stdin: {\"tabs\": [{\"kind\": \"http\", \"title\": \"login\", \
        \"target\": \"https://app.example.com\", \"request\": \"POST /login HTTP/1.1\\nHost: ...\"}, \
        {\"kind\": \"ws\", \"title\": \"feed\", \"target\": \"wss://app.example.com\", \"request\": \"GET /ws HTTP/1.1\\n...\", \
        \"messages\": [\"{\\\"op\\\":\\\"sub\\\"}\"], \"wait\": 3, \"until\": \"done\"}], \"active\": 0}. \
        kind is http (default) or ws; binary marks an http request held one character per byte; messages, \
        wait (seconds) and until (regex) are for ws tabs; active is the index of the tab shown. Text is \
        stored as given, auth placeholders included; responses are never stored. At most 500 tabs and \
        16 MB. Nothing is sent: Replay sends a tab when someone presses Send.")]
    Save,
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
    let store = Store::open(project)?;
    match cmd {
        TabsCmd::List => {
            let saved = load(&store)?;
            let tabs = saved["tabs"].as_array().cloned().unwrap_or_default();
            let data = json!({"count": tabs.len(), "active": saved["active"], "tabs": tabs});
            out.ok(data, || {
                if tabs.is_empty() {
                    return "no saved Replay tabs".into();
                }
                tabs.iter()
                    .enumerate()
                    .map(|(i, t)| {
                        // Typed or prepared by someone else: shown escaped, stored and in JSON as is.
                        let kind = escape_controls(t["kind"].as_str().unwrap_or("http"));
                        let title = escape_controls(t["title"].as_str().unwrap_or_default());
                        let target = escape_controls(t["target"].as_str().unwrap_or_default());
                        format!("{:>3}  {kind:<4}  {title}  {target}", i + 1)
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        TabsCmd::Save => {
            let mut input = Vec::new();
            std::io::stdin().take(MAX_BYTES as u64 + 1).read_to_end(&mut input)?;
            let (json, count) = parse(&input)?;
            store.meta_set(KEY, (count > 0).then_some(json.as_str()))?;
            out.ok(json!({"count": count, "bytes": if count > 0 { json.len() } else { 0 }}), || {
                format!("saved {count} Replay tab{}", if count == 1 { "" } else { "s" })
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

/// Checks a set to save and returns it as compact JSON with its tab count.
fn parse(input: &[u8]) -> Result<(String, usize), Error> {
    let too_big = || {
        Error::InvalidInput(format!(
            "Replay tabs are over {} MB, the most a project keeps; close some tabs or shorten large requests",
            MAX_BYTES / (1024 * 1024)
        ))
    };
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
        let bad = |what: String| Error::InvalidInput(format!("Replay tab {} ({:?}): {what}", i + 1, t.title));
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
        if t.wait.is_some_and(|w| w < 0.0) {
            return Err(bad("wait can't be negative".into()));
        }
        if t.until.as_ref().is_some_and(|u| u.chars().count() > MAX_UNTIL) {
            return Err(bad(format!("until is longer than {MAX_UNTIL} characters")));
        }
    }
    let json = serde_json::to_string(&set).map_err(|e| Error::InvalidInput(e.to_string()))?;
    if json.len() > MAX_BYTES {
        return Err(too_big());
    }
    Ok((json, set.tabs.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(input: &str) -> String {
        parse(input.as_bytes()).unwrap_err().to_string()
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
        let (json, count) = parse(input.as_bytes()).unwrap();
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
        assert_eq!(parse(fits.as_bytes()).unwrap().1, 1);
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
        let ok = |v: Value| parse(v.to_string().as_bytes()).map(|(_, n)| n).map_err(|e| e.to_string());
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
        let (json, _) = parse(br#"{"tabs": [{"kind": "ws", "request": "", "wait": null, "messages": []}]}"#).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v["tabs"][0].get("wait").is_none(), "{v}");
        assert_eq!(v["tabs"][0]["messages"], json!([]));
        let (json, _) = parse(br#"{"tabs": [{"kind": "ws", "request": "", "wait": 0}]}"#).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&json).unwrap()["tabs"][0]["wait"], 0.0);
        // Defaults are filled in and an unset binary is left out.
        let (json, count) = parse(br#"{"tabs": [{"request": "x", "binary": false}]}"#).unwrap();
        assert_eq!(count, 1);
        assert_eq!(json, r#"{"tabs":[{"kind":"http","title":"","target":"","request":"x"}]}"#);
        // Nothing open: nothing can be active.
        assert_eq!(parse(br#"{"tabs": []}"#).unwrap(), (r#"{"tabs":[]}"#.to_string(), 0));
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
}
