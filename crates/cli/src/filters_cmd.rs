//! `history filters`: the saved Traffic filters the app offers, kept in the project file so
//! they travel with it and an agent can read (and add) them. A filter is what the Traffic
//! toolbar holds: the text and what it searches (URL, contents or a filter-language query),
//! the sources picked, and the three checkboxes. Nothing here searches or sends anything.

use std::io::Read;
use std::path::Path;

use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::output::{escape_controls, Out};

/// The meta key holding the saved set (JSON): `{"v", "rev", "filters"}`.
const KEY: &str = "traffic.filters";
/// Format of the saved set. A build refuses to save over a newer one, whose fields it would drop.
const VERSION: u64 = 1;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_FILTERS: usize = 200;
/// The most an agent can bring the set to through MCP, so a person always has room for theirs.
const MAX_THROUGH_MCP: usize = 150;
const MAX_NAME: usize = 100;
const MAX_SOURCES: usize = 16;
const MAX_SOURCE: usize = 32;

#[derive(Subcommand)]
pub enum FiltersCmd {
    /// List the saved Traffic filters: name, what the text searches, the text, sources and checkboxes.
    #[command(after_help = "mode is url (the text filters URL, title and method in the app), contents \
        (`history list --contains`) or query (`history list --filter`). rev goes up with every save; \
        `save --if-revision` checks it.")]
    List,
    /// Replace the saved Traffic filters with the JSON on stdin (or add to them with --append).
    #[command(after_help = "Reads JSON from stdin: {\"filters\": [{\"name\": \"server errors\", \"filter\": \
        {\"text\": \"status:5xx NOT path:/health\", \"query\": true, \"sources\": [\"proxy\"], \"hideAssets\": true}}]}. \
        A filter's fields: text, contents (search inside requests and responses), query (text is a \
        `history list --filter` query, which must parse), sources (empty: every source), hideErrors (2xx/3xx \
        only), hideAssets, hideRefused (out-of-scope rows; true when left out). contents and query can't both be \
        on. Names are unique, at most 100 characters; at most 200 filters. An empty list leaves none. Through MCP \
        only --append is allowed, a name already saved is refused, and the set can't grow past 150, so an agent \
        can't remove or change a person's filters or leave them no room.")]
    Save {
        /// Add the filters after the saved ones instead of replacing them. A name already saved is refused.
        #[arg(long)]
        append: bool,
        /// Save only if the saved set is still at this revision (`rev` from list or save; 0 when none
        /// was saved); otherwise fail with a conflict and change nothing.
        #[arg(long, value_name = "REV")]
        if_revision: Option<u64>,
    },
}

const fn yes() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Filter {
    #[serde(default)]
    text: String,
    #[serde(default)]
    contents: bool,
    #[serde(default)]
    query: bool,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    hide_errors: bool,
    #[serde(default)]
    hide_assets: bool,
    #[serde(default = "yes")]
    hide_refused: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    name: String,
    filter: Filter,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Set {
    filters: Vec<Saved>,
}

fn mode(f: &Value) -> &'static str {
    if f["query"].as_bool() == Some(true) {
        "query"
    } else if f["contents"].as_bool() == Some(true) {
        "contents"
    } else {
        "url"
    }
}

pub fn filters(project: &Path, cmd: FiltersCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        FiltersCmd::List => {
            let saved = load(&Store::open(project)?)?;
            let list = saved["filters"].as_array().cloned().unwrap_or_default();
            let rev = saved["rev"].as_u64().unwrap_or(0);
            let v = saved["v"].as_u64().unwrap_or(VERSION);
            let listed: Vec<Value> = list
                .iter()
                .map(|s| {
                    let mut s = s.clone();
                    s["mode"] = json!(mode(&s["filter"]));
                    s
                })
                .collect();
            let data = json!({"count": list.len(), "rev": rev, "v": v, "filters": listed});
            out.ok(data, || {
                if list.is_empty() {
                    return "no saved Traffic filters".into();
                }
                // Typed by someone else: shown escaped, stored and in JSON as is.
                list.iter()
                    .map(|s| {
                        let f = &s["filter"];
                        let name = escape_controls(s["name"].as_str().unwrap_or_default());
                        let text = escape_controls(f["text"].as_str().unwrap_or_default());
                        format!("{name}  [{}]  {text}", mode(f))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        FiltersCmd::Save { append, if_revision } => {
            if crate::mcp::in_tool_call() && !append {
                return Err(Error::InvalidInput(
                    "through MCP saved Traffic filters can only be added (append: true), so an agent can't remove \
                     the ones a person keeps; replacing them is for the app or a terminal"
                        .into(),
                ));
            }
            let mut input = Vec::new();
            std::io::stdin().take(MAX_BYTES as u64 + 1).read_to_end(&mut input)?;
            let set = parse(&input)?;
            let given = set.filters.len();
            let mut store = Store::open(project)?;
            let (count, rev) = store.meta_update(KEY, |old| {
                let (rev, before) = current(old.as_deref(), append || if_revision.is_some())?;
                if let Some(want) = if_revision.filter(|w| *w != rev) {
                    return Err(Error::Conflict(format!(
                        "the saved Traffic filters are at revision {rev}, not {want}: they were saved from elsewhere \
                         meanwhile; list them again"
                    )));
                }
                let before = if append { before } else { Vec::new() };
                let cap = if crate::mcp::in_tool_call() { MAX_THROUGH_MCP } else { MAX_FILTERS };
                let (json, count) = build(set, before, rev + 1, cap)?;
                Ok((Some(json), (count, rev + 1)))
            })?;
            let mut data = json!({"count": count, "rev": rev});
            if append {
                data["added"] = json!(given);
            }
            out.ok(data, || {
                let s = |n: usize| if n == 1 { "" } else { "s" };
                if append {
                    format!("added {given} Traffic filter{} ({count} saved)", s(given))
                } else {
                    format!("saved {count} Traffic filter{}", s(count))
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
        Some(s) => serde_json::from_str(&s).map_err(|e| {
            Error::InvalidInput(format!("the saved Traffic filters are not valid JSON ({e}); save new ones"))
        }),
        None => Ok(json!({"filters": []})),
    }
}

/// The stored set's revision and filters, for a save over it. Refuses a set of a newer format,
/// and a broken one when it is to be kept (`keep`: appending or checking the revision).
fn current(stored: Option<&str>, keep: bool) -> Result<(u64, Vec<Value>), Error> {
    let Some(s) = stored else { return Ok((0, Vec::new())) };
    let v: Value = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(_) if !keep => return Ok((0, Vec::new())),
        Err(e) => {
            return Err(Error::InvalidInput(format!(
                "the saved Traffic filters are not valid JSON ({e}); save new ones without --append or --if-revision"
            )))
        }
    };
    let version = v["v"].as_u64().unwrap_or(1);
    if version > VERSION {
        return Err(Error::Conflict(format!(
            "the saved Traffic filters were saved by a newer brainproxy (format {version}, this one writes \
             {VERSION}), which keeps things this one would drop; update brainproxy to change them"
        )));
    }
    Ok((v["rev"].as_u64().unwrap_or(0), v["filters"].as_array().cloned().unwrap_or_default()))
}

/// Checks a set to save: names, sizes, and that a query parses.
fn parse(input: &[u8]) -> Result<Set, Error> {
    if input.len() > MAX_BYTES {
        return Err(too_big());
    }
    let mut set: Set =
        serde_json::from_slice(input).map_err(|e| Error::InvalidInput(format!("Traffic filters: {e}")))?;
    if set.filters.len() > MAX_FILTERS {
        return Err(Error::InvalidInput(format!(
            "{} Traffic filters; at most {MAX_FILTERS} can be saved",
            set.filters.len()
        )));
    }
    let mut names = std::collections::HashSet::new();
    for s in &mut set.filters {
        s.name = s.name.trim().to_string();
        let bad = |what: String| Error::InvalidInput(format!("Traffic filter {:?}: {what}", s.name));
        if s.name.is_empty() {
            return Err(Error::InvalidInput("a Traffic filter needs a name".into()));
        }
        if s.name.chars().count() > MAX_NAME {
            return Err(bad(format!("the name is longer than {MAX_NAME} characters")));
        }
        if !names.insert(s.name.clone()) {
            return Err(bad("the name is given twice".into()));
        }
        let f = &mut s.filter;
        if f.text.len() > brainproxy_core::filter::MAX_LEN {
            return Err(bad(format!("the text is longer than {} bytes", brainproxy_core::filter::MAX_LEN)));
        }
        if f.contents && f.query {
            return Err(bad("contents and query can't both be on".into()));
        }
        if f.query && !f.text.trim().is_empty() {
            brainproxy_core::filter::Query::parse(&f.text).map_err(|e| bad(e.to_string()))?;
        }
        let mut seen = std::collections::HashSet::new();
        f.sources.retain(|x| seen.insert(x.clone()));
        if f.sources.len() > MAX_SOURCES {
            return Err(bad(format!("more than {MAX_SOURCES} sources")));
        }
        if let Some(x) = f
            .sources
            .iter()
            .find(|x| x.is_empty() || x.len() > MAX_SOURCE || !x.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        {
            return Err(bad(format!("{x:?} isn't a source name")));
        }
    }
    Ok(set)
}

/// The set to store as compact JSON, with its count: `set` after the filters `before` (kept by
/// an append), at revision `rev`, with at most `cap` in all. An appended name that is already
/// saved is refused.
fn build(set: Set, before: Vec<Value>, rev: u64, cap: usize) -> Result<(String, usize), Error> {
    let count = before.len() + set.filters.len();
    if count > cap {
        let why = if cap < MAX_FILTERS {
            format!("through MCP the set can grow to {cap}, so a person keeps room for their own")
        } else {
            format!("at most {cap} can be saved, remove some first")
        };
        return Err(Error::InvalidInput(format!("{count} Traffic filters with the saved ones; {why}")));
    }
    if let Some(s) = set.filters.iter().find(|s| before.iter().any(|b| b["name"].as_str() == Some(s.name.as_str()))) {
        return Err(Error::Conflict(format!(
            "a Traffic filter named {:?} is already saved; pick another name (adding never replaces one)",
            s.name
        )));
    }
    let mut filters = before;
    for s in set.filters {
        filters.push(serde_json::to_value(s).map_err(|e| Error::InvalidInput(e.to_string()))?);
    }
    let json = serde_json::to_string(&json!({"v": VERSION, "rev": rev, "filters": filters}))
        .map_err(|e| Error::InvalidInput(e.to_string()))?;
    if json.len() > MAX_BYTES {
        return Err(too_big());
    }
    Ok((json, count))
}

fn too_big() -> Error {
    Error::InvalidInput(format!("saved Traffic filters are over {} MB", MAX_BYTES / (1024 * 1024)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(input: &str) -> String {
        parse(input.as_bytes()).unwrap_err().to_string()
    }

    #[test]
    fn checks_and_stores_filters() {
        let set = parse(
            br#"{"filters": [{"name": " errors ", "filter": {"text": "status:5xx", "query": true, "sources": ["proxy", "proxy"]}},
                {"name": "tokens", "filter": {"text": "Bearer ", "contents": true, "hideRefused": false}}]}"#,
        )
        .unwrap();
        let (json, count) = build(set, Vec::new(), 1, MAX_FILTERS).unwrap();
        assert_eq!(count, 2);
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!((v["v"].as_u64(), v["rev"].as_u64()), (Some(1), Some(1)));
        assert_eq!(
            v["filters"][0],
            json!({"name": "errors", "filter": {"text": "status:5xx", "contents": false, "query": true,
                "sources": ["proxy"], "hideErrors": false, "hideAssets": false, "hideRefused": true}})
        );
        assert_eq!(v["filters"][1]["filter"]["hideRefused"], false);
        assert_eq!(mode(&v["filters"][0]["filter"]), "query");
        assert_eq!(mode(&v["filters"][1]["filter"]), "contents");
    }

    #[test]
    fn refuses_what_the_app_could_not_use() {
        assert!(err(r#"{"filters": [{"name": "", "filter": {}}]}"#).contains("needs a name"));
        assert!(err(r#"{"filters": [{"name": "a", "filter": {}}, {"name": "a ", "filter": {}}]}"#).contains("twice"));
        assert!(err(r#"{"filters": [{"name": "a", "filter": {"contents": true, "query": true}}]}"#).contains("both"));
        assert!(err(r#"{"filters": [{"name": "a", "filter": {"query": true, "text": "stauts:1"}}]}"#)
            .contains("unknown field \"stauts\""));
        // A query left empty is fine, as the app allows: it just filters nothing yet.
        assert!(parse(br#"{"filters": [{"name": "a", "filter": {"query": true, "text": " "}}]}"#).is_ok());
        assert!(err(r#"{"filters": [{"name": "a", "filter": {"sources": ["Proxy"]}}]}"#).contains("isn't a source"));
        assert!(err(r#"{"filters": [{"name": "a", "filter": {"color": "red"}}]}"#).contains("unknown field"));
        assert!(
            err(&format!(r#"{{"filters": [{{"name": "{}", "filter": {{}}}}]}}"#, "n".repeat(101))).contains("longer")
        );
    }

    #[test]
    fn an_append_never_replaces_a_name() {
        let before = vec![json!({"name": "mine", "filter": {}})];
        let set = parse(br#"{"filters": [{"name": "mine", "filter": {"text": "x"}}]}"#).unwrap();
        let e = build(set, before.clone(), 2, MAX_FILTERS).unwrap_err();
        assert_eq!(e.kind(), "conflict");
        let set = parse(br#"{"filters": [{"name": "theirs", "filter": {}}]}"#).unwrap();
        assert_eq!(build(set, before, 2, MAX_FILTERS).unwrap().1, 2);
    }

    #[test]
    fn an_agent_leaves_the_person_room() {
        let before: Vec<Value> = (0..MAX_THROUGH_MCP).map(|i| json!({"name": format!("f{i}"), "filter": {}})).collect();
        let set = || parse(br#"{"filters": [{"name": "one more", "filter": {}}]}"#).unwrap();
        let e = build(set(), before.clone(), 2, MAX_THROUGH_MCP).unwrap_err().to_string();
        assert!(e.contains("through MCP the set can grow to 150"), "{e}");
        assert_eq!(build(set(), before, 2, MAX_FILTERS).unwrap().1, MAX_THROUGH_MCP + 1);
    }

    #[test]
    fn a_newer_format_is_not_saved_over() {
        assert_eq!(current(Some(r#"{"v": 2, "rev": 4, "filters": []}"#), false).unwrap_err().kind(), "conflict");
        assert_eq!(current(Some("not json"), false).unwrap().0, 0);
        assert!(current(Some("not json"), true).is_err());
        assert_eq!(current(Some(r#"{"v": 1, "rev": 4, "filters": [{}]}"#), true).unwrap().0, 4);
    }
}
