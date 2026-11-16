//! Editing in place, end to end: `rules edit`, `findings edit` and `auth macro edit` change only
//! what they are given, keep the record's id, place and history, say who changed it, refuse a
//! stale `--if-revision`, and hold an agent to what it may add.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

const MCP: &str = "BRAINPROXY_MCP_CALL";
const CLIENT: &str = "BRAINPROXY_CLIENT";
const AGENT: [(&str, &str); 1] = [(MCP, "1")];
const GUI: [(&str, &str); 1] = [(CLIENT, "gui")];

struct Env {
    dir: PathBuf,
    project: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-edit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Env { project: dir.join("p.bpdb"), home: dir.join("home"), dir };
        env.ok(&["engagement", "start", "--target", "127.0.0.1", "--target", "localhost"]);
        env
    }

    /// Runs the CLI with these provenance variables (the test's own are removed) and stdin.
    fn run_as(&self, vars: &[(&str, &str)], args: &[&str], stdin: Option<&[u8]>) -> (i32, Value) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
        cmd.env_remove(MCP).env_remove(CLIENT).env_remove("BRAINPROXY_PROJECT").envs(vars.iter().copied());
        cmd.args(["--format", "json", "--project"]).arg(&self.project).arg("--home").arg(&self.home).args(args);
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        if let Some(input) = stdin {
            let _ = child.stdin.take().unwrap().write_all(input);
        }
        let out = child.wait_with_output().unwrap();
        let v = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
        (out.status.code().unwrap(), v)
    }

    fn ok_as(&self, vars: &[(&str, &str)], args: &[&str]) -> Value {
        let (code, v) = self.run_as(vars, args, None);
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }

    fn ok(&self, args: &[&str]) -> Value {
        self.ok_as(&[], args)
    }

    /// The error kind and message of a command that must fail.
    fn fails(&self, vars: &[(&str, &str)], args: &[&str], stdin: Option<&[u8]>) -> (String, String) {
        let (code, v) = self.run_as(vars, args, stdin);
        assert_ne!(code, 0, "{args:?} -> {v}");
        let e = &v["error"];
        (e["kind"].as_str().unwrap_or_default().to_string(), e["message"].as_str().unwrap_or_default().to_string())
    }

    /// Writes a file beside the project and gives its path.
    fn file(&self, name: &str, text: &str) -> String {
        let file = self.dir.join(name);
        std::fs::write(&file, text).unwrap();
        file.display().to_string()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Answers every request `200 OK` with the request it got as the body.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut req = Vec::new();
            let mut buf = [0u8; 8192];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => req.extend_from_slice(&buf[..k]),
                }
            }
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", req.len());
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&req);
        }
    });
    port
}

fn ids(rules: &Value) -> Vec<u64> {
    rules.as_array().unwrap().iter().map(|r| r["id"].as_u64().unwrap()).collect()
}

#[test]
fn a_rule_is_edited_in_place_and_whoever_changes_what_it_does_answers_for_it() {
    let env = Env::new("rules");
    for (name, value) in [("X-One", "1"), ("X-Two", "2"), ("X-Three", "3")] {
        let add = ["rules", "add", "--location", "request-header", "--name", name, "--replace", value];
        env.ok_as(&GUI, &[&add[..], &["--comment", "first"]].concat());
    }
    let listed = env.ok(&["rules", "list"]);
    let rev = listed["revisions"]["2"].as_str().unwrap().to_string();

    // Only the replacement changes; the id, the place, the name and the comment stay, and the
    // command line now answers for what the rule does.
    let d = env.ok(&["rules", "edit", "2", "--replace", "two", "--if-revision", &rev]);
    assert_eq!(ids(&d["rules"]), [1, 2, 3]);
    let r = &d["rule"];
    assert_eq!(
        (r["id"].as_u64(), r["name"].as_str(), r["replace"].as_str(), r["comment"].as_str(), r["origin"].as_str()),
        (Some(2), Some("X-Two"), Some("two"), Some("first"), Some("cli")),
        "{d}"
    );
    assert_ne!(d["revision"], json!(rev));
    assert_eq!(d["revisions"]["2"], d["revision"]);
    // The revision read before it is stale now: nothing changes.
    let (kind, msg) = env.fails(&[], &["rules", "edit", "2", "--replace", "again", "--if-revision", &rev], None);
    assert!(kind == "conflict" && msg.contains("changed elsewhere"), "{kind}: {msg}");
    assert_eq!(env.ok(&["rules", "list"])["rules"][1]["replace"], "two");
    // The edited rule is the one that applies.
    let tried =
        env.run_as(&[], &["rules", "test", "-", "--rule", "2"], Some(b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n"));
    let content = tried.1["data"]["request"]["result"]["content"].as_str().unwrap_or_default().to_string();
    assert!(content.contains("X-Two: two"), "{tried:?}");

    // A comment alone leaves the rule the person's, even from an agent; an empty one removes it.
    let d = env.ok_as(&AGENT, &["rules", "edit", "1", "--comment", "checked"]);
    assert_eq!((d["rule"]["origin"].as_str(), d["rule"]["comment"].as_str()), (Some("gui"), Some("checked")));
    let d = env.ok(&["rules", "edit", "1", "--comment", ""]);
    assert!(d["rule"].get("comment").is_none(), "{d}");
    assert_eq!(d["rule"]["origin"], "gui");
    // An agent's change to what a person's rule does is the agent's.
    let d = env.ok_as(&AGENT, &["rules", "edit", "3", "--replace", "three"]);
    assert_eq!(d["rule"]["origin"], "mcp");
    // An edit leaves a disabled rule disabled.
    env.ok(&["rules", "disable", "3"]);
    let d = env.ok(&["rules", "edit", "3", "--name", "X-3"]);
    assert_eq!((d["rule"]["enabled"].as_bool(), d["rule"]["name"].as_str()), (Some(false), Some("X-3")));

    // Nothing to change, a rule that isn't there, and a rule that doesn't fit.
    let (kind, _) = env.fails(&[], &["rules", "edit", "1"], None);
    assert_eq!(kind, "invalid_input");
    let (kind, _) = env.fails(&[], &["rules", "edit", "99", "--comment", "x"], None);
    assert_eq!(kind, "not_found");
    let (kind, msg) = env.fails(&[], &["rules", "edit", "1", "--location", "path"], None);
    assert!(kind == "invalid_input" && msg.contains("--name goes with"), "{kind}: {msg}");
    let (kind, _) = env.fails(&[], &["rules", "edit", "1", "--match", "("], None);
    assert_eq!(kind, "invalid_input");
    let after = env.ok(&["rules", "list"]);
    assert_eq!(after["rules"][0]["location"], "request-header");
    assert_eq!(after["rules"][0]["pattern"], "");
    // An empty name takes the action with it.
    env.ok(&["rules", "edit", "1", "--action", "add"]);
    let d = env.ok(&["rules", "edit", "1", "--name", "", "--replace", "X-New: 1"]);
    assert!(d["rule"].get("name").is_none() && d["rule"].get("action").is_none(), "{d}");
}

#[test]
fn an_agents_edit_is_checked_as_an_agents_add() {
    let port = serve();
    let env = Env::new("rules-mcp");
    let url = format!("http://127.0.0.1:{port}/a");
    // A person's rule that changes nothing that matters.
    let quiet = ["rules", "add", "--location", "request-header", "--match-kind", "literal", "--match", "Qq"];
    env.ok_as(&GUI, &[&quiet[..], &["--replace", "Qq", "--applies-to", "proxy,send"]].concat());

    // An agent can't make it set a Host the scope doesn't list without saying the test is meant.
    let host = ["rules", "edit", "1", "--name", "Host", "--match", "", "--replace", "e.test"];
    let (_, msg) = env.fails(&AGENT, &host, None);
    assert!(msg.contains("sets Host e.test") && msg.contains("--host-header-test"), "{msg}");
    assert_eq!(env.ok(&["rules", "list"])["rules"][0]["pattern"], "Qq");
    // Nor slip in one that only shows on a request: the rule is the agent's now, so the request
    // is refused where it is sent.
    env.ok_as(&AGENT, &["rules", "edit", "1", "--match", "Zz", "--replace", "st"]);
    let (_, msg) = env.fails(&GUI, &["send", "--url", &url, "-H", "HoZz: e.test"], None);
    assert!(msg.contains("an agent's rule put a host the scope doesn't list"), "{msg}");
    // --host-header-test alone says the test is meant, and the request goes out.
    let d = env.ok_as(&AGENT, &["rules", "edit", "1", "--host-header-test"]);
    assert_eq!((d["rule"]["host_header_test"].as_bool(), d["rule"]["origin"].as_str()), (Some(true), Some("mcp")));
    let sent = env.ok_as(&GUI, &["send", "--url", &url, "-H", "HoZz: e.test", "--max-body", "4096"]);
    assert!(sent["response"]["body"]["content"].as_str().unwrap().contains("Host: e.test"), "{sent}");
    // A comment keeps the mark; a change of what the rule does needs it said again.
    let d = env.ok_as(&AGENT, &["rules", "edit", "1", "--comment", "Host test"]);
    assert_eq!(d["rule"]["host_header_test"], true);
    let d = env.ok_as(&AGENT, &["rules", "edit", "1", "--match", "Yy"]);
    assert!(d["rule"].get("host_header_test").is_none(), "{d}");

    // A script is a person's: an agent can't change a script rule's workings, give one, or
    // make text of one, but may comment on it.
    let script = env.file("upper.js", "function replace(m) { return m.text.toUpperCase(); }");
    env.ok(&["rules", "add", "--location", "response-body", "--match", "x", "--script", &script]);
    let why = "runs code from a file, so it isn't offered through MCP";
    for args in [
        &["rules", "edit", "2", "--host", "a\\.test"][..],
        &["rules", "edit", "2", "--replace", "y"],
        &["rules", "edit", "1", "--script", &script],
    ] {
        let (_, msg) = env.fails(&AGENT, args, None);
        assert!(msg.contains(why), "{args:?}: {msg}");
    }
    let d = env.ok_as(&AGENT, &["rules", "edit", "2", "--comment", "uppercases x"]);
    assert_eq!((d["rule"]["origin"].as_str(), d["rule"]["replacer"].as_str()), (Some("cli"), Some("script")));
    // A person can make text of it.
    let d = env.ok(&["rules", "edit", "2", "--replace", "y"]);
    assert!(d["rule"].get("script").is_none() && d["rule"].get("replacer").is_none(), "{d}");
    assert_eq!(d["rule"]["replace"], "y");

    // A request rule that is on may be what keeps requests from the target: an agent can't
    // change it, as it can't switch it off.
    let stops = env.file("stops.js", "function request(req) { return { block: 'not this one' }; }");
    env.ok(&["rules", "add", "--location", "request", "--script", &stops, "--applies-to", "send"]);
    let (_, msg) = env.fails(&AGENT, &["rules", "edit", "3", "--applies-to", "proxy"], None);
    assert!(msg.contains("could switch it off") && msg.contains("isn't switched off or removed"), "{msg}");
    let d = env.ok(&["rules", "edit", "3", "--applies-to", "send,fuzz"]);
    assert_eq!(d["rule"]["applies_to"], json!(["send", "fuzz"]));
}

#[test]
fn a_finding_added_by_hand_is_edited_in_place_and_its_timeline_says_what_changed() {
    let port = serve();
    let env = Env::new("findings");
    let sent: Vec<String> = ["/orders/7", "/orders/8"]
        .iter()
        .map(|p| env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}{p}")])["id"].to_string())
        .collect();
    let add = [
        "findings",
        "add",
        "--title",
        "Order IDOR",
        "--risk",
        "high",
        "--url",
        "http://127.0.0.1/orders/7",
        "--description",
        "Any user reads any order.",
    ];
    let id = env.ok_as(&GUI, &add)["id"].to_string();
    env.ok(&["findings", "mark", &id, "--state", "confirmed", "--note", "seen twice"]);
    let shown = env.ok(&["findings", "show", &id]);
    let rev = shown["revision"].as_str().unwrap().to_string();
    let issue = shown["issue_id"].clone();

    let edit = |vars: &[(&str, &str)], more: &[&str]| env.ok_as(vars, &[&["findings", "edit", &id][..], more].concat());
    let d = edit(
        &[],
        &["--risk", "critical", "--param", "id", "--evidence", "order 8", "--cwe", "639", "--if-revision", &rev],
    );
    assert_eq!(d["changed"], json!(["risk", "param", "cwe", "evidence"]), "{d}");
    let f = &d["finding"];
    assert_eq!(
        (f["id"].to_string(), f["risk"].as_str(), f["state"].as_str(), f["note"].as_str(), f["origin"].as_str()),
        (id.clone(), Some("critical"), Some("confirmed"), Some("seen twice"), Some("gui")),
        "{d}"
    );
    assert_eq!((f["cwe"].as_i64(), f["issue_id"].clone()), (Some(639), issue.clone()));
    assert_ne!(d["revision"], json!(rev));
    assert_eq!(d["revision"], f["revision"]);
    // The timeline says who changed what, with the values before and after.
    let events = env.ok(&["findings", "timeline", &id])["events"].as_array().unwrap().clone();
    let e = events.last().unwrap();
    assert_eq!((e["kind"].as_str(), e["origin"].as_str()), (Some("edited"), Some("cli")), "{e}");
    assert_eq!(e["text"], "risk, param, cwe, evidence");
    let old: Value = serde_json::from_str(e["old"].as_str().unwrap()).unwrap();
    let new: Value = serde_json::from_str(e["new"].as_str().unwrap()).unwrap();
    assert_eq!(old, json!({"risk": "high", "param": "", "cwe": null, "evidence": ""}));
    assert_eq!(new, json!({"risk": "critical", "param": "id", "cwe": 639, "evidence": "order 8"}));
    // A stale revision changes nothing, and neither does an edit to what it already is.
    let (kind, _) = env.fails(&[], &["findings", "edit", &id, "--risk", "low", "--if-revision", &rev], None);
    assert_eq!(kind, "conflict");
    let d = edit(&[], &["--risk", "critical"]);
    assert_eq!(d["changed"], json!([]));
    assert_eq!(env.ok(&["findings", "timeline", &id])["events"].as_array().unwrap().len(), events.len());
    assert_eq!(edit(&[], &["--cwe", "0"])["finding"]["cwe"], Value::Null);

    // The write-up is shared by the title: another one is refused unless it is to replace it.
    let (kind, msg) = env.fails(&[], &["findings", "edit", &id, "--description", "Orders leak."], None);
    assert!(kind == "conflict" && msg.contains("--replace-text"), "{kind}: {msg}");
    let d = edit(&[], &["--description", "Orders leak.", "--solution", "Check the owner.", "--replace-text"]);
    assert_eq!(d["changed"], json!(["description", "solution"]));
    assert_eq!(d["finding"]["replaced_texts"][0]["description"], "Any user reads any order.", "{d}");
    assert_eq!(d["finding"]["solution"], "Check the owner.");

    // History entries are replaced, or unlinked; the first is the evidence.
    let links = format!("{},{}", sent[1], sent[0]);
    let d = edit(&[], &["--history-id", &links]);
    assert_eq!(d["finding"]["history_ids"], json!([sent[1].parse::<i64>().unwrap(), sent[0].parse::<i64>().unwrap()]));
    assert_eq!(d["finding"]["history_id"].to_string(), sent[1]);
    let (kind, _) = env.fails(&[], &["findings", "edit", &id, "--history-id", "999"], None);
    assert_eq!(kind, "not_found");
    let d = edit(&[], &["--no-history"]);
    assert_eq!((d["finding"]["history_ids"].clone(), d["finding"]["history_id"].clone()), (json!([]), Value::Null));

    // The same issue as another finding is refused.
    let other =
        env.ok(&["findings", "add", "--title", "Order IDOR", "--risk", "low", "--url", "http://127.0.0.1/orders/9"]);
    let (kind, msg) = env.fails(
        &[],
        &["findings", "edit", &other["id"].to_string(), "--param", "id", "--url", "http://127.0.0.1/orders/7"],
        None,
    );
    assert!(kind == "conflict" && msg.contains(&format!("finding {id} is already this issue")), "{kind}: {msg}");

    // A new title moves it to the issue of its new alert type, with its write-up when that
    // type has none; the old title's findings keep theirs.
    let d = edit(&[], &["--title", "Invoice IDOR"]);
    let f = &d["finding"];
    assert_eq!((f["alert_ref"].as_str(), f["name"].as_str()), (Some("manual:invoice-idor"), Some("Invoice IDOR")));
    assert_eq!((f["description"].as_str(), f["solution"].as_str()), (Some("Orders leak."), Some("Check the owner.")));
    assert_ne!(f["issue_id"], issue);
    let kinds: Vec<String> = env.ok(&["findings", "timeline", &id])["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds[kinds.len() - 2..], ["edited", "moved"]);
    assert_eq!(env.ok(&["findings", "show", &other["id"].to_string()])["description"], "Orders leak.");

    // A URL that isn't one, a finding that isn't there, nothing to change, and a removed one.
    let (kind, _) = env.fails(&[], &["findings", "edit", &id, "--url", "javascript:alert(1)"], None);
    assert_eq!(kind, "invalid_input");
    let (kind, _) = env.fails(&[], &["findings", "edit", "999", "--risk", "low"], None);
    assert_eq!(kind, "not_found");
    let (kind, _) = env.fails(&[], &["findings", "edit", &id], None);
    assert_eq!(kind, "invalid_input");
    env.ok(&["findings", "remove", &other["id"].to_string()]);
    let (kind, msg) = env.fails(&[], &["findings", "edit", &other["id"].to_string(), "--risk", "info"], None);
    assert!(kind == "conflict" && msg.contains("was removed"), "{kind}: {msg}");
}

#[test]
fn an_agent_edits_only_the_findings_it_added() {
    let env = Env::new("findings-mcp");
    let person =
        env.ok_as(&GUI, &["findings", "add", "--title", "XSS", "--risk", "high", "--url", "http://127.0.0.1/q"]);
    let person = person["id"].to_string();
    let (kind, msg) = env.fails(&AGENT, &["findings", "edit", &person, "--risk", "info"], None);
    assert!(
        kind == "invalid_input" && msg.contains("only the findings it added") && msg.contains("findings mark"),
        "{kind}: {msg}"
    );
    assert_eq!(env.ok(&["findings", "show", &person])["risk"], "high");

    let mine = env.ok_as(
        &AGENT,
        &["findings", "add", "--title", "Debug page", "--risk", "low", "--url", "http://127.0.0.1/debug"],
    );
    let mine = mine["id"].to_string();
    let d = env.ok_as(&AGENT, &["findings", "edit", &mine, "--evidence", "a stack trace"]);
    assert_eq!(d["changed"], json!(["evidence"]));
    let last = env.ok(&["findings", "timeline", &mine])["events"].as_array().unwrap().last().unwrap().clone();
    assert_eq!((last["kind"].as_str(), last["origin"].as_str()), (Some("edited"), Some("mcp")));
    // The edit is on the agent's trail for the finding.
    let trail = env.ok(&["findings", "trail", &mine]);
    assert!(trail.to_string().contains("\"edited\""), "{trail}");
    // Texts come from the call's stdin, a blank write-up can be filled, and none replaced.
    let file = env.file("desc.md", "From a file.");
    let (_, msg) = env.fails(&AGENT, &["findings", "edit", &mine, "--description-file", &file], None);
    assert!(msg.contains("only '-' is accepted"), "{msg}");
    let (code, v) =
        env.run_as(&AGENT, &["findings", "edit", &mine, "--description-file", "-"], Some(b"Shows a stack trace."));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["finding"]["description"], "Shows a stack trace.");
    let (_, msg) = env.fails(&AGENT, &["findings", "edit", &mine, "--description", "Other.", "--replace-text"], None);
    assert!(msg.contains("--replace-text is refused through MCP"), "{msg}");
    // Once a person has edited it, it is theirs too.
    env.ok_as(&GUI, &["findings", "edit", &mine, "--risk", "medium"]);
    let (_, msg) = env.fails(&AGENT, &["findings", "edit", &mine, "--risk", "info"], None);
    assert!(msg.contains("a person has edited it since"), "{msg}");
    assert_eq!(env.ok(&["findings", "show", &mine])["origin"], "mcp", "the agent still added it");
}

#[test]
fn a_macro_is_edited_in_place_and_keeps_its_place_and_its_rules() {
    let env = Env::new("macros");
    let step = |name: &str, path: &str| env.file(name, &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"));
    let (a, b, c) = (step("a.txt", "/a"), step("b.txt", "/b"), step("c.txt", "/c"));
    let add = ["auth", "macro", "add", "app", "login", "--scheme", "http", "--step", &a, "--step", &b];
    env.ok_as(&GUI, &[&add[..], &["--extract", "1:tok=regex:t=(\\w+)"]].concat());
    env.ok_as(&GUI, &["auth", "macro", "add", "app", "csrf", "--scheme", "http", "--step", &c]);
    env.ok(&["auth", "rule", "add", "app", "--action", "macro:login", "--action", "update:tok"]);
    let rev = env.ok(&["auth", "macro", "show", "app", "login"])["revision"].as_str().unwrap().to_string();

    // Steps reordered, one added: a kept step keeps its extractor.
    let edit = ["auth", "macro", "edit", "app", "login", "--scheme", "http"];
    let d =
        env.ok(&[&edit[..], &["--step", "step:2", "--step", "step:1", "--step", &c, "--if-revision", &rev]].concat());
    assert_eq!(d["changed"], true);
    let m = &d["macro"];
    let requests = json!(["GET http://127.0.0.1:9/b", "GET http://127.0.0.1:9/a", "GET http://127.0.0.1:9/c"]);
    assert_eq!(
        (m["requests"].clone(), m["origin"].as_str(), m["vars"].clone()),
        (requests, Some("cli"), json!(["tok"]))
    );
    let shown = env.ok(&["auth", "macro", "show", "app", "login"]);
    let extract: Vec<usize> =
        shown["macro"]["steps"].as_array().unwrap().iter().map(|s| s["extract"].as_array().unwrap().len()).collect();
    assert_eq!(extract, [0, 1, 0]);
    assert_eq!(shown["revision"], d["revision"]);
    // It keeps its place, and the rule that runs it still does.
    let names: Vec<String> = env.ok(&["auth", "macro", "list", "app"])["macros"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["login", "csrf"]);
    let rules = env.ok(&["auth", "rule", "list", "app"]);
    assert!(rules.to_string().contains("\"login\""), "{rules}");
    // The revision read before is stale.
    let (kind, _) = env.fails(&[], &[&edit[..], &["--no-extract", "--if-revision", &rev]].concat(), None);
    assert_eq!(kind, "conflict");

    // Extractors are replaced, on the steps as they are now.
    let d = env.ok(&[&edit[..], &["--extract", "3:tok=json:token"]].concat());
    let shown = env.ok(&["auth", "macro", "show", "app", "login"]);
    assert_eq!(shown["macro"]["steps"][2]["extract"][0]["expr"], "token", "{d}");
    assert!(shown["macro"]["steps"][1]["extract"].as_array().unwrap().is_empty());
    // An edit that changes nothing changes nobody's record.
    let d = env.ok_as(&AGENT, &[&edit[..], &["--extract", "3:tok=json:token"]].concat());
    assert_eq!((d["changed"].as_bool(), d["macro"]["origin"].as_str()), (Some(false), Some("cli")));

    // A step that isn't there, a macro that isn't, a profile that isn't, and nothing to change.
    let (kind, msg) = env.fails(&[], &[&edit[..], &["--step", "step:9"]].concat(), None);
    assert!(kind == "invalid_input" && msg.contains("steps 1 to 3"), "{kind}: {msg}");
    let (kind, _) = env.fails(&[], &["auth", "macro", "edit", "app", "nope", "--no-extract"], None);
    assert_eq!(kind, "not_found");
    let (kind, _) = env.fails(&[], &["auth", "macro", "edit", "other", "login", "--no-extract"], None);
    assert_eq!(kind, "not_found");
    let (kind, _) = env.fails(&[], &["auth", "macro", "edit", "app", "login"], None);
    assert_eq!(kind, "invalid_input");

    // Through MCP a step file comes from the project's folder, and a step's Host the scope
    // doesn't list is refused unless the test is meant; the agent then answers for the macro.
    let outside = std::env::temp_dir().join(format!("bp-edit-{}-outside.txt", std::process::id()));
    std::fs::write(&outside, "GET /x HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n").unwrap();
    let (_, msg) = env.fails(&AGENT, &[&edit[..], &["--step", outside.to_str().unwrap()]].concat(), None);
    let _ = std::fs::remove_file(&outside);
    assert!(msg.contains("--step"), "{msg}");
    let foreign = env.file("foreign.txt", "GET /x HTTP/1.1\r\nHost: e.test\r\n\r\n");
    let spec = format!("http://127.0.0.1:9={foreign}");
    let (_, msg) = env.fails(&AGENT, &[&edit[..], &["--step", "step:1", "--step", &spec]].concat(), None);
    assert!(msg.contains("macro login step 2 sets Host e.test") && msg.contains("--host-header-test"), "{msg}");
    let d = env.ok_as(&AGENT, &[&edit[..], &["--step", "step:1", "--step", &spec, "--host-header-test"]].concat());
    assert_eq!((d["macro"]["steps"].as_u64(), d["macro"]["origin"].as_str()), (Some(2), Some("mcp")));
}
