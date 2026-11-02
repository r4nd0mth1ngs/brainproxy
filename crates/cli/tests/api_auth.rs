//! End-to-end tests for what APIs ask of a scan beyond a static key: OAuth tokens and their
//! renewal, SigV4 and private-key signers, Postman environments and pre-request scripts, and
//! GraphQL schemas. Every secret here is fake and starts with FAKE.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use brainproxy_core::http::request::split_head_body;
use brainproxy_core::sign::{hmac_digest, HmacAlg};
use serde_json::{json, Value};

#[derive(Clone, Debug)]
struct Hit {
    method: String,
    target: String,
    head: String,
    body: String,
}

impl Hit {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

/// A local API with a token endpoint at /token. Tokens are `tok-N`; `ttl` is their expires_in.
#[derive(Clone)]
struct Api {
    port: u16,
    hits: Arc<Mutex<Vec<Hit>>>,
    issued: Arc<AtomicUsize>,
    ttl: Arc<Mutex<u64>>,
}

impl Api {
    fn start(ttl: u64) -> Api {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = Api {
            port: listener.local_addr().unwrap().port(),
            hits: Arc::default(),
            issued: Arc::default(),
            ttl: Arc::new(Mutex::new(ttl)),
        };
        let shared = api.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let api = shared.clone();
                std::thread::spawn(move || api.handle(stream));
            }
        });
        api
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }

    fn at(&self, target: &str) -> Vec<Hit> {
        self.hits().into_iter().filter(|h| h.target.split('?').next() == Some(target)).collect()
    }

    fn handle(&self, mut s: TcpStream) {
        while let Some(raw) = read_request(&mut s) {
            let (head, body) = split_head_body(&raw);
            let head = String::from_utf8_lossy(head).into_owned();
            let line = head.lines().next().unwrap_or_default().to_string();
            let mut words = line.split(' ');
            let (method, target) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
            let hit = Hit {
                method: method.into(),
                target: target.into(),
                head: head.clone(),
                body: String::from_utf8_lossy(body).into_owned(),
            };
            self.hits.lock().unwrap().push(hit.clone());
            let reply = if target == "/token" {
                let n = self.issued.fetch_add(1, Ordering::SeqCst) + 1;
                let ttl = *self.ttl.lock().unwrap();
                let text = json!({"access_token": format!("tok-{n}"), "token_type": "bearer", "expires_in": ttl,
                    "refresh_token": format!("FAKE-refresh-{n}")})
                .to_string();
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{text}",
                    text.len()
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}\n"
                    .to_string()
            };
            if s.write_all(reply.as_bytes()).is_err() {
                return;
            }
        }
    }
}

fn read_request(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return Some(buf);
            }
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-api-auth-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    ok(&project, &["engagement", "start", "--target", "127.0.0.1"], &[]);
    (dir, project)
}

struct Output {
    code: i32,
    json: Value,
    all: String,
}

fn run(project: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    c.args(["--format", "json", "--project"]).arg(project).args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Output {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        all: format!("{stdout}\n{stderr}"),
    }
}

fn ok(project: &Path, args: &[&str], env: &[(&str, &str)]) -> Value {
    let o = run(project, args, env);
    assert_eq!(o.code, 0, "{args:?}: {}", o.all);
    o.json["data"].clone()
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_string()
}

/// Everything the project file holds, as text.
fn project_text(project: &Path) -> String {
    let mut text = String::from_utf8_lossy(&std::fs::read(project).unwrap()).into_owned();
    for suffix in ["-wal", "-shm"] {
        let other = PathBuf::from(format!("{}{suffix}", project.display()));
        if let Ok(b) = std::fs::read(other) {
            text.push_str(&String::from_utf8_lossy(&b));
        }
    }
    text
}

fn api_doc(api: &Api) -> String {
    json!({"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "servers": [{"url": api.origin()}],
        "paths": {"/v1/a": {"get": {}}, "/v1/b": {"get": {}}}})
    .to_string()
}

#[test]
fn client_credentials_get_a_token_kept_out_of_history() {
    let api = Api::start(3600);
    let (dir, p) = setup("cc");
    let doc = write(&dir, "api.json", &api_doc(&api));
    let token_url = format!("{}/token", api.origin());
    let shown = ok(
        &p,
        &[
            "auth",
            "add",
            "cc",
            "--oauth-flow",
            "client_credentials",
            "--oauth-token-url",
            &token_url,
            "--oauth-client-id",
            "the-client",
            "--oauth-client-secret-env",
            "CLIENT_SECRET",
            "--oauth-store-secrets",
            "--oauth-scope",
            "read write",
        ],
        &[("CLIENT_SECRET", "FAKE-CLIENT-SECRET")],
    );
    assert!(!shown.to_string().contains("FAKE-CLIENT-SECRET"), "{shown}");
    ok(&p, &["import", "api", "--auth", "cc", "--", &doc], &[]);
    let tokens = api.at("/token");
    assert_eq!(tokens.len(), 1, "{tokens:?}");
    assert!(tokens[0].body.contains("grant_type=client_credentials"), "{}", tokens[0].body);
    assert!(tokens[0].body.contains("client_secret=FAKE-CLIENT-SECRET"), "{}", tokens[0].body);
    assert!(tokens[0].body.contains("scope=read+write"), "{}", tokens[0].body);
    for h in api.at("/v1/a").iter().chain(&api.at("/v1/b")) {
        assert_eq!(h.header("Authorization"), Some("Bearer tok-1"), "{h:?}");
    }
    // No token in history, and neither token request nor secret in it at all.
    let rows = ok(&p, &["history", "list", "--limit", "50"], &[]);
    assert!(!rows.to_string().contains("/token"), "{rows}");
    let raw =
        ok(&p, &["history", "show", rows["items"][0]["id"].to_string().as_str(), "--part", "request", "--raw"], &[]);
    assert!(!raw.to_string().contains("tok-1"), "{raw}");
    // The status says there is a refresh token, not what it is.
    let status = ok(&p, &["auth", "status", "cc", "--offline"], &[]);
    assert_eq!(status["session"]["refresh_token"], true, "{status}");
    assert!(!status.to_string().contains("FAKE-refresh"), "{status}");
}

#[test]
fn a_token_about_to_run_out_is_renewed_with_its_refresh_token() {
    // Issued already within the renewal margin, so the next run has to renew it.
    let api = Api::start(10);
    let (dir, p) = setup("renew");
    let doc = write(&dir, "api.json", &api_doc(&api));
    let token_url = format!("{}/token", api.origin());
    ok(
        &p,
        &[
            "auth",
            "add",
            "r",
            "--oauth-flow",
            "client_credentials",
            "--oauth-token-url",
            &token_url,
            "--oauth-client-id",
            "c",
            "--oauth-client-secret-env",
            "CLIENT_SECRET",
            "--oauth-client-auth",
            "basic",
            "--oauth-store-secrets",
        ],
        &[("CLIENT_SECRET", "FAKE-CLIENT-SECRET")],
    );
    *api.ttl.lock().unwrap() = 3600;
    ok(&p, &["auth", "login", "r"], &[]);
    *api.ttl.lock().unwrap() = 10;
    ok(&p, &["auth", "login", "r"], &[]);
    *api.ttl.lock().unwrap() = 3600;
    let before = api.at("/token").len();
    ok(&p, &["import", "api", "--auth", "r", "--concurrency", "1", "--", &doc], &[]);
    let tokens = api.at("/token");
    assert_eq!(tokens.len(), before + 1, "renewed once, not per request: {tokens:?}");
    let last = tokens.last().unwrap();
    assert!(last.body.contains("grant_type=refresh_token"), "{}", last.body);
    assert!(last.body.contains(&format!("refresh_token=FAKE-refresh-{before}")), "{}", last.body);
    assert!(last.header("Authorization").is_some_and(|a| a.starts_with("Basic ")), "{last:?}");
    assert!(!last.body.contains("client_secret"), "{}", last.body);
    for h in api.at("/v1/a") {
        assert_eq!(h.header("Authorization"), Some(format!("Bearer tok-{}", before + 1).as_str()), "{h:?}");
    }
}

#[test]
fn a_token_endpoint_out_of_scope_is_refused_and_nothing_is_sent() {
    let api = Api::start(3600);
    let (dir, p) = setup("scope");
    let doc = write(&dir, "api.json", &api_doc(&api));
    ok(
        &p,
        &[
            "auth",
            "add",
            "o",
            "--oauth-flow",
            "client_credentials",
            "--oauth-token-url",
            "https://id.elsewhere.test/token",
            "--oauth-client-id",
            "c",
            "--oauth-client-secret-env",
            "CLIENT_SECRET",
            "--oauth-store-secrets",
        ],
        &[("CLIENT_SECRET", "FAKE-CLIENT-SECRET")],
    );
    let o = run(&p, &["import", "api", "--auth", "o", "--", &doc], &[]);
    assert_ne!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains("FAKE-CLIENT-SECRET"), "{}", o.all);
    assert!(api.hits().is_empty(), "{:?}", api.hits());
}

#[test]
fn authorization_code_signs_in_through_the_redirect() {
    let api = Api::start(3600);
    let (_dir, p) = setup("code");
    let token_url = format!("{}/token", api.origin());
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port().to_string();
    ok(
        &p,
        &[
            "auth",
            "add",
            "c",
            "--oauth-flow",
            "authorization_code",
            "--oauth-token-url",
            &token_url,
            "--oauth-client-id",
            "pub",
            "--oauth-authorize-url",
            "https://id.test/authorize",
            "--oauth-redirect-port",
            &port,
        ],
        &[],
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(&p)
        .args(["auth", "oauth", "authorize", "c", "--no-open", "--wait", "20"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while stderr.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    let line = String::from_utf8(line).unwrap();
    let url = url::Url::parse(line.strip_prefix("Sign in at: ").expect(&line)).unwrap();
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["redirect_uri"], format!("http://127.0.0.1:{port}/callback"));
    let hit = |path: String| {
        let mut s = TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap())).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    };
    assert!(hit("/callback?code=EVIL&state=wrong".into()).starts_with("HTTP/1.1 400"));
    assert!(hit(format!("/callback?code=THE-CODE&state={}", q["state"])).starts_with("HTTP/1.1 200"));
    assert!(child.wait().unwrap().success());
    let body = &api.at("/token")[0].body;
    assert!(body.contains("code=THE-CODE") && body.contains("code_verifier=") && !body.contains("EVIL"), "{body}");
    let status = ok(&p, &["auth", "status", "c", "--offline"], &[]);
    assert_eq!(status["session"]["token"], true, "{status}");
}

#[test]
fn a_sigv4_signer_reaches_the_wire_and_its_keys_stay_off_the_project() {
    let api = Api::start(3600);
    let (dir, p) = setup("v4");
    let doc = write(&dir, "api.json", &api_doc(&api));
    let env = [("AK", "AKIDFAKE"), ("SK", "FAKE-SECRET-ACCESS-KEY"), ("TOK", "FAKE-SESSION-TOKEN")];
    ok(
        &p,
        &[
            "auth",
            "sign",
            "add",
            "aws",
            "v4",
            "--sigv4-region",
            "eu-west-1",
            "--sigv4-service",
            "execute-api",
            "--access-key-env",
            "AK",
            "--secret-env",
            "SK",
            "--session-token-env",
            "TOK",
            "--origin",
            &api.origin(),
        ],
        &[],
    );
    ok(&p, &["auth", "rule", "add", "aws", "--action", "sign:v4"], &[]);
    ok(&p, &["import", "api", "--auth", "aws", "--", &doc], &env);
    let hit = &api.at("/v1/a")[0];
    let auth = hit.header("Authorization").unwrap();
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDFAKE/"), "{auth}");
    assert!(auth.contains("/eu-west-1/execute-api/aws4_request"), "{auth}");
    assert!(hit.header("X-Amz-Date").is_some() && hit.header("X-Amz-Content-Sha256").is_some(), "{hit:?}");
    assert_eq!(hit.header("X-Amz-Security-Token"), Some("FAKE-SESSION-TOKEN"));
    let text = project_text(&p);
    for secret in ["AKIDFAKE", "FAKE-SECRET-ACCESS-KEY", "FAKE-SESSION-TOKEN"] {
        assert!(!text.contains(secret), "{secret} in the project");
    }
}

#[test]
fn private_key_signers_are_available_on_the_command_line() {
    let api = Api::start(3600);
    let (dir, p) = setup("key");
    let doc = write(&dir, "api.json", &api_doc(&api));
    // Ed25519 PKCS#8 from RFC 8410 section 10.3: a published test key.
    let key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n";
    let key = write(&dir, "ed.pem", key);
    ok(
        &p,
        &[
            "auth",
            "sign",
            "add",
            "k",
            "ed",
            "--key-alg",
            "EdDSA",
            "--secret-file",
            &key,
            "--origin",
            &api.origin(),
            "--to",
            "header:X-Sig",
            "--output",
            "base64",
            "--canonical",
            "{{method}} {{path}}",
        ],
        &[],
    );
    ok(
        &p,
        &[
            "auth",
            "sign",
            "add",
            "k",
            "tok",
            "--jwt",
            "EdDSA",
            "--secret-file",
            &key,
            "--origin",
            &api.origin(),
            "--to",
            "header:X-Jwt",
            "--claims",
            "{\"sub\":\"a\"}",
        ],
        &[],
    );
    ok(&p, &["auth", "rule", "add", "k", "--action", "sign:ed", "--action", "sign:tok"], &[]);
    ok(&p, &["import", "api", "--auth", "k", "--", &doc], &[]);
    let hit = &api.at("/v1/a")[0];
    assert!(hit.header("X-Sig").is_some_and(|s| s.len() == 88), "{hit:?}");
    let jwt = hit.header("X-Jwt").unwrap();
    assert_eq!(brainproxy_core::codec::decode_jwt(jwt).unwrap()["header"]["alg"], "EdDSA");
    let o = run(
        &p,
        &[
            "auth",
            "sign",
            "add",
            "k",
            "bad",
            "--key-alg",
            "HS256",
            "--secret-file",
            &key,
            "--origin",
            &api.origin(),
            "--to",
            "header:X-B",
            "--canonical",
            "x",
        ],
        &[],
    );
    assert_ne!(o.code, 0);
    assert!(o.all.contains("isn't a private-key algorithm"), "{}", o.all);
}

fn collection(script: &[&str]) -> String {
    json!({
        "info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "variable": [{"key": "host", "value": "from-collection"}, {"key": "signing_secret", "value": "FAKE-OVERRIDDEN"}],
        "event": [{"listen": "prerequest", "script": {"exec": script}}],
        "item": [{"name": "One", "request": {"method": "POST", "url": "{{base}}/v1/a?x={{tenant}}",
            "header": [{"key": "X-Auth-Sig", "value": "{{sig}}"}],
            "body": {"mode": "raw", "raw": "{\"n\":1}"}}}]
    })
    .to_string()
}

fn environment(api: &Api) -> String {
    json!({"name": "prod", "_postman_variable_scope": "environment", "values": [
        {"key": "base", "value": api.origin(), "enabled": true},
        {"key": "tenant", "value": "acme", "enabled": true},
        {"key": "off", "value": "OFF", "enabled": false},
        {"key": "signing_secret", "value": "FAKE-ENV-SECRET", "type": "secret", "enabled": true}]})
    .to_string()
}

#[test]
fn an_environment_file_fills_the_collection_and_keeps_secrets_back() {
    let api = Api::start(3600);
    let (dir, p) = setup("env");
    let doc = write(&dir, "c.json", &collection(&["// nothing"]));
    let env = write(&dir, "prod.json", &environment(&api));
    // Without it the host is unknown.
    let d = ok(&p, &["import", "api", "--dry-run", "--", &doc], &[]);
    assert_eq!(d["built"], 0, "{d}");
    let d = ok(&p, &["import", "api", "--dry-run", "--environment", &env, "--", &doc], &[]);
    assert_eq!(d["built"], 1, "{d}");
    assert_eq!(d["environment"]["name"], "prod");
    let text = d.to_string();
    assert!(!text.contains("FAKE-ENV-SECRET") && !text.contains("FAKE-OVERRIDDEN"), "{text}");
    assert!(d["requests"][0]["url"].as_str().unwrap().contains("x=acme"), "{d}");
    let secret = d["variables"].as_array().unwrap().iter().find(|v| v["name"] == "signing_secret").unwrap().clone();
    assert_eq!(secret["secret"], true, "{secret}");
    assert_eq!(secret["source"], "environment", "{secret}");
    // A changed file is refused once the preview has pinned it.
    let sha = d["environment"]["sha256"].as_str().unwrap().to_string();
    ok(
        &p,
        &["import", "api", "--dry-run", "--environment", &env, "--expect-environment-sha256", &sha, "--", &doc],
        &[],
    );
    std::fs::write(&env, environment(&api).replace("acme", "other")).unwrap();
    let o = run(
        &p,
        &["import", "api", "--dry-run", "--environment", &env, "--expect-environment-sha256", &sha, "--", &doc],
        &[],
    );
    assert!(o.code != 0 && o.all.contains("environment file changed"), "{}", o.all);
    // The file given as the document says what to do with it.
    let o = run(&p, &["import", "api", "--dry-run", "--", &env], &[]);
    assert!(o.code != 0 && o.all.contains("--environment"), "{}", o.all);
}

#[test]
fn a_chosen_prerequest_script_signs_each_request_as_sent() {
    let api = Api::start(3600);
    let (dir, p) = setup("script");
    let script = [
        "const secret = pm.environment.get('signing_secret');",
        "const text = pm.request.method + '\\n' + pm.request.url.getPathWithQuery() + '\\n' + pm.request.body.toString();",
        "const sig = CryptoJS.HmacSHA256(text, secret).toString(CryptoJS.enc.Hex);",
        "pm.collectionVariables.set('sig', sig);",
        "pm.request.headers.upsert({key: 'X-Direct', value: 'set-by-script'});",
    ];
    let doc = write(&dir, "c.json", &collection(&script));
    let env = write(&dir, "prod.json", &environment(&api));

    // Listed, not run: a preview and an import without the signer execute nothing.
    let d = ok(&p, &["import", "api", "--dry-run", "--environment", &env, "--", &doc], &[]);
    assert_eq!(d["scripts"][0]["scopes"], json!(["collection"]));
    assert_eq!(d["scripts"][0]["signs"], true);
    assert!(d["scripts"][0].get("text").is_none(), "{d}");
    let sha = d["scripts"][0]["sha256"].as_str().unwrap().to_string();
    let shown = ok(&p, &["import", "api", "--dry-run", "--show-scripts", "--environment", &env, "--", &doc], &[]);
    assert!(shown["scripts"][0]["text"].as_str().unwrap().contains("HmacSHA256"), "{shown}");

    ok(
        &p,
        &[
            "auth",
            "sign",
            "add",
            "pm",
            "sig",
            "--script",
            &doc,
            "--script-sha256",
            &sha,
            "--environment",
            &env,
            "--origin",
            &api.origin(),
        ],
        &[],
    );
    ok(&p, &["auth", "rule", "add", "pm", "--action", "sign:sig"], &[]);
    ok(&p, &["import", "api", "--auth", "pm", "--environment", &env, "--", &doc], &[]);
    let hit = &api.at("/v1/a")[0];
    let want = hex_of(&hmac_digest(
        HmacAlg::Sha256,
        b"FAKE-ENV-SECRET",
        format!("POST\n{}\n{{\"n\":1}}", hit.target).as_bytes(),
    ));
    // Back from the collection's `X-Auth-Sig: {{sig}}`, which the importer strips as a credential.
    assert_eq!(hit.header("X-Auth-Sig"), Some(want.as_str()), "{hit:?}");
    assert_eq!(hit.header("X-Direct"), Some("set-by-script"));
    assert!(hit.header("X-Brainproxy-Script").is_none(), "the marker stays home: {hit:?}");

    // The secret stays in its file, and the script's text is not copied into the project.
    let text = project_text(&p);
    assert!(!text.contains("FAKE-ENV-SECRET"), "the secret in the project");
    assert!(!text.contains("HmacSHA256"), "the script in the project");

    // A script that changed since it was chosen doesn't run.
    std::fs::write(&doc, collection(&["pm.request.headers.upsert({key: 'X-Evil', value: '1'});"])).unwrap();
    let before = api.hits().len();
    run(&p, &["import", "api", "--auth", "pm", "--environment", &env, "--", &doc], &[]);
    assert!(api.hits()[before..].iter().all(|h| h.header("X-Evil").is_none()));
}

#[test]
fn a_script_can_change_only_headers_and_query() {
    let api = Api::start(3600);
    let (dir, p) = setup("confine");
    let env = write(&dir, "prod.json", &environment(&api));
    for (i, (script, says)) in [
        ("pm.request.headers.upsert({key: 'Host', value: 'evil.test'});", "can't change Host"),
        ("pm.request.headers.upsert({key: 'Content-Length', value: '0'});", "can't change Content-Length"),
        ("pm.request.url = 'http://evil.test/';", "changing pm.request.url"),
        ("pm.sendRequest('http://evil.test/');", "pm.sendRequest"),
    ]
    .iter()
    .enumerate()
    {
        let doc = write(&dir, &format!("c{i}.json"), &collection(&[script]));
        let name = format!("s{i}");
        ok(
            &p,
            &["auth", "sign", "add", &name, "sig", "--script", &doc, "--environment", &env, "--origin", &api.origin()],
            &[],
        );
        ok(&p, &["auth", "rule", "add", &name, "--action", "sign:sig"], &[]);
        let before = api.hits().len();
        let o = run(&p, &["import", "api", "--auth", &name, "--environment", &env, "--", &doc], &[]);
        assert!(api.hits().len() == before, "{script} sent something: {:?}", api.hits());
        assert!(o.all.contains(says), "{script}: {}", o.all);
    }
    let doc = write(&dir, "bad.json", &collection(&["const = ;"]));
    let o = run(&p, &["auth", "sign", "add", "b", "sig", "--script", &doc, "--origin", &api.origin()], &[]);
    assert!(o.code != 0 && o.all.contains("doesn't parse"), "{}", o.all);
}

#[test]
fn a_graphql_schema_runs_with_mutations_opted_in() {
    let api = Api::start(3600);
    let (dir, p) = setup("gql");
    let sdl = "type Query { me: User user(id: ID!): User }\n\
               type Mutation { deleteUser(id: ID!): Boolean }\n\
               type User { id: ID! name: String }\n";
    let schema = write(&dir, "schema.graphql", sdl);
    let endpoint = format!("{}/graphql", api.origin());
    // A schema file names no endpoint.
    let d = ok(&p, &["import", "api", "--dry-run", "--", &schema], &[]);
    assert_eq!((d["format"].as_str(), d["base_url_required"].as_bool()), (Some("graphql"), Some(true)), "{d}");
    let d = ok(&p, &["import", "api", "--dry-run", "--base-url", &endpoint, "--", &schema], &[]);
    assert_eq!(d["built"], 3, "{d}");
    let row = |n: &str| d["requests"].as_array().unwrap().iter().find(|r| r["name"] == n).unwrap().clone();
    assert_eq!(row("query me")["included"], true);
    let mutation = row("mutation deleteUser");
    assert_eq!((mutation["included"].as_bool(), mutation["excluded_reason"].as_str()), (Some(false), Some("method")));
    assert_eq!((mutation["opt_in"].as_str(), mutation["state_changing"].as_bool()), (Some("MUTATION"), Some(true)));

    ok(&p, &["import", "api", "--base-url", &endpoint, "--", &schema], &[]);
    let sent: Vec<String> = api.at("/graphql").iter().map(|h| h.body.clone()).collect();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(sent.iter().all(|b| !b.contains("mutation")), "{sent:?}");
    ok(&p, &["import", "api", "--base-url", &endpoint, "--include-methods", "MUTATION", "--", &schema], &[]);
    assert!(api.at("/graphql").iter().any(|h| h.body.contains("deleteUser") && h.method == "POST"));
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
