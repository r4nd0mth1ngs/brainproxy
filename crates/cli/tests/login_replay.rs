//! Logins plain recorded requests couldn't repeat before, each against a local app and each
//! lost and made again by itself:
//!
//! - `/a`: a password form, then a one-time code on its own page. The site takes each code
//!   once. Replayed as requests, with the code made from the profile's TOTP secret.
//! - `/b`: a page that hashes the password in JavaScript, posts JSON with a one-time code, and
//!   keeps a bearer token in localStorage. Replayed in a headless browser.
//! - `/c`: a passkey. The site checks the signature and that its counter goes up every time.
//!   Registered and replayed with the browser's virtual authenticator.
//!
//! The browser tests are skipped when no Chromium-based browser is installed. While they
//! record, a script the test app serves does what a person would (the recorder is started
//! unattended, where a page script's events count).

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};

const USER: &str = "alice";
/// Needs encoding in a form body.
const PASS: &str = "p&ss w0rd";
/// SHA-256, eight digits, and a short period: a login that must wait for the next code
/// (the site takes each once) doesn't wait long.
const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const TOTP_URI: &str =
    "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test&algorithm=SHA256&digits=8&period=3";

fn generator() -> brainproxy_core::totp::Generator {
    brainproxy_core::totp::Totp::from_input(TOTP_URI, None, None, None).unwrap().generator().unwrap()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')))
        .unwrap_or_default()
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes).as_ref().to_vec()
}

#[derive(Default)]
struct App {
    counter: usize,
    /// Every request: "METHOD /path -> status".
    log: Vec<String>,
    /// Bodies of the requests that carried a code or a password, as the app got them.
    bodies: Vec<String>,
    /// Valid sessions (cookie values), for all three apps.
    sessions: HashSet<String>,
    /// Time steps whose code was taken: a code works once.
    used_steps: HashSet<u64>,
    /// Codes refused.
    refused: usize,
    logins: usize,
    /// /a: the cookie a login form was given, and its token; then whether its password was right.
    forms: HashMap<String, String>,
    passed: HashMap<String, String>,
    /// /b
    nonces: HashSet<String>,
    tokens: HashSet<String>,
    /// /c
    passwords_off: bool,
    challenges: HashSet<String>,
    /// Credential id and public key (the uncompressed P-256 point).
    passkey: Option<(String, Vec<u8>)>,
    /// The signature counter of each sign-in, in order.
    counts: Vec<u32>,
    /// What the page script does in place of a person while a login is recorded.
    autopilot: Option<&'static str>,
}

impl App {
    /// Whether `code` is the current code (or the one before, as sites allow) and unused.
    fn take_code(&mut self, code: &str) -> bool {
        let g = generator();
        let now = g.step(brainproxy_core::totp::unix_now());
        let step = [now, now - 1].into_iter().find(|s| g.code_for_step(*s) == code);
        match step.filter(|s| self.used_steps.insert(*s)) {
            Some(_) => true,
            None => {
                self.refused += 1;
                false
            }
        }
    }

    fn session(&mut self, app: &str) -> String {
        self.logins += 1;
        let id = format!("{app}sess{}x{:x}", self.counter, self.counter * 7919 + 13);
        self.sessions.insert(id.clone());
        id
    }
}

struct Server {
    port: u16,
    app: Arc<Mutex<App>>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Arc::new(Mutex::new(App::default()));
        // `localhost` may resolve to ::1 first.
        let listeners = [Some(listener), TcpListener::bind(("::1", port)).ok()];
        for listener in listeners.into_iter().flatten() {
            let shared = app.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(s) = stream else { continue };
                    let app = shared.clone();
                    std::thread::spawn(move || handle(s, &app, port));
                }
            });
        }
        Server { port, app }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    /// The same app by name: a passkey belongs to a domain, never to an address.
    fn local(&self, path: &str) -> String {
        format!("http://localhost:{}{path}", self.port)
    }

    fn with<T>(&self, f: impl FnOnce(&mut App) -> T) -> T {
        f(&mut self.app.lock().unwrap())
    }

    /// Waits until the app says so (a page script has finished what a person would do).
    fn wait_for(&self, what: &str, done: impl Fn(&App) -> bool) {
        let start = Instant::now();
        while !self.with(|a| done(a)) {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "{what} didn't happen; the app saw: {:#?}",
                self.with(|a| a.log.clone())
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Request line, lowercased headers, body.
type Request = (String, Vec<(String, String)>, String);

fn read_request(s: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(i) = text.find("\r\n\r\n") {
            let mut lines = text[..i].split("\r\n");
            let line = lines.next()?.to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                .collect();
            let cl = headers.iter().find(|(k, _)| k == "content-length").map_or(0, |(_, v)| v.parse().unwrap_or(0));
            if buf.len() >= i + 4 + cl {
                return Some((line, headers, String::from_utf8_lossy(&buf[i + 4..i + 4 + cl]).to_string()));
            }
        }
    }
}

const HELPERS: &str = r#"
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const raw = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const post = (url, body) => fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}).then((r) => r.json());
"#;

/// What a person would do, done by the page while a login is recorded.
fn autopilot(kind: Option<&'static str>, path: &str, code: &str) -> String {
    let set = "const set = (el, v) => { el.value = v; el.dispatchEvent(new Event('input', {bubbles: true})); \
               el.dispatchEvent(new Event('change', {bubbles: true})); };";
    let act = match (kind, path) {
        (Some("b"), "/b/login") => format!(
            "set(f.user, {USER:?}); set(f.pass, {PASS:?}); set(f.otp, {code:?}); setTimeout(() => go.click(), 150);"
        ),
        (Some("enroll"), "/c/login") => {
            format!("set(f.user, 'carol'); set(f.pass, {PASS:?}); setTimeout(() => pw.click(), 150);")
        }
        (Some("enroll"), "/c/home") => "settings.click();".to_string(),
        (Some("enroll"), "/c/settings") => "add.click();".to_string(),
        (Some("passkey"), "/c/login") => "pk.click();".to_string(),
        (Some("leave"), "/d/login") => "sso.click();".to_string(),
        _ => return String::new(),
    };
    format!("<script>setTimeout(() => {{ {set} {act} }}, 300);</script>")
}

fn handle(mut s: TcpStream, app: &Mutex<App>, port: u16) {
    let Some((line, headers, body)) = read_request(&mut s) else { return };
    let header = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let cookies: HashMap<String, String> = header("cookie")
        .unwrap_or_default()
        .split(';')
        .filter_map(|c| c.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let cookie = |name: &str| cookies.get(name).cloned().unwrap_or_default();
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    // A proxy may send the absolute form.
    let path = target.split('?').next().unwrap_or("/");
    let path =
        path.find("://").and_then(|i| path[i + 3..].find('/').map(|j| &path[i + 3 + j..])).unwrap_or(path).to_string();
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();
    let field = |name: &str| form.get(name).cloned().unwrap_or_default();
    let sent: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let text = |name: &str| sent[name].as_str().unwrap_or_default().to_string();

    let mut a = app.lock().unwrap();
    a.counter += 1;
    let n = a.counter;
    let code = generator().now();
    let auto = autopilot(a.autopilot, &path, &code);
    let page = |status: &str, extra: &str, body: &str| {
        let body = format!("<!doctype html><html><body>{body}{auto}</body></html>");
        format!("HTTP/1.1 {status}\r\nContent-Type: text/html\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    };
    let api = |status: &str, extra: &str, v: Value| {
        let body = v.to_string();
        format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    };
    let to = |location: &str, extra: &str| {
        format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n")
    };
    if method == "POST" {
        a.bodies.push(body.clone());
    }
    let code_form = |ticket: &str, note: &str| {
        format!(
            "<p>{note}</p><form method=post action=/a/otp><input type=hidden name=ticket value=\"{ticket}\">\
             <input name=otp autocomplete=one-time-code><button>Verify</button></form>"
        )
    };
    let resp = match (method.as_str(), path.as_str()) {
        // --- /a: a password form, then a one-time code on its own page.
        ("GET", "/a/login") => {
            let (id, token) = (format!("pre{n}"), format!("csrf{n}t0k{:x}", n * 7919));
            a.forms.insert(id.clone(), token.clone());
            let form = format!(
                "<form method=post action=/a/login><input type=hidden name=csrf value=\"{token}\">\
                 <input name=user><input type=password name=pass><button>Sign in</button></form>"
            );
            page("200 OK", &format!("Set-Cookie: apre={id}; Path=/\r\n"), &form)
        }
        ("POST", "/a/login") => {
            let pre = cookie("apre");
            let good = a.forms.get(&pre).is_some_and(|t| *t == field("csrf")) && field("user") == USER && field("pass") == PASS;
            if good {
                a.passed.insert(pre, format!("tick{n}e7{:x}", n * 104_729));
                to("/a/otp", "")
            } else {
                page("200 OK", "", "<p>Wrong user or password</p><form method=post action=/a/login><input type=password name=pass></form>")
            }
        }
        ("GET", "/a/otp") => match a.passed.get(&cookie("apre")).cloned() {
            Some(ticket) => page("200 OK", "", &code_form(&ticket, "Enter the code from your app")),
            None => to("/a/login", ""),
        },
        ("POST", "/a/otp") => {
            let pre = cookie("apre");
            let ticket = a.passed.get(&pre).cloned().unwrap_or_default();
            if !ticket.is_empty() && ticket == field("ticket") && a.take_code(&field("otp")) {
                a.passed.remove(&pre);
                let id = a.session("a");
                to("/a/home", &format!("Set-Cookie: asid={id}; Path=/\r\n"))
            } else {
                page("200 OK", "", &code_form(&ticket, "Wrong code"))
            }
        }
        ("GET", "/a/home") if a.sessions.contains(&cookie("asid")) => {
            page("200 OK", "", "<p>Welcome alice</p><a href=/a/logout>Log out</a>")
        }
        ("GET", "/a/home") => to("/a/login", ""),
        // One form for all three.
        ("POST", "/a/one") => {
            if field("user") == USER && field("pass") == PASS && a.take_code(&field("otp")) {
                let id = a.session("a");
                to("/a/home", &format!("Set-Cookie: asid={id}; Path=/\r\n"))
            } else {
                page("200 OK", "", "<p>Wrong</p><form method=post action=/a/one><input type=password name=pass></form>")
            }
        }

        // --- /b: the page hashes the password, posts JSON, keeps a bearer token.
        ("GET", "/b/login") => {
            let nonce = format!("n{n}c{:x}", n * 15_485_863);
            a.nonces.insert(nonce.clone());
            let body = format!(
                r#"<form id=f><input name=user autocomplete=username><input type=password name=pass>
<input name=otp autocomplete=one-time-code inputmode=numeric><button id=go type=submit>Sign in</button></form><p id=msg></p>
<script>{HELPERS}
const NONCE = "{nonce}";
// A page that would like the replay to click something of its choosing.
try {{ window.__bpRecord(JSON.stringify({{t: 'click', css: '#forged', top: true, url: location.href}})); }} catch (e) {{}}
const sha = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))]
  .map((b) => b.toString(16).padStart(2, '0')).join('');
f.addEventListener('submit', async (e) => {{
  e.preventDefault();
  const j = await post('/b/api/login', {{user: f.user.value, proof: await sha(f.pass.value + NONCE), otp: f.otp.value, nonce: NONCE}});
  if (j.token) {{ localStorage.setItem('token', j.token); location.href = '/b/home'; }} else msg.textContent = 'Wrong';
}});
</script>"#
            );
            page("200 OK", "", &body)
        }
        ("POST", "/b/api/login") => {
            let nonce = text("nonce");
            let proof = hex::encode(sha256(format!("{PASS}{nonce}").as_bytes()));
            if a.nonces.remove(&nonce) && text("user") == USER && text("proof") == proof && a.take_code(&text("otp")) {
                let id = a.session("b");
                let token = format!("tok{n}b3ar3r{:x}", n * 32_452_843);
                a.tokens.insert(token.clone());
                api("200 OK", &format!("Set-Cookie: bsid={id}; Path=/\r\n"), json!({"token": token}))
            } else {
                api("403 Forbidden", "", json!({"error": "wrong"}))
            }
        }
        ("GET", "/b/home") => page(
            "200 OK",
            "",
            "<p id=who></p><a href=/b/logout>Log out</a><script>fetch('/b/api/me', {headers: {Authorization: 'Bearer ' + \
             localStorage.getItem('token')}}).then((r) => r.json()).then((j) => { who.textContent = j.user ? 'Hello ' + j.user : \
             'Signed out'; });</script>",
        ),
        ("GET", "/b/api/me") => {
            let bearer = header("authorization").and_then(|v| v.strip_prefix("Bearer ").map(str::to_string)).unwrap_or_default();
            if a.tokens.contains(&bearer) && a.sessions.contains(&cookie("bsid")) {
                api("200 OK", "", json!({"user": USER}))
            } else {
                api("401 Unauthorized", "", json!({"error": "login"}))
            }
        }

        // --- /c: a password to start with, then a passkey.
        ("GET", "/c/login") => page(
            "200 OK",
            "",
            &format!(
                r#"<form id=f method=post action=/c/login><input name=user><input type=password name=pass><button id=pw>Sign in</button></form>
<button id=pk type=button>Sign in with a passkey</button><p id=msg></p>
<script>{HELPERS}
pk.addEventListener('click', async () => {{
  try {{
    const c = await (await fetch('/c/api/challenge')).json();
    const cred = await navigator.credentials.get({{publicKey: {{challenge: raw(c.challenge), rpId: 'localhost', userVerification: 'required'}}}});
    const r = cred.response;
    const j = await post('/c/api/assert', {{id: b64(cred.rawId), auth: b64(r.authenticatorData), client: b64(r.clientDataJSON), sig: b64(r.signature)}});
    if (j.ok) location.href = '/c/home'; else msg.textContent = 'Refused: ' + j.error;
  }} catch (e) {{ msg.textContent = 'Error: ' + e; fetch('/c/api/error?' + encodeURIComponent(String(e))); }}
}});
</script>"#
            ),
        ),
        ("POST", "/c/login") => {
            if !a.passwords_off && field("user") == "carol" && field("pass") == PASS {
                let id = a.session("c");
                to("/c/home", &format!("Set-Cookie: csid={id}; Path=/\r\n"))
            } else {
                page("200 OK", "", "<p>Wrong</p><form method=post action=/c/login><input type=password name=pass></form>")
            }
        }
        ("GET", "/c/home") if a.sessions.contains(&cookie("csid")) => {
            page("200 OK", "", "<p>Welcome carol</p><a id=settings href=/c/settings>Security</a> <a href=/c/logout>Log out</a>")
        }
        ("GET", "/c/settings") if a.sessions.contains(&cookie("csid")) => page(
            "200 OK",
            "",
            &format!(
                r#"<button id=add type=button>Add a passkey</button><p id=msg></p>
<script>{HELPERS}
add.addEventListener('click', async () => {{
  try {{
    const c = await (await fetch('/c/api/challenge')).json();
    const cred = await navigator.credentials.create({{publicKey: {{
      rp: {{name: 'Test', id: 'localhost'}}, user: {{id: new TextEncoder().encode('carol-id'), name: 'carol', displayName: 'Carol'}},
      challenge: raw(c.challenge), pubKeyCredParams: [{{type: 'public-key', alg: -7}}],
      authenticatorSelection: {{residentKey: 'required', userVerification: 'required'}}}}}});
    const j = await post('/c/api/register', {{id: b64(cred.rawId), spki: b64(cred.response.getPublicKey())}});
    msg.textContent = j.ok ? 'Passkey added' : 'Refused';
  }} catch (e) {{ msg.textContent = 'Error: ' + e; fetch('/c/api/error?' + encodeURIComponent(String(e))); }}
}});
</script>"#
            ),
        ),
        ("GET", "/c/home" | "/c/settings") => to("/c/login", ""),
        ("GET", "/c/api/challenge") => {
            let challenge = b64(format!("challenge-{n}-{:x}", n * 49_979_687).as_bytes());
            a.challenges.insert(challenge.clone());
            api("200 OK", "", json!({"challenge": challenge}))
        }
        ("POST", "/c/api/register") if a.sessions.contains(&cookie("csid")) => {
            // The key as a SubjectPublicKeyInfo: the P-256 point is its last 65 bytes.
            let spki = unb64(&text("spki"));
            let point = spki[spki.len().saturating_sub(65)..].to_vec();
            a.passkey = Some((text("id"), point));
            api("200 OK", "", json!({"ok": true}))
        }
        ("POST", "/c/api/assert") => match verify_assertion(&mut a, &sent, port) {
            Ok(count) => {
                a.counts.push(count);
                let id = a.session("c");
                api("200 OK", &format!("Set-Cookie: csid={id}; Path=/\r\n"), json!({"ok": true}))
            }
            Err(e) => api("403 Forbidden", "", json!({"ok": false, "error": e})),
        },
        // --- /d: a sign-in that goes through a host the engagement doesn't cover.
        ("GET", "/d/login") => page(
            "200 OK",
            "",
            &format!("<a id=sso href=\"http://127.0.0.2:{port}/d/outside\">Sign in with your company account</a>"),
        ),
        _ => page("404 Not Found", "", "<p>Not here</p>"),
    };
    let status = resp.split(' ').nth(1).unwrap_or("").to_string();
    a.log.push(format!("{method} {target} -> {status}"));
    drop(a);
    let _ = s.write_all(resp.as_bytes());
}

/// Checks a WebAuthn assertion as a site does: the challenge is one it gave, for this origin;
/// the authenticator data is for this site, with the user present and verified; the counter
/// is higher than the last one seen; and the signature is the registered key's.
fn verify_assertion(a: &mut App, sent: &Value, port: u16) -> Result<u32, String> {
    let part = |name: &str| unb64(sent[name].as_str().unwrap_or_default());
    let (id, point) = a.passkey.clone().ok_or("no passkey is registered")?;
    if sent["id"].as_str() != Some(id.as_str()) {
        return Err("another credential".into());
    }
    let (auth, client, sig) = (part("auth"), part("client"), part("sig"));
    let data: Value = serde_json::from_slice(&client).map_err(|e| e.to_string())?;
    let challenge = b64(&unb64(data["challenge"].as_str().unwrap_or_default()));
    if data["type"] != "webauthn.get" || !a.challenges.remove(&challenge) {
        return Err("not an answer to a challenge given here".into());
    }
    if data["origin"].as_str() != Some(&format!("http://localhost:{port}")) {
        return Err(format!("signed for {}", data["origin"]));
    }
    if auth.len() < 37 || auth[..32] != sha256(b"localhost")[..] {
        return Err("authenticator data for another site".into());
    }
    if auth[32] & 0x05 != 0x05 {
        return Err("the user wasn't present and verified".into());
    }
    let count = u32::from_be_bytes([auth[33], auth[34], auth[35], auth[36]]);
    if a.counts.last().is_some_and(|last| count <= *last) {
        return Err(format!("the counter didn't go up ({count} after {:?})", a.counts));
    }
    let mut signed = auth.clone();
    signed.extend(sha256(&client));
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, &point)
        .verify(&signed, &sig)
        .map_err(|_| "bad signature".to_string())?;
    Ok(count)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

struct Project {
    file: std::path::PathBuf,
    home: std::path::PathBuf,
}

impl Project {
    fn new(name: &str) -> Project {
        let dir = std::env::temp_dir().join(format!("bp-login-replay-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = Project { file: dir.join("p.bpdb"), home: dir.join("home") };
        p.ok(&["engagement", "start", "--target", "127.0.0.1", "--target", "localhost"]);
        p
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = bin();
        c.args(["--format", "json", "--project"])
            .arg(&self.file)
            .arg("--home")
            .arg(&self.home)
            .args(args)
            .env("BP_TEST_PASSWORD", PASS)
            .env("BP_TEST_TOTP", TOTP_URI)
            // The pages are this test's own: Chromium's sandbox may be unavailable in containers and CI.
            .env("BRAINPROXY_BROWSER_NO_SANDBOX", "1")
            .env("BRAINPROXY_RECORD_UNATTENDED", "1")
            .stdin(Stdio::null());
        c
    }

    fn run(&self, args: &[&str]) -> (i32, Value) {
        let out = self.command(args).output().unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!("bad JSON ({e}): {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
        });
        (out.status.code().unwrap(), v)
    }

    fn ok(&self, args: &[&str]) -> Value {
        let (code, v) = self.run(args);
        assert_eq!(code, 0, "{args:?}: {v}");
        v["data"].clone()
    }

    /// Starts the proxy; its address.
    fn proxy(&self) -> String {
        self.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["listen"].as_str().unwrap().to_string()
    }

    /// Waits until the proxy has written the row of a request to `path` (it writes them on a
    /// thread of its own, a moment after the answer).
    fn wait_recorded(&self, path: &str) {
        let sql = format!(
            "SELECT count(*) FROM history WHERE source = 'proxy' AND status IS NOT NULL AND url LIKE '%{path}'"
        );
        let start = Instant::now();
        while self.ok(&["query", &sql])["rows"][0][0] == 0 {
            assert!(start.elapsed() < Duration::from_secs(60), "the proxy never recorded {path}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The requests of history rows from `source`, as recorded.
    fn recorded(&self, source: &str) -> Vec<String> {
        let rows = self.ok(&["query", &format!("SELECT id FROM history WHERE source = '{source}' ORDER BY id")]);
        let ids: Vec<i64> =
            rows["rows"].as_array().unwrap().iter().filter_map(|r| r[0].as_i64().or(r["id"].as_i64())).collect();
        ids.iter()
            .map(|id| {
                let out =
                    self.command(&["history", "show", &id.to_string(), "--raw", "--part", "request"]).output().unwrap();
                String::from_utf8_lossy(&out.stdout).into_owned()
            })
            .collect()
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = self.command(&["proxy", "stop"]).output();
    }
}

/// A browser's worth of HTTP through the proxy: one request, with a cookie jar.
struct Visitor {
    proxy: String,
    cookies: HashMap<String, String>,
}

impl Visitor {
    fn send(&mut self, method: &str, url: &str, body: &str) -> String {
        let mut s = TcpStream::connect(&self.proxy).unwrap();
        let host = url.split('/').nth(2).unwrap();
        let jar = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let mut req = format!("{method} {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        if !jar.is_empty() {
            req.push_str(&format!("Cookie: {jar}\r\n"));
        }
        if method == "POST" {
            req.push_str(&format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        s.write_all(format!("{req}\r\n{body}").as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        for line in out.lines().take_while(|l| !l.is_empty()) {
            if let Some((k, v)) = line.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")) {
                if let Some((name, value)) = v.split(';').next().and_then(|c| c.split_once('=')) {
                    self.cookies.insert(name.trim().to_string(), value.trim().to_string());
                }
                let _ = k;
            }
        }
        out
    }
}

fn value_of(html: &str, name: &str) -> String {
    let at = html.find(&format!("name={name} value=\"")).unwrap_or_else(|| panic!("no {name} in {html}"));
    let rest = &html[at + name.len() + 13..];
    rest[..rest.find('"').unwrap()].to_string()
}

fn encoded(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish()
}

#[test]
fn a_recorded_login_with_a_one_time_code_is_replayed_and_made_again() {
    let srv = Server::start();
    let p = Project::new("totp");
    let mut browser = Visitor { proxy: p.proxy(), cookies: HashMap::new() };

    // A person logs in through the proxy: password, then the code from their app.
    let form = browser.send("GET", &srv.url("/a/login"), "");
    let csrf = value_of(&form, "csrf");
    let r = browser.send("POST", &srv.url("/a/login"), &encoded(&[("csrf", &csrf), ("user", USER), ("pass", PASS)]));
    assert!(r.starts_with("HTTP/1.1 302"), "{r}");
    let ticket = value_of(&browser.send("GET", &srv.url("/a/otp"), ""), "ticket");
    let typed = generator().now();
    let r = browser.send("POST", &srv.url("/a/otp"), &encoded(&[("ticket", &ticket), ("otp", &typed)]));
    assert!(r.starts_with("HTTP/1.1 302"), "{r}");
    assert!(browser.send("GET", &srv.url("/a/home"), "").contains("Welcome alice"));

    p.wait_recorded("/a/home");
    // Without the secret the login can't be made again: the session it is, and the output says what would help.
    let seen = p.ok(&["auth", "record", "finish", "app", "--since", "0"]);
    assert_eq!(seen["mode"], "session", "{seen}");
    assert_eq!(seen["needs_totp"], true, "{seen}");
    assert!(seen["warnings"].to_string().contains("--totp-secret-env"), "{seen}");

    // With it: the login request, then the code request with its own token and {{totp}}.
    let saved =
        p.ok(&["auth", "record", "finish", "app", "--since", "0", "--save", "--totp-secret-env", "BP_TEST_TOTP"]);
    assert_eq!(saved["mode"], "replay", "{saved}");
    let step = &saved["profile"]["login_steps"][0];
    assert!(step["request"].as_str().unwrap().ends_with("ticket={{csrf}}&otp={{totp}}"), "{saved}");
    assert_eq!(step["csrf_url"], srv.url("/a/otp"), "{saved}");
    assert_eq!(saved["profile"]["totp"]["secret"]["env"], "BP_TEST_TOTP", "{saved}");
    assert!(saved["found"].to_string().contains("makes the code that was typed"), "{saved}");
    assert!(!saved.to_string().contains(SECRET) && !saved.to_string().contains(&typed), "{saved}");

    // The site takes a code once, and the one typed while recording is spent: the login waits
    // for the next and gets in.
    let login = p.ok(&["auth", "login", "app"]);
    assert_eq!(login["login"]["success"], true, "{login}");
    assert_eq!(srv.with(|a| (a.logins, a.refused)), (2, 0));

    // The session is lost; the next request logs in again by itself.
    srv.with(|a| a.sessions.clear());
    let home = srv.url("/a/home");
    let sent = p.ok(&["send", "--url", &home, "--auth", "app"]);
    assert_eq!(sent["response"]["status"], 200, "{sent}");
    assert_eq!(srv.with(|a| (a.logins, a.refused)), (3, 0));

    // No record of a login brainproxy made holds a code or the password: a placeholder each.
    let recorded = p.recorded("auth").join("\n---\n");
    assert!(
        recorded.contains("otp=«auth:app:totp»") && recorded.contains("pass=«auth:app:password:form»"),
        "{recorded}"
    );
    let codes: Vec<String> =
        srv.with(|a| a.bodies.iter().filter_map(|b| b.split("otp=").nth(1).map(str::to_string)).collect());
    assert_eq!(codes.len(), 3);
    assert!(codes.iter().skip(1).all(|c| !recorded.contains(c.as_str())), "{recorded}");
    // And the site got real ones.
    assert!(codes.iter().all(|c| c.len() == 8 && c.bytes().all(|b| b.is_ascii_digit())), "{codes:?}");

    // The profile shows where the secret is, never the secret.
    let shown = p.ok(&["auth", "show", "app"]);
    assert!(!shown.to_string().contains(SECRET), "{shown}");
}

#[test]
fn a_code_in_the_login_form_a_stored_secret_and_what_an_agent_may_read() {
    let srv = Server::start();
    let p = Project::new("totp-one");
    let (login, check) = (srv.url("/a/one"), srv.url("/a/home"));
    let args = [
        "auth",
        "add",
        "one",
        "--login-url",
        &login,
        "--login-body",
        "user={{username}}&pass={{password}}&otp={{totp}}",
        "--username",
        USER,
        "--password-env",
        "BP_TEST_PASSWORD",
        "--check-url",
        &check,
        "--logged-in",
        "Welcome alice",
        "--logged-out",
        "Location: /a/login",
        "--relogin-interval",
        "0",
    ];
    // The secret from the variable the app uses: stored, and masked from then on.
    let out = p.command(&args).env("BRAINPROXY_SECRET_TOTP", TOTP_URI).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let added: Value = serde_json::from_slice(&out.stdout).unwrap();
    let totp = &added["data"]["profile"]["totp"];
    assert_eq!(
        (&totp["secret"]["literal"], &totp["algorithm"], &totp["digits"], &totp["period"]),
        (&json!("********"), &json!("sha256"), &json!(8), &json!(3))
    );
    assert!(!added.to_string().contains(SECRET));

    assert_eq!(p.ok(&["auth", "login", "one"])["login"]["success"], true);
    // Twice within a code's period: the second login waits for the next code.
    srv.with(|a| a.sessions.clear());
    assert_eq!(p.ok(&["send", "--url", &check, "--auth", "one"])["response"]["status"], 200);
    assert_eq!(srv.with(|a| (a.logins, a.refused)), (2, 0));

    // An edit that can't see the secret keeps it; one without the flag drops it, and the login says why it can't go on.
    let mut edit = args.to_vec();
    edit.push("--keep-totp");
    assert_eq!(p.ok(&edit)["profile"]["totp"]["secret"]["literal"], "********");
    srv.with(|a| a.sessions.clear());
    assert_eq!(p.ok(&["auth", "login", "one"])["login"]["success"], true);
    p.ok(&args);
    let (code, v) = p.run(&["auth", "login", "one"]);
    assert_ne!(code, 0);
    assert!(v["error"]["message"].as_str().unwrap().contains("no TOTP secret"), "{v}");

    // Through MCP only a BRAINPROXY_SECRET_* variable is read, as for a password.
    let agent: Vec<&str> =
        args.iter().map(|a| if *a == "BP_TEST_PASSWORD" { "BRAINPROXY_SECRET_PW" } else { a }).collect();
    let as_agent = |more: &[&str]| {
        let mut c = p.command(&[agent.as_slice(), more].concat());
        c.env("BRAINPROXY_MCP_CALL", "1").env("BRAINPROXY_SECRET_OTP", SECRET);
        let out = c.output().unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let (ok, out) = as_agent(&["--totp-secret-env", "BP_TEST_TOTP"]);
    assert!(!ok && out.contains("--totp-secret-env") && out.contains("BRAINPROXY_SECRET_"), "{out}");
    let (ok, out) = as_agent(&["--totp-secret-env", "BRAINPROXY_SECRET_OTP"]);
    assert!(ok && out.contains("BRAINPROXY_SECRET_OTP") && !out.contains(SECRET), "{out}");

    // A secret that isn't one is refused without being repeated.
    let out = p.command(&args).env("BRAINPROXY_SECRET_TOTP", "not a secret!").output().unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("not a secret!"));
}

/// Whether the browser tests can run, saying why not when they can't.
fn browser_available(test: &str) -> bool {
    let p = Project::new(&format!("browsers-{test}"));
    let list = p.ok(&["browser", "list"]);
    if list["browser_crawl"] != true {
        eprintln!("SKIPPED {test}: a browser isn't driven on this platform");
        return false;
    }
    let chromium = list["browsers"].as_array().into_iter().flatten().any(|b| b["kind"] == "chromium");
    if !chromium {
        eprintln!(
            "SKIPPED {test}: no Chromium-based browser found (install chromium, Chrome, Edge or Brave to run it)"
        );
    }
    chromium
}

#[test]
fn a_login_built_in_javascript_is_replayed_in_a_browser_and_made_again() {
    if !browser_available("js-login") {
        return;
    }
    let srv = Server::start();
    let p = Project::new("browser");
    p.proxy();

    // "A person" logs in in the recording browser: user, password, the code, Sign in.
    srv.with(|a| a.autopilot = Some("b"));
    let started = p.ok(&["auth", "record", "start", &srv.url("/b/login")]);
    assert_eq!(started["steps"], true, "{started}");
    srv.wait_for("the recorded login", |a| a.log.iter().any(|l| l.starts_with("GET /b/api/me -> 200")));
    srv.with(|a| a.autopilot = None);
    p.wait_recorded("/b/api/me");

    // A start that can't go ahead leaves the recording in hand alone.
    let (code, v) = p.run(&["auth", "record", "start", &srv.url("/b/login"), "--browser", "netscape"]);
    assert_ne!(code, 0, "{v}");

    // (The steps below are the person's alone: the page's own call to the recorder's binding
    // reached nothing.)
    // No request holds the password (the page hashed it), so plain requests can't repeat this;
    // without the secret for the code, neither can the steps.
    let seen = p.ok(&["auth", "record", "finish", "js"]);
    assert_eq!((&seen["mode"], &seen["needs_totp"]), (&json!("session"), &json!(true)), "{seen}");

    let saved = p.ok(&["auth", "record", "finish", "js", "--save", "--totp-secret-env", "BP_TEST_TOTP"]);
    assert_eq!(saved["mode"], "browser", "{saved}");
    assert_eq!(
        saved["steps"],
        json!([
            "fill input[name=\"user\"] with {{username}}",
            "fill input[name=\"pass\"] with {{password}}",
            "fill input[name=\"otp\"] with {{totp}}",
            "click #go",
        ]),
        "{saved}"
    );
    let profile = &saved["profile"];
    assert_eq!(profile["username"], USER, "{saved}");
    assert_eq!(profile["password"]["literal"], "********", "{saved}");
    assert_eq!(profile["token_header"], "Authorization: Bearer {{token}}", "{saved}");
    assert_eq!(profile["check_url"], srv.url("/b/api/me"), "{saved}");
    assert!(!saved.to_string().contains(PASS), "{saved}");

    // Replayed in a headless browser: the cookie and the token the page got are the session's.
    let login = p.ok(&["auth", "login", "js"]);
    assert_eq!(login["login"]["success"], true, "{login}");
    assert_eq!(login["session"]["cookies"], json!(["bsid"]), "{login}");
    assert_eq!(login["session"]["token"], true, "{login}");
    assert_eq!(srv.with(|a| (a.logins, a.refused)), (2, 0));

    // Session and token are lost; `send --auth` logs in again in the browser and gets its answer.
    srv.with(|a| {
        a.sessions.clear();
        a.tokens.clear();
    });
    let me = srv.url("/b/api/me");
    let sent = p.ok(&["send", "--url", &me, "--auth", "js"]);
    assert_eq!(sent["response"]["status"], 200, "{sent}");
    assert_eq!(srv.with(|a| (a.logins, a.refused)), (3, 0));

    // What the login browser sent is on record (source auth) with the code as a placeholder.
    let recorded = p.recorded("auth").join("\n---\n");
    assert!(recorded.contains("POST /b/api/login") && recorded.contains("\"otp\":\"«auth:js:totp»\""), "{recorded}");
    let codes: Vec<String> = srv.with(|a| {
        a.bodies
            .iter()
            .filter_map(|b| serde_json::from_str::<Value>(b).ok()?["otp"].as_str().map(str::to_string))
            .collect()
    });
    assert_eq!(codes.len(), 3, "{codes:?}");
    assert!(codes.iter().skip(1).all(|c| !recorded.contains(c.as_str())), "{recorded}");

    // The profile shows its steps, and neither the password nor the secret.
    let shown = p.ok(&["auth", "show", "js"]);
    assert_eq!(shown["browser_steps"].as_array().map(Vec::len), Some(4), "{shown}");
    assert!(!shown.to_string().contains(PASS) && !shown.to_string().contains(SECRET), "{shown}");
}

#[test]
fn a_passkey_registered_while_recording_signs_in_with_a_counter_that_goes_up() {
    if !browser_available("passkey") {
        return;
    }
    let srv = Server::start();
    let p = Project::new("passkey");
    p.proxy();

    // Recording with a virtual authenticator: log in with the password, add a passkey in the settings.
    srv.with(|a| a.autopilot = Some("enroll"));
    let started = p.ok(&["auth", "record", "start", &srv.local("/c/login"), "--passkey"]);
    assert_eq!((&started["steps"], &started["passkey"]), (&json!(true), &json!(true)), "{started}");
    srv.wait_for("the passkey's registration", |a| a.passkey.is_some());
    srv.with(|a| a.autopilot = None);
    p.wait_recorded("/c/api/register");
    let saved = p.ok(&["auth", "record", "finish", "pk", "--save"]);
    assert_eq!(saved["passkeys"][0]["rp_id"], "localhost", "{saved}");
    assert_eq!(saved["passkeys"][0]["user_name"], "carol", "{saved}");
    // (The authenticator counts making the key, too.)
    let made = saved["passkeys"][0]["sign_count"].as_u64().unwrap();
    assert!(saved["found"].to_string().contains("Passkey for localhost"), "{saved}");
    assert!(!saved.to_string().contains("private_key"), "{saved}");

    // The site stops taking passwords. Recording the passkey sign-in, with the profile's passkey in the browser.
    srv.with(|a| {
        a.passwords_off = true;
        a.sessions.clear();
        a.autopilot = Some("passkey");
    });
    p.ok(&["auth", "record", "start", &srv.local("/c/login"), "--passkeys-from", "pk"]);
    let homes = |a: &App| a.log.iter().filter(|l| l.contains(" /c/home -> 200")).count();
    srv.wait_for("the passkey sign-in", |a| a.counts.len() == 1 && homes(a) >= 2);
    srv.with(|a| a.autopilot = None);
    let sql = "SELECT count(*) FROM history WHERE source = 'proxy' AND status = 200 AND url LIKE '%/c/home'";
    while p.ok(&["query", sql])["rows"][0][0].as_i64() < Some(2) {
        std::thread::sleep(Duration::from_millis(100));
    }
    // The site has counted that signature, so the profile has too, already: whatever becomes
    // of this recording, its next sign-in uses a higher count.
    let start = Instant::now();
    while p.ok(&["auth", "show", "pk"])["passkeys"][0]["sign_count"].as_u64() != Some(made + 1) {
        assert!(start.elapsed() < Duration::from_secs(20), "the count used while recording wasn't stored");
        std::thread::sleep(Duration::from_millis(200));
    }
    let saved = p.ok(&["auth", "record", "finish", "pk", "--save"]);
    assert_eq!(saved["mode"], "browser", "{saved}");
    assert_eq!(saved["steps"], json!(["click #pk"]), "{saved}");
    assert_eq!(saved["passkeys"][0]["sign_count"], made + 1, "{saved}");
    assert_eq!(saved["profile"]["check_url"], srv.local("/c/home"), "{saved}");

    // Replayed: the passkey is put back and signs; the site sees its counter go up.
    let login = p.ok(&["auth", "login", "pk"]);
    assert_eq!(login["login"]["success"], true, "{login}");
    assert_eq!(login["session"]["cookies"], json!(["csid"]), "{login}");

    // The session is lost; the next request signs in again by itself, in another process.
    srv.with(|a| a.sessions.clear());
    let home = srv.local("/c/home");
    let sent = p.ok(&["send", "--url", &home, "--auth", "pk"]);
    assert_eq!(sent["response"]["status"], 200, "{sent}");
    let made = made as u32;
    assert_eq!(srv.with(|a| a.counts.clone()), [made + 1, made + 2, made + 3]);

    // The count is kept with the profile; the key is never shown.
    let shown = p.ok(&["auth", "show", "pk"]);
    assert_eq!(shown["passkeys"][0]["sign_count"], made + 3, "{shown}");
    assert!(!shown.to_string().contains("private_key"), "{shown}");
    let listed = p.ok(&["auth", "list"]);
    assert_eq!(listed["profiles"][0]["browser_login"], srv.local("/c/login"), "{listed}");

    // Removing the profile removes its passkey.
    // Nothing `query` can read ever held the key or what was typed while recording.
    let meta = p.ok(&["query", "SELECT key, value FROM meta"]).to_string();
    assert!(!meta.contains("private_key") && !meta.contains("privateKey") && !meta.contains(PASS), "{meta}");
    p.ok(&["auth", "remove", "pk"]);
    assert_eq!(p.ok(&["auth", "list"])["profiles"], json!([]));
}

#[test]
fn a_recorded_step_that_leaves_the_engagement_scope_is_refused() {
    if !browser_available("scope") {
        return;
    }
    let srv = Server::start();
    let p = Project::new("scope");
    p.proxy();
    // The sign-in link goes to another host (the same test app, as it happens, by an address
    // the engagement doesn't name).
    srv.with(|a| a.autopilot = Some("leave"));
    p.ok(&["auth", "record", "start", &srv.url("/d/login")]);
    // The proxy refuses the page the click leads to, and notes that it did.
    let refused = "SELECT count(*) FROM history WHERE url LIKE '%/d/outside%'";
    let start = Instant::now();
    while p.ok(&["query", refused])["rows"][0][0] == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the click was never made: {}",
            p.ok(&["query", "SELECT url, error FROM history"])
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    srv.with(|a| a.autopilot = None);
    p.wait_recorded("/d/login");
    let saved = p.ok(&["auth", "record", "finish", "sso", "--save"]);
    assert_eq!((&saved["mode"], &saved["steps"]), (&json!("browser"), &json!(["click #sso"])), "{saved}");

    // Replayed, the click would take the browser out of scope: refused, and nothing is sent there.
    let (code, v) = p.run(&["auth", "login", "sso"]);
    assert_ne!(code, 0, "{v}");
    assert_eq!(v["error"]["kind"], "out_of_scope", "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains("browser step 1 (click #sso)") && message.contains("127.0.0.2"), "{v}");
    assert!(!srv.with(|a| a.log.iter().any(|l| l.contains("/d/outside"))), "{:?}", srv.with(|a| a.log.clone()));
    assert_eq!(p.ok(&["auth", "status", "sso", "--offline"])["session"]["logged_in"], false);
}
