//! `crawl --browser` against a local single-page app whose API endpoints only show up
//! when its JavaScript runs: a client-side route reached by clicking an element with a
//! click listener (history.pushState), a hash route with a form, and buttons that call
//! fetch(). The API paths are built at run time, so the plain crawl can't read them from
//! the script. A sign-in form's button stays disabled until its fields are filled.
//! Skipped when no Chromium-based browser is installed.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;

const INDEX: &str = r##"<!doctype html><html><head><title>SPA</title></head><body>
<nav><span data-route="/reports">Reports</span> <a href="#/settings">Settings</a> <a href="#/login">Sign in</a> <a href="/account/7">Delete account</a> <button id="logout">Log out</button></nav>
<div id="view"></div><script src="/app.js"></script></body></html>"##;

const APP: &str = r#"
const api = (...p) => ['', 'api', ...p].join('/');
function render() {
  const view = document.getElementById('view');
  const route = location.hash.startsWith('#/') ? location.hash.slice(1) : location.pathname;
  if (route === '/reports') {
    view.innerHTML = '<button id="load">Load report</button> <button id="del">Delete report</button>';
    document.getElementById('load').addEventListener('click', () =>
      fetch(api('reports', 'export'), {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({format: 'csv'})}).then(r => r.json()).then(() =>
          view.insertAdjacentHTML('beforeend', '<p>exported</p>')));
    document.getElementById('del').addEventListener('click', () => fetch(api('reports', '1'), {method: 'DELETE'}));
  } else if (route === '/settings') {
    view.innerHTML = '<form id="f"><input name="nickname"><button>Save</button></form>';
    document.getElementById('f').addEventListener('submit', (e) => {
      e.preventDefault();
      fetch(api('settings') + '?nickname=' + encodeURIComponent(e.target.nickname.value));
    });
  } else if (route === '/login') {
    view.innerHTML = '<form id="l"><input name="email" type="email"><input name="password" type="password">' +
      '<button id="go" disabled>Sign in</button></form>';
    const f = document.getElementById('l');
    f.addEventListener('input', () => {
      document.getElementById('go').disabled = !(f.email.value && f.password.value);
    });
    f.addEventListener('submit', (e) => {
      e.preventDefault();
      fetch(api('login'), {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: f.email.value, password: f.password.value})});
    });
  } else if (route === '/register') {
    // Like Angular Material's select: a combobox whose inner trigger listens, and whose options
    // are made in an overlay at the end of the page when it opens.
    view.innerHTML = '<form id="r"><input name="email" type="email">' +
      '<div id="q" role="combobox" aria-haspopup="listbox" aria-label="Security question" tabindex="0">' +
      '<span class="trigger">Choose a question</span></div><button id="reg" disabled>Register</button></form>';
    let question = '';
    const f = document.getElementById('r');
    const q = document.getElementById('q');
    const check = () => { document.getElementById('reg').disabled = !(f.email.value && question); };
    q.querySelector('.trigger').addEventListener('click', () => {
      const panel = document.createElement('div');
      panel.id = 'q-panel';
      panel.setAttribute('role', 'listbox');
      panel.innerHTML = '<div role="option" aria-disabled="true">Pick one</div>' +
        '<div role="option" data-v="pet">Your first pet?</div><div role="option" data-v="city">Your city?</div>';
      document.body.appendChild(panel);
      q.setAttribute('aria-controls', 'q-panel');
      panel.querySelectorAll('[data-v]').forEach((o) => o.addEventListener('click', () => {
        question = o.dataset.v;
        q.querySelector('.trigger').textContent = o.textContent;
        panel.remove();
        q.removeAttribute('aria-controls');
        check();
      }));
    });
    f.addEventListener('input', check);
    f.addEventListener('submit', (e) => {
      e.preventDefault();
      fetch(api('register') + '?question=' + question);
    });
  } else if (route === '/contact') {
    // A rating slider that must be moved (see-through, as Material draws its own over it), and
    // an arithmetic captcha shown in the page.
    view.innerHTML = '<form id="c"><textarea name="comment"></textarea><p>0/160</p>' +
      '<input type="range" name="rating" min="0" max="5" value="0" style="opacity: 0">' +
      '<label for="cap">What is <code>3+4*2</code> ?</label><input id="cap" aria-label="Result of the CAPTCHA">' +
      '<button id="send" disabled>Send</button></form>';
    const f = document.getElementById('c');
    f.addEventListener('input', () => {
      document.getElementById('send').disabled =
        !(f.comment.value && Number(f.rating.value) > 0 && f.cap.value === '11');
    });
    f.addEventListener('submit', (e) => {
      e.preventDefault();
      fetch(api('feedback') + '?captcha=' + f.cap.value + '&rating=' + f.rating.value);
    });
  } else if (route === '/forgot') {
    // Staged: the answer and new password fields open once the e-mail has been looked up, a
    // second after the last keystroke.
    view.innerHTML = '<form id="p"><input name="email" type="email"><input name="answer" disabled>' +
      '<input name="pw" type="password" disabled><button id="change" disabled>Change</button></form>';
    const f = document.getElementById('p');
    let lookup;
    f.email.addEventListener('input', () => {
      clearTimeout(lookup);
      lookup = setTimeout(() => fetch(api('question') + '?email=' + encodeURIComponent(f.email.value))
        .then((r) => r.json()).then(() => { f.answer.disabled = false; f.pw.disabled = false; }), 1000);
    });
    f.addEventListener('input', () => {
      document.getElementById('change').disabled = !(f.email.value && f.answer.value && f.pw.value);
    });
    f.addEventListener('submit', (e) => {
      e.preventDefault();
      fetch(api('password') + '?answer=' + f.answer.value);
    });
  } else {
    view.innerHTML = '<p>Welcome</p>';
  }
}
document.querySelectorAll('[data-route]').forEach((el) => el.addEventListener('click', () => {
  history.pushState({}, '', el.dataset.route);
  render();
}));
document.getElementById('logout').addEventListener('click', () => fetch(api('logout-now'), {method: 'POST'}));
addEventListener('hashchange', render);
addEventListener('popstate', render);
render();
fetch(api('me'));
"#;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

fn run(args: &[&str], project: &std::path::Path) -> (i32, Value) {
    let out = bin()
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        // The page is this test's own: Chromium's sandbox may be unavailable in containers and CI.
        .env("BRAINPROXY_BROWSER_NO_SANDBOX", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad JSON ({e}): {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    });
    (out.status.code().unwrap(), v)
}

/// The single-page app; returns its port and the request lines it saw.
fn serve_spa() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let mut len = 0;
                loop {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                    let text = String::from_utf8_lossy(&buf[..len]).to_string();
                    if let Some(i) = text.find("\r\n\r\n") {
                        let cl = text
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string())
                            })
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        if len >= i + 4 + cl {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf[..len]).to_ascii_lowercase();
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                log.lock().unwrap().push(line.clone());
                let path = line.split(' ').nth(1).unwrap_or("/");
                // The script may be cached but must be revalidated on every use.
                if path == "/app.js" && text.contains("\r\nif-none-match: \"v1\"") {
                    let _ = s.write_all(b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n");
                    return;
                }
                let cache = if path == "/app.js" { "ETag: \"v1\"\r\nCache-Control: max-age=0\r\n" } else { "" };
                let (ct, body) = if path == "/app.js" {
                    ("application/javascript", APP.to_string())
                } else if path.starts_with("/api/") {
                    ("application/json", "{\"ok\":true}".to_string())
                } else if path.starts_with("/spin") {
                    // Never answers again once loaded.
                    ("text/html", "<script>setTimeout(() => { for (;;) {} }, 0)</script>".to_string())
                } else if path == "/tamper" {
                    (
                        "text/html",
                        "<a href=\"/tampered-link\">x</a><script>__bp.snapshot = () => ({});</script>".to_string(),
                    )
                } else if path == "/favicon.ico" {
                    ("image/x-icon", String::new())
                } else {
                    // Every other path is the app (deep links to client-side routes work).
                    ("text/html", INDEX.to_string())
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\n{cache}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    (port, seen)
}

/// Whether this test can run, saying why not when it can't.
fn browser_available(test: &str) -> bool {
    let dir = std::env::temp_dir().join(format!("bp-test-{}-browser-list-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (code, list) = run(&["browser", "list"], &dir.join("p.bpdb"));
    assert_eq!(code, 0, "{list}");
    if list["data"]["browser_crawl"] != true {
        eprintln!("SKIPPED {test}: the browser crawl doesn't run on this platform");
        return false;
    }
    let chromium = list["data"]["browsers"].as_array().into_iter().flatten().any(|b| b["kind"] == "chromium");
    if !chromium {
        eprintln!(
            "SKIPPED {test}: no Chromium-based browser found (install chromium, Chrome, Edge or Brave to run it)"
        );
    }
    chromium
}

/// A project scoped to loopback, in a folder of its own.
fn test_project(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    let (code, v) = run(&["engagement", "start", "--target", "127.0.0.1"], &project);
    assert_eq!(code, 0, "{v}");
    (dir, project)
}

#[test]
fn browser_crawl_finds_api_calls_made_by_javascript() {
    if !browser_available("browser_crawl_finds_api_calls_made_by_javascript") {
        return;
    }
    let (_dir, project) = test_project("browser-crawl");

    let (port, seen) = serve_spa();
    let site = format!("http://127.0.0.1:{port}/");
    let (code, v) = run(&["crawl", &site, "--browser", "--max-pages", "60", "--max-minutes", "3"], &project);
    assert_eq!(code, 0, "{v}");
    let data = &v["data"];
    assert_eq!(data["mode"], "browser", "{v}");
    assert_eq!(data["sandbox"], false, "this test asks for no sandbox, and the summary says so: {v}");

    let lines = seen.lock().unwrap().clone();
    let saw = |l: &str| lines.iter().any(|x| x.starts_with(l));
    // Reached only by running the script, clicking a listener-only element, a button, and a form.
    assert!(saw("GET /api/me "), "{lines:?}");
    assert!(saw("POST /api/reports/export "), "{lines:?}");
    assert!(saw("GET /api/settings?nickname=brainproxy "), "{lines:?}");
    assert!(saw("GET /reports "), "the pushState route is loaded directly too: {lines:?}");
    assert!(saw("POST /api/login "), "a button enabled by filling the form is clicked: {lines:?}");
    // Every page load revalidates the script; once fetched, the crawl answers that itself.
    assert_eq!(lines.iter().filter(|l| l.starts_with("GET /app.js ")).count(), 1, "{lines:?}");
    assert!(data["revalidations_answered"].as_u64().unwrap() >= 1, "{v}");
    // Nothing destructive reached the site.
    assert!(!lines.iter().any(|l| l.starts_with("DELETE ") || l.contains("logout")), "{lines:?}");
    assert!(!saw("GET /account/7 "), "a link labelled Delete account isn't followed: {lines:?}");

    let not_clicked: Vec<&str> = data["not_clicked"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(not_clicked.iter().any(|l| l.contains("Log out")), "{v}");
    assert!(not_clicked.iter().any(|l| l.contains("Delete report")), "{v}");
    assert!(not_clicked.iter().any(|l| l.contains("Delete account")), "{v}");
    let api: Vec<String> = data["api_calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| format!("{} {}", e["method"].as_str().unwrap(), e["path"].as_str().unwrap()))
        .collect();
    for want in ["GET /api/me", "POST /api/reports/export", "GET /api/settings"] {
        assert!(api.iter().any(|a| a == want), "{want} not in {api:?}");
    }
    let export = data["api_calls"].as_array().unwrap().iter().find(|e| e["path"] == "/api/reports/export").unwrap();
    assert_eq!(export["params"], serde_json::json!(["format"]), "JSON body keys are parameters");

    // Recorded in history as crawl-browser, ready for `scan active`.
    let (code, h) = run(&["history", "list", "--source", "crawl-browser", "--limit", "200"], &project);
    assert_eq!(code, 0, "{h}");
    let rows = h["data"]["items"].as_array().cloned().unwrap_or_default();
    let export = format!("{site}api/reports/export");
    assert!(rows.iter().any(|r| r["url"] == export.as_str() && r["method"] == "POST"), "{h}");
}

/// Forms a person can fill but the field filler alone can't: an ARIA combobox whose options
/// appear only once it is opened, a slider, an arithmetic captcha, and a form whose fields open
/// after its first field is answered.
#[test]
fn browser_crawl_fills_comboboxes_captchas_and_staged_forms() {
    if !browser_available("browser_crawl_fills_comboboxes_captchas_and_staged_forms") {
        return;
    }
    let (_dir, project) = test_project("browser-forms");
    let (port, seen) = serve_spa();
    let at = |r: &str| format!("http://127.0.0.1:{port}/#/{r}");
    let (register, contact, forgot) = (at("register"), at("contact"), at("forgot"));
    let args =
        ["crawl", &register, &contact, &forgot, "--browser", "--depth", "2", "--max-pages", "40", "--max-minutes", "3"];
    let (code, v) = run(&args, &project);
    assert_eq!(code, 0, "{v}");
    let lines = seen.lock().unwrap().clone();
    let saw = |l: &str| lines.iter().any(|x| x.starts_with(l));
    assert!(saw("GET /api/register?question=pet "), "the combobox's first option is picked: {lines:?}");
    assert!(saw("GET /api/feedback?captcha=11&rating=5 "), "the captcha is solved: {lines:?}");
    assert!(saw("GET /api/password?answer=brainproxy "), "the fields opened later are filled: {lines:?}");
    assert!(v["data"]["forms_submitted"].as_u64().unwrap() >= 3, "{v}");
}

#[test]
fn browser_crawl_survives_pages_that_spin_or_tamper() {
    if !browser_available("browser_crawl_survives_pages_that_spin_or_tamper") {
        return;
    }
    let (_dir, project) = test_project("browser-hostile");
    let (port, seen) = serve_spa();
    let at = |p: &str| format!("http://127.0.0.1:{port}{p}");
    let (spin1, spin2, tamper) = (at("/spin1"), at("/spin2"), at("/tamper"));
    let args =
        ["crawl", &spin1, &spin2, &tamper, "--browser", "--depth", "1", "--max-pages", "20", "--max-minutes", "3"];
    let (code, v) = run(&args, &project);
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["tab_restarts"].as_u64().unwrap() >= 1, "a fresh tab replaces the stuck one: {v}");
    let lines = seen.lock().unwrap().clone();
    // The page can't replace the crawler's functions, and the crawl got past the spinning pages.
    assert!(lines.iter().any(|l| l.starts_with("GET /tampered-link ")), "{lines:?}");
}

#[cfg(unix)]
#[test]
fn browser_crawl_removes_its_profile_on_ctrl_c() {
    if !browser_available("browser_crawl_removes_its_profile_on_ctrl_c") {
        return;
    }
    let (dir, project) = test_project("browser-interrupt");
    let (port, _seen) = serve_spa();
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let profiles = || {
        std::fs::read_dir(&tmp)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("brainproxy-browser-"))
            .count()
    };
    let child = bin()
        .args(["--format", "json", "--project"])
        .arg(&project)
        .args(["crawl", &format!("http://127.0.0.1:{port}/spin"), "--browser", "--max-minutes", "3"])
        .env("BRAINPROXY_BROWSER_NO_SANDBOX", "1")
        .env("TMPDIR", &tmp)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while profiles() == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(profiles(), 1, "the crawl made its profile");
    // Time for the crawl to get going, then what Ctrl-C sends.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let sent = Command::new("kill").args(["-INT", &child.id().to_string()]).status().unwrap();
    assert!(sent.success());
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad JSON ({e}): {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    });
    assert_eq!(v["data"]["stopped"], true, "{v}");
    assert_eq!(profiles(), 0, "the profile is gone");
}

#[test]
fn browser_crawl_flags_need_browser() {
    let dir = std::env::temp_dir().join(format!("bp-test-{}-browser-flags", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = bin()
        .args(["--format", "json", "--project"])
        .arg(dir.join("p.bpdb"))
        .args(["crawl", "http://127.0.0.1:1/", "--headful"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("--browser"), "{text}");
}
