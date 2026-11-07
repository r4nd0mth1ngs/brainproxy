//! End-to-end tests for report layouts: CVSS on issues, presets, branding, saved profiles,
//! DOCX, and PDF where a browser can run.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 8192];
            let mut req = Vec::new();
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let k = s.read(&mut buf).unwrap_or(0);
                if k == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..k]);
            }
            let body = "<html><body>hi</body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: Express\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

fn run(project: &Path, args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .env_remove("BRAINPROXY_PROJECT")
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn ok(project: &Path, args: &[&str]) -> Value {
    let (code, v) = run(project, args);
    assert_eq!(code, 0, "{args:?}: {v}");
    v["data"].clone()
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-layout-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    ok(&project, &["engagement", "start", "--target", "127.0.0.1"]);
    (dir, project)
}

#[test]
fn layouts_profiles_cvss_and_word() {
    let port = serve();
    let (dir, project) = setup("all");
    ok(&project, &["send", "--url", &format!("http://127.0.0.1:{port}/a")]);
    let path = |n: &str| dir.join(n).to_str().unwrap().to_string();
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();

    // Rate the header issue; the report shows it and SARIF scores by it.
    let issues = ok(&project, &["findings", "issues"]);
    let issue =
        issues["issues"].as_array().unwrap().iter().find(|i| i["alert_ref"] == "10037").unwrap()["id"].to_string();
    let rated = ok(
        &project,
        &["findings", "issue", "cvss", &issue, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"],
    );
    assert_eq!(
        (rated["cvss"]["score"].as_f64(), rated["cvss"]["severity"].as_str()),
        (Some(6.9), Some("medium")),
        "{rated}"
    );
    let (code, v) = run(&project, &["findings", "issue", "cvss", &issue, "CVSS:3.1/AV:N/AC:L"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");

    // Executive, branded, with a logo.
    std::fs::write(dir.join("logo.png"), b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").unwrap();
    let r = ok(
        &project,
        &[
            "report",
            "html",
            "--preset",
            "executive",
            "--company",
            "Acme",
            "--accent",
            "#112233",
            "--logo",
            &path("logo.png"),
            "--output",
            &path("exec.html"),
        ],
    );
    assert_eq!(r["preset"], "executive");
    let html = read("exec.html");
    assert!(
        html.contains("Security assessment by Acme")
            && html.contains("<h2>Posture</h2>")
            && html.contains("data:image/png;base64,")
    );
    assert!(!html.contains("Technical details"));
    let (code, v) = run(&project, &["report", "html", "--accent", "red"]);
    assert_eq!(code, 2, "{v}");
    std::fs::write(dir.join("logo.svg"), b"<svg onload=alert(1)/>").unwrap();
    let (code, v) = run(&project, &["report", "html", "--logo", &path("logo.svg")]);
    assert_eq!(code, 2, "{v}");

    // A saved profile, with flags over it.
    ok(&project, &["report-profile", "save", "dev", "--preset", "developer", "--company", "Acme"]);
    assert_eq!(ok(&project, &["report-profile", "list"])["profiles"][0]["name"], "dev");
    ok(&project, &["report", "markdown", "--profile", "dev", "--output", &path("dev.md")]);
    let md = read("dev.md");
    assert!(
        md.contains("Security assessment by Acme")
            && md.contains("### How to reproduce")
            && md.contains("CVSS 4.0:** 6.9")
    );
    ok(
        &project,
        &["report", "markdown", "--profile", "dev", "--sections", "list", "--output", &path("list.md"), "--force"],
    );
    assert!(!read("list.md").contains("How to reproduce"));
    let (code, _) = run(&project, &["report", "html", "--profile", "nope"]);
    assert_eq!(code, 4);
    // Saved on top of another, a logo stays; an empty flag clears what the profile has.
    ok(&project, &["report-profile", "save", "brand", "--company", "Acme", "--logo", &path("logo.png")]);
    let copy = ok(&project, &["report-profile", "save", "brand2", "--from", "brand", "--preset", "executive"]);
    assert!(copy["layout"]["logo"].as_str().unwrap().ends_with("bytes"), "{copy}");
    ok(&project, &["report", "html", "--profile", "brand2", "--company=", "--output", &path("plain.html")]);
    let plain = read("plain.html");
    assert!(!plain.contains("Security assessment by") && plain.contains("data:image/png;base64,"));
    // So does --logo= (and --logo "", which the app sends for "No logo").
    let bare = ok(&project, &["report-profile", "save", "brand3", "--from", "brand2", "--logo="]);
    assert!(bare["layout"]["logo"].is_null(), "{bare}");
    ok(&project, &["report", "html", "--profile", "brand2", "--logo", "", "--output", &path("nologo.html")]);
    assert!(!read("nologo.html").contains("data:image/png;base64,"));
    ok(&project, &["report-profile", "remove", "dev"]);

    // Word: a zip holding the document; binary formats need a file.
    ok(&project, &["report", "docx", "--output", &path("r.docx")]);
    let docx = std::fs::read(dir.join("r.docx")).unwrap();
    assert!(docx.starts_with(b"PK\x03\x04") && docx.windows(17).any(|w| w == b"word/document.xml"));
    let (code, v) = run(&project, &["report", "docx"]);
    assert_eq!(code, 2, "{v}");

    // PDF where a browser starts here; otherwise a clear error, not a crash.
    let (code, v) = run(&project, &["report", "pdf", "--output", &path("r.pdf")]);
    if code == 0 {
        assert!(std::fs::read(dir.join("r.pdf")).unwrap().starts_with(b"%PDF"));
    } else {
        eprintln!("no PDF here: {v}");
        assert!(v["error"]["message"].is_string(), "{v}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
