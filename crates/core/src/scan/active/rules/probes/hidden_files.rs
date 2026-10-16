//! Ported from ZAP HiddenFilesScanRule and HexString (ascanrules, Apache License
//! 2.0). The payload list is ZAP's `json/hidden_files.json` (initial set adapted
//! from snallygaster by Hanno Böck), embedded unchanged.

use std::sync::LazyLock;

use serde::Deserialize;

use super::common::{base_path, is_page_200, ComparableResponse};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40035",
    name: "Hidden File Found",
    risk: Risk::Medium,
    confidence: Confidence::High,
    cwe: 538,
    wasc: 13,
    description: "A sensitive file was identified as accessible or available. This may leak administrative, \
        configuration, or credential information which can be leveraged by a malicious individual to further attack \
        the system or conduct social engineering efforts.",
    solution: "Consider whether or not the component is actually required in production, if it isn't then disable \
        it. If it is then ensure access to it requires appropriate authentication and authorization, or limit \
        exposure to internal systems or specific source IPs, etc.",
    references: &[
        "https://blog.hboeck.de/archives/892-Introducing-Snallygaster-a-Tool-to-Scan-for-Secrets-on-Web-Servers.html",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CONF-05"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Source control paths added to the JSON list as custom payloads (ZAP's default
/// payload provider).
const CUSTOM_FILES: [&str; 4] = [".hg", ".bzr", "._darcs", "BitKeeper"];

#[derive(Debug, Default, Deserialize)]
struct HiddenFile {
    path: String,
    #[serde(default)]
    content: Vec<String>,
    #[serde(default)]
    not_content: Vec<String>,
    #[serde(default)]
    binary: String,
    #[serde(default)]
    links: Vec<String>,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    extra: String,
    #[serde(skip)]
    custom: bool,
}

#[derive(Deserialize)]
struct HiddenFiles {
    files: Vec<HiddenFile>,
}

static FILES: LazyLock<Vec<HiddenFile>> = LazyLock::new(|| {
    let mut files = serde_json::from_str::<HiddenFiles>(include_str!("data/hidden_files.json"))
        .map(|f| f.files)
        .unwrap_or_default();
    files.extend(CUSTOM_FILES.iter().map(|p| HiddenFile { path: p.to_string(), custom: true, ..Default::default() }));
    files
});

/// ZAP's generatePath. Note it cuts at the *first* '/', so a non-directory base
/// path always yields a file at the root.
fn generate_path(base_path: &str, hidden: &str) -> String {
    if base_path.contains('/') {
        if base_path.ends_with('/') {
            format!("{base_path}{hidden}")
        } else {
            format!("{}/{hidden}", &base_path[..base_path.find('/').unwrap_or(0)])
        }
    } else {
        format!("{base_path}/{hidden}")
    }
}

/// HexString.compile: `\xHH` becomes that byte, `\\xHH` stays a literal `\xHH`.
fn hex_compile(binary: &str) -> Vec<u8> {
    let b = binary.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let is_hex = |i: usize| b.get(i).is_some_and(u8::is_ascii_hexdigit);
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && b.get(i + 1) == Some(&b'\\')
            && b.get(i + 2) == Some(&b'x')
            && is_hex(i + 3)
            && is_hex(i + 4)
        {
            out.extend_from_slice(&b[i + 1..i + 5]);
            i += 5;
        } else if b[i] == b'\\' && b.get(i + 1) == Some(&b'x') && is_hex(i + 2) && is_hex(i + 3) {
            out.push(u8::from_str_radix(&binary[i + 2..i + 4], 16).unwrap_or(0));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// The file's content checks: none of `not_content` all present, all of
/// `content` present, and the body starting with `binary`.
fn content_matches(file: &HiddenFile, body: &[u8], text: &str) -> bool {
    let all = |list: &[String]| list.iter().all(|s| text.contains(s.as_str()));
    let not_content_ok = file.not_content.is_empty() || !all(&file.not_content);
    not_content_ok && all(&file.content) && body.starts_with(&hex_compile(&file.binary))
}

fn other_info(file: &HiddenFile) -> String {
    let mut s = file.kind.clone();
    if !file.extra.trim().is_empty() {
        s.push_str("\n\n");
        s.push_str(&file.extra);
    }
    // brainproxy findings have no per-instance references: the file's links go here.
    if !file.links.is_empty() {
        if !s.is_empty() {
            s.push_str("\n\n");
        }
        s.push_str("References:\n");
        s.push_str(&file.links.join("\n"));
    }
    s
}

/// A pseudo-random positive number for the paths that should not exist.
fn rnd() -> u64 {
    crate::scan::active::rand_u64() >> 1
}

pub struct HiddenFilesRule;

impl HiddenFilesRule {
    async fn request(cx: &Cx, base: &str, path: &str) -> Option<Response> {
        cx.send(cx.request_for("GET", &generate_path(base, path))).await.ok()
    }
}

impl ActiveRule for HiddenFilesRule {
    fn id(&self) -> u32 {
        40035
    }

    fn name(&self) -> &'static str {
        "Hidden File Finder"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Host
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let base = base_path(cx);
            let Some(missing) = Self::request(cx, &base, &format!("zap{}", rnd())).await else { return };
            let Some(missing_dot) = Self::request(cx, &base, &format!(".zap{}", rnd())).await else { return };
            let missing = ComparableResponse::from_response(&missing, "");
            let missing_dot = ComparableResponse::from_response(&missing_dot, "");
            for file in FILES.iter() {
                if cx.stopped() {
                    return;
                }
                let Some(resp) = Self::request(cx, &base, &file.path).await else { continue };
                // 401/403 alerts are LOW-threshold only.
                if !is_page_200(cx, &resp).await {
                    continue;
                }
                let reference = if file.path.starts_with('.') { &missing_dot } else { &missing };
                if ComparableResponse::from_response(&resp, "").compare_with(reference) >= 0.9 {
                    // Essentially the same response as for a file that really doesn't exist.
                    continue;
                }
                let confidence = if file.custom {
                    Confidence::Low
                } else if content_matches(file, &resp.body, resp.body_str()) {
                    Confidence::High
                } else {
                    continue;
                };
                let finding =
                    ALERT.raise("", resp.status_line.clone()).confidence(confidence).other_info(other_info(file));
                cx.report(finding, &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_payloads() {
        assert_eq!(FILES.len(), 46 + 4);
        let git = FILES.iter().find(|f| f.path == ".git/config").unwrap();
        assert_eq!(git.content, vec!["[core]"]);
        assert_eq!(git.kind, "git_dir");
        assert!(FILES.iter().any(|f| !f.extra.is_empty()));
        assert!(FILES.iter().filter(|f| f.custom).all(|f| CUSTOM_FILES.contains(&f.path.as_str())));
    }

    #[test]
    fn paths() {
        assert_eq!(generate_path("/", ".git/config"), "/.git/config");
        assert_eq!(generate_path("/app/", ".git/config"), "/app/.git/config");
        assert_eq!(generate_path("/app/index.php", ".git/config"), "/.git/config");
        assert_eq!(generate_path("", ".hg"), "/.hg");
    }

    #[test]
    fn hex() {
        assert_eq!(hex_compile("\\x7fELF"), b"\x7fELF");
        assert_eq!(hex_compile("\\x00\\x00\\x00\\x01Bud1"), b"\0\0\0\x01Bud1");
        assert_eq!(hex_compile("\\\\x41"), b"\\x41");
        assert_eq!(hex_compile("SQLite format"), b"SQLite format");
        assert_eq!(hex_compile(""), b"");
    }

    #[test]
    fn content_checks() {
        let cvs = FILES.iter().find(|f| f.path == "CVS/root").unwrap();
        assert!(content_matches(cvs, b":pserver:anon@cvs", ":pserver:anon@cvs"));
        assert!(!content_matches(cvs, b"<html>:</html>", "<html>:</html>"));
        let core = FILES.iter().find(|f| f.path == "core").unwrap();
        assert!(content_matches(core, b"\x7fELF\x02\x01", "\u{7f}ELF"));
        assert!(!content_matches(core, b"ELF", "ELF"));
        let git = FILES.iter().find(|f| f.path == ".git/config").unwrap();
        assert!(!content_matches(git, b"<html>Welcome</html>", "<html>Welcome</html>"));
    }

    #[test]
    fn other_infos() {
        let f = HiddenFile { kind: "git_dir".into(), links: vec!["https://x".into()], ..Default::default() };
        assert_eq!(other_info(&f), "git_dir\n\nReferences:\nhttps://x");
        let f = HiddenFile { kind: "t".into(), extra: "more".into(), ..Default::default() };
        assert_eq!(other_info(&f), "t\n\nmore");
    }
}
