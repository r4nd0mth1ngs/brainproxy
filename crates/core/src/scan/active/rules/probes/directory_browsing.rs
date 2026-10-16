//! Ported from ZAP DirectoryBrowsingScanRule (ascanrules, Apache License 2.0).
//!
//! brainproxy has no technology filter, so every technology is "in scope" and the
//! IIS and Apache/Tomcat patterns are always tried first, as ZAP does by default.

use std::sync::LazyLock;

use regex::Regex;

use super::common::{base_path, is_page_200, with_request_line};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "0",
    name: "Directory Browsing",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 548,
    wasc: 48,
    description: "It is possible to view the directory listing. Directory listing may reveal hidden scripts, include \
        files, backup source files, etc. which can be accessed to read sensitive information.",
    solution: "Disable directory browsing. If this is required, make sure the listed files does not induce risks.",
    references: &["https://httpd.apache.org/docs/current/mod/core.html#options"],
    tags: &["API_2023_API8", "OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

static IIS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)Parent Directory").unwrap());
static APACHE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)\bDirectory Listing\b.*(Tomcat|Apache)").unwrap());
static GENERAL_DIR1: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)\bDirectory\b").unwrap());
static GENERAL_DIR2: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)[\s<]+IMG\s*=").unwrap());
static GENERAL_PARENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)Parent directory").unwrap());

/// checkIfDirectory: the path without query, with a trailing slash.
fn directory_path(path: &str) -> String {
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    }
}

/// The listing evidence and confidence, if the body looks like a directory listing.
fn detect(body: &str) -> Option<(String, Confidence)> {
    if let Some(m) = IIS.find(body) {
        return Some((m.as_str().to_string(), Confidence::Medium));
    }
    if let Some(m) = APACHE.find(body) {
        return Some((m.as_str().to_string(), Confidence::Medium));
    }
    if let Some(m) = GENERAL_PARENT.find(body) {
        return Some((m.as_str().to_string(), Confidence::Low));
    }
    if let Some(m) = GENERAL_DIR1.find(body) {
        if GENERAL_DIR2.is_match(body) {
            return Some((m.as_str().to_string(), Confidence::Low));
        }
    }
    None
}

pub struct DirectoryBrowsing;

impl ActiveRule for DirectoryBrowsing {
    fn id(&self) -> u32 {
        0
    }

    fn name(&self) -> &'static str {
        "Directory Browsing"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let dir = directory_path(&base_path(cx));
            let method = cx.base().method.clone();
            if cx.stopped() || !cx.once(&format!("0|{}|{method}|{dir}", cx.target().origin())) {
                return;
            }
            let Ok(resp) = cx.send_following(with_request_line(cx.base_request(), &method, &dir)).await else {
                return;
            };
            if !is_page_200(cx, &resp).await {
                return;
            }
            if let Some((evidence, confidence)) = detect(resp.body_str()) {
                let attack = format!("{}{dir}", cx.target().origin());
                cx.report(ALERT.raise("", evidence).attack(attack).confidence(confidence), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_paths() {
        assert_eq!(directory_path("/"), "/");
        assert_eq!(directory_path("/uploads"), "/uploads/");
        assert_eq!(directory_path("/a/index.php"), "/a/index.php/");
    }

    #[test]
    fn detects_listings() {
        let apache = "<title>Index of /x</title><a href=\"/\">Parent Directory</a>";
        assert_eq!(detect(apache), Some(("Parent Directory".into(), Confidence::Medium)));
        let tomcat = "<h1>Directory Listing For [/]</h1>\n<hr><p>Apache Tomcat/9</p>";
        assert_eq!(detect(tomcat), None, "the Apache pattern is single-line, as in ZAP");
        let tomcat = "<h1>Directory Listing For [/]</h1> Apache Tomcat/9";
        assert_eq!(detect(tomcat).unwrap().1, Confidence::Medium);
        let generic = "<h2>Directory of /files</h2><IMG SRC=\"/icons/folder.gif\">";
        assert_eq!(detect("<p>Directory</p> <img = x>").unwrap().1, Confidence::Low);
        assert_eq!(detect(generic), None, "needs `IMG =`");
        assert_eq!(detect("<p>Welcome to the company directory service</p>"), None);
    }
}
