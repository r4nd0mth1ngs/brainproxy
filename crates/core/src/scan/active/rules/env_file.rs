//! Ported from ZAP EnvFileScanRule and AbstractAppFilePlugin (ascanrules and
//! commonlib, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40034-1",
    name: ".env Information Leak",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 215,
    wasc: 13,
    description: "One or more .env files seems to have been located on the server. These files often expose \
        infrastructure or administrative account credentials, API or APP keys, or other sensitive configuration \
        information.",
    solution: "Ensure the .env file is not accessible.",
    references: &["https://www.google.com/search?q=db_password+filetype%3Aenv"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CONF-05"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const FILENAME: &str = ".env";
const RESPONSE_LEN_MAX: usize = 500;
static COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^#\s{0,10}\w+").unwrap());
static KEYVAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^\w+=\w+").unwrap());

pub struct EnvFile;

/// AbstractAppFilePlugin.createTestablePath: the file in the request's directory.
pub(crate) fn testable_path(path: &str, filename: &str) -> String {
    if path.contains('/') {
        if path.ends_with('/') {
            format!("{path}{filename}")
        } else {
            format!("{}/{filename}", &path[..path.rfind('/').unwrap_or(0)])
        }
    } else {
        format!("/{filename}")
    }
}

impl ActiveRule for EnvFile {
    fn id(&self) -> u32 {
        40034
    }

    fn name(&self) -> &'static str {
        ".env Information Leak"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let path = testable_path(&cx.base().path, FILENAME);
            if cx.stopped() || !cx.once(&format!("40034|{}{path}", cx.target().origin())) {
                return;
            }
            let Ok(resp) = cx.send(cx.request_for("GET", &path)).await else { return };
            if resp.status != 200 || is_false_positive(&resp) {
                return;
            }
            let finding = ALERT.raise("", resp.status_line.clone());
            cx.report(finding, &resp);
        })
    }
}

fn is_false_positive(resp: &crate::scan::active::Response) -> bool {
    let body = resp.body_str();
    if body.chars().count() > RESPONSE_LEN_MAX {
        return true;
    }
    let ct = resp.content_type();
    let ct = ct.split(';').next().unwrap_or("").trim();
    if ct.is_empty() || ct == "application/octet-stream" {
        return !COMMENT.is_match(body) && !KEYVAL.is_match(body);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testable_paths() {
        assert_eq!(testable_path("/", ".env"), "/.env");
        assert_eq!(testable_path("/app/", ".env"), "/app/.env");
        assert_eq!(testable_path("/app/index.php", ".env"), "/app/.env");
        assert_eq!(testable_path("/index.php", ".env"), "/.env");
        assert_eq!(testable_path("", ".env"), "/.env");
    }
}
