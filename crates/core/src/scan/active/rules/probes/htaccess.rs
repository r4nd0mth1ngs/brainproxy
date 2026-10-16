//! Ported from ZAP HtAccessScanRule and commonlib AbstractAppFilePlugin
//! (ascanrules and commonlib, Apache License 2.0).

use super::common::{app_file_probe, has_html_element, is_text_type};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40032-1",
    name: ".htaccess Information Leak",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 94,
    wasc: 14,
    description: "htaccess files can be used to alter the configuration of the Apache Web Server software to \
        enable/disable additional functionality and features that the Apache Web Server software has to offer.",
    solution: "Ensure the .htaccess file is not accessible.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Server-side/Apache_Configuration_htaccess",
        "https://httpd.apache.org/docs/2.4/howto/htaccess.html",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CONF-05"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const FILENAME: &str = ".htaccess";
const TEN_K: usize = 10 * 1024;
const COMMON_DIRECTIVES: [&str; 12] = [
    "addtype",
    "allow",
    "deny",
    "errordocument",
    "files",
    "limit",
    "options",
    "order",
    "redirect",
    "require",
    "rewritecond",
    "rewriterule",
];

fn is_false_positive(resp: &Response) -> bool {
    let body = resp.body_str();
    if resp.body.is_empty() {
        return true;
    }
    let ct = resp.content_type();
    if !is_text_type(&ct) || ct.contains("xml") || ct.contains("json") {
        return true;
    }
    if has_html_element(body) {
        return true;
    }
    !has_directive(body)
}

/// A common directive at the start of a line (followed by whitespace) in the first 10k.
fn has_directive(body: &str) -> bool {
    let body10k: String = body.chars().take(TEN_K).collect::<String>().to_lowercase();
    if !COMMON_DIRECTIVES.iter().any(|d| body10k.contains(d)) {
        return false;
    }
    body10k.split('\n').any(|line| {
        let line = line.trim();
        COMMON_DIRECTIVES
            .iter()
            .any(|d| line.starts_with(d) && line[d.len()..].chars().next().is_some_and(char::is_whitespace))
    })
}

pub struct HtAccess;

impl ActiveRule for HtAccess {
    fn id(&self) -> u32 {
        40032
    }

    fn name(&self) -> &'static str {
        ".htaccess Information Leak"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let Some(resp) = app_file_probe(cx, 40032, FILENAME).await else { return };
            if !is_false_positive(&resp) {
                cx.report(ALERT.raise("", resp.status_line.clone()), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directives() {
        assert!(has_directive("# comment\nOptions -Indexes\n"));
        assert!(has_directive("  RewriteRule ^(.*)$ index.php [L]"));
        assert!(has_directive("<Files .env>\n\tOrder allow,deny\n\tDeny from all\n</Files>"));
        assert!(!has_directive("Options"), "a directive needs whitespace after it");
        assert!(!has_directive("this page explains the allowed options"));
        assert!(!has_directive("hello world"));
    }
}
