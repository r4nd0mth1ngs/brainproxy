//! Ported from ZAP SourceCodeDisclosureCve20121823ScanRule (ascanrules, Apache
//! License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use super::common::{base_path, fresh_request, is_text_type, render_html_text};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "20017",
    name: "Source Code Disclosure - CVE-2012-1823",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 20,
    wasc: 20,
    description:
        "Some PHP versions, when configured to run using CGI, do not correctly handle query strings that lack \
        an unescaped \"=\" character, enabling PHP source code disclosure, and arbitrary code execution. In this case, \
        the contents of the PHP file were served directly to the web browser. This output will typically contain PHP, \
        although it may also contain straight HTML.",
    solution:
        "Upgrade to the latest stable version of PHP, or use the Apache web server and the mod_rewrite module to \
        filter out malicious requests using the \"RewriteCond\" and \"RewriteRule\" directives.",
    references: &[
        "https://owasp.org/www-community/vulnerabilities/Improper_Data_Validation",
        "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/89.html",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A06", "OWASP_2017_A09", "CVE-2012-1823"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const ATTACK_PARAM: &str = "?-s";

// Rust's regex has no DOTALL-across-`.*` with `matches()` semantics, so we use
// `(?s)` for dotall and anchor the whole string; the capture is the tag itself.
static PHP_STANDARD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)^.*(<\?php.+?\?>).*$").unwrap());
static PHP_SHORT_ECHO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)^.*(<\?=.+?\?>).*$").unwrap());

/// The disclosed PHP tag found in the rendered body, if any.
fn php_tag(rendered: &str) -> Option<String> {
    if let Some(c) = PHP_STANDARD.captures(rendered) {
        return Some(c[1].to_string());
    }
    PHP_SHORT_ECHO.captures(rendered).map(|c| c[1].to_string())
}

/// Response contains non-whitespace control characters (ZAP responseContainsControlChars).
fn contains_control_chars(body: &str) -> bool {
    body.chars().filter(|c| !c.is_whitespace()).any(|c| c.is_control())
}

/// Whether the path looks like JavaScript (ZAP ResourceIdentificationUtils).
fn is_javascript(cx: &Cx) -> bool {
    let ct = cx.base_response().content_type();
    if ct.contains("javascript") || ct.contains("ecmascript") {
        return true;
    }
    let p = cx.base().path.to_ascii_lowercase();
    p.ends_with(".js") || p.ends_with(".jsx")
}

pub struct SourceDisclosureCve20121823;

impl SourceDisclosureCve20121823 {
    /// True when the original response already contains PHP tags (ZAP skips then).
    fn evidence_in_original(cx: &Cx) -> bool {
        php_tag(&render_html_text(cx.base_response().body_str())).is_some()
    }

    async fn matches(cx: &Cx, resp: &Response) -> Option<String> {
        // isPage200
        if resp.status != 200 || cx.not_found(resp).await {
            return None;
        }
        let body = resp.body_str();
        let rendered = render_html_text(body);
        // The rendering must have changed something (ZAP: !responseBody.equals(decoded)).
        if rendered == body {
            return None;
        }
        php_tag(&rendered)
    }
}

impl ActiveRule for SourceDisclosureCve20121823 {
    fn id(&self) -> u32 {
        20017
    }

    fn name(&self) -> &'static str {
        "Source Code Disclosure - CVE-2012-1823"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            // Judged as the attack's response will be: after the scan's response rules.
            let base = cx.base_response();
            if !is_text_type(&base.content_type()) || contains_control_chars(base.body_str()) {
                return; // Ignore images, pdfs, etc.
            }
            // At MEDIUM threshold, skip JavaScript resources.
            if is_javascript(cx) || Self::evidence_in_original(cx) {
                return;
            }
            // At LOW/MEDIUM strength, do not attack URLs that returned "Not Found".
            if cx.not_found(cx.base_response()).await || cx.stopped() {
                return;
            }
            let target = format!("{}{ATTACK_PARAM}", base_path(cx));
            let Ok(resp) = cx.send(fresh_request(cx, "GET", &target, &[])).await else { return };
            if let Some(source) = Self::matches(cx, &resp).await {
                cx.report(ALERT.raise("", source.clone()).other_info(source), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_php_tags() {
        assert_eq!(php_tag("junk <?php echo 1; ?> more"), Some("<?php echo 1; ?>".into()));
        assert_eq!(php_tag("x <?= $y ?> z"), Some("<?= $y ?>".into()));
        assert_eq!(php_tag("<html>no php here</html>"), None);
        assert_eq!(php_tag("<?php $a=1;\n$b=2; ?>"), Some("<?php $a=1;\n$b=2; ?>".into()));
    }

    #[test]
    fn control_chars() {
        assert!(contains_control_chars("abc\u{0}def"));
        assert!(!contains_control_chars("line1\nline2\tend"));
    }

    /// The page is judged a text one, or not, as the scan reads it: after its response rules.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_page_is_judged_after_the_scans_response_rules() {
        use crate::rules::{Engine, Rule, RuleAction, RuleLocation};
        fn cgi(target: &str) -> String {
            let (status, body) = match target {
                "/" => ("200 OK", "<p>Hello</p>"),
                "/?-s" => ("200 OK", "<code>&lt;?php echo $secret; ?&gt;</code>"),
                _ => ("404 Not Found", "nope"),
            };
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/x-httpd-php\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        }
        let s = super::super::common::scan_page(20017, vec![], cgi).await;
        assert_eq!((s.requests, s.new_findings), (0, 0), "{s:?}");
        let html = Rule {
            name: Some("Content-Type".into()),
            action: Some(RuleAction::Set),
            applies_to: vec![Engine::Scan],
            ..Rule::new(1, RuleLocation::ResponseHeader, "", "text/html")
        };
        let s = super::super::common::scan_page(20017, vec![html], cgi).await;
        assert_eq!(s.raised.get("20017"), Some(&1), "{s:?}");
    }
}
