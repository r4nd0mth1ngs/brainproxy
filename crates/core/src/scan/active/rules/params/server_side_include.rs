//! Ported from ZAP ServerSideIncludeScanRule (ascanrules, Apache License 2.0).
//!
//! Unix and Windows checks both run (no technology filter in brainproxy).

use std::sync::LazyLock;

use regex::Regex;

use super::common;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40009",
    name: "Server Side Include",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 97,
    wasc: 31,
    description: "Certain parameters may cause Server Side Include commands to be executed. This may allow database connection or \
        arbitrary code to be executed.",
    solution: "Do not trust client side input and enforce a tight check in the server side. Disable server side \
        includes.\nRefer to manual to disable Sever Side Include.\nUse least privilege to run your web server or \
        application server.\nFor Apache, disable the following:\nOptions Indexes FollowSymLinks Includes\nAddType \
        application/x-httpd-cgi .cgi\nAddType text/x-server-parsed-html .html.",
    references: &[
        "https://httpd.apache.org/docs/current/howto/ssi.html",
    ],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-11"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const SSI_UNIX: &str = "<!--#EXEC cmd=\"ls /\"-->";
const SSI_UNIX2: &str = "\"><!--#EXEC cmd=\"ls /\"--><";
const SSI_WIN: &str = "<!--#EXEC cmd=\"dir \\\"-->";
const SSI_WIN2: &str = "\"><!--#EXEC cmd=\"dir \\\"--><";

// PATTERN_PARAM is CASE_INSENSITIVE | MULTILINE, plus DOTALL here.
static UNIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?ims)\broot\b.*\busr\b").unwrap());
static WIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?ims)\bprogram files\b.*\b(WINDOWS|WINNT)\b").unwrap());

pub struct ServerSideInclude;

impl ActiveRule for ServerSideInclude {
    fn id(&self) -> u32 {
        40009
    }

    fn name(&self) -> &'static str {
        "Server Side Include"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let original = cx.base_response().body_str();
            for (pattern, payloads) in [(&*UNIX, [SSI_UNIX, SSI_UNIX2]), (&*WIN, [SSI_WIN, SSI_WIN2])] {
                // Pre-check the original response for the pattern (to avoid false positives).
                if pattern.is_match(original) {
                    continue;
                }
                for payload in payloads {
                    if cx.stopped() {
                        return;
                    }
                    let Ok(resp) = common::send_following(cx, payload).await else { continue };
                    if let Some(m) = pattern.find(resp.body_str()) {
                        let f = ALERT.raise(cx.point().name.clone(), m.as_str()).attack(payload);
                        cx.report(f, &resp);
                        return;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_patterns() {
        assert_eq!(UNIX.find("bin\nROOT\nsbin\nusr\nvar").unwrap().as_str(), "ROOT\nsbin\nusr");
        assert!(!UNIX.is_match("rootusr"));
        assert!(WIN.is_match("Program Files\r\nUsers\r\nWindows"));
        assert!(!WIN.is_match("Program Files\r\nUsers"));
        assert_eq!(SSI_WIN, r#"<!--#EXEC cmd="dir \"-->"#);
    }
}
