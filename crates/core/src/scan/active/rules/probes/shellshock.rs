//! Ported from ZAP ShellShockScanRule (ascanrules, Apache License 2.0).
//!
//! The reflected (`-1`) and timing (`-2`) attacks are ported. ZAP has no
//! callback/OAST variant for this rule, so nothing OAST-only is omitted. The
//! sleep time is ZAP's default (5s); brainproxy has no rule-config override.

use super::common::check_timing_dependence;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static REFLECTED: AlertDef = AlertDef {
    alert_ref: "10048-1",
    name: "Remote Code Execution - Shell Shock",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 78,
    wasc: 31,
    description: "The server is running a version of the Bash shell that allows remote attackers to execute arbitrary \
        code.",
    solution: "Update Bash on the server to the latest version.",
    references: &[
        "https://nvd.nist.gov/vuln/detail/cve-2014-6271",
        "https://www.troyhunt.com/everything-you-need-to-know-about2/",
    ],
    tags: &["OWASP_2025_A03", "OWASP_2025_A05", "OWASP_2021_A06", "OWASP_2017_A09", "WSTG-v42-INPV-12"],
};

static TIMING: AlertDef = AlertDef {
    alert_ref: "10048-2",
    name: "Remote Code Execution - Shell Shock",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 78,
    wasc: 31,
    description: REFLECTED.description,
    solution: REFLECTED.solution,
    references: REFLECTED.references,
    // The timing alert carries TEST_TIMING; the reflected one does not.
    tags: &["OWASP_2025_A03", "OWASP_2025_A05", "OWASP_2021_A06", "OWASP_2017_A09", "WSTG-v42-INPV-12", "TEST_TIMING"],
};

static ALERTS: [&AlertDef; 2] = [&REFLECTED, &TIMING];

const ATTACK_HEADER: &str = "X-Powered-By";
const EVIDENCE: &str = "ShellShock-Vulnerable";
const EXTRA_INFO: &str = "From CVE-2014-6271: GNU Bash through 4.3 processes trailing strings after function \
    definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via \
    a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the \
    mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other \
    situations in which setting the environment occurs across a privilege boundary from Bash execution, aka \
    \"ShellShock.\" NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the \
    vulnerability that is still present after the incorrect fix.";

const DEFAULT_SLEEP_TIME: u32 = 5;
const BLIND_REQUESTS_LIMIT: usize = 4;
const TIME_CORRELATION_ERROR_RANGE: f64 = 0.15;
const TIME_SLOPE_ERROR_RANGE: f64 = 0.30;

fn reflected_attack() -> String {
    format!("() {{ :;}}; echo '{ATTACK_HEADER}: {EVIDENCE}'")
}

fn timing_attack(seconds: u32) -> String {
    format!("() {{ :;}}; /bin/sleep {seconds}")
}

fn timing_evidence(elapsed_ms: u128) -> String {
    format!("Using the attack, a delay of [{elapsed_ms}] milliseconds was induced and detected")
}

pub struct ShellShock;

impl ActiveRule for ShellShock {
    fn id(&self) -> u32 {
        10048
    }

    fn name(&self) -> &'static str {
        "Remote Code Execution - Shell Shock"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.stopped() {
                return;
            }
            let param = cx.point().name.clone();

            // 1) Reflected attack: CGI echoes the evidence into a response header.
            let attack1 = reflected_attack();
            if let Ok(resp) = cx.send_payload(&attack1).await {
                if resp.headers_named(ATTACK_HEADER).any(|v| v.contains(EVIDENCE)) {
                    let finding =
                        REFLECTED.raise(param.clone(), EVIDENCE).attack(attack1.clone()).other_info(EXTRA_INFO);
                    cx.report(finding, &resp);
                    return;
                }
            }

            // 2) Timing attack: PHP evidence shows up as a delay.
            if cx.stopped() {
                return;
            }
            let last: std::sync::Mutex<Option<(crate::scan::active::Response, String)>> = std::sync::Mutex::new(None);
            let vulnerable = check_timing_dependence(
                BLIND_REQUESTS_LIMIT,
                DEFAULT_SLEEP_TIME,
                |delay| {
                    let attack = timing_attack(delay);
                    let last = &last;
                    async move {
                        let resp = cx.send_payload(&attack).await.ok()?;
                        let secs = resp.duration.as_secs_f64();
                        *last.lock().unwrap() = Some((resp, attack));
                        Some(secs)
                    }
                },
                TIME_CORRELATION_ERROR_RANGE,
                TIME_SLOPE_ERROR_RANGE,
            )
            .await;

            if vulnerable {
                if let Some((resp, attack)) = last.into_inner().unwrap() {
                    let finding = TIMING
                        .raise(param, timing_evidence(resp.duration.as_millis()))
                        .attack(attack)
                        .other_info(EXTRA_INFO);
                    cx.report(finding, &resp);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attacks() {
        assert_eq!(reflected_attack(), "() { :;}; echo 'X-Powered-By: ShellShock-Vulnerable'");
        assert_eq!(timing_attack(5), "() { :;}; /bin/sleep 5");
        assert_eq!(timing_evidence(6003), "Using the attack, a delay of [6003] milliseconds was induced and detected");
    }
}
