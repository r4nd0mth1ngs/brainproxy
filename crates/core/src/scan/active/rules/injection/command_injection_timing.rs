//! Ported from ZAP CommandInjectionTimingScanRule (ascanrules, Apache License 2.0).

use std::sync::LazyLock;

use super::command_injection::{DESCRIPTION, REFERENCES, SOLUTION};
use super::common::{by_strength, insert_uninit_var, java_double, point};
use super::timing::{check_timing, sleep_seconds, whole_seconds, TimingOutcome};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90037",
    name: "Remote OS Command Injection (Time Based)",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 78,
    wasc: 31,
    description: DESCRIPTION,
    solution: SOLUTION,
    references: REFERENCES,
    tags: &[
        "OWASP_2025_A05",
        "OWASP_2021_A03",
        "OWASP_2017_A01",
        "WSTG-v42-INPV-12",
        "API_2023_API10",
        "HIPAA",
        "PCI_DSS",
        "TEST_TIMING",
    ],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const NIX_BLIND_TEST_CMD: &str = "sleep {0}";
const WIN_BLIND_TEST_CMD: &str = "timeout /T {0}";
const PS_BLIND_TEST_CMD: &str = "start-sleep -s {0}";

static NIX_PAYLOADS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let c = NIX_BLIND_TEST_CMD;
    let v = insert_uninit_var(c);
    let mut p = vec![
        format!("&{c}&"),
        format!(";{c};"),
        format!("\"&{c}&\""),
        format!("\";{c};\""),
        format!("'&{c}&'"),
        format!("';{c};'"),
        format!("\n{c}\n"), // force enter
        format!("`{c}`"),   // backtick execution
        format!("||{c}"),   // or control concatenation
        format!("&&{c}"),   // and control concatenation
        format!("|{c}#"),   // pipe & comment
    ];
    // Uninitialized variable WAF bypass.
    p.extend([
        format!("&{v}&"),
        format!(";{v};"),
        format!("\"&{v}&\""),
        format!("\";{v};\""),
        format!("'&{v}&'"),
        format!("';{v};'"),
        format!("\n{v}\n"),
        format!("`{v}`"),
        format!("||{v}"),
        format!("&&{v}"),
        format!("|{v}#"),
    ]);
    p
});

static WIN_PAYLOADS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let c = WIN_BLIND_TEST_CMD;
    vec![
        format!("&{c}"),
        format!("|{c}"),
        format!("\"&{c}&\""),
        format!("\"|{c}"),
        format!("'&{c}&'"),
        format!("'|{c}"),
        format!("run {c}"), // FoxPro for running os commands
    ]
});

static PS_PAYLOADS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let c = PS_BLIND_TEST_CMD;
    vec![format!(";{c}"), format!("\";{c}"), format!("';{c}"), format!(";{c} #")]
});

/// `ascanrules.commandinjection.time.otherinfo`.
fn other_info(attack: &str) -> String {
    format!(
        "The scan rule was able to control the timing of the application response by sending [{attack}] to the \
         operating system running this application."
    )
}

/// The value sent for a requested delay. ZAP formats the delay as a Java double
/// (`sleep 5.0`); the reported attack uses the configured integer sleep.
fn payload_for(value: &str, template: &str, delay: f64) -> String {
    format!("{value}{}", template.replace("{0}", &java_double(delay)))
}

pub struct CommandInjectionTiming;

impl ActiveRule for CommandInjectionTiming {
    fn id(&self) -> u32 {
        90037
    }

    fn name(&self) -> &'static str {
        "Remote OS Command Injection (Time Based)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let max = PS_PAYLOADS.len().max(NIX_PAYLOADS.len()).max(WIN_PAYLOADS.len());
            let target_count = by_strength(cx.strength(), [2, 6, 12, max]);
            for payloads in [&*NIX_PAYLOADS, &*WIN_PAYLOADS, &*PS_PAYLOADS] {
                if cx.stopped() || test_injection(cx, target_count, payloads).await {
                    return;
                }
            }
        })
    }
}

async fn test_injection(cx: &Cx, target_count: usize, payloads: &[String]) -> bool {
    let (param, value) = point(cx);
    let sleep = sleep_seconds();
    for template in payloads.iter().take(target_count) {
        let attack = format!("{value}{}", template.replace("{0}", &sleep.to_string()));
        let outcome = check_timing(cx, sleep, |x| payload_for(&value, template, x), whole_seconds).await;
        if let TimingOutcome::Injectable(t) = outcome {
            // ZAP attaches the alert to the last message sent.
            let finding = ALERT.raise(param, "").attack(attack.clone()).other_info(other_info(&attack));
            cx.report(finding, &t.last);
            return true;
        }
        if cx.stopped() {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_lists() {
        assert_eq!((NIX_PAYLOADS.len(), WIN_PAYLOADS.len(), PS_PAYLOADS.len()), (22, 7, 4));
        assert_eq!(payload_for("a", &NIX_PAYLOADS[1], 5.0), "a;sleep 5.0;");
        assert_eq!(payload_for("", &WIN_PAYLOADS[6], 1.0), "run timeout /T 1.0");
        assert_eq!(payload_for("x", &PS_PAYLOADS[3], 5.0), "x;start-sleep -s 5.0 #");
        assert!(NIX_PAYLOADS[11].starts_with("&sleep$") && NIX_PAYLOADS[11].ends_with(" {0}&"));
    }

    #[test]
    fn texts() {
        assert_eq!(
            other_info("sleep 5"),
            "The scan rule was able to control the timing of the application response by sending [sleep 5] to the \
             operating system running this application."
        );
    }
}
