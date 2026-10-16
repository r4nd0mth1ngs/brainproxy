//! Ported from ZAP CodeInjectionScanRule (ascanrules, Apache License 2.0).

use super::common::point;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

const DESCRIPTION: &str =
    "A code injection may be possible including custom code that will be evaluated by the scripting engine.";
const SOLUTION: &str = "Do not trust client side input, even if there is client side validation in place.\n\
    In general, type check all data on the server side and escape all data received from the client.\n\
    Avoid the use of eval() functions combined with user input data.";
const REFERENCES: &[&str] = &[
    "https://cwe.mitre.org/data/definitions/94.html",
    "https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval%20Injection",
];
const TAGS: &[&str] =
    &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-11", "API_2023_API10", "HIPAA", "PCI_DSS"];

static PHP_ALERT: AlertDef = AlertDef {
    alert_ref: "90019-1",
    name: "Server Side Code Injection - PHP Code Injection",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 94,
    wasc: 20,
    description: DESCRIPTION,
    solution: SOLUTION,
    references: REFERENCES,
    tags: TAGS,
};

static ASP_ALERT: AlertDef = AlertDef {
    alert_ref: "90019-2",
    name: "Server Side Code Injection - ASP Code Injection",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 94,
    wasc: 20,
    description: DESCRIPTION,
    solution: SOLUTION,
    references: REFERENCES,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 2] = [&PHP_ALERT, &ASP_ALERT];

/// Printed by the PHP payloads, which build it from `chr()` calls so a plain
/// reflection of the payload doesn't match.
const PHP_CONTROL_TOKEN: &str = "zap_token";

macro_rules! php_token {
    () => {
        "chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110)"
    };
}

const PHP_PAYLOADS: [&str; 5] = [
    concat!("\";print(", php_token!(), ");$var=\""),
    concat!("';print(", php_token!(), ");$var='"),
    concat!("${@print(", php_token!(), ")}"),
    concat!("${@print(", php_token!(), ")}\\"),
    concat!(";print(", php_token!(), ");"),
];

/// ASP payloads multiplying two random numbers (the product must show up).
const ASP_PAYLOADS: [&str; 3] =
    ["\"+response.write({0}*{1})+\"", "'+response.write({0}*{1})+'", "response.write({0}*{1})"];

const MAX_VALUE: u64 = 999_998;

/// `MessageFormat.format(payload, n1, n2)` as intended: plain numbers. Deviation:
/// ZAP's MessageFormat writes `268,327*513,977` (grouping separators) and treats
/// the quotes of the second payload as escapes (sending `{0}*{1}` literally), so
/// its ASP check can't match; this sends the intended expressions.
fn asp_payload(template: &str, n1: u64, n2: u64) -> String {
    template.replace("{0}", &n1.to_string()).replace("{1}", &n2.to_string())
}

fn random_value() -> u64 {
    crate::scan::active::rand_u64() % MAX_VALUE + 1
}

pub struct CodeInjection;

impl ActiveRule for CodeInjection {
    fn id(&self) -> u32 {
        90019
    }

    fn name(&self) -> &'static str {
        "Server Side Code Injection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if test_php(cx).await || cx.stopped() {
                return;
            }
            test_asp(cx).await;
        })
    }
}

async fn test_php(cx: &Cx) -> bool {
    let (param, _) = point(cx);
    for payload in PHP_PAYLOADS {
        if cx.stopped() {
            break;
        }
        let Ok(resp) = cx.send_payload(payload).await else { continue };
        if resp.body_str().contains(PHP_CONTROL_TOKEN) {
            cx.report(PHP_ALERT.raise(param, PHP_CONTROL_TOKEN).attack(payload), &resp);
            return true;
        }
    }
    false
}

async fn test_asp(cx: &Cx) -> bool {
    let (param, _) = point(cx);
    let (n1, n2) = (random_value(), random_value());
    let evidence = (n1 * n2).to_string();
    for template in ASP_PAYLOADS {
        if cx.stopped() {
            break;
        }
        let Ok(resp) = cx.send_payload(&asp_payload(template, n1, n2)).await else { continue };
        if resp.body_str().contains(&evidence) {
            // ZAP reports the payload template as the attack.
            cx.report(ASP_ALERT.raise(param, evidence).attack(template), &resp);
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads() {
        assert_eq!(
            PHP_PAYLOADS[0],
            "\";print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110));$var=\""
        );
        assert_eq!(
            PHP_PAYLOADS[3],
            "${@print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110))}\\"
        );
        // The token is not in the payloads themselves, so reflection can't match.
        assert!(PHP_PAYLOADS.iter().all(|p| !p.contains(PHP_CONTROL_TOKEN)));
        assert_eq!(asp_payload(ASP_PAYLOADS[1], 268327, 513977), "'+response.write(268327*513977)+'");
        assert_eq!((268327u64 * 513977).to_string(), "137913906479");
        for _ in 0..100 {
            assert!((1..=MAX_VALUE).contains(&random_value()));
        }
    }
}
