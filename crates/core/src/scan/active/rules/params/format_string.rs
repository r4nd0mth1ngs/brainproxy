//! Ported from ZAP FormatStringScanRule (ascanrules, Apache License 2.0).
//!
//! ZAP only runs this rule when the C technology is in scope; brainproxy has no
//! technology filter, so it always runs.

use super::common;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "30002",
    name: "Format String Error",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 134,
    wasc: 6,
    description: "A Format String error occurs when the submitted data of an input string is evaluated as a command by the \
        application.",
    solution: "Rewrite the background program using proper deletion of bad character strings. This will require a recompile of \
        the background executable.",
    references: &[
        "https://owasp.org/www-community/attacks/Format_string_attack",
    ],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2025_A10", "OWASP_2021_A03", "OWASP_2017_A01"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const ERROR1: &str = "Potential Format String Error. The script closed the connection on a /%s.";
const ERROR2: &str = "Potential Format String Error. The script closed the connection on a /%s and /%x.";
const ERROR3: &str =
    "Potential Format String Error. The script closed the connection on a Microsoft format string error.";
const INITIAL: &str = "ZAP";

/// GNU / generic C: many `%n%s` in a row.
pub(crate) fn initial_attack() -> String {
    format!("{INITIAL}{}\n", "%n%s".repeat(20))
}

/// Verification: `%x` only.
pub(crate) fn second_attack() -> String {
    format!("{INITIAL}{}\n", "%x".repeat(10))
}

/// Microsoft positional format strings.
pub(crate) fn microsoft_attack() -> String {
    let mut s = format!("{INITIAL} ");
    for i in 0..20 {
        s.push_str(&format!("%{}!s", i + 1));
    }
    for i in 20..40 {
        s.push_str(&format!("%{}!n", i + 1));
    }
    s.push('\n');
    s
}

pub struct FormatString;

impl ActiveRule for FormatString {
    fn id(&self) -> u32 {
        30002
    }

    fn name(&self) -> &'static str {
        "Format String Error"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.stopped() || cx.base_response().status == 500 {
                return;
            }
            let param = cx.point().name.clone();
            let Ok(initial) = common::send_following(cx, INITIAL).await else { return };
            if initial.status == 500 {
                return;
            }
            let initial_len = initial.body.len();
            let attack = initial_attack();
            let Ok(resp) = common::send_following(cx, &attack).await else { return };
            if resp.status == 500 {
                let second = second_attack();
                let Ok(verify) = common::send_following(cx, &second).await else { return };
                if verify.body.len() > initial_len + 20 && verify.status == 200 {
                    cx.report(ALERT.raise(param, "").attack(second).other_info(ERROR2), &verify);
                } else {
                    cx.report(ALERT.raise(param, "").attack(attack).other_info(ERROR1), &resp);
                }
                return;
            }
            if cx.stopped() {
                return;
            }
            let ms = microsoft_attack();
            let Ok(resp) = common::send_following(cx, &ms).await else { return };
            if resp.status == 500 {
                cx.report(ALERT.raise(param, "").attack(ms).other_info(ERROR3), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads() {
        assert!(initial_attack().starts_with("ZAP%n%s%n%s"));
        assert_eq!(initial_attack().len(), 3 + 80 + 1);
        assert_eq!(second_attack(), "ZAP%x%x%x%x%x%x%x%x%x%x\n");
        let ms = microsoft_attack();
        assert!(ms.starts_with("ZAP %1!s%2!s"));
        assert!(ms.ends_with("%40!n\n"));
    }
}
