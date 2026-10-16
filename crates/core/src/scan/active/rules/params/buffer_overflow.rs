//! Ported from ZAP BufferOverflowScanRule (ascanrules, Apache License 2.0).
//!
//! ZAP only runs this rule when the C technology is in scope; brainproxy has no
//! technology filter, so it always runs.

use super::common;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "30001",
    name: "Buffer Overflow",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 120,
    wasc: 7,
    description:
        "Buffer overflow errors are characterized by the overwriting of memory spaces of the background web process, \
        which should have never been modified intentionally or unintentionally. Overwriting values of the IP \
        (Instruction Pointer), BP (Base Pointer) and other registers causes exceptions, segmentation faults, and other \
        process errors to occur. Usually these errors end execution of the application in an unexpected way.",
    solution:
        "Rewrite the background program using proper return length checking. This will require a recompile of the \
        background executable.",
    references: &["https://owasp.org/www-community/attacks/Buffer_overflow_attack"],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2025_A10", "OWASP_2021_A03", "OWASP_2017_A01"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER: &str =
    "Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.";
const CONNECTION_CLOSED: &str = "Connection: close";

/// `randomCharacterString`: ASCII letters only.
pub(crate) fn random_letters(len: usize) -> String {
    const LETTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    (0..len).map(|_| LETTERS[(crate::scan::active::rand_u64() % LETTERS.len() as u64) as usize] as char).collect()
}

pub struct BufferOverflow;

impl ActiveRule for BufferOverflow {
    fn id(&self) -> u32 {
        30001
    }

    fn name(&self) -> &'static str {
        "Buffer Overflow"
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
            let attack = random_letters(2100);
            let Ok(resp) = common::send_following(cx, &attack).await else { return };
            if resp.status == 500 && common::headers_as_string(&resp).contains(CONNECTION_CLOSED) {
                let f = ALERT.raise(cx.point().name.clone(), CONNECTION_CLOSED).attack(attack).other_info(OTHER);
                cx.report(f, &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_only() {
        let s = random_letters(2100);
        assert_eq!(s.len(), 2100);
        assert!(s.bytes().all(|b| b.is_ascii_alphabetic()));
    }
}
