//! Ported from ZAP CrlfInjectionScanRule (ascanrules, Apache License 2.0).

use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40003",
    name: "CRLF Injection",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 113,
    wasc: 25,
    description: "Cookie can be set via CRLF injection. It may also be possible to set arbitrary HTTP response \
        headers. In addition, by carefully crafting the injected response using cross-site script, cache poisoning \
        vulnerability may also exist.",
    solution: "Type check the submitted parameter carefully. Do not allow CRLF to be injected by filtering CRLF.",
    references: &[
        "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
        "https://cwe.mitre.org/data/definitions/113.html",
    ],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-15", "API_2023_API10", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct CrlfInjection;

impl ActiveRule for CrlfInjection {
    fn id(&self) -> u32 {
        40003
    }

    fn name(&self) -> &'static str {
        "CRLF Injection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let marker = format!("Tamper={}", uuid_like());
            let cookie = format!("Set-cookie: {marker}");
            let attacks = [
                cookie.clone(),
                format!("any\r\n{cookie}"),
                format!("any?\r\n{cookie}"),
                format!("any\n{cookie}"),
                format!("any?\n{cookie}"),
                format!("any\r\n{cookie}\r\n"),
                format!("any?\r\n{cookie}\r\n"),
            ];
            let needle = format!("\nset-cookie: {}", marker.to_ascii_lowercase());
            for attack in attacks {
                if cx.stopped() {
                    return;
                }
                let Ok(resp) = cx.send_payload(&attack).await else { continue };
                let head = resp.head_text();
                if let Some(i) = head.to_ascii_lowercase().find(&needle) {
                    let evidence = head[i + 1..i + needle.len()].to_string();
                    let finding =
                        ALERT.raise(cx.point().name.clone(), evidence).attack(attack).confidence(Confidence::Medium);
                    cx.report(finding, &resp);
                    return;
                }
            }
        })
    }
}

/// A random UUID-shaped string (the value only has to be unique per scan).
fn uuid_like() -> String {
    let a = super::super::rand_u64();
    let b = super::super::rand_u64();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        a >> 32,
        (a >> 16) & 0xffff,
        a & 0xfff,
        (b >> 48) & 0x3fff | 0x8000,
        b & 0xffff_ffff_ffff
    )
}
