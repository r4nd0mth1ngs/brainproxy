//! Ported from ZAP XsltInjectionScanRule (ascanrules, Apache License 2.0).
//!
//! ZAP's request limit per strength counts across all parameters of a page (one rule
//! instance per message); here it applies per insertion point, so every parameter gets
//! the full set of checks at MEDIUM.

use super::common;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90017",
    name: "XSLT Injection",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 91,
    wasc: 23,
    description: "Injection using XSL transformations may be possible, and may allow an attacker to read system \
        information, read and write files, or execute arbitrary code.",
    solution: "Sanitize and analyze every user input coming from any client-side.",
    references: &[
        "https://hacktricks.wiki/en/pentesting-web/xslt-server-side-injection-extensible-stylesheet-language-transformations.html",
    ],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "HIPAA", "PCI_DSS"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

#[derive(Clone, Copy, PartialEq)]
enum Check {
    Error,
    Vendor,
    PortScan,
    Command,
}

impl Check {
    const ALL: [Check; 4] = [Check::Error, Check::Vendor, Check::PortScan, Check::Command];

    fn payloads(self, cx: &Cx) -> Vec<String> {
        let fixed: &[&str] = match self {
            Check::Error => &["<"],
            Check::Vendor => &[
                "<xsl:value-of select=\"system-property('xsl:vendor')\"/>",
                "system-property('xsl:vendor')/>",
                "\"/><xsl:value-of select=\"system-property('xsl:vendor')\"/><!--",
                "<xsl:value-of select=\"system-property('xsl:vendor')\"/><!--",
            ],
            Check::PortScan => {
                // One port on the target's own host, as ZAP does.
                let host = &cx.target().host;
                let host = if host.contains(':') { format!("[{host}]") } else { host.clone() };
                return vec![format!("<xsl:value-of select=\"document('http://{host}:22')\"/>")];
            }
            Check::Command => &[
                "<xsl:variable name=\"rtobject\" select=\"runtime:getRuntime()\"/>\n\
                 <xsl:variable name=\"process\" select=\"runtime:exec($rtobject,'erroneous_command')\"/>\n\
                 <xsl:variable name=\"waiting\" select=\"process:waitFor($process)\"/>\n\
                 <xsl:value-of select=\"$process\"/>",
                "<xsl:value-of select=\"php:function('exec','erroneous_command 2>&amp;1')\"/>",
            ],
        };
        fixed.iter().map(|s| s.to_string()).collect()
    }

    fn evidences(self) -> &'static [&'static str] {
        match self {
            Check::Error => &["compilation error", "XSLT compile error", "SAXParseException"],
            Check::Vendor => &["libxslt", "Microsoft", "Saxonica", "Apache", "Xalan", "SAXON", "Transformiix"],
            Check::PortScan => &[
                "failed to open stream",
                "Invalid Http response",
                "Connection Refused",
                "No connection could be made because the target machine actively refused it",
                "Can not load requested doc",
            ],
            Check::Command => &["Cannot run program", "erroneous_command: not found"],
        }
    }

    fn other_info(self, evidence: &str) -> String {
        match self {
            Check::Error => "The response to sending an XSLT token included error messages that may indicate a \
                vulnerability to XSLT injections."
                .into(),
            Check::Vendor => {
                format!("The XSLT processor vendor name \"{evidence}\" was returned after an injection request.")
            }
            Check::PortScan => "Port scanning may be possible.".into(),
            Check::Command => "Command execution may be possible.".into(),
        }
    }
}

fn request_limit(strength: Strength) -> usize {
    match strength {
        Strength::Low => 6,
        Strength::Medium => 12,
        Strength::High | Strength::Insane => 24,
    }
}

pub struct XsltInjection;

impl ActiveRule for XsltInjection {
    fn id(&self) -> u32 {
        90017
    }

    fn name(&self) -> &'static str {
        "XSLT Injection"
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
            let limit = request_limit(cx.strength());
            let mut sent = 0;
            for check in Check::ALL {
                // Evidence already in the original response can't indicate anything.
                let relevant: Vec<&str> = check.evidences().iter().copied().filter(|e| !original.contains(e)).collect();
                for payload in check.payloads(cx) {
                    if cx.stopped() || sent >= limit {
                        return;
                    }
                    let Ok(resp) = common::send_following(cx, &payload).await else { continue };
                    sent += 1;
                    let body = resp.body_str();
                    let Some(evidence) = relevant.iter().find(|e| body.contains(**e)) else { continue };
                    if check == Check::Vendor {
                        // Same payload with a broken function name: still there means a false positive.
                        let invalid = payload.replace("vendor", "vedor");
                        let Ok(still) = common::send_following(cx, &invalid).await else { continue };
                        sent += 1;
                        if still.body_str().contains(evidence) {
                            continue;
                        }
                    }
                    let f = ALERT
                        .raise(cx.point().name.clone(), *evidence)
                        .attack(&payload)
                        .other_info(check.other_info(evidence));
                    cx.report(f, &resp);
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
    fn payload_texts() {
        assert_eq!(Check::Vendor.evidences().len(), 7);
        assert_eq!(
            Check::Vendor.other_info("libxslt"),
            "The XSLT processor vendor name \"libxslt\" was returned after an injection request."
        );
        assert_eq!(request_limit(Strength::Medium), 12);
    }
}
