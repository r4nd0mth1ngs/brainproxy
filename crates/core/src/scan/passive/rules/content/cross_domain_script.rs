//! Ported from ZAP CrossDomainScriptInclusionScanRule (pscanrules, Apache License 2.0).

use super::common::{element_source, is_other_domain};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10017",
    name: "Cross-Domain JavaScript Source File Inclusion",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 829,
    wasc: 15,
    description: "The page includes one or more script files from a third-party domain.",
    solution: "Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be \
        controlled by end users of the application.",
    references: &[],
    tags: &["OWASP_2025_A08", "OWASP_2021_A08", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct CrossDomainScript;

impl PassiveRule for CrossDomainScript {
    fn id(&self) -> u32 {
        10017
    }

    fn name(&self) -> &'static str {
        "Cross-Domain JavaScript Source File Inclusion"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_body.is_empty() || !msg.is_html() {
            return;
        }
        let html = msg.body();
        for t in tags(html).iter().filter(|t| t.name == "script") {
            let Some(src) = t.attr("src") else { continue };
            if !is_other_domain(&msg.host, src) {
                continue;
            }
            if t.attr("integrity").is_none_or(|i| i.trim().is_empty()) {
                out.push(ALERT.raise(src, element_source(html, t)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_third_party_script_without_integrity() {
        let html = r#"<script src="https://cdn.other.test/lib.js"></script><script src="//x.test/a.js" integrity=" "></script>"#;
        let f = msg("https://a.test/").html(html).scan(&CrossDomainScript);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].param, "https://cdn.other.test/lib.js");
        assert_eq!(f[0].evidence, r#"<script src="https://cdn.other.test/lib.js"></script>"#);
        assert_eq!(f[1].param, "//x.test/a.js");
    }

    #[test]
    fn ignores_same_host_relative_and_sri_scripts() {
        let html = r#"<script src="https://A.test/x.js"></script><script src="/a.js"></script>
            <script src="js/b.js"></script><script src="https://cdn.test/c.js" integrity="sha384-abc"></script>"#;
        assert!(msg("https://a.test/").html(html).scan(&CrossDomainScript).is_empty());
    }
}
