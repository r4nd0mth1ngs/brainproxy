//! Ported from ZAP PolyfillCdnScriptScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use super::common::{element_content, element_source};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT_SRC: AlertDef = AlertDef {
    alert_ref: "10115-1",
    name: "Script Served From Malicious Domain (polyfill)",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 829,
    wasc: 15,
    description: "The page includes one or more script files loaded from one of the 'polyfill' domains.\nThese are \
        not associated with the polyfill.js library and are known to serve malicious content.",
    solution: "Change all scripts to use a known good source based on their documentation.",
    references: &["https://sansec.io/research/polyfill-supply-chain-attack"],
    tags: &["OWASP_2025_A03", "OWASP_2021_A06", "OWASP_2017_A09"],
};

static ALERT_INLINE: AlertDef = AlertDef {
    alert_ref: "10115-2",
    name: "Script Served From Malicious Domain (polyfill)",
    risk: Risk::High,
    confidence: Confidence::Low,
    cwe: 829,
    wasc: 15,
    description: "The page includes one or more script which appear to include a reference to one of the \
        'polyfill' domains.\nThese are not associated with the polyfill.js library and are known to serve \
        malicious content.\nYou should check to see if it is a safe reference (for example in a comment) or \
        whether the script is loading content from that domain.",
    solution: "Change all scripts to use a known good source based on their documentation.",
    references: &["https://sansec.io/research/polyfill-supply-chain-attack"],
    tags: &["OWASP_2025_A03", "OWASP_2021_A06", "OWASP_2017_A09"],
};

static ALERTS: [&AlertDef; 2] = [&ALERT_SRC, &ALERT_INLINE];

const DOMAINS: [&str; 9] = [
    "polyfill.io/",
    "bootcss.com/",
    "bootcdn.net/",
    "staticfile.net/",
    "staticfile.org/",
    "unionadjs.com/",
    "xhsbpza.com/",
    "union.macoms.la/",
    "newcrbpc.com/",
];

/// ZAP's `http[s]?://.*<domain>.*\w` (domain dots unescaped, as in ZAP; `.`
/// does not cross lines). Index 0 is the full-match form, 1 the find form.
static PATTERNS: LazyLock<Vec<(Regex, Regex)>> = LazyLock::new(|| {
    DOMAINS
        .iter()
        .map(|d| {
            let p = format!(r"http[s]?://[^\n\r]*{d}[^\n\r]*[0-9A-Za-z_]");
            (Regex::new(&format!(r"(?i)\A(?:{p})\z")).unwrap(), Regex::new(&format!("(?i){p}")).unwrap())
        })
        .collect()
});

pub struct PolyfillCdn;

impl PassiveRule for PolyfillCdn {
    fn id(&self) -> u32 {
        10115
    }

    fn name(&self) -> &'static str {
        "Script Served From Malicious Domain (polyfill)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_body.is_empty() || !msg.is_html() {
            return;
        }
        let html = msg.body();
        let all = tags(html);
        let scripts: Vec<_> = all.iter().filter(|t| t.name == "script").collect();
        let mut raised = false;
        for s in &scripts {
            let Some(src) = s.attr("src") else { continue };
            for (full, _) in PATTERNS.iter() {
                if full.is_match(src) {
                    out.push(ALERT_SRC.raise(src, element_source(html, s)));
                    raised = true;
                }
            }
        }
        if raised {
            return;
        }
        for s in &scripts {
            let contents = element_content(html, s);
            let lc = contents.to_lowercase();
            for (i, d) in DOMAINS.iter().enumerate() {
                if lc.contains(d) {
                    if let Some(m) = PATTERNS[i].1.find(contents) {
                        out.push(ALERT_INLINE.raise("", m.as_str()));
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_polyfill_src() {
        let html = r#"<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>"#;
        let f = msg("https://a.test/").html(html).scan(&PolyfillCdn);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].def.alert_ref, "10115-1");
        assert_eq!(f[0].param, "https://cdn.polyfill.io/v3/polyfill.min.js");
        assert_eq!(f[0].evidence, html);
    }

    #[test]
    fn flags_inline_reference() {
        let html = "<script>\nload('https://cdn.bootcss.com/x/y.js');\n</script>";
        let f = msg("https://a.test/").html(html).scan(&PolyfillCdn);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].def.alert_ref, "10115-2");
        assert_eq!(f[0].evidence, "https://cdn.bootcss.com/x/y.js");
    }

    #[test]
    fn ignores_other_scripts() {
        let html = r#"<script src="https://cdnjs.cloudflare.com/polyfill.js"></script><script>var a=1;</script>"#;
        assert!(msg("https://a.test/").html(html).scan(&PolyfillCdn).is_empty());
    }
}
