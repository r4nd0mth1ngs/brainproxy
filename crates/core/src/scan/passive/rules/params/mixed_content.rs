//! Ported from ZAP MixedContentScanRule (pscanrules, Apache License 2.0).

use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static MIXED: AlertDef = AlertDef {
    alert_ref: "10040",
    name: "Secure Pages Include Mixed Content",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 311,
    wasc: 4,
    description: "The page includes mixed content, that is content accessed via HTTP instead of HTTPS.",
    solution: "A page that is available over SSL/TLS must be comprised completely of content which is transmitted \
        over SSL/TLS.\nThe page must not contain any content that is transmitted over unencrypted HTTP.\nThis \
        includes content from third party sites.",
    references: &["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CRYP-03", "SYSTEMIC"],
};

static MIXED_SCRIPTS: AlertDef = AlertDef {
    alert_ref: "10040",
    name: "Secure Pages Include Mixed Content (Including Scripts)",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 311,
    wasc: 4,
    description: "The page includes mixed content, that is content accessed via HTTP instead of HTTPS.",
    solution: "A page that is available over SSL/TLS must be comprised completely of content which is transmitted \
        over SSL/TLS.\nThe page must not contain any content that is transmitted over unencrypted HTTP.\nThis \
        includes content from third party sites.",
    references: &["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CRYP-03", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 2] = [&MIXED, &MIXED_SCRIPTS];

/// Attributes checked on every element, in ZAP's order (action/formaction are
/// only skipped at HIGH threshold).
const ATTRIBUTES: [&str; 9] =
    ["src", "background", "classid", "codebase", "data", "icon", "usemap", "action", "formaction"];

pub struct MixedContent;

impl PassiveRule for MixedContent {
    fn id(&self) -> u32 {
        10040
    }

    fn name(&self) -> &'static str {
        "Secure Pages Include Mixed Content"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_https() || msg.resp_body.is_empty() || !msg.is_html() {
            return;
        }
        let mut first: Option<String> = None;
        let mut info = String::new();
        let mut inc_script = false;
        for tag in tags(msg.body()) {
            for att in ATTRIBUTES {
                let Some(v) = tag.attr(att) else { continue };
                if !v.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("http:")) {
                    continue;
                }
                if att == "src" && tag.name == "script" {
                    inc_script = true;
                }
                first.get_or_insert_with(|| v.to_string());
                info.push_str(&format!("tag={} {att}={v}\n", tag.name));
            }
        }
        let Some(first) = first else { return };
        let def = if inc_script { &MIXED_SCRIPTS } else { &MIXED };
        out.push(def.raise("", first).other_info(info));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_http_resources_on_https_page() {
        let page = "<html><img src=\"http://a.test/i.png\"><form action=\"HTTP://a.test/post\"></form>\
                    <link href=\"http://a.test/s.css\" rel=stylesheet></html>";
        let f = msg("https://a.test/").html(page).scan(&MixedContent);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].def.name, f[0].risk), ("Secure Pages Include Mixed Content", Risk::Low));
        assert_eq!(f[0].evidence, "http://a.test/i.png");
        assert_eq!(f[0].other_info, "tag=img src=http://a.test/i.png\ntag=form action=HTTP://a.test/post\n");
    }

    #[test]
    fn scripts_raise_medium_variant() {
        let page = "<img src=\"http://a.test/i.png\"><script src=\"http://a.test/a.js\"></script>";
        let f = msg("https://a.test/").html(page).scan(&MixedContent);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].def.alert_ref, f[0].def.name, f[0].risk), ("10040", MIXED_SCRIPTS.name, Risk::Medium));
    }

    #[test]
    fn ignores_http_pages_and_secure_content() {
        let page = "<img src=\"http://a.test/i.png\">";
        assert!(msg("http://a.test/").html(page).scan(&MixedContent).is_empty());
        let ok = "<img src=\"https://a.test/i.png\"><img src=\"//a.test/x.png\"><a href=\"http://a.test/\">x</a>";
        assert!(msg("https://a.test/").html(ok).scan(&MixedContent).is_empty());
    }
}
