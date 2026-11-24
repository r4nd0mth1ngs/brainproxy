//! Ported from ZAP ExpressionLanguageInjectionScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Sends `${a+b}` with two random six-digit numbers whose sum the page doesn't already show;
//! the sum in the answer means an expression language (JSP EL, Spring, OGNL) evaluated the
//! input. Redirects are followed, as in ZAP.

use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90025",
    name: "Expression Language Injection",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 917,
    wasc: 20,
    description: "The software constructs all or part of an expression language (EL) statement in a Java Server Page \
        (JSP) using externally-influenced input from an upstream component, but it does not neutralize or \
        incorrectly neutralizes special elements that could modify the intended EL statement before it is executed. \
        In certain versions of Spring 3.0.5 and earlier, there was a vulnerability (CVE-2011-2730) in which \
        Expression Language tags would be evaluated twice, which effectively exposed any application to EL \
        injection. However, even for later versions, this weakness is still possible depending on configuration.",
    solution: "Perform data validation best practice against untrusted input and to ensure that output encoding is \
        applied when data arrives on the EL layer, so that no metacharacter is found by the interpreter within the \
        user content before evaluation. The most obvious patterns to detect include ${ and #{, but it may be \
        possible to encode or fragment this data.",
    references: &[
        "https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection",
        "https://cwe.mitre.org/data/definitions/917.html",
    ],
    tags: &[
        "API_2023_API10",
        "OWASP_2025_A05",
        "OWASP_2021_A03",
        "OWASP_2017_A01",
        "WSTG-v42-INPV-11",
        "HIPAA",
        "PCI_DSS",
    ],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// A number from 100000 to 999999, as ZAP draws them.
fn big() -> u64 {
    100_000 + rand_u64() % 900_000
}

/// Two numbers whose sum `page` doesn't hold (ZAP tries up to 1,000 times).
fn operands(page: &str) -> (u64, u64) {
    let mut pair = (big(), big());
    for _ in 0..1000 {
        if !page.contains(&(pair.0 + pair.1).to_string()) {
            break;
        }
        pair = (big(), big());
    }
    pair
}

pub struct ExpressionLanguage;

impl ActiveRule for ExpressionLanguage {
    fn id(&self) -> u32 {
        90025
    }

    fn name(&self) -> &'static str {
        "Expression Language Injection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let (a, b) = operands(cx.base_response().body_str());
            let payload = format!("${{{a}+{b}}}");
            let sum = (a + b).to_string();
            let Ok(resp) = cx.send_following(cx.payload_request(&payload)).await else { return };
            if resp.body_str().contains(&sum) {
                cx.report(ALERT.raise(cx.point().name.clone(), sum).attack(payload), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::active::rules::test_app::{get, html, scan, serve, Opts};

    /// Evaluates `${a+b}` as an EL engine would, leaving any other text alone.
    fn evaluate(s: &str) -> String {
        let Some(inner) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}')) else { return s.to_string() };
        match inner.split_once('+').map(|(a, b)| (a.parse::<u64>(), b.parse::<u64>())) {
            Some((Ok(a), Ok(b))) => (a + b).to_string(),
            _ => s.to_string(),
        }
    }

    #[test]
    fn operands_avoid_the_page() {
        let (a, b) = operands("nothing");
        assert!((100_000..1_000_000).contains(&a) && (100_000..1_000_000).contains(&b));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn evaluated_input_and_echoed_input() {
        let port = serve(|r| match r.path.as_str() {
            "/el" => html(&format!("<p>Hello {}</p>", evaluate(&r.param("name").unwrap_or_default()))),
            _ => html(&format!("<p>Hello {}</p>", r.param("name").unwrap_or_default())),
        });
        let (s, found) = scan(90025, vec![get(port, "/el?name=bob")], Opts::default()).await;
        assert_eq!(found.len(), 1, "{s:?}");
        assert_eq!(found[0].param, "name");
        assert!(found[0].attack.starts_with("${") && found[0].attack.ends_with('}'));
        // Echoed as text: the expression, not its sum.
        let (s, found) = scan(90025, vec![get(port, "/echo?name=bob")], Opts::default()).await;
        assert!(found.is_empty());
        assert_eq!(s.requests, 1);
    }
}
