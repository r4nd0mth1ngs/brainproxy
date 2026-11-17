//! Ported from ZAP XpathInjectionScanRule (ascanrules, Apache License 2.0).
//!
//! ZAP's optional custom error strings (the "XPath-Errors" payload category of the
//! Custom Payloads add-on) are not supported; the default list is used.
//!
//! Not in ZAP: when no error shows, a boolean check (medium confidence). The value is closed
//! and an always-true and an always-false comparison are added, each ANDed and then ORed
//! (`2' and '1'='1` / `2' and '1'='2`, then `or`): read as data both are unknown values and
//! give the same page; built into an XPath predicate, one keeps the original page and the
//! other changes it (`differential`, which also sends a pair that passes a second time).
//! Single quotes at LOW; double quotes and numeric comparisons (`2 and 1=1`) from MEDIUM, the
//! numeric ones at MEDIUM only for a numeric original value.
//!
//! `' and '1'='1` reads the same way in SQL, so a pair that passes is confirmed with one SQL
//! can't evaluate: the same conditions with the root element counted (`count(/*)=1`, always
//! true in XPath, against `count(/*)=0`). In SQL `/*` opens a comment and `count(` is never
//! closed, so both values are the same syntax error and give the same page.

use super::common;
use crate::scan::active::rules::differential::{Differential, Kept};
use crate::scan::active::rules::injection::common::by_strength;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90021",
    name: "XPath Injection",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 643,
    wasc: 39,
    description: "XPath Injection is an attack technique used to exploit applications that construct XPath (XML Path Language) \
        queries from user-supplied input to query or navigate XML documents. It can be used directly by an application \
        to query an XML document, as part of a larger operation such as applying an XSLT transformation to an XML \
        document, or applying an XQuery to an XML document. The syntax of XPath bears some resemblance to an SQL query, \
        and indeed, it is possible to form SQL-like queries on an XML document using XPath.\n\nIf an application uses \
        run-time XPath query construction, embedding unsafe user input into the query, it may be possible for the \
        attacker to inject data into the query such that the newly formed query will be parsed in a way differing from \
        the programmer's intention.",
    solution: "Use parameterized XPath queries (e.g. using XQuery). This will help ensure separation between data plane and \
        control plane.\n\nProperly validate user input. Reject data where appropriate, filter where appropriate and \
        escape where appropriate. Make sure input that will be used in XPath queries is safe in that context.",
    references: &[
        "https://owasp.org/www-community/attacks/XPATH_Injection",
        "https://owasp.org/www-community/attacks/Blind_XPath_Injection",
        "https://cwe.mitre.org/data/definitions/643.html",
    ],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-09"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Payloads able to generate an explicit XML error.
pub(crate) const XPATH_PAYLOADS: [&str; 3] = ["\"'", "<!--", "]]>"];

/// XPath errors (from the W3AF XPath injection plugin).
pub(crate) const DEFAULT_ERRORS: [&str; 29] = [
    "XPathException",
    "MS.Internal.Xml.",
    "Unknown error in XPath",
    "org.apache.xpath.XPath",
    "A closing bracket expected in",
    "An operand in Union Expression does not produce a node-set",
    "Cannot convert expression to a number",
    "Document Axis does not allow any context Location Steps",
    "Empty Path Expression",
    "Empty Relative Location Path",
    "Empty Union Expression",
    "Expected ')' in",
    "Expected node test or name specification after axis operator",
    "Incompatible XPath key",
    "Incorrect Variable Binding",
    "libxml2 library function failed",
    "libxml2",
    "xmlsec library function",
    "xmlsec",
    "error '80004005'",
    "A document must contain exactly one root element.",
    "<font face=\"Arial\" size=2>Expression must evaluate to a node-set.",
    "Expected token '\\]'",
    "<p>msxml4.dll</font>",
    "<p>msxml3.dll</font>",
    // Lotus notes error when document searching inside nsf files
    "4005 Notes error: Query is not understandable",
    // PHP error
    "SimpleXMLElement::xpath()",
    "xmlXPathEval: evaluation failed",
    "Expression must evaluate to a node-set.",
];

/// The always-true and always-false values for `orig` closed with `quote` (none: a number),
/// joined with `op` (`and` or `or`).
fn pair(orig: &str, quote: &str, op: &str) -> (String, String) {
    let q = quote;
    (format!("{orig}{q} {op} {q}1{q}={q}1"), format!("{orig}{q} {op} {q}1{q}={q}2"))
}

/// The XPath-only pair confirming `pair(orig, quote, op)`: the condition is whether the
/// document has a root element, and a comparison that leaves the result as it is (true after
/// `and`, false after `or`) takes the template's closing quote.
fn xpath_pair(orig: &str, quote: &str, op: &str) -> (String, String) {
    let q = quote;
    let rest = if op == "and" { format!("{q}1{q}={q}1") } else { format!("{q}1{q}={q}2") };
    (format!("{orig}{q} {op} count(/*)=1 {op} {rest}"), format!("{orig}{q} {op} count(/*)=0 {op} {rest}"))
}

/// The quotes and operators to try, by strength: single quotes, then double quotes and numbers.
fn pairs(orig: &str, strength: Strength) -> Vec<(&'static str, &'static str)> {
    let numeric = !orig.is_empty() && orig.parse::<f64>().is_ok();
    let mut quotes = vec!["'"];
    if by_strength(strength, [false, true, true, true]) {
        quotes.push("\"");
        if numeric || by_strength(strength, [false, false, true, true]) {
            quotes.push("");
        }
    }
    quotes.into_iter().flat_map(|q| ["and", "or"].map(|op| (q, op))).collect()
}

fn boolean_info(t: &str, f: &str, xt: &str, kept: Kept) -> String {
    let how = match kept {
        Kept::ByTrue => "kept the original page and the FALSE one",
        Kept::ByFalse => "changed the original page and the FALSE one",
    };
    format!(
        "The TRUE condition [{t}] {how} [{f}] did the opposite, and so did the XPath-only [{xt}], so the value is \
         evaluated as part of an XPath expression. Taken as plain values, the two would give the same page; in SQL, \
         the XPath-only pair is a syntax error both ways."
    )
}

/// The first error found in `response` that is not in `original`.
pub(crate) fn new_error(response: &str, original: &str) -> Option<&'static str> {
    DEFAULT_ERRORS.into_iter().find(|e| response.contains(e) && !original.contains(e))
}

pub struct XpathInjection;

impl ActiveRule for XpathInjection {
    fn id(&self) -> u32 {
        90021
    }

    fn name(&self) -> &'static str {
        "XPath Injection"
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
            for payload in XPATH_PAYLOADS {
                if let Ok(resp) = common::send_no_follow(cx, payload).await {
                    if let Some(error) = new_error(resp.body_str(), original) {
                        let f = ALERT.raise(cx.point().name.clone(), error).attack(payload);
                        cx.report(f, &resp);
                        return;
                    }
                }
                if cx.stopped() {
                    return;
                }
            }
            let Some(diff) = Differential::new(cx).await else { return };
            let orig = cx.point().value.clone();
            for (q, op) in pairs(&orig, cx.strength()) {
                if cx.stopped() {
                    return;
                }
                let (t, f) = pair(&orig, q, op);
                let Some((kept, _)) = diff.test(&t, &f).await else { continue };
                if cx.stopped() {
                    return;
                }
                // SQL, which reads the first pair the same way, stops here.
                let (xt, xf) = xpath_pair(&orig, q, op);
                if let Some((xkept, resp)) = diff.test(&xt, &xf).await {
                    if xkept == kept {
                        let finding = ALERT
                            .raise(cx.point().name.clone(), "")
                            .attack(xt.clone())
                            .confidence(Confidence::Medium)
                            .other_info(boolean_info(&t, &f, &xt, kept));
                        cx.report(finding, &resp);
                        return;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_new_to_the_response() {
        assert_eq!(
            new_error("Warning: SimpleXMLElement::xpath(): Invalid expression", ""),
            Some("SimpleXMLElement::xpath()")
        );
        assert_eq!(new_error("libxml2 error", "powered by libxml2"), None);
        // Order matters: the first matching error is the evidence.
        assert_eq!(new_error("libxml2 library function failed", ""), Some("libxml2 library function failed"));
        assert_eq!(new_error("all good", ""), None);
    }

    #[test]
    fn boolean_pairs() {
        assert_eq!(pair("2", "'", "and"), ("2' and '1'='1".into(), "2' and '1'='2".into()));
        assert_eq!(pair("2", "", "or"), ("2 or 1=1".into(), "2 or 1=2".into()));
        assert_eq!(
            xpath_pair("2", "'", "and"),
            ("2' and count(/*)=1 and '1'='1".into(), "2' and count(/*)=0 and '1'='1".into())
        );
        assert_eq!(xpath_pair("9", "\"", "or").0, "9\" or count(/*)=1 or \"1\"=\"2");
        assert_eq!(xpath_pair("2", "", "and").1, "2 and count(/*)=0 and 1=1");
        assert_eq!(pairs("bob", Strength::Low).len(), 2);
        // Numbers for a numeric value from MEDIUM, for any value from HIGH.
        assert_eq!(pairs("bob", Strength::Medium).len(), 4);
        assert_eq!(pairs("2", Strength::Medium).len(), 6);
        assert_eq!(pairs("bob", Strength::High).len(), 6);
        assert_eq!(pairs("bob", Strength::Medium)[2], ("\"", "and"));
    }
}
