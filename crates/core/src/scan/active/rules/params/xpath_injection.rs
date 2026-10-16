//! Ported from ZAP XpathInjectionScanRule (ascanrules, Apache License 2.0).
//!
//! ZAP's optional custom error strings (the "XPath-Errors" payload category of the
//! Custom Payloads add-on) are not supported; the default list is used.

use super::common;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
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
}
