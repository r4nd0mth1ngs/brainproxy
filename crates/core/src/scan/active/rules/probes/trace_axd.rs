//! Ported from ZAP TraceAxdScanRule and commonlib AbstractAppFilePlugin
//! (ascanrules and commonlib, Apache License 2.0).

use super::common::app_file_probe;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40029-1",
    name: "Trace.axd Information Leak",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 215,
    wasc: 13,
    description: "The ASP.NET Trace Viewer (trace.axd) was found to be available. This component can leak a \
        significant amount of valuable information.",
    solution: "Consider whether or not Trace Viewer is actually required in production, if it isn't then disable it. \
        If it is then ensure access to it requires authentication and authorization.",
    references: &[
        "https://learn.microsoft.com/en-us/previous-versions/bb386420(v=vs.140)",
        "https://learn.microsoft.com/en-us/previous-versions/wwh16c6c(v=vs.140)",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CONF-05"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const FILENAME: &str = "trace.axd";

fn is_false_positive(body: &str) -> bool {
    !body.contains("Application Trace") && !body.contains("Request Details") && !body.contains("Trace Information")
}

pub struct TraceAxd;

impl ActiveRule for TraceAxd {
    fn id(&self) -> u32 {
        40029
    }

    fn name(&self) -> &'static str {
        "Trace.axd Information Leak"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let Some(resp) = app_file_probe(cx, 40029, FILENAME).await else { return };
            if !is_false_positive(resp.body_str()) {
                cx.report(ALERT.raise("", resp.status_line.clone()), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn false_positives() {
        assert!(!is_false_positive("<h1>Application Trace</h1>"));
        assert!(!is_false_positive("<h2>Request Details</h2>"));
        assert!(is_false_positive("<h1>Not here</h1>"));
    }
}
