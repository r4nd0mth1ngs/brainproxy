//! Ported from ZAP ElmahScanRule and commonlib AbstractHostFilePlugin
//! (ascanrules and commonlib, Apache License 2.0).

use super::common::host_file_probe;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40028-1",
    name: "ELMAH Information Leak",
    risk: Risk::Medium,
    confidence: Confidence::High,
    cwe: 94,
    wasc: 14,
    description: "The Error Logging Modules and Handlers (ELMAH [elmah.axd]) HTTP Module was found to be available. \
        This module can leak a significant amount of valuable information.",
    solution: "Consider whether or not ELMAH is actually required in production, if it isn't then disable it. If it \
        is then ensure access to it requires authentication and authorization. See also: \
        https://elmah.github.io/a/securing-error-log-pages/",
    references: &[
        "https://www.troyhunt.com/aspnet-session-hijacking-with-google/",
        "https://www.nuget.org/packages/elmah",
        "https://elmah.github.io/",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CONF-05"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const FILENAME: &str = "/elmah.axd";

fn has_content(body: &str) -> bool {
    body.contains("Error Log for")
}

pub struct Elmah;

impl ActiveRule for Elmah {
    fn id(&self) -> u32 {
        40028
    }

    fn name(&self) -> &'static str {
        "ELMAH Information Leak"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Host
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let Some(resp) = host_file_probe(cx, FILENAME).await else { return };
            // At the MEDIUM threshold only responses with ELMAH content are raised.
            if has_content(resp.body_str()) {
                cx.report(ALERT.raise("", resp.status_line.clone()), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content() {
        assert!(has_content("<title>Error log for /LM/W3SVC/1 on WEB01</title><h1>Error Log for Demo</h1>"));
        assert!(!has_content("<h1>Welcome</h1>"));
    }
}
