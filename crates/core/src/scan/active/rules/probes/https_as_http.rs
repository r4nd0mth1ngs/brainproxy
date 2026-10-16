//! Ported from ZAP HttpsAsHttpScanRule (ascanrules, Apache License 2.0).

use super::common::base_path_query;
use crate::http::Target;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10047",
    name: "HTTPS Content Available via HTTP",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 311,
    wasc: 4,
    description: "Content which was initially accessed via HTTPS (i.e.: using SSL/TLS encryption) is also accessible \
        via HTTP (without encryption).",
    solution: "Ensure that your web server, application server, load balancer, etc. is configured to only serve such \
        content via HTTPS. Consider implementing HTTP Strict Transport Security.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        "https://owasp.org/www-community/Security_Headers",
        "https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security",
        "https://caniuse.com/stricttransportsecurity",
        "https://datatracker.ietf.org/doc/html/rfc6797",
    ],
    tags: &["OWASP_2025_A04", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CRYP-03", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// The same URL over http (ZAP `setSecure(false)`: only the scheme changes, so
/// the implicit https port 443 becomes the implicit http port 80).
fn http_target(https: &Target) -> Target {
    let port = if https.port == 443 { 80 } else { https.port };
    Target { scheme: "http".into(), host: https.host.clone(), port }
}

pub struct HttpsAsHttp;

impl ActiveRule for HttpsAsHttp {
    fn id(&self) -> u32 {
        10047
    }

    fn name(&self) -> &'static str {
        "HTTPS Content Available via HTTP"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if !cx.target().is_tls() || cx.not_found(cx.base_response()).await {
                return;
            }
            let target = http_target(cx.target());
            let pq = base_path_query(cx);
            let url = format!("{}{pq}", target.origin());
            if cx.stopped() || !cx.once(&format!("10047|{}|{url}", cx.base().method)) {
                return;
            }
            let Ok(resp) = cx.send_to(&target, cx.base_request().to_vec()).await else { return };
            if resp.status == 200 {
                let finding = ALERT.raise("", url.clone()).other_info(format!("ZAP attempted to connect via: {url}"));
                cx.report(finding, &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_targets() {
        let t = http_target(&Target::from_url("https://example.com/").unwrap());
        assert_eq!(t.origin(), "http://example.com");
        let t = http_target(&Target::from_url("https://example.com:8443/").unwrap());
        assert_eq!(t.origin(), "http://example.com:8443");
    }
}
