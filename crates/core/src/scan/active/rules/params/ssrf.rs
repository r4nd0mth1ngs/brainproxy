//! Ported from ZAP SsrfScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Needs the OOB listener (`brainproxy oob start`); without it the rule sends
//! nothing, like ZAP without an OAST service. Differences: an interaction raises
//! the alert, and ZAP's canary-in-the-response check is left out because the
//! listener answers with an empty body. The https payload needs DNS mode: in host
//! mode the token is in the URL path, which a TLS handshake never shows the listener.

use crate::oob::Payload;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40046",
    name: "Server Side Request Forgery",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 918,
    wasc: 20,
    description: "The web server receives a remote address and retrieves the contents of this URL, but it does not \
        sufficiently ensure that the request is being sent to the expected destination.",
    solution: "Do not accept remote addresses as request parameters, and if you must, ensure that they are validated \
        against an allow-list of expected values.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    tags: &["OWASP_2025_A05", "OWASP_2021_A10", "WSTG-v42-INPV-19", "HIPAA", "PCI_DSS", "OUT_OF_BAND"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// The URL to send for `payload` with `scheme`; None when the listener couldn't tell.
fn attack_url(payload: &Payload, scheme: &str) -> Option<String> {
    match scheme {
        "http" => Some(payload.url.clone()),
        _ if payload.dns => Some(payload.url.replacen("http://", &format!("{scheme}://"), 1)),
        _ => None,
    }
}

pub struct Ssrf;

impl ActiveRule for Ssrf {
    fn id(&self) -> u32 {
        40046
    }

    fn name(&self) -> &'static str {
        "Server Side Request Forgery"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            for scheme in ["http", "https"] {
                if cx.stopped() {
                    return;
                }
                let Some(payload) = cx.oob_payload() else { return };
                let Some(attack) = attack_url(&payload, scheme) else { continue };
                let request = cx.payload_request(&attack);
                let resp = cx.send(request.clone()).await.ok();
                let finding = ALERT.raise(cx.point().name.clone(), "").attack(attack);
                cx.oob_register(&payload, finding, &request, resp.as_ref());
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_the_listener_can_correlate() {
        let dns = Payload {
            token: "bpx".into(),
            host: "bpx.oob.example".into(),
            url: "http://bpx.oob.example/".into(),
            dns: true,
        };
        assert_eq!(attack_url(&dns, "http").as_deref(), Some("http://bpx.oob.example/"));
        assert_eq!(attack_url(&dns, "https").as_deref(), Some("https://bpx.oob.example/"));
        let host =
            Payload { token: "bpx".into(), host: "10.0.0.1:80".into(), url: "http://10.0.0.1/bpx".into(), dns: false };
        assert_eq!(attack_url(&host, "http").as_deref(), Some("http://10.0.0.1/bpx"));
        assert_eq!(attack_url(&host, "https"), None);
    }
}
