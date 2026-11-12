//! brainproxy's own rule: the same request answered differently over HTTP/3 than over TCP.
//! Runs only when the scan sends over HTTP/3 (`--http3`), once per method and URL: the base
//! request over HTTP/3, then over TCP; a different status is confirmed with a second HTTP/3
//! request before it is reported.

use super::common::base_path_query;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ACCESS: AlertDef = AlertDef {
    alert_ref: "100006",
    name: "Access Control Differs over HTTP/3",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 284,
    wasc: 2,
    description: "The request was refused over TCP (HTTP/1.1 or HTTP/2) but answered over HTTP/3. A control in \
        front of the application, such as a web application firewall, a load balancer rule or an IP allow list, \
        may only see TCP traffic, so the HTTP/3 (QUIC) path goes around it.",
    solution: "Apply the same access rules and filtering to HTTP/3 as to HTTP/1.1 and HTTP/2, or stop offering \
        HTTP/3 (Alt-Svc) until they do.",
    references: &["https://www.rfc-editor.org/rfc/rfc9114", "https://www.rfc-editor.org/rfc/rfc7838"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-CONF-01"],
};

static DIFFERS: AlertDef = AlertDef {
    alert_ref: "100007",
    name: "Response Differs over HTTP/3",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 0,
    wasc: 0,
    description: "The same request got a different status over HTTP/3 than over TCP (HTTP/1.1 or HTTP/2). The \
        HTTP/3 path may reach a different server, configuration or set of controls than the TCP one.",
    solution: "Check why the two paths answer differently, and test the HTTP/3 path on its own (send, fuzz and \
        Replay take --http3).",
    references: &["https://www.rfc-editor.org/rfc/rfc9114"],
    tags: &["WSTG-v42-CONF-01"],
};

static ALERTS: [&AlertDef; 2] = [&ACCESS, &DIFFERS];

/// Statuses a control refusing a request answers with.
fn refused(status: u16) -> bool {
    matches!(status, 401 | 403 | 406 | 451)
}

/// Statuses that say more about load or the moment than about the request.
fn passing(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

/// Whether `resp` came over HTTP/3 (not over TCP after HTTP/3 couldn't be used).
fn over_http3(status_line: &str) -> bool {
    status_line.starts_with("HTTP/3 ")
}

pub struct Http3Differs;

impl ActiveRule for Http3Differs {
    fn id(&self) -> u32 {
        100006
    }

    fn name(&self) -> &'static str {
        "Response Differs over HTTP/3"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if !cx.sends_http3() || !cx.target().is_tls() || cx.stopped() {
                return;
            }
            let url = format!("{}{}", cx.target().origin(), base_path_query(cx));
            if !cx.once(&format!("100006|{}|{url}", cx.base().method)) {
                return;
            }
            let request = cx.base_request().to_vec();
            let Ok(h3) = cx.send(request.clone()).await else { return };
            if !over_http3(&h3.status_line) || cx.stopped() {
                return;
            }
            let Ok(tcp) = cx.send_tcp(request.clone()).await else { return };
            if h3.status == tcp.status || passing(h3.status) || passing(tcp.status) || cx.stopped() {
                return;
            }
            // The same answer over HTTP/3 again, so a flaky page isn't reported.
            let Ok(again) = cx.send(request).await else { return };
            if !over_http3(&again.status_line) || again.status != h3.status {
                return;
            }
            let other = format!("Over TCP: {}. Over HTTP/3: {}.", tcp.status_line.trim(), h3.status_line.trim());
            let def = if refused(tcp.status) && (200..400).contains(&h3.status) { &ACCESS } else { &DIFFERS };
            cx.report(def.raise("", h3.status_line.trim().to_string()).other_info(other), &h3);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_refusals_and_noise() {
        assert!(refused(403) && refused(401) && !refused(404) && !refused(200));
        assert!(passing(503) && passing(429) && !passing(403));
        assert!(over_http3("HTTP/3 200") && !over_http3("HTTP/1.1 200 OK") && !over_http3("HTTP/2 200"));
    }
}
