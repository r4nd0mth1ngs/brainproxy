//! Ported from ZAP HttPoxyScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Sends the page with a `Proxy` header naming the out-of-band listener. CGI turns the header
//! into `HTTP_PROXY`, which many HTTP clients take as their proxy setting, so an application
//! that then fetches anything makes the listener's name be looked up. ZAP starts a proxy of
//! its own on every local address; here the OOB listener stands in for it, and only in DNS
//! mode: a proxied request names the site it is for, not the proxy, so only the lookup of the
//! proxy's name carries the token. Without a listener with a domain the rule is skipped, as
//! the other out-of-band checks are. The attack carries a random cache buster ([`bust`]).

use crate::http::RawRequest;
use crate::scan::active::canary::bust;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10107",
    name: "Httpoxy - Proxy Header Misuse",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 20,
    wasc: 20,
    description: "The server initiated a proxied request via the proxy specified in the HTTP Proxy header of the \
        request.Httpoxy typically affects code running in CGI or CGI like environments.\nThis may allow attackers \
        to:\n* Proxy the outgoing HTTP requests made by the web application\n* Direct the server to open outgoing \
        connections to an address and port of their choosing or\n* Tie up server resources by forcing the vulnerable \
        software to use a malicious proxy.",
    solution: "The best immediate mitigation is to block Proxy request headers as early as possible, and before they \
        hit your application.",
    references: &["https://httpoxy.org/"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A06", "OWASP_2017_A09"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct Httpoxy;

impl ActiveRule for Httpoxy {
    fn id(&self) -> u32 {
        10107
    }

    fn name(&self) -> &'static str {
        "Httpoxy - Proxy Header Misuse"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let Some(p) = cx.oob_payload().filter(|p| p.dns) else { return };
            let proxy = p.url.trim_end_matches('/').to_string();
            // The page's own request, body and all, as ZAP's copy of it.
            let req = RawRequest::from_bytes(cx.base_request().to_vec()).set_header("Proxy", &proxy);
            let req = bust(req.as_bytes());
            let resp = cx.send(req.clone()).await.ok();
            let info = format!(
                "An outgoing message was proxied via [{proxy}], the host and port injected into the HTTP Proxy header."
            );
            let finding = ALERT.raise("Proxy", "").attack(format!("Proxy: {proxy}")).other_info(info);
            cx.oob_register(&p, finding, &req, resp.as_ref());
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::scan::active::rules::test_app::{get, html, post, scan, serve, Opts};

    /// What a vulnerable CGI app's HTTP client does with `HTTP_PROXY`: looks the proxy up
    /// (here, by asking the test's OOB DNS server).
    fn look_up(proxy: &str, dns: std::net::SocketAddr) {
        let host = proxy.trim_start_matches("http://").split(':').next().unwrap_or("");
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in host.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let _ = s.send_to(&q, dns);
    }

    async fn listener() -> (tokio::net::TcpListener, tokio::net::UdpSocket) {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (tcp, udp)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_cgi_app_that_takes_the_proxy_header() {
        let (tcp, udp) = listener().await;
        let dns = udp.local_addr().unwrap();
        // The app fetches what the form asks for, through HTTP_PROXY: so the form must go too.
        let port = serve(move |r| {
            if let (Some(p), Some(_)) = (r.header("proxy"), r.param("feed")) {
                look_up(p, dns);
            }
            html("<html>ok</html>")
        });
        let form = post(port, "/cgi-bin/app", "application/x-www-form-urlencoded", "feed=news");
        let (s, found) = scan(10107, vec![form], Opts { oob: Some((tcp, udp)), ..Default::default() }).await;
        assert_eq!(found.len(), 1, "{s:?}");
        assert!(found[0].attack.starts_with("Proxy: http://bp") && found[0].attack.contains(".oob.test"));
        assert_eq!(
            (found[0].risk.as_str(), found[0].param.as_str(), found[0].method.as_str()),
            ("high", "Proxy", "POST")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_app_that_ignores_it_and_a_scan_without_a_listener() {
        let (tcp, udp) = listener().await;
        let port = serve(|_| html("<html>ok</html>"));
        let (s, found) =
            scan(10107, vec![get(port, "/cgi-bin/app")], Opts { oob: Some((tcp, udp)), ..Default::default() }).await;
        assert!(found.is_empty());
        assert_eq!(s.requests, 1);
        let (s, _) = scan(10107, vec![get(port, "/cgi-bin/app")], Opts::default()).await;
        assert_eq!(s.requests, 0, "no listener: skipped");
    }
}
