//! brainproxy's own rule: a response advertises HTTP/3 (`Alt-Svc: h3=...`, RFC 7838 / RFC 9114).

use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "100005",
    name: "HTTP/3 Offered (Alt-Svc)",
    risk: Risk::Info,
    confidence: Confidence::High,
    cwe: 0,
    wasc: 0,
    description: "The response advertises HTTP/3 in its Alt-Svc header: the same site is also served over QUIC \
        (UDP). Clients that support HTTP/3 switch to it, so the HTTP/3 path is part of the attack surface: a web \
        application firewall, rate limit, access rule or logging that only sees TCP traffic may not apply to it.",
    solution: "Make sure every control in front of the application covers HTTP/3 as well as HTTP/1.1 and HTTP/2, \
        or stop advertising HTTP/3. Test the HTTP/3 path itself: brainproxy's send, fuzz, Replay and active scan \
        take --http3, and the active scan then compares HTTP/3 answers with TCP ones.",
    references: &["https://www.rfc-editor.org/rfc/rfc9114", "https://www.rfc-editor.org/rfc/rfc7838"],
    tags: &["WSTG-v42-CONF-01", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct AltSvcH3;

impl PassiveRule for AltSvcH3 {
    fn id(&self) -> u32 {
        100005
    }

    fn name(&self) -> &'static str {
        "HTTP/3 Offered (Alt-Svc)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // Alt-Svc only counts on a secure origin (RFC 7838 2.1), and QUIC is always TLS.
        if !msg.is_https() {
            return;
        }
        for value in msg.resp_headers_named("Alt-Svc") {
            let Some(Some(alt)) = crate::http::h3::parse_alt_svc(value, &msg.host) else { continue };
            let elsewhere = if alt.host.eq_ignore_ascii_case(&msg.host) {
                String::new()
            } else {
                format!(" That is another host than the site's: it is in scope only if the scope lists {}.", alt.host)
            };
            let other = format!(
                "HTTP/3 endpoint: {}:{} (UDP), for {} s.{elsewhere}",
                alt.host,
                alt.port,
                alt.max_age.as_secs()
            );
            out.push(ALERT.raise("", format!("Alt-Svc: {value}")).other_info(other));
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn reports_an_advertised_http3_endpoint() {
        let f = msg("https://a.test/").header("Alt-Svc", r#"h3=":443"; ma=86400"#).scan(&AltSvcH3);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, r#"Alt-Svc: h3=":443"; ma=86400"#);
        assert!(f[0].other_info.starts_with("HTTP/3 endpoint: a.test:443 (UDP)"), "{}", f[0].other_info);
        let f = msg("https://a.test/").header("alt-svc", r#"h3="cdn.test:8443""#).scan(&AltSvcH3);
        assert!(f[0].other_info.contains("another host"), "{}", f[0].other_info);
    }

    #[test]
    fn ignores_other_protocols_clear_and_http() {
        for v in [r#"h2=":443""#, r#"h3-29=":443""#, "clear"] {
            assert!(msg("https://a.test/").header("Alt-Svc", v).scan(&AltSvcH3).is_empty(), "{v}");
        }
        assert!(msg("http://a.test/").header("Alt-Svc", r#"h3=":443""#).scan(&AltSvcH3).is_empty());
    }
}
