//! Ported from ZAP CrossDomainMisconfigurationScanRule (pscanrules, Apache License 2.0).

use super::common::{header_first, headers_block};
use crate::scan::passive::rules::content::common::{is_css, is_font, is_image};
use crate::scan::passive::util::url_host;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10098",
    name: "Cross-Domain Misconfiguration",
    // ZAP: Medium. A wildcard is Low here; an origin allowed with credentials is Medium.
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 264,
    wasc: 14,
    description: "Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) \
        misconfiguration on the web server.",
    solution: "Ensure that sensitive data is not available in an unauthenticated manner (using IP address \
        white-listing, for instance).\nConfigure the \"Access-Control-Allow-Origin\" HTTP header to a more \
        restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the \
        Same Origin Policy (SOP) in a more restrictive manner.",
    references: &[
        "https://vulncat.fortify.com/en/detail?category=HTML5&subcategory=Overly%20Permissive%20CORS%20Policy",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER_INFO: &str = "The CORS misconfiguration on the web server permits cross-domain read requests from \
    arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not \
    permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk \
    somewhat. This misconfiguration could be used by an attacker to access data that is available in an \
    unauthenticated manner, but which uses some other form of security, such as IP address white-listing.";

const ACAO: &str = "access-control-allow-origin";

pub struct CrossDomainMisconfiguration;

impl PassiveRule for CrossDomainMisconfiguration {
    fn id(&self) -> u32 {
        10098
    }

    fn name(&self) -> &'static str {
        "Cross-Domain Misconfiguration"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let Some(acao) = header_first(msg, ACAO) else { return };
        // Evidence: from the first textual occurrence in the header block to the end of that line.
        let block = headers_block(msg);
        let lower = block.to_ascii_lowercase();
        let Some(start) = lower.find(ACAO) else { return };
        let end = block[start..].find('\r').map(|e| start + e).unwrap_or(block.len());
        let evidence = &block[start..end];
        if acao == "*" {
            // Diverges from ZAP, which raises Medium on every response: `*` can't be combined
            // with credentials, so it exposes only what anyone could fetch, and on fonts,
            // images, media and stylesheets (made to be loaded cross-origin) not even that.
            if !is_static_asset(msg) {
                out.push(ALERT.raise("", evidence).other_info(OTHER_INFO));
            }
            return;
        }
        // Not in ZAP: what does let another site read a user's data is an origin allowed
        // together with credentials. Passively an allow-list can't be told from reflection,
        // so an origin of the same site (a sibling front end) is left alone and the rest
        // is Low confidence until a request from another origin confirms it.
        let credentials = header_first(msg, ACAC).is_some_and(|v| v.eq_ignore_ascii_case("true"));
        if !credentials {
            return;
        }
        let info = |what: &str| format!("{what} {CREDENTIALS_INFO}");
        if acao.eq_ignore_ascii_case("null") {
            let f = ALERT.raise("", evidence).risk(Risk::Medium).confidence(Confidence::Medium);
            out.push(f.other_info(info("The response allows the origin \"null\" with credentials.")));
            return;
        }
        let Some(origin) = msg.req_header("origin").map(str::trim) else { return };
        let Some(origin_host) = url_host(origin) else { return };
        if origin.eq_ignore_ascii_case(acao) && !same_site(&origin_host, &msg.host) {
            let f = ALERT.raise("", evidence).risk(Risk::Medium).confidence(Confidence::Low);
            out.push(f.other_info(info(&format!(
                "The request's origin {origin} is a different site, and the response allows it with credentials."
            ))));
        }
    }
}

const ACAC: &str = "access-control-allow-credentials";

const CREDENTIALS_INFO: &str = "A page on that origin can send requests with the user's cookies and read the \
    responses. If the server reflects any origin it is given, any site can; send the request with another \
    Origin to tell reflection from an allow-list.";

/// Files made to be loaded from other sites, whose content is public anyway.
fn is_static_asset(msg: &Message) -> bool {
    let ct = msg.content_type();
    is_font(msg) || is_image(msg) || is_css(msg) || ct.starts_with("audio/") || ct.starts_with("video/")
}

/// Whether two hosts share their last two labels (a.example.com, b.example.com): a rough
/// registrable domain, which on a public suffix such as co.uk errs towards same-site, so
/// towards saying nothing.
fn same_site(a: &str, b: &str) -> bool {
    let tail = |h: &str| -> String {
        let h = h.trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = h.rsplitn(3, '.').collect();
        labels.iter().take(2).rev().copied().collect::<Vec<_>>().join(".")
    };
    tail(a) == tail(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_wildcard_origin() {
        let f = msg("https://a.test/").header("Access-Control-Allow-Origin", "*").scan(&CrossDomainMisconfiguration);
        assert_eq!((f.len(), f[0].evidence.as_str()), (1, "Access-Control-Allow-Origin: *"));
        assert_eq!(f[0].other_info, OTHER_INFO);
    }

    /// A wildcard is Low and left out on assets made to be loaded cross-origin; an origin of
    /// another site allowed with credentials, which ZAP's rule never raised, is Medium.
    #[test]
    fn grades_by_what_another_site_can_read() {
        let f = msg("https://a.test/api").header("Access-Control-Allow-Origin", "*").scan(&CrossDomainMisconfiguration);
        assert_eq!(f[0].risk, Risk::Low);
        for (path, ct) in [("/f.woff2", "font/woff2"), ("/logo", "image/png"), ("/s.css", ""), ("/v", "video/mp4")] {
            let m = msg(&format!("https://a.test{path}")).header("Content-Type", ct);
            assert!(
                m.header("Access-Control-Allow-Origin", "*").scan(&CrossDomainMisconfiguration).is_empty(),
                "{path}"
            );
        }

        let reflected = |origin: &str, acao: &str, acac: &str| {
            msg("https://api.a.test/me")
                .req_header("Origin", origin)
                .header("Access-Control-Allow-Origin", acao)
                .header("Access-Control-Allow-Credentials", acac)
                .scan(&CrossDomainMisconfiguration)
        };
        let f = reflected("https://evil.test", "https://evil.test", "true");
        assert_eq!((f.len(), f[0].risk, f[0].confidence), (1, Risk::Medium, Confidence::Low));
        assert_eq!(f[0].evidence, "Access-Control-Allow-Origin: https://evil.test");
        let f = reflected("https://x.test", "null", "true");
        assert_eq!((f.len(), f[0].risk, f[0].confidence), (1, Risk::Medium, Confidence::Medium));
        // A front end of the same site, or no credentials: nothing.
        assert!(reflected("https://www.a.test", "https://www.a.test", "true").is_empty());
        assert!(reflected("https://evil.test", "https://evil.test", "false").is_empty());
        assert!(reflected("https://evil.test", "https://other.test", "true").is_empty());
    }

    #[test]
    fn ignores_specific_origin() {
        let m = msg("https://a.test/").header("Access-Control-Allow-Origin", "https://b.test");
        assert!(m.scan(&CrossDomainMisconfiguration).is_empty());
        assert!(msg("https://a.test/").scan(&CrossDomainMisconfiguration).is_empty());
    }
}
