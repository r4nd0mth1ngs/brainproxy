//! Ported from ZAP InfoPrivateAddressDisclosureScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use super::common::is_text;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "2",
    name: "Private IP Disclosure",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 497,
    wasc: 13,
    description: "A private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x) or an Amazon EC2 private hostname (for \
        example, ip-10-0-56-78) has been found in the HTTP response body. This information might be helpful for \
        further attacks targeting internal systems.",
    solution: "Remove the private IP address from the HTTP response body. For comments, use JSP/ASP/PHP comment \
        instead of HTML/JavaScript comment which can be seen by client browsers.",
    references: &["https://datatracker.ietf.org/doc/html/rfc1918"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// ZAP's pattern without its look-arounds (checked in code): `(?<!\d\.)` before
/// the dotted forms, `(?!\.\d)` after the dotted and ip-10- forms and `(?!-\d)`
/// after the other EC2 forms. Group `addr` is ZAP's group 1.
static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    let o = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})";
    let b = r"(?-u:\b)";
    let addr = [
        format!(r"{b}10\.(?:{o}\.){{2}}{o}{b}"),
        format!(r"{b}172\.(?:3[01]|2[0-9]|1[6-9])\.{o}\.{o}{b}"),
        format!(r"{b}192\.168\.{o}\.{o}{b}"),
        format!(r"{b}ip-10-(?:{o}-){{2}}{o}{b}"),
        format!(r"{b}ip-172-(?:3[01]|2[0-9]|1[6-9])-{o}-{o}{b}"),
        format!(r"{b}ip-192-168-{o}-{o}{b}"),
    ]
    .join("|");
    let port = "(?:0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65(?:[0-4][0-9]{2}|5[0-2][0-9]|53[0-5]))";
    Regex::new(&format!(r"(?P<addr>{addr})(?::{port}{b})?")).unwrap()
});

/// Applies ZAP's look-arounds to a candidate address at `start..end`.
fn lookarounds_ok(text: &str, addr: &str, start: usize, end: usize) -> bool {
    let b = text.as_bytes();
    let next_is = |sep: u8| b.get(end) == Some(&sep) && b.get(end + 1).is_some_and(u8::is_ascii_digit);
    if addr.starts_with("ip-") {
        // ZAP's ip-10- alternative uses the dotted look-ahead.
        !next_is(if addr.starts_with("ip-10-") { b'.' } else { b'-' })
    } else {
        let after_digit_dot = start >= 2 && b[start - 1] == b'.' && b[start - 2].is_ascii_digit();
        !after_digit_dot && !next_is(b'.')
    }
}

/// Diverges from ZAP: `10.0.0.0/8` (a validator's or a network library's constant) names a
/// range, not a host that discloses anything.
fn is_cidr(text: &str, end: usize) -> bool {
    let b = text.as_bytes();
    b.get(end) == Some(&b'/') && b.get(end + 1).is_some_and(u8::is_ascii_digit)
}

/// Diverges from ZAP: an address written as IPv4-mapped IPv6 (`::ffff:172.17.0.1`) is how a
/// dual-stack server (Node, Java, .NET) writes the peer of a socket, so in a response it is
/// almost always the address the server saw this request come from ("Blocked illegal activity
/// by ::ffff:172.17.0.1"). Reached at a loopback or private address, the server sees the
/// tester at a private address of their own network (a Docker bridge's gateway, a LAN
/// address), which tells nothing new. Behind a public address, a private peer is the server's
/// own proxy or load balancer, which is worth reporting, as is any address in the dotted form
/// alone (a configured host such as `192.168.99.100:3000`).
fn echoed_peer(text: &str, start: usize, host: &str) -> bool {
    let before = &text.as_bytes()[..start];
    let mapped = before.len() >= 7 && before[before.len() - 7..].eq_ignore_ascii_case(b"::ffff:");
    mapped && internal_host(host)
}

/// Whether the target host is a loopback or private address (or `localhost`): one only a
/// tester inside its network reaches. A name is taken as public, whatever it resolves to.
fn internal_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback() || v4.is_private())
        }
        Err(_) => false,
    }
}

pub struct PrivateAddress;

impl PassiveRule for PrivateAddress {
    fn id(&self) -> u32 {
        2
    }

    fn name(&self) -> &'static str {
        "Private IP Disclosure"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !is_text(msg) {
            return;
        }
        let body = msg.body();
        let mut found: Vec<&str> = Vec::new();
        let mut pos = 0;
        while pos <= body.len() {
            let Some(c) = PATTERN.captures_at(body, pos) else { break };
            let (all, addr) = (c.get(0).unwrap(), c.name("addr").unwrap());
            if !lookarounds_ok(body, addr.as_str(), addr.start(), addr.end()) {
                // Like a failed look-around in Java: retry from the next position.
                pos = all.start() + 1;
                continue;
            }
            pos = all.end().max(all.start() + 1);
            if !addr.as_str().eq_ignore_ascii_case(&msg.host)
                && !is_cidr(body, all.end())
                && !echoed_peer(body, addr.start(), &msg.host)
            {
                found.push(all.as_str());
            }
        }
        if let Some(first) = found.first() {
            let mut other = found.join("\n");
            other.push('\n');
            out.push(ALERT.raise("", *first).other_info(other));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_private_addresses() {
        let body = "db at 10.0.1.25:5432, cache 172.16.5.4 and ip-10-0-56-78 plus 192.168.1.1";
        let f = msg("https://a.test/").html(body).scan(&PrivateAddress);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "10.0.1.25:5432");
        assert_eq!(f[0].other_info, "10.0.1.25:5432\n172.16.5.4\nip-10-0-56-78\n192.168.1.1\n");
    }

    #[test]
    fn applies_lookarounds_and_host_exclusion() {
        let body = "version 1.10.0.0.1 and 10.0.0.1.5 and 172.15.0.1 and 10.0.0.256 and ip-172-16-0-1-2";
        assert!(msg("https://a.test/").html(body).scan(&PrivateAddress).is_empty());
        assert!(msg("http://192.168.1.10/").html("at 192.168.1.10").scan(&PrivateAddress).is_empty());
        assert!(msg("https://a.test/").body("10.0.0.1").scan(&PrivateAddress).is_empty());
    }

    /// Range constants in a script are not addresses; a host next to them still is.
    #[test]
    fn ignores_cidr_ranges() {
        let js = "const r = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];";
        let m = msg("https://a.test/v.js").header("Content-Type", "application/javascript");
        assert!(m.body(js).scan(&PrivateAddress).is_empty());
        let f = msg("https://a.test/").html("net 10.0.0.0/8, gateway 10.0.0.1").scan(&PrivateAddress);
        assert_eq!(f[0].evidence, "10.0.0.1");
    }

    /// Juice Shop in Docker, reached at 127.0.0.1, names the tester's address as the bridge
    /// gateway shows it: that isn't a disclosure. A configured host on the same page still is.
    #[test]
    fn ignores_the_testers_own_address_echoed_by_an_internal_server() {
        let blocked = "<title>Error: Blocked illegal activity by ::ffff:172.17.0.1</title>";
        for target in ["http://127.0.0.1:3300/profile", "http://localhost/", "http://10.1.2.3/", "http://[::1]/"] {
            assert!(msg(target).html(blocked).scan(&PrivateAddress).is_empty(), "{target}");
        }
        let config = r#"{"uri":"http://192.168.99.100:3000"} blocked ::FFFF:172.17.0.1"#;
        let f = msg("http://127.0.0.1:3300/rest/admin/application-configuration").html(config).scan(&PrivateAddress);
        assert_eq!(
            (f[0].evidence.as_str(), f[0].other_info.as_str()),
            ("192.168.99.100:3000", "192.168.99.100:3000\n")
        );
        // The dotted form alone may be anything the server knows of, so it is reported.
        assert_eq!(msg("http://127.0.0.1/").html("by 172.17.0.1").scan(&PrivateAddress)[0].evidence, "172.17.0.1");
    }

    /// Behind a public name, a private peer is the site's own proxy or load balancer.
    #[test]
    fn reports_a_private_peer_of_a_public_site() {
        let f = msg("https://shop.test/").html("request from ::ffff:10.0.4.7 refused").scan(&PrivateAddress);
        assert_eq!(f[0].evidence, "10.0.4.7");
    }
}
