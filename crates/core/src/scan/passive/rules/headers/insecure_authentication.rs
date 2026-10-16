//! Ported from ZAP InsecureAuthenticationScanRule (pscanrules, Apache License 2.0).
//!
//! ZAP checks the request (Authorization) when it is sent and the response
//! (WWW-Authenticate) when it is received; both happen here, request first.

use std::sync::LazyLock;

use regex::Regex;

use super::common::{header_values, java_base64_decode};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &[
    "OWASP_2025_A01",
    "OWASP_2025_A04",
    "OWASP_2025_A07",
    "OWASP_2021_A01",
    "OWASP_2021_A02",
    "OWASP_2017_A02",
    "OWASP_2017_A03",
    "WSTG-v42-ATHN-01",
];

static CREDENTIALS: AlertDef = AlertDef {
    alert_ref: "10105-1",
    name: "Authentication Credentials Captured",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 287,
    wasc: 1,
    description: "An insecure authentication mechanism is in use. This allows an attacker on the network access to \
        the userid and password of the authenticated user. For Basic Authentication, the attacker must merely \
        monitor the network traffic until a Basic Authentication request is received, and then base64 decode the \
        username and password. For Digest Authentication, the attacker has access to the username, and possibly \
        also the password, if the hash (including a nonce) can be successfully cracked, or if a Man-In-The-Middle \
        attack is mounted.\nThe attacker eavesdrops on the network until an authentication has completed.",
    solution: "Use HTTPS, and use a secure authentication mechanism that does not transmit the userid or password \
        in an un-encrypted fashion. In particular, avoid use of the Basic Authentication mechanism, since this \
        trivial obfuscation mechanism is easily broken.",
    references: &[
        "https://owasp.org/www-community/attacks/Brute_force_attack",
        "https://en.wikipedia.org/wiki/Digest_access_authentication",
    ],
    tags: TAGS,
};

static WEAK_METHOD: AlertDef = AlertDef {
    alert_ref: "10105-2",
    name: "Weak Authentication Method",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 326,
    wasc: 4,
    description: "HTTP basic or digest authentication has been used over an unsecured connection. The credentials \
        can be read and then reused by someone with access to the network.",
    solution: "Protect the connection using HTTPS or use a stronger authentication mechanism.",
    references: &["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
    tags: TAGS,
};

static ALERTS: [&AlertDef; 2] = [&CREDENTIALS, &WEAK_METHOD];

// Java: .*username="([^"]+)".* with matches() (greedy, so the last username wins).
static DIGEST_USER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^.*username="([^"]+)".*$"#).unwrap());

/// Java `s.split(" ")`: trailing empty strings removed.
fn java_split_space(s: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = s.split(' ').collect();
    while parts.last() == Some(&"") {
        parts.pop();
    }
    parts
}

fn credentials(msg: &Message, v: &str) -> Option<Finding> {
    let lv = v.to_lowercase();
    if !lv.starts_with("basic ") && !lv.starts_with("digest ") {
        return None;
    }
    let mech = v.get(..6).unwrap_or(v).trim();
    let (method, uri) = (&msg.method, &msg.url);
    if mech.eq_ignore_ascii_case("basic") {
        let parts = java_split_space(v);
        if parts.len() != 2 {
            return None;
        }
        let (mut user, mut pass) = (None, None);
        if let Some(bytes) = java_base64_decode(parts[1]) {
            let decoded = String::from_utf8_lossy(&bytes).into_owned();
            match decoded.split_once(':') {
                Some((u, p)) => (user, pass) = (Some(u.to_string()), Some(p.to_string())),
                None => user = Some(decoded),
            }
        }
        let risk = if pass.is_some() { Risk::High } else { Risk::Medium };
        let other = format!(
            "[{method}] [{uri}] uses insecure authentication mechanism [{mech}], revealing username [{}] and password \
             [{}].",
            user.as_deref().unwrap_or("null"),
            pass.as_deref().unwrap_or("null")
        );
        return Some(CREDENTIALS.raise("", "").risk(risk).other_info(other));
    }
    let (_, rest) = v.split_once(' ')?;
    let user = DIGEST_USER.captures(rest)?.get(1)?.as_str();
    let other = format!(
        "[{method}] [{uri}] uses insecure authentication mechanism [{mech}], revealing username [{user}] and \
         additional information [{rest}]."
    );
    Some(CREDENTIALS.raise("", "").other_info(other))
}

pub struct InsecureAuthentication;

impl PassiveRule for InsecureAuthentication {
    fn id(&self) -> u32 {
        10105
    }

    fn name(&self) -> &'static str {
        "Weak Authentication Method"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.is_https() {
            return;
        }
        for v in msg.req_headers_named("Authorization").map(str::trim) {
            out.extend(credentials(msg, v));
        }
        for a in header_values(msg, "WWW-Authenticate") {
            let la = a.to_lowercase();
            if la.contains("basic") || la.contains("digest") {
                out.push(WEAK_METHOD.raise("", format!("WWW-Authenticate: {a}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_basic_credentials() {
        // dXNlcjpwYXNz = user:pass
        let f = msg("http://a.test/x").req_header("Authorization", "Basic dXNlcjpwYXNz").scan(&InsecureAuthentication);
        assert_eq!((f.len(), f[0].risk), (1, Risk::High));
        assert_eq!(
            f[0].other_info,
            "[GET] [http://a.test/x] uses insecure authentication mechanism [Basic], revealing username [user] and \
             password [pass]."
        );
        // dXNlcg== = user (no password), and undecodable values still alert at Medium.
        let f = msg("http://a.test/x").req_header("Authorization", "basic dXNlcg==").scan(&InsecureAuthentication);
        assert_eq!(f[0].risk, Risk::Medium);
        assert!(f[0].other_info.contains("username [user] and password [null]"));
        let f = msg("http://a.test/x").req_header("Authorization", "Basic !!").scan(&InsecureAuthentication);
        assert!(f[0].other_info.contains("username [null] and password [null]"));
    }

    #[test]
    fn flags_digest_and_www_authenticate() {
        let f = msg("http://a.test/x")
            .req_header("Authorization", "Digest username=\"bob\", realm=\"r\"")
            .header("WWW-Authenticate", "Basic realm=\"x\"")
            .scan(&InsecureAuthentication);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].risk, Risk::Medium);
        assert!(f[0]
            .other_info
            .ends_with("revealing username [bob] and additional information [username=\"bob\", realm=\"r\"]."));
        assert_eq!((f[1].def.alert_ref, f[1].evidence.as_str()), ("10105-2", "WWW-Authenticate: Basic realm=\"x\""));
    }

    #[test]
    fn ignores_https_bearer_and_malformed() {
        let m = msg("https://a.test/")
            .req_header("Authorization", "Basic dXNlcjpwYXNz")
            .header("WWW-Authenticate", "Basic");
        assert!(m.scan(&InsecureAuthentication).is_empty());
        let m = msg("http://a.test/")
            .req_header("Authorization", "Bearer abc")
            .req_header("Authorization", "Basic a b")
            .req_header("Authorization", "Digest realm=\"r\"")
            .header("WWW-Authenticate", "Bearer");
        assert!(m.scan(&InsecureAuthentication).is_empty());
    }
}
