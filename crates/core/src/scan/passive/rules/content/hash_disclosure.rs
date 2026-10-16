//! Ported from ZAP HashDisclosureScanRule (pscanrules, Apache License 2.0).
//!
//! Only the patterns ZAP uses at the default (MEDIUM) threshold are ported: the
//! High-confidence crypt formats. The Low-confidence bare-hex patterns (SHA-*,
//! MD4/MD5, salted SHA-1, LanMan) only run at LOW threshold in ZAP.
//! ZAP checks the request when it is sent and the response when it is received;
//! here both run on the captured exchange.

use std::sync::LazyLock;

use regex::Regex;

use super::common::{headers_as_string, is_javascript, is_text};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const SOLUTION: &str = "Ensure that hashes that are used to protect credentials or other resources are not leaked \
    by the web server or database. There is typically no requirement for password hashes to be accessible to the web \
    browser.";
const REFS: &[&str] = &["https://openwall.info/wiki/john/sample-hashes"];
const TAGS: &[&str] = &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A03"];

macro_rules! hash_alert {
    ($ident:ident, $ref:literal, $kind:literal) => {
        static $ident: AlertDef = AlertDef {
            alert_ref: $ref,
            name: concat!("Hash Disclosure - ", $kind),
            risk: Risk::High,
            confidence: Confidence::High,
            cwe: 497,
            wasc: 13,
            description: concat!("A hash was disclosed by the web server. - ", $kind),
            solution: SOLUTION,
            references: REFS,
            tags: TAGS,
        };
    };
}

hash_alert!(LANMAN_DES, "10097-1", "LanMan / DES");
hash_alert!(KERBEROS, "10097-2", "Kerberos AFS DES");
hash_alert!(OPENBSD_BLOWFISH, "10097-3", "OpenBSD Blowfish");
hash_alert!(MD5_CRYPT, "10097-4", "MD5 Crypt");
hash_alert!(SHA256_CRYPT, "10097-5", "SHA-256 Crypt");
hash_alert!(SHA512_CRYPT, "10097-6", "SHA-512 Crypt");
hash_alert!(BCRYPT, "10097-7", "BCrypt");
hash_alert!(NTLM, "10097-8", "NTLM");

static ALERTS: [&AlertDef; 8] =
    [&LANMAN_DES, &KERBEROS, &OPENBSD_BLOWFISH, &MD5_CRYPT, &SHA256_CRYPT, &SHA512_CRYPT, &BCRYPT, &NTLM];

/// ZAP's ordered pattern list (MEDIUM threshold part).
static PATTERNS: LazyLock<Vec<(Regex, &'static AlertDef)>> = LazyLock::new(|| {
    [
        (r"(?i)\$LM\$[a-f0-9]{16}", &LANMAN_DES),
        (r"(?i)\$K4\$[a-f0-9]{16},", &KERBEROS),
        (r"(?i)\$2a\$05\$[a-z0-9\+\-_./=]{53}", &OPENBSD_BLOWFISH),
        (r"(?i)\$2y\$05\$[a-z0-9\+\-_./=]{53}", &OPENBSD_BLOWFISH),
        (r"\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}", &MD5_CRYPT),
        (r"\$5\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}", &SHA256_CRYPT),
        (r"\$5\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}", &SHA256_CRYPT),
        (r"\$6\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}", &SHA512_CRYPT),
        (r"\$6\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}", &SHA512_CRYPT),
        (r"\$2\$[0-9]{2}\$[./0-9A-Za-z]{53}", &BCRYPT),
        (r"\$2a\$[0-9]{2}\$[./0-9A-Za-z]{53}", &BCRYPT),
        (r"\$3\$\$[0-9a-f]{32}", &NTLM),
        (r"\$NT\$[0-9a-f]{32}", &NTLM),
    ]
    .into_iter()
    .map(|(p, a)| (Regex::new(p).unwrap(), a))
    .collect()
});

/// Every pattern starts with one of these prefixes; most haystacks have none.
static PREFILTER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\$(?:lm|k4|2a|2y|1|5|6|2|3|nt)\$").unwrap());

pub struct HashDisclosure;

impl PassiveRule for HashDisclosure {
    fn id(&self) -> u32 {
        10097
    }

    fn name(&self) -> &'static str {
        "Hash Disclosure"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let req_headers = headers_as_string(&msg.req_headers);
        let req_body = msg.req_body_str();
        let mut haystacks = vec![req_headers.as_str(), req_body.as_str()];
        let resp_headers;
        if is_text(msg) && !is_javascript(msg) {
            resp_headers = headers_as_string(&msg.resp_headers);
            haystacks.push(&resp_headers);
            haystacks.push(msg.body());
        }
        // Request findings first, then response (ZAP order: send, then receive).
        for pair in haystacks.chunks(2) {
            let live: Vec<&str> = pair.iter().copied().filter(|h| PREFILTER.is_match(h)).collect();
            if live.is_empty() {
                continue;
            }
            for (re, alert) in PATTERNS.iter() {
                for hay in &live {
                    for m in re.find_iter(hay) {
                        out.push(alert.raise("", m.as_str()));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    const SHA512: &str =
        "$6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1";

    #[test]
    fn flags_crypt_hashes() {
        let body = format!("<td>{SHA512}</td><td>$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/</td>");
        let f = msg("https://a.test/").html(&body).scan(&HashDisclosure);
        let got: Vec<(&str, &str)> = f.iter().map(|f| (f.def.alert_ref, f.evidence.as_str())).collect();
        assert_eq!(got, [("10097-4", "$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/"), ("10097-6", SHA512)]);
        let bf = "$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe";
        let f = msg("https://a.test/").req_body(bf).scan(&HashDisclosure);
        let refs: Vec<&str> = f.iter().map(|f| f.def.alert_ref).collect();
        assert_eq!(refs, ["10097-3", "10097-7"]);
    }

    #[test]
    fn ignores_plain_hex_and_javascript() {
        let md5 = "21232f297a57a5a743894a0e4a801fc3 da39a3ee5e6b4b0d3255bfef95601890afd80709";
        assert!(msg("https://a.test/").html(md5).scan(&HashDisclosure).is_empty());
        let js = msg("https://a.test/a.js").header("Content-Type", "application/javascript").body(SHA512);
        assert!(js.scan(&HashDisclosure).is_empty());
    }
}
