//! brainproxy's own rule (100020): password hashes in a response. ZAP's Hash Disclosure (10097)
//! knows crypt formats only at its default threshold, since bare hex is as often an id or a
//! checksum; here bare hex counts when the field it is in is named like a password, and the
//! modern password-hash formats (Argon2, Django's PBKDF2) count anywhere.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use super::common::{is_css, is_javascript, is_source_map, is_text};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const SOLUTION: &str = "Never send password hashes to the client: leave the field out of the API's responses (an \
    allow-list of the fields each response may carry is safer than removing secret ones). Store passwords with a \
    slow, salted hash (Argon2id, scrypt or bcrypt), not a plain digest such as MD5 or SHA-1.";
const REFS: &[&str] = &[
    "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
];
const TAGS: &[&str] = &["OWASP_2025_A04", "OWASP_2021_A02", "API_2023_API3"];

static IN_FIELD: AlertDef = AlertDef {
    alert_ref: "100020-1",
    name: "Password Hash in Response",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 916,
    wasc: 13,
    description: "A response carries a field named like a password whose value is a hex digest (MD5, SHA-1, \
        SHA-256 or SHA-512). An unsalted digest of a password is cracked in seconds with word lists and lookup \
        tables, and the response shows it to anyone who can make the request.",
    solution: SOLUTION,
    references: REFS,
    tags: TAGS,
};

static FORMAT: AlertDef = AlertDef {
    alert_ref: "100020-2",
    name: "Password Hash in Response",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 916,
    wasc: 13,
    description: "A response carries a password hash in a password-hashing format (Argon2 or PBKDF2). A slow hash \
        resists cracking, but weak passwords still fall to a guessing attack once the hash is known.",
    solution: SOLUTION,
    references: REFS,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 2] = [&IN_FIELD, &FORMAT];

/// A JSON string field (or a JavaScript-object-like one) with a hex value of digest length.
static HEX_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["']([A-Za-z][\w-]{0,40})["']\s*:\s*["']([0-9a-fA-F]{32,128})["']"#).expect("static pattern")
});

static FORMATS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}\$[A-Za-z0-9+/]{16,}|\bpbkdf2_sha(?:1|256|512)\$\d{3,7}\$[A-Za-z0-9./+]{4,}\$[A-Za-z0-9./+=]{20,}",
    )
    .expect("static pattern")
});

/// Whether a field named `key` holds a password: `password`, `passwd`, `pwd`, `hash`,
/// `passwordHash`, `hashed_password`; not a reset token, a salt or a policy about passwords.
fn password_field(key: &str) -> bool {
    let k: String = key.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
    let named = k.contains("password") || k.contains("passwd") || k.contains("pwd") || k == "pass" || k == "hash";
    let other = ["token", "reset", "salt", "nonce", "policy", "hint", "length", "algo", "otp", "key"];
    named && !other.iter().any(|o| k.contains(o))
}

/// Digest lengths: MD5 (and NTLM), SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
fn digest_name(hex: &str) -> Option<&'static str> {
    let first = hex.as_bytes().first()?;
    // A run of one character is a placeholder, not a digest.
    if hex.bytes().all(|b| b.eq_ignore_ascii_case(first)) {
        return None;
    }
    Some(match hex.len() {
        32 => "MD5 (or NTLM)",
        40 => "SHA-1",
        56 => "SHA-224",
        64 => "SHA-256",
        96 => "SHA-384",
        128 => "SHA-512",
        _ => return None,
    })
}

pub struct PasswordHash;

impl PassiveRule for PasswordHash {
    fn id(&self) -> u32 {
        100020
    }

    fn name(&self) -> &'static str {
        "Password Hash in Response"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // Scripts and source maps hold samples and test fixtures, not the server's data.
        if !is_text(msg) || is_javascript(msg) || is_css(msg) || is_source_map(msg) {
            return;
        }
        let body = msg.body();
        // One finding per field name, however many records the response lists.
        let mut fields: BTreeMap<&str, (&str, &str, usize)> = BTreeMap::new();
        for c in HEX_FIELD.captures_iter(body) {
            let (Some(all), Some(key), Some(hex)) = (c.get(0), c.get(1), c.get(2)) else { continue };
            let Some(digest) = digest_name(hex.as_str()) else { continue };
            if password_field(key.as_str()) {
                fields.entry(key.as_str()).or_insert((all.as_str(), digest, 0)).2 += 1;
            }
        }
        for (key, (evidence, digest, n)) in fields {
            let times = if n == 1 { String::new() } else { format!(" It holds one in {n} places.") };
            out.push(
                IN_FIELD
                    .raise(key, evidence)
                    .other_info(format!("The field '{key}' holds what looks like a {digest} digest.{times}")),
            );
        }
        if let Some(m) = FORMATS.find(body) {
            out.push(FORMAT.raise("", m.as_str()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn json(url: &str, body: &str) -> Vec<Finding> {
        msg(url).header("Content-Type", "application/json; charset=utf-8").body(body).scan(&PasswordHash)
    }

    /// Juice Shop's /rest/memories lists every poster's user, password digest included.
    #[test]
    fn flags_digests_in_password_fields() {
        let memories = r#"{"status":"success","data":[{"User":{"id":13,"email":"bjoern@owasp.org","password":"9283f1b2e9669749081963be0462e466","role":"deluxe","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4"}},{"User":{"id":4,"password":"0c36e517e3fa95aabf1bbffc6744a4ef"}}]}"#;
        let f = json("http://a.test/rest/memories", memories);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!((f[0].def.alert_ref, f[0].param.as_str()), ("100020-1", "password"));
        assert_eq!(f[0].evidence, r#""password":"9283f1b2e9669749081963be0462e466""#);
        assert!(f[0].other_info.contains("MD5") && f[0].other_info.contains("2 places"), "{}", f[0].other_info);
        let f = json("http://a.test/u", r#"{"password_hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}"#);
        assert!(f[0].other_info.contains("SHA-1"), "{}", f[0].other_info);
    }

    #[test]
    fn flags_password_hash_formats_anywhere() {
        let argon = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
        let f = json("http://a.test/api/me", &format!(r#"{{"credential":"{argon}"}}"#));
        assert_eq!((f[0].def.alert_ref, f[0].evidence.as_str()), ("100020-2", argon));
        let django = "pbkdf2_sha256$600000$ZsSHkmw8Ue4f$pIP7rk2PBeb3EbAbRkmD6p8z1y8OgXJ9n3h3nE0YFkk=";
        let f = msg("http://a.test/admin/user/1/").html(&format!("<td>{django}</td>")).scan(&PasswordHash);
        assert_eq!(f[0].evidence, django);
    }

    /// Hex ids, checksums, tokens and commit hashes aren't password digests; a bundle's
    /// fixtures and a translation's labels aren't the server's data.
    #[test]
    fn ignores_other_hex_fields_bundles_and_translations() {
        let ids = r#"{"id":"5f2b9c1e8a4d3b2c1f0e9d8c","sessionId":"0123456789abcdef0123456789abcdef","etag":"d41d8cd98f00b204e9800998ecf8427e","sha":"da39a3ee5e6b4b0d3255bfef95601890afd80709","passwordResetToken":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4","passwordSalt":"0c36e517e3fa95aabf1bbffc6744a4ef","password":"00000000000000000000000000000000"}"#;
        assert!(json("http://a.test/api/x", ids).is_empty());
        let i18n = r#"{"LABEL_PASSWORD":"Password","INVALID_PASSWORD_LENGTH":"Password must be 5-40 characters"}"#;
        assert!(json("http://a.test/assets/i18n/en.json", i18n).is_empty());
        let bundle = r#"const fixture={password:"21232f297a57a5a743894a0e4a801fc3"};"#;
        let js = msg("http://a.test/main.js").header("Content-Type", "application/javascript").body(bundle);
        assert!(js.scan(&PasswordHash).is_empty());
        let map = r#"{"version":3,"sourcesContent":["{'password':'21232f297a57a5a743894a0e4a801fc3'}"]}"#;
        assert!(json("http://a.test/main.js.map", map).is_empty());
    }
}
