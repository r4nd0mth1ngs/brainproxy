//! brainproxy's own rule (100008): JSON Web Token problems visible in traffic, without sending
//! anything. A token in a URL; and for tokens the server hands out (in a response): one with
//! `alg: none`, one without an expiry, and one whose claims hold a secret such as a password.
//! The active rule 100007 tests how the server checks tokens.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const REFS: &[&str] = &[
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
    "https://www.rfc-editor.org/rfc/rfc8725",
];

static IN_URL: AlertDef = AlertDef {
    alert_ref: "100008-1",
    name: "JWT in URL",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 598,
    wasc: 13,
    description: "A JSON Web Token is sent in the URL. URLs are written to server and proxy logs and browser \
        history, and sent to other sites in the Referer header, so the token can leak and be used by someone else.",
    solution: "Send tokens in the Authorization header or a cookie (Secure, HttpOnly), never in the URL.",
    references: REFS,
    tags: &["OWASP_2025_A07", "OWASP_2021_A07", "WSTG-v42-SESS-10"],
};

static NONE_ISSUED: AlertDef = AlertDef {
    alert_ref: "100008-2",
    name: "JWT Issued with 'none' Algorithm",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 347,
    wasc: 0,
    description: "The server hands out a JSON Web Token whose header says \"alg\": \"none\": it isn't signed. If \
        the server also accepts such tokens, anyone can make one for any user.",
    solution: "Sign every token, and accept only the algorithms the server issues (never 'none'). The active rule \
        100007 tests whether unsigned tokens are accepted.",
    references: REFS,
    tags: &["OWASP_2025_A04", "OWASP_2021_A02", "WSTG-v42-SESS-10"],
};

static NO_EXPIRY: AlertDef = AlertDef {
    alert_ref: "100008-3",
    name: "JWT Without Expiry",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 613,
    wasc: 0,
    description: "The server hands out a JSON Web Token with no 'exp' claim. Unless the server tracks it some \
        other way, the token never stops working, so one that leaks can be used for good.",
    solution: "Give every token an 'exp' a short time ahead, and use refresh tokens for longer sessions.",
    references: REFS,
    tags: &["OWASP_2025_A07", "OWASP_2021_A07", "WSTG-v42-SESS-10"],
};

static SENSITIVE: AlertDef = AlertDef {
    alert_ref: "100008-4",
    name: "JWT Contains Sensitive Data",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 315,
    wasc: 13,
    description: "A JSON Web Token the server hands out has a claim that looks like a secret (a password, a key, a \
        card or national ID number). A JWT's payload is only encoded, not encrypted: anyone who sees the token \
        can read it.",
    solution: "Keep secrets and personal data out of token claims; put an identifier in the token and look the \
        rest up on the server, or use an encrypted token (JWE).",
    references: REFS,
    tags: &["OWASP_2025_A04", "OWASP_2021_A02", "WSTG-v42-SESS-10"],
};

static ALERTS: [&AlertDef; 4] = [&IN_URL, &NONE_ISSUED, &NO_EXPIRY, &SENSITIVE];

static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*").unwrap());

/// Claim names (lower case, `_` and `-` removed) that hold a secret.
const SECRET_CLAIMS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "clientsecret",
    "privatekey",
    "apikey",
    "creditcard",
    "cardnumber",
    "ccnumber",
    "cvv",
    "ssn",
    "socialsecuritynumber",
    "nationalid",
    "passport",
];

/// The decoded header and payload of each distinct JWT in `text`.
fn tokens(text: &str) -> Vec<(String, Value, Value)> {
    let mut out: Vec<(String, Value, Value)> = Vec::new();
    for m in TOKEN.find_iter(text) {
        if out.iter().any(|(t, _, _)| t == m.as_str()) {
            continue;
        }
        let Ok(v) = crate::codec::decode_jwt(m.as_str()) else { continue };
        let (header, payload) = (v["header"].clone(), v["payload"].clone());
        if header.get("alg").and_then(Value::as_str).is_some() && payload.is_object() {
            out.push((m.as_str().to_string(), header, payload));
        }
    }
    out
}

/// The first claim name (at any depth) that names a secret.
fn secret_claim(v: &Value) -> Option<String> {
    match v {
        Value::Object(m) => m.iter().find_map(|(k, v)| {
            let norm: String = k.chars().filter(|c| *c != '_' && *c != '-').collect::<String>().to_ascii_lowercase();
            let filled = !matches!(v, Value::Null) && v.as_str() != Some("");
            if SECRET_CLAIMS.contains(&norm.as_str()) && filled && !v.is_object() {
                Some(k.clone())
            } else {
                secret_claim(v)
            }
        }),
        Value::Array(a) => a.iter().find_map(secret_claim),
        _ => None,
    }
}

pub struct JwtIssues;

impl PassiveRule for JwtIssues {
    fn id(&self) -> u32 {
        100008
    }

    fn name(&self) -> &'static str {
        "JWT Issues"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if let Some(query) = &msg.query {
            if let Some((token, _, _)) = tokens(query).into_iter().next() {
                let param = msg.query_params().into_iter().find(|(_, v)| v.contains(&token)).map(|(k, _)| k);
                out.push(IN_URL.raise(param.unwrap_or_default(), token));
            }
        }
        // Tokens the server hands out: in its headers (Set-Cookie, Location) or its body.
        let mut text: String = msg.resp_headers.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
        text.push_str(msg.body());
        let issued = tokens(&text);
        if let Some((token, ..)) = issued
            .iter()
            .find(|(_, h, _)| h.get("alg").and_then(Value::as_str).is_some_and(|a| a.eq_ignore_ascii_case("none")))
        {
            out.push(NONE_ISSUED.raise("", token.clone()));
        }
        if let Some((token, ..)) = issued.iter().find(|(_, _, p)| p.get("exp").is_none()) {
            out.push(NO_EXPIRY.raise("", token.clone()));
        }
        if let Some((token, claim)) = issued.iter().find_map(|(t, _, p)| secret_claim(p).map(|c| (t, c))) {
            out.push(
                SENSITIVE.raise("", token.clone()).other_info(format!("The token's payload has a '{claim}' claim.")),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn jwt(header: &str, payload: &str) -> String {
        format!("{}.{}.c2ln", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload))
    }

    #[test]
    fn token_in_url() {
        let t = jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"a","exp":1}"#);
        let f = msg(&format!("https://a.test/x?access_token={t}&b=1")).scan(&JwtIssues);
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].def.alert_ref, f[0].param.as_str(), f[0].evidence.as_str()),
            ("100008-1", "access_token", t.as_str())
        );
    }

    #[test]
    fn issued_tokens_none_no_expiry_and_secrets() {
        let t = jwt(r#"{"alg":"none"}"#, r#"{"sub":"a","user":{"password":"hunter2"}}"#);
        let f = msg("https://a.test/login").body(&format!(r#"{{"token":"{t}"}}"#)).scan(&JwtIssues);
        let refs: Vec<&str> = f.iter().map(|f| f.def.alert_ref).collect();
        assert_eq!(refs, ["100008-2", "100008-3", "100008-4"]);
        assert!(f[2].other_info.contains("'password'"));
        // In a cookie, signed, expiring, nothing secret: fine.
        let t = jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"a","exp":1,"password_changed":true,"pwd":""}"#);
        let f = msg("https://a.test/login").header("Set-Cookie", &format!("session={t}; HttpOnly")).scan(&JwtIssues);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn tokens_only_sent_by_the_client_are_left_to_the_active_rule() {
        let t = jwt(r#"{"alg":"none"}"#, r#"{"sub":"a"}"#);
        let f = msg("https://a.test/").req_header("Authorization", &format!("Bearer {t}")).scan(&JwtIssues);
        assert!(f.is_empty(), "{f:?}");
    }
}
