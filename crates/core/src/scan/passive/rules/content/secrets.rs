//! brainproxy's own rule (100021): secrets in responses, scripts above all. A single-page app's
//! bundle is where keys and test credentials end up, and nothing else reads it for them.
//! Only formats that are hard to hit by chance count (a provider's key prefix and length, a
//! PEM private key with its body), and an assignment of a literal to a variable named like a
//! password or secret, with filters for labels, placeholders and field names.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use super::common::{cut_chars, is_css, is_font, is_image, is_source_map, is_text};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const REFS: &[&str] = &[
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
];

static KEY: AlertDef = AlertDef {
    alert_ref: "100021-1",
    name: "Secret Key in Response",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 798,
    wasc: 13,
    description: "The response contains a credential in a provider's own format (a private key, or a cloud, \
        payment, chat or source-hosting API key). Anyone who can load the response can use it with the rights \
        it was issued with.",
    solution: "Revoke the key and issue a new one, then keep secrets on the server: a browser needs no private \
        key or secret API key. Keys meant to be public (such as a browser API key) should be restricted to the \
        sites and APIs that use them.",
    references: REFS,
    tags: &["OWASP_2025_A04", "OWASP_2021_A02", "OWASP_2017_A03", "WSTG-v42-INFO-05"],
};

static ASSIGNED: AlertDef = AlertDef {
    alert_ref: "100021-2",
    name: "Hard-coded Password or Secret",
    risk: Risk::Medium,
    confidence: Confidence::Low,
    cwe: 798,
    wasc: 13,
    description: "The response assigns a literal value to a variable or field named like a password or a secret \
        (such as `testPassword = \"...\"` in a script, or `\"dbPassword\": \"...\"` in data). If it is a real \
        credential, everyone who loads the response has it.",
    solution: "Check whether the value is a working credential. If it is, change it and move it out of the code \
        or data the client gets: credentials for tests or other systems don't belong in what a browser loads.",
    references: REFS,
    tags: &["OWASP_2025_A04", "OWASP_2021_A02", "OWASP_2017_A03", "WSTG-v42-INFO-05"],
};

static ALERTS: [&AlertDef; 2] = [&KEY, &ASSIGNED];

/// A key format: what it is, its pattern (group 1, if any, is the random part the
/// placeholder checks look at), and its risk.
struct Format {
    what: &'static str,
    pattern: &'static str,
    risk: Risk,
}

const FORMATS: &[Format] = &[
    Format {
        what: "private key",
        // The body must follow (raw, or with `\n` escapes in a string): a header alone is a
        // parser's or a template's constant.
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:\s|\\[rn])+([A-Za-z0-9+/=]{40,})",
        risk: Risk::High,
    },
    Format { what: "AWS access key ID", pattern: r"\b(?:AKIA|ASIA)([A-Z2-7]{16})\b", risk: Risk::Medium },
    Format { what: "Stripe secret key", pattern: r"\b[sr]k_live_([0-9A-Za-z]{24,99})\b", risk: Risk::High },
    Format {
        what: "Slack token",
        pattern: r"\bxox[abprse]-(?:[0-9]{6,}-){1,3}([0-9A-Za-z]{20,48})\b",
        risk: Risk::High,
    },
    Format {
        what: "Slack webhook",
        pattern: r"https://hooks\.slack\.com/services/T[0-9A-Z]{6,12}/B[0-9A-Z]{6,12}/([0-9A-Za-z]{20,32})\b",
        risk: Risk::Medium,
    },
    Format {
        what: "GitHub token",
        pattern: r"\b(?:gh[pousr]_([0-9A-Za-z]{36})|github_pat_([0-9A-Za-z_]{82}))\b",
        risk: Risk::High,
    },
    // Browser keys are often public on purpose (Maps, Firebase); restricted, they are harmless.
    Format { what: "Google API key", pattern: r"\bAIza([0-9A-Za-z_\-]{35})(?:[^0-9A-Za-z_\-]|\z)", risk: Risk::Low },
];

static FORMAT_RES: LazyLock<Vec<Regex>> =
    LazyLock::new(|| FORMATS.iter().map(|f| Regex::new(f.pattern).expect("static pattern")).collect());

/// `name = "value"`, `name: 'value'`, `"name": "value"`, `` name=`value` ``, where the name
/// mentions a password or secret. A value has no spaces (so labels and messages don't count).
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b([a-z_$][\w$]{0,30}?(?:password|passwd|pwd|secret|api_?key|access_?key|auth_?token|private_?key)[\w$]{0,20})["']?\s*[:=]\s*["'`]([^"'`\s\\]{6,80})["'`]"#,
    )
    .expect("static pattern")
});

/// Names of fields that describe a password rather than hold one.
const DESCRIBING: &[&str] = &[
    "label",
    "placeholder",
    "hint",
    "error",
    "message",
    "msg",
    "title",
    "text",
    "type",
    "field",
    "name",
    "input",
    "control",
    "pattern",
    "regex",
    "length",
    "min",
    "max",
    "policy",
    "strength",
    "visible",
    "show",
    "hide",
    "toggle",
    "reset",
    "forgot",
    "confirm",
    "repeat",
    "question",
    "url",
    "path",
    "route",
    "endpoint",
    "header",
    "param",
    "query",
    "event",
    "selector",
    "class",
    "icon",
    "id",
    "mode",
    "format",
    "change",
    "required",
    "valid",
    "match",
];

/// Values that are placeholders or words, not secrets.
const PLACEHOLDERS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "changeme",
    "change_me",
    "changeit",
    "example",
    "undefined",
    "null",
    "none",
    "redacted",
    "masked",
    "hidden",
    "default",
    "placeholder",
    "your_password",
    "yourpassword",
    "mypassword",
    "new-password",
    "current-password",
    "one-time-code",
];

/// Shannon entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = s.chars().count() as f64;
    counts.values().map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
}

/// A key's random part that is a placeholder: `EXAMPLE`, `xxxx`, or too little variety.
fn placeholder_key(random: &str) -> bool {
    let lower = random.to_ascii_lowercase();
    ["example", "xxxx", "0000", "test", "dummy", "fake", "sample"].iter().any(|p| lower.contains(p))
        || entropy(random) < 3.0
}

/// Whether `value` assigned to `key` looks like a credential, not a label, a field's name
/// (`currentPassword`), a constant (`INVALID_PASSWORD`), a template or a placeholder.
fn credential(key: &str, value: &str) -> bool {
    let k = key.to_ascii_lowercase();
    let v = value.to_ascii_lowercase();
    let distinct = value.chars().collect::<std::collections::BTreeSet<_>>().len();
    let lower_word = value.bytes().all(|b| b.is_ascii_lowercase() || b == b'-' || b == b'_');
    let camel_identifier = value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|b| b.is_ascii_alphabetic())
        && value.bytes().any(|b| b.is_ascii_uppercase());
    let constant = value.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    !DESCRIBING.iter().any(|d| k.contains(d))
        && !PLACEHOLDERS.contains(&v.as_str())
        && !["pass", "pwd", "secret", "key", "token", "${", "{{", "%s", "%(", "<", ">"].iter().any(|p| v.contains(p))
        && !value.starts_with(['/', '#', '.', '@', '$', '*'])
        && !v.starts_with("http")
        && !value.contains('/')
        && distinct >= 4
        && !lower_word
        && !camel_identifier
        && !constant
}

pub struct Secrets;

impl PassiveRule for Secrets {
    fn id(&self) -> u32 {
        100021
    }

    fn name(&self) -> &'static str {
        "Secrets in Response"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // Source maps hold the project's tests and fixtures, whose keys are samples.
        let js_file = msg.path.to_ascii_lowercase().ends_with(".js");
        if !(is_text(msg) || js_file) || is_css(msg) || is_font(msg) || is_image(msg) || is_source_map(msg) {
            return;
        }
        let body = msg.body();
        let mut seen: Vec<&str> = Vec::new();
        for (f, re) in FORMATS.iter().zip(FORMAT_RES.iter()) {
            let found = re.captures_iter(body).find(|c| {
                let random = c.iter().skip(1).flatten().next().map_or("", |m| m.as_str());
                !placeholder_key(random)
            });
            let Some(c) = found else { continue };
            let Some(all) = c.get(0) else { continue };
            // A private key's evidence is its header line, not the key.
            let evidence = all.as_str().split(['\r', '\n', '\\']).next().unwrap_or("").trim_end_matches(['\'', '"']);
            seen.push(all.as_str());
            out.push(KEY.raise(f.what, evidence).risk(f.risk).other_info(format!("A {} is in the response.", f.what)));
        }
        let mut names: Vec<&str> = Vec::new();
        for c in ASSIGNMENT.captures_iter(body) {
            let (Some(all), Some(key), Some(value)) = (c.get(0), c.get(1), c.get(2)) else { continue };
            let (key, value) = (key.as_str(), value.as_str());
            if names.contains(&key) || seen.iter().any(|s| s.contains(value)) || !credential(key, value) {
                continue;
            }
            names.push(key);
            out.push(ASSIGNED.raise(key, cut_chars(all.as_str(), 200)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn js(body: &str) -> Vec<Finding> {
        msg("https://a.test/main.js").header("Content-Type", "application/javascript").body(body).scan(&Secrets)
    }

    fn kinds(f: &[Finding]) -> Vec<(&str, &str, Risk)> {
        f.iter().map(|f| (f.def.alert_ref, f.param.as_str(), f.risk)).collect()
    }

    #[test]
    fn flags_provider_keys_and_private_keys() {
        // The fake Stripe and Slack keys are split so push protection doesn't take them for real ones.
        let bundle = concat!(
            r#"var cfg={aws:"AKIAQ7XZ3M5RTK2WLB6P",region:"eu-west-1"};"#,
            r#"const k="-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n";"#,
            r#"stripe("sk_"#,
            r#"live_4eC39HqLyjWDarjtT1zdp7dc");slack="xox"#,
            r#"b-263594206564-2343454543-Fyf3hJ8TpLs2bBEkLmNqRsTu";"#,
            r#"gh="ghp_R8kd72Hs0qLmZp4XcVb3nW9tYuIoPa1sDfGh";maps="AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q";"#,
        );
        let f = js(bundle);
        assert_eq!(
            kinds(&f),
            [
                ("100021-1", "private key", Risk::High),
                ("100021-1", "AWS access key ID", Risk::Medium),
                ("100021-1", "Stripe secret key", Risk::High),
                ("100021-1", "Slack token", Risk::High),
                ("100021-1", "GitHub token", Risk::High),
                ("100021-1", "Google API key", Risk::Low),
            ]
        );
        assert_eq!(f[0].evidence, "-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(f[1].evidence, "AKIAQ7XZ3M5RTK2WLB6P");
    }

    /// Juice Shop's main.js carries the test user's password.
    #[test]
    fn flags_literal_passwords_and_secrets() {
        let f = js("this.testingUsername=`testing@juice-sh.op`,this.testingPassword=`IamUsedForTesting`}");
        assert_eq!(kinds(&f), [("100021-2", "testingPassword", Risk::Medium)]);
        assert_eq!(f[0].evidence, "testingPassword=`IamUsedForTesting`");
        let config = r#"{"db":{"host":"db","dbPassword":"S3cr3t!2024"},"client_secret":"8fJk2Lq9ZxR4"}"#;
        let f = msg("https://a.test/config.json").header("Content-Type", "application/json").body(config);
        let f = f.scan(&Secrets);
        assert_eq!(kinds(&f).iter().map(|k| k.1).collect::<Vec<_>>(), ["dbPassword", "client_secret"]);
    }

    /// What minified Angular, React and i18n files hold around passwords; documentation keys.
    #[test]
    fn ignores_labels_fields_placeholders_and_samples() {
        let bundle = concat!(
            r#"{path:"forgot-password",component:Xe},formControlName:"password",type:"password","#,
            r#"autocomplete:"new-password",passwordControl:new FormControl("",[]),this.error="Invalid password","#,
            r#"apiKeyHeader:"X-Api-Key",secretQuestion:"Your eldest siblings middle name?",password:"*********","#,
            r#"password:"${pw}",passwordStrength:"strong",newPassword:"currentPassword",secretKey:"SECRET_KEY","#,
            r#"password:"changeme",pwd:"aaaaaaaa",apiKey:"apiKeyValue",PASSWORD_PATTERN:"^(?=.*[0-9])","#,
            r#"aws:"AKIAIOSFODNN7EXAMPLE",gh:"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",k:"-----BEGIN PRIVATE KEY-----\n...","#,
            r#"stripe:"sk_"#,
            r#"live_xxxxxxxxxxxxxxxxxxxxxxxx",slack:"xox"#,
            r#"b-000000000000-000000000000-xxxxxxxxxxxxxxxxxxxxxxxx""#,
        );
        assert!(js(bundle).is_empty(), "{:?}", js(bundle));
        let i18n = r#"{"LABEL_PASSWORD":"Password","MANDATORY_PASSWORD":"Please provide a password.","INVALID_PASSWORD_LENGTH":"Password must be {{length}} characters"}"#;
        let f = msg("https://a.test/assets/i18n/en.json").header("Content-Type", "application/json").body(i18n);
        assert!(f.scan(&Secrets).is_empty());
        let map = r#"{"version":3,"sourcesContent":["const key = 'AKIAQ7XZ3M5RTK2WLB6P'; password = 'Hunter2!x'"]}"#;
        assert!(msg("https://a.test/main.js.map").body(map).scan(&Secrets).is_empty());
        let img = msg("https://a.test/a.png").header("Content-Type", "image/png").body("AKIAQ7XZ3M5RTK2WLB6P");
        assert!(img.scan(&Secrets).is_empty());
    }

    /// A script served without a JavaScript type is still read by its extension.
    #[test]
    fn reads_scripts_served_as_plain_text() {
        let f =
            msg("https://cdn.a.test/app.js").header("Content-Type", "text/plain").body(r#"x="AKIAQ7XZ3M5RTK2WLB6P""#);
        assert_eq!(f.scan(&Secrets).len(), 1);
        let f = msg("https://cdn.a.test/app.js").header("Content-Type", "application/octet-stream");
        assert_eq!(f.body(r#"x="AKIAQ7XZ3M5RTK2WLB6P""#).scan(&Secrets).len(), 1);
    }
}
