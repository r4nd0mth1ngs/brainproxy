//! Ported from ZAP PiiScanRule (pscanrules, Apache License 2.0).
//!
//! ZAP's optional BIN-list lookup (which raises confidence to High and adds
//! issuer details) is not ported: findings are always Medium confidence.

use std::sync::LazyLock;

use regex::Regex;

use super::common::{chars_back, chars_forward, element_source, is_css, is_image, is_valid_luhn};
use crate::scan::passive::util::{decode_entities, find_ci, tags};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10062",
    name: "PII Disclosure",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 359,
    wasc: 13,
    description: "The response contains Personally Identifiable Information, such as CC number, SSN and similar \
        sensitive data.",
    solution: "Check the response for the potential presence of personally identifiable information (PII), ensure \
        nothing sensitive is leaked by the application.",
    references: &[],
    tags: &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A03"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Runs of 3+ digit groups separated by (RE2/ASCII) whitespace.
static SEQUENCE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:[0-9]{3,}[\t\n\x0C\r ]*)+").unwrap());

/// ZAP's card types, in order, anchored (candidates are all digits, so ZAP's
/// `\b...\b` only ever matches the whole candidate).
static CARDS: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    [
        ("American Express", r"3[47][0-9]{13}"),
        ("DinersClub", r"3(?:0[0-5]|[68][0-9])[0-9]{11}"),
        ("Discover", r"6(?:011|5[0-9]{2})[0-9]{12}"),
        ("Jcb", r"(?:2131|1800|35[0-9]{3})[0-9]{11}"),
        ("Maestro", r"(?:5[0678][0-9]{2}|6304|6390|67[0-9]{2})[0-9]{8,15}"),
        ("Mastercard", r"(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}"),
        ("Visa", r"4[0-9]{12}(?:[0-9]{3})?"),
    ]
    .into_iter()
    .map(|(n, p)| (n, Regex::new(&format!(r"\A(?:{p})\z")).unwrap()))
    .collect()
});

const INLINE: &[&str] = &[
    "a", "abbr", "acronym", "b", "bdi", "bdo", "big", "cite", "code", "del", "dfn", "em", "font", "i", "ins", "kbd",
    "label", "mark", "q", "s", "samp", "small", "span", "strike", "strong", "sub", "sup", "time", "tt", "u", "var",
];

/// Approximates Jericho's TextExtractor: tags and comments removed (block-level
/// tags become spaces), script/style contents dropped, entities decoded and
/// whitespace collapsed.
fn extract_text(html: &str) -> String {
    let b = html.as_bytes();
    let mut raw = String::with_capacity(html.len());
    let mut i = 0;
    while let Some(off) = html[i..].find('<') {
        let lt = i + off;
        raw.push_str(&html[i..lt]);
        let rest = &html[lt..];
        if rest.starts_with("<!--") {
            i = rest.find("-->").map(|e| lt + e + 3).unwrap_or(b.len());
            continue;
        }
        let closing = rest.starts_with("</");
        let name_start = lt + if closing { 2 } else { 1 };
        let name_len = html[name_start..].bytes().take_while(|c| c.is_ascii_alphanumeric() || *c == b'-').count();
        if name_len == 0 && !rest.starts_with("<!") && !rest.starts_with("<?") {
            raw.push('<');
            i = lt + 1;
            continue;
        }
        let name = html[name_start..name_start + name_len].to_ascii_lowercase();
        // End of the tag, honouring quoted attribute values.
        let mut j = name_start + name_len;
        let mut quote = 0u8;
        while j < b.len() {
            match b[j] {
                q @ (b'"' | b'\'') if quote == 0 => quote = q,
                q if q == quote => quote = 0,
                b'>' if quote == 0 => break,
                _ => {}
            }
            j += 1;
        }
        i = (j + 1).min(b.len());
        if !INLINE.contains(&name.as_str()) {
            raw.push(' ');
        }
        if !closing && (name == "script" || name == "style") {
            i = find_ci(html, &format!("</{name}"), i).unwrap_or(b.len());
        }
    }
    raw.push_str(&html[i..]);
    let decoded = decode_entities(&raw);
    decoded.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

/// ZAP's isSci: the context looks like a float in exponent notation.
fn is_sci(containing: &str) -> bool {
    if !containing.contains(['e', 'E']) {
        return false;
    }
    let s: String = containing.chars().filter(|c| c.is_ascii_digit() || matches!(c, 'e' | 'E' | '-')).collect();
    s.parse::<f32>().is_ok()
}

fn scan_text(text: &str, out: &mut Vec<Finding>) {
    for g in SEQUENCE.find_iter(text) {
        // Up to 3 characters either side (none before if fewer than 3 exist).
        let back = chars_back(text, g.start(), 3);
        let s = if text[back..g.start()].chars().count() == 3 { back } else { g.start() };
        let e = chars_forward(text, g.end(), 3);
        let containing: String = text[s..e].chars().filter(|c| !c.is_ascii_whitespace()).collect();
        if containing.contains('_') {
            continue;
        }
        let original = g.as_str();
        let candidate: String = original.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        for (name, re) in CARDS.iter() {
            if !re.is_match(&candidate) {
                continue;
            }
            if containing.contains('.') {
                // Part of a decimal number (ZAP aborts the whole scan here).
                break;
            }
            if is_valid_luhn(&candidate) && !is_sci(&containing) {
                out.push(ALERT.raise("", original).other_info(format!("Credit Card Type detected: {name}")));
            }
        }
    }
}

pub struct Pii;

impl PassiveRule for Pii {
    fn id(&self) -> u32 {
        10062
    }

    fn name(&self) -> &'static str {
        "PII Disclosure"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if is_css(msg) || is_image(msg) {
            return;
        }
        let pdf = msg.content_type().contains("pdf") || msg.path.to_ascii_lowercase().ends_with(".pdf");
        if !(msg.is_html() || msg.is_json() || msg.is_xml()) || pdf {
            return;
        }
        let body = msg.body();
        // Cheap exit: a card number needs at least 12 digits.
        if body.bytes().filter(u8::is_ascii_digit).nth(11).is_none() {
            return;
        }
        let text = extract_text(body);
        if !text.trim().is_empty() {
            scan_text(&text, out);
        }
        for t in tags(body).iter().filter(|t| t.name == "script") {
            let src = element_source(body, t);
            if !src.trim().is_empty() {
                scan_text(src, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn extracts_visible_text() {
        let html = "<p>Card:</p><div>4111 <b>1111</b>&nbsp;x</div><script>var a='9';</script><!-- c -->end";
        assert_eq!(extract_text(html), "Card: 4111 1111\u{a0}x end");
    }

    #[test]
    fn flags_card_numbers() {
        let html = "<p>Your card: 4716 1869 7854 4330 is on file</p><script>var mc = '5555555555554444';</script>";
        let f = msg("https://a.test/").html(html).scan(&Pii);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].evidence, "4716 1869 7854 4330 ");
        assert_eq!(f[0].other_info, "Credit Card Type detected: Visa");
        assert_eq!(f[0].confidence, Confidence::Medium);
        assert_eq!(f[1].other_info, "Credit Card Type detected: Mastercard");
        let f = msg("https://a.test/").header("Content-Type", "application/json").body(r#"{"cc":"378282246310005"}"#);
        assert_eq!(f.scan(&Pii)[0].other_info, "Credit Card Type detected: American Express");
    }

    #[test]
    fn ignores_invalid_decimal_sci_and_other_types() {
        let html = "<p>4716186978544331 3.4716186978544330 4716186978544330e-2 id_4716186978544330</p>";
        assert!(msg("https://a.test/").html(html).scan(&Pii).is_empty());
        let txt = msg("https://a.test/").header("Content-Type", "text/plain").body("4716186978544330");
        assert!(txt.scan(&Pii).is_empty());
    }
}
