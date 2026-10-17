//! Ported from ZAP ViewstateScanRule (pscanrules, Apache License 2.0).
//!
//! 10032-4 ("Viewstate without MAC Signature (Unsure)") is raised by ZAP only at LOW threshold
//! and isn't ported. Where ZAP throws (a missing split chunk, a non-numeric field count, a
//! decoded value shorter than the 22 characters the MAC test reads), no alert is raised, as in
//! ZAP. Analyzer matches are listed sorted instead of in Java `HashSet` order.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use regex::Regex;

use crate::scan::passive::util::{tags, Tag};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &["OWASP_2025_A06", "OWASP_2025_A08", "OWASP_2021_A04", "OWASP_2017_A06", "SYSTEMIC"];
const MAC_REFS: &[&str] = &["https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff649308(v=pandp.10)"];

macro_rules! alert {
    ($r:literal, $name:literal, $risk:ident, $conf:ident, $desc:literal, $soln:literal, $refs:expr) => {
        AlertDef {
            alert_ref: $r,
            name: $name,
            risk: Risk::$risk,
            confidence: Confidence::$conf,
            cwe: 642,
            wasc: 14,
            description: $desc,
            solution: $soln,
            references: $refs,
            tags: TAGS,
        }
    };
}

static IP: AlertDef = alert!(
    "10032-1",
    "Potential IP Addresses Found in the Viewstate",
    Medium,
    Medium,
    "Potential IP addresses were found being serialized in the viewstate field.",
    "Verify the provided information isn't confidential.",
    &[]
);
static EMAIL: AlertDef = alert!(
    "10032-2",
    "Emails Found in the Viewstate",
    Medium,
    Medium,
    "Email addresses were found being serialized in the viewstate field.",
    "Verify the provided information isn't confidential.",
    &[]
);
static OLD_VERSION: AlertDef = alert!(
    "10032-3",
    "Old Asp.Net Version in Use",
    Low,
    Medium,
    "This website uses ASP.NET version 1.0 or 1.1.",
    "Ensure the engaged framework is still supported by Microsoft.",
    &[]
);
static NO_MAC: AlertDef = alert!(
    "10032-5",
    "Viewstate without MAC Signature (Sure)",
    High,
    Medium,
    "This website uses ASP.NET's Viewstate but without any MAC.",
    "Ensure the MAC is set for all pages on this website.",
    MAC_REFS
);
static SPLIT: AlertDef = alert!(
    "10032-6",
    "Split Viewstate in Use",
    Info,
    Low,
    "This website uses ASP.NET's Viewstate and its value is split into several chunks.",
    "None - this may be a deliberate tuning of the configuration as this isn't the default setting.",
    &[]
);

static ALERTS: [&AlertDef; 5] = [&IP, &EMAIL, &OLD_VERSION, &NO_MAC, &SPLIT];

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}").unwrap());
static IP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}").unwrap());

/// java.util.Base64's basic decoder: standard alphabet, optional padding, no whitespace.
pub(super) const JAVA_B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// ZAP's base64Decode: on a dangling last character, retries without it.
fn decode(value: &str) -> Option<String> {
    let bytes = JAVA_B64
        .decode(value)
        .ok()
        .or_else(|| (value.len() % 4 == 1).then(|| JAVA_B64.decode(&value[..value.len() - 1]).ok()).flatten())?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Hidden fields keyed by id (else name): every `<input>`, then any tag whose name starts with `__`.
fn hidden_fields(html: &str) -> BTreeMap<String, Tag> {
    let all = tags(html);
    let inputs = all.iter().filter(|t| t.name == "input");
    let named = all.iter().filter(|t| t.name != "input" && t.attr("name").is_some_and(|n| n.starts_with("__")));
    let mut map = BTreeMap::new();
    for t in inputs.chain(named) {
        if let Some(key) = t.attr("id").or(t.attr("name")) {
            map.insert(key.to_string(), t.clone());
        }
    }
    map
}

/// The (possibly reassembled) viewstate value and whether it was split.
fn viewstate(fields: &BTreeMap<String, Tag>) -> Option<(String, bool)> {
    let value = |k: &str| fields.get(k).and_then(|t| t.attr("value"));
    let Some(count) = fields.get("__VIEWSTATEFIELDCOUNT") else {
        return Some((value("__VIEWSTATE")?.to_string(), false));
    };
    let max: i32 = count.attr("value")?.parse().ok()?;
    let mut v = value("__VIEWSTATE")?.to_string();
    for i in 1..max {
        v.push_str(value(&format!("__VIEWSTATE{i}"))?);
    }
    Some((v, true))
}

pub struct Viewstate;

impl PassiveRule for Viewstate {
    fn id(&self) -> u32 {
        10032
    }

    fn name(&self) -> &'static str {
        "Viewstate"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let body = msg.body();
        if !body.contains("__VIEWSTATE") {
            return;
        }
        let Some((value, split)) = viewstate(&hidden_fields(body)) else { return };
        let asp_net1 = value.starts_with("dD");
        if !asp_net1 && !value.starts_with("/w") {
            return; // unknown version: ZAP treats it as invalid
        }
        let Some(decoded) = decode(&value) else { return };
        // ZAP indexes the Java (UTF-16) string; the MAC is assumed to be the last 20 characters.
        let u: Vec<u16> = decoded.encode_utf16().collect();
        let l = u.len();
        if l < 22 {
            return;
        }
        let marker: Vec<u16> = (if asp_net1 { ">>" } else { "dd" }).encode_utf16().collect();
        let mac_test1 = u[l - 22..l - 20] == marker[..];
        let mac_test2 = u[l - 2..] != marker[..];
        if !mac_test1 && !mac_test2 {
            out.push(NO_MAC.raise("", ""));
        }
        if asp_net1 {
            out.push(OLD_VERSION.raise("", ""));
        }
        for (def, re) in [(&EMAIL, &*EMAIL_RE), (&IP, &*IP_RE)] {
            let found: BTreeSet<&str> = re.find_iter(&decoded).map(|m| m.as_str()).collect();
            if !found.is_empty() {
                let list = found.into_iter().collect::<Vec<_>>().join(", ");
                out.push(def.raise("", "").other_info(format!("[{list}]")));
            }
        }
        if split {
            out.push(SPLIT.raise("", ""));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn b64(s: &str) -> String {
        // A leading U+00FF stands for the 0xff byte ASP.NET 2+ state starts with.
        let bytes = match s.strip_prefix("\u{ff}") {
            Some(rest) => [&[0xff][..], rest.as_bytes()].concat(),
            None => s.as_bytes().to_vec(),
        };
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn page(fields: &str) -> Vec<Finding> {
        msg("http://a.test/").html(&format!("<form>{fields}</form>")).scan(&Viewstate)
    }

    fn refs(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.def.alert_ref).collect()
    }

    #[test]
    fn asp_net2_without_mac_with_secrets() {
        // "/w" prefix: base64 of a value starting with 0xff 0x01.
        let state = format!("\u{ff}\u{1}admin@corp.test 10.0.0.12 {}dd", "x".repeat(30));
        let v = b64(&state);
        assert!(v.starts_with("/w"), "{v}");
        let f = page(&format!(r#"<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="{v}">"#));
        assert_eq!(refs(&f), ["10032-5", "10032-2", "10032-1"]);
        assert_eq!(f[1].other_info, "[admin@corp.test]");
        assert_eq!(f[2].other_info, "[10.0.0.12]");
    }

    #[test]
    fn asp_net2_with_mac_is_quiet() {
        let state = format!("\u{ff}\u{1}{}dd{}", "x".repeat(10), "M".repeat(20));
        let f = page(&format!(r#"<input type="hidden" id="__VIEWSTATE" value="{}">"#, b64(&state)));
        assert!(f.is_empty(), "{:?}", refs(&f));
    }

    #[test]
    fn split_and_old_version() {
        // "dD" prefix: ASP.NET 1.x ("t<" ...), MAC present.
        let state = format!("t<{}>>{}", "y".repeat(10), "M".repeat(20));
        let v = b64(&state);
        assert!(v.starts_with("dD"), "{v}");
        let (a, b) = v.split_at(8);
        let f = page(&format!(
            r#"<input type="hidden" name="__VIEWSTATEFIELDCOUNT" value="2"><input name="__VIEWSTATE" value="{a}">
               <input name="__VIEWSTATE1" value="{b}">"#
        ));
        assert_eq!(refs(&f), ["10032-3", "10032-6"]);
    }

    #[test]
    fn invalid_or_missing_viewstates_are_quiet() {
        assert!(page(r#"<input name="__VIEWSTATE" value="not base64!">"#).is_empty());
        assert!(page(r#"<input name="__VIEWSTATE" value="/wEPZA==">"#).is_empty()); // too short
        assert!(
            page(r#"<input name="__VIEWSTATEFIELDCOUNT" value="3"><input name="__VIEWSTATE" value="/w">"#).is_empty()
        );
        assert!(page(r#"<input name="__EVENTVALIDATION" value="/wEWAgK">"#).is_empty());
    }
}
