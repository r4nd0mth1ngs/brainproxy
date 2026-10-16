//! Ported from ZAP PaddingOracleScanRule (ascanrules, Apache License 2.0).

use std::sync::LazyLock;

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use regex::Regex;

use super::common;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90024",
    name: "Generic Padding Oracle",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 209,
    wasc: 20,
    description: "By manipulating the padding on an encrypted string, an attacker is able to generate an error message that \
        indicates a likely 'padding oracle' vulnerability. Such a vulnerability can affect any application or framework \
        that uses encryption improperly, such as some versions of ASP.net, Java Server Faces, and Mono. An attacker may \
        exploit this issue to decrypt data and recover encryption keys, potentially viewing and modifying confidential \
        data. This rule should detect the MS10-070 padding oracle vulnerability in ASP.net if CustomErrors are enabled \
        for that.",
    solution: "Update the affected server software, or modify the scripts so that they properly validate encrypted data before \
        attempting decryption.",
    references: &[
        "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070",
        "https://www.mono-project.com/docs/about-mono/vulnerabilities/",
        "https://bugzilla.redhat.com/show_bug.cgi?id=623799",
    ],
    tags: &["OWASP_2025_A04", "OWASP_2021_A02", "OWASP_2017_A06", "WSTG-v42-CRYP-02"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub(crate) const ERROR_PATTERNS: [&str; 7] =
    ["BadPaddingException", "padding", "runtime", "runtime error", "server error", "cryptographicexception", "crypto"];

// Java's decoders accept missing padding and non-canonical trailing bits.
const LENIENT: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_allow_trailing_bits(true)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent);
const B64: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT);
const B64URL: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT);
const B64_ENC: GeneralPurpose = base64::engine::general_purpose::STANDARD;
const B64URL_ENC: GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

static NUMERIC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+$").unwrap());
static HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:[a-fA-F0-9]{2})+$").unwrap());
static BASE64URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]+[012]$").unwrap());
static BASE64: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9/+]+={0,2}$").unwrap());

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Encoder {
    Hex,
    Base64Url,
    Base64,
}

impl Encoder {
    const ALL: [Encoder; 3] = [Encoder::Hex, Encoder::Base64Url, Encoder::Base64];

    pub(crate) fn encode(self, v: &[u8]) -> String {
        match self {
            Encoder::Hex => hex::encode(v),
            Encoder::Base64Url => {
                let e = B64URL_ENC.encode(v);
                let padding = (4 - e.len() % 4) % 4;
                format!("{e}{padding}")
            }
            Encoder::Base64 => B64_ENC.encode(v),
        }
    }

    pub(crate) fn decode(self, v: &str) -> Option<Vec<u8>> {
        match self {
            Encoder::Hex => HEX.is_match(v).then(|| hex::decode(v).ok()).flatten(),
            Encoder::Base64Url => {
                if !BASE64URL.is_match(v) {
                    return None;
                }
                // The last char is the padding count; ZAP adds its char code.
                let last = v.len() - 1;
                (last + v.as_bytes()[last] as usize).is_multiple_of(4).then(|| B64URL.decode(&v[..last]).ok()).flatten()
            }
            Encoder::Base64 => (BASE64.is_match(v) && v.len().is_multiple_of(4)).then(|| B64.decode(v).ok()).flatten(),
        }
    }
}

/// isEncrypted: at least 16 bytes, more than a quarter outside printable ASCII.
pub(crate) fn is_encrypted(v: &[u8]) -> bool {
    v.len() >= 16 && v.iter().filter(|&&b| !(0x20..=0x7f).contains(&b)).count() > v.len() / 4
}

pub struct PaddingOracle;

impl ActiveRule for PaddingOracle {
    fn id(&self) -> u32 {
        90024
    }

    fn name(&self) -> &'static str {
        "Generic Padding Oracle"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let value = cx.point().value.clone();
            // All-numeric values are probably not encoded.
            if NUMERIC.is_match(&value) {
                return;
            }
            for encoder in Encoder::ALL {
                if check(cx, &value, encoder).await {
                    break;
                }
            }
        })
    }
}

async fn check(cx: &Cx, value: &str, encoder: Encoder) -> bool {
    let Some(mut oracle) = encoder.decode(value).filter(|o| is_encrypted(o)) else { return false };
    let param = cx.point().name.clone();
    let Ok(control) = common::send_following(cx, &encoder.encode(&oracle)).await else { return false };
    if control.status != 200 {
        return false;
    }
    let last = oracle.len() - 1;
    oracle[last] ^= 0x1;
    let Ok(resp) = common::send_following(cx, &encoder.encode(&oracle)).await else { return false };
    if resp.status == 500 {
        let reason = resp.status_line.splitn(3, ' ').nth(2).unwrap_or("").to_string();
        cx.report(ALERT.raise(param.clone(), reason).attack(common::request_url(cx, &resp)), &resp);
    }
    let Ok(empty) = common::send_following(cx, "").await else { return false };
    for pattern in ERROR_PATTERNS {
        if resp.body_str().contains(pattern)
            && !control.body_str().contains(pattern)
            && !empty.body_str().contains(pattern)
        {
            cx.report(ALERT.raise(param, pattern).attack(common::request_url(cx, &resp)), &resp);
            return true;
        }
        if cx.stopped() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoders_round_trip() {
        let data: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(37).wrapping_add(200)).collect();
        assert!(is_encrypted(&data));
        for e in Encoder::ALL {
            assert_eq!(e.decode(&e.encode(&data)).as_deref(), Some(&data[..]), "{e:?}");
        }
        assert!(!is_encrypted(b"plain ascii text here"));
        assert!(!is_encrypted(&data[..8]));
        assert_eq!(Encoder::Hex.decode("abc"), None);
        assert_eq!(Encoder::Base64.decode("abc"), None);
    }
}
