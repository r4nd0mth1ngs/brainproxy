//! Time-based one-time codes (RFC 6238) for a login's second factor.
//!
//! An auth profile can hold the secret an authenticator app would hold. The current code is
//! then a value like the password: templates name it `{{totp}}`, requests carry the
//! placeholder `«auth:PROFILE:totp»`, and the [`crate::auth::Vault`] works the code out as the
//! bytes go on the wire, so no record of a request holds a code and a request re-sent from
//! history gets a fresh one.
//!
//! The secret is base32, as sites show it beside the QR code, or the `otpauth://` URI the QR
//! code holds, whose algorithm, digits and period then apply.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::auth::Secret;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn parse(s: &str) -> Result<Algorithm> {
        Ok(match s.trim().to_ascii_lowercase().replace('-', "").as_str() {
            "sha1" => Algorithm::Sha1,
            "sha256" => Algorithm::Sha256,
            "sha512" => Algorithm::Sha512,
            _ => return Err(Error::InvalidInput(format!("unknown TOTP algorithm {s:?}; one of sha1, sha256, sha512"))),
        })
    }

    fn hmac(self) -> ring::hmac::Algorithm {
        match self {
            Algorithm::Sha1 => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::Sha256 => ring::hmac::HMAC_SHA256,
            Algorithm::Sha512 => ring::hmac::HMAC_SHA512,
        }
    }
}

/// A profile's TOTP setup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Totp {
    /// The shared secret: base32, or an `otpauth://` URI. Stored in the project file, or read
    /// from an environment variable when a code is needed.
    pub secret: Secret,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "six")]
    pub digits: u32,
    /// Seconds a code is valid for.
    #[serde(default = "thirty")]
    pub period: u64,
}

fn six() -> u32 {
    6
}
fn thirty() -> u64 {
    30
}

/// What works out codes: the decoded key and its parameters.
#[derive(Clone)]
pub struct Generator {
    key: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl std::fmt::Debug for Generator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Generator({:?}, {} digits, {}s)", self.algorithm, self.digits, self.period)
    }
}

fn check_params(digits: u32, period: u64) -> Result<()> {
    if !(4..=10).contains(&digits) {
        return Err(Error::InvalidInput(format!("TOTP digits must be 4 to 10, not {digits}")));
    }
    if !(1..=86_400).contains(&period) {
        return Err(Error::InvalidInput(format!("TOTP period must be 1 to 86400 seconds, not {period}")));
    }
    Ok(())
}

impl Totp {
    /// A setup from what the user gave: base32 or an `otpauth://` URI, whose parameters win
    /// over the defaults but not over one given beside it. A URI is stored as its secret alone.
    pub fn from_input(
        input: &str,
        algorithm: Option<Algorithm>,
        digits: Option<u32>,
        period: Option<u64>,
    ) -> Result<Totp> {
        let p = parse_secret(input)?;
        let t = Totp {
            secret: Secret::Literal(base32_encode(&p.key)),
            algorithm: algorithm.or(p.algorithm).unwrap_or_default(),
            digits: digits.or(p.digits).unwrap_or(6),
            period: period.or(p.period).unwrap_or(30),
        };
        check_params(t.digits, t.period)?;
        Ok(t)
    }

    /// A setup whose secret is read from `var` whenever a code is needed.
    pub fn from_env(var: &str, algorithm: Option<Algorithm>, digits: Option<u32>, period: Option<u64>) -> Result<Totp> {
        let t = Totp {
            secret: Secret::Env(var.to_string()),
            algorithm: algorithm.unwrap_or_default(),
            digits: digits.unwrap_or(6),
            period: period.unwrap_or(30),
        };
        check_params(t.digits, t.period)?;
        Ok(t)
    }

    pub fn validate(&self) -> Result<()> {
        check_params(self.digits, self.period)?;
        if let Secret::Literal(s) = &self.secret {
            parse_secret(s)?;
        }
        Ok(())
    }

    /// Reads the secret (now, for one in the environment). An `otpauth://` URI there brings
    /// its own algorithm, digits and period.
    pub fn generator(&self) -> Result<Generator> {
        let p = parse_secret(&self.secret.resolve()?)?;
        let g = Generator {
            key: p.key,
            algorithm: p.algorithm.unwrap_or(self.algorithm),
            digits: p.digits.unwrap_or(self.digits),
            period: p.period.unwrap_or(self.period),
        };
        check_params(g.digits, g.period)?;
        Ok(g)
    }

    /// The setup with a stored secret hidden, for display.
    pub fn redacted(&self) -> Totp {
        let mut t = self.clone();
        if let Secret::Literal(_) = t.secret {
            t.secret = Secret::Literal("********".into());
        }
        t
    }

    /// The secret as it may be quoted somewhere (as given, and as plain base32), for a
    /// report to mask. One in an unset variable is left out.
    pub(crate) fn secret_values(&self) -> Vec<String> {
        let Ok(raw) = self.secret.resolve() else { return vec![] };
        let mut out = vec![raw.trim().to_string()];
        if let Ok(p) = parse_secret(&raw) {
            let plain = base32_encode(&p.key);
            if !out.contains(&plain) {
                out.push(plain);
            }
        }
        out
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Generator {
    /// The time step `unix` falls in.
    pub fn step(&self, unix: u64) -> u64 {
        unix / self.period
    }

    /// The code of a time step (RFC 4226's truncation of the HMAC of the step).
    pub fn code_for_step(&self, step: u64) -> String {
        let key = ring::hmac::Key::new(self.algorithm.hmac(), &self.key);
        let mac = ring::hmac::sign(&key, &step.to_be_bytes());
        let mac = mac.as_ref();
        let at = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([mac[at] & 0x7f, mac[at + 1], mac[at + 2], mac[at + 3]]);
        let code = u64::from(bin) % 10u64.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    pub fn code_at(&self, unix: u64) -> String {
        self.code_for_step(self.step(unix))
    }

    pub fn now(&self) -> String {
        self.code_at(unix_now())
    }

    /// How long the current code has been valid, and how long it stays so.
    pub fn window(&self) -> (Duration, Duration) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let into = Duration::from_nanos((now.as_nanos() % (u128::from(self.period) * 1_000_000_000)) as u64);
        (into, Duration::from_secs(self.period).saturating_sub(into))
    }

    /// The time step, among those around `unix`, whose code is `code`: which code a person
    /// typed at about that time.
    pub fn step_of(&self, code: &str, unix: u64, around: u64) -> Option<u64> {
        let s = self.step(unix);
        (s.saturating_sub(around)..=s + around).find(|&step| self.code_for_step(step) == code)
    }
}

struct Parsed {
    key: Vec<u8>,
    algorithm: Option<Algorithm>,
    digits: Option<u32>,
    period: Option<u64>,
}

/// Base32, or an `otpauth://totp/...?secret=...` URI. Errors never repeat the input.
fn parse_secret(input: &str) -> Result<Parsed> {
    let input = input.trim();
    if !input.to_ascii_lowercase().starts_with("otpauth://") {
        return Ok(Parsed { key: base32_decode(input)?, algorithm: None, digits: None, period: None });
    }
    let bad = |what: &str| Error::InvalidInput(format!("the otpauth:// URI {what}"));
    let url = url::Url::parse(input).map_err(|_| bad("can't be read"))?;
    match url.host_str().map(str::to_ascii_lowercase).as_deref() {
        Some("totp") => {}
        Some("hotp") => return Err(bad("is for counter-based codes (hotp); only time-based ones (totp) are made")),
        _ => return Err(bad("isn't otpauth://totp/...")),
    }
    let mut p = Parsed { key: Vec::new(), algorithm: None, digits: None, period: None };
    for (k, v) in url.query_pairs() {
        match k.to_ascii_lowercase().as_str() {
            "secret" => p.key = base32_decode(&v)?,
            "algorithm" => p.algorithm = Some(Algorithm::parse(&v)?),
            "digits" => p.digits = Some(v.parse().map_err(|_| bad("has digits that aren't a number"))?),
            "period" => p.period = Some(v.parse().map_err(|_| bad("has a period that isn't a number"))?),
            _ => {}
        }
    }
    if p.key.is_empty() {
        return Err(bad("has no secret"));
    }
    Ok(p)
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 as people copy it: any case, spaces and hyphens between groups, padding or none.
fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !c.is_whitespace() && !matches!(c, '-' | '=')) {
        let v = BASE32.iter().position(|&b| b as char == c.to_ascii_uppercase()).ok_or_else(|| {
            Error::InvalidInput("the TOTP secret isn't base32 (letters A-Z and digits 2-7) or an otpauth:// URI".into())
        })?;
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return Err(Error::InvalidInput("the TOTP secret is empty".into()));
    }
    Ok(out)
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(BASE32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generator(key: &[u8], algorithm: Algorithm, digits: u32) -> Generator {
        Generator { key: key.to_vec(), algorithm, digits, period: 30 }
    }

    #[test]
    fn rfc_6238_test_vectors() {
        let sha1 = generator(b"12345678901234567890", Algorithm::Sha1, 8);
        let sha256 = generator(b"12345678901234567890123456789012", Algorithm::Sha256, 8);
        let sha512 =
            generator(b"1234567890123456789012345678901234567890123456789012345678901234", Algorithm::Sha512, 8);
        for (t, a, b, c) in [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ] {
            assert_eq!(sha1.code_at(t), a, "sha1 at {t}");
            assert_eq!(sha256.code_at(t), b, "sha256 at {t}");
            assert_eq!(sha512.code_at(t), c, "sha512 at {t}");
        }
        // Six digits are the last six of the eight.
        assert_eq!(generator(b"12345678901234567890", Algorithm::Sha1, 6).code_at(59), "287082");
        assert_eq!(sha1.step_of("94287082", 95, 2), Some(1));
        assert_eq!(sha1.step_of("00000000", 95, 2), None);
    }

    #[test]
    fn secrets_are_read_as_people_copy_them() {
        // "12345678901234567890" in base32.
        let b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let spaced = "gezd gnbv gy3t qojq-gezd gnbv gy3t qojq====";
        for s in [b32, spaced] {
            let t = Totp::from_input(s, None, None, None).unwrap();
            assert_eq!(t.secret, Secret::Literal(b32.into()));
            assert_eq!((t.algorithm, t.digits, t.period), (Algorithm::Sha1, 6, 30));
            assert_eq!(t.generator().unwrap().code_at(59), "287082");
        }
        let uri = format!(
            "otpauth://totp/Corp:alice%40corp.test?secret={b32}&issuer=Corp&algorithm=SHA256&digits=8&period=60"
        );
        let t = Totp::from_input(&uri, None, None, None).unwrap();
        assert_eq!((t.algorithm, t.digits, t.period), (Algorithm::Sha256, 8, 60));
        assert_eq!(t.secret, Secret::Literal(b32.into()));
        // A flag beside the URI wins.
        assert_eq!(Totp::from_input(&uri, None, Some(6), None).unwrap().digits, 6);
        assert_eq!(base32_encode(&base32_decode("MZXW6YTBOI").unwrap()), "MZXW6YTBOI");
    }

    #[test]
    fn bad_secrets_are_refused_without_being_repeated() {
        for bad in ["not base32!", "", "otpauth://hotp/x?secret=GEZDGNBV&counter=1", "otpauth://totp/x?issuer=y"] {
            let e = Totp::from_input(bad, None, None, None).unwrap_err().to_string();
            assert!(bad.is_empty() || !e.contains(bad), "{e}");
        }
        assert!(Totp::from_input("GEZDGNBV", None, Some(3), None).is_err());
        assert!(Totp::from_input("GEZDGNBV", None, None, Some(0)).is_err());
        assert!(Algorithm::parse("md5").is_err());
        assert_eq!(Algorithm::parse("SHA-512").unwrap(), Algorithm::Sha512);
    }

    #[test]
    fn a_stored_secret_is_masked_and_known_to_reports() {
        let t = Totp::from_input("otpauth://totp/x?secret=gezdgnbvgy3tqojq", None, None, None).unwrap();
        assert_eq!(t.redacted().secret, Secret::Literal("********".into()));
        assert_eq!(t.secret_values(), vec!["GEZDGNBVGY3TQOJQ".to_string()]);
        let env = Totp::from_env("BP_TEST_TOTP_UNSET_VAR", None, None, None).unwrap();
        assert_eq!(env.redacted(), env);
        assert!(env.secret_values().is_empty());
    }
}
