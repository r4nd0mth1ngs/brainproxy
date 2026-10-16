//! Ported from ZAP TimestampDisclosureScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;
use time::OffsetDateTime;

use super::common::is_font;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10096",
    name: "Timestamp Disclosure - Unix",
    risk: Risk::Low,
    confidence: Confidence::Low,
    cwe: 497,
    wasc: 13,
    description: "A timestamp was disclosed by the application/web server. - Unix",
    solution: "Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to \
        disclose exploitable patterns.",
    references: &["https://cwe.mitre.org/data/definitions/200.html"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const EPOCH_Y2038: i64 = 2_147_483_647;

/// `\b(?:1\d|2[0-2])\d{8}\b`; ZAP's `(?!%)` is checked in code.
static PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u:\b)(?:1[0-9]|2[0-2])[0-9]{8}(?-u:\b)").unwrap());

const IGNORED_HEADERS: [&str; 11] = [
    "keep-alive",
    "cache-control",
    "etag",
    "age",
    "strict-transport-security",
    "report-to",
    "nel",
    "expect-ct",
    "ratelimit-reset",
    "x-ratelimit-reset",
    "x-rate-limit-reset",
];

fn shift_years(t: OffsetDateTime, years: i32) -> OffsetDateTime {
    let y = t.year() + years;
    t.replace_year(y).or_else(|_| t.replace_day(28).and_then(|t| t.replace_year(y))).unwrap_or(t)
}

/// MEDIUM threshold range: [now - 10 years, min(Y2038, now + 10 years)].
fn range() -> (i64, i64) {
    let now = OffsetDateTime::now_utc();
    (shift_years(now, -10).unix_timestamp(), shift_years(now, 10).unix_timestamp().min(EPOCH_Y2038))
}

/// `yyyy-MM-dd HH:mm:ss` (UTC).
fn format_ts(ts: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(ts) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        ),
        Err(_) => ts.to_string(),
    }
}

fn scan_text(name: &str, text: &str, (start, stop): (i64, i64), out: &mut Vec<Finding>) {
    for m in PATTERN.find_iter(text) {
        if text.as_bytes().get(m.end()) == Some(&b'%') {
            continue;
        }
        let Ok(ts) = m.as_str().parse::<i64>() else { continue };
        if ts < start || ts > stop {
            continue;
        }
        let other = format!("{}, which evaluates to: {}.", m.as_str(), format_ts(ts));
        out.push(ALERT.raise(name, m.as_str()).other_info(other));
    }
}

pub struct Timestamp;

impl PassiveRule for Timestamp {
    fn id(&self) -> u32 {
        10096
    }

    fn name(&self) -> &'static str {
        "Timestamp Disclosure"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if is_font(msg) {
            return;
        }
        let r = range();
        for (k, v) in &msg.resp_headers {
            if !IGNORED_HEADERS.iter().any(|h| k.eq_ignore_ascii_case(h)) {
                scan_text(k, v, r, out);
            }
        }
        scan_text("", msg.body(), r, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    #[test]
    fn flags_recent_timestamps_in_headers_and_body() {
        let ts = (now() - 86_400).to_string();
        let f = msg("https://a.test/")
            .header("X-Generated", &ts)
            .header("ETag", &ts)
            .body(&format!("{{\"created\":{ts}}}"))
            .scan(&Timestamp);
        assert_eq!(f.len(), 2);
        assert_eq!((f[0].param.as_str(), f[0].evidence.as_str()), ("X-Generated", ts.as_str()));
        assert_eq!(f[1].param, "");
        assert!(f[1].other_info.starts_with(&format!("{ts}, which evaluates to: ")));
        assert_eq!(format_ts(1704114087), "2024-01-01 13:01:27");
    }

    #[test]
    fn ignores_out_of_range_percent_and_fonts() {
        let old = (now() - 11 * 366 * 86_400).to_string();
        let recent = now().to_string();
        let body = format!("{old} {recent}% 12345678901 {recent}0");
        assert!(msg("https://a.test/").body(&body).scan(&Timestamp).is_empty());
        let font = msg("https://a.test/f.woff2").body(&recent);
        assert!(font.scan(&Timestamp).is_empty());
    }
}
