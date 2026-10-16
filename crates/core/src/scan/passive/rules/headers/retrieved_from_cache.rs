//! Ported from ZAP RetrievedFromCacheScanRule (pscanrules, Apache License 2.0).

use super::common::header_values;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const DESC: &str = "The content was retrieved from a shared cache. If the response data is sensitive, personal or \
    user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a \
    user gaining complete control of the session of another user, depending on the configuration of the caching \
    components in use in their environment. This is primarily an issue where caching servers such as \"proxy\" \
    caches are configured on the local network. This configuration is typically found in corporate or educational \
    environments, for instance.";
const SOLN: &str = "Validate that the response does not contain sensitive, personal or user-specific information. \
    If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being \
    stored and retrieved from the cache by another user:\nCache-Control: no-cache, no-store, must-revalidate, \
    private\nPragma: no-cache\nExpires: 0\nThis configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching \
    servers to not store the response, and to not retrieve the response (without validation) from the cache, in \
    response to a similar request.";
const REFS: &[&str] = &[
    "https://datatracker.ietf.org/doc/html/rfc7234",
    "https://datatracker.ietf.org/doc/html/rfc7231",
    "https://www.rfc-editor.org/rfc/rfc9110.html",
];
const TAGS: &[&str] = &["OWASP_2025_A07", "OWASP_2021_A07", "OWASP_2017_A02", "WSTG-v42-ATHN-06", "SYSTEMIC"];

static X_CACHE_HIT: AlertDef = AlertDef {
    alert_ref: "10050-1",
    name: "Retrieved from Cache",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 525,
    wasc: 0,
    description: DESC,
    solution: SOLN,
    references: REFS,
    tags: TAGS,
};

static AGE: AlertDef = AlertDef {
    alert_ref: "10050-2",
    name: "Retrieved from Cache",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 525,
    wasc: 0,
    description: DESC,
    solution: SOLN,
    references: REFS,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 2] = [&X_CACHE_HIT, &AGE];

/// Java Long.parseLong: optional sign, ASCII digits, fits in i64.
fn parse_java_long(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

pub struct RetrievedFromCache;

impl PassiveRule for RetrievedFromCache {
    fn id(&self) -> u32 {
        10050
    }

    fn name(&self) -> &'static str {
        "Retrieved from Cache"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        for xc in header_values(msg, "X-Cache") {
            for seg in xc.split(',') {
                let seg = seg.strip_prefix(' ').unwrap_or(seg);
                let first = seg.split(' ').next().unwrap_or("");
                if first.to_uppercase() == "HIT" {
                    out.push(X_CACHE_HIT.raise("", seg));
                    return;
                }
            }
        }
        for age in header_values(msg, "Age") {
            if parse_java_long(age).is_some_and(|n| n >= 0) {
                out.push(AGE.raise("", format!("Age: {age}")).other_info(
                    "The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.",
                ));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_x_cache_hit_then_age() {
        let f = msg("https://a.test/")
            .header("X-Cache", "MISS from a, HIT from cache.kolich.local")
            .header("Age", "5")
            .scan(&RetrievedFromCache);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].def.alert_ref, f[0].evidence.as_str()), ("10050-1", "HIT from cache.kolich.local"));
        let f = msg("https://a.test/").header("Age", "+12").scan(&RetrievedFromCache);
        assert_eq!((f[0].def.alert_ref, f[0].evidence.as_str()), ("10050-2", "Age: +12"));
        assert!(f[0].other_info.contains("'Age' header"));
    }

    #[test]
    fn ignores_miss_and_bad_age() {
        let m = msg("https://a.test/").header("X-Cache", "MISS from a, HITS").header("Age", "-1").header("Age", "x");
        assert!(m.scan(&RetrievedFromCache).is_empty());
    }
}
