//! Ported from ZAP CacheControlScanRule (pscanrules, Apache License 2.0).

use super::common::{header_values, is_error, is_redirect, zap_is_text};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10015",
    name: "Re-examine Cache-control Directives",
    risk: Risk::Info,
    confidence: Confidence::Low,
    cwe: 525,
    wasc: 13,
    description: "The cache-control header has not been set properly or is missing, allowing the browser and \
        proxies to cache content. For static assets like css, js, or image files this might be intended, however, \
        the resources should be reviewed to ensure that no sensitive content will be cached.",
    solution: "For secure content, ensure the cache-control HTTP header is set with \"no-cache, no-store, \
        must-revalidate\". If an asset should be cached consider setting the directives \"public, max-age, \
        immutable\".",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control",
        "https://grayduck.mn/2021/09/13/cache-control-recommendations/",
    ],
    tags: &["OWASP_2025_A07", "OWASP_2021_A07", "OWASP_2017_A02", "WSTG-v42-ATHN-06", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

fn path_ends_with_ci(msg: &Message, exts: &[&str]) -> bool {
    let p = msg.path.as_bytes();
    exts.iter().any(|e| p.len() >= e.len() && p[p.len() - e.len()..].eq_ignore_ascii_case(e.as_bytes()))
}

/// ResourceIdentificationUtils.isImage: image Content-Type or an image file extension.
fn is_image(msg: &Message) -> bool {
    msg.content_type().contains("image")
        || path_ends_with_ci(msg, &[".bmp", ".ico", ".jpg", ".jpeg", ".gif", ".tiff", ".tif", ".png"])
}

fn is_javascript(msg: &Message) -> bool {
    msg.is_javascript() || path_ends_with_ci(msg, &[".js"])
}

fn is_css(msg: &Message) -> bool {
    msg.is_css() || path_ends_with_ci(msg, &[".css"])
}

pub struct CacheControl;

impl PassiveRule for CacheControl {
    fn id(&self) -> u32 {
        10015
    }

    fn name(&self) -> &'static str {
        "Re-examine Cache-control Directives"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_https() || msg.resp_body.is_empty() || msg.method == "POST" || is_image(msg) {
            return;
        }
        if is_redirect(msg.status) || is_error(msg.status) || !zap_is_text(msg) || is_javascript(msg) || is_css(msg) {
            return;
        }
        let cc = header_values(msg, "Cache-Control").collect::<Vec<_>>().join(", ").to_lowercase();
        let has_header = msg.resp_header("Cache-Control").is_some();
        if !has_header || !cc.contains("no-store") || !cc.contains("no-cache") || !cc.contains("must-revalidate") {
            out.push(ALERT.raise("Cache-Control", cc));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_missing_or_weak_cache_control() {
        let f = msg("https://a.test/").html("<p>").scan(&CacheControl);
        assert_eq!((f.len(), f[0].evidence.as_str()), (1, ""));
        let f = msg("https://a.test/")
            .html("<p>")
            .header("Cache-Control", "No-Cache")
            .header("Cache-Control", "private")
            .scan(&CacheControl);
        assert_eq!(f[0].evidence, "no-cache, private");
        assert_eq!(f[0].param, "Cache-Control");
    }

    #[test]
    fn ignores_good_header_and_out_of_scope() {
        let good = || msg("https://a.test/").html("<p>").header("Cache-Control", "no-cache, no-store, must-revalidate");
        assert!(good().scan(&CacheControl).is_empty());
        assert!(msg("http://a.test/").html("<p>").scan(&CacheControl).is_empty());
        assert!(msg("https://a.test/").html("<p>").method("POST").scan(&CacheControl).is_empty());
        assert!(msg("https://a.test/").html("<p>").status(302).scan(&CacheControl).is_empty());
        assert!(msg("https://a.test/").html("<p>").status(404).scan(&CacheControl).is_empty());
        assert!(msg("https://a.test/x.js").html("<p>").scan(&CacheControl).is_empty());
        assert!(msg("https://a.test/x.png").html("<p>").scan(&CacheControl).is_empty());
        assert!(msg("https://a.test/").header("Content-Type", "text/css").body("a{}").scan(&CacheControl).is_empty());
        assert!(msg("https://a.test/")
            .header("Content-Type", "application/pdf")
            .body("x")
            .scan(&CacheControl)
            .is_empty());
        assert!(msg("https://a.test/").html("").scan(&CacheControl).is_empty());
    }
}
