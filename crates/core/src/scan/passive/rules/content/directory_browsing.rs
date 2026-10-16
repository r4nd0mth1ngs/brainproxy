//! Ported from ZAP DirectoryBrowsingScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10033",
    name: "Directory Browsing",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 548,
    wasc: 16,
    description: "It is possible to view a listing of the directory contents. Directory listings may reveal hidden \
        scripts, include files, backup source files, etc., which can be accessed to reveal sensitive information.",
    solution: "Configure the web server to disable directory browsing.",
    references: &["https://cwe.mitre.org/data/definitions/548.html"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

static PATTERNS: LazyLock<[(Regex, &str); 2]> = LazyLock::new(|| {
    [
        (Regex::new(r"(?ms)<title>Index of /[^<]+?</title>").unwrap(), "Apache 2"),
        (
            Regex::new(r#"(?ms)<pre><A\s+HREF\s*=\s*"/[^>]*">\[To Parent Directory\]</A><br><br>"#).unwrap(),
            "Microsoft IIS",
        ),
    ]
});

pub struct DirectoryBrowsing;

impl PassiveRule for DirectoryBrowsing {
    fn id(&self) -> u32 {
        10033
    }

    fn name(&self) -> &'static str {
        "Directory Browsing"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let body = msg.body();
        // Cheap literal prefilter: both patterns need one of these.
        if !body.contains("<title>Index of /") && !body.contains("[To Parent Directory]") {
            return;
        }
        for (re, server) in PATTERNS.iter() {
            if let Some(m) = re.find(body) {
                out.push(ALERT.raise("", m.as_str()).other_info(format!("Web server identified: {server}")));
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
    fn flags_apache_and_iis_listings() {
        let f = msg("https://a.test/files/")
            .html("<html><head><title>Index of /files</title></head>")
            .scan(&DirectoryBrowsing);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "<title>Index of /files</title>");
        assert_eq!(f[0].other_info, "Web server identified: Apache 2");
        let iis = r#"<pre><A HREF="/">[To Parent Directory]</A><br><br> 1/1/2020 <A HREF="/x/">x</A>"#;
        let f = msg("https://a.test/x/").html(iis).scan(&DirectoryBrowsing);
        assert_eq!(f[0].other_info, "Web server identified: Microsoft IIS");
    }

    #[test]
    fn ignores_normal_pages() {
        assert!(msg("https://a.test/").html("<title>Index of things</title>").scan(&DirectoryBrowsing).is_empty());
    }
}
