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

/// A listing's pattern (its match is the evidence), a text the page must also have (a
/// title alone can be an article's), and the server it identifies.
type Listing = (Regex, Option<&'static str>, &'static str);

static PATTERNS: LazyLock<Vec<Listing>> = LazyLock::new(|| {
    let re = |p: &str| Regex::new(p).expect("the patterns are static");
    vec![
        // Diverges from ZAP, which calls nginx's listing Apache's and misses its root
        // (`Index of /`): nginx's autoindex is told apart by its `../` line.
        (re(r"<title>Index of /[^<]*</title>"), Some(r#"<hr><pre><a href="../">../</a>"#), "nginx"),
        (re(r"(?ms)<title>Index of /[^<]+?</title>"), None, "Apache 2"),
        (re(r#"(?ms)<pre><A\s+HREF\s*=\s*"/[^>]*">\[To Parent Directory\]</A><br><br>"#), None, "Microsoft IIS"),
        // Diverges from ZAP: the listings of today's application servers.
        (re(r"<title>listing directory /[^<]*</title>"), Some(r#"<ul id="files""#), "Express (serve-index)"),
        (re(r"<title>Directory listing for /[^<]*</title>"), Some("<h1>Directory listing for /"), "Python http.server"),
        (re(r"<title>Directory Listing For \[?/[^<]*</title>"), Some("<h1>Directory Listing For "), "Apache Tomcat"),
        (
            re(
                r#"\A(?:<!doctype html>\n<meta name="viewport" content="width=device-width">\n)?<pre>\n(?:<a href="[^"]*">|</pre>)"#,
            ),
            None,
            "Go net/http",
        ),
    ]
});

/// Every pattern needs one of these; most pages have none.
const PREFILTER: &[&str] =
    &["<title>Index of /", "[To Parent Directory]", "<title>listing directory /", "<title>Directory ", "<pre>\n"];

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
        if !PREFILTER.iter().any(|p| body.contains(p)) {
            return;
        }
        for (re, also, server) in PATTERNS.iter() {
            if let Some(m) = re.find(body).filter(|_| also.is_none_or(|a| body.contains(a))) {
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

    fn listing(url: &str, body: &str) -> (String, String) {
        let f = msg(url).html(body).scan(&DirectoryBrowsing);
        assert_eq!(f.len(), 1, "{body}");
        (f[0].evidence.clone(), f[0].other_info.clone())
    }

    #[test]
    fn flags_listings_of_other_servers() {
        // Juice Shop's /ftp, /encryptionkeys and /support/logs (Express serve-index).
        let express = "<title>listing directory /ftp</title>\n<style>ul#files { width: 100% }</style></head>\
            <body class=\"directory\"><h1><a href=\".\">~</a> / <a href=\"ftp\">ftp</a></h1>\
            <ul id=\"files\" class=\"view-tiles\"><li><a href=\"ftp/acquisitions.md\" title=\"acquisitions.md\">";
        let (evidence, server) = listing("http://a.test/ftp", express);
        assert_eq!(
            (evidence.as_str(), server.as_str()),
            ("<title>listing directory /ftp</title>", "Web server identified: Express (serve-index)")
        );
        let python = "<title>Directory listing for /</title>\n</head>\n<body>\n<h1>Directory listing for /</h1>\n\
            <hr>\n<ul>\n<li><a href=\"app.py\">app.py</a></li>";
        assert_eq!(listing("http://a.test/", python).1, "Web server identified: Python http.server");
        let tomcat = "<title>Directory Listing For [/docs/]</title><body><h1>Directory Listing For [/docs/]</h1>";
        assert_eq!(listing("http://a.test/docs/", tomcat).1, "Web server identified: Apache Tomcat");
        let nginx = "<html>\r\n<head><title>Index of /</title></head>\r\n<body>\r\n<h1>Index of /</h1><hr><pre>\
            <a href=\"../\">../</a>\r\n<a href=\"backup/\">backup/</a>";
        assert_eq!(
            listing("http://a.test/", nginx),
            ("<title>Index of /</title>".into(), "Web server identified: nginx".into())
        );
        let go = "<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n\
            <a href=\"config.yml\">config.yml</a>\n</pre>\n";
        assert_eq!(listing("http://a.test/static/", go).1, "Web server identified: Go net/http");
        let old_go = "<pre>\n<a href=\"a.txt\">a.txt</a>\n</pre>\n";
        assert_eq!(listing("http://a.test/static/", old_go).1, "Web server identified: Go net/http");
    }

    #[test]
    fn ignores_normal_pages() {
        assert!(msg("https://a.test/").html("<title>Index of things</title>").scan(&DirectoryBrowsing).is_empty());
        // An article about listings, and a page that shows preformatted links.
        let article = "<title>Directory listing for /var/www: how to turn it off</title><h1>Turning off listings</h1>\
            <p>Python's server prints <code>&lt;h1&gt;Directory listing for /</code>.</p>";
        assert!(msg("https://a.test/blog/listing").html(article).scan(&DirectoryBrowsing).is_empty());
        let page = "<!doctype html><html><body><p>Links:</p><pre>\n<a href=\"a\">a</a>\n</pre></body></html>";
        assert!(msg("https://a.test/links").html(page).scan(&DirectoryBrowsing).is_empty());
        let spa = "<!doctype html><html><head><title>OWASP Juice Shop</title></head><body><app-root></app-root>";
        assert!(msg("https://a.test/ftp-help").html(spa).scan(&DirectoryBrowsing).is_empty());
    }
}
