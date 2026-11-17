//! Ported from ZAP ApplicationErrorScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use super::common::{
    cut_chars, generic_in_data, is_css, is_generic_phrase, is_javascript, is_source_map, xml_unescape,
};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90022",
    name: "Application Error Disclosure",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 550,
    wasc: 13,
    description: "This page contains an error/warning message that may disclose sensitive information like the \
        location of the file that produced the unhandled exception. This information can be used to launch further \
        attacks against the web application. The alert could be a false positive if the error message is found \
        inside a documentation page.",
    solution: "Review the source code of this page. Implement custom error pages. Consider implementing a mechanism \
        to provide a unique error reference/identifier to the client (browser) while logging the details on the \
        server side and not exposing them to the user.",
    references: &[],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-ERRH-01", "WSTG-v42-ERRH-02"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub(crate) const EMBEDDED: &str = include_str!("../../data/application_errors.xml");

/// ZAP's ContentMatcher patterns: (literal strings, regexes), each in file order.
struct Matcher {
    strings: Vec<String>,
    string_set: RegexSet,
    regexes: Vec<Regex>,
    regex_set: RegexSet,
}

/// Java regex escapes that mean something else (or nothing) in Rust: `\<` and
/// `\>` are literals in Java but word-boundary assertions in Rust.
fn java_regex_to_rust(p: &str) -> String {
    p.replace(r"\<", "<").replace(r"\>", ">")
}

fn parse_patterns(data: &str) -> (Vec<String>, Vec<String>) {
    let (mut strings, mut regexes) = (Vec::new(), Vec::new());
    let mut rest = data;
    while let Some(i) = rest.find("<Pattern ") {
        rest = &rest[i..];
        let Some(gt) = rest.find('>') else { break };
        let attrs = &rest[..gt];
        let Some(end) = rest.find("</Pattern>") else { break };
        let text = xml_unescape(&rest[gt + 1..end]);
        if attrs.contains("type=\"regex\"") {
            regexes.push(java_regex_to_rust(&text));
        } else {
            strings.push(text);
        }
        rest = &rest[end..];
    }
    (strings, regexes)
}

static MATCHER: LazyLock<Matcher> = LazyLock::new(|| {
    let (strings, regex_src) = parse_patterns(crate::data::get("application_errors.xml"));
    let string_set = RegexSet::new(strings.iter().map(|s| regex::escape(s))).unwrap();
    let regexes = regex_src.iter().map(|r| Regex::new(r).unwrap()).collect();
    let regex_set = RegexSet::new(&regex_src).unwrap();
    Matcher { strings, string_set, regexes, regex_set }
});

/// Number of patterns; every regex must compile (see `crate::data`).
pub(crate) fn validate(text: &str) -> crate::Result<usize> {
    let (strings, regexes) = parse_patterns(text);
    RegexSet::new(&regexes).map_err(|e| crate::Error::InvalidInput(e.to_string()))?;
    Ok(strings.len() + regexes.len())
}

/// ResourceIdentificationUtils.responseContainsControlChars: binary content.
fn contains_control_chars(body: &[u8]) -> bool {
    body.iter().any(|&b| b <= 0x08 || (0x0E..=0x1F).contains(&b))
}

/// A stack trace in a 2xx HTML page is nearly always an example (documentation, a tutorial,
/// a Q&A page), so traces count only in error responses and in data an API answers with;
/// a database driver's or a framework's error text counts anywhere, as ZAP's list does.
#[derive(PartialEq)]
enum Kind {
    Trace,
    Error,
}

/// An error format of today's stacks, which ZAP's list (PHP, ASP and JDBC era) lacks.
struct Signature {
    what: &'static str,
    pattern: &'static str,
    kind: Kind,
    risk: Risk,
    /// How many matches it takes: one `at file:line:col` can be prose, two are a trace.
    min: usize,
}

/// The rest of a driver's message, up to the end of the line, tag or JSON string.
macro_rules! message_tail {
    () => {
        r#"(?:[^<\n"\\]|\\.){0,100}"#
    };
}

/// Brainproxy's own signatures, kept apart from ZAP's data file so drift checks stay exact.
/// In order of preference: a database error says more than the trace around it.
const SIGNATURES: &[Signature] = &[
    Signature {
        what: "SQLite error",
        pattern: concat!(
            r"\bSQLITE_(?:ERROR|CONSTRAINT|MISMATCH|RANGE|READONLY|CORRUPT|CANTOPEN|SCHEMA|TOOBIG|NOTADB|IOERR)\b",
            message_tail!()
        ),
        kind: Kind::Error,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "MySQL error",
        pattern: concat!(
            r"\bER_(?:PARSE_ERROR|BAD_FIELD_ERROR|NO_SUCH_TABLE|BAD_TABLE_ERROR|WRONG_VALUE_COUNT_ON_ROW|DUP_ENTRY)\b",
            message_tail!()
        ),
        kind: Kind::Error,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "Sequelize (Node.js ORM) error",
        pattern: r"\bSequelize(?:Database|UniqueConstraint|ForeignKeyConstraint|ExclusionConstraint|Connection|ConnectionRefused|HostNotFound|AccessDenied|Timeout)Error\b",
        kind: Kind::Error,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "MongoDB error",
        pattern: concat!(r"\bMongo(?:Server|Network|Parse|Bulk|Write)Error\b", message_tail!()),
        kind: Kind::Error,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "ASP.NET error page",
        pattern: r"Server Error in '[^'\n<]{0,100}' Application\.",
        kind: Kind::Error,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "Django debug page",
        pattern: r"you have <code>DEBUG = True</code>",
        kind: Kind::Error,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "PHP fatal error",
        pattern: r"(?:PHP )?(?:Fatal|Parse) error: +[^\n<]{1,300}? in (?:/|[A-Za-z]:\\)[^\s<:]{1,300}\.php(?::\d+| on line \d+)",
        kind: Kind::Error,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "Python traceback",
        pattern: r#"Traceback \(most recent call last\):\s+File (?:"|&quot;)"#,
        kind: Kind::Trace,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "Go panic",
        pattern: r"goroutine \d+ \[running\]:",
        kind: Kind::Trace,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "Java stack trace",
        pattern: r"\bat (?:[\w.$]+/)?(?:[A-Za-z_$][\w$]*\.){2,}[\w$<>]+\((?:[\w$]+\.java:\d+|Native Method|Unknown Source)\)",
        kind: Kind::Trace,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: ".NET stack trace",
        pattern: r"\bat (?:System|Microsoft)\.[\w.`\[\],]+\([^)\n]{0,200}\)",
        kind: Kind::Trace,
        risk: Risk::Medium,
        min: 1,
    },
    Signature {
        what: "Node.js stack trace",
        pattern: r"\bat (?:(?:new |async )?[\w$.<>\[\] ]{1,120}? \()?(?:/|[A-Za-z]:\\|file:///|node:)[^\s()<>']{1,300}?:\d+:\d+\b",
        kind: Kind::Trace,
        risk: Risk::Medium,
        min: 2,
    },
    Signature {
        what: "Spring Boot error page",
        pattern: r"<h1>Whitelabel Error Page</h1>",
        kind: Kind::Error,
        risk: Risk::Low,
        min: 1,
    },
];

static SIGNATURE_SET: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new(SIGNATURES.iter().map(|s| s.pattern)).expect("the signatures are static"));
static SIGNATURE_RES: LazyLock<Vec<Regex>> =
    LazyLock::new(|| SIGNATURES.iter().map(|s| Regex::new(s.pattern).expect("the signatures are static")).collect());

/// The first of [`SIGNATURES`] in the body, as a finding.
fn signature_finding(msg: &Message, body: &str) -> Option<Finding> {
    let example_page = msg.is_success() && msg.is_html();
    SIGNATURE_SET.matches(body).iter().find_map(|i| {
        let sig = &SIGNATURES[i];
        if sig.kind == Kind::Trace && example_page {
            return None;
        }
        let mut found = SIGNATURE_RES[i].find_iter(body);
        let first = found.next()?;
        if found.take(sig.min.saturating_sub(1)).count() + 1 < sig.min {
            return None;
        }
        Some(
            ALERT
                .raise("", cut_chars(first.as_str(), 200))
                .risk(sig.risk)
                .other_info(format!("{} in the response.", sig.what)),
        )
    })
}

pub struct ApplicationError;

impl PassiveRule for ApplicationError {
    fn id(&self) -> u32 {
        90022
    }

    fn name(&self) -> &'static str {
        "Application Error Disclosure"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if contains_control_chars(&msg.resp_body) {
            return;
        }
        // Diverges from ZAP, which also reads source maps (library code in strings) and
        // takes "Internal Server Error" in a hint or a translation file for an error page.
        let no_page = msg.content_type().contains("application/wasm")
            || is_javascript(msg)
            || is_css(msg)
            || is_source_map(msg)
            || msg.resp_body.is_empty();
        // Diverges from ZAP: today's stack traces and drivers' errors first (in a 500 too,
        // whose body ZAP never reads), since they say what the 500 or a generic phrase hides.
        if !no_page {
            if let Some(f) = signature_finding(msg, msg.body()) {
                out.push(f);
                return;
            }
        }
        if msg.status == 500 {
            // Diverges from ZAP: a specific message of ZAP's list in the 500 is the evidence;
            // a generic one ("Internal Server Error") adds nothing to the status.
            if let Some(f) = (!no_page).then(|| zap_match(msg, true)).flatten() {
                out.push(f);
            } else if !msg.resp_body.is_empty() {
                // Diverges from ZAP: an empty 500 discloses nothing.
                out.push(ALERT.raise("", "HTTP/1.1 500 Internal Server Error").risk(Risk::Low));
            }
            return;
        }
        if msg.status == 404 || no_page {
            return;
        }
        out.extend(zap_match(msg, false));
    }
}

/// ZAP's list on the body: all literal strings first, then the regexes; first in file order
/// wins. With `specific_only`, the generic phrases don't count.
fn zap_match(msg: &Message, specific_only: bool) -> Option<Finding> {
    let body = msg.body();
    let m = &*MATCHER;
    let counts = |s: &str| !generic_in_data(msg, s) && !(specific_only && is_generic_phrase(s));
    if let Some(i) = m.string_set.matches(body).iter().find(|&i| counts(&m.strings[i])) {
        return Some(ALERT.raise("", m.strings[i].as_str()));
    }
    let i = m.regex_set.matches(body).iter().next()?;
    m.regexes[i].find(body).map(|found| ALERT.raise("", found.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn all_patterns_compile() {
        let m = &*MATCHER;
        assert_eq!(m.strings.len(), 88);
        assert_eq!(m.regexes.len(), 22);
        assert!(m.regexes.iter().any(|r| r.as_str().contains(r"\&quot\;\\\&quot;")));
    }

    #[test]
    fn flags_strings_before_regexes() {
        let f = msg("https://a.test/")
            .html("ORA-01756: quoted string; You have an error in your SQL syntax near")
            .scan(&ApplicationError);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "You have an error in your SQL syntax");
        let f = msg("https://a.test/").html("<p>ora-00933: SQL command</p>").scan(&ApplicationError);
        assert_eq!(f[0].evidence, "ora-00933: ");
        let php = "<b>Warning</b>:  include(x.php) in <b>/var/www/a.php</b> on line <b>3</b><br />";
        assert_eq!(msg("https://a.test/").html(php).scan(&ApplicationError)[0].evidence, php);
    }

    #[test]
    fn status_500_is_low() {
        let f = msg("https://a.test/").status(500).html("oops").scan(&ApplicationError);
        assert_eq!((f.len(), f[0].risk), (1, Risk::Low));
    }

    /// A hint's or a translation's "Internal Server Error" in JSON data isn't an error page
    /// (it raised a Medium on Juice Shop's /api/Hints), nor is a source map's library code,
    /// nor an empty 500.
    #[test]
    fn ignores_generic_phrases_in_json_data_source_maps_and_empty_500s() {
        let json = |path: &str, body: &str| {
            msg(&format!("https://a.test{path}")).header("Content-Type", "application/json; charset=utf-8").body(body)
        };
        let hint = r#"{"data":[{"text":"500 Internal Server Error is always an interesting status code"}]}"#;
        assert!(json("/api/Hints", hint).scan(&ApplicationError).is_empty());
        let i18n = r#"{"ERR":"Internal Server Error","DENIED":"You are not allowed to access this"}"#;
        assert!(json("/assets/i18n/en.json", i18n).scan(&ApplicationError).is_empty());
        let f = json("/api/x", r#"{"e":"You have an error in your SQL syntax"}"#).scan(&ApplicationError);
        assert_eq!(f[0].evidence, "You have an error in your SQL syntax");
        let map = json("/main.js.map", r#"{"version":3,"sourcesContent":["throw new Error('internal error')"]}"#);
        assert!(map.scan(&ApplicationError).is_empty());
        assert!(msg("https://a.test/rest/country-mapping").status(500).scan(&ApplicationError).is_empty());
        // The same text in an HTML page is still one.
        assert_eq!(msg("https://a.test/").html(hint).scan(&ApplicationError).len(), 1);
    }

    /// Juice Shop's Express error page: the stack frames are the evidence, not the status.
    const EXPRESS_TRACE: &str = "<h1>OWASP Juice Shop (Express ^4.22.1)</h1>\n<h2><em>500</em> Error: Unexpected path: \
        /rest/user/login</h2>\n<ul id=\"stacktrace\"><li> &nbsp; &nbsp;at /juice-shop/build/routes/angular.js:18:18</li>\
        <li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)\
        </li></ul>";

    fn first(f: &[Finding]) -> (&str, &str, Risk) {
        (f[0].def.alert_ref, f[0].evidence.as_str(), f[0].risk)
    }

    #[test]
    fn a_500_reports_the_stack_trace_or_database_error_in_its_body() {
        let f = msg("https://a.test/rest/user/login").status(500).html(EXPRESS_TRACE).scan(&ApplicationError);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(first(&f), ("90022", "at /juice-shop/build/routes/angular.js:18:18", Risk::Medium));
        assert!(f[0].other_info.contains("Node.js stack trace"), "{}", f[0].other_info);

        let sqli = "<title>Error: SQLITE_ERROR: near &quot;)&quot;: syntax error</title>\
            <h2><em>500</em> Error: SQLITE_ERROR: near &quot;)&quot;: syntax error</h2><ul id=\"stacktrace\"></ul>";
        let f = msg("https://a.test/rest/products/search?q=%27))").status(500).html(sqli).scan(&ApplicationError);
        assert_eq!(first(&f), ("90022", "SQLITE_ERROR: near &quot;)&quot;: syntax error", Risk::Medium));

        let py = "Traceback (most recent call last):\n  File \"/app/views.py\", line 12, in index\n    \
            return db.get(id)\nKeyError: 'id'\n";
        let f =
            msg("https://a.test/").status(500).header("Content-Type", "text/plain").body(py).scan(&ApplicationError);
        assert_eq!(first(&f).1, "Traceback (most recent call last):\n  File \"");

        let go =
            "panic: runtime error: index out of range [3] with length 3\n\ngoroutine 7 [running]:\nmain.handler(...)";
        let f =
            msg("https://a.test/").status(500).header("Content-Type", "text/plain").body(go).scan(&ApplicationError);
        assert_eq!(first(&f).1, "goroutine 7 [running]:");

        let java =
            "<pre>java.lang.NullPointerException\n\tat com.acme.web.OrderController.show(OrderController.java:42)\n\
            \tat org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)</pre>";
        let f = msg("https://a.test/").status(500).html(java).scan(&ApplicationError);
        assert_eq!(first(&f).1, "at com.acme.web.OrderController.show(OrderController.java:42)");

        let dotnet = "<h1>Server Error in '/' Application.</h1><h2><i>Object reference not set</i></h2>\
            <b>Stack Trace:</b> at System.Data.SqlClient.SqlConnection.OnError(SqlException exception)";
        let f = msg("https://a.test/").status(500).html(dotnet).scan(&ApplicationError);
        assert_eq!(first(&f).1, "Server Error in '/' Application.");

        let php = "PHP Fatal error:  Uncaught Error: Call to undefined function foo() in /var/www/html/index.php:3";
        let f =
            msg("https://a.test/").status(500).header("Content-Type", "text/plain").body(php).scan(&ApplicationError);
        assert!(first(&f).1.starts_with("PHP Fatal error:  Uncaught Error"), "{f:?}");

        let spring = "<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error";
        let f = msg("https://a.test/").status(500).html(spring).scan(&ApplicationError);
        assert_eq!(first(&f), ("90022", "<h1>Whitelabel Error Page</h1>", Risk::Low));

        // A JSON API's error with the ORM's error name, on a 200 too.
        let seq = r#"{"error":{"name":"SequelizeDatabaseError","original":{"errno":1}}}"#;
        let json = msg("https://a.test/api/x").header("Content-Type", "application/json").body(seq);
        assert_eq!(first(&json.scan(&ApplicationError)).1, "SequelizeDatabaseError");
    }

    #[test]
    fn a_500_with_only_generic_text_stays_the_low_status_finding() {
        let page = "<h1>Internal Server Error</h1><p>Something went wrong. Error Report: 1234</p>";
        let f = msg("https://a.test/").status(500).html(page).scan(&ApplicationError);
        assert_eq!(first(&f), ("90022", "HTTP/1.1 500 Internal Server Error", Risk::Low));
        // A specific signature from ZAP's list in a 500 is shown too.
        let f = msg("https://a.test/").status(500).html("You have an error in your SQL syntax").scan(&ApplicationError);
        assert_eq!(first(&f), ("90022", "You have an error in your SQL syntax", Risk::Medium));
    }

    /// Documentation, tutorials and Q&A pages print stack traces as examples; a script bundle
    /// carries the driver's error names as strings; translations mention errors.
    #[test]
    fn ignores_traces_in_docs_pages_bundles_and_translations() {
        let docs = "<article><h1>Debugging Node</h1><pre><code>Error: boom\n    at main (/app/index.js:3:9)\n    \
            at Module._compile (node:internal/modules/cjs/loader:1256:14)</code></pre><pre>Traceback (most recent \
            call last):\n  File &quot;x.py&quot;, line 1</pre><p>at java.base/java.lang.Thread.run(Thread.java:833)</p>";
        assert!(msg("https://docs.a.test/debugging").html(docs).scan(&ApplicationError).is_empty());
        let bundle = r#"var e={SQLITE_ERROR:1};function f(){return"SequelizeDatabaseError"}//at a (/b/c.js:1:2) at d (/e.js:3:4)"#;
        let js = msg("https://a.test/main.js").header("Content-Type", "application/javascript").body(bundle);
        assert!(js.scan(&ApplicationError).is_empty());
        let i18n = r#"{"ERROR_TITLE":"Something went wrong","MIN":"at least 2 characters at index 3:4"}"#;
        let json = msg("https://a.test/assets/i18n/en.json").header("Content-Type", "application/json").body(i18n);
        assert!(json.scan(&ApplicationError).is_empty());
    }

    #[test]
    fn ignores_404_js_and_clean_pages() {
        assert!(msg("https://a.test/").status(404).html("internal error").scan(&ApplicationError).is_empty());
        let js = msg("https://a.test/app.js").header("Content-Type", "application/javascript").body("internal error");
        assert!(js.scan(&ApplicationError).is_empty());
        assert!(msg("https://a.test/").html("<p>hello</p>").scan(&ApplicationError).is_empty());
    }
}
