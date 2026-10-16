//! Ported from ZAP InformationDisclosureSuspiciousCommentsScanRule (pscanrules, Apache License 2.0).
//!
//! ZAP finds JavaScript comments with an ANTLR ECMAScript lexer; this port uses a
//! small hand-written scanner that skips strings, template literals and regex
//! literals the same way.

use std::sync::LazyLock;

use regex::Regex;

use super::common::{chars_back, chars_forward, element_content, is_font, is_javascript, is_text};
use crate::scan::passive::util::{comments, tags};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10027",
    name: "Information Disclosure - Suspicious Comments",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 615,
    wasc: 13,
    description: "The response appears to contain suspicious comments which may help an attacker.",
    solution: "Remove all comments that return information that may help an attacker and fix any underlying \
        problems they refer to.",
    references: &[],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "WSTG-v42-INFO-05"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const PAYLOADS: [&str; 16] = [
    "TODO",
    "FIXME",
    "BUG",
    "BUGS",
    "XXX",
    "QUERY",
    "DB",
    "ADMIN",
    "ADMINISTRATOR",
    "USER",
    "USERNAME",
    "SELECT",
    "WHERE",
    "FROM",
    "LATER",
    "DEBUG",
];

struct Patterns {
    /// Any payload, to skip most comments in one pass.
    any: Regex,
    /// (ZAP's pattern source, compiled) in payload order.
    each: Vec<(String, Regex)>,
}

static PATTERNS: LazyLock<Patterns> = LazyLock::new(|| {
    let b = r"(?-u:\b)";
    let any = Regex::new(&format!(r"(?i){b}(?:{}){b}", PAYLOADS.join("|"))).unwrap();
    let each =
        PAYLOADS.iter().map(|p| (format!(r"\b{p}\b"), Regex::new(&format!(r"(?i){b}{p}{b}")).unwrap())).collect();
    Patterns { any, each }
});

/// Hits per pattern, in order of first hit: (pattern index, [(comment, snippet)]).
type Hits<'a> = Vec<(usize, Vec<(&'a str, &'a str)>)>;

fn record<'a>(comment: &'a str, hits: &mut Hits<'a>) {
    let p = &*PATTERNS;
    if !p.any.is_match(comment) {
        return;
    }
    for (i, (_, re)) in p.each.iter().enumerate() {
        if let Some(m) = re.find(comment) {
            let snippet = &comment[chars_back(comment, m.start(), 20)..chars_forward(comment, m.end(), 20)];
            match hits.iter_mut().find(|(j, _)| *j == i) {
                Some((_, v)) => v.push((comment, snippet)),
                None => hits.push((i, vec![(comment, snippet)])),
            }
            return;
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Tok {
    None,
    /// Identifier or keyword that may precede a regex literal.
    Keyword,
    /// Identifier, literal, `)`, `]`, `++`, `--`: a following `/` divides.
    Operand,
    /// Any other punctuator: a following `/` starts a regex.
    Punct,
}

const REGEX_KEYWORDS: &[&str] = &[
    "return",
    "typeof",
    "case",
    "do",
    "else",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "instanceof",
    "yield",
    "await",
];

/// Comments in JavaScript source (`//`, `/* */` and `<!-- -->`), with delimiters.
pub fn js_comments(src: &str) -> Vec<&str> {
    let mut out = Vec::new();
    if !src.contains("//") && !src.contains("/*") && !src.contains("<!--") {
        return out;
    }
    let b = src.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut last = Tok::None;
    // Brace depth inside each open template-literal substitution.
    let mut templates: Vec<usize> = Vec::new();
    // Scans a template literal body from `i`; returns where code resumes.
    let template_body = |mut i: usize, templates: &mut Vec<usize>| -> usize {
        while i < n {
            match b[i] {
                b'\\' => i += 2,
                b'`' => return i + 1,
                b'$' if b.get(i + 1) == Some(&b'{') => {
                    templates.push(0);
                    return i + 2;
                }
                _ => i += 1,
            }
        }
        n
    };
    while i < n {
        let c = b[i];
        match c {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let e = src[i..].find(['\n', '\r']).map(|e| i + e).unwrap_or(n);
                out.push(&src[i..e]);
                i = e;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let e = src[i + 2..].find("*/").map(|e| i + 2 + e + 2).unwrap_or(n);
                out.push(&src[i..e]);
                i = e;
            }
            b'<' if src[i..].starts_with("<!--") => match src[i + 4..].find("-->") {
                Some(e) => {
                    let e = i + 4 + e + 3;
                    out.push(&src[i..e]);
                    i = e;
                }
                None => {
                    last = Tok::Punct;
                    i += 1;
                }
            },
            b'/' if last != Tok::Operand => {
                // Regex literal: up to an unescaped `/` outside a class, on one line.
                let mut j = i + 1;
                let mut class = false;
                let mut ok = false;
                while j < n {
                    match b[j] {
                        b'\\' => j += 1,
                        b'[' => class = true,
                        b']' => class = false,
                        b'/' if !class => {
                            ok = true;
                            break;
                        }
                        b'\n' | b'\r' => break,
                        _ => {}
                    }
                    j += 1;
                }
                if ok {
                    i = j + 1;
                    while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                        i += 1;
                    }
                    last = Tok::Operand;
                } else {
                    last = Tok::Punct;
                    i += 1;
                }
            }
            b'\'' | b'"' => {
                let mut j = i + 1;
                while j < n && b[j] != c && b[j] != b'\n' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                i = (j + 1).min(n);
                last = Tok::Operand;
            }
            b'`' => {
                i = template_body(i + 1, &mut templates);
                last = Tok::Operand;
            }
            b'{' => {
                if let Some(d) = templates.last_mut() {
                    *d += 1;
                }
                last = Tok::Punct;
                i += 1;
            }
            b'}' => {
                match templates.last_mut() {
                    Some(0) => {
                        templates.pop();
                        i = template_body(i + 1, &mut templates);
                        last = Tok::Operand;
                        continue;
                    }
                    Some(d) => *d -= 1,
                    None => {}
                }
                last = Tok::Punct;
                i += 1;
            }
            b')' | b']' => {
                last = Tok::Operand;
                i += 1;
            }
            b'+' | b'-' if b.get(i + 1) == Some(&c) => {
                last = Tok::Operand;
                i += 2;
            }
            _ if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c >= 0x80 => {
                let s = i;
                while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$' || b[i] >= 0x80) {
                    i += 1;
                }
                let word = &src[s..i];
                last = if REGEX_KEYWORDS.contains(&word) { Tok::Keyword } else { Tok::Operand };
            }
            _ if c.is_ascii_whitespace() => i += 1,
            _ => {
                last = Tok::Punct;
                i += 1;
            }
        }
    }
    out
}

/// Java MessageFormat number formatting (grouping separators).
fn group_digits(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub struct SuspiciousComments;

impl PassiveRule for SuspiciousComments {
    fn id(&self) -> u32 {
        10027
    }

    fn name(&self) -> &'static str {
        "Information Disclosure - Suspicious Comments"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_body.is_empty() || !is_text(msg) || is_font(msg) {
            return;
        }
        let body = msg.body();
        let mut hits: Hits<'_> = Vec::new();
        if is_javascript(msg) {
            for c in js_comments(body) {
                record(c, &mut hits);
            }
        } else {
            let all = tags(body);
            let scripts: Vec<(usize, &str)> = all
                .iter()
                .filter(|t| t.name == "script")
                .map(|t| {
                    let content = element_content(body, t);
                    (content.as_ptr() as usize - body.as_ptr() as usize, content)
                })
                .collect();
            for inner in comments(body) {
                let start = inner.as_ptr() as usize - body.as_ptr() as usize;
                // Skip comments inside <script> elements (their JS is lexed below).
                let k = scripts.partition_point(|(s, _)| *s <= start);
                if k > 0 && start < scripts[k - 1].0 + scripts[k - 1].1.len() {
                    continue;
                }
                let end = (start + inner.len() + 3).min(body.len());
                record(&body[start - 4..end], &mut hits);
            }
            for (_, content) in scripts {
                for c in js_comments(content) {
                    record(c, &mut hits);
                }
            }
        }
        let p = &*PATTERNS;
        for (i, list) in hits {
            let (comment, snippet) = list[0];
            let source = &p.each[i].0;
            let detail: String = comment.chars().take(128).collect();
            let other = if list.len() == 1 {
                format!(
                    "The following pattern was used: {source} and was detected in likely comment: \"{detail}\", \
                     see evidence field for the suspicious comment/snippet."
                )
            } else {
                format!(
                    "The following pattern was used: {source} and was detected {} times, the first in likely \
                     comment: \"{detail}\", see evidence field for the suspicious comment/snippet.",
                    group_digits(list.len())
                )
            };
            out.push(ALERT.raise("", snippet).other_info(other));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn lexes_js_comments() {
        let js = r#"var a = "// not"; /* one */ x = 4 / 2; // two
            r = /\/\/ no [/]/g; t = `// no ${ {a:1}["a"] } // still no`; <!-- three --> y = a++ / 2 // four"#;
        assert_eq!(js_comments(js), ["/* one */", "// two", "<!-- three -->", "// four"]);
        assert_eq!(group_digits(1234567), "1,234,567");
    }

    #[test]
    fn flags_html_and_script_comments() {
        let html = "<!-- TODO: remove admin backdoor --><script>// fixme later\nvar s = '// todo';</script>\
            <!-- todo again -->";
        let f = msg("https://a.test/").html(html).scan(&SuspiciousComments);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].evidence, "<!-- TODO: remove admin backd");
        assert!(f[0].other_info.starts_with(
            "The following pattern was used: \\bTODO\\b and was detected 2 times, the first in likely comment: \
             \"<!-- TODO: remove admin backdoor -->\""
        ));
        assert_eq!(f[1].evidence, "// fixme later");
        assert!(f[1].other_info.contains("detected in likely comment: \"// fixme later\""));
    }

    #[test]
    fn flags_javascript_files() {
        let f = msg("https://a.test/a.js")
            .header("Content-Type", "application/javascript")
            .body("let q = 1; /* select * from users */")
            .scan(&SuspiciousComments);
        assert_eq!(f.len(), 1);
        assert!(f[0].other_info.contains(r"\bSELECT\b"));
    }

    #[test]
    fn ignores_clean_comments_and_code() {
        let html = "<!-- layout --><p>TODO list app</p><script>var todo = 'admin'; // render\n</script>";
        assert!(msg("https://a.test/").html(html).scan(&SuspiciousComments).is_empty());
    }
}
