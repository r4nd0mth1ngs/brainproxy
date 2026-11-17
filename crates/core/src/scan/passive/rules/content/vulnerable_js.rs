//! Ported from ZAP RetireScanRule (retire, Apache License 2.0), with Retire.js's
//! vulnerability database (`jsrepository.json`, Apache License 2.0) as the retire add-on ships it.
//!
//! A JavaScript library is recognised by its URL, file name, content (for HTML pages, the
//! `<script>` elements), or SHA-1, and its version checked against the database's
//! vulnerable ranges. Beyond ZAP, a page's `<script src>` URLs are matched by URL and file
//! name too, so a library loaded from an out-of-scope CDN (never fetched) is still found, and
//! every vulnerable library of a file is reported, not only the first. Patterns use the regex
//! crate: the few that need look-around or a backreference are rewritten (see
//! [`rust_compatible`]), and one that still doesn't compile is skipped and said. Compiled once,
//! not per response as in ZAP (about 25 ms for 1 MB of script; a `RegexSet` over all
//! content patterns was 40 times slower, as it loses the literal prefilters).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10003",
    name: "Vulnerable JS Library",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 1395,
    wasc: 0,
    description: "The identified library appears to be vulnerable.",
    solution: "Upgrade to the latest version of the affected library.",
    references: &["https://owasp.org/Top10/2021/A06_2021-Vulnerable_and_Outdated_Components/"],
    tags: &["OWASP_2025_A03", "OWASP_2021_A06", "OWASP_2017_A09"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub(crate) const EMBEDDED: &str = include_str!("../../data/jsrepository.json");

#[derive(Deserialize)]
struct RawEntry {
    #[serde(default)]
    extractors: RawExtractors,
    #[serde(default)]
    vulnerabilities: Vec<RawVuln>,
}

#[derive(Deserialize, Default)]
struct RawExtractors {
    #[serde(default)]
    uri: Vec<String>,
    #[serde(default)]
    filename: Vec<String>,
    #[serde(default)]
    filecontent: Vec<String>,
    #[serde(default)]
    hashes: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawVuln {
    below: Option<String>,
    at_or_above: Option<String>,
    severity: Option<String>,
    #[serde(default)]
    identifiers: Identifiers,
    #[serde(default)]
    info: Vec<String>,
}

#[derive(Deserialize, Default)]
struct Identifiers {
    #[serde(default)]
    #[serde(rename = "CVE")]
    cve: Vec<String>,
}

/// A compiled pattern, and the groups that must have captured the same text (what a
/// backreference `(\2)` asked for, which the regex crate doesn't do).
struct Pattern {
    re: Regex,
    same: Vec<(usize, usize)>,
}

impl Pattern {
    fn captures<'h>(&self, input: &'h str) -> Option<regex::Captures<'h>> {
        // The first match whose backreferenced groups agree.
        self.re
            .captures_iter(input)
            .find(|c| self.same.iter().all(|&(a, b)| c.get(a).map(|m| m.as_str()) == c.get(b).map(|m| m.as_str())))
    }

    fn is_match(&self, input: &str) -> bool {
        if self.same.is_empty() {
            self.re.is_match(input)
        } else {
            self.captures(input).is_some()
        }
    }
}

struct Library {
    name: String,
    uri: Vec<Pattern>,
    filename: Vec<Pattern>,
    content: Vec<Pattern>,
    hashes: BTreeMap<String, String>,
    vulns: Vec<RawVuln>,
}

struct Repo {
    libs: Vec<Library>,
    /// Patterns of the "dont check" entry: such files aren't checked at all.
    skip: Vec<Pattern>,
    /// Patterns that couldn't be compiled even after [`rust_compatible`], as given.
    dropped: Vec<String>,
}

/// ZAP's VersionConverter: the `§§version§§` token becomes a lazy version pattern; a
/// pattern ending with it gets a trailing whitespace check.
fn fix_pattern(p: &str) -> String {
    const VERSION: &str = "[0-9][0-9a-z._\\-]+?";
    let mut p = p.replace("§§version§§", VERSION).replace("{}", "\\{\\}");
    if p.ends_with(&format!("{VERSION})")) {
        p.push_str("\\s");
    }
    p
}

/// The content ranges of a pattern's capturing groups, in group-number order.
fn capture_groups(p: &str) -> Vec<(usize, usize)> {
    let b = p.as_bytes();
    let (mut groups, mut open): (Vec<(usize, usize)>, Vec<Option<usize>>) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'[' => {
                // A class: `]` right after `[` or `[^` is a literal.
                i += 1;
                if b.get(i) == Some(&b'^') {
                    i += 1;
                }
                if b.get(i) == Some(&b']') {
                    i += 1;
                }
                while i < b.len() && b[i] != b']' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'(' => {
                let rest = &p[i + 1..];
                let named = rest.starts_with("?P<")
                    || (rest.starts_with("?<") && !rest.starts_with("?<=") && !rest.starts_with("?<!"));
                if rest.starts_with('?') && !named {
                    open.push(None);
                } else {
                    let start = if named { rest.find('>').map_or(i + 1, |g| i + 1 + g + 1) } else { i + 1 };
                    groups.push((start, start));
                    open.push(Some(groups.len() - 1));
                }
            }
            b')' => {
                if let Some(Some(g)) = open.pop() {
                    groups[g].1 = i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    groups
}

/// The end of the group that opens at byte `at` (the index just past its `)`).
fn group_end(p: &str, at: usize) -> Option<usize> {
    let b = p.as_bytes();
    let (mut depth, mut i, mut class) = (0usize, at, false);
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'[' if !class => class = true,
            b']' if class => class = false,
            b'(' if !class => depth += 1,
            b')' if !class => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Retire.js's patterns are JavaScript regexes; a few use what the regex crate doesn't have.
/// A positive look-around is dropped (it only narrows a match the version check narrows
/// again), and a backreference that is a whole group, `(\2)`, becomes a copy of group 2 with
/// the two groups checked for equal text after matching. Anything else is left as None.
fn rust_compatible(p: &str) -> Option<(String, Vec<(usize, usize)>)> {
    let mut p = p.to_string();
    while let Some(at) = ["(?<=", "(?="].iter().filter_map(|l| p.find(l)).min() {
        let end = group_end(&p, at)?;
        p.replace_range(at..end, "");
    }
    let mut same = Vec::new();
    loop {
        let groups = capture_groups(&p);
        let Some((g, n)) = groups.iter().enumerate().find_map(|(g, &(s, e))| {
            let inner = p.get(s..e)?;
            let n: usize = inner.strip_prefix('\\')?.parse().ok()?;
            (1..=9).contains(&n).then_some((g, n))
        }) else {
            break;
        };
        let (s, e) = groups[g];
        let (rs, re) = *groups.get(n - 1)?;
        let source = p.get(rs..re)?.to_string();
        p.replace_range(s..e, &source);
        same.push((n, g + 1));
    }
    Some((p, same))
}

fn compile(patterns: &[String], dropped: &mut Vec<String>) -> Vec<Pattern> {
    let mut out = Vec::new();
    for p in patterns {
        let fixed = fix_pattern(p);
        let compiled = match Regex::new(&fixed) {
            Ok(re) => Some(Pattern { re, same: Vec::new() }),
            Err(_) => rust_compatible(&fixed)
                .and_then(|(rewritten, same)| Regex::new(&rewritten).ok().map(|re| Pattern { re, same })),
        };
        match compiled {
            Some(pattern) => out.push(pattern),
            None => dropped.push(p.clone()),
        }
    }
    out
}

fn parse(text: &str) -> crate::Result<Repo> {
    let entries: BTreeMap<String, RawEntry> = serde_json::from_str(text)
        .map_err(|e| crate::Error::InvalidInput(format!("not a Retire.js repository: {e}")))?;
    let mut libs = Vec::new();
    let mut skip = Vec::new();
    let mut dropped = Vec::new();
    for (name, e) in entries {
        let x = e.extractors;
        if name == "dont check" {
            skip = compile(&[x.uri, x.filename, x.filecontent].concat(), &mut dropped);
            continue;
        }
        libs.push(Library {
            uri: compile(&x.uri, &mut dropped),
            filename: compile(&x.filename, &mut dropped),
            content: compile(&x.filecontent, &mut dropped),
            name,
            hashes: x.hashes.into_iter().map(|(h, v)| (h.to_ascii_lowercase(), v)).collect(),
            vulns: e.vulnerabilities,
        });
    }
    if libs.is_empty() || skip.is_empty() {
        return Err(crate::Error::InvalidInput("no libraries, or no \"dont check\" entry".into()));
    }
    Ok(Repo { libs, skip, dropped })
}

/// Number of libraries (data files are validated before use; see `crate::data`).
pub(crate) fn validate(text: &str) -> crate::Result<usize> {
    Ok(parse(text)?.libs.len())
}

static REPO: LazyLock<Option<Repo>> = LazyLock::new(|| {
    let repo = parse(crate::data::get("jsrepository.json")).ok()?;
    // Said once per process: a library whose patterns are all gone is never found.
    for p in &repo.dropped {
        eprintln!("brainproxy: a Retire.js pattern doesn't compile and is skipped: {p}");
    }
    Some(repo)
});

/// ZAP's RetireUtil.isAtOrAbove: dot/dash-separated parts, numbers above words.
fn at_or_above(v1: &str, v2: &str) -> bool {
    let a: Vec<&str> = v1.split(['.', '-']).collect();
    let b: Vec<&str> = v2.split(['.', '-']).collect();
    let num = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or("0"), b.get(i).copied().unwrap_or("0"));
        match (num(x), num(y)) {
            (true, false) => return true,
            (false, true) => return false,
            // Equal words (beta, rc) compare the parts after them, as Retire.js does.
            (false, false) if x != y => return x > y,
            (false, false) => continue,
            _ => {}
        }
        let (x, y) = (x.parse::<u128>().unwrap_or(0), y.parse::<u128>().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    true
}

/// A version worth checking: has separators (not a cache buster) and isn't all zeros.
fn good_candidate(v: &str) -> bool {
    let parts: Vec<&str> = v.split(['.', '_', '-']).collect();
    parts.len() > 1 && parts.iter().map(|p| p.parse::<u64>()).sum::<Result<u64, _>>() != Ok(0)
}

struct Hit<'a> {
    lib: &'a Library,
    version: String,
    evidence: String,
    risk: Risk,
    cves: Vec<&'a str>,
    info: Vec<&'a str>,
}

fn vulnerable<'a>(lib: &'a Library, version: &str, evidence: &str) -> Option<Hit<'a>> {
    if !good_candidate(version) {
        return None;
    }
    let mut hit = Hit {
        lib,
        version: version.to_string(),
        evidence: evidence.trim().to_string(),
        risk: Risk::Info,
        cves: vec![],
        info: vec![],
    };
    for v in &lib.vulns {
        let above = v.at_or_above.as_deref().filter(|s| !s.is_empty());
        let below = v.below.as_deref().filter(|s| !s.is_empty());
        let affected = match (above, below) {
            (Some(a), Some(b)) => at_or_above(version, a) && !at_or_above(version, b),
            (None, Some(b)) => !at_or_above(version, b),
            (Some(a), None) => at_or_above(version, a),
            (None, None) => false,
        };
        if affected {
            let risk = match v.severity.as_deref().map(str::to_ascii_lowercase).as_deref() {
                Some("critical") => Risk::Critical,
                Some("high") => Risk::High,
                Some("low") => Risk::Low,
                _ => Risk::Medium,
            };
            hit.risk = hit.risk.max(risk);
            for c in &v.identifiers.cve {
                if !hit.cves.contains(&c.as_str()) {
                    hit.cves.push(c);
                }
            }
            for i in &v.info {
                if !hit.info.contains(&i.as_str()) {
                    hit.info.push(i);
                }
            }
        }
    }
    (hit.risk != Risk::Info).then_some(hit)
}

/// `lib` at a vulnerable version, by the first of its `pick` patterns that matches `input`.
fn scan_by<'a>(lib: &'a Library, input: &str, pick: fn(&Library) -> &Vec<Pattern>) -> Option<Hit<'a>> {
    pick(lib).iter().find_map(|p| {
        let c = p.captures(input)?;
        vulnerable(lib, c.get(1)?.as_str(), c.get(0)?.as_str())
    })
}

/// Whether the response is a script: by its type, or by a `.js` path when the type says
/// nothing more specific (object stores and some CDNs send `text/plain` or `octet-stream`).
fn is_script(msg: &Message) -> bool {
    let ct = msg.content_type();
    let untyped = ct.is_empty() || ct.starts_with("text/plain") || ct.starts_with("application/octet-stream");
    msg.is_javascript() || (untyped && msg.path.to_ascii_lowercase().ends_with(".js"))
}

static SRC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)<script\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)"#).unwrap());
static SCRIPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<script\b.*?(?:</script\s*>|\z)").unwrap());

pub struct VulnerableJs;

impl PassiveRule for VulnerableJs {
    fn id(&self) -> u32 {
        10003
    }

    fn name(&self) -> &'static str {
        "Vulnerable JS Library (Powered by Retire.js)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // Before touching REPO: its first use compiles the database.
        // Diverges from ZAP: a script served as plain text or bytes is read too.
        if msg.status != 200 || !(msg.is_html() || is_script(msg)) {
            return;
        }
        let Some(repo) = REPO.as_ref() else { return };
        let url = msg.url.split(['?', '#']).next().unwrap_or("");
        let file = url.rsplit('/').next().unwrap_or("");
        // For pages, only the script elements (ZAP: Jericho's SCRIPT elements).
        let content = if msg.is_html() {
            SCRIPT.find_iter(msg.body()).map(|m| m.as_str()).collect::<Vec<_>>().join("\n")
        } else {
            msg.body().to_string()
        };
        if [&msg.url, file, &content].iter().any(|s| repo.skip.iter().any(|p| p.is_match(s))) {
            return;
        }
        // Scripts the page loads, by their src URL and file name.
        let srcs: Vec<&str> = SRC
            .captures_iter(&content)
            .filter_map(|c| c.get(1))
            .map(|m| m.as_str())
            .filter(|src| !repo.skip.iter().any(|p| p.is_match(src)))
            .collect();
        let hash = {
            use sha1::Digest;
            hex::encode(sha1::Sha1::digest(&msg.resp_body))
        };
        // Diverges from ZAP, which reports the first vulnerable library only: a bundle or a
        // page carries several, each its own finding (the library is the parameter).
        for lib in &repo.libs {
            let mut note = String::new();
            let hit = scan_by(lib, &msg.url, |l| &l.uri)
                .or_else(|| (!file.is_empty()).then(|| scan_by(lib, file, |l| &l.filename)).flatten())
                .or_else(|| scan_by(lib, &content, |l| &l.content))
                .or_else(|| {
                    srcs.iter().find_map(|src| {
                        let name = src.split(['?', '#']).next().unwrap_or("").rsplit('/').next().unwrap_or("");
                        let hit = scan_by(lib, src, |l| &l.uri).or_else(|| scan_by(lib, name, |l| &l.filename))?;
                        note = format!("Loaded by this page from {src}");
                        Some(hit)
                    })
                })
                .or_else(|| {
                    let version = lib.hashes.get(&hash)?;
                    note = format!("The library matched the known vulnerable hash {hash}.");
                    vulnerable(lib, version, "")
                });
            let Some(h) = hit else { continue };
            let mut other = format!("The identified library {}, version {} is vulnerable.\n", h.lib.name, h.version);
            for line in h.cves.iter().chain([&note.as_str()].iter().copied().filter(|s| !s.is_empty())).chain(&h.info) {
                other.push_str(line);
                other.push('\n');
            }
            out.push(ALERT.raise(h.lib.name.as_str(), h.evidence).risk(h.risk).other_info(other.trim_end()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn embedded_database_compiles() {
        let repo = parse(EMBEDDED).unwrap();
        assert!(repo.libs.len() > 50, "{}", repo.libs.len());
        assert!(repo.libs.iter().map(|l| l.content.len()).sum::<usize>() > 150);
        assert!(!repo.skip.is_empty());
    }

    #[test]
    fn versions_compare_like_zap() {
        assert!(at_or_above("1.12.4", "1.12.4"));
        assert!(at_or_above("1.12.10", "1.12.4"));
        assert!(!at_or_above("1.2", "1.12.4"));
        assert!(at_or_above("3.0.0", "3.0.0-rc1"));
        assert!(!at_or_above("3.0.0-beta1", "3.0.0-rc1"));
        assert!(at_or_above("3.0.0-rc.1", "3.0.0-rc.1"));
        assert!(at_or_above("4.9.0-beta.5", "4.9.0-beta.3"));
        assert!(!at_or_above("4.9.0-beta.2", "4.9.0-beta.3"));
        assert!(good_candidate("1.8.3") && !good_candidate("7a06f256") && !good_candidate("0.0.0"));
    }

    #[test]
    fn flags_old_jquery_by_file_name_and_content() {
        let f = msg("https://a.test/js/jquery-1.8.3.min.js")
            .header("Content-Type", "application/javascript")
            .body("/* lib */")
            .scan(&VulnerableJs);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].other_info.contains("jquery, version 1.8.3"), "{}", f[0].other_info);
        assert!(f[0].other_info.contains("CVE-"), "{}", f[0].other_info);
        assert!(f[0].risk >= Risk::Medium);

        let page = msg("https://a.test/")
            .html("<html><script>/*! jQuery v1.8.3 jquery.com | jquery.org/license */</script></html>")
            .scan(&VulnerableJs);
        assert_eq!(page.len(), 1, "{page:?}");
        assert!(page[0].evidence.contains("1.8.3"), "{}", page[0].evidence);

        // Loaded from a CDN the scan never fetches.
        let cdn = msg("https://a.test/")
            .html(r#"<script src="https://code.jquery.com/jquery-1.8.3.min.js"></script>"#)
            .scan(&VulnerableJs);
        assert_eq!(cdn.len(), 1, "{cdn:?}");
        assert!(
            cdn[0].other_info.contains("Loaded by this page from https://code.jquery.com/"),
            "{}",
            cdn[0].other_info
        );
    }

    fn libraries(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.param.as_str()).collect()
    }

    /// A vendor bundle carries several libraries; each vulnerable one is its own finding.
    #[test]
    fn flags_every_vulnerable_library_in_a_file() {
        let vendor = "/*! jQuery v1.8.0 jquery.com | jquery.org/license */\nvar a=1;\n\
            /**\n * @license\n * Lodash <https://lodash.com/>\n */\n;(function(){var VERSION = '4.17.4';})();\n\
            /*\n AngularJS v1.2.0\n (c) 2010-2014 Google, Inc. http://angularjs.org\n License: MIT\n*/\n";
        let f = msg("https://a.test/vendor.js").header("Content-Type", "application/javascript").body(vendor);
        let f = f.scan(&VulnerableJs);
        let mut libs = libraries(&f);
        libs.sort_unstable();
        assert_eq!(libs, ["angularjs", "jquery", "lodash"], "{f:?}");

        let page = msg("https://a.test/").html(
            "<script src=\"https://code.jquery.com/jquery-1.8.3.min.js\"></script>\
             <script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.0/angular.min.js\"></script>",
        );
        let mut libs = libraries(&page.scan(&VulnerableJs)).into_iter().map(str::to_string).collect::<Vec<_>>();
        libs.sort_unstable();
        assert_eq!(libs, ["angularjs", "jquery"]);
    }

    /// Minified builds without the licence comment: the patterns that need a backreference or
    /// a look-behind, which the regex crate lacks, are rewritten rather than dropped.
    #[test]
    fn flags_minified_jquery_and_lodash() {
        let repo = parse(EMBEDDED).unwrap();
        assert!(repo.dropped.is_empty(), "patterns that don't compile: {:?}", repo.dropped);
        let js = |body: &str| {
            msg("https://a.test/chunk-1.js")
                .header("Content-Type", "application/javascript")
                .body(body)
                .scan(&VulnerableJs)
        };
        let filler = "x".repeat(60);
        let jquery = format!("var t=\"1.8.3\",{filler}b.fn=b.prototype={{jquery:t,constructor:b}}");
        assert_eq!(libraries(&js(&jquery)), ["jquery"]);
        // Two different variables aren't jQuery's `x.fn = x.prototype`.
        let other = format!("var t=\"1.8.3\",{filler}b.fn=c.prototype={{jquery:t,constructor:b}}");
        assert!(js(&other).is_empty());
        let lodash = "var e=\"4.17.4\",n=200,r=\"Expected a function\",i=\"__lodash_hash_undefined__\",o=500;";
        assert_eq!(libraries(&js(lodash)), ["lodash"]);
    }

    /// Object stores and some CDNs serve scripts as text/plain or octet-stream.
    #[test]
    fn reads_scripts_served_as_plain_text() {
        let body = "/*! jQuery v1.8.3 jquery.com | jquery.org/license */";
        for ct in ["text/plain", "application/octet-stream"] {
            let f = msg("https://s3.a.test/assets/app.js").header("Content-Type", ct).body(body).scan(&VulnerableJs);
            assert_eq!(libraries(&f), ["jquery"], "{ct}");
        }
        let readme = msg("https://a.test/README.txt").header("Content-Type", "text/plain").body(body);
        assert!(readme.scan(&VulnerableJs).is_empty());
    }

    #[test]
    fn current_versions_and_other_content_pass() {
        let js = |url: &str| msg(url).header("Content-Type", "application/javascript").body("x").scan(&VulnerableJs);
        assert!(js("https://a.test/js/jquery-3.7.1.min.js").is_empty());
        assert!(js("https://a.test/js/app-1.8.3.js").is_empty());
        // Script text outside <script> elements of a page isn't looked at.
        assert!(msg("https://a.test/").html("<p>jQuery v1.8.3</p>").scan(&VulnerableJs).is_empty());
        let img = msg("https://a.test/jquery-1.8.3.js").header("Content-Type", "image/png").body("x");
        assert!(img.scan(&VulnerableJs).is_empty());
    }
}
