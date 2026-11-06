//! Ported from ZAP RetireScanRule (retire, Apache License 2.0), with Retire.js's
//! vulnerability database (`jsrepository.json`, Apache License 2.0) as the retire add-on ships it.
//!
//! A JavaScript library is recognised by its URL, file name, content (for HTML pages, the
//! `<script>` elements), or SHA-1, and its version checked against the database's
//! vulnerable ranges. Beyond ZAP, a page's `<script src>` URLs are matched by URL and file
//! name too, so a library loaded from an out-of-scope CDN (never fetched) is still found. Patterns use the regex crate: the few that need look-around or
//! backreferences are skipped (the library's other patterns still apply). Compiled once,
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

struct Library {
    name: String,
    uri: Vec<Regex>,
    filename: Vec<Regex>,
    content: Vec<Regex>,
    hashes: BTreeMap<String, String>,
    vulns: Vec<RawVuln>,
}

struct Repo {
    libs: Vec<Library>,
    /// Patterns of the "dont check" entry: such files aren't checked at all.
    skip: Vec<Regex>,
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

fn compile(patterns: &[String]) -> Vec<Regex> {
    patterns.iter().filter_map(|p| Regex::new(&fix_pattern(p)).ok()).collect()
}

fn parse(text: &str) -> crate::Result<Repo> {
    let entries: BTreeMap<String, RawEntry> = serde_json::from_str(text)
        .map_err(|e| crate::Error::InvalidInput(format!("not a Retire.js repository: {e}")))?;
    let mut libs = Vec::new();
    let mut skip = Vec::new();
    for (name, e) in entries {
        let x = e.extractors;
        if name == "dont check" {
            skip = compile(&[x.uri, x.filename, x.filecontent].concat());
            continue;
        }
        libs.push(Library {
            name,
            uri: compile(&x.uri),
            filename: compile(&x.filename),
            content: compile(&x.filecontent),
            hashes: x.hashes.into_iter().map(|(h, v)| (h.to_ascii_lowercase(), v)).collect(),
            vulns: e.vulnerabilities,
        });
    }
    if libs.is_empty() || skip.is_empty() {
        return Err(crate::Error::InvalidInput("no libraries, or no \"dont check\" entry".into()));
    }
    Ok(Repo { libs, skip })
}

/// Number of libraries (data files are validated before use; see `crate::data`).
pub(crate) fn validate(text: &str) -> crate::Result<usize> {
    Ok(parse(text)?.libs.len())
}

static REPO: LazyLock<Option<Repo>> = LazyLock::new(|| parse(crate::data::get("jsrepository.json")).ok());

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

/// First library (in database order) whose `pick` patterns match `input` at a vulnerable version.
fn scan_by<'a>(repo: &'a Repo, input: &str, pick: fn(&Library) -> &Vec<Regex>) -> Option<Hit<'a>> {
    repo.libs.iter().find_map(|lib| {
        pick(lib).iter().find_map(|re| {
            let c = re.captures(input)?;
            vulnerable(lib, c.get(1)?.as_str(), c.get(0)?.as_str())
        })
    })
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
        if msg.status != 200 || !(msg.is_html() || msg.is_javascript()) {
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
        if [&msg.url, file, &content].iter().any(|s| repo.skip.iter().any(|re| re.is_match(s))) {
            return;
        }
        let mut note = String::new();
        let hit = scan_by(repo, &msg.url, |l| &l.uri)
            .or_else(|| (!file.is_empty()).then(|| scan_by(repo, file, |l| &l.filename)).flatten())
            .or_else(|| scan_by(repo, &content, |l| &l.content))
            .or_else(|| {
                // Scripts the page loads, by their src URL and file name.
                let srcs = SRC.captures_iter(&content).filter_map(|c| c.get(1)).map(|m| m.as_str());
                srcs.filter(|src| !repo.skip.iter().any(|re| re.is_match(src))).find_map(|src| {
                    let name = src.split(['?', '#']).next().unwrap_or("").rsplit('/').next().unwrap_or("");
                    let hit = scan_by(repo, src, |l| &l.uri).or_else(|| scan_by(repo, name, |l| &l.filename))?;
                    note = format!("Loaded by this page from {src}");
                    Some(hit)
                })
            })
            .or_else(|| {
                use sha1::Digest;
                let hash = hex::encode(sha1::Sha1::digest(&msg.resp_body));
                repo.libs.iter().find_map(|lib| {
                    let version = lib.hashes.get(&hash)?;
                    note = format!("The library matched the known vulnerable hash {hash}.");
                    vulnerable(lib, version, "")
                })
            });
        let Some(h) = hit else { return };
        let mut other = format!("The identified library {}, version {} is vulnerable.\n", h.lib.name, h.version);
        for line in h.cves.iter().chain([&note.as_str()].iter().copied().filter(|s| !s.is_empty())).chain(&h.info) {
            other.push_str(line);
            other.push('\n');
        }
        out.push(ALERT.raise("", h.evidence).risk(h.risk).other_info(other.trim_end()));
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
