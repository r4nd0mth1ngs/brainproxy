//! Built-in fuzzer wordlists, used as `wordlist:NAME` payload sources and listed by
//! `brainproxy wordlists`. Built by scripts/update-wordlists.py from upstream files pinned to
//! a commit (sources, licenses, and checksums in data/MANIFEST.json; attributions in NOTICE).

use serde_json::Value;

const LISTS: &[(&str, &str)] = &[
    ("sqli", include_str!("data/sqli.txt")),
    ("sqli-time", include_str!("data/sqli-time.txt")),
    ("sqli-login-bypass", include_str!("data/sqli-login-bypass.txt")),
    ("xss", include_str!("data/xss.txt")),
    ("path-traversal", include_str!("data/path-traversal.txt")),
    ("command-injection", include_str!("data/command-injection.txt")),
    ("ssti", include_str!("data/ssti.txt")),
    ("nosqli", include_str!("data/nosqli.txt")),
    ("naughty-strings", include_str!("data/naughty-strings.txt")),
    ("special-chars", include_str!("data/special-chars.txt")),
    ("content-discovery", include_str!("data/content-discovery.txt")),
    ("parameters", include_str!("data/parameters.txt")),
    ("headers", include_str!("data/headers.txt")),
    ("usernames", include_str!("data/usernames.txt")),
    ("passwords", include_str!("data/passwords.txt")),
    ("http-methods", include_str!("data/http-methods.txt")),
    ("extensions", include_str!("data/extensions.txt")),
];

const MANIFEST: &str = include_str!("data/MANIFEST.json");

/// The list's entries, one per line.
pub fn get(name: &str) -> Option<impl Iterator<Item = &'static str>> {
    LISTS.iter().find(|(n, _)| *n == name).map(|(_, data)| data.lines().filter(|l| !l.is_empty()))
}

pub fn names() -> impl Iterator<Item = &'static str> {
    LISTS.iter().map(|(n, _)| *n)
}

/// MANIFEST.json: `lists` (description, caution, count, sources, sha256) and `sources`
/// (repo, commit, license).
pub fn manifest() -> Value {
    serde_json::from_str(MANIFEST).expect("valid embedded manifest")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_lists_match_the_manifest() {
        let m = manifest();
        let listed: Vec<&str> = m["lists"].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(listed, names().collect::<Vec<_>>());
        for name in names() {
            assert_eq!(get(name).unwrap().count() as u64, m["lists"][name]["count"].as_u64().unwrap(), "{name}");
            let source = m["lists"][name]["sources"][0]["source"].as_str().unwrap();
            assert!(m["sources"][source]["license"].is_string(), "{name}: no license for {source}");
        }
        assert!(get("nope").is_none());
    }

    #[test]
    fn payloads_have_no_placeholder_left_for_another_tool() {
        // The fuzzer sends a payload as it is: `sleep(__TIME__)` would never delay anything.
        let placeholder = regex::Regex::new(r"__[A-Z][A-Z0-9_]*__").unwrap();
        for name in names() {
            for line in get(name).unwrap() {
                assert!(!placeholder.is_match(line), "{name}: {line}");
            }
        }
    }
}
