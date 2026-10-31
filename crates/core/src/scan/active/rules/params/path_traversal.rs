//! Ported from ZAP PathTraversalScanRule (ascanrules, Apache License 2.0).
//!
//! brainproxy has no technology filter, so every check runs (ZAP's default, where
//! all technologies are in scope). `isPage200` is a plain status check.

use std::sync::LazyLock;

use regex::Regex;

use super::common;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::passive::util::decode_entities;
use crate::scan::{AlertDef, Confidence, Risk};

macro_rules! alert {
    ($name:ident, $ref:literal) => {
        static $name: AlertDef = AlertDef {
            alert_ref: $ref,
            name: "Path Traversal",
            risk: Risk::High,
            confidence: Confidence::Medium,
            cwe: 22,
            wasc: 33,
            description: DESCRIPTION,
            solution: SOLUTION,
            references: REFERENCES,
            tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-ATHZ-01"],
        };
    };
}

const DESCRIPTION: &str = "The Path Traversal attack technique allows an attacker access to files, directories, and commands that \
        potentially reside outside the web document root directory. An attacker may manipulate a URL in such a way that \
        the web site will execute or reveal the contents of arbitrary files anywhere on the web server. Any device that \
        exposes an HTTP-based interface is potentially vulnerable to Path Traversal.\n\nMost web sites restrict user \
        access to a specific portion of the file-system, typically called the \"web document root\" or \"CGI root\" \
        directory. These directories contain the files intended for user access and the executable necessary to drive \
        web application functionality. To access files or execute commands anywhere on the file-system, Path Traversal \
        attacks will utilize the ability of special-characters sequences.\n\nThe most basic Path Traversal attack uses \
        the \"../\" special-character sequence to alter the resource location requested in the URL. Although most \
        popular web servers will prevent this technique from escaping the web document root, alternate encodings of the \
        \"../\" sequence may help bypass the security filters. These method variations include valid and invalid \
        Unicode-encoding (\"..%u2216\" or \"..%c0%af\") of the forward slash character, backslash characters (\"..\\\") \
        on Windows-based servers, URL encoded characters \"%2e%2e%2f\"), and double URL encoding (\"..%255c\") of the \
        backslash character.\n\nEven if the web server properly restricts Path Traversal attempts in the URL path, a \
        web application itself may still be vulnerable due to improper handling of user-supplied input. This is a \
        common problem of web applications that use template mechanisms or load static text from files. In variations \
        of the attack, the original URL parameter value is substituted with the file name of one of the web \
        application's dynamic scripts. Consequently, the results can reveal source code because the file is interpreted \
        as text instead of an executable script. These techniques often employ additional special characters such as \
        the dot (\".\") to reveal the listing of the current working directory, or \"%00\" NULL characters in order to \
        bypass rudimentary file extension checks.";
const SOLUTION: &str = "Assume all input is malicious. Use an \"accept known good\" input validation strategy, i.e., use an allow list \
        of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform \
        to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious \
        or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting \
        potential attacks or determining which inputs are so malformed that they should be rejected outright.\n\nWhen \
        performing input validation, consider all potentially relevant properties, including length, type of input, the \
        full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and \
        conformance to business rules. As an example of business rule logic, \"boat\" may be syntactically valid \
        because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as \
        \"red\" or \"blue.\"\n\nFor filenames, use stringent allow lists that limit the character set to be used. If \
        feasible, only allow a single \".\" character in the filename to avoid weaknesses, and exclude directory \
        separators such as \"/\". Use an allow list of allowable file extensions.\n\nWarning: if you attempt to cleanse \
        your data, then do so that the end result is not in the form that can be dangerous. A sanitizing mechanism can \
        remove characters such as '.' and ';' which may be required for some exploits. An attacker can try to fool the \
        sanitizing mechanism into \"cleaning\" data into a dangerous form. Suppose the attacker injects a '.' inside a \
        filename (e.g. \"sensi.tiveFile\") and the sanitizing mechanism removes the character resulting in the valid \
        filename, \"sensitiveFile\". If the input data are now assumed to be safe, then the file may be compromised. \
        \n\nInputs should be decoded and canonicalized to the application's current internal representation before \
        being validated. Make sure that your application does not decode the same input twice. Such errors could be \
        used to bypass allow list schemes by introducing dangerous inputs after they have been checked.\n\nUse a \
        built-in path canonicalization function (such as realpath() in C) that produces the canonical version of the \
        pathname, which effectively removes \"..\" sequences and symbolic links.\n\nRun your code using the lowest \
        privileges that are required to accomplish the necessary tasks. If possible, create isolated accounts with \
        limited privileges that are only used for a single task. That way, a successful attack will not immediately \
        give the attacker access to the rest of the software or its environment. For example, database applications \
        rarely need to run as the database administrator, especially in day-to-day operations.\n\nWhen the set of \
        acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input \
        values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.\n\nRun your code in \
        a \"jail\" or similar sandbox environment that enforces strict boundaries between the process and the operating \
        system. This may effectively restrict which files can be accessed in a particular directory or which commands \
        can be executed by your software.\n\nOS-level examples include the Unix chroot jail, AppArmor, and SELinux. In \
        general, managed code may provide some protection. For example, java.io.FilePermission in the Java \
        SecurityManager allows you to specify restrictions on file operations.\n\nThis may not be a feasible solution, \
        and it only limits the impact to the operating system; the rest of your application may still be subject to \
        compromise.";
const REFERENCES: &[&str] =
    &["https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"];
const INFO: &str =
    "While the evidence field indicates {0}, the rule actually checked that the response contains matches for all of \
        the following: {1}.";

alert!(ALERT_1, "6-1");
alert!(ALERT_2, "6-2");
alert!(ALERT_3, "6-3");
alert!(ALERT_4, "6-4");
alert!(ALERT_5, "6-5");

static ALERTS: [&AlertDef; 5] = [&ALERT_1, &ALERT_2, &ALERT_3, &ALERT_4, &ALERT_5];

const NON_EXISTANT_FILENAME: &str = "thishouldnotexistandhopefullyitwillnot";

const WIN_DIR_EVIDENCE: &str = "Windows";
pub(crate) const WIN_LOCAL_FILE_TARGETS: &[&str] = &[
    "c:/Windows/system.ini",
    "../../../../../../../../../../../../../../../../Windows/system.ini",
    "c:\\Windows\\system.ini",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
    "/../../../../../../../../../../../../../../../../Windows/system.ini",
    "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
    "Windows/system.ini",
    "Windows\\system.ini",
    "file:///c:/Windows/system.ini",
    "file:///c:\\Windows\\system.ini",
    "file:\\\\\\c:\\Windows\\system.ini",
    "file:\\\\\\c:/Windows/system.ini",
    "d:\\Windows\\system.ini",
    "d:/Windows/system.ini",
    "file:///d:/Windows/system.ini",
    "file:///d:\\Windows\\system.ini",
    "file:\\\\\\d:\\Windows\\system.ini",
    "file:\\\\\\d:/Windows/system.ini",
];

const NIX_DIR_EVIDENCE: &str = "etc";
pub(crate) const NIX_LOCAL_FILE_TARGETS: &[&str] = &[
    "/etc/passwd",
    "../../../../../../../../../../../../../../../../etc/passwd",
    "/../../../../../../../../../../../../../../../../etc/passwd",
    "etc/passwd",
    "file:///etc/passwd",
    "file:\\\\\\etc/passwd",
];

const WIN_LOCAL_DIR_TARGETS: &[&str] = &[
    "c:/",
    "c:\\",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
    "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
    "file:///c:/",
    "file:///c:\\",
    "file:\\\\\\c:\\",
    "file:\\\\\\c:/",
    "file:\\\\\\",
    "d:\\",
    "d:/",
    "file:///d:/",
    "file:///d:\\",
    "file:\\\\\\d:\\",
    "file:\\\\\\d:/",
];

const NIX_LOCAL_DIR_TARGETS: &[&str] = &[
    "/",
    "../../../../../../../../../../../../../../../../",
    "/../../../../../../../../../../../../../../../../",
    "file:///",
];

const LOCAL_FILE_RELATIVE_PREFIXES: &[&str] = &["", "/", "\\"];

static WIN_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[drivers\]").unwrap());
// Dot used to match 'x' or '!' (used in AIX).
static NIX_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"root:.:0:0").unwrap());
static WAR_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"</web-app>").unwrap());
static ERROR_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Exception|Error").unwrap());
static PROGRAM_FILES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Program\sFiles").unwrap());
// Java's `\W` is ASCII-only: `(?:^|\W)name(?:\W|$)`.
static NIX_DIRS: LazyLock<[Regex; 5]> = LazyLock::new(|| {
    ["proc", "etc", "boot", "tmp", "home"]
        .map(|d| Regex::new(&format!(r"(?i)(?:^|[^0-9A-Za-z_]){d}(?:[^0-9A-Za-z_]|$)")).unwrap())
});
const NIX_MATCHES: &str = "proc, etc, boot, tmp, home";
const WIN_MATCHES: &str = "Windows, Program Files";

#[derive(Clone, Copy)]
pub(crate) enum Matcher {
    Pattern(&'static LazyLock<Regex>),
    NixDirs,
    WinDirs,
}

impl Matcher {
    /// ContentsMatcher.match: the evidence, if the contents match.
    pub(crate) fn find(self, contents: &str) -> Option<String> {
        match self {
            Matcher::Pattern(re) => re.find(contents).map(|m| m.as_str().to_string()),
            Matcher::NixDirs => NIX_DIRS.iter().all(|re| re.is_match(contents)).then(|| NIX_DIR_EVIDENCE.to_string()),
            Matcher::WinDirs => (contents.contains(WIN_DIR_EVIDENCE) && PROGRAM_FILES.is_match(contents))
                .then(|| WIN_DIR_EVIDENCE.to_string()),
        }
    }
}

/// HTML responses are entity-decoded; others are matched with their headers.
fn contents_to_match(resp: &Response) -> String {
    if common::is_html(resp) {
        decode_entities(resp.body_str())
    } else {
        format!("{}{}", resp.head_text(), resp.body_str())
    }
}

/// Request counts per strength: (nix, win, nix dir, win dir, WEB-INF depth, null byte).
fn counts(strength: Strength) -> (usize, usize, usize, usize, usize, bool) {
    match strength {
        Strength::Low => (2, 2, 1, 1, 0, false),
        Strength::Medium => (2, 4, 2, 2, 1, false),
        Strength::High => (4, 8, 3, 4, 2, false),
        Strength::Insane => (
            NIX_LOCAL_FILE_TARGETS.len(),
            WIN_LOCAL_FILE_TARGETS.len(),
            NIX_LOCAL_DIR_TARGETS.len(),
            WIN_LOCAL_DIR_TARGETS.len(),
            4,
            true,
        ),
    }
}

/// `URI.getName()`: the last path segment.
fn url_file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

pub struct PathTraversal;

impl ActiveRule for PathTraversal {
    fn id(&self) -> u32 {
        6
    }

    fn name(&self) -> &'static str {
        "Path Traversal"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let (nix, win, nix_dir, win_dir, depth, null_byte) = counts(cx.strength());
            let value = &cx.point().value;
            let extension = if null_byte { value.rfind('.').map(|i| &value[i..]) } else { None };
            let base = contents_to_match(cx.base_response());
            let check = Check { cx, base: &base };
            let null = common::NULL_BYTE;

            // Check 1: Windows local files.
            let win_pattern = Matcher::Pattern(&WIN_PATTERN);
            for target in &WIN_LOCAL_FILE_TARGETS[..win] {
                if check.send(target, win_pattern, &ALERT_1).await {
                    return;
                }
                if null_byte {
                    if check.send(&format!("{target}{null}"), win_pattern, &ALERT_1).await {
                        return;
                    }
                    if let Some(ext) = extension {
                        if check.send(&format!("{target}{null}{ext}"), win_pattern, &ALERT_1).await {
                            return;
                        }
                    }
                }
            }
            // Check 2: *NIX local files.
            let nix_pattern = Matcher::Pattern(&NIX_PATTERN);
            for target in &NIX_LOCAL_FILE_TARGETS[..nix] {
                if check.send(target, nix_pattern, &ALERT_2).await {
                    return;
                }
                if null_byte {
                    if check.send(&format!("{target}{null}"), nix_pattern, &ALERT_2).await {
                        return;
                    }
                    if let Some(ext) = extension {
                        if check.send(&format!("{target}{null}{ext}"), nix_pattern, &ALERT_2).await {
                            return;
                        }
                    }
                }
            }
            // Check 3: directory listings.
            for target in &NIX_LOCAL_DIR_TARGETS[..nix_dir] {
                if check.send(target, Matcher::NixDirs, &ALERT_3).await {
                    return;
                }
            }
            for target in &WIN_LOCAL_DIR_TARGETS[..win_dir] {
                if check.send(target, Matcher::WinDirs, &ALERT_3).await {
                    return;
                }
            }
            // Check 4: well known J2EE files with increasing ../ prefixes.
            let war = Matcher::Pattern(&WAR_PATTERN);
            let mut sslash = "WEB-INF/web.xml".to_string();
            let mut bslash = sslash.replace('/', "\\");
            for _ in 0..depth {
                for v in [sslash.clone(), bslash.clone(), format!("/{sslash}"), format!("\\{bslash}")] {
                    if check.send(&v, war, &ALERT_4).await {
                        return;
                    }
                }
                sslash = format!("../{sslash}");
                bslash = format!("..\\{bslash}");
            }

            // Check 5 (LOW and MEDIUM threshold): the URL's own file name as the value,
            // when a random value does not give a 200 (or gives an error page).
            let Ok(resp) = common::send_following(cx, NON_EXISTANT_FILENAME).await else { return };
            let file_name = url_file_name(&cx.base().path);
            if file_name.is_empty() || (resp.status == 200 && !ERROR_PATTERN.is_match(resp.body_str())) {
                return;
            }
            for prefix in LOCAL_FILE_RELATIVE_PREFIXES {
                if cx.stopped() {
                    return;
                }
                let attack = format!("{prefix}{file_name}");
                // The original request, as on a URL path's last segment: it proves nothing.
                if attack == cx.point().value {
                    continue;
                }
                let Ok(resp) = common::send_following(cx, &attack).await else { continue };
                // The same page as the original request (a server that normalises `/x` to `x`)
                // is not the file's contents.
                let unchanged = resp.body_str() == cx.base_response().body_str();
                if resp.status == 200 && !unchanged && !ERROR_PATTERN.is_match(resp.body_str()) {
                    let f = ALERT_5.raise(cx.point().name.clone(), "").attack(attack).confidence(Confidence::Low);
                    cx.report(f, &resp);
                    return;
                }
            }
        })
    }
}

struct Check<'a> {
    cx: &'a Cx,
    base: &'a str,
}

impl Check<'_> {
    /// sendAndCheckPayload: true when a finding was raised or the scan stopped.
    async fn send(&self, value: &str, matcher: Matcher, alert: &'static AlertDef) -> bool {
        if self.cx.stopped() {
            return true;
        }
        if matcher.find(self.base).is_some() {
            // Evidence already present, no point sending the attack.
            return false;
        }
        let Ok(resp) = common::send_following(self.cx, value).await else { return false };
        let Some(evidence) = matcher.find(&contents_to_match(&resp)) else { return false };
        if resp.status != 200 {
            return false;
        }
        let mut f = alert.raise(self.cx.point().name.clone(), evidence.clone()).attack(value);
        if evidence == NIX_DIR_EVIDENCE || evidence == WIN_DIR_EVIDENCE {
            let all = if evidence == WIN_DIR_EVIDENCE { WIN_MATCHES } else { NIX_MATCHES };
            f = f.other_info(INFO.replace("{0}", &evidence).replace("{1}", all));
        }
        self.cx.report(f, &resp);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_counts_per_strength() {
        let total = |s| {
            let (n, w, nd, wd, d, _) = counts(s);
            n + w + nd + wd + d * 4 + 1
        };
        // ZAP's documented totals per parameter (excluding the final url-filename check).
        assert_eq!(total(Strength::Low), 7);
        assert_eq!(total(Strength::Medium), 15);
        assert_eq!(total(Strength::High), 28);
        assert_eq!(WIN_LOCAL_FILE_TARGETS.len(), 18);
        assert_eq!(WIN_LOCAL_DIR_TARGETS.len(), 15);
        assert_eq!(NIX_LOCAL_FILE_TARGETS[5], r"file:\\\etc/passwd");
    }

    #[test]
    fn matchers() {
        let p = Matcher::Pattern(&NIX_PATTERN);
        assert_eq!(p.find("root:x:0:0:root:/root:/bin/bash").as_deref(), Some("root:x:0:0"));
        assert_eq!(p.find("root:!:0:0").as_deref(), Some("root:!:0:0"));
        assert!(p.find("root:xx:0:0").is_none());
        assert_eq!(
            Matcher::Pattern(&WIN_PATTERN).find("; for 16-bit app support\n[drivers]\nwave=mmdrv.dll").as_deref(),
            Some("[drivers]")
        );
        let listing = "bin\nboot\ndev\netc\nhome\nproc\ntmp\nusr";
        assert_eq!(Matcher::NixDirs.find(listing).as_deref(), Some("etc"));
        assert!(Matcher::NixDirs.find("bin boot etcetera home proc tmp").is_none());
        assert_eq!(Matcher::WinDirs.find("Windows Program Files Users").as_deref(), Some("Windows"));
        assert!(Matcher::WinDirs.find("Windows ProgramFiles").is_none());
    }

    #[test]
    fn other_info_and_file_names() {
        let info = INFO.replace("{0}", "etc").replace("{1}", NIX_MATCHES);
        assert_eq!(
            info,
            "While the evidence field indicates etc, the rule actually checked that the response contains matches for \
             all of the following: proc, etc, boot, tmp, home."
        );
        assert_eq!(url_file_name("/a/b/view.jsp"), "view.jsp");
        assert_eq!(url_file_name("/a/"), "");
    }
}
