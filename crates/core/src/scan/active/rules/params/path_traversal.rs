//! Ported from ZAP PathTraversalScanRule (ascanrules, Apache License 2.0).
//!
//! brainproxy has no technology filter, so every check runs (ZAP's default, where
//! all technologies are in scope). `isPage200` is a plain status check.
//!
//! ZAP's check 5 (alert 6-5) isn't run. It sends the URL's own file name and reports a 200
//! without "error" in it after a random value didn't get one: the status alone, rated high.
//! That is what any parameter that takes a name from a fixed list does (`?view=products`), and
//! where the value already was the file name it resent the original request: on the OWASP
//! Benchmark it raised 15 false reports and no true one in 1,639 tests. Nothing in such a
//! response shows a file was read, and the probe names the app's own script, which a sink that
//! writes to the path (PHP resolves it next to the script) would overwrite.
//!
//! Two checks of brainproxy's own find sinks that never show a file's contents: one that only
//! says whether a file exists, opens it without printing it, or prints only an error. They
//! compare answers, each confirmed by a second request, and read nothing:
//! - 6-6 (medium): a directory every system has at its root, reached with `../` or from `/`,
//!   (`/etc`, `/usr`; `C:\Windows`, `C:\Users`) gets another answer than the same name under
//!   a directory that doesn't exist, and the two directories get the same one. The value got
//!   out of the directory the app meant.
//! - 6-7 (low): the original value and `./value` get the same answer, while `./RANDOM/value`
//!   and `RANDOM/../value` get another, the same for both: the value is a path the file system
//!   resolves as given, not normalised or cut to a file name first. That `../` gets out isn't
//!   shown, which is why it is low.
//!
//! The value is taken out of each answer before they are compared, since such pages often
//! show the path they were given.

use std::sync::LazyLock;

use regex::Regex;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

use super::common;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
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
alert!(ALERT_EXISTS, "6-6");
alert!(ALERT_LOOKUP, "6-7");

static ALERTS: [&AlertDef; 5] = [&ALERT_1, &ALERT_2, &ALERT_3, &ALERT_EXISTS, &ALERT_LOOKUP];

// The files read are ones nothing can overwrite. A sink that *writes* to the path it is given
// (a servlet saving an upload under the name sent, say) opens the target for writing, which
// truncates it: ZAP's /etc/passwd emptied the OWASP Benchmark container's, running as root. So:
// - *nix: /proc/version, which the kernel makes up on every read; opening it for writing
//   truncates nothing, and writing to it fails, even as root.
// - Windows: kernel32.dll in System32, owned by TrustedInstaller (Administrators and SYSTEM may
//   only read it) and mapped as an image into every process, which no one may then open for
//   writing.
// The directory listings (check 3) can't be written to at all. ZAP's J2EE check (6-4, the app's
// own WEB-INF/web.xml, which a write sink could replace) isn't run, for the same reason.
// What it gives up: *nix systems without a Linux /proc (BSDs, macOS) are found only by their
// directory listing.
const WIN_DIR_EVIDENCE: &str = "Windows";
pub(crate) const WIN_LOCAL_FILE_TARGETS: &[&str] = &[
    "c:/Windows/System32/kernel32.dll",
    "../../../../../../../../../../../../../../../../Windows/System32/kernel32.dll",
    "c:\\Windows\\System32\\kernel32.dll",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\System32\\kernel32.dll",
    "/../../../../../../../../../../../../../../../../Windows/System32/kernel32.dll",
    "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\System32\\kernel32.dll",
    "Windows/System32/kernel32.dll",
    "Windows\\System32\\kernel32.dll",
    "file:///c:/Windows/System32/kernel32.dll",
    "file:///c:\\Windows\\System32\\kernel32.dll",
    "file:\\\\\\c:\\Windows\\System32\\kernel32.dll",
    "file:\\\\\\c:/Windows/System32/kernel32.dll",
    "d:\\Windows\\System32\\kernel32.dll",
    "d:/Windows/System32/kernel32.dll",
    "file:///d:/Windows/System32/kernel32.dll",
    "file:///d:\\Windows\\System32\\kernel32.dll",
    "file:\\\\\\d:\\Windows\\System32\\kernel32.dll",
    "file:\\\\\\d:/Windows/System32/kernel32.dll",
];

const NIX_DIR_EVIDENCE: &str = "etc";
pub(crate) const NIX_LOCAL_FILE_TARGETS: &[&str] = &[
    "/proc/version",
    "../../../../../../../../../../../../../../../../proc/version",
    "/../../../../../../../../../../../../../../../../proc/version",
    "proc/version",
    "file:///proc/version",
    "file:\\\\\\proc/version",
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

// The DOS stub every PE file starts with.
static WIN_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"This program cannot be run in DOS mode").expect("static regex"));
static NIX_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Linux version \d+\.\d+\S* \(").expect("static regex"));
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

/// Request counts per strength: (nix, win, nix dir, win dir, null byte).
fn counts(strength: Strength) -> (usize, usize, usize, usize, bool) {
    match strength {
        Strength::Low => (2, 2, 1, 1, false),
        Strength::Medium => (2, 4, 2, 2, false),
        Strength::High => (4, 8, 3, 4, false),
        Strength::Insane => (
            NIX_LOCAL_FILE_TARGETS.len(),
            WIN_LOCAL_FILE_TARGETS.len(),
            NIX_LOCAL_DIR_TARGETS.len(),
            WIN_LOCAL_DIR_TARGETS.len(),
            true,
        ),
    }
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
            let (nix, win, nix_dir, win_dir, null_byte) = counts(cx.strength());
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
            if existence(cx).await || cx.stopped() {
                return;
            }
            lookup(cx).await;
        })
    }
}

/// How the existence check reaches the root: a prefix, the separator after a directory, and
/// two directories every such system has there.
type RootForm = (&'static str, char, [&'static str; 2]);

const UP_NIX: &str = "../../../../../../../../../../../../../../../../";
const UP_WIN: &str = "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\";

/// The forms the existence check tries at each strength, most likely first.
fn root_forms(strength: Strength) -> &'static [RootForm] {
    const FORMS: &[RootForm] = &[
        (UP_NIX, '/', ["etc", "usr"]),
        ("/", '/', ["etc", "usr"]),
        (UP_WIN, '\\', ["Windows", "Users"]),
        ("c:\\", '\\', ["Windows", "Users"]),
    ];
    match strength {
        Strength::Low => &FORMS[..1],
        Strength::Medium => &FORMS[..3],
        Strength::High | Strength::Insane => FORMS,
    }
}

/// A random directory name: the same length every time, so two answers that show it compare
/// alike.
fn random_dir() -> String {
    format!("{:012x}", rand_u64() & 0xffff_ffff_ffff)
}

/// An answer as the checks compare them: its status and its body, entities decoded, with
/// every value the check sent taken out wherever the page shows it.
#[derive(Debug, PartialEq)]
struct Shape {
    status: u16,
    body: String,
}

/// The ways a page may show a value it was sent: as it is, URL-encoded, or escaped in a
/// JavaScript or JSON string.
fn shown_forms(sent: &str) -> [String; 5] {
    [
        sent.to_string(),
        common::url_encode(sent),
        utf8_percent_encode(sent, NON_ALPHANUMERIC).to_string(),
        sent.replace('\\', "\\\\").replace('/', "\\/"),
        sent.replace('\\', "\\\\"),
    ]
}

/// `body` (entities decoded) with each of `sent`, in any of its forms, taken out.
fn shape(status: u16, body: &str, sent: &[String]) -> Shape {
    let mut forms: Vec<String> = sent.iter().flat_map(|s| shown_forms(s)).filter(|f| !f.is_empty()).collect();
    // Longest first, so a value isn't cut by a shorter one inside it.
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));
    forms.dedup();
    let mut body = decode_entities(body);
    for f in &forms {
        body = body.replace(f.as_str(), "\u{1}");
    }
    Shape { status, body }
}

/// The answers one check got. Each comparison takes every value the check sent out of both
/// answers, not only each one's own: a page that shows `/srv/files/etc` for any value ending in
/// `etc` would otherwise look different for `/etc` (taken out) and `/RANDOM/etc` (not there).
struct Probes<'a> {
    cx: &'a Cx,
    sent: Vec<String>,
    got: Vec<Response>,
}

impl<'a> Probes<'a> {
    fn new(cx: &'a Cx) -> Self {
        Self { cx, sent: Vec::new(), got: Vec::new() }
    }

    /// Sends `value`; its index, or None when it got no answer, or one that says to slow down
    /// (which says nothing about the value).
    async fn send(&mut self, value: &str) -> Option<usize> {
        let resp = common::send_following(self.cx, value).await.ok()?;
        if matches!(resp.status, 429 | 503) {
            return None;
        }
        self.sent.push(value.to_string());
        self.got.push(resp);
        Some(self.got.len() - 1)
    }

    fn shape(&self, i: usize) -> Shape {
        shape(self.got[i].status, self.got[i].body_str(), &self.sent)
    }

    fn alike(&self, a: usize, b: usize) -> bool {
        self.shape(a) == self.shape(b)
    }
}

/// The first line of `hit` that `miss` hasn't and that doesn't show a value sent: what the page
/// says differently (at most 200 characters).
fn evidence(hit: &Shape, miss: &Shape) -> String {
    let theirs: std::collections::HashSet<&str> = miss.body.lines().map(str::trim).collect();
    let line = hit.body.lines().map(str::trim).find(|l| !l.is_empty() && !l.contains('\u{1}') && !theirs.contains(l));
    line.map(|l| l.chars().take(200).collect()).unwrap_or_default()
}

/// 6-6: a directory at the root against the same name under one that doesn't exist. Every
/// path it sends is a directory or under a missing one, which nothing can open for writing.
async fn existence(cx: &Cx) -> bool {
    for &(prefix, sep, [dir, other_dir]) in root_forms(cx.strength()) {
        if cx.stopped() {
            return true;
        }
        let mut p = Probes::new(cx);
        let there = format!("{prefix}{dir}");
        let missing = |rnd: &str| format!("{prefix}{rnd}{sep}{dir}");
        let first_missing = missing(&random_dir());
        let (Some(hit), Some(miss)) = (p.send(&there).await, p.send(&first_missing).await) else { continue };
        if p.alike(hit, miss) {
            continue;
        }
        // Each again: a page that changes by itself, or shows the path in a form not taken
        // out, doesn't give the same answer twice.
        let other = format!("{prefix}{other_dir}");
        let (Some(miss_again), Some(hit_again)) = (p.send(&missing(&random_dir())).await, p.send(&other).await) else {
            continue;
        };
        if p.alike(hit, miss) || !p.alike(miss, miss_again) || !p.alike(hit, hit_again) {
            continue;
        }
        let info = format!(
            "The directories {there} and {other} gave one answer, and {first_missing} and another path under a \
             directory that doesn't exist gave another: the value reaches the file system outside the directory \
             the application meant. No file was read; the check only compares answers."
        );
        let f = ALERT_EXISTS
            .raise(cx.point().name.clone(), evidence(&p.shape(hit), &p.shape(miss)))
            .attack(there)
            .other_info(info);
        cx.report(f, &p.got[hit]);
        return true;
    }
    false
}

/// 6-7: the original value, as `./value`, against it under a directory that doesn't exist.
/// It names only the file the value already names (`./value`, and `RANDOM/../value` where a
/// path is resolved by its text), or a path under a missing directory.
async fn lookup(cx: &Cx) -> bool {
    let value = cx.point().value.as_str();
    // A path from the root, a URL or a drive, or what is too short to tell from the rest of
    // the page once taken out of it.
    let unusable = value.len() < 3
        || value.len() > 200
        || value.starts_with(['/', '\\', '.'])
        || value.contains([':', '\r', '\n', '\0']);
    if unusable {
        return false;
    }
    let mut p = Probes::new(cx);
    let same = format!("./{value}");
    let (Some(original), Some(same_at)) = (p.send(value).await, p.send(&same).await) else { return false };
    if !p.alike(original, same_at) {
        return false;
    }
    let below = |rnd: &str| format!("./{rnd}/{value}");
    let Some(miss) = p.send(&below(&random_dir())).await else { return false };
    if p.alike(original, miss) {
        return false;
    }
    // A path cleaned by its text (`a/../b` is `b`) gives the original answer here; the file
    // system can't go through a directory that doesn't exist.
    let through = format!("{}/../{value}", random_dir());
    let (Some(miss_again), Some(through_at)) = (p.send(&below(&random_dir())).await, p.send(&through).await) else {
        return false;
    };
    let holds = p.alike(original, same_at)
        && !p.alike(original, miss)
        && p.alike(miss, miss_again)
        && p.alike(miss, through_at);
    if !holds {
        return false;
    }
    let info = format!(
        "{value} and {same} gave the same answer, and {through} the one a path under a directory that doesn't exist \
         gave: the value is a path the file system resolves as it is given, not cleaned or cut to a file name \
         first. Whether ../ gets out of the directory isn't shown. No file was read; the check only compares \
         answers."
    );
    let f = ALERT_LOOKUP
        .raise(cx.point().name.clone(), evidence(&p.shape(same_at), &p.shape(miss)))
        .attack(same)
        .other_info(info)
        .confidence(Confidence::Low);
    cx.report(f, &p.got[same_at]);
    true
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
            let (n, w, nd, wd, _) = counts(s);
            n + w + nd + wd
        };
        // ZAP's totals per parameter (7, 15, 28) less check 5's random value and the J2EE
        // check's web.xml requests (0, 4, 8).
        assert_eq!(total(Strength::Low), 6);
        assert_eq!(total(Strength::Medium), 10);
        assert_eq!(total(Strength::High), 19);
        assert_eq!(WIN_LOCAL_FILE_TARGETS.len(), 18);
        assert_eq!(WIN_LOCAL_DIR_TARGETS.len(), 15);
        assert_eq!(NIX_LOCAL_FILE_TARGETS[5], r"file:\\\proc/version");
    }

    /// The file a sink opens for a target: no `file:` scheme, drive or `..`, `/` separators.
    fn resolved(target: &str) -> String {
        let path = target.strip_prefix("file:").unwrap_or(target).replace('\\', "/");
        let path = path.trim_start_matches('/');
        let path = path.get(1..2).filter(|c| *c == ":").map_or(path, |_| path.get(2..).unwrap_or(""));
        path.split('/').filter(|s| !s.is_empty() && *s != "." && *s != "..").collect::<Vec<_>>().join("/")
    }

    #[test]
    fn nothing_sent_names_a_file_a_write_could_clobber() {
        // A sink that writes where it is told truncates what it opens: these must be a file no
        // one can write (procfs, a protected system DLL in use) or a directory.
        for t in NIX_LOCAL_FILE_TARGETS.iter().chain(WIN_LOCAL_FILE_TARGETS) {
            let file = resolved(t);
            assert!(
                file == "proc/version" || file.eq_ignore_ascii_case("Windows/System32/kernel32.dll"),
                "{t} opens {file}"
            );
        }
        for t in NIX_LOCAL_DIR_TARGETS.iter().chain(WIN_LOCAL_DIR_TARGETS) {
            assert!(t.ends_with('/') || t.ends_with('\\'), "{t} is a directory");
            assert_eq!(resolved(t), "", "{t} is the root");
        }
        assert_eq!(resolved(r"file:\\\c:\Windows\System32\kernel32.dll"), "Windows/System32/kernel32.dll");
        assert_eq!(resolved("../../etc/passwd"), "etc/passwd");
    }

    #[test]
    fn matchers() {
        let p = Matcher::Pattern(&NIX_PATTERN);
        let version = "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-075) (x86_64-linux-gnu-gcc-13) #45-Ubuntu";
        assert_eq!(p.find(version).as_deref(), Some("Linux version 6.8.0-45-generic ("));
        assert!(p.find("Runs on Linux version 6 and later").is_none());
        let pe = "MZ\u{90}\0\u{3}\0\0\0\u{4}\0\0\0\u{ff}\u{ff}\0\0!This program cannot be run in DOS mode.\r\r\n$";
        assert_eq!(Matcher::Pattern(&WIN_PATTERN).find(pe).as_deref(), Some("This program cannot be run in DOS mode"));
        let listing = "bin\nboot\ndev\netc\nhome\nproc\ntmp\nusr";
        assert_eq!(Matcher::NixDirs.find(listing).as_deref(), Some("etc"));
        assert!(Matcher::NixDirs.find("bin boot etcetera home proc tmp").is_none());
        assert_eq!(Matcher::WinDirs.find("Windows Program Files Users").as_deref(), Some("Windows"));
        assert!(Matcher::WinDirs.find("Windows ProgramFiles").is_none());
    }

    #[test]
    fn other_info() {
        let info = INFO.replace("{0}", "etc").replace("{1}", NIX_MATCHES);
        assert_eq!(
            info,
            "While the evidence field indicates etc, the rule actually checked that the response contains matches for \
             all of the following: proc, etc, boot, tmp, home."
        );
    }
}

#[cfg(test)]
mod e2e {
    //! The existence and lookup checks against pages over a real directory, which never show a
    //! file's contents.
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use crate::guard::{Guard, ScopeSpec};
    use crate::http::{SendOptions, Target};
    use crate::jobs::JobControl;
    use crate::scan::active::{run, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};
    use crate::scan::message::url_decode;

    /// Escaped as the OWASP Benchmark's ESAPI encoder does, `/` included.
    fn escape(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || " .-_".contains(c) {
                    c.to_string()
                } else {
                    format!("&#x{:x};", c as u32)
                }
            })
            .collect()
    }

    /// `a/./b/../c` as `a/c`, by its text; None when it climbs out of where it starts.
    fn clean(v: &str) -> Option<String> {
        let mut out: Vec<&str> = Vec::new();
        for part in v.split(['/', '\\']) {
            match part {
                "" | "." => {}
                ".." => {
                    out.pop()?;
                }
                p => out.push(p),
            }
        }
        Some(out.join("/"))
    }

    fn page(dir: &Path, path: &str, v: &str) -> Option<String> {
        let base = dir.to_string_lossy();
        let says = |file: &str, exists: bool| {
            let tail = if exists { "And file already exists." } else { "But file doesn't exist yet." };
            format!("<html><body><p>Access to file: '{}' created.</p>\n<p>{tail}</p></body></html>", escape(file))
        };
        Some(match path {
            // The directory and the value, joined as text, as `TESTFILES_DIR + param` does.
            "/exists" => {
                let file = format!("{base}/{v}");
                says(&file, Path::new(&file).exists())
            }
            // Only a file counts, so a directory looks like nothing there.
            "/is-file" => {
                let file = format!("{base}/{v}");
                says(&file, Path::new(&file).is_file())
            }
            // Safe: only the file name is used.
            "/basename" => {
                let name = Path::new(v).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let file = dir.join(&name);
                says(&file.to_string_lossy(), !name.is_empty() && file.exists())
            }
            // Safe: the path cleaned by its text, and refused when it climbs out.
            "/cleaned" => match clean(v) {
                Some(rel) if !rel.is_empty() => {
                    let file = dir.join(&rel);
                    says(&file.to_string_lossy(), file.exists())
                }
                _ => "<html><body><p>Not allowed.</p></body></html>".into(),
            },
            // Safe: reads the value and ignores it.
            "/ignored" => says(&format!("{base}/notes.txt"), true),
            _ => return None,
        })
    }

    fn spawn_app(dir: PathBuf) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let target = req.split(' ').nth(1).unwrap_or("/").to_string();
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let v = query.strip_prefix("file=").map(url_decode).unwrap_or_default();
                    let resp = match page(&dir, path, &v) {
                        Some(body) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        ),
                        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
                    };
                    let _ = s.write_all(resp.as_bytes());
                });
            }
        });
        port
    }

    fn fetch(port: u16, path: &str) -> (Vec<u8>, Vec<u8>) {
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").into_bytes();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(&req).unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).unwrap();
        (req, resp)
    }

    async fn scan(name: &str, port: u16, path: &str, strength: Strength) -> ActiveSummary {
        let (request, response) = fetch(port, path);
        let target = Target::from_url(&format!("http://127.0.0.1:{port}{path}")).unwrap();
        let targets = vec![ScanTarget { history_id: None, target, request, response, duration_ms: None }];
        let project = std::env::temp_dir().join(format!("bp-pt-{name}-{}.bpdb", std::process::id()));
        let _ = std::fs::remove_file(&project);
        let guard =
            Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }])
                .unwrap();
        let cfg = ActiveConfig {
            strength,
            tuning: Default::default(),
            concurrency: 2,
            rate: None,
            send: SendOptions { guard: Some(guard), timeout: Duration::from_secs(10), ..Default::default() },
            points: PointOptions::default(),
            rules: Some(vec![6]),
            exclude_rules: vec![],
            no_rules: false,
            checks: vec![],
            max_duration: Some(Duration::from_secs(120)),
            auth: None,
            oob: None,
            oob_wait: Duration::ZERO,
            check_methods: vec![],
            prune: false,
        };
        let s = run(&project, targets, cfg, JobControl::default()).await.unwrap();
        let _ = std::fs::remove_file(&project);
        s
    }

    fn app(name: &str) -> (PathBuf, u16) {
        let dir = std::env::temp_dir().join(format!("bp-pt-files-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("notes.txt"), "notes").unwrap();
        let port = spawn_app(dir.clone());
        (dir, port)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_page_that_only_says_whether_a_file_exists_is_found() {
        let (dir, port) = app("exists");
        let s = scan("exists", port, "/exists?file=notes.txt", Strength::Medium).await;
        assert_eq!(s.raised.get("6-6"), Some(&1), "{s:?}");
        assert_eq!(s.raised.len(), 1, "{s:?}");
        // At low strength too, through `../` (*nix only: Windows' form is tried from medium).
        if !cfg!(windows) {
            let s = scan("exists-low", port, "/exists?file=notes.txt", Strength::Low).await;
            assert_eq!(s.raised.get("6-6"), Some(&1), "{s:?}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_value_used_as_a_path_as_given_is_a_low_confidence_lookup() {
        let (dir, port) = app("is-file");
        let s = scan("is-file", port, "/is-file?file=notes.txt", Strength::Medium).await;
        // Windows resolves `RANDOM\..\notes.txt` by its text, as a path cleaned first would be.
        let expected = if cfg!(windows) { None } else { Some(&1) };
        assert_eq!(s.raised.get("6-7"), expected, "{s:?}");
        assert_eq!(s.raised.get("6-6"), None, "a directory isn't a file there: {s:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pages_that_ignore_or_clean_the_value_raise_nothing() {
        let (dir, port) = app("safe");
        for path in ["/basename?file=notes.txt", "/cleaned?file=notes.txt", "/ignored?file=notes.txt"] {
            let s = scan("safe", port, path, Strength::High).await;
            assert!(s.raised.is_empty(), "{path}: {s:?}");
            assert!(s.requests > 10, "{path}: the rule attacked: {s:?}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn answers_compare_without_the_value_they_show() {
        let sent = ["../etc".to_string()];
        let a = super::shape(200, "<p>Access to &#x2f;srv&#x2f;..&#x2f;etc created.</p>", &sent);
        let b = super::shape(200, "<p>Access to /srv/..%2Fetc created.</p>", &sent);
        let c = super::shape(200, "<p>Access to /srv/..\\/etc created.</p>", &sent);
        assert_eq!((a.body.as_str(), &a), ("<p>Access to /srv/\u{1} created.</p>", &b));
        assert_eq!(a, c);
        assert_ne!(a, super::shape(404, "<p>Access to /srv/../etc created.</p>", &sent));
        // Every value sent is taken out of every answer, the longest first.
        let both = ["/etc".to_string(), "/0123/etc".to_string()];
        let shown = |v: &str| super::shape(200, &format!("<p>{v}</p>"), &both).body;
        assert_eq!(shown("/srv/etc"), "<p>/srv\u{1}</p>");
        assert_eq!(shown("/0123/etc"), "<p>\u{1}</p>");
        let sent = ["zq9".to_string()];
        let hit = super::shape(200, "Access to zq9\nAnd file already exists.\n", &sent);
        let miss = super::shape(200, "Access to zq9\nBut file doesn't exist yet.\n", &sent);
        assert_eq!(super::evidence(&hit, &miss), "And file already exists.");
    }
}
