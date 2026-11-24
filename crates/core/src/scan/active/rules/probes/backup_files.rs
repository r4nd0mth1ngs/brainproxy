//! Ported from ZAP BackupFileDisclosureScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Asks for copies of the page's file under backup names (`page.php.bak`, `page.bak`,
//! `page - Copy.php`, `Copy of page.php`, and the same for its folder). How many depends on
//! the strength, as in ZAP (see [`limits`]; the counts per strength are in
//! docs/ACTIVE_RULES.md). Before that, a random file name in the same folder, and a random
//! folder name in place of the parent's, show what this server answers for a file that isn't
//! there, so a catch-all page isn't taken for a backup.

use super::common::base_path;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10095",
    name: "Backup File Disclosure",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 530,
    wasc: 34,
    description: "A backup of the file was disclosed by the web server.",
    solution: "Do not edit files in-situ on the web server, and ensure that un-necessary files (including hidden \
        files) are removed from the web server.",
    references: &[
        "https://cwe.mitre.org/data/definitions/530.html",
        "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.html",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A03", "WSTG-v42-CONF-04"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// ZAP's lists, in its order (duplicates included: they make no request of their own).
const EXTENSIONS: &[&str] = &[
    ".bak",
    ".backup",
    ".bac",
    ".zip",
    ".tar",
    ".jar",
    ".log",
    ".swp",
    "~",
    ".old",
    ".~bk",
    ".orig",
    ".tmp",
    ".exe",
    ".0",
    ".1",
    ".2",
    ".3",
    ".gz",
    ".bz2",
    ".7z",
    ".s7z",
    ".lz",
    ".z",
    ".lzma",
    ".lzo",
    ".apk",
    ".cab",
    ".rar",
    ".war",
    ".ear",
    ".tar.gz",
    ".tgz",
    ".tar.z",
    ".tar.bz2",
    ".tbz2",
    ".tar.lzma",
    ".tlz",
    ".zipx",
    ".iso",
    ".src",
    ".dev",
    ".a",
    ".a",
    ".ar",
    ".cbz",
    ".cpio",
    ".shar",
    ".lbr",
    ".lbr",
    ".mar",
    ".f",
    ".rz",
    ".sfark",
    ".xz",
    ".ace",
    ".afa",
    ".alz",
    ".arc",
    ".arj",
    ".ba",
    ".bh",
    ".cfs",
    ".cpt",
    ".dar",
    ".dd",
    ".dgc",
    ".dmg",
    ".gca",
    ".ha",
    ".hki",
    ".ice",
    ".inc",
    ".j",
    ".kgb",
    ".lhz",
    ".lha",
    ".lzk",
    ".pak",
    ".partimg.",
    ".paq6",
    ".paq7",
    ".paq8",
    ".pea",
    ".pim",
    ".pit",
    ".qda",
    ".rk",
    ".sda",
    ".sea",
    ".sen",
    ".sfx",
    ".sit",
    ".sitx",
    ".sqx",
    "s.xz",
    ".tar.7z",
    ".tar.xz",
    ".uc",
    ".uc0",
    ".uc2",
    ".ucn",
    ".ur2",
    ".ue2",
    ".uca",
    ".uha",
    ".wim",
    ".xar",
    ".xp3",
    ".yz1",
    ".zoo",
    ".zpaq",
    ".zz",
    ".include",
    "1",
    "_1",
    "2",
    "_2",
    "x",
    "_x",
    "bak",
    "_bak",
    "old",
    "_old",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "_a",
    "_b",
    "_c",
    "_d",
    "_e",
    "_f",
    "inc",
    "_inc",
    "_backup",
];

const SUFFIXES: &[&str] = &[
    " - Copy",
    " - Copy (2)",
    " - Copy (3)",
    "backup",
    "_backup",
    "-backup",
    "bak",
    "_bak",
    "-bak",
    "old",
    "_old",
    "-old",
    "1",
    "-1",
    "_1",
    "2",
    "-2",
    "_2",
    " - Copy - Copy",
    "(copy)",
    "(another copy)",
    "(second copy)",
    "(third copy)",
    "(fourth copy)",
    "(2nd copy)",
    "(3rd copy)",
    "(4th copy)",
    " (copy)",
    " (another copy)",
    " (second copy)",
    " (third copy)",
    " (fourth copy)",
    " (2nd copy)",
    " (3rd copy)",
    " (4th copy)",
];

const PREFIXES: &[&str] = &[
    "Copy of ",
    "Copy (2) of ",
    "Copy (3) of ",
    "Copy of Copy of ",
    "backup",
    "backup_",
    "backup-",
    "bak",
    "bak_",
    "bak-",
    "old",
    "old_",
    "old-",
    "1",
    "1_",
    "1-",
    "2",
    "2_",
    "2-",
];

/// ZAP's numbers per strength: extensions, suffixes and prefixes to try, and whether to put
/// a backup extension before the file's own (`page.bak.php`). Each loop runs one more time
/// than its number, as ZAP's do.
fn limits(strength: Strength) -> (usize, usize, usize, bool) {
    match strength {
        Strength::Low => (3, 2, 0, false),
        Strength::Medium => (10, 3, 2, false),
        Strength::High => (20, 5, 4, true),
        Strength::Insane => (EXTENSIONS.len(), SUFFIXES.len(), PREFIXES.len(), true),
    }
}

/// `path` with `insert` at byte `at`.
fn splice(path: &str, at: usize, insert: &str) -> String {
    format!("{}{insert}{}", &path[..at], &path[at..])
}

/// The backup names to try for `path`: those in the file's folder, and those that rename
/// its folder (when it isn't at the root). No duplicates, in ZAP's order.
pub(super) fn candidates(path: &str, strength: Strength) -> (Vec<String>, Vec<String>) {
    let (n_ext, n_suffix, n_prefix, switch) = limits(strength);
    let name_at = path.rfind('/').map_or(0, |i| i + 1);
    let name = &path[name_at..];
    let (dot, ext) = match name.rfind('.') {
        Some(i) => (name_at + i, &name[i..]),
        None => (path.len(), ""),
    };
    let mut file: Vec<String> = Vec::new();
    let push = |list: &mut Vec<String>, p: String| {
        if !list.contains(&p) {
            list.push(p);
        }
    };
    for e in EXTENSIONS.iter().take(n_ext + 1) {
        push(&mut file, format!("{path}{e}"));
        push(&mut file, format!("{}{e}", &path[..dot]));
        if !ext.is_empty() && switch {
            push(&mut file, format!("{}{e}{ext}", &path[..dot]));
        }
    }
    for s in SUFFIXES.iter().take(n_suffix + 1) {
        push(&mut file, splice(path, dot, s));
    }
    for p in PREFIXES.iter().take(n_prefix + 1) {
        push(&mut file, splice(path, name_at, p));
    }
    let mut folder = Vec::new();
    // A parent folder other than the root: `/a/page.php` has one, `/page.php` doesn't.
    if path.split('/').filter(|s| !s.is_empty()).count() >= 2 {
        let dir_end = name_at - 1;
        let dir_start = path[..dir_end].rfind('/').map_or(0, |i| i + 1);
        for s in SUFFIXES.iter().take(n_suffix + 1) {
            push(&mut folder, splice(path, dir_end, s));
        }
        // ZAP's folder prefix loop shares the suffix loop's counter, so it always stops
        // after the first prefix.
        push(&mut folder, splice(path, dir_start, PREFIXES[0]));
    }
    (file, folder)
}

/// A random name of `len` lower-case letters and digits.
fn random(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..len).map(|_| CHARS[(rand_u64() % CHARS.len() as u64) as usize] as char).collect()
}

/// A request target for `path`, its spaces escaped.
fn target(path: &str) -> String {
    path.replace(' ', "%20")
}

pub struct BackupFiles;

impl BackupFiles {
    /// Whether `resp` is a backup: a success with a body that differs from what the server
    /// gives for a file that isn't there (`missing`).
    fn is_backup(resp: &Response, missing: &Response) -> bool {
        (200..300).contains(&resp.status)
            && !resp.body.is_empty()
            && if missing.status == 404 {
                resp.status != 404
            } else {
                resp.status != missing.status && resp.body != missing.body
            }
    }

    async fn probe(cx: &Cx, paths: &[String], missing: &Response, original: &str) {
        for path in paths {
            if cx.stopped() {
                return;
            }
            let Ok(resp) = cx.send(cx.request_for("GET", &target(path))).await else { continue };
            if Self::is_backup(&resp, missing) {
                let url = format!("{}{}", cx.target().origin(), target(path));
                let info = format!("A backup of [{original}] is available at [{url}]");
                cx.report(ALERT.raise("", "").attack(url).other_info(info), &resp);
            }
        }
    }
}

impl ActiveRule for BackupFiles {
    fn id(&self) -> u32 {
        10095
    }

    fn name(&self) -> &'static str {
        "Backup File Disclosure"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.base_response().status == 404 {
                return;
            }
            let path = base_path(cx);
            let Some(slash) = path.rfind('/') else { return };
            let name = &path[slash + 1..];
            if name.is_empty() {
                return;
            }
            let original = format!("{}{}", cx.target().origin(), path);
            let missing_file = format!("{}/{}", &path[..slash], random(name.len()));
            let Ok(missing) = cx.send(cx.request_for("GET", &missing_file)).await else { return };
            let (file, folder) = candidates(&path, cx.strength());
            Self::probe(cx, &file, &missing, &original).await;
            if folder.is_empty() {
                return;
            }
            let parent_start = path[..slash].rfind('/').map_or(0, |i| i + 1);
            let parent = &path[parent_start..slash];
            let missing_parent = format!("{}{}{}", &path[..parent_start], random(parent.len().max(4)), &path[slash..]);
            let Ok(missing) = cx.send(cx.request_for("GET", &missing_parent)).await else { return };
            Self::probe(cx, &folder, &missing, &original).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::active::rules::test_app::{get, html, not_found, resp, scan, serve, Opts};

    #[test]
    fn names_and_counts_per_strength() {
        let (file, folder) = candidates("/app/admin/login.php", Strength::Medium);
        assert_eq!(
            &file[..4],
            [
                "/app/admin/login.php.bak",
                "/app/admin/login.bak",
                "/app/admin/login.php.backup",
                "/app/admin/login.backup"
            ]
        );
        assert!(file.contains(&"/app/admin/login - Copy.php".to_string()));
        assert!(file.contains(&"/app/admin/Copy of login.php".to_string()));
        assert_eq!(folder.last().unwrap(), "/app/Copy of admin/login.php");
        assert!(folder.contains(&"/app/admin - Copy/login.php".to_string()));
        // Requests per strength for a file with an extension in a folder below the root (the
        // two probes for a missing file and folder included): documented in ACTIVE_RULES.md.
        let count = |s| {
            let (f, d) = candidates("/app/admin/login.php", s);
            f.len() + d.len() + 2
        };
        assert_eq!(
            [count(Strength::Low), count(Strength::Medium), count(Strength::High), count(Strength::Insane)],
            [18, 36, 83, 494]
        );
        // At the root: no folder names, and one probe.
        let (f, d) = candidates("/login.php", Strength::Medium);
        assert_eq!((f.len() + 1, d.len()), (30, 0));
        // Without an extension the two extension forms are one.
        assert_eq!(candidates("/a/README", Strength::Low).0[..2], ["/a/README.bak", "/a/README.backup"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_bak_copy_is_found_and_a_catch_all_is_not() {
        let port = serve(|r| match r.path.as_str() {
            "/app/login.php" => html("<html>Log in</html>"),
            "/app/login.php.bak" => resp(200, "text/plain", &[], "<?php $pw = 'hunter2';"),
            _ => not_found(),
        });
        let (s, found) = scan(10095, vec![get(port, "/app/login.php")], Opts::default()).await;
        assert_eq!(found.len(), 1, "{s:?}");
        assert!(found[0].attack.ends_with("/app/login.php.bak"));
        assert_eq!(s.requests, 36, "the counts documented for MEDIUM");

        // Every path answers 200 with the same page: no backups.
        let all = serve(|_| html("<html>Welcome</html>"));
        let (_, found) = scan(10095, vec![get(all, "/a/b/page.php")], Opts::default()).await;
        assert!(found.is_empty());
    }
}
