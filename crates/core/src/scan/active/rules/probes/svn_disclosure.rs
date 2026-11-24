//! Ported from ZAP SourceCodeDisclosureSvnScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! For a page with a file name: the pre-1.7 working copy's `.svn/text-base/<file>.svn-base`
//! in its folder, then the 1.7+ working copy database `.svn/wc.db` in its folder and each
//! folder above, whose `nodes` table names the file's pristine copy. ZAP stops the whole rule
//! at the first 4xx or 5xx answer, so on most sites it never reads a `wc.db`, and it never
//! tries the root folder; here a missing file moves on to the next place, and the root is
//! tried too. A `wc.db` is fetched once per scan, however many pages sit under it.

use super::git_disclosure::{file_name, matches_extension, SOURCE_DESC};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "42",
    name: "Source Code Disclosure - SVN",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 541,
    wasc: 34,
    description: SOURCE_DESC,
    solution: "Ensure that SVN metadata files are not deployed to the web server or application server.",
    references: &[
        "https://projects.webappsec.org/w/page/13246953/Predictable%20Resource%20Location",
        "https://cwe.mitre.org/data/definitions/425.html",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Redirects and 404: the file isn't there (ZAP's UNWANTED_RESPONSE_CODES).
const UNWANTED: [u16; 7] = [301, 302, 303, 304, 305, 307, 404];

/// Whether `resp` may hold the file: not a redirect, a 404 or another error, and not the page
/// itself.
fn usable(cx: &Cx, resp: &Response) -> bool {
    !UNWANTED.contains(&resp.status) && resp.status < 400 && resp.body != cx.base_response().body
}

/// The pristine copy `wc.db` names for `relpath`, as a path under `.svn/`. The database is
/// the server's answer: it is opened read-only from a temporary file, on a blocking thread,
/// with its schema not trusted to run functions.
async fn pristine(db: Vec<u8>, relpath: String) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        let dir = tempfile_dir()?;
        let file = dir.join("wc.db");
        std::fs::write(&file, &db).ok()?;
        let found = read_wc_db(&file, &relpath);
        let _ = std::fs::remove_dir_all(&dir);
        found
    })
    .await
    .ok()
    .flatten()
}

fn tempfile_dir() -> Option<std::path::PathBuf> {
    let dir =
        std::env::temp_dir().join(format!("bp-svn-{}-{:016x}", std::process::id(), crate::scan::active::rand_u64()));
    std::fs::create_dir(&dir).ok()?;
    Some(dir)
}

fn read_wc_db(file: &std::path::Path, relpath: &str) -> Option<String> {
    use rusqlite::OpenFlags;
    let conn = rusqlite::Connection::open_with_flags(file, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    conn.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA query_only = ON;").ok()?;
    let format: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).ok()?;
    // SVN 1.7 to 1.14 (formats 29 to 31), as ZAP.
    if !(29..=31).contains(&format) {
        return None;
    }
    conn.query_row(
        "SELECT 'pristine/' || substr(checksum, 7, 2) || '/' || substr(checksum, 7) || '.svn-base' FROM nodes \
         WHERE local_relpath = ?1 ORDER BY wc_id",
        [relpath],
        |r| r.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
    .filter(|p| !p.is_empty() && !p.contains(".."))
}

pub struct SvnDisclosure;

impl SvnDisclosure {
    fn raise(cx: &Cx, resp: &Response, name: &str, ext: Option<&str>) -> bool {
        let Some(evidence) = matches_extension(resp.body_str(), ext) else { return false };
        // ZAP passes over a file type it has no check for at the MEDIUM threshold.
        if evidence.is_empty() {
            return false;
        }
        let url =
            format!("{}{}", cx.target().origin(), super::common::request_line(resp).split(' ').nth(1).unwrap_or(""));
        let finding = ALERT
            .raise("", evidence)
            .attack(url.clone())
            .other_info(format!("The source code for [{name}] was found at [{url}]"));
        cx.report(finding, resp);
        true
    }
}

impl ActiveRule for SvnDisclosure {
    fn id(&self) -> u32 {
        42
    }

    fn name(&self) -> &'static str {
        "Source Code Disclosure - SVN"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.strength() <= Strength::Medium && cx.base_response().status == 404 {
                return;
            }
            let path = cx.base().path.clone();
            let Some((name, ext)) = file_name(&path) else { return };
            if path.contains("/.svn/") || path.ends_with("/.svn") {
                return;
            }
            let Some(slash) = path.rfind('/') else { return };
            let mut dir = path[..=slash].to_string();
            // Before SVN 1.7: a copy of each file next to it.
            let text_base = format!("{dir}.svn/text-base/{name}.svn-base");
            if let Ok(resp) = cx.send(cx.request_for("GET", &text_base)).await {
                if usable(cx, &resp) && Self::raise(cx, &resp, &name, ext.as_deref()) {
                    return;
                }
            }
            // SVN 1.7 and later: one database at the working copy's root.
            loop {
                if cx.stopped() {
                    return;
                }
                let wc_db = format!("{dir}.svn/wc.db");
                // One working copy database serves every page under it: fetched once per scan.
                if let Ok(resp) = cx.send_once(wc_db.as_bytes(), cx.send(cx.request_for("GET", &wc_db))).await {
                    if usable(cx, &resp) {
                        let relpath = path[dir.len()..].to_string();
                        let Some(file) = pristine(resp.body.clone(), relpath).await else { return };
                        let Ok(copy) = cx.send(cx.request_for("GET", &format!("{dir}.svn/{file}"))).await else {
                            return;
                        };
                        if usable(cx, &copy) {
                            Self::raise(cx, &copy, &name, ext.as_deref());
                        }
                        return;
                    }
                }
                if dir == "/" {
                    return;
                }
                let up = dir.trim_end_matches('/');
                let Some(slash) = up.rfind('/') else { return };
                dir = up[..=slash].to_string();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::active::rules::test_app::{get, html, not_found, resp, scan, serve, serve_bytes, Opts};

    const SOURCE: &str = "<?php\n$db = mysqli_connect('db', 'app', 'hunter2');\n";

    /// A wc.db (format 31) naming the pristine copy of `relpath`.
    fn wc_db(relpath: &str) -> Vec<u8> {
        let dir = tempfile_dir().unwrap();
        let file = dir.join("wc.db");
        let conn = rusqlite::Connection::open(&file).unwrap();
        conn.execute_batch(
            "CREATE TABLE nodes (wc_id INTEGER, local_relpath TEXT, kind TEXT, checksum TEXT); PRAGMA user_version = 31;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nodes VALUES (1, ?1, 'file', '$sha1$0123456789abcdef0123456789abcdef01234567')",
            [relpath],
        )
        .unwrap();
        drop(conn);
        let data = std::fs::read(&file).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        data
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn text_base_and_wc_db() {
        let old = serve(|r| match r.path.as_str() {
            "/app/login.php" => html("<html>Log in</html>"),
            "/app/.svn/text-base/login.php.svn-base" => resp(200, "text/plain", &[], SOURCE),
            _ => not_found(),
        });
        let (s, found) = scan(42, vec![get(old, "/app/login.php")], Opts::default()).await;
        assert_eq!(found.len(), 1, "{s:?}");
        assert_eq!(found[0].evidence, "<?php");
        assert!(found[0].attack.ends_with("/app/.svn/text-base/login.php.svn-base"));

        // The database sits a folder up, at the working copy's root; its bytes go out as they are.
        let db = wc_db("app/login.php");
        let port = serve_bytes(move |path| match path {
            "/app/login.php" => Some(b"<html>Log in</html>".to_vec()),
            "/.svn/wc.db" => Some(db.clone()),
            "/.svn/pristine/01/0123456789abcdef0123456789abcdef01234567.svn-base" => Some(SOURCE.as_bytes().to_vec()),
            _ => None,
        });
        let (s, found) = scan(42, vec![get(port, "/app/login.php")], Opts::default()).await;
        assert_eq!(found.len(), 1, "{s:?}");
        assert!(found[0].url.ends_with(".svn-base"), "{found:?}");
        // text-base, /app/.svn/wc.db, /.svn/wc.db, the pristine copy.
        assert_eq!(s.requests, 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_site_without_svn_and_a_catch_all() {
        let safe =
            serve(|r| if r.path == "/a/b.php" || r.path == "/a/c.php" { html("<html>b</html>") } else { not_found() });
        let (s, found) = scan(42, vec![get(safe, "/a/b.php"), get(safe, "/a/c.php")], Opts::default()).await;
        assert!(found.is_empty());
        assert_eq!(s.requests, 4, "a text-base per page, then wc.db in /a/ and / once for both");
        // Every path answers the page itself: nothing.
        let same = serve(|_| html("<html><?php in a page</html>"));
        let (_, found) = scan(42, vec![get(same, "/a/b.php")], Opts::default()).await;
        assert!(found.is_empty());
    }
}
