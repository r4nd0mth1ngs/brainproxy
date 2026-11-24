//! Ported from ZAP SourceCodeDisclosureGitScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! For a page with a file name, looks for a `.git/index` in its folder and each folder above,
//! finds the file's blob there, and reads the blob (loose, or from the pack `objects/info/packs`
//! names). Source that differs from the page and looks like its type is a finding. At most 20
//! Git files are fetched per page, as in ZAP; an index or pack shared by many pages is
//! fetched once per scan.

use std::sync::LazyLock;

use regex::Regex;

use super::git_metadata::{index_entries, is_sha1, loose_blob, pack_name, packed_blob, PackIndex};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

pub(super) const SOURCE_DESC: &str = "The source code for the current page was disclosed by the web server.";
const WASC_34_REFS: &[&str] = &[
    "https://projects.webappsec.org/w/page/13246953/Predictable%20Resource%20Location",
    "https://cwe.mitre.org/data/definitions/425.html",
];

static ALERT: AlertDef = AlertDef {
    alert_ref: "41",
    name: "Source Code Disclosure - Git",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 541,
    wasc: 34,
    description: SOURCE_DESC,
    solution: "Ensure that Git metadata files are not deployed to the web server or application server.",
    references: WASC_34_REFS,
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// ZAP's limit on Git URLs requested for one page.
const MAX_GIT_REQUESTS: usize = 20;

static JSP: LazyLock<Regex> = LazyLock::new(|| Regex::new("<%.*%>").expect("static regex compiles"));

/// Whether `data` looks like source of a file with `ext` (upper case): ZAP's checks for JSP,
/// PHP, Java and HTML; any other type is taken as it is. (ZAP's PHP pattern for Git, `<?php`
/// as a regex, matches any `php`; the literal `<?php` is meant, as its SVN rule has it.)
pub(super) fn matches_extension(data: &str, ext: Option<&str>) -> Option<String> {
    let found = |needle: &str| data.contains(needle).then(|| needle.to_string());
    match ext {
        Some("JSP") => JSP.find(data).map(|m| m.as_str().to_string()),
        Some("PHP") => found("<?php"),
        Some("JAVA") => found("class"),
        Some("HTML") => found("<html"),
        _ => Some(String::new()),
    }
}

/// The last path segment and its extension (upper case), if it has a name.
pub(super) fn file_name(path: &str) -> Option<(String, Option<String>)> {
    let name = path.rsplit('/').next().filter(|n| !n.is_empty())?;
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_uppercase());
    Some((name.to_string(), ext))
}

/// Fetches Git files for one page, counting them against [`MAX_GIT_REQUESTS`].
struct Fetcher<'a> {
    cx: &'a Cx,
    sent: usize,
    used: Vec<String>,
}

impl Fetcher<'_> {
    /// The body of `path` when it answers 200. Shared files (an index, a pack) are fetched
    /// once per scan, as ZAP's message cache does.
    async fn get(&mut self, path: &str) -> Option<Response> {
        if self.sent >= MAX_GIT_REQUESTS || self.cx.stopped() {
            return None;
        }
        self.sent += 1;
        let req = self.cx.request_for("GET", path);
        let resp = self.cx.send_once(path.as_bytes(), self.cx.send(req)).await.ok()?;
        if resp.status != 200 {
            return None;
        }
        self.used.push(format!("{}{path}", self.cx.target().origin()));
        Some(resp)
    }
}

pub struct GitDisclosure;

impl GitDisclosure {
    /// The blob of the file at `path` in a `.git` folder at or above it, with the response
    /// that held it.
    async fn find(cx: &Cx, path: &str, git: &mut Fetcher<'_>) -> Option<(Vec<u8>, Response)> {
        let mut dir = &path[..path.rfind('/')? + 1];
        let (sha, base) = loop {
            let index = format!("{dir}.git/index");
            if let Some(resp) = git.get(&index).await {
                let entries = index_entries(&resp.body).unwrap_or_default();
                if let Some((_, sha)) = entries.iter().find(|(name, _)| format!("{dir}{name}") == path) {
                    break (sha.clone(), format!("{dir}.git/"));
                }
            }
            if dir == "/" || dir.is_empty() || cx.stopped() {
                return None;
            }
            let up = dir.trim_end_matches('/');
            dir = &up[..up.rfind('/')? + 1];
        };
        if !is_sha1(&sha) {
            return None;
        }
        let loose = format!("{base}objects/{}/{}", &sha[..2], &sha[2..]);
        if let Some(resp) = git.get(&loose).await {
            return loose_blob(&resp.body).map(|b| (b, resp));
        }
        let info = git.get(&format!("{base}objects/info/packs")).await?;
        let pack = pack_name(&info.body)?;
        let idx = git.get(&format!("{base}objects/pack/{}.idx", pack.trim_end_matches(".pack"))).await?;
        let index = PackIndex::parse(&idx.body)?;
        let pack = git.get(&format!("{base}objects/pack/{pack}")).await?;
        packed_blob(&pack.body, &index, &sha).map(|b| (b, pack))
    }
}

impl ActiveRule for GitDisclosure {
    fn id(&self) -> u32 {
        41
    }

    fn name(&self) -> &'static str {
        "Source Code Disclosure - Git"
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
            let mut git = Fetcher { cx, sent: 0, used: Vec::new() };
            let Some((source, resp)) = Self::find(cx, &path, &mut git).await else { return };
            if source == cx.base_response().body {
                // Served as it is: not source the server keeps to itself.
                return;
            }
            let text = String::from_utf8_lossy(&source);
            if matches_extension(&text, ext.as_deref()).is_none() {
                return;
            }
            let evidence = format!("The source code for [{name}] was extracted using [{}]", git.used.join(", "));
            cx.report(ALERT.raise("", evidence).other_info(text.into_owned()), &resp);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::git_metadata::tests::{index_v2, pack_with_delta, sha1_hex, zlib};
    use super::*;
    use crate::scan::active::rules::test_app::{get, html, not_found, scan, serve, serve_bytes, Opts};

    const SOURCE: &[u8] = b"<?php\n$db = new PDO('mysql:host=db', 'app', 'hunter2');\necho 'Hello';\n";

    #[test]
    fn extension_checks() {
        assert_eq!(matches_extension("<% out.print(1); %>", Some("JSP")).unwrap(), "<% out.print(1); %>");
        assert!(matches_extension("a php mention", Some("PHP")).is_none());
        assert_eq!(matches_extension("x", Some("ASPX")).unwrap(), "");
        assert_eq!(file_name("/a/b.php").unwrap(), ("b.php".into(), Some("PHP".into())));
        assert!(file_name("/a/").is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_loose_blob_two_folders_up() {
        let blob = [format!("blob {}\0", SOURCE.len()).as_bytes(), SOURCE].concat();
        let sha = sha1_hex(&blob);
        let loose = zlib(&blob);
        let index = index_v2(&[("app/sub/page.php", &sha)]);
        let obj = format!("/.git/objects/{}/{}", &sha[..2], &sha[2..]);
        let port = serve_bytes(move |path| match path {
            "/app/sub/page.php" => Some(b"<html>Hello</html>".to_vec()),
            "/.git/index" => Some(index.clone()),
            p if p == obj => Some(loose.clone()),
            _ => None,
        });
        let (s, found) = scan(41, vec![get(port, "/app/sub/page.php")], Opts::default()).await;
        assert_eq!(found.len(), 1, "{s:?}");
        assert!(found[0].evidence.starts_with("The source code for [page.php] was extracted using ["), "{found:?}");
        assert!(found[0].other_info.contains("hunter2"));
        // /app/sub/.git/index, /app/.git/index, /.git/index, then the object.
        assert_eq!(s.requests, 4, "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_packed_blob_and_a_site_without_git() {
        let base = b"<?php\n// the first version of the page, long enough to copy from\n$a = 1;\n".to_vec();
        let target = [&base[..base.len() / 2], b"\n$password = 'hunter2';\n".as_slice()].concat();
        let (pack, idx, _, target_sha) = pack_with_delta(&base, &target);
        let index = index_v2(&[("page.php", &target_sha)]);
        let name = format!("pack-{}", "ab".repeat(20));
        let (pack_path, idx_path) =
            (format!("/.git/objects/pack/{name}.pack"), format!("/.git/objects/pack/{name}.idx"));
        let info = format!("P {name}.pack\n\n").into_bytes();
        let port = serve_bytes(move |path| match path {
            "/page.php" => Some(b"<html>page</html>".to_vec()),
            "/.git/index" => Some(index.clone()),
            "/.git/objects/info/packs" => Some(info.clone()),
            p if p == pack_path => Some(pack.clone()),
            p if p == idx_path => Some(idx.clone()),
            _ => None,
        });
        let (_, found) = scan(41, vec![get(port, "/page.php")], Opts::default()).await;
        assert_eq!(found.len(), 1);
        assert!(found[0].other_info.contains("hunter2"));

        // Fixed: no .git served. One index request per folder, nothing found.
        let safe = serve(|r| if r.path == "/app/page.php" { html("<html>ok</html>") } else { not_found() });
        let (s, found) = scan(41, vec![get(safe, "/app/page.php")], Opts::default()).await;
        assert!(found.is_empty());
        assert_eq!(s.requests, 2);
    }
}
