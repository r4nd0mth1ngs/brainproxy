//! Per-parameter active rules ported from ZAP's ascanrules and ascanrulesBeta add-ons
//! (Apache License 2.0).

mod buffer_overflow;
pub(super) mod common;
mod cross_site_scripting;
mod external_redirect;
mod format_string;
mod log4shell;
mod padding_oracle;
mod parameter_tamper;
mod path_traversal;
mod persistent_xss;
mod remote_file_include;
mod server_side_include;
mod ssrf;
mod ssti;
mod xpath_injection;
mod xslt_injection;
mod xxe;

use crate::scan::active::ActiveRule;

pub fn all() -> Vec<Box<dyn ActiveRule>> {
    vec![
        Box::new(cross_site_scripting::CrossSiteScripting),
        Box::new(path_traversal::PathTraversal),
        Box::new(remote_file_include::RemoteFileInclude),
        Box::new(server_side_include::ServerSideInclude),
        Box::new(ssti::Ssti),
        Box::new(xpath_injection::XpathInjection),
        Box::new(xxe::Xxe),
        Box::new(format_string::FormatString),
        Box::new(buffer_overflow::BufferOverflow),
        Box::new(external_redirect::ExternalRedirect),
        Box::new(parameter_tamper::ParameterTamper),
        Box::new(padding_oracle::PaddingOracle),
        Box::new(log4shell::Log4Shell),
        Box::new(ssrf::Ssrf),
        Box::new(xslt_injection::XsltInjection),
        Box::new(persistent_xss::PersistentXssPrime),
        Box::new(persistent_xss::PersistentXssSpider),
        Box::new(persistent_xss::PersistentXss),
    ]
}

#[cfg(test)]
mod e2e {
    //! The rules through the real engine against a tiny local app.
    use std::io::{Read, Write};
    use std::time::Duration;

    use crate::guard::{Guard, ScopeSpec};
    use crate::http::{SendOptions, Target};
    use crate::jobs::JobControl;
    use crate::scan::active::{run, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};
    use crate::scan::message::url_decode;

    fn escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
    }

    /// Guestbooks for the persistent XSS tests: (raw, escaped), the last 20 entries each.
    static GUESTBOOK: std::sync::Mutex<(Vec<String>, Vec<String>)> = std::sync::Mutex::new((Vec::new(), Vec::new()));

    /// The guestbook served as JSON and as plain text, entries unescaped.
    static GUESTBOOK_DATA: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    static TICKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn sign(book: &mut Vec<String>, text: String) {
        book.push(text);
        if book.len() > 20 {
            book.remove(0);
        }
    }

    fn respond(path: &str, query: &str) -> String {
        let param = |name: &str| -> String {
            query.split('&').find_map(|p| p.strip_prefix(&format!("{name}="))).map(url_decode).unwrap_or_default()
        };
        let ok = |ct: &str, body: String| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found".to_string();
        match path {
            "/xss" => ok("text/html", format!("<html><body><p>Hello {}</p></body></html>", param("q"))),
            "/xss-safe" => ok("text/html", format!("<html><body><p>Hello {}</p></body></html>", escape(&param("q")))),
            // Markup in a JSON string or a text page, unescaped: no browser renders it.
            "/xss-json" => ok("application/json", format!("{{\"html\":\"<p>Hello {}</p>\"}}", param("q"))),
            "/xss-text" => ok("text/plain; charset=utf-8", format!("<p>Hello {}</p>", param("q"))),
            // Strips ASCII brackets (and `%`), but echoes full-width ones as they came, which
            // no browser reads as markup. The value is shown outside tags and in a paragraph.
            "/xss-fullwidth" => {
                let q: String = param("q").chars().filter(|c| !"<>%".contains(*c)).collect();
                ok("text/html", format!("Hello {q}<html><body><p>{q}</p></body></html>"))
            }
            // A C program printing the value as its format: `%n` crashes it, `%x` prints a
            // word of the stack, `%%` a percent sign.
            "/printf" => {
                let q = param("q").replace("%%", "%");
                if q.contains("%n") {
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    ok("text/html", format!("<p>{}</p>", q.replace("%x", "bfffe3c4")))
                }
            }
            // Decodes the value again, as `decodeURIComponent` does: any `%` not followed by
            // two hex digits is a 500 (URIError). It also echoes the value.
            "/uri" => {
                let q = param("q");
                let bad = q
                    .match_indices('%')
                    .any(|(i, _)| !q.get(i + 1..i + 3).is_some_and(|h| h.chars().all(|c| c.is_ascii_hexdigit())));
                if bad {
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    ok("text/html", format!("<p>{}</p>", escape(&q)))
                }
            }
            "/comment-data" => {
                sign(&mut GUESTBOOK_DATA.lock().unwrap(), param("text"));
                ok("text/html", "<p>saved</p>".into())
            }
            "/comments-json" | "/comments-text" => {
                let items: String = GUESTBOOK_DATA.lock().unwrap().iter().map(|e| format!("<li>{e}</li>")).collect();
                if path == "/comments-json" {
                    ok("application/json", format!("{{\"html\":\"<ul>{items}</ul>\"}}"))
                } else {
                    ok("text/plain", format!("<ul>{items}</ul>"))
                }
            }
            "/file" => {
                let name = param("name");
                if name == "readme.txt" {
                    ok("text/plain", "read me".into())
                } else if name.ends_with("etc/passwd") {
                    ok("text/plain", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/bin/false\n".into())
                } else {
                    not_found
                }
            }
            // Transforms `name` as an XSLT fragment: the vendor function answers, a misspelt one errors.
            "/xslt" => {
                let name = param("name");
                if name.contains("system-property('xsl:vendor')") {
                    ok("text/html", "<p>Hello libxslt</p>".into())
                } else if name.contains("system-property('xsl:vedor')") {
                    ok("text/html", "<p>Hello </p>".into())
                } else {
                    ok("text/html", format!("<p>Hello {}</p>", escape(&name)))
                }
            }
            // Mentions a vendor for any XSL-looking input, misspelt or not (a false positive trap).
            "/xslt-fp" => {
                let name = param("name");
                let vendor = if name.contains("xsl") { "Microsoft" } else { "" };
                ok("text/html", format!("<p>Hello {}{vendor}</p>", escape(&name)))
            }
            "/comment" => {
                sign(&mut GUESTBOOK.lock().unwrap().0, param("text"));
                ok("text/html", "<p>saved</p>".into())
            }
            "/comment-safe" => {
                sign(&mut GUESTBOOK.lock().unwrap().1, escape(&param("text")));
                ok("text/html", "<p>saved</p>".into())
            }
            "/comments" | "/comments-safe" => {
                let book = GUESTBOOK.lock().unwrap();
                let entries = if path == "/comments" { &book.0 } else { &book.1 };
                let items: String = entries.iter().map(|e| format!("<li>{e}</li>")).collect();
                ok("text/html", format!("<html><body><ul>{items}</ul></body></html>"))
            }
            "/file-safe" => {
                if param("name") == "readme.txt" {
                    ok("text/plain", "read me".into())
                } else {
                    not_found
                }
            }
            // Cleans the decoded path, as many routers do: `/own/%2Fstatus` is `/own/status`.
            "/own/status" | "/own/%2Fstatus" => ok("application/json", "{\"status\":\"ok\"}".into()),
            // The same, on a page that differs on every request.
            "/own/clock" | "/own/%2Fclock" => {
                let tick = TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                ok("application/json", format!("{{\"tick\":{tick}}}"))
            }
            // Reads `page` as a file relative to the script, so it can read itself.
            "/view" => match param("page").as_str() {
                "home" => ok("text/plain", "welcome home".into()),
                "view" => ok("text/plain", "the source of view".into()),
                _ => not_found,
            },
            // The same, already reading itself: the attack returns the original page.
            "/view.jsp" => match param("file").as_str() {
                "view.jsp" => ok("text/plain", "the source of view.jsp".into()),
                _ => not_found,
            },
            // `/Employees/Employee[@emplid='<id>']`, errors hidden, as the OWASP Benchmark's.
            "/xpath" | "/staff" => xpath_page(&format!("@emplid='{}'", param("id")), ""),
            // A numeric comparison, `[@emplid=<id>]`.
            "/xpathnum" => xpath_page(&format!("@emplid={}", param("id")), ""),
            // The string one on a page that changes on every request.
            "/xpathclock" => xpath_page(&format!("@emplid='{}'", param("id")), &clock()),
            // Safe: the value compared as data (a bound XPath variable).
            "/xpath-safe" => xpath_rows(|e| e.0 == param("id"), ""),
            "/xpath-safe-clock" => xpath_rows(|e| e.0 == param("id"), &clock()),
            // Safe: the value is read and ignored, as the Benchmark's safe pages do.
            "/xpath-ignored" => xpath_page("@emplid='3'", ""),
            _ => not_found,
        }
    }

    const EMPLOYEES: [(&str, &str); 2] = [("2", "Alice Smith, Accounts"), ("3", "Bob Jones, Sales")];

    /// A header that differs on every request, as one with a clock or a CSRF token does.
    fn clock() -> String {
        let n = TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!(
            "<header><h1>Staff directory</h1><nav>Home People Teams Rooms Help Sign out</nav>\
             <p>Rendered in {n} ms for session {:x}</p></header>",
            n * 7919
        )
    }

    fn xpath_rows(keep: impl Fn(&(&str, &str)) -> bool, extra: &str) -> String {
        let rows: String = EMPLOYEES.iter().filter(|e| keep(e)).map(|e| format!("{}<br/>\n", e.1)).collect();
        let body = format!("{extra}Your query results are: <br/>\n{rows}");
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// Evaluates `predicate` for each employee; one that doesn't parse is a 500.
    fn xpath_page(predicate: &str, extra: &str) -> String {
        if xpath_eval(predicate, EMPLOYEES[0].0).is_none() {
            let body = "Error parsing XPath input";
            return format!("HTTP/1.1 500 Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
        xpath_rows(|e| xpath_eval(predicate, e.0) == Some(true), extra)
    }

    /// An XPath predicate of `@emplid`, string and number literals, `=`, `and` and `or`.
    fn xpath_eval(predicate: &str, emplid: &str) -> Option<bool> {
        #[derive(Debug, PartialEq)]
        enum Tok {
            Str(String),
            Num(f64),
            Op(String),
        }
        let mut toks = Vec::new();
        let mut rest = predicate.trim_start();
        while let Some(c) = rest.chars().next() {
            if c == '\'' || c == '"' {
                let end = rest[1..].find(c)?;
                toks.push(Tok::Str(rest[1..1 + end].to_string()));
                rest = &rest[end + 2..];
            } else if c == '=' {
                toks.push(Tok::Op("=".into()));
                rest = &rest[1..];
            } else {
                let end = rest.find([' ', '=', '\'', '"']).unwrap_or(rest.len());
                let word = &rest[..end];
                toks.push(match word {
                    "@emplid" => Tok::Str(emplid.to_string()),
                    "and" | "or" => Tok::Op(word.to_string()),
                    w => Tok::Num(w.parse().ok()?),
                });
                rest = &rest[end..];
            }
            rest = rest.trim_start();
        }
        let value = |t: &Tok| match t {
            Tok::Str(s) => Some(s.clone()),
            Tok::Num(n) => Some(n.to_string()),
            Tok::Op(_) => None,
        };
        // `a = b` terms joined by `and` (first) and `or`.
        let mut any = false;
        for alt in toks.split(|t| *t == Tok::Op("or".into())) {
            let mut all = true;
            for term in alt.split(|t| *t == Tok::Op("and".into())) {
                let [a, Tok::Op(eq), b] = term else { return None };
                if eq != "=" {
                    return None;
                }
                let (a, b) = (value(a)?, value(b)?);
                let num = |s: &str| s.parse::<f64>().ok();
                all &= match (num(&a), num(&b)) {
                    (Some(x), Some(y)) => x == y,
                    _ => a == b,
                };
            }
            any |= all;
        }
        Some(any)
    }

    fn spawn_app() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let target = req.split(' ').nth(1).unwrap_or("/").to_string();
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let _ = s.write_all(respond(path, query).as_bytes());
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

    async fn scan(name: &str, port: u16, paths: &[&str], rules: Option<Vec<u32>>) -> ActiveSummary {
        let targets = paths
            .iter()
            .map(|p| {
                let (request, response) = fetch(port, p);
                let target = Target::from_url(&format!("http://127.0.0.1:{port}{p}")).unwrap();
                ScanTarget { history_id: None, target, request, response, duration_ms: None }
            })
            .collect();
        scan_targets(name, targets, PointOptions::default(), rules).await
    }

    async fn scan_targets(
        name: &str,
        targets: Vec<ScanTarget>,
        points: PointOptions,
        rules: Option<Vec<u32>>,
    ) -> ActiveSummary {
        let project = std::env::temp_dir().join(format!("bp-params-{name}-{}.bpdb", std::process::id()));
        let _ = std::fs::remove_file(&project);
        let guard =
            Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }])
                .unwrap();
        let cfg = ActiveConfig {
            strength: Strength::Medium,
            tuning: Default::default(),
            concurrency: 4,
            rate: None,
            send: SendOptions { guard: Some(guard), timeout: Duration::from_secs(10), ..Default::default() },
            points,
            rules,
            exclude_rules: vec![],
            no_rules: false,
            checks: vec![],
            max_duration: Some(Duration::from_secs(120)),
            auth: None,
            oob: None,
            oob_wait: std::time::Duration::ZERO,
            check_methods: vec![],
            prune: false,
        };
        let summary = run(&project, targets, cfg, JobControl::default()).await.unwrap();
        let _ = std::fs::remove_file(&project);
        summary
    }

    /// Reflects the request unescaped: the decoded path, or a body as the app would read
    /// it, with XML entities resolved.
    fn spawn_reflector() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (head, body) = req.split_once("\r\n\r\n").unwrap_or((&req, ""));
                    let path = url_decode(head.split(' ').nth(1).unwrap_or("/"));
                    let body = body.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"");
                    let page = format!("<html><body><p>{path}</p><p>{body}</p></body></html>");
                    let _ = s.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                            page.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        port
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn attacks_reach_multipart_xml_and_path() {
        let port = spawn_reflector();
        let post = |path: &str, ct: &str, body: &str| {
            let request = format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes();
            ScanTarget {
                history_id: None,
                target: Target::from_url(&format!("http://127.0.0.1:{port}{path}")).unwrap(),
                request,
                response: b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n".to_vec(),
                duration_ms: None,
            }
        };
        let multipart = "--b\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n--b--\r\n";
        let targets = vec![
            post("/m", "multipart/form-data; boundary=b", multipart),
            post("/x", "application/xml", "<note>hi</note>"),
        ];
        let s = scan_targets("bodies", targets, PointOptions::default(), Some(vec![40012])).await;
        assert_eq!(s.raised.get("40012"), Some(&2), "{s:?}");

        let target = |path: &str| post(path, "text/plain", "");
        let opts = PointOptions { path: true, ..Default::default() };
        let s = scan_targets("path", vec![target("/users/42")], opts, Some(vec![40012])).await;
        assert_eq!(s.raised.get("40012"), Some(&2), "one per path segment: {s:?}");
        let s = scan_targets("nopath", vec![target("/users/42")], PointOptions::default(), Some(vec![40012])).await;
        assert_eq!(s.raised.get("40012"), None, "URL paths are opt-in: {s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn finds_xss_and_path_traversal() {
        let port = spawn_app();
        let s = scan("vuln", port, &["/xss?q=hi", "/file?name=readme.txt"], Some(vec![40012, 6])).await;
        assert_eq!(s.raised.get("40012"), Some(&1), "{s:?}");
        assert_eq!(s.raised.get("6-2"), Some(&1), "{s:?}");
        assert_eq!(s.raised.len(), 2, "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn path_traversal_own_file_name_comes_from_the_probe() {
        let port = spawn_app();
        let target = |path: &str| {
            let (request, response) = fetch(port, path);
            let target = Target::from_url(&format!("http://127.0.0.1:{port}{path}")).unwrap();
            ScanTarget { history_id: None, target, request, response, duration_ms: None }
        };
        let opts = PointOptions { path: true, ..Default::default() };

        // A last segment is never attacked with its own value, with or without a slash.
        let s = scan_targets("own-status", vec![target("/own/status")], opts.clone(), Some(vec![6])).await;
        assert!(s.raised.is_empty(), "{s:?}");
        let s = scan_targets("own-clock", vec![target("/own/clock")], opts.clone(), Some(vec![6])).await;
        assert!(s.raised.is_empty(), "{s:?}");

        // A query parameter that reads the script is still found; the path segment is not.
        let s = scan_targets("own-view", vec![target("/view?page=home")], opts.clone(), Some(vec![6])).await;
        assert_eq!(s.raised.get("6-5"), Some(&1), "{s:?}");
        assert_eq!(s.raised.len(), 1, "{s:?}");
        // Also when the value is already the script's name and the attack is the original page.
        let s = scan_targets("own-jsp", vec![target("/view.jsp?file=view.jsp")], opts, Some(vec![6])).await;
        assert_eq!(s.raised.get("6-5"), Some(&1), "{s:?}");
        assert_eq!(s.raised.len(), 1, "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn finds_xslt_vendor_injection() {
        let port = spawn_app();
        let s = scan("xslt", port, &["/xslt?name=bob"], Some(vec![90017])).await;
        assert_eq!(s.raised.get("90017"), Some(&1), "{s:?}");
        assert_eq!(s.requests, 3, "error probe, vendor payload, misspelt re-check: {s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn finds_persistent_xss_through_its_dependencies() {
        let port = spawn_app();
        // Selecting 40014 alone pulls in Prime and Spider.
        let s = scan("pxss", port, &["/comment?text=hi", "/comments"], Some(vec![40014])).await;
        assert_eq!(s.rules, 3, "{s:?}");
        assert_eq!(s.raised.get("40014-1"), Some(&1), "{s:?}");
        assert_eq!(s.raised.len(), 1, "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn finds_blind_xpath_injection() {
        let port = spawn_app();
        let paths = [
            // Data originally: "and true" keeps Alice, "and false" loses her.
            "/xpath?id=2",
            // No data originally: "or true" finds everyone (another path: one finding per
            // page and parameter is kept).
            "/staff?id=9",
            "/xpathnum?id=2",
            "/xpathclock?id=2",
        ];
        let s = scan("xpath", port, &paths, Some(vec![90021])).await;
        assert_eq!(s.raised.get("90021"), Some(&4), "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn safe_xpath_pages_raise_nothing() {
        let port = spawn_app();
        let paths =
            ["/xpath-safe?id=2", "/xpath-safe?id=9", "/xpath-safe-clock?id=2", "/xpath-ignored?id=2", "/xss-safe?q=2"];
        let s = scan("xpathsafe", port, &paths, Some(vec![90021])).await;
        assert!(s.raised.is_empty(), "false positives: {s:?}");
        assert!(s.requests > 5 * 10, "the rule did attack: {s:?}");
    }

    #[test]
    fn xpath_helper() {
        assert_eq!(xpath_eval("@emplid='2'", "2"), Some(true));
        assert_eq!(xpath_eval("@emplid='2' and '1'='2'", "2"), Some(false));
        assert_eq!(xpath_eval("@emplid='9' or '1'='1'", "2"), Some(true));
        assert_eq!(xpath_eval("@emplid=2 and 1=1", "2"), Some(true));
        assert_eq!(xpath_eval("@emplid=\"2\" or \"1\"=\"2\"", "3"), Some(false));
        assert_eq!(xpath_eval("@emplid='2''", "2"), None);
        assert_eq!(xpath_eval("@emplid=2'", "2"), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn xss_in_a_response_no_browser_renders_as_html() {
        let port = spawn_app();
        // Reflected: not reported at all, as ZAP does at MEDIUM.
        let s = scan("xss-data", port, &["/xss-json?q=hi", "/xss-text?q=hi"], Some(vec![40012])).await;
        assert!(s.raised.is_empty(), "{s:?}");
        // Persistent: the weak JSON alert, never the High one.
        let s = scan("pxss-json", port, &["/comment-data?text=hi", "/comments-json"], Some(vec![40014])).await;
        assert_eq!(s.raised.get("40014-2"), Some(&1), "{s:?}");
        assert_eq!(s.raised.len(), 1, "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn xss_full_width_brackets_echoed_are_not_xss() {
        let port = spawn_app();
        let s = scan("xss-fullwidth", port, &["/xss-fullwidth?q=hi"], Some(vec![40012])).await;
        assert!(s.raised.is_empty(), "{s:?}");
        assert!(s.requests > 10, "the rule did attack: {s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn format_string_needs_the_conversions_to_cause_the_500() {
        let port = spawn_app();
        let s = scan("fmt", port, &["/printf?q=hi"], Some(vec![30002])).await;
        assert_eq!(s.raised.get("30002"), Some(&1), "{s:?}");
        // A 500 for any stray `%` (and `%%`) is not a format string error.
        let s = scan("fmt-uri", port, &["/uri?q=hi"], Some(vec![30002])).await;
        assert!(s.raised.is_empty(), "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn persistent_xss_in_plain_text_is_low_risk() {
        let port = spawn_app();
        let s = scan("pxss-text", port, &["/comment-data?text=hi", "/comments-text"], Some(vec![40014])).await;
        assert_eq!(s.raised.get("40014-3"), Some(&1), "{s:?}");
        assert_eq!(s.raised.len(), 1, "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn safe_endpoints_raise_nothing() {
        let port = spawn_app();
        let ids: Vec<u32> = super::all().iter().map(|r| r.id()).collect();
        let s = scan(
            "safe",
            port,
            &[
                "/xss-safe?q=hi",
                "/file-safe?name=readme.txt",
                "/xslt-fp?name=bob",
                "/comment-safe?text=hi",
                "/comments-safe",
            ],
            Some(ids),
        )
        .await;
        assert!(s.raised.is_empty(), "false positives: {s:?}");
        assert!(s.requests > 20, "the rules did attack: {s:?}");
    }
}
