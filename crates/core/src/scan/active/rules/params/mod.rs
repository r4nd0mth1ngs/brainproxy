//! Per-parameter active rules ported from ZAP's ascanrules add-on (Apache License 2.0).

mod buffer_overflow;
mod common;
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
            _ => not_found,
        }
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
