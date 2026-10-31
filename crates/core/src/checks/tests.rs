use super::*;
use base64::Engine;

fn unsupported_reason(yaml: &str) -> String {
    match parse(yaml, Path::new("t.yaml"), None, &LoadOptions::default()) {
        Err((_, Problem::Unsupported(r))) => r,
        Err((_, Problem::Invalid(r))) => panic!("expected unsupported, got invalid: {r}"),
        Ok(_) => panic!("expected unsupported, got a check"),
    }
}

fn invalid_reason(yaml: &str) -> String {
    match parse(yaml, Path::new("t.yaml"), None, &LoadOptions::default()) {
        Err((_, Problem::Invalid(r))) => r,
        Err((_, Problem::Unsupported(r))) => panic!("expected invalid, got unsupported: {r}"),
        Ok(_) => panic!("expected invalid, got a check"),
    }
}

const GIT_CONFIG: &str = r#"
id: git-config
info:
  name: Git Config - Detect
  author: someone
  severity: medium
  description: Git configuration was detected.
  reference: https://example.com/git
  classification:
    cwe-id: CWE-200
  tags: config,git,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: word
        words: ["[core]"]
      - type: status
        status: [200]
    extractors:
      - type: regex
        group: 1
        regex: ['url = (\S+)']
"#;

#[test]
fn parses_nuclei_template() {
    let c = parse_str(GIT_CONFIG).unwrap();
    assert_eq!(c.id, "git-config");
    assert_eq!(c.risk, Risk::Medium);
    assert_eq!(c.cwe, 200);
    assert_eq!(c.tags, ["config", "git", "exposure"]);
    assert_eq!(c.references, ["https://example.com/git"]);
    assert_eq!(c.scope, "host");
    assert_eq!(c.requests, 1);
    let b = &c.blocks[0];
    assert!(b.matchers_and);
    assert_eq!(b.matchers.len(), 2);
    assert!(matches!(b.extractors[0].kind, ExtractKind::Regex(_, 1)));
}

#[test]
fn unsupported_features_are_named() {
    let base = "id: x\ninfo: {name: x, severity: low}\n";
    let block = |extra: &str| format!("{base}http:\n  - path: ['{{{{BaseURL}}}}/']\n{extra}");
    let dsl = |e: &str| block(&format!("    matchers:\n      - type: dsl\n        dsl:\n          - '{e}'\n"));
    assert_eq!(unsupported_reason(&dsl("date_time(\"%Y\")")), "DSL function `date_time`");
    assert_eq!(unsupported_reason(&dsl("contains(interactsh_protocol, \"dns\")")), NEEDS_OOB);
    assert_eq!(unsupported_reason(&dsl("body =~ \"x\"")), "DSL operator `=~`");
    assert!(invalid_reason(&dsl("contains(body")).starts_with("dsl: "));
    assert_eq!(
        unsupported_reason(&block(
            "    matchers:\n      - type: word\n        part: status_code_2\n        words: [a]\n"
        )),
        "part `status_code`"
    );
    assert_eq!(
        unsupported_reason(&block(
            "    matchers:\n      - type: status\n        status: [200]\nflow: javascript() && http(1)\n"
        )),
        "flow (JavaScript)"
    );
    assert_eq!(
        unsupported_reason(&block(
            "    matchers:\n      - type: status\n        status: [200]\nflow: http(1) && http(2)\n"
        )),
        "flow (JavaScript)"
    );
    assert!(parse_str(&block(
        "    matchers:\n      - type: status\n        status: [200]\nflow: '!http(1) || (http(1))'\n"
    ))
    .unwrap()
    .flow
    .is_some());
    assert_eq!(unsupported_reason(&format!("{base}dns:\n  - name: x\n")), "top-level `dns`");
    assert_eq!(
        unsupported_reason(&block(
            "    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [dns]\n"
        )),
        NEEDS_OOB
    );
    assert_eq!(
        unsupported_reason(&block("    payloads:\n      user: helpers/wordlists/users.txt\n    matchers:\n      - type: status\n        status: [200]\n")),
        "payload files (no template directory)"
    );
    assert_eq!(
        unsupported_reason(&block("    matchers:\n      - type: regex\n        regex: ['a(?=b)']\n")),
        "regex syntax (lookaround/backreference)"
    );
    assert_eq!(
        unsupported_reason(&format!(
            "{base}http:\n  - path: ['{{{{BaseURL}}}}/{{{{aes_gcm(a, b)}}}}']\n    matchers:\n      - type: status\n        status: [200]\n"
        )),
        "DSL function `aes_gcm`"
    );
    assert_eq!(
        unsupported_reason(&format!(
            "{base}http:\n  - path: ['{{{{BaseURL}}}}/{{{{base64(username)}}}}']\n    matchers:\n      - type: status\n        status: [200]\n"
        )),
        "template inputs without a value (--check-var): username"
    );
}

#[test]
fn template_inputs() {
    let t = "id: x\ninfo: {name: x, severity: low}\nvariables:\n  user: guest\nhttp:\n  - raw:\n      - |\n        POST /login HTTP/1.1\n        Host: {{Hostname}}\n\n        u={{user}}&p={{url_encode(password)}}&t={{token}}\n    matchers:\n      - type: dsl\n        dsl: ['contains(body, greeting)']\n";
    let opts = |vars: &[(&str, &str)], any| LoadOptions {
        vars: vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        any_inputs: any,
        oob: false,
    };
    let reason = |o: &LoadOptions| match parse(t, Path::new("t.yaml"), None, o) {
        Err((_, Problem::Unsupported(r))) => r,
        _ => panic!("expected unsupported"),
    };
    // Names that are neither defined nor given are listed, sorted.
    assert_eq!(reason(&opts(&[], false)), "template inputs without a value (--check-var): password, token");
    assert_eq!(reason(&opts(&[("password", "x")], false)), "template inputs without a value (--check-var): token");
    // Given inputs are kept when used (in placeholders or DSL) or when they
    // override a template variable (`user`); others are dropped.
    let c = parse(
        t,
        Path::new("t.yaml"),
        None,
        &opts(&[("password", "p w"), ("token", "1"), ("user", "admin"), ("greeting", "hi"), ("other", "o")], false),
    )
    .unwrap_or_else(|_| panic!("loads"));
    let mut names: Vec<&str> = c.inputs.iter().map(|(k, _)| k.as_str()).collect();
    names.sort();
    assert_eq!(names, ["greeting", "password", "token", "user"]);
    // `checks update` keeps templates whatever inputs they need.
    assert!(parse(t, Path::new("t.yaml"), None, &opts(&[], true)).is_ok());
    assert_eq!(parse_var("username=a=b").unwrap(), ("username".into(), "a=b".into()));
    assert!(parse_var("novalue").is_err());
    assert!(parse_var("bad name=x").is_err());
}

#[test]
fn invalid_templates() {
    assert_eq!(invalid_reason("info: {name: x}\nhttp: []\n"), "missing id");
    assert_eq!(
        invalid_reason("id: x\ninfo: {severity: low}\nhttp:\n  - path: ['{{BaseURL}}/']\n"),
        "request block without matchers or extractors"
    );
    assert_eq!(
        invalid_reason("id: x\ninfo: {severity: low}\nscope: param\nhttp:\n  - path: ['{{BaseURL}}/']\n    matchers:\n      - type: status\n        status: [500]\n"),
        "scope: param blocks take `inject` values (no path/raw)"
    );
    assert_eq!(
        invalid_reason("id: x\ninfo: {severity: bad}\nhttp:\n  - path: ['{{BaseURL}}/']\n    matchers:\n      - type: status\n        status: [500]\n"),
        "unknown severity \"bad\""
    );
    assert_eq!(
        invalid_reason("id: x\ninfo: {severity: low}\nhttp:\n  - path: ['/']\n    headers: {\"X-A\": \"a\\r\\nX-B: b\"}\n    matchers:\n      - type: status\n        status: [500]\n"),
        "bad header"
    );
}

#[test]
fn brainproxy_param_extension() {
    let c = parse_str(
        r#"
id: bp-ssti
info: {name: SSTI, severity: high, confidence: high}
scope: param
http:
  - inject: ["{{7*191}}", "${7*191}"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["1337"]
      - type: word
        part: baseline_body
        words: ["1337"]
        negative: true
"#,
    )
    .unwrap();
    assert_eq!(c.rule_scope, RuleScope::Param);
    assert_eq!(c.confidence, Confidence::High);
    assert_eq!(c.blocks[0].inject, ["{{7*191}}", "${7*191}"]);
    assert_eq!(c.blocks[0].matchers[1].part, Part::BaselineBody);
}

#[test]
fn payload_combinations() {
    let p = vec![
        ("u".to_string(), vec!["a".into(), "b".into()]),
        ("p".to_string(), vec!["1".into(), "2".into(), "3".into()]),
    ];
    assert_eq!(combos(&p, Attack::ClusterBomb, 100).len(), 6);
    let pf = combos(&p, Attack::Pitchfork, 100);
    assert_eq!(pf.len(), 2);
    assert_eq!(pf[1], vec![("u".to_string(), "b".to_string()), ("p".to_string(), "2".to_string())]);
    assert_eq!(combos(&p, Attack::ClusterBomb, 4).len(), 4);
    assert_eq!(combos(&[], Attack::BatteringRam, 10), vec![Vec::<(String, String)>::new()]);
}

#[test]
fn filter_and_load_dedupes() {
    let dir = std::env::temp_dir().join(format!("bp-checks-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("a.yaml"), GIT_CONFIG).unwrap();
    std::fs::write(dir.join("sub/b.yml"), GIT_CONFIG).unwrap();
    std::fs::write(dir.join("c.yaml"), "id: c\ninfo: {severity: low}\nflow: x\n").unwrap();
    std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
    let l = load(std::slice::from_ref(&dir), &Default::default()).unwrap();
    assert_eq!(l.checks.len(), 1);
    assert_eq!(l.skipped.len(), 2);
    assert!(l.skipped.iter().any(|s| s.reason == "duplicate id"));
    assert_eq!(l.reasons().len(), 2);

    let c = &l.checks[0];
    assert!(Filter::default().keep(c));
    assert!(Filter { tags: vec!["GIT".into()], ..Default::default() }.keep(c));
    assert!(!Filter { exclude_tags: vec!["exposure".into()], ..Default::default() }.keep(c));
    assert!(!Filter { min_severity: Some(Severity::High), ..Default::default() }.keep(c));
    assert!(!Filter { ids: vec!["other".into()], ..Default::default() }.keep(c));
    // Included tags win over the other filters; a folder of that name counts too.
    let high = Filter { min_severity: Some(Severity::High), include_tags: vec!["git".into()], ..Default::default() };
    assert!(high.keep(c));
    let mut in_eol = c.clone();
    in_eol.tags.clear();
    in_eol.file = std::path::PathBuf::from("nuclei/http/technologies/eol/x-eol.yaml");
    assert!(Filter { min_severity: Some(Severity::High), include_tags: vec!["eol".into()], ..Default::default() }
        .keep(&in_eol));
    assert!(!Filter { min_severity: Some(Severity::High), ..Default::default() }.keep(&in_eol));
    // A band: high but not critical.
    let band = Filter { min_severity: Some(Severity::High), max_severity: Some(Severity::High), ..Default::default() };
    let mut sev = c.clone();
    for (s, kept) in [("medium", false), ("high", true), ("critical", false)] {
        sev.severity = s.into();
        assert_eq!(band.keep(&sev), kept, "{s}");
    }
    sev.severity = "unknown".into();
    assert!(Filter { max_severity: Some(Severity::Info), ..Default::default() }.keep(&sev));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn store_update_from_dir_keeps_only_loadable_templates() {
    let base = std::env::temp_dir().join(format!("bp-store-{}", std::process::id()));
    let src = base.join("nuclei-templates");
    std::fs::create_dir_all(src.join("http/exposures")).unwrap();
    std::fs::create_dir_all(src.join("dns")).unwrap();
    std::fs::write(src.join("http/exposures/git.yaml"), GIT_CONFIG).unwrap();
    std::fs::write(src.join("http/exposures/flow.yaml"), "id: f\ninfo: {severity: low}\nself-contained: true\n")
        .unwrap();
    std::fs::write(src.join("dns/x.yaml"), "id: d\n").unwrap();
    let home = base.join("home");
    let m = update(&home, Source::Dir(src.clone())).await.unwrap();
    assert_eq!((m.templates, m.stored), (2, 1));
    assert_eq!(m.skipped, vec![("top-level `self-contained`".to_string(), 1)]);
    assert!(nuclei_dir(&home).join("http/exposures/git.yaml").is_file());
    assert!(!nuclei_dir(&home).join("http/exposures/flow.yaml").exists());
    assert_eq!(nuclei_status(&home).nuclei.unwrap().stored, 1);
    // A second import replaces the store.
    std::fs::remove_file(src.join("http/exposures/git.yaml")).unwrap();
    std::fs::write(src.join("http/exposures/git2.yaml"), GIT_CONFIG.replace("id: git-config", "id: git2")).unwrap();
    update(&home, Source::Dir(src)).await.unwrap();
    assert!(!nuclei_dir(&home).join("http/exposures/git.yaml").exists());
    assert_eq!(load(&resolve_selectors(&home, &["nuclei".into()]), &Default::default()).unwrap().checks[0].id, "git2");
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn store_paths_are_confined() {
    assert_eq!(store::tests_store_path("http/a/b.yaml"), Some(true));
    assert_eq!(store::tests_store_path("helpers/wordlists/users.txt"), Some(false));
    for bad in [
        "../http/a.yaml",
        "http/../../x.yaml",
        "/http/a.yaml",
        "dns/a.yaml",
        "http/a.sh",
        "http/a b.yaml",
        "helpers/../../x.txt",
        "helpers/",
    ] {
        assert_eq!(store::tests_store_path(bad), None, "{bad}");
    }
}

#[tokio::test]
async fn store_update_from_tarball_layout() {
    // Same handling as the GitHub tarball: "<repo>-<sha>/http/...".
    let gz = crate::fetch::tests::tar_gz(&[
        ("nuclei-templates-abc/http/git.yaml", GIT_CONFIG.as_bytes()),
        ("nuclei-templates-abc/http/../../evil.yaml", GIT_CONFIG.as_bytes()),
        ("nuclei-templates-abc/README.md", b"x"),
        ("nuclei-templates-abc/helpers/wordlists/u.txt", b"admin\n"),
    ]);
    let mut seen = Vec::new();
    crate::fetch::tar_gz_files(&gz, |p, _| {
        if let Some((_, rel)) = p.split_once('/') {
            if store::tests_store_path(rel).is_some() {
                seen.push(rel.to_string());
            }
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, ["http/git.yaml", "helpers/wordlists/u.txt"]);
}

#[test]
fn json_paths() {
    let doc: Value = serde_json::from_str(
        r#"{"version":"1.2","data":{"users":[{"name":"a","id":1},{"name":"b","id":2}]},"setup-token":"t","n":null}"#,
    )
    .unwrap();
    let q = |q: &str| json_path(&doc, &compile_json_path(q).unwrap());
    assert_eq!(q(".version"), ["1.2"]);
    assert_eq!(q(".data.users[].name"), ["a", "b"]);
    assert_eq!(q(".data.users[] | .id"), ["1", "2"]);
    assert_eq!(q(".data.users[1].name"), ["b"]);
    assert_eq!(q(".[\"setup-token\"]"), ["t"]);
    assert_eq!(q(".data.users[0]"), [r#"{"name":"a","id":1}"#]);
    assert!(q(".missing.x").is_empty() && q(".n").is_empty());
    for bad in [".[] | select(.a == 1)", "..|objects", ".a // empty", "keys"] {
        assert!(compile_json_path(bad).is_none(), "{bad}");
    }
}

#[tokio::test]
async fn payload_files_from_helpers() {
    let base = std::env::temp_dir().join(format!("bp-payload-files-{}", std::process::id()));
    let src = base.join("nuclei-templates");
    std::fs::create_dir_all(src.join("http/default-logins")).unwrap();
    std::fs::create_dir_all(src.join("helpers/wordlists")).unwrap();
    std::fs::write(src.join("helpers/wordlists/users.txt"), "admin\r\n\nroot\n").unwrap();
    std::fs::write(base.join("secret.txt"), "outside\n").unwrap();
    let t = |id: &str, file: &str| {
        format!("id: {id}\ninfo: {{severity: low}}\nhttp:\n  - path: ['{{{{BaseURL}}}}/{{{{user}}}}']\n    payloads:\n      user: {file}\n    matchers:\n      - type: status\n        status: [200]\n")
    };
    let dir = src.join("http/default-logins");
    std::fs::write(dir.join("ok.yaml"), t("ok", "helpers/wordlists/users.txt")).unwrap();
    std::fs::write(dir.join("up.yaml"), t("up", "../../../secret.txt")).unwrap();
    std::fs::write(dir.join("abs.yaml"), t("abs", base.join("secret.txt").to_str().unwrap())).unwrap();
    std::fs::write(dir.join("missing.yaml"), t("missing", "helpers/nope.txt")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(base.join("secret.txt"), src.join("helpers/wordlists/link.txt")).unwrap();
    #[cfg(unix)]
    std::fs::write(dir.join("link.yaml"), t("link", "helpers/wordlists/link.txt")).unwrap();

    // Loading the checkout root: helpers/ resolves from an ancestor directory.
    let l = load(std::slice::from_ref(&src), &Default::default()).unwrap();
    assert_eq!(l.checks.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["ok"], "{:?}", l.skipped);
    assert_eq!(l.checks[0].blocks[0].payloads[0].1, ["admin", "root"]);
    let reason = |id: &str| l.skipped.iter().find(|s| s.id.as_deref() == Some(id)).unwrap().reason.clone();
    assert!(reason("up").starts_with("payload file path"), "{}", reason("up"));
    assert!(reason("abs").starts_with("payload file path"), "{}", reason("abs"));
    assert!(reason("missing").starts_with("payload file not found"));
    #[cfg(unix)]
    assert!(reason("link").starts_with("payload file not found"), "a symlink out of the root is refused");
    // Loading only http/ can't see helpers/ (outside the root).
    let l = load(&[src.join("http")], &Default::default()).unwrap();
    assert!(l.checks.is_empty());

    // `checks update` keeps helpers/ (not the symlink), so the stored template loads.
    let home = base.join("home");
    let m = update(&home, Source::Dir(src)).await.unwrap();
    assert_eq!((m.stored, m.helpers), (1, 1), "{m:?}");
    let l = load(&resolve_selectors(&home, &["nuclei".into()]), &Default::default()).unwrap();
    assert_eq!(l.checks[0].blocks[0].payloads[0].1, ["admin", "root"]);
    std::fs::remove_dir_all(&base).unwrap();
}

const OAST: &str = r#"
id: oast-ssrf
info: {name: Blind SSRF, severity: high}
variables:
  cb: "http://{{interactsh-url}}/x"
http:
  - path: ["{{BaseURL}}/?u={{cb}}"]
    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words: [http]
      - type: dsl
        dsl: ['contains(interactsh_request, "User-Agent: curl") && status_code == 200']
      - type: status
        status: [200]
    extractors:
      - type: dsl
        dsl: [interactsh_ip]
"#;

#[test]
fn interactsh_templates_need_a_listener() {
    let oob = LoadOptions { oob: true, ..Default::default() };
    match parse(OAST, Path::new("t.yaml"), None, &LoadOptions::default()) {
        Err((_, Problem::Unsupported(r))) => assert_eq!(r, NEEDS_OOB),
        _ => panic!("needs a listener"),
    }
    let c = parse(OAST, Path::new("t.yaml"), None, &oob).unwrap_or_else(|_| panic!("loads with a listener"));
    assert!(c.oob_url);
    let b = &c.blocks[0];
    assert!(b.oob);
    assert_eq!(b.matchers.iter().map(|m| m.oob).collect::<Vec<_>>(), [true, true, false]);
    assert!(b.matchers[0].src.is_some() && b.matchers[2].src.is_none());
    // The interactsh_ip extractor is dropped (correlation shows the caller).
    assert!(b.extractors.is_empty());
    // A url without interactsh matchers loads too (fire and forget).
    assert!(!parse_str_oob("id: x\ninfo: {severity: low}\nhttp:\n  - path: ['{{BaseURL}}/?u={{interactsh-url}}']\n    matchers:\n      - type: status\n        status: [200]\n").blocks[0].oob);
}

fn parse_str_oob(t: &str) -> Check {
    parse(t, Path::new("t.yaml"), None, &LoadOptions { oob: true, ..Default::default() }).unwrap_or_else(|_| panic!())
}

#[test]
fn interactions_are_matched_against_interactsh_matchers() {
    let c = parse_str_oob(OAST);
    let srcs: Vec<Value> = c.blocks[0].matchers.iter().filter_map(|m| m.src.clone()).collect();
    // As `defer_oob` stores it: the response's status_code kept for the DSL.
    let check =
        |status: u16, and: bool| serde_json::json!({"and": and, "matchers": srcs, "vars": {"status_code": status}});
    let curl = b"GET /bpaaaaaaaaaaaaaaaaaa/x HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: curl/8\r\n\r\n";
    assert!(interaction_matches(&check(200, true), "http", "10.0.0.5:4242", curl));
    // HTTPS (a TLS ClientHello) counts as http, like interactsh.
    assert!(interaction_matches(&check(200, true), "tls", "10.0.0.5:4242", curl));
    assert!(!interaction_matches(&check(200, true), "dns", "10.0.0.5:53", curl));
    assert!(!interaction_matches(&check(500, true), "http", "10.0.0.5:4242", curl));
    assert!(!interaction_matches(&check(200, true), "http", "10.0.0.5:4242", b"GET / HTTP/1.1\r\n\r\n"));
    assert!(interaction_matches(&check(500, false), "http", "10.0.0.5:4242", b"GET / HTTP/1.1\r\n\r\n"));
    let ip = serde_json::json!({"matchers": [{"type": "dsl", "dsl": ["interactsh_ip == '10.0.0.5'"]}]});
    assert!(interaction_matches(&ip, "dns", "10.0.0.5:53", b""));
    assert!(interaction_matches(&ip, "dns", "[10.0.0.5]:53", b""));
    let neg = serde_json::json!({"matchers": [{"type": "word", "part": "interactsh_protocol", "words": ["dns"], "negative": true}]});
    assert!(interaction_matches(&neg, "http", "x:1", b"") && !interaction_matches(&neg, "dns", "x:1", b""));
}

#[test]
fn raw_annotations() {
    let raw = |r: &str| {
        format!(
            "id: t\ninfo: {{name: t, severity: high}}\nhttp:\n  - raw:\n      - |\n{}\n    matchers:\n      - type: status\n        status: [200]\n",
            r.lines().map(|l| format!("        {l}")).collect::<Vec<_>>().join("\n")
        )
    };
    let c = parse_str(&raw("@timeout: 20s\nGET / HTTP/1.1\nHost: {{Hostname}}")).unwrap();
    assert_eq!(c.blocks[0].timeout, Some(std::time::Duration::from_secs(20)));
    assert!(c.blocks[0].raws[0].starts_with("GET / HTTP/1.1"), "{:?}", c.blocks[0].raws[0]);
    assert_eq!(parse_str(&raw("@timeout:5\nGET / HTTP/1.1")).unwrap().blocks[0].timeout.unwrap().as_secs(), 5);
    assert_eq!(parse_str(&raw("@timeout 15s\nGET / HTTP/1.1")).unwrap().blocks[0].timeout.unwrap().as_secs(), 15);
    assert_eq!(parse_str(&raw("GET / HTTP/1.1")).unwrap().blocks[0].timeout, None);
    assert!(unsupported_reason(&raw("@Host: https://other:443\nGET / HTTP/1.1")).contains("@Host"));
    assert!(invalid_reason(&raw("@timeout: soon\nGET / HTTP/1.1")).contains("@timeout"));
}

fn passive_check(yaml: &str) -> PassiveCheck {
    let c = parse(yaml, Path::new("t.yaml"), None, &LoadOptions::default()).unwrap_or_else(|_| panic!("loads"));
    into_passive(vec![c]).pop().expect("a passive check")
}

fn passive_hits(c: &PassiveCheck, request: &str, status: u16, headers: &[(&str, &str)]) -> usize {
    let headers = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let resp = crate::scan::active::Response::recorded(status, headers, Vec::new());
    let mut out = Vec::new();
    c.scan("a.test", request, &resp, &mut out);
    out.len()
}

#[test]
fn passive_scope() {
    let ok = "id: p\ninfo: {severity: low}\nscope: passive\nhttp:\n  - matchers:\n      - type: word\n        part: header\n        words: [X-Debug]\n";
    let c = parse(ok, Path::new("t.yaml"), None, &LoadOptions::default()).unwrap_or_else(|_| panic!("loads"));
    assert_eq!((c.scope, c.requests), ("passive", 0));
    // Passive checks aren't active rules, and active ones aren't passive.
    assert!(into_rules(vec![c.clone()], std::time::Duration::from_secs(1)).is_empty());
    assert!(into_passive(vec![parse_str(GIT_CONFIG).unwrap()]).is_empty());
    let p = passive_check(ok);
    assert_eq!(passive_hits(&p, "GET / HTTP/1.1\r\n", 200, &[("X-Debug", "1")]), 1);
    assert_eq!(passive_hits(&p, "GET / HTTP/1.1\r\n", 200, &[("X-Other", "1")]), 0);
    // Nothing that sends, and nothing that needs more than one recorded response.
    for (block, why) in [
        ("  - path: ['{{BaseURL}}/x']\n    matchers: [{type: status, status: [200]}]", "only have matchers"),
        ("  - matchers: [{type: word, part: body_2, words: [x]}]", "one recorded response"),
        ("  - matchers: [{type: word, part: baseline_body, words: [x]}]", "one recorded response"),
    ] {
        let y = format!("id: p\ninfo: {{severity: low}}\nscope: passive\nhttp:\n{block}\n");
        assert!(invalid_reason(&y).contains(why), "{block}: {}", invalid_reason(&y));
    }
    let active = "id: a\ninfo: {severity: low}\nhttp:\n  - path: ['{{BaseURL}}/']\n    matchers: [{type: word, part: request_header, words: [x]}]\n";
    assert!(invalid_reason(active).contains("needs scope: passive"));
}

/// PHP2Shell rule 100001's version test re-expressed as a passive check: the format
/// carries it (named extractor values feed DSL matchers), so built-in version rules
/// can move to the feed.
#[test]
fn passive_check_expresses_php2shell_version_rule() {
    let c = passive_check(
        r#"
id: php2shell-version
info: {severity: high}
scope: passive
http:
  - extractors:
      - type: regex
        name: v
        part: header
        group: 1
        regex: ['(?i)\bPHP/(\d+\.\d+\.\d+)']
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(v, '>= 5.4.0, < 8.2.0') || compare_versions(v, '>= 8.2.0, < 8.2.35') || compare_versions(v, '>= 8.3.0, < 8.3.36') || compare_versions(v, '>= 8.4.0, < 8.4.27') || compare_versions(v, '>= 8.5.0, < 8.5.12')"
"#,
    );
    let hit = |h: &str| passive_hits(&c, "GET / HTTP/1.1\r\n", 200, &[("X-Powered-By", h)]) > 0;
    assert!(hit("PHP/8.2.34") && hit("PHP/7.4.33") && hit("PHP/8.5.11"));
    assert!(!hit("PHP/8.2.35") && !hit("PHP/8.5.12") && !hit("PHP/5.3.29") && !hit("Express"));
}

#[test]
fn feed_brotli_check_flags_accepted_br_bodies() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../feed/passive/brotli/brotli-request-body-accepted.yaml");
    let c = passive_check(&std::fs::read_to_string(path).unwrap());
    let br = "POST /api HTTP/1.1\r\nContent-Type: application/json\r\nContent-Encoding: br\r\n";
    assert_eq!(passive_hits(&c, br, 200, &[]), 1);
    assert_eq!(passive_hits(&c, &br.replace("br\r", "gzip, BR\r"), 201, &[]), 1);
    // Refused (Express 4 answers 415), not compressed, or only accepting br responses.
    assert_eq!(passive_hits(&c, br, 415, &[]), 0);
    assert_eq!(passive_hits(&c, &br.replace("br\r", "gzip\r"), 200, &[]), 0);
    assert_eq!(passive_hits(&c, "GET / HTTP/1.1\r\nAccept-Encoding: gzip, br\r\n", 200, &[]), 0);
}

#[test]
fn feed_php_checks_list_known_vulnerabilities() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../feed/passive/php");
    let checks: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| passive_check(&std::fs::read_to_string(e.unwrap().path()).unwrap()))
        .collect();
    assert_eq!(checks.len(), 4, "one check per severity band");
    // (findings, matched CVE ids) for one response header.
    let scan = |name: &str, value: &str| {
        let resp =
            crate::scan::active::Response::recorded(200, vec![(name.to_string(), value.to_string())], Vec::new());
        let mut out = Vec::new();
        for c in &checks {
            c.scan("a.test", "GET / HTTP/1.1\r\n", &resp, &mut out);
        }
        let cves: Vec<String> = out
            .iter()
            .filter_map(|f| f.other_info.lines().find_map(|l| l.strip_prefix("Matched: ")))
            .flat_map(|m| m.split(", ").map(|n| n.split(' ').next().unwrap().to_string()))
            .collect();
        (out.len(), cves)
    };
    let (n, cves) = scan("X-Powered-By", "PHP/7.4.33");
    assert!(n <= 4 && cves.iter().any(|c| c == "CVE-2024-4577"));
    // Fixed in 7.3.11, so only earlier 7.x releases.
    assert!(
        !cves.iter().any(|c| c == "CVE-2019-11043")
            && scan("X-Powered-By", "PHP/7.3.10").1.iter().any(|c| c == "CVE-2019-11043")
    );
    assert!(scan("Server", "Apache/2.4.41 (Unix) PHP/8.3.0").1.iter().any(|c| c == "CVE-2024-2756"));
    assert!(!scan("X-Powered-By", "PHP/8.1.2").1.iter().any(|c| c == "CVE-2024-2756"));
    // PHP2Shell is reported by rule 100001, not here.
    assert!(!scan("X-Powered-By", "PHP/8.2.34").1.iter().any(|c| c.starts_with("CVE-2026-10961")));
    // Fixed or unreleased versions, versions without a patch number, and other products.
    for (h, v) in [
        ("X-Powered-By", "PHP/8.5.12"),
        ("X-Powered-By", "PHP/9.0.0"),
        ("X-Powered-By", "PHP/8.2"),
        ("Server", "Foo-PHP/7.4.33"),
    ] {
        assert_eq!(scan(h, v).0, 0, "{v}");
    }
}

/// A key for tests only (never trusted by a build).
const TEST_KEY: &str =
    "MFECAQEwBQYDK2VwBCIEIBpRIkmizhbv7dGtJc9/G+zkXw6t7WRZcrnkbDkqkEv8gSEAGpYIJV1dKseRAbg2qOXP+7CX7vxHR9P+Gap3jDwYgCo=";
const TEST_PUBLIC: &str = "GpYIJV1dKseRAbg2qOXP+7CX7vxHR9P+Gap3jDwYgCo=";

#[tokio::test]
async fn feed_is_signed_and_verified() {
    let base = std::env::temp_dir().join(format!("bp-feed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let src = base.join("repo/feed");
    std::fs::create_dir_all(src.join("http")).unwrap();
    std::fs::write(src.join("http/git.yaml"), GIT_CONFIG).unwrap();
    let (id, n) = feed::sign(&src, TEST_KEY).unwrap();
    assert_eq!((id.len(), n), (16, 1));
    let home = base.join("home");
    let keys = &[TEST_PUBLIC];
    // A file added after signing isn't installed: only what feed.json lists is.
    std::fs::write(src.join("http/unsigned.yaml"), GIT_CONFIG.replace("id: git-config", "id: unsigned")).unwrap();
    let m = feed::update_with(&home, Source::Dir(base.join("repo")), keys).await.unwrap();
    assert_eq!((m.templates, m.stored, m.signed_by.as_str()), (1, 1, id.as_str()));
    assert_eq!(m.changes.unwrap().added, vec!["http/git.yaml".to_string()]);
    assert!(brainproxy_dir(&home).join("http/git.yaml").is_file());
    assert!(!brainproxy_dir(&home).join("http/unsigned.yaml").exists());
    assert_eq!(nuclei_status(&home).brainproxy.unwrap().signed_by, id);
    assert_eq!(load(&resolve_selectors(&home, &["all".into()]), &Default::default()).unwrap().checks.len(), 1);

    // Tampering anywhere fails the update and keeps the installed store.
    let fails = |what: &str| {
        let (home, src, base) = (home.clone(), src.clone(), base.clone());
        let what = what.to_string();
        async move {
            let e = feed::update_with(&home, Source::Dir(src.clone()), keys).await.unwrap_err().to_string();
            assert!(brainproxy_dir(&home).join("http/git.yaml").is_file(), "{what}: store kept");
            assert!(!base.join("home/checks/.brainproxy.new").exists(), "{what}: staging removed");
            e
        }
    };
    std::fs::write(src.join("http/git.yaml"), GIT_CONFIG.replace("[core]", "[c0re]")).unwrap();
    assert!(fails("file").await.contains("sha256"));
    feed::sign(&src, TEST_KEY).unwrap();
    std::fs::remove_file(src.join("http/unsigned.yaml")).unwrap();
    feed::sign(&src, TEST_KEY).unwrap();
    let c = feed::update_with(&home, Source::Dir(src.clone()), keys).await.unwrap().changes.unwrap();
    assert_eq!((c.added.len(), c.changed, c.removed.len()), (0, vec!["http/git.yaml".to_string()], 0));
    let list = std::fs::read_to_string(src.join("feed.json")).unwrap();
    std::fs::write(src.join("feed.json"), list.replace("\"version\": 1", "\"version\":1")).unwrap();
    assert!(fails("list").await.contains("doesn't match"));
    std::fs::write(src.join("feed.json"), list).unwrap();
    let sig = std::fs::read_to_string(src.join("feed.sig")).unwrap();
    std::fs::write(src.join("feed.sig"), sig.replacen(&id, "0000000000000000", 1)).unwrap();
    assert!(fails("key").await.contains("not trusted"));
    // The real build trusts other keys, and refuses to run with none.
    std::fs::write(src.join("feed.sig"), sig).unwrap();
    assert!(feed::update(&home, Source::Dir(src.clone())).await.unwrap_err().to_string().contains("not trusted"));
    assert!(feed::update_with(&home, Source::Dir(src), &[]).await.is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn feed_lists_only_plain_template_paths() {
    let (_, pair_public, _) = feed::keygen().unwrap();
    assert_eq!(pair_public.len(), 44);
    let base = std::env::temp_dir().join(format!("bp-feed-paths-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("notes.txt"), "x").unwrap();
    assert!(feed::sign(&base, TEST_KEY).unwrap_err().to_string().contains("not a feed file"));
    // A list naming a path outside the store is refused even when validly signed.
    std::fs::remove_file(base.join("notes.txt")).unwrap();
    feed::sign(&base, TEST_KEY).unwrap();
    let list = br#"{"version":1,"files":{"../x.yaml":"00"}}"#;
    let doc = base64::engine::general_purpose::STANDARD.decode(TEST_KEY).unwrap();
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&doc).unwrap();
    let sig = format!(
        "{} {}",
        feed::key_id(base64::engine::general_purpose::STANDARD.decode(TEST_PUBLIC).unwrap().as_slice()),
        base64::engine::general_purpose::STANDARD.encode(pair.sign(list).as_ref())
    );
    assert!(feed::verify(list, sig.as_bytes(), &[TEST_PUBLIC]).unwrap_err().to_string().contains("bad path"));
    std::fs::remove_dir_all(&base).unwrap();
}

/// The repository's feed/ is signed with a key this build trusts, and every file matches.
#[test]
fn repository_feed_verifies() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../feed");
    let read = |n: &str| std::fs::read(dir.join(n)).unwrap();
    let (_, list) = feed::verify(&read("feed.json"), &read("feed.sig"), feed::TRUSTED_KEYS)
        .expect("feed/ signature: run `brainproxy checks feed sign feed --key <key>`");
    let mut on_disk = Vec::new();
    walk(&dir, &mut on_disk).unwrap();
    assert_eq!(on_disk.len(), list.files.len(), "feed/ has templates feed.json doesn't list: sign it again");
    for (rel, want) in &list.files {
        assert_eq!(&crate::fetch::sha256_hex(&read(rel)), want, "{rel} changed since signing: sign the feed again");
        let loaded = load(&[dir.join(rel)], &LoadOptions::default()).unwrap();
        assert!(loaded.skipped.is_empty(), "{rel}: {:?}", loaded.skipped);
    }
}

#[test]
fn body_hex_sends_bytes() {
    let y = |b: &str| {
        format!("id: h\ninfo: {{severity: low}}\nhttp:\n  - method: POST\n    path: ['{{{{BaseURL}}}}/']\n{b}\n    matchers: [{{type: status, status: [200]}}]\n")
    };
    let c = parse_str(&y("    body-hex: '8f00 807b7d03'")).unwrap();
    assert_eq!(c.blocks[0].body_bytes.as_deref(), Some(&[0x8f, 0x00, 0x80, 0x7b, 0x7d, 0x03][..]));
    assert!(invalid_reason(&y("    body-hex: zz")).contains("not hex"));
    assert!(invalid_reason(&y("    body: x\n    body-hex: '00'")).contains("replaces `body`"));
    // The feed probe's streams are valid Brotli for "{}" and "{".
    let br = |hex: &str| {
        let headers = vec![("Content-Encoding".to_string(), "br".to_string())];
        crate::capture::decode_body(&headers, &::hex::decode(hex).unwrap())
    };
    assert_eq!((br("8f00807b7d03"), br("0f00807b03")), (b"{}".to_vec(), b"{".to_vec()));
}

#[test]
fn a_timeout_that_is_not_a_number_is_invalid() {
    let t = "id: x\ninfo: {severity: low}\nhttp:\n  - raw:\n      - |\n        @timeout: nan\n        GET / HTTP/1.1\n        Host: {{Hostname}}\n    matchers:\n      - type: status\n        status: [200]\n";
    assert!(invalid_reason(t).contains("@timeout"), "{}", invalid_reason(t));
}
