use super::*;

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
            "{base}http:\n  - path: ['{{{{BaseURL}}}}/{{{{generate_jwt(a, b)}}}}']\n    matchers:\n      - type: status\n        status: [200]\n"
        )),
        "DSL function `generate_jwt`"
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
    assert!(!Filter { min_risk: Some(Risk::High), ..Default::default() }.keep(c));
    assert!(!Filter { ids: vec!["other".into()], ..Default::default() }.keep(c));
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
