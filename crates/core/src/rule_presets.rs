//! Response modification presets: ready-made match-and-replace rules for what a tester most
//! often changes in what the browser is shown (hidden and disabled form fields, length limits,
//! form validation, scripts, plugins, cookie flags). A preset is only a list of ordinary rules:
//! `rules presets add` saves them as `rules add` would, and from then on they list, switch on and
//! off, and go away like any other rule. Each names its preset in its comment.
//!
//! Every preset rule applies to proxied responses only (no `applies_to`: the proxy). The HTML ones
//! carry a Content-Type condition ([`HTML`]), so a script, JSON or an image passes untouched. Their
//! patterns are bytes regexes with Unicode off (`-u`), so a body that isn't UTF-8 is still matched
//! byte by byte, and the regex engine's search time is linear in the body whatever it holds (it
//! never backtracks); bodies are already capped where the proxy reads and decodes them.
//!
//! Burp's "convert HTTPS links to HTTP" is left out on purpose: the browser would then ask the
//! proxy for plain HTTP, and brainproxy has nothing that upgrades such a request back to HTTPS
//! upstream, so most sites would redirect back or break.

use crate::error::{Error, Result};
use crate::rules::{Rule, RuleAction, RuleLocation};

/// The Content-Type of an HTML page: text/html or XHTML, with any parameters.
pub const HTML: &str = r"^\s*(text/html|application/xhtml\+xml)\s*(;|$)";

/// An attribute's value: quoted, or unquoted as HTML allows.
const VALUE: &str = r#"(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+)"#;

/// One attribute of a tag, with the space before it. A quoted value may hold a `>` or another
/// attribute's name, which the tag patterns step over rather than read.
const ATTR: &str = r#"\s+[^\s"'<>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?"#;

/// How an unhidden field is marked. Written first in the tag: of two `style` attributes the
/// first counts, so one the page gave the field (`display:none`, say) doesn't hide it again.
const SHOWN: &str = r#"style="display:inline-block;visibility:visible;outline:2px dashed #e5484d" title="hidden field, shown by brainproxy""#;

/// A preset: its name (what `rules presets add` takes), a title and what it does.
pub struct Preset {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    build: fn() -> Vec<Rule>,
}

impl Preset {
    /// The rules it adds, without ids, each with a comment that names the preset; with `host`,
    /// only for targets whose host matches that regex.
    pub fn rules(&self, host: Option<&str>) -> Vec<Rule> {
        let mut rules = (self.build)();
        for rule in &mut rules {
            let what = rule.comment.take().unwrap_or_default();
            rule.comment = Some(format!("preset {}: {what}", self.name));
            rule.host = host.filter(|h| !h.is_empty()).map(str::to_string);
        }
        rules
    }
}

/// The presets, in the order they are listed.
pub const PRESETS: &[Preset] = &[
    Preset {
        name: "unhide-fields",
        title: "Unhide hidden form fields",
        description: "Hidden inputs become text inputs, outlined in red so they stand out.",
        build: unhide_fields,
    },
    Preset {
        name: "enable-fields",
        title: "Enable disabled form fields",
        description: "Removes disabled from form controls and readonly from inputs and text areas.",
        build: enable_fields,
    },
    Preset {
        name: "remove-length-limits",
        title: "Remove input field length limits",
        description: "Removes maxlength from inputs and text areas.",
        build: remove_length_limits,
    },
    Preset {
        name: "remove-form-validation",
        title: "Remove form validation",
        description: "Marks every form novalidate (no browser checks of required, pattern, type and the like) and \
                      removes its onsubmit handler.",
        build: remove_form_validation,
    },
    Preset {
        name: "remove-scripts",
        title: "Remove all JavaScript",
        description: "Removes script elements and adds a Content-Security-Policy of script-src 'none', so the \
                      browser runs no inline handler or javascript: link either.",
        build: remove_scripts,
    },
    Preset {
        name: "remove-objects",
        title: "Remove object and embed tags",
        description: "Removes object elements (with what they hold) and embed tags.",
        build: remove_objects,
    },
    Preset {
        name: "remove-cookie-httponly",
        title: "Remove the HttpOnly flag from cookies",
        description: "Removes HttpOnly from every Set-Cookie header, so the page's scripts can read the cookies.",
        build: remove_cookie_httponly,
    },
    Preset {
        name: "remove-cookie-secure",
        title: "Remove the Secure flag from cookies",
        description: "Removes Secure from every Set-Cookie header, so cookies are sent over plain HTTP too. Browsers \
                      then refuse __Secure- and __Host- cookies and SameSite=None ones, which must be Secure.",
        build: remove_cookie_secure,
    },
];

/// The preset called `name`.
pub fn preset(name: &str) -> Result<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name).ok_or_else(|| {
        let names: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
        Error::InvalidInput(format!("no preset {name:?}; presets: {}", names.join(", ")))
    })
}

/// Whether two rules do the same: the same place, match, replacement and conditions, whatever
/// their id, comment, who added them and whether they are on.
pub fn same_rule(a: &Rule, b: &Rule) -> bool {
    let given = |s: &Option<String>| s.clone().filter(|s| !s.is_empty());
    a.location == b.location
        && a.pattern == b.pattern
        && a.replace == b.replace
        && a.matcher == b.matcher
        && a.name == b.name
        && a.action.unwrap_or_default() == b.action.unwrap_or_default()
        && a.engines() == b.engines()
        && given(&a.host) == given(&b.host)
        && given(&a.content_type) == given(&b.content_type)
        && a.replacer == b.replacer
        && a.script == b.script
}

/// A rule for HTML response bodies.
fn html_body(what: &str, pattern: String, replace: &str) -> Rule {
    Rule {
        content_type: Some(HTML.into()),
        comment: Some(what.into()),
        ..Rule::new(0, RuleLocation::ResponseBody, &pattern, replace)
    }
}

/// A rule that removes `attr` (with any value) from the start tags of `tags` (alternatives, as
/// in a regex). One match removes it once from a tag, which is all a tag should hold.
fn drop_attr(what: &str, tags: &str, attr: &str) -> Rule {
    html_body(what, format!(r"(?i-u)(<(?:{tags})\b(?:{ATTR})*?)\s+{attr}(?:\s*=\s*{VALUE})?([\s/>])"), "${1}${2}")
}

/// A rule that removes a flag from each Set-Cookie header (of any response). A cookie's value
/// can't hold a `;`, so whatever follows one is an attribute.
fn drop_cookie_flag(what: &str, flag: &str) -> Rule {
    Rule {
        name: Some("Set-Cookie".into()),
        comment: Some(what.into()),
        ..Rule::new(0, RuleLocation::ResponseHeader, &format!(r"(?i-u);\s*{flag}\b(?:\s*=[^;]*)?"), "")
    }
}

fn unhide_fields() -> Vec<Rule> {
    vec![html_body(
        "hidden inputs become outlined text inputs",
        format!(r#"(?i-u)<input\b((?:{ATTR})*?\s+type\s*=\s*)(?:"hidden"|'hidden'|hidden)([\s/>])"#),
        &format!(r#"<input {SHOWN}${{1}}"text"${{2}}"#),
    )]
}

fn enable_fields() -> Vec<Rule> {
    vec![
        drop_attr("remove disabled", "input|select|textarea|button|fieldset|optgroup|option", "disabled"),
        drop_attr("remove readonly", "input|textarea", "readonly"),
    ]
}

fn remove_length_limits() -> Vec<Rule> {
    vec![drop_attr("remove maxlength", "input|textarea", "maxlength")]
}

fn remove_form_validation() -> Vec<Rule> {
    vec![
        html_body("forms are novalidate", r"(?i-u)<form\b".into(), "<form novalidate"),
        drop_attr("remove onsubmit", "form", "onsubmit"),
    ]
}

fn remove_scripts() -> Vec<Rule> {
    vec![
        // A script element ends at the first `</script`, whatever it holds: as the browser reads it.
        html_body("remove script elements", r"(?is-u)<script\b.*?</script(?:[\s/][^>]*)?>".into(), ""),
        Rule {
            name: Some("Content-Security-Policy".into()),
            action: Some(RuleAction::Add),
            content_type: Some(HTML.into()),
            comment: Some("no script runs".into()),
            ..Rule::new(0, RuleLocation::ResponseHeader, "", "script-src 'none'")
        },
    ]
}

fn remove_objects() -> Vec<Rule> {
    vec![
        html_body("remove object elements", r"(?is-u)<object\b.*?</object(?:[\s/][^>]*)?>".into(), ""),
        html_body("remove embed tags", format!(r"(?i-u)<embed\b(?:{ATTR})*\s*/?>"), ""),
    ]
}

fn remove_cookie_httponly() -> Vec<Rule> {
    vec![drop_cookie_flag("remove HttpOnly", "httponly")]
}

fn remove_cookie_secure() -> Vec<Rule> {
    vec![drop_cookie_flag("remove Secure", "secure")]
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::rules::{validate_rule, Engine, RuleSet};

    /// `body` served as `content_type` (none: no Content-Type), with the header lines in `head`,
    /// after `name`'s rules: the whole response.
    fn through(name: &str, content_type: &str, head: &str, body: &[u8]) -> Vec<u8> {
        let set = RuleSet::compile(&preset(name).unwrap().rules(None)).unwrap();
        let typed = if content_type == "none" { String::new() } else { format!("Content-Type: {content_type}\r\n") };
        let mut response =
            format!("HTTP/1.1 200 OK\r\n{typed}{head}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
        response.extend_from_slice(body);
        set.response(Engine::Proxy, "app.test", b"GET / HTTP/1.1\r\n\r\n", response).bytes
    }

    /// The body of an HTML page after `name`'s rules.
    fn html(name: &str, body: &str) -> String {
        let out = through(name, "text/html; charset=utf-8", "", body.as_bytes());
        let at = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        String::from_utf8(out[at..].to_vec()).unwrap()
    }

    #[test]
    fn every_preset_is_rules_a_project_takes_and_names_itself_in_their_comments() {
        let names: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
        for p in PRESETS {
            assert_eq!(names.iter().filter(|n| **n == p.name).count(), 1, "{} listed twice", p.name);
            let rules = p.rules(Some("app\\.test"));
            assert!(!rules.is_empty());
            for rule in &rules {
                validate_rule(rule).unwrap_or_else(|e| panic!("{}: {e}", p.name));
                assert!(rule.comment.as_deref().unwrap().starts_with(&format!("preset {}: ", p.name)));
                assert_eq!(rule.host.as_deref(), Some("app\\.test"));
                // Proxied responses only.
                assert!(rule.applies_to.is_empty() && rule.engines() == [Engine::Proxy], "{}", p.name);
                assert!(matches!(rule.location, RuleLocation::ResponseBody | RuleLocation::ResponseHeader));
            }
        }
        assert!(preset("convert-https").is_err());
        // An empty host is no condition.
        assert!(preset("enable-fields").unwrap().rules(Some("")).iter().all(|r| r.host.is_none()));
    }

    #[test]
    fn unhide_fields_turns_hidden_inputs_into_outlined_text_inputs() {
        let out = html(
            "unhide-fields",
            r#"<form><INPUT TYPE=HIDDEN name=csrf value="a>b"><input name="t" type='hidden'/>
<input value="type=hidden" type="text"><input data-type="hidden" name=x><input type="hiddenish"></form>"#,
        );
        assert_eq!(
            out,
            format!(
                r#"<form><input {SHOWN} TYPE="text" name=csrf value="a>b"><input {SHOWN} name="t" type="text"/>
<input value="type=hidden" type="text"><input data-type="hidden" name=x><input type="hiddenish"></form>"#
            )
        );
        // The page's own style comes after the one written first, so it can't hide the field.
        let out = html("unhide-fields", r#"<input style="display:none" type="hidden">"#);
        assert!(out.starts_with(&format!(r#"<input {SHOWN} style="display:none""#)), "{out}");
    }

    #[test]
    fn enable_fields_removes_disabled_and_readonly() {
        let out = html(
            "enable-fields",
            r#"<input disabled name=a><select name=b disabled="disabled"><option DISABLED>x</option></select>
<textarea readonly disabled></textarea><button class="btn disabled" disabled/>
<input data-disabled="1" title='disabled'><div disabled></div><input readonly=readonly>"#,
        );
        assert_eq!(
            out,
            r#"<input name=a><select name=b><option>x</option></select>
<textarea></textarea><button class="btn disabled"/>
<input data-disabled="1" title='disabled'><div disabled></div><input>"#
        );
    }

    #[test]
    fn remove_length_limits_removes_maxlength() {
        let out = html(
            "remove-length-limits",
            r#"<input name=a maxlength=8><textarea MAXLENGTH="200" rows=3></textarea><input data-maxlength=3 maxlength='2'/><p maxlength=1>"#,
        );
        assert_eq!(out, r#"<input name=a><textarea rows=3></textarea><input data-maxlength=3/><p maxlength=1>"#);
    }

    #[test]
    fn remove_form_validation_makes_forms_novalidate_without_onsubmit() {
        let out = html(
            "remove-form-validation",
            r#"<form action=/x onsubmit="return check(this)"><input required pattern="\d+"></form><FORM>"#,
        );
        assert_eq!(out, r#"<form novalidate action=/x><input required pattern="\d+"></form><form novalidate>"#);
    }

    #[test]
    fn remove_scripts_removes_script_elements_and_forbids_the_rest() {
        let body = "<head><script src=/a.js></script><SCRIPT type=module>\nif (a < b) x('</p>')\n</script >\
                    </head><body onload=go()><p>hi</p><script>var s = 1</script\n></body>";
        let out = through("remove-scripts", "text/html", "", body.as_bytes());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\r\nContent-Security-Policy: script-src 'none'\r\n"), "{text}");
        assert!(text.ends_with("<head></head><body onload=go()><p>hi</p></body>"), "{text}");
    }

    #[test]
    fn remove_objects_removes_object_and_embed() {
        let out = html(
            "remove-objects",
            r#"<p>a</p><object data="x.swf"><param name=a value=b><embed src="y.swf"></object><EMBED src=z.swf type="a/b"/><p>b</p>"#,
        );
        assert_eq!(out, "<p>a</p><p>b</p>");
    }

    #[test]
    fn cookie_presets_remove_their_flag_from_every_set_cookie() {
        let head = "Set-Cookie: sid=1; Path=/; Secure; HttpOnly\r\nSet-Cookie: t=x;secure;SameSite=Lax\r\n\
                    Set-Cookie: httponlyish=1; Path=/httponly\r\n";
        let out = String::from_utf8(through("remove-cookie-secure", "application/json", head, b"{}")).unwrap();
        assert!(out.contains("Set-Cookie: sid=1; Path=/; HttpOnly\r\n"), "{out}");
        assert!(out.contains("Set-Cookie: t=x;SameSite=Lax\r\n"), "{out}");
        let out = String::from_utf8(through("remove-cookie-httponly", "text/plain", head, b"")).unwrap();
        assert!(out.contains("Set-Cookie: sid=1; Path=/; Secure\r\n"), "{out}");
        assert!(out.contains("Set-Cookie: t=x;secure;SameSite=Lax\r\n"), "{out}");
        assert!(out.contains("Set-Cookie: httponlyish=1; Path=/httponly\r\n"), "{out}");
    }

    #[test]
    fn html_presets_leave_what_isnt_html_alone() {
        let body = br#"{"form": "<input type=hidden disabled maxlength=1><script>x</script><form><embed src=x>"}"#;
        for p in PRESETS.iter().filter(|p| !p.name.starts_with("remove-cookie")) {
            for content_type in ["application/json", "text/javascript", "image/svg+xml", "text/htmlx", "", "none"] {
                let response = through(p.name, content_type, "", body);
                assert!(response.ends_with(body), "{} changed {content_type}", p.name);
                assert!(!String::from_utf8_lossy(&response).contains("Content-Security-Policy"), "{}", p.name);
            }
            // XHTML is HTML, whatever the case or parameters.
            let response = through(p.name, "Application/XHTML+XML;charset=utf-8", "", body);
            assert!(!response.ends_with(body), "{} left XHTML alone", p.name);
        }
    }

    #[test]
    fn a_body_that_isnt_utf8_is_matched_byte_by_byte() {
        let mut body = b"<p>\xff\xfe</p><input type=hidden name=a><script>\xc3\x28</script>".to_vec();
        body.extend_from_slice(b"\x00\x01<input disabled>");
        for (name, gone) in
            [("unhide-fields", &b"type=hidden"[..]), ("remove-scripts", b"<script>"), ("enable-fields", b"disabled")]
        {
            let out = through(name, "text/html", "", &body);
            assert!(!out.windows(gone.len()).any(|w| w == gone), "{name}: {}", String::from_utf8_lossy(&out));
            assert!(out.windows(4).any(|w| w == b"\xff\xfe</"), "{name} kept the other bytes");
        }
    }

    /// Bodies built to make a pattern work hardest: tags that never close, attributes that never
    /// end, a start tag repeated with no end tag. Each preset must still get through a large one
    /// quickly (the regex engine doesn't backtrack; this checks no pattern defeats it).
    #[test]
    fn large_hostile_bodies_go_through_every_preset_quickly() {
        let size = 4 << 20;
        let unit: &[&[u8]] = &[
            b"<input a=1 b='2' c=\"3\" ",
            b"<script <object <form <embed x ",
            b"<input type=\"hidden",
            b"<textarea disabled readonly maxlength",
            b"\xff\x00<\xfe",
        ];
        for u in unit {
            let body: Vec<u8> = u.iter().copied().cycle().take(size).collect();
            for p in PRESETS.iter().filter(|p| !p.name.starts_with("remove-cookie")) {
                let started = Instant::now();
                through(p.name, "text/html", "", &body);
                let took = started.elapsed();
                assert!(
                    took < Duration::from_secs(20),
                    "{} took {took:?} on 4 MiB of {:?}",
                    p.name,
                    String::from_utf8_lossy(u)
                );
            }
        }
    }

    #[test]
    fn same_rule_ignores_id_comment_origin_and_state() {
        let a = &preset("remove-scripts").unwrap().rules(None)[1];
        let b = Rule {
            id: 9,
            enabled: false,
            comment: None,
            origin: Some("gui".into()),
            host: Some(String::new()),
            ..a.clone()
        };
        assert!(same_rule(a, &b));
        assert!(!same_rule(a, &Rule { host: Some("x".into()), ..b.clone() }));
        assert!(!same_rule(a, &Rule { content_type: None, ..b.clone() }));
        assert!(!same_rule(a, &Rule { applies_to: vec![Engine::Send], ..b.clone() }));
        // No action is the default action, set.
        let c = &preset("remove-cookie-secure").unwrap().rules(None)[0];
        assert!(same_rule(c, &Rule { action: Some(RuleAction::Set), ..c.clone() }));
    }
}
