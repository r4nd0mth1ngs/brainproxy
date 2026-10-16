//! Ported from ZAP SourceCodeDisclosureWebInfScanRule (ascanrules, Apache License
//! 2.0).
//!
//! Deviation: ZAP decompiles each retrieved `.class` file with Procyon, puts the
//! decompiled Java source in the alert's other-info, and mines that source for
//! further imported classes and referenced `.properties` files (the "-2"
//! Properties File Disclosure alert). brainproxy has no Java decompiler, so this
//! port detects the disclosure of a Java class file referenced from a WEB-INF
//! descriptor (it is served, with the class-file magic) and raises the "-1"
//! alert. Import-following and the "-2" properties alert are omitted.

use std::sync::LazyLock;

use regex::Regex;

use super::common::is_page_200;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static WEBINF_ALERT: AlertDef = AlertDef {
    alert_ref: "10045-1",
    name: "Source Code Disclosure - /WEB-INF Folder",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 541,
    wasc: 34,
    description: "Java source code was disclosed by the web server in Java class files in the WEB-INF folder. The \
        class files can be dis-assembled to produce source code which very closely matches the original source code.",
    solution: "The web server should be configured to not serve the /WEB-INF folder or its contents to web browsers, \
        since it contains sensitive information such as compiled Java source code and properties files which may \
        contain credentials. Java classes deployed with the application should be obfuscated, as an additional layer \
        of defence in a \"defence-in-depth\" approach.",
    references: &[
        "https://owasp.org/www-community/attacks/Forced_browsing",
        "https://cwe.mitre.org/data/definitions/425.html",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CONF-05"],
};

static ALERTS: [&AlertDef; 1] = [&WEBINF_ALERT];

const WEBINF_FILES: [&str; 2] = ["web.xml", "applicationContext.xml"];

/// Java class names (including package), as in ZAP.
static CLASSNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9a-zA-Z_.]+\.[a-zA-Z0-9_]+").unwrap());

/// Class names referenced by a descriptor body, excluding java./javax.
fn class_names(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in CLASSNAME.find_iter(body) {
        let name = m.as_str();
        if !name.starts_with("java.") && !name.starts_with("javax.") && !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// The WEB-INF path of a class file for a class name.
fn class_path(classname: &str) -> String {
    format!("/WEB-INF/classes/{}.class", classname.replace('.', "/"))
}

/// Whether a response body is a Java class file (0xCAFEBABE magic).
fn is_class_file(body: &[u8]) -> bool {
    body.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
}

pub struct SourceDisclosureWebInf;

impl ActiveRule for SourceDisclosureWebInf {
    fn id(&self) -> u32 {
        10045
    }

    fn name(&self) -> &'static str {
        "Source Code Disclosure - /WEB-INF Folder"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Host
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let mut classes: Vec<String> = Vec::new();
            for file in WEBINF_FILES {
                if cx.stopped() {
                    return;
                }
                let Ok(resp) = cx.send(cx.request_for("GET", &format!("/WEB-INF/{file}"))).await else { continue };
                for name in class_names(resp.body_str()) {
                    if !classes.contains(&name) {
                        classes.push(name);
                    }
                }
            }
            for classname in classes {
                if cx.stopped() {
                    return;
                }
                let Ok(resp) = cx.send(cx.request_for("GET", &class_path(&classname))).await else { continue };
                if is_page_200(cx, &resp).await && is_class_file(&resp.body) {
                    let info = format!("A Java class file was disclosed for class [{classname}].");
                    cx.report(WEBINF_ALERT.raise("", resp.status_line.clone()).other_info(info), &resp);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_from_descriptor() {
        let xml = "<servlet-class>com.example.App</servlet-class><x>java.lang.String</x><y>javax.servlet.Foo</y>";
        assert_eq!(class_names(xml), vec!["com.example.App"]);
        // Duplicates removed.
        let xml = "a.B a.B c.D";
        assert_eq!(class_names(xml), vec!["a.B", "c.D"]);
    }

    #[test]
    fn paths_and_magic() {
        assert_eq!(class_path("com.example.App"), "/WEB-INF/classes/com/example/App.class");
        assert!(is_class_file(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x34]));
        assert!(!is_class_file(b"<html>"));
    }
}
