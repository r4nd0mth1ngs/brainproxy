//! Ported from ZAP RemoteFileIncludeScanRule (ascanrules, Apache License 2.0).
//!
//! The payloads make the *target* fetch www.google.com; brainproxy itself only
//! talks to the in-scope target.

use std::sync::LazyLock;

use regex::Regex;

use super::common::{self, NULL_BYTE};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "7",
    name: "Remote File Inclusion",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 98,
    wasc: 5,
    description: "Remote File Include (RFI) is an attack technique used to exploit \"dynamic file include\" mechanisms in web \
        applications. When web applications take user input (URL, parameter value, etc.) and pass them into file \
        include commands, the web application might be tricked into including remote files with malicious \
        code.\n\nAlmost all web application frameworks support file inclusion. File inclusion is mainly used for \
        packaging common code into separate files that are later referenced by main application modules. When a web \
        application references an include file, the code in this file may be executed implicitly or explicitly by \
        calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the \
        web application might be vulnerable to RFI.\nAn attacker can use RFI for:\n    * Running malicious code on the \
        server: any code in the included malicious files will be run by the server. If the file include is not executed \
        using some wrapper, code in include files is executed in the context of the server user. This could lead to a \
        complete system compromise.\n    * Running malicious code on clients: the attacker's malicious code can \
        manipulate the content of the response sent to the client. The attacker can embed malicious code in the \
        response that will be run by the client (for example, JavaScript to steal the client session cookies).\n\nPHP \
        is particularly vulnerable to RFI attacks due to the extensive use of \"file includes\" in PHP programming and \
        due to default server configurations that increase susceptibility to an RFI attack.",
    solution: "Phase: Architecture and Design\nWhen the set of acceptable objects, such as filenames or URLs, is limited or \
        known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, \
        and reject all other inputs.\nFor example, ID 1 could map to \"inbox.txt\" and ID 2 could map to \
        \"profile.txt\". Features such as the ESAPI AccessReferenceMap provide this capability.\n\nPhases: Architecture \
        and Design; Operation\nRun your code in a \"jail\" or similar sandbox environment that enforces strict \
        boundaries between the process and the operating system. This may effectively restrict which files can be \
        accessed in a particular directory or which commands can be executed by your software.\nOS-level examples \
        include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For \
        example, java.io.FilePermission in the Java SecurityManager allows you to specify restrictions on file \
        operations.\nThis may not be a feasible solution, and it only limits the impact to the operating system; the \
        rest of your application may still be subject to compromise.\nBe careful to avoid CWE-243 and other weaknesses \
        related to jails.\nFor PHP, the interpreter offers restrictions such as open basedir or safe mode which can \
        make it more difficult for an attacker to escape out of the application. Also consider Suhosin, a hardened PHP \
        extension, which includes various options that disable some of the more dangerous PHP features.\n\nPhase: \
        Implementation\nAssume all input is malicious. Use an \"accept known good\" input validation strategy, i.e., \
        use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not \
        strictly conform to specifications, or transform it into something that does. Do not rely exclusively on \
        looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful \
        for detecting potential attacks or determining which inputs are so malformed that they should be rejected \
        outright.\nWhen performing input validation, consider all potentially relevant properties, including length, \
        type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related \
        fields, and conformance to business rules. As an example of business rule logic, \"boat\" may be syntactically \
        valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as \
        \"red\" or \"blue.\"\nFor filenames, use stringent allow lists that limit the character set to be used. If \
        feasible, only allow a single \".\" character in the filename to avoid weaknesses such as CWE-23, and exclude \
        directory separators such as \"/\" to avoid CWE-36. Use an allow list of allowable file extensions, which will \
        help to avoid CWE-434.\n\nPhases: Architecture and Design; Operation\nStore library, include, and utility files \
        outside of the web document root, if possible. Otherwise, store them in a separate directory and use the web \
        server's access control capabilities to prevent attackers from directly requesting them. One common practice is \
        to define a fixed constant in each calling program, then check for the existence of the constant in the \
        library/include file; if the constant does not exist, then the file was directly requested, and it can exit \
        immediately.\nThis significantly reduces the chance of an attacker being able to bypass any protection \
        mechanisms that are in the base program but not in the include files. It will also reduce your attack \
        surface.\n\nPhases: Architecture and Design; Implementation\nUnderstand all the potential areas where untrusted \
        inputs can enter your software: parameters or arguments, cookies, anything read from the network, environment \
        variables, reverse DNS lookups, query results, request headers, URL components, e-mail, files, databases, and \
        any external systems that provide data to the application. Remember that such inputs may be obtained indirectly \
        through API calls.\nMany file inclusion problems occur because the programmer assumed that certain inputs could \
        not be modified, especially for cookies and URL components.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion",
        "https://cwe.mitre.org/data/definitions/98.html",
    ],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-11"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

static PREFIXES: LazyLock<Vec<String>> = LazyLock::new(|| {
    let plain = ["http://", "", "HTTP://", "https://", "HTTPS://", "HtTp://", "HtTpS://"];
    // Null byte variants, in case the validator stops at the null byte.
    plain.iter().map(|p| p.to_string()).chain(plain.iter().map(|p| format!("{NULL_BYTE}{p}"))).collect()
});

const TARGETS: [&str; 5] = [
    "www.google.com/",
    "www.google.com:80/",
    "www.google.com",
    "www.google.com/search?q=ZAP",
    "www.google.com:80/search?q=ZAP",
];

// Java `.` does not match line terminators; neither does Rust's (except \r, which is rare here).
static PATTERNS: LazyLock<[Regex; 2]> = LazyLock::new(|| {
    [Regex::new(r"<title>Google</title>").unwrap(), Regex::new(r"<title.*?ZAP[ -]*?Google.*?/title>").unwrap()]
});

fn pattern(target_index: usize) -> &'static Regex {
    &PATTERNS[if target_index < 3 { 0 } else { 1 }]
}

fn prefix_count(strength: Strength) -> usize {
    match strength {
        Strength::Low => 1,
        Strength::Medium => 2,
        Strength::High => 4,
        Strength::Insane => PREFIXES.len(),
    }
}

pub struct RemoteFileInclude;

impl ActiveRule for RemoteFileInclude {
    fn id(&self) -> u32 {
        7
    }

    fn name(&self) -> &'static str {
        "Remote File Inclusion"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let base = cx.base_response();
            let original = format!("{}{}", base.head_text(), base.body_str());
            for prefix in &PREFIXES[..prefix_count(cx.strength())] {
                for (i, target) in TARGETS.iter().enumerate() {
                    if cx.stopped() {
                        return;
                    }
                    let attack = format!("{prefix}{target}");
                    let Ok(resp) = common::send_no_follow(cx, &attack).await else { continue };
                    let response = format!("{}{}", resp.head_text(), resp.body_str());
                    let Some(m) = pattern(i).find(&response) else { continue };
                    if resp.status != 200 {
                        continue;
                    }
                    // Not the same as in the original response.
                    if pattern(i).find(&original).is_some_and(|o| o.as_str() == m.as_str()) {
                        continue;
                    }
                    let f = ALERT.raise(cx.point().name.clone(), m.as_str()).attack(attack);
                    cx.report(f, &resp);
                    return;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_and_patterns() {
        assert_eq!(PREFIXES.len(), 14);
        assert_eq!(PREFIXES[7], "\0http://");
        assert_eq!(prefix_count(Strength::Medium), 2);
        assert!(pattern(0).is_match("<html><title>Google</title>"));
        assert!(pattern(3).is_match("<title>ZAP - Google Search</title>"));
        assert!(!pattern(3).is_match("<title>Google</title>"));
    }
}
