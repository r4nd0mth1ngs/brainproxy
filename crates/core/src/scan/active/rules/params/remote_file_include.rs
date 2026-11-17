//! Ported from ZAP RemoteFileIncludeScanRule (ascanrules, Apache License 2.0).
//!
//! ZAP's payloads make the *target* fetch www.google.com and look for Google's title in the
//! answer. The scope guard only covers brainproxy's own connections, so that used the target
//! to call a third party the engagement never named (a scan of one host made it fetch Google).
//! Here the URL is the OOB listener's (`brainproxy oob start`), and the target fetching it
//! raises the alert; without a listener the rule sends nothing, like the other out-of-band
//! checks. What it gives up: the listener answers with an empty body, so the alert says the
//! parameter's URL was fetched, not that what came back was included in the page (which is
//! also what SSRF, 40046, reports for the same fetch).

use std::sync::LazyLock;

use super::common::NULL_BYTE;
use crate::oob::Payload;
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

/// The value to send: `prefix` before the listener URL without its scheme. None for an https
/// prefix in host mode, where the token is in the path, which a TLS handshake never shows.
fn attack(prefix: &str, payload: &Payload) -> Option<String> {
    let https = prefix.to_ascii_lowercase().contains("https");
    if https && !payload.dns {
        return None;
    }
    let rest = payload.url.split_once("://").map_or(payload.url.as_str(), |(_, rest)| rest);
    Some(format!("{prefix}{rest}"))
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
            for prefix in &PREFIXES[..prefix_count(cx.strength())] {
                if cx.stopped() {
                    return;
                }
                // A token per attack, so an interaction names the prefix that got through.
                let Some(payload) = cx.oob_payload() else { return };
                let Some(attack) = attack(prefix, &payload) else { continue };
                let request = cx.payload_request(&attack);
                let resp = cx.send(request.clone()).await.ok();
                let finding = ALERT.raise(cx.point().name.clone(), "").attack(attack);
                cx.oob_register(&payload, finding, &request, resp.as_ref());
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_name_only_the_listener() {
        assert_eq!(PREFIXES.len(), 14);
        assert_eq!(PREFIXES[7], "\0http://");
        assert_eq!(prefix_count(Strength::Medium), 2);
        let host =
            Payload { token: "bpx".into(), host: "10.0.0.1:80".into(), url: "http://10.0.0.1/bpx".into(), dns: false };
        let all: Vec<String> = PREFIXES.iter().filter_map(|p| attack(p, &host)).collect();
        assert_eq!(all[..3], ["http://10.0.0.1/bpx", "10.0.0.1/bpx", "HTTP://10.0.0.1/bpx"]);
        assert_eq!(all.len(), 8, "no https in host mode: {all:?}");
        let dns =
            Payload { token: "bpx".into(), host: "bpx.oob.test".into(), url: "http://bpx.oob.test/".into(), dns: true };
        assert_eq!(attack("HtTpS://", &dns).as_deref(), Some("HtTpS://bpx.oob.test/"));
        for p in PREFIXES.iter() {
            assert!(attack(p, &dns).is_some_and(|a| a.contains("bpx.oob.test") && !a.contains("google")));
        }
    }
}
