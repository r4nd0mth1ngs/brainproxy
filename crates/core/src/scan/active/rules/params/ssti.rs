//! Ported from ZAP SstiScanRule and the `ssti` package (TemplateFormat,
//! DjangoTemplateFormat, GoTemplateFormat, ReflectedSinkPoint) (ascanrules, Apache
//! License 2.0).
//!
//! Only the reflected sink is checked: ZAP's stored sinks come from the persistent
//! XSS spider's source/sink database, which brainproxy does not have.

use super::common::{self, ComparableResponse};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90035",
    name: "Server Side Template Injection",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 1336,
    wasc: 20,
    description: "When the user input is inserted in the template instead of being used as argument in rendering is evaluated by \
        the template engine. Depending on the template engine it can lead to remote code execution.",
    solution: "Instead of inserting the user input in the template, use it as rendering argument.",
    references: &[
        "https://portswigger.net/research/server-side-template-injection",
    ],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-18"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER_INFO: &str = "Proof found at [{0}]\ncontent:\n[{1}]";

pub(crate) const DELIMITER: &str = "zj";
const SIMILARITY_THRESHOLD: f32 = 0.75;
const ERROR_POLYGLOTS: [&str; 2] = ["<%={{={@{#{${zj}}%>", "<th:t=\"${zj}#foreach"];
const WAYS_TO_FIX_CODE_SYNTAX: [&str; 4] = ["\"", "'", "1", ""];
const MIN: u32 = 1111;
const MAX: u32 = 9900;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Engine {
    Generic,
    Django,
    Go,
}

/// TemplateFormat: how to make an engine evaluate arithmetic, and what to expect.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TemplateFormat {
    end_tag: &'static str,
    /// The operation, with `%d` for the two numbers.
    format: &'static str,
    engine: Engine,
}

const fn generic(end_tag: &'static str, format: &'static str) -> TemplateFormat {
    TemplateFormat { end_tag, format, engine: Engine::Generic }
}

pub(crate) const TEMPLATE_FORMATS: [TemplateFormat; 14] = [
    generic(" ", " %d*%d "),
    generic("}", "{%d*%d}"),
    generic("}", "${%d*%d}"),
    generic("}", "#{%d*%d}"),
    generic("}", "{#%d*%d}"),
    generic("}", "{@%d*%d}"),
    generic("}}", "{{%d*%d}}"),
    generic("}}", "{{=%d*%d}}"),
    generic("%>", "<%=%d*%d%>"),
    generic(")${x}", "#set($x=%d*%d)${x}"),
    generic("}\"></p>", "<p th:text=\"${%d*%d}\"></p>"),
    // Dustjs
    generic("}", "{@math key=\"%d\" method=\"multiply\" operand=\"%d\"/}"),
    TemplateFormat { end_tag: "}}", format: "{{%d0|add:%d0}}", engine: Engine::Django },
    TemplateFormat { end_tag: "}", format: "{{print \"%d\" \"%d\"}}", engine: Engine::Go },
];

/// `NumberFormat.getNumberInstance(locale).format(n)` for US (`,`) and Germany (`.`).
fn group_thousands(n: u64, sep: char) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(sep);
        }
        out.push(c);
    }
    out
}

impl TemplateFormat {
    /// getRenderTestAndResult for given numbers: [exploit, result, US-formatted, DE-formatted].
    pub(crate) fn render_test_and_result(&self, n1: u32, n2: u32) -> Vec<String> {
        let exploit = self.format.replacen("%d", &n1.to_string(), 1).replacen("%d", &n2.to_string(), 1);
        let result: u64 = match self.engine {
            Engine::Generic => n1 as u64 * n2 as u64,
            Engine::Django => n1 as u64 * 10 + n2 as u64 * 10,
            Engine::Go => format!("{n1}{n2}").parse().unwrap_or(0),
        };
        vec![exploit, result.to_string(), group_thousands(result, ','), group_thousands(result, '.')]
    }

    /// engineSpecificCheck (the Go check: the payload itself was not just reflected).
    fn engine_specific_check(&self, output: &str, render_test: &str) -> bool {
        match self.engine {
            Engine::Go => {
                let stripped: String = render_test.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
                !output.contains(&stripped)
            }
            _ => true,
        }
    }
}

/// `output.matches("[\\w\\W]*zj.*RESULT.*zj[\\w\\W]*")`: on one line (Java's `.` stops
/// at line terminators), the result between two delimiters.
pub(crate) fn delimited_result(output: &str, result: &str) -> bool {
    if result.is_empty() {
        return false;
    }
    output.split(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}']).any(|line| {
        line.match_indices(result)
            .any(|(p, _)| line[..p].contains(DELIMITER) && line[p + result.len()..].contains(DELIMITER))
    })
}

/// ReflectedSinkPoint.getCurrentStateInString: body then headers.
fn sink_state(resp: &Response) -> String {
    format!("{}{}", resp.body_str(), common::headers_as_string(resp))
}

fn random_number() -> u32 {
    MIN + (crate::scan::active::rand_u64() % (MAX - MIN + 1) as u64) as u32
}

pub struct Ssti;

impl ActiveRule for Ssti {
    fn id(&self) -> u32 {
        90035
    }

    fn name(&self) -> &'static str {
        "Server Side Template Injection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            match cx.strength() {
                Strength::Low => efficient_scan(cx).await,
                Strength::Medium | Strength::High => search_for_maths_execution(cx, false).await,
                Strength::Insane => search_for_maths_execution(cx, true).await,
            }
        })
    }
}

/// LOW strength: look for suspect behaviour with polyglots first (few requests).
async fn efficient_scan(cx: &Cx) {
    let value = cx.point().value.clone();
    let alphabet: Vec<char> = if value.is_empty() {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect()
    } else {
        value.chars().collect()
    };
    let reference: String = (0..ERROR_POLYGLOTS[0].chars().count())
        .map(|_| alphabet[(crate::scan::active::rand_u64() % alphabet.len() as u64) as usize])
        .collect();
    let Ok(ref_resp) = common::send_no_follow(cx, &reference).await else { return };
    let original = ComparableResponse::new(cx.base_response(), &value);
    let similarity_of_reference = original.compare_with(&ComparableResponse::new(&ref_resp, &reference));
    if cx.stopped() {
        return;
    }
    let mut suspect = false;
    for polyglot in ERROR_POLYGLOTS {
        let Ok(resp) = common::send_no_follow(cx, polyglot).await else { continue };
        let similarity = original.compare_with(&ComparableResponse::new(&resp, polyglot));
        if similarity / similarity_of_reference < SIMILARITY_THRESHOLD {
            suspect = true;
        }
    }
    if suspect {
        search_for_maths_execution(cx, false).await;
    }
}

/// See if arithmetic results show up between our delimiters.
async fn search_for_maths_execution(cx: &Cx, fix_syntax: bool) {
    let code_fix_prefixes: &[&str] = if fix_syntax { &WAYS_TO_FIX_CODE_SYNTAX } else { &[""] };
    for format in &TEMPLATE_FORMATS {
        let template_fixing_prefix = if fix_syntax { format.end_tag } else { "" };
        for code_fix_prefix in code_fix_prefixes {
            if cx.stopped() {
                return;
            }
            let values = format.render_test_and_result(random_number(), random_number());
            let render_test = format!("{code_fix_prefix}{template_fixing_prefix}{DELIMITER}{}{DELIMITER}", values[0]);
            let Ok(resp) = common::send_no_follow(cx, &render_test).await else { continue };
            let output = sink_state(&resp);
            for result in &values[1..] {
                if output.contains(result.as_str())
                    && delimited_result(&output, result)
                    && format.engine_specific_check(&output, &render_test)
                {
                    let other = OTHER_INFO.replace("{0}", &cx.base().url).replace("{1}", &output);
                    let f = ALERT.raise(cx.point().name.clone(), "").attack(render_test).other_info(other);
                    cx.report(f, &resp);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_tests() {
        let r = TEMPLATE_FORMATS[6].render_test_and_result(2614, 1450);
        assert_eq!(r, ["{{2614*1450}}", "3790300", "3,790,300", "3.790.300"]);
        let r = TEMPLATE_FORMATS[9].render_test_and_result(1111, 9900);
        assert_eq!(r[0], "#set($x=1111*9900)${x}");
        let r = TEMPLATE_FORMATS[12].render_test_and_result(1234, 5678);
        assert_eq!(r[0..2], ["{{12340|add:56780}}", "69120"]);
        let r = TEMPLATE_FORMATS[13].render_test_and_result(1234, 5678);
        assert_eq!(r[0..2], ["{{print \"1234\" \"5678\"}}", "12345678"]);
        assert_eq!(
            TEMPLATE_FORMATS[11].render_test_and_result(2, 3)[0],
            "{@math key=\"2\" method=\"multiply\" operand=\"3\"/}"
        );
        assert_eq!(group_thousands(356435234, '.'), "356.435.234");
        assert_eq!(group_thousands(999, ','), "999");
    }

    #[test]
    fn detection() {
        assert!(delimited_result("<h2>Hello zj3790300zj</h2>", "3790300"));
        assert!(delimited_result("a\nzj <b>3790300</b> zj\n", "3790300"));
        assert!(!delimited_result("zj\n3790300\nzj", "3790300"));
        assert!(!delimited_result("3790300 zjzj", "3790300"));
        // The Go check rejects a plain reflection of the payload.
        let go = TEMPLATE_FORMATS[13];
        let test = "zj{{print \"1234\" \"5678\"}}zj";
        assert!(!go.engine_specific_check("zjprint12345678zj", test));
        assert!(go.engine_specific_check("zj12345678zj", test));
    }
}
