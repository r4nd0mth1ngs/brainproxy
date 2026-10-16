//! Ported from ZAP React2ShellScanRule (ascanrules, Apache License 2.0).

use std::sync::LazyLock;

use super::common::{base_path_query, with_body, with_request_line};
use crate::http::RawRequest;
use crate::scan::active::points::form_encode;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40048",
    name: "Remote Code Execution (React2Shell)",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 78,
    wasc: 32,
    description: "The server is running Next.js and vulnerable versions of React Server Components with Next.js which \
        allow remote attackers to execute arbitrary code.",
    solution: "Upgrade to the latest versions of the React libraries you are using. ",
    references: &[
        "https://react2shell.com/",
        "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
        "https://www.slcyber.io/research/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478",
    ],
    tags: &["OWASP_2025_A03", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "CVE-2025-55182", "CVE-2025-66478"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const EVIDENCE: &str = "E{\"digest\"";
const STATE_TREE: &str = "[\"\",{\"children\":[\"__PAGE__\",{},null,null]},null,null,true]";
const ATTACK: &str = "[\"$1:a:a\"]";
const OTHER_INFO: &str = "The attack verifies that the server is running vulnerable React Server Components, and \
    that the remote code execution (RCE) vulnerability is present without causing any damage.\nIt forces an error via \
    a malformed multipart request and checks for the presence of a string which confirms RCE is possible.";

/// "----" plus a random UUID-shaped string, fixed for the process (as in ZAP).
static BOUNDARY: LazyLock<String> = LazyLock::new(|| {
    let (a, b) = (rand_u64(), rand_u64());
    format!(
        "----{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        a >> 32,
        (a >> 16) & 0xffff,
        a & 0xfff,
        (b >> 48) & 0x3fff | 0x8000,
        b & 0xffff_ffff_ffff
    )
});

fn payload(boundary: &str) -> String {
    format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n{{}}\r\n--{boundary}\r\n\
         Content-Disposition: form-data; name=\"0\"\r\n\r\n{ATTACK}\r\n--{boundary}--\r\n"
    )
}

fn is_vulnerable(status: u16, body: &str) -> bool {
    status == 500 && body.contains(EVIDENCE)
}

pub struct React2Shell;

impl ActiveRule for React2Shell {
    fn id(&self) -> u32 {
        40048
    }

    fn name(&self) -> &'static str {
        "Remote Code Execution (React2Shell)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Host
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.stopped() {
                return;
            }
            let raw = with_request_line(cx.base_request(), "POST", &base_path_query(cx));
            let raw = RawRequest::from_bytes(raw)
                .set_header("Next-Action", "x")
                .set_header("Next-Router-State-Tree", &form_encode(STATE_TREE))
                .set_header("Content-Type", &format!("multipart/form-data; boundary={}", *BOUNDARY))
                .into_bytes();
            let Ok(resp) = cx.send(with_body(raw, payload(&BOUNDARY).as_bytes())).await else { return };
            if is_vulnerable(resp.status, resp.body_str()) {
                cx.report(ALERT.raise("", EVIDENCE).attack(ATTACK).other_info(OTHER_INFO), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_payload() {
        let p = payload("----b");
        assert!(p.starts_with("------b\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n{}\r\n"));
        assert!(p.ends_with("name=\"0\"\r\n\r\n[\"$1:a:a\"]\r\n------b--\r\n"));
        assert!(BOUNDARY.starts_with("----") && BOUNDARY.len() == 40);
        assert_eq!(
            form_encode(STATE_TREE),
            "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
        );
    }

    #[test]
    fn detection() {
        assert!(is_vulnerable(500, "0:{\"a\":\"$@1\"}\n1:E{\"digest\":\"2971658870\"}"));
        assert!(!is_vulnerable(200, "1:E{\"digest\":\"1\"}"));
        assert!(!is_vulnerable(500, "Internal Server Error"));
    }
}
