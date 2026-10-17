//! Ported from ZAP PersistentXssPrimeScanRule, PersistentXssSpiderScanRule and PersistentXssScanRule
//! (ascanrules, Apache License 2.0).
//!
//! Three rules in three engine phases, like ZAP's dependency chain: Prime (40016) stores a
//! unique marker through every parameter, Spider (40017) re-requests every page and records
//! where markers show up (`source_sink`), and the attack (40014) stores XSS payloads through
//! each parameter that has such a sink and looks for them on the sink pages. Behaviour is
//! ZAP's at the MEDIUM alert threshold: attacks are looked for anywhere on the sink page, and
//! PUT requests are skipped. The attack stops after its first alert.

use std::sync::Arc;

use super::common::{self, HtmlContext, HtmlContextAnalyser, EYE_CATCHER};
use super::cross_site_scripting::{XSS_DESCRIPTION, XSS_REFERENCES, XSS_SOLUTION};
use crate::scan::active::source_sink::Sink;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, PointKind, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Finding, Risk};

const TAGS: &[&str] = &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A07", "WSTG-v42-INPV-02", "HIPAA", "PCI_DSS"];
const NOT_HTML: &str = "Raised with LOW confidence as the Content-Type is not HTML.";

static ALERT: AlertDef = AlertDef {
    alert_ref: "40014-1",
    name: "Cross Site Scripting (Persistent)",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 79,
    wasc: 8,
    description: XSS_DESCRIPTION,
    solution: XSS_SOLUTION,
    references: XSS_REFERENCES,
    tags: TAGS,
};

static JSON: AlertDef = AlertDef {
    alert_ref: "40014-2",
    name: "Cross Site Scripting Weakness (Persistent in JSON Response)",
    risk: Risk::Low,
    confidence: Confidence::Low,
    cwe: 79,
    wasc: 8,
    description:
        "A XSS attack was found in a JSON response, this might leave content consumers vulnerable to attack if \
        they don't appropriately handle the data (response).",
    solution: XSS_SOLUTION,
    references: XSS_REFERENCES,
    tags: TAGS,
};

static NOT_HTML_ALERT: AlertDef = AlertDef {
    alert_ref: "40014-3",
    name: "Cross Site Scripting (Persistent)",
    risk: Risk::High,
    confidence: Confidence::Low,
    cwe: 79,
    wasc: 8,
    description: XSS_DESCRIPTION,
    solution: XSS_SOLUTION,
    references: XSS_REFERENCES,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 3] = [&ALERT, &JSON, &NOT_HTML_ALERT];

const GENERIC_SCRIPT_ALERT: &str = "<script>alert(1);</script>";

/// Stores a unique marker through each parameter.
pub struct PersistentXssPrime;

impl ActiveRule for PersistentXssPrime {
    fn id(&self) -> u32 {
        40016
    }

    fn name(&self) -> &'static str {
        "Cross Site Scripting (Persistent) - Prime"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &[]
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let _ = common::send_no_follow(cx, &cx.source_value()).await;
        })
    }
}

/// Re-requests each page and records which stored markers it displays.
pub struct PersistentXssSpider;

impl ActiveRule for PersistentXssSpider {
    fn id(&self) -> u32 {
        40017
    }

    fn name(&self) -> &'static str {
        "Cross Site Scripting (Persistent) - Spider"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &[]
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn phase(&self) -> u8 {
        1
    }

    fn depends_on(&self) -> &'static [u32] {
        &[40016]
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if let Ok(resp) = cx.send(cx.base_request().to_vec()).await {
                cx.test_for_sink(&resp);
            }
        })
    }
}

pub struct PersistentXss;

impl ActiveRule for PersistentXss {
    fn id(&self) -> u32 {
        40014
    }

    fn name(&self) -> &'static str {
        "Cross Site Scripting (Persistent)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn phase(&self) -> u8 {
        2
    }

    fn depends_on(&self) -> &'static [u32] {
        &[40017]
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.base().method == "PUT" {
                return;
            }
            let sinks = cx.sinks();
            if sinks.is_empty() {
                return;
            }
            let other_info = format!("Source URL: {}", cx.base().url);
            Pxss { cx, other_info }.scan(sinks).await;
        })
    }
}

struct Pxss<'a> {
    cx: &'a Cx,
    other_info: String,
}

impl Pxss<'_> {
    fn report(&self, def: &'static AlertDef, attack: &str, evidence: &str, other_info: &str, resp: &Response) {
        let f: Finding = def.raise(self.cx.point().name.clone(), evidence).attack(attack).other_info(other_info);
        self.cx.report(f, resp);
    }

    /// The common alert: the attack as found, with the source URL as other info.
    fn raise(&self, ctx: &HtmlContext) {
        self.report(&ALERT, &ctx.target, "", &self.other_info, &ctx.resp);
    }

    /// The alert variant ZAP raises with the attack as evidence and no other info.
    fn raise_evidence(&self, ctx: &HtmlContext) {
        self.report(&ALERT, &ctx.target, &ctx.target, "", &ctx.resp);
    }

    /// performAttack: stores `attack` through the parameter, re-reads the sink page and
    /// finds the attack in it. `None` when the scan stopped.
    async fn perform(
        &self,
        sink: &Sink,
        attack: &str,
        find_decoded: bool,
        ignore_safe_parents: bool,
    ) -> Option<Vec<HtmlContext>> {
        if self.cx.stopped() {
            return None;
        }
        let _ = common::send_following(self.cx, attack).await;
        if self.cx.stopped() {
            return None;
        }
        let resp = self.cx.send_following_to(&sink.target, sink.request.clone()).await;
        if self.cx.stopped() {
            return None;
        }
        // A failed sink request leaves ZAP with an empty response: nothing found.
        let Ok(resp) = resp else { return Some(Vec::new()) };
        let needle = if find_decoded { common::url_decode(attack) } else { attack.to_string() };
        Some(HtmlContextAnalyser::new(Arc::new(resp)).contexts(&needle, None, 0, ignore_safe_parents))
    }

    async fn scan(&self, sinks: Vec<Sink>) {
        // Errors on the eye catcher or a sink request end the scan of this parameter (ZAP's
        // IOException handler).
        if common::send_following(self.cx, EYE_CATCHER).await.is_err() {
            return;
        }
        for sink in &sinks {
            if self.cx.stopped() {
                return;
            }
            let Ok(resp) = self.cx.send_following_to(&sink.target, sink.request.clone()).await else { return };
            let contexts = HtmlContextAnalyser::new(Arc::new(resp)).contexts(EYE_CATCHER, None, 0, false);
            for ctx in &contexts {
                if self.cx.stopped() {
                    return;
                }
                match self.attack_context(sink, ctx).await {
                    Outcome::Found => return,
                    Outcome::Stop => break,
                    Outcome::Next => {}
                }
            }
        }
    }

    async fn attack_context(&self, sink: &Sink, ctx: &HtmlContext) -> Outcome {
        let q = &ctx.surrounding_quote;
        if ctx.tag_attribute.is_some() {
            if ctx.in_script_attribute {
                let Some(c2) = self.perform(sink, ";alert(1)", false, false).await else { return Outcome::Stop };
                if let Some(c) = c2.iter().find(|c| c.tag_attribute.is_some() && c.in_script_attribute) {
                    self.raise(c);
                    return Outcome::Found;
                }
            } else if ctx.in_url_attribute {
                let Some(c2) = self.perform(sink, "javascript:alert(1);", false, false).await else {
                    return Outcome::Stop;
                };
                if let Some(c) = c2.iter().find(|c| c.in_url_attribute) {
                    self.raise_evidence(c);
                    return Outcome::Found;
                }
            }
            if ctx.in_tag_with_src {
                match self.perform(sink, &format!("{q} src=http://badsite.com"), false, false).await {
                    None => return Outcome::Stop,
                    Some(c2) if !c2.is_empty() => return self.found(&c2[0]),
                    _ => {}
                }
            }
            for attack in [format!("{q}>{GENERIC_SCRIPT_ALERT}"), format!("{q} onMouseOver={q}alert(1);")] {
                match self.perform(sink, &attack, false, false).await {
                    None => return Outcome::Stop,
                    Some(c2) if !c2.is_empty() => return self.found(&c2[0]),
                    _ => {}
                }
            }
            return Outcome::Next;
        }
        if ctx.html_comment {
            let attack = format!("-->{GENERIC_SCRIPT_ALERT}<!--");
            match self.perform(sink, &attack, false, false).await {
                None => return Outcome::Stop,
                Some(c2) if !c2.is_empty() => return self.found(&c2[0]),
                _ => {}
            }
            return match self.perform(sink, "--><b onMouseOver=alert(1);>test</b><!--", false, false).await {
                Some(c2) if !c2.is_empty() => self.found(&c2[0]),
                _ => Outcome::Next,
            };
        }
        match ctx.parent_tag() {
            Some(parent) if parent.eq_ignore_ascii_case("body") => {
                match self.perform(sink, GENERIC_SCRIPT_ALERT, false, false).await {
                    None => return Outcome::Stop,
                    Some(c2) if !c2.is_empty() => return self.found(&c2[0]),
                    _ => {}
                }
                if let Some(c2) = self.perform(sink, "<b onMouseOver=alert(1);>test</b>", false, false).await {
                    let in_body = |c: &HtmlContext| {
                        c.parent_tag()
                            .is_some_and(|p| ["body", "b", "script"].iter().any(|t| p.eq_ignore_ascii_case(t)))
                    };
                    if c2.iter().any(in_body) {
                        self.raise_evidence(&c2[0]);
                        return Outcome::Found;
                    }
                }
                if matches!(self.cx.point().kind, PointKind::Query | PointKind::Form) {
                    let encoded = common::url_encode(GENERIC_SCRIPT_ALERT);
                    if let Some(c3) = self.perform(sink, &encoded, true, false).await.filter(|c| !c.is_empty()) {
                        let attack = common::url_encode(&common::url_encode(&c3[0].target));
                        self.report(&ALERT, &attack, GENERIC_SCRIPT_ALERT, "", &c3[0].resp);
                        return Outcome::Found;
                    }
                    return Outcome::Stop;
                }
                Outcome::Next
            }
            Some(parent) => {
                let attack = format!("</{parent}>{GENERIC_SCRIPT_ALERT}<{parent}>");
                match self.perform(sink, &attack, false, false).await {
                    None => return Outcome::Stop,
                    Some(c2) if !c2.is_empty() => return self.found(&c2[0]),
                    _ => {}
                }
                if parent.eq_ignore_ascii_case("script") {
                    return match self.perform(sink, &format!("{q};alert(1);{q}"), false, false).await {
                        None => Outcome::Stop,
                        Some(c2) if !c2.is_empty() => self.found(&c2[0]),
                        _ => Outcome::Next,
                    };
                }
                match self.perform(sink, "<img src=x onerror=alert(1);>", false, true).await {
                    Some(c) if !c.is_empty() => {
                        self.raise_evidence(&c[0]);
                        Outcome::Found
                    }
                    _ => Outcome::Next,
                }
            }
            None => {
                if !ctx.resp.body_str().contains(&ctx.target) {
                    return Outcome::Next;
                }
                let Some(c2) = self.perform(sink, GENERIC_SCRIPT_ALERT, false, true).await else {
                    return Outcome::Stop;
                };
                let Some(c) = c2.iter().find(|c| c.parent_tag().is_some()) else { return Outcome::Next };
                if common::is_html(&c.resp) {
                    self.report(&ALERT, &c.target, &c.target, "", &c2[0].resp);
                } else if c.resp.content_type().contains("json") {
                    self.report(&JSON, GENERIC_SCRIPT_ALERT, "", NOT_HTML, &c2[0].resp);
                } else {
                    self.report(&NOT_HTML_ALERT, &c.target, &c.target, NOT_HTML, &c2[0].resp);
                }
                Outcome::Found
            }
        }
    }

    fn found(&self, ctx: &HtmlContext) -> Outcome {
        self.raise(ctx);
        Outcome::Found
    }
}

enum Outcome {
    /// An alert was raised: done with this parameter.
    Found,
    /// Stop looking at this sink's contexts (ZAP `break`).
    Stop,
    /// Try the next context.
    Next,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_chain() {
        assert_eq!(PersistentXss.depends_on(), [40017]);
        assert_eq!(PersistentXssSpider.depends_on(), [40016]);
        assert!(PersistentXssPrime.phase() < PersistentXssSpider.phase());
        assert!(PersistentXssSpider.phase() < PersistentXss.phase());
    }
}
