//! Ported from ZAP CrossSiteScriptingScanRule (ascanrules, Apache License 2.0).
//!
//! Behaviour is ZAP's at the MEDIUM alert threshold: every attack must be found
//! again in the same HTML context as the eye catcher, and reflections in non-HTML
//! responses are not reported (the LOW-threshold "Cross Site Scripting Weakness
//! (Reflected in JSON Response)" alert is therefore never raised).

use std::sync::{Arc, LazyLock};

use super::common::{
    self, HtmlContext, HtmlContextAnalyser, EYE_CATCHER, IGNORE_HTML_COMMENT, IGNORE_IN_SCRIPT, IGNORE_IN_URL,
    IGNORE_PARENT, IGNORE_TAG, IGNORE_WITH_SRC, NULL_BYTE,
};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, PointKind, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40012",
    name: "Cross Site Scripting (Reflected)",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 79,
    wasc: 8,
    description: "Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's \
        browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a \
        software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is \
        usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other \
        browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will \
        run within the security context (or zone) of the hosting web site. With this level of privilege, the code has \
        the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted \
        user could have his/her account hijacked (cookie theft), their browser redirected to another location, or \
        possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks \
        essentially compromise the trust relationship between a user and the web site. Applications utilizing browser \
        object instances which load content from the file system may execute code under the local machine zone allowing \
        for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and \
        DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted \
        link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the \
        vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable \
        resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the \
        victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious \
        form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another \
        technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe \
        Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a \
        period of time. Examples of an attacker's favorite targets often include message board posts, web mail \
        messages, and web chat software. The unsuspecting user is not required to interact with any additional \
        site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing \
        the code.",
    solution: "Phase: Architecture and Design\nUse a vetted library or framework that does not allow this weakness to occur or \
        provides constructs that make this weakness easier to avoid.\nExamples of libraries and frameworks that make it \
        easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding \
        module, and Apache Wicket.\n\nPhases: Implementation; Architecture and Design\nUnderstand the context in which \
        your data will be used and the encoding that will be expected. This is especially important when transmitting \
        data between different components, or when generating outputs that can contain multiple encodings at the same \
        time, such as web pages or multi-part mail messages. Study all expected communication protocols and data \
        representations to determine the required encoding strategies.\nFor any data that will be output to another web \
        page, especially any data that was received from external inputs, use the appropriate encoding on all \
        non-alphanumeric characters.\nConsult the XSS Prevention Cheat Sheet for more details on the types of encoding \
        and escaping that are needed.\n\nPhase: Architecture and Design\nFor any security checks that are performed on \
        the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. \
        Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by \
        changing the client to remove the client-side checks entirely. Then, these modified values would be submitted \
        to the server.\n\nIf available, use structured mechanisms that automatically enforce the separation between \
        data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation \
        automatically, instead of relying on the developer to provide this capability at every point where output is \
        generated.\n\nPhase: Implementation\nFor every web page that is generated, use and specify a character encoding \
        such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding \
        by guessing which encoding is actually being used by the web page. This can cause the web browser to treat \
        certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations \
        related to encoding/escaping.\n\nTo help mitigate XSS attacks against the user's session cookie, set the \
        session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of \
        Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to \
        malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not \
        supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide \
        read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.\n\nAssume all \
        input is malicious. Use an \"accept known good\" input validation strategy, i.e., use an allow list of \
        acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to \
        specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or \
        malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential \
        attacks or determining which inputs are so malformed that they should be rejected outright.\n\nWhen performing \
        input validation, consider all potentially relevant properties, including length, type of input, the full range \
        of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to \
        business rules. As an example of business rule logic, \"boat\" may be syntactically valid because it only \
        contains alphanumeric characters, but it is not valid if you are expecting colors such as \"red\" or \
        \"blue.\"\n\nEnsure that you perform input validation at well-defined interfaces within the application. This \
        will help protect the application even if a component is reused or moved elsewhere.",
    references: &[
        "https://owasp.org/www-community/attacks/xss/",
        "https://cwe.mitre.org/data/definitions/79.html",
    ],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A07", "WSTG-v42-INPV-01"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHERINFO_ACCESSKEY: &str =
    "The accesskey attribute specifies a shortcut key to activate/focus an element. This attribute can trigger \
        payloads for non-conventional or custom tags.";

pub(crate) const GENERIC_SCRIPT_ALERT: &str = "<scrIpt>alert(1);</scRipt>";
const GENERIC_ONERROR_ALERT: &str = "<img src=x onerror=prompt()>";
const IMG_ONERROR_LOG: &str = "<img src=x onerror=console.log(1);>";
const SVG_ONLOAD_ALERT: &str = "<svg onload=alert(1)>";
const B_MOUSE_ALERT: &str = "<b onMouseOver=alert(1);>test</b>";
const ACCESSKEY_ATTRIBUTE_ALERT: &str = "accesskey='x' onclick='alert(1)' b";
const TAG_ONCLICK_ALERT: &str = "button onclick='alert(1)'/";
/// Null byte + script: validators written in C may stop reading at the null byte.
const GENERIC_NULL_BYTE_SCRIPT_ALERT: &str = "\0<scrIpt>alert(1);</scRipt>";
const GENERIC_SCRIPT_ALERT_LIST: [&str; 3] =
    [GENERIC_SCRIPT_ALERT, GENERIC_NULL_BYTE_SCRIPT_ALERT, GENERIC_ONERROR_ALERT];
const HEADER_SPLITTING: &str = "\n\r\n\r";

static OUTSIDE_OF_TAGS_PAYLOADS: LazyLock<[String; 7]> = LazyLock::new(|| {
    [
        GENERIC_SCRIPT_ALERT.to_string(),
        GENERIC_NULL_BYTE_SCRIPT_ALERT.to_string(),
        GENERIC_ONERROR_ALERT.to_string(),
        IMG_ONERROR_LOG.to_string(),
        B_MOUSE_ALERT.to_string(),
        SVG_ONLOAD_ALERT.to_string(),
        common::url_encode(GENERIC_SCRIPT_ALERT),
    ]
});

/// (original, replacement, check original): characters that may be filtered and what
/// to try instead; with "check original" the evidence keeps the original character
/// (the server is expected to convert it back).
type Mutation = (char, char, bool);
const MUTATIONS: [&[Mutation]; 3] = [
    &[('(', '`', false), (')', '`', false)],
    &[('<', '＜', true), ('>', '＞', true)],
    &[('(', '`', false), (')', '`', false), ('<', '＜', true), ('>', '＞', true)],
];

pub struct CrossSiteScripting;

impl ActiveRule for CrossSiteScripting {
    fn id(&self) -> u32 {
        40012
    }

    fn name(&self) -> &'static str {
        "Cross Site Scripting (Reflected)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move { Xss { cx }.scan().await })
    }
}

#[derive(Clone, Copy, Default)]
struct Opts {
    ignore: u32,
    find_decoded: bool,
    null_byte: bool,
    ignore_safe_parents: bool,
}

impl Opts {
    fn ignore(ignore: u32) -> Self {
        Self { ignore, ..Default::default() }
    }
}

struct Xss<'a> {
    cx: &'a Cx,
}

impl Xss<'_> {
    fn param(&self) -> &str {
        &self.cx.point().name
    }

    fn raise(&self, ctx: &HtmlContext) {
        self.raise_with(ctx, &ctx.resp);
    }

    fn raise_with(&self, ctx: &HtmlContext, resp: &Response) {
        self.raise_info(ctx, resp, "");
    }

    fn raise_info(&self, ctx: &HtmlContext, resp: &Response, other_info: &str) {
        let f = ALERT
            .raise(self.param(), ctx.target.clone())
            .attack(ctx.target.clone())
            .other_info(other_info)
            .confidence(Confidence::Medium);
        self.cx.report(f, resp);
    }

    /// One attack: send, then find the evidence in the expected context.
    async fn attack_once(
        &self,
        attack: &str,
        target: Option<&HtmlContext>,
        evidence: Option<&str>,
        o: Opts,
    ) -> Option<(Vec<HtmlContext>, HtmlContextAnalyser, String)> {
        if self.cx.stopped() {
            return None;
        }
        let resp = common::send_following(self.cx, attack).await.ok()?;
        if self.cx.stopped() {
            return None;
        }
        let (attack, evidence) = if o.null_byte {
            // The parser would see no enclosing tag for a leading null byte.
            let a = attack.replacen(NULL_BYTE, "", 1);
            (a.clone(), a)
        } else {
            (attack.to_string(), evidence.unwrap_or(attack).to_string())
        };
        let hca = HtmlContextAnalyser::new(Arc::new(resp));
        let needle = if o.find_decoded { common::url_decode(&evidence) } else { evidence };
        let contexts = hca.contexts(&needle, target, o.ignore, o.ignore_safe_parents);
        Some((contexts, hca, attack))
    }

    /// performAttack: `None` when nothing could be sent (or the scan stopped). When the
    /// attack is not found, retries once with filtered characters mutated.
    async fn perform(
        &self,
        attack: &str,
        target: Option<&HtmlContext>,
        evidence: Option<&str>,
        o: Opts,
    ) -> Option<Vec<HtmlContext>> {
        let (contexts, hca, attack) = self.attack_once(attack, target, evidence, o).await?;
        if !contexts.is_empty() {
            return Some(contexts);
        }
        for m in MUTATIONS {
            if !attack.contains(m[0].0) {
                continue;
            }
            let filtered: String = attack.chars().filter(|c| !m.iter().any(|(orig, _, _)| orig == c)).collect();
            let needle = if o.find_decoded { common::url_decode(&filtered) } else { filtered };
            if hca.contexts(&needle, target, o.ignore, o.ignore_safe_parents).is_empty() {
                continue;
            }
            let mut mutated_attack = attack.clone();
            let mut mutated_evidence = attack.clone();
            for &(orig, mutation, check_original) in m {
                mutated_attack = mutated_attack.replace(orig, &mutation.to_string());
                if !check_original {
                    mutated_evidence = mutated_evidence.replace(orig, &mutation.to_string());
                }
            }
            return self.attack_once(&mutated_attack, target, Some(&mutated_evidence), o).await.map(|r| r.0);
        }
        Some(Vec::new())
    }

    async fn scan(&self) {
        let cx = self.cx;
        if cx.base().method.eq_ignore_ascii_case("PUT") {
            return;
        }
        let value = cx.point().value.clone();
        // Inject the 'safe' eye catcher and see where it appears.
        let Ok(resp) = common::send_following(cx, EYE_CATCHER).await else { return };
        if cx.stopped() {
            return;
        }
        let mut resp2 = Arc::new(resp);
        let mut hca = HtmlContextAnalyser::new(resp2.clone());
        let mut contexts = hca.contexts(EYE_CATCHER, None, 0, false);
        if contexts.is_empty() {
            contexts = hca.contexts(&EYE_CATCHER.to_lowercase(), None, 0, false);
        }
        if contexts.is_empty() {
            contexts = hca.contexts(&EYE_CATCHER.to_uppercase(), None, 0, false);
        }
        let mut appended = false;
        if contexts.is_empty() {
            // Try again, appending the eye catcher to the original value.
            let Ok(resp) = common::send_following(cx, &format!("{value}{EYE_CATCHER}")).await else { return };
            appended = true;
            resp2 = Arc::new(resp);
            hca = HtmlContextAnalyser::new(resp2.clone());
            contexts = hca.contexts(&format!("{value}{EYE_CATCHER}"), None, 0, false);
        }
        let mut worked = false;
        if contexts.is_empty() {
            worked = self.direct_attack().await;
        }
        for ctx in &contexts {
            if worked || cx.stopped() {
                break;
            }
            if ctx.tag_attribute.is_some() {
                // In a tag attribute: lots of attack vectors possible.
                worked = self.tag_attack(ctx).await;
            } else if ctx.in_attribute_name {
                worked = self.attribute_attack(ctx).await;
            } else if ctx.html_comment {
                worked = self.comment_attack(ctx).await;
            } else {
                match ctx.parent_tag() {
                    Some(p) if p.eq_ignore_ascii_case("body") => worked = self.body_attack(ctx).await,
                    Some(p) => {
                        worked = self.close_tag_attack(ctx).await;
                        if worked {
                            break;
                        } else if p.eq_ignore_ascii_case("script") {
                            worked = self.script_attack(ctx).await;
                        } else {
                            worked = self.image_tag_attack(ctx).await;
                        }
                    }
                    // Last chance: is the payload reflected outside of any tags?
                    None => worked = self.outside_tags_attack(ctx).await,
                }
            }
            if ctx.in_element_name {
                worked = self.element_attack(ctx).await;
            }
        }
        // Always attack the header if the eye catcher is reflected in it.
        if resp2.head_text().contains(EYE_CATCHER) {
            self.attack_header(if appended { &value } else { "" }).await;
        }
    }

    async fn direct_attack(&self) -> bool {
        for script_alert in GENERIC_SCRIPT_ALERT_LIST {
            if let Some(c) = self.perform(&format!("'\"{script_alert}"), None, None, Opts::default()).await {
                if !c.is_empty() && self.process_contexts(&c, false) {
                    return true;
                }
            }
            if self.cx.stopped() {
                break;
            }
        }
        false
    }

    async fn tag_attack(&self, ctx: &HtmlContext) -> bool {
        let q = ctx.surrounding_quote.as_str();
        if ctx.in_script_attribute {
            // Good chance this will be vulnerable: try a simple alert attack.
            let Some(c) = self.perform(";alert(1)", Some(ctx), None, Opts::default()).await else { return false };
            if let Some(c2) = c.iter().find(|c2| c2.tag_attribute.is_some() && c2.in_script_attribute) {
                self.raise(c2);
                return true;
            }
        } else if ctx.in_url_attribute {
            let Some(c) = self.perform("javascript:alert(1);", Some(ctx), None, Opts::default()).await else {
                return false;
            };
            if let Some(c2) = c.iter().find(|c2| c2.in_url_attribute && js_scheme_injection_valid(c2)) {
                self.raise(c2);
                return true;
            }
        }
        if ctx.in_tag_with_src {
            // In an attribute of a tag which supports src attributes.
            let o = Opts::ignore(IGNORE_TAG | IGNORE_IN_URL | IGNORE_WITH_SRC);
            let Some(c) = self.perform(&format!("{q} src=http://badsite.com"), Some(ctx), None, o).await else {
                return false;
            };
            if let Some(c2) = c.first() {
                self.raise(c2);
                return true;
            }
        }
        for script_alert in GENERIC_SCRIPT_ALERT_LIST {
            let attack = format!("{q}>{script_alert}");
            let Some(c) = self.perform(&attack, Some(ctx), None, Opts::ignore(IGNORE_TAG)).await else { return false };
            if let Some(c2) = c.first() {
                self.raise(c2);
                return true;
            }
            if self.cx.stopped() {
                return false;
            }
        }
        // Try adding an onMouseOver.
        let attack = format!("{q} onMouseOver={q}alert(1);");
        let Some(c) = self.perform(&attack, Some(ctx), None, Opts::ignore(IGNORE_TAG | IGNORE_IN_URL)).await else {
            return false;
        };
        if let Some(c2) = c.first() {
            self.raise(c2);
            return true;
        }
        false
    }

    async fn comment_attack(&self, ctx: &HtmlContext) -> bool {
        for script_alert in GENERIC_SCRIPT_ALERT_LIST {
            let attack = format!("-->{script_alert}<!--");
            let Some(c) = self.perform(&attack, Some(ctx), None, Opts::ignore(IGNORE_HTML_COMMENT)).await else {
                return false;
            };
            if let Some(c2) = c.first() {
                self.raise(c2);
                return true;
            }
            if self.cx.stopped() {
                return false;
            }
        }
        // Maybe they're blocking script tags.
        let attack = format!("-->{B_MOUSE_ALERT}<!--");
        let Some(c) = self.perform(&attack, Some(ctx), None, Opts::ignore(IGNORE_HTML_COMMENT)).await else {
            return false;
        };
        if let Some(c2) = c.first() {
            self.raise(c2);
            return true;
        }
        false
    }

    async fn body_attack(&self, ctx: &HtmlContext) -> bool {
        for script_alert in GENERIC_SCRIPT_ALERT_LIST {
            let Some(c) = self.perform(script_alert, None, None, Opts::ignore(IGNORE_PARENT)).await else { continue };
            if let Some(c2) = c.first() {
                self.raise(c2);
                return true;
            }
            if self.cx.stopped() {
                return false;
            }
        }
        // Maybe they're blocking script tags.
        if let Some(c) = self.perform(B_MOUSE_ALERT, Some(ctx), None, Opts::ignore(IGNORE_PARENT)).await {
            let hit = c.iter().any(|c2| {
                c2.parent_tag().is_some_and(|p| p.eq_ignore_ascii_case("body") || p.eq_ignore_ascii_case("b"))
            });
            if hit {
                self.raise(&c[0]);
                return true;
            }
        }
        if matches!(self.cx.point().kind, PointKind::Query | PointKind::Form) {
            // Try double encoded.
            let o = Opts { find_decoded: true, ..Default::default() };
            if let Some(c) = self.perform(&common::url_encode(GENERIC_SCRIPT_ALERT), None, None, o).await {
                if let Some(c3) = c.first() {
                    let attack = common::url_encode(&common::url_encode(&c3.target));
                    let f =
                        ALERT.raise(self.param(), GENERIC_SCRIPT_ALERT).attack(attack).confidence(Confidence::Medium);
                    self.cx.report(f, &c3.resp);
                    return true;
                }
            }
        }
        false
    }

    async fn close_tag_attack(&self, ctx: &HtmlContext) -> bool {
        let parent = ctx.parent_tag().unwrap_or("");
        for script_alert in GENERIC_SCRIPT_ALERT_LIST {
            let attack = format!("</{parent}>{script_alert}<{parent}>");
            let Some(c) = self.perform(&attack, Some(ctx), None, Opts::ignore(IGNORE_IN_SCRIPT)).await else {
                return false;
            };
            if let Some(c2) = c.iter().find(|c2| c2.surrounding_quote.is_empty()) {
                self.raise(c2);
                return true;
            }
            if self.cx.stopped() {
                return false;
            }
        }
        false
    }

    async fn script_attack(&self, ctx: &HtmlContext) -> bool {
        let q = ctx.surrounding_quote.as_str();
        let attack = format!("{q};alert(1);{q}");
        let Some(c) = self.perform(&attack, Some(ctx), None, Opts::default()).await else { return false };
        if let Some(c2) = c.iter().find(|c2| q.is_empty() || !c2.surrounding_quote.is_empty()) {
            self.raise(c2);
            return true;
        }
        false
    }

    /// processContexts at MEDIUM threshold: only HTML responses are reported, but any
    /// match ends the attack.
    fn process_contexts(&self, contexts: &[HtmlContext], requires_parent: bool) -> bool {
        for ctx in contexts {
            if ctx.parent_tag().is_some() || !requires_parent {
                if common::is_html(&ctx.resp) {
                    self.raise_with(ctx, &contexts[0].resp);
                }
                return true;
            }
        }
        false
    }

    async fn outside_tags_attack(&self, ctx: &HtmlContext) -> bool {
        for script_alert in OUTSIDE_OF_TAGS_PAYLOADS.iter() {
            if ctx.resp.body_str().contains(&ctx.target) {
                let o = Opts { null_byte: true, ignore_safe_parents: true, ..Default::default() };
                let Some(c) = self.perform(script_alert, None, None, o).await else { continue };
                if self.process_contexts(&c, true) {
                    return true;
                }
            }
            if self.cx.stopped() {
                return false;
            }
        }
        false
    }

    async fn image_tag_attack(&self, ctx: &HtmlContext) -> bool {
        let o = Opts { ignore: IGNORE_IN_SCRIPT, ignore_safe_parents: true, ..Default::default() };
        if let Some(c) = self.perform(GENERIC_ONERROR_ALERT, Some(ctx), None, o).await {
            if let Some(c2) = c.first() {
                self.raise(c2);
                return true;
            }
        }
        false
    }

    async fn attribute_attack(&self, ctx: &HtmlContext) -> bool {
        let Some(c) = self.perform(ACCESSKEY_ATTRIBUTE_ALERT, Some(ctx), None, Opts::default()).await else {
            return false;
        };
        if let Some(c2) =
            c.iter().find(|c2| c2.has_attribute("onclick", "alert(1)") && c2.has_attribute("accesskey", "x"))
        {
            self.raise_info(c2, &c2.resp, OTHERINFO_ACCESSKEY);
            return true;
        }
        false
    }

    async fn element_attack(&self, ctx: &HtmlContext) -> bool {
        let attack = format!("tag {ACCESSKEY_ATTRIBUTE_ALERT}");
        // In this case the parent effectively changes.
        let mut c = self.perform(&attack, Some(ctx), None, Opts::ignore(IGNORE_PARENT)).await;
        if c.as_ref().is_none_or(|c| c.is_empty()) {
            let Some(c2) = self.perform(TAG_ONCLICK_ALERT, None, None, Opts::default()).await else { return false };
            if let Some(hit) = c2.iter().find(|x| x.has_attribute("onclick", "alert(1)")) {
                self.raise(hit);
                return true;
            }
            c = Some(c2);
        }
        if let Some(hit) = c
            .unwrap_or_default()
            .iter()
            .find(|x| x.has_attribute("accesskey", "x") && x.has_attribute("onclick", "alert(1)"))
        {
            self.raise_info(hit, &hit.resp, OTHERINFO_ACCESSKEY);
            return true;
        }
        false
    }

    /// The eye catcher was reflected in the response head: try header splitting.
    async fn attack_header(&self, value: &str) {
        for script_alert in GENERIC_SCRIPT_ALERT_LIST {
            let attack = format!("{value}{HEADER_SPLITTING}{script_alert}");
            let o = Opts { ignore_safe_parents: true, ..Default::default() };
            if let Some(c) = self.perform(&attack, None, Some(script_alert), o).await {
                if let Some(c2) = c.first() {
                    let f = ALERT.raise(self.param(), c2.target.clone()).attack(attack).confidence(Confidence::Medium);
                    self.cx.report(f, &c2.resp);
                    return;
                }
            }
        }
    }
}

fn js_scheme_injection_valid(ctx: &HtmlContext) -> bool {
    ctx.tag_attribute_value.as_deref().is_some_and(|v| v.trim_start().starts_with(ctx.target.as_str()))
}

#[cfg(test)]
mod tests {
    use super::super::common::testing::html;
    use super::*;

    #[test]
    fn payload_lists() {
        assert_eq!(OUTSIDE_OF_TAGS_PAYLOADS[6], "%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E");
        assert_eq!(GENERIC_NULL_BYTE_SCRIPT_ALERT, format!("{NULL_BYTE}{GENERIC_SCRIPT_ALERT}"));
        // The mutation filters remove every mutated character.
        let filtered: String = "<scrIpt>alert(1);</scRipt>".chars().filter(|c| !"()<>".contains(*c)).collect();
        assert_eq!(filtered, "scrIptalert1;/scRipt");
    }

    #[test]
    fn javascript_scheme_must_start_the_value() {
        let resp = html(
            "<html><body><a href=' javascript:alert(1);'>x</a><a href='/x?javascript:alert(1);'>y</a></body></html>",
        );
        let c = HtmlContextAnalyser::new(resp).contexts("javascript:alert(1);", None, 0, false);
        assert_eq!(c.len(), 2);
        assert!(js_scheme_injection_valid(&c[0]));
        assert!(!js_scheme_injection_valid(&c[1]));
    }

    #[test]
    fn close_tag_attack_context_matches_eye_catcher_context() {
        let eye = HtmlContextAnalyser::new(html("<html><body><p>Hello 0W45pz4p</p></body></html>")).contexts(
            EYE_CATCHER,
            None,
            0,
            false,
        );
        assert_eq!(eye[0].parent_tag(), Some("p"));
        let attack = format!("</p>{GENERIC_SCRIPT_ALERT}<p>");
        let page = format!("<html><body><p>Hello {attack}</p></body></html>");
        let c = HtmlContextAnalyser::new(html(&page)).contexts(&attack, Some(&eye[0]), IGNORE_IN_SCRIPT, false);
        assert_eq!(c.len(), 1);
        assert!(c[0].surrounding_quote.is_empty());
        // Escaped output is not found.
        let safe = "<html><body><p>Hello &lt;/p&gt;&lt;scrIpt&gt;alert(1);&lt;/scRipt&gt;&lt;p&gt;</p></body></html>";
        assert!(HtmlContextAnalyser::new(html(safe))
            .contexts(&attack, Some(&eye[0]), IGNORE_IN_SCRIPT, false)
            .is_empty());
    }

    #[test]
    fn attribute_context_breakout() {
        let eye = HtmlContextAnalyser::new(html("<html><body><input name=q value=\"0W45pz4p\"></body></html>"))
            .contexts(EYE_CATCHER, None, 0, false);
        assert_eq!(eye[0].tag_attribute.as_deref(), Some("value"));
        assert_eq!(eye[0].surrounding_quote, "\"");
        let attack = format!("\">{GENERIC_SCRIPT_ALERT}");
        let page = format!("<html><body><input name=q value=\"{attack}\"></body></html>");
        let c = HtmlContextAnalyser::new(html(&page)).contexts(&attack, Some(&eye[0]), IGNORE_TAG, false);
        assert_eq!(c.len(), 1, "the quote closes the attribute and the context still matches");
    }
}
