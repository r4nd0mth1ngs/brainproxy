//! Ported from ZAP SOAPActionSpoofingActiveScanRule (soap, Apache License 2.0).
//!
//! On a recorded SOAP 1.1 request (a `SOAPAction` header and an envelope with a body), sends
//! the same envelope with an empty `SOAPAction` and with a made-up one. When the server
//! answers either as it answered the original (the same elements in the SOAP body, no fault),
//! it ignores the header and goes by the body alone: anything in front of it that allows or
//! routes operations by `SOAPAction` can be passed with one operation's action and another's
//! body.
//!
//! Differences from ZAP: ZAP spoofs the action to each other operation of an imported WSDL
//! and reports which one ran. brainproxy keeps no WSDL operations, so this port can't spoof to
//! another operation: it tests whether the header is checked at all, with an empty and a random
//! action, and only reports the case ZAP calls "SOAPAction ignored". The responses ZAP reports
//! at low risk (a fault, an empty or an unreadable answer) are the server checking the action,
//! and aren't reported. SOAP 1.2's action in the Content-Type isn't tested.

use crate::http::RawRequest;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90026",
    name: "SOAP Action Spoofing",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 451,
    wasc: 0,
    description: "An unintended SOAP operation was executed by the server.",
    solution: "If not required, the SOAPAction attribute should be disabled. If needed, the operation within the \
        SOAPAction and the SOAP body should always be compared before executing any operation. Any mismatch should be \
        regarded as an attack.",
    references: &["https://www.nds.ruhr-uni-bochum.de/media/nds/veroeffentlichungen/2012/07/11/camera-ready.pdf"],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct SoapActionSpoofing;

impl ActiveRule for SoapActionSpoofing {
    fn id(&self) -> u32 {
        90026
    }

    fn name(&self) -> &'static str {
        "SOAP Action Spoofing"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let Some(original) = cx.base().req_headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("soapaction"))
            else {
                return;
            };
            let original = original.1.trim().to_string();
            if body_elements(&String::from_utf8_lossy(&cx.base().req_body)).is_none() {
                return;
            }
            // The original's answer is what the operation it names returns.
            let Some(expected) = body_elements(cx.base_response().body_str()).filter(|e| !is_fault(e)) else {
                return;
            };
            let quoted = original.starts_with('"');
            let random = format!("urn:brainproxy:{:016x}", rand_u64());
            for spoofed in [String::new(), random] {
                if cx.stopped() {
                    return;
                }
                let value = if quoted { format!("\"{spoofed}\"") } else { spoofed };
                let req = RawRequest::from_bytes(cx.base_request().to_vec()).set_header("SOAPAction", &value);
                let Ok(resp) = cx.send(req.into_bytes()).await else { continue };
                if body_elements(resp.body_str()).as_ref() == Some(&expected) {
                    let mut f = ALERT.raise("SOAPAction", "");
                    f.attack = value.clone();
                    f.other_info = format!(
                        "The SOAPAction header has been ignored. SOAP version 1.1\nOriginal SOAP Action: {original}\n\
                         Spoofed SOAP Action: {value}\nThe server answered as it answered the original action, so it \
                         goes by the SOAP body and not the header. Without a WSDL, the scan can't name another \
                         operation to spoof to: check by hand whether a gateway or filter in front of the service \
                         allows or routes requests by SOAPAction."
                    );
                    cx.report(f, &resp);
                    return;
                }
            }
        })
    }
}

/// Whether the SOAP body's elements are a fault.
fn is_fault(elements: &[String]) -> bool {
    elements.iter().any(|e| e.eq_ignore_ascii_case("fault"))
}

/// The local names of the SOAP body's child elements, in order, when `xml` is a SOAP envelope
/// with a body; None otherwise (no envelope, or an empty body).
fn body_elements(xml: &str) -> Option<Vec<String>> {
    let mut depth = 0usize;
    let mut body_depth = None;
    let mut seen_envelope = false;
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        rest = &rest[lt + 1..];
        let end = rest.find('>')?;
        let tag = &rest[..end];
        rest = &rest[end + 1..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        let closing = tag.starts_with('/');
        let self_closing = tag.ends_with('/');
        let name = tag.trim_start_matches('/').split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or("");
        let local = name.rsplit(':').next().unwrap_or(name);
        if closing {
            if body_depth == Some(depth) {
                break;
            }
            depth = depth.saturating_sub(1);
            continue;
        }
        depth += 1;
        match body_depth {
            None if depth == 1 && local == "Envelope" => seen_envelope = true,
            None if seen_envelope && depth == 2 && local == "Body" => body_depth = Some(depth),
            Some(b) if depth == b + 1 => out.push(local.to_string()),
            _ => {}
        }
        if self_closing {
            if body_depth == Some(depth) {
                break;
            }
            depth -= 1;
        }
    }
    (body_depth.is_some() && !out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_soap_body_s_elements_are_read() {
        let ok = r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Header><h/></soap:Header><soap:Body><m:GetPriceResponse xmlns:m="urn:x"><m:Price>1</m:Price>
            </m:GetPriceResponse><m:Extra/></soap:Body></soap:Envelope>"#;
        assert_eq!(body_elements(ok), Some(vec!["GetPriceResponse".to_string(), "Extra".to_string()]));
        let fault = "<Envelope><Body><Fault><faultcode>Client</faultcode></Fault></Body></Envelope>";
        assert!(is_fault(&body_elements(fault).unwrap()));
        assert_eq!(body_elements("<Envelope><Body/></Envelope>"), None);
        assert_eq!(body_elements("<html><body><p>x</p></body></html>"), None);
        assert_eq!(body_elements("not xml"), None);
    }
}
