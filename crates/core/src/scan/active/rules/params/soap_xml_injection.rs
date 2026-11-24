//! Ported from ZAP SOAPXMLInjectionActiveScanRule (soap, Apache License 2.0).
//!
//! For each element value in the Body of a recorded SOAP request: one request with the value
//! changed (`v_modified`), and one that closes the element and opens a second one of the same
//! name with that changed value (`v</name><name>v_modified`), sent unescaped. If the server
//! answers the injection exactly as it answers the changed value (and not as the original),
//! it read the injected element: XML injection (high). An answer to the injection that isn't
//! SOAP any more is reported at low risk, as ZAP does.

use crate::scan::active::points::xml_values;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, PointKind, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90029",
    name: "SOAP XML Injection",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 91,
    wasc: 0,
    description: "Some XML injected code has been interpreted by the server.",
    solution: "Use a detailed description of SOAP attributes in the WSDL file.",
    references: &["https://www.nds.ruhr-uni-bochum.de/media/nds/veroeffentlichungen/2012/07/11/camera-ready.pdf"],
    tags: &["API_2023_API10", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const SOAP_11: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP_12: &str = "http://www.w3.org/2003/05/soap-envelope";

/// The local part of a qualified name.
fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Whether `body` is a well-formed SOAP envelope: its root element is an `Envelope` and a
/// SOAP 1.1 or 1.2 namespace is declared.
pub(crate) fn is_soap(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else { return false };
    if xml_values(body).is_none() || !(text.contains(SOAP_11) || text.contains(SOAP_12)) {
        return false;
    }
    let mut rest = text.trim_start_matches('\u{feff}');
    loop {
        rest = rest.trim_start();
        let skip = [("<?", "?>"), ("<!--", "-->")].into_iter().find(|(open, _)| rest.starts_with(open));
        match skip {
            Some((_, close)) => match rest.find(close) {
                Some(i) => rest = &rest[i + close.len()..],
                None => return false,
            },
            None => break,
        }
    }
    let Some(tag) = rest.strip_prefix('<') else { return false };
    let name = tag.split(|c: char| c.is_whitespace() || c == '>' || c == '/').next().unwrap_or("");
    local(name) == "Envelope"
}

/// The element a point names, if it is an element in the SOAP Body: its qualified name as
/// the document spells it.
fn body_element(point_name: &str) -> Option<&str> {
    let segments: Vec<&str> = point_name.split('.').collect();
    let last = *segments.last()?;
    if last.starts_with('@') {
        return None;
    }
    let in_body = segments.iter().rev().skip(1).any(|s| local(s.split('[').next().unwrap_or(s)) == "Body");
    in_body.then(|| last.split('[').next().unwrap_or(last))
}

pub struct SoapXmlInjection;

impl ActiveRule for SoapXmlInjection {
    fn id(&self) -> u32 {
        90029
    }

    fn name(&self) -> &'static str {
        "SOAP XML Injection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let point = cx.point();
            if point.kind != PointKind::Xml {
                return;
            }
            let Some(element) = body_element(&point.name) else { return };
            let (_, body) = crate::http::request::split_head_body(cx.base_request());
            if !is_soap(body) {
                return;
            }
            let modified = format!("{}_modified", point.value);
            let attack = format!("{}</{element}><{element}>{modified}", point.value);
            let Ok(changed) = cx.send_payload(&modified).await else { return };
            if cx.stopped() {
                return;
            }
            let Ok(injected) = cx.send_payload_raw(&attack).await else { return };
            let version = if cx.base().req_header("soapaction").is_some() { "1.1" } else { "1.2" };
            if !is_soap(&injected.body) {
                let info =
                    format!("Response does not have SOAP format after XML Injection attack. SOAP version {version}.");
                let finding = ALERT.raise(point.name.clone(), "").attack(attack).other_info(info).risk(Risk::Low);
                cx.report(finding, &injected);
            } else if injected.body == changed.body && changed.body != cx.base_response().body {
                let info =
                    format!("Response content has been altered after XML Injection attack. SOAP version {version}.");
                cx.report(ALERT.raise(point.name.clone(), "").attack(attack).other_info(info), &injected);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::active::rules::test_app::{post, resp, scan, serve, Opts};

    fn envelope(inner: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"{SOAP_11}\"><soap:Body><getUser><name>{inner}</name>\
             </getUser></soap:Body></soap:Envelope>"
        )
    }

    /// The `<name>` elements of a request, as a lax parser that takes the last one reads them.
    fn names(body: &str) -> Vec<String> {
        body.split("<name>").skip(1).filter_map(|s| s.split("</name>").next()).map(str::to_string).collect()
    }

    fn answer(user: &str) -> String {
        resp(200, "text/xml", &[], &envelope(&format!("user {user}")))
    }

    #[test]
    fn soap_shapes() {
        assert!(is_soap(envelope("x").as_bytes()));
        assert!(!is_soap(b"<html><body>no</body></html>"));
        assert!(!is_soap(envelope("<broken").as_bytes()));
        assert_eq!(body_element("soap:Envelope.soap:Body.getUser.name"), Some("name"));
        assert_eq!(body_element("soap:Envelope.soap:Header.token"), None);
        assert_eq!(body_element("soap:Envelope.soap:Body.getUser.@id"), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_injected_element_is_read_and_an_escaped_one_is_not() {
        let port = serve(|r| match r.path.as_str() {
            // Concatenates the XML and reads the last <name>.
            "/lax" => answer(names(&r.body).last().map_or("", String::as_str)),
            // Parses the value as text: the injection is one odd name.
            _ => answer(&names(&r.body).concat()),
        });
        let soap = |path: &str| post(port, path, "text/xml; charset=utf-8", &envelope("alice"));
        let (s, found) = scan(90029, vec![soap("/lax")], Opts::default()).await;
        assert_eq!(found.len(), 1, "{s:?}");
        assert_eq!((found[0].risk.as_str(), found[0].attack.as_str()), ("high", "alice</name><name>alice_modified"));
        let (s, found) = scan(90029, vec![soap("/strict")], Opts::default()).await;
        assert!(found.is_empty(), "{found:?}");
        assert_eq!(s.requests, 2);
    }
}
