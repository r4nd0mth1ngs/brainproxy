//! Ported from ZAP CloudMetadataScanRule (ascanrules, Apache License 2.0).
//!
//! The request goes to the scanned host (the connection stays inside the
//! engagement scope); only the Host header names the metadata service, as in ZAP.

use super::common::{base_path_query, is_success, with_request_line};
use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90034",
    name: "Cloud Metadata Potentially Exposed",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 1230,
    wasc: 0,
    description: "The Cloud Metadata Attack attempts to abuse a misconfigured NGINX server in order to access the \
        instance metadata maintained by cloud service providers such as AWS, GCP and Azure.\nAll of these providers \
        provide metadata via an internal unroutable IP address '169.254.169.254' - this can be exposed by \
        incorrectly configured NGINX servers and accessed by using this IP address in the Host header field.",
    solution: "Do not trust any user data in NGINX configs. In this case it is probably the use of the $host \
        variable which is set from the 'Host' header and can be controlled by an attacker.",
    references: &["https://blog.nginx.org/blog/trust-no-one-perils-of-trusting-user-input"],
    tags: &["API_2023_API8", "OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER_INFO: &str = "Based on the successful response status code cloud metadata may have been returned in the \
    response. Check the response data to see if any cloud metadata has been returned.\nThe meta data returned can \
    include information that would allow an attacker to completely compromise the system.";

struct Endpoint {
    host: &'static str,
    path: &'static str,
    headers: &'static [(&'static str, &'static str)],
}

struct Provider {
    endpoints: &'static [Endpoint],
    indicators: &'static [&'static str],
}

const GOOGLE: &[(&str, &str)] = &[("Metadata-Flavor", "Google")];
const ORACLE: &[(&str, &str)] = &[("Authorization", "Bearer Oracle")];

static PROVIDERS: &[Provider] = &[
    // AWS
    Provider {
        endpoints: &[
            Endpoint { host: "169.254.169.254", path: "/latest/meta-data/", headers: &[] },
            Endpoint { host: "aws.zaproxy.org", path: "/latest/meta-data/", headers: &[] },
        ],
        indicators: &["ami-id\n", "instance-id\n", "local-hostname\n", "public-hostname\n"],
    },
    // GCP
    Provider {
        endpoints: &[
            Endpoint { host: "169.254.169.254", path: "/computeMetadata/v1/", headers: GOOGLE },
            Endpoint { host: "metadata.google.internal", path: "/computeMetadata/v1/", headers: GOOGLE },
        ],
        indicators: &["project-id\n", "zone\n", "machineType\n", "machine-type\n", "hostname\n"],
    },
    // OCI
    Provider {
        endpoints: &[
            Endpoint { host: "169.254.169.254", path: "/opc/v1/instance/", headers: &[] },
            Endpoint { host: "metadata.oraclecloud.com", path: "/opc/v1/instance/", headers: &[] },
            Endpoint { host: "169.254.169.254", path: "/opc/v2/instance/", headers: ORACLE },
            Endpoint { host: "metadata.oraclecloud.com", path: "/opc/v2/instance/", headers: ORACLE },
        ],
        indicators: &["\"oci", "\"instance\"", "\"availabilityDomain\"", "\"region"],
    },
    // Alibaba Cloud
    Provider {
        endpoints: &[
            Endpoint { host: "100.100.100.200", path: "/latest/meta-data/", headers: &[] },
            Endpoint { host: "alibaba.zaproxy.org", path: "/latest/meta-data/", headers: &[] },
        ],
        indicators: &["image-id\n", "instance-id\n", "hostname\n", "region-id\n"],
    },
    // Azure
    Provider {
        endpoints: &[Endpoint {
            host: "169.254.169.254",
            path: "/metadata/instance",
            headers: &[("Metadata", "true")],
        }],
        indicators: &["\"compute\"", "\"network\"", "\"osType\"", "\"vmSize\""],
    },
    // IBM Cloud
    Provider {
        endpoints: &[Endpoint {
            host: "169.254.169.254",
            path: "/metadata/v1",
            headers: &[("Metadata-Flavor", "ibm"), ("Accept", "application/json")],
        }],
        indicators: &["\"compute\"", "\"network\"", "\"vm_id\"", "\"os_type\""],
    },
    // OpenStack
    Provider {
        endpoints: &[Endpoint { host: "169.254.169.254", path: "/openstack/latest/meta_data.json", headers: &[] }],
        indicators: &["\"uuid\"", "\"meta\"", "\"public_keys\""],
    },
];

/// The indicator found in a metadata response body, if any.
fn indicator(provider: &Provider, body: &str) -> Option<&'static str> {
    provider.indicators.iter().copied().find(|i| body.contains(i))
}

/// The base path replaced by the endpoint path, keeping the query (ZAP `setPath`).
fn endpoint_target(base_path_query: &str, path: &str) -> String {
    match base_path_query.split_once('?') {
        Some((_, q)) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

pub struct CloudMetadata;

impl ActiveRule for CloudMetadata {
    fn id(&self) -> u32 {
        90034
    }

    fn name(&self) -> &'static str {
        "Cloud Metadata Potentially Exposed"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Host
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let pq = base_path_query(cx);
            let method = cx.base().method.clone();
            for provider in PROVIDERS {
                for ep in provider.endpoints {
                    if cx.stopped() {
                        return;
                    }
                    let raw = with_request_line(cx.base_request(), &method, &endpoint_target(&pq, ep.path));
                    let mut req = RawRequest::from_bytes(raw).set_header("Host", ep.host);
                    for (k, v) in ep.headers {
                        req = req.set_header(k, v);
                    }
                    let Ok(resp) = cx.send(req.into_bytes()).await else { continue };
                    if !is_success(&resp) || resp.body.is_empty() {
                        continue;
                    }
                    if let Some(ind) = indicator(provider, resp.body_str()) {
                        let finding = ALERT.raise("", ind).attack(ep.host).other_info(OTHER_INFO);
                        cx.report(finding, &resp);
                        return;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicators() {
        assert_eq!(indicator(&PROVIDERS[0], "ami-id\nhostname\ninstance-id\n"), Some("ami-id\n"));
        assert_eq!(indicator(&PROVIDERS[0], "<html>instance-id</html>"), None);
        assert_eq!(indicator(&PROVIDERS[4], r#"{"compute":{}}"#), Some("\"compute\""));
        assert_eq!(PROVIDERS.iter().map(|p| p.endpoints.len()).sum::<usize>(), 13);
    }

    #[test]
    fn endpoint_targets() {
        assert_eq!(endpoint_target("/app?x=1", "/latest/meta-data/"), "/latest/meta-data/?x=1");
        assert_eq!(endpoint_target("/", "/metadata/v1"), "/metadata/v1");
    }
}
