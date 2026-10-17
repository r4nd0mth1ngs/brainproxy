//! Ported from ZAP SourceSinkUtils (commonlib, Apache License 2.0).
//!
//! Tracks where input stored by one request (the source: URL + parameter) shows up
//! later (the sinks: pages whose responses contain it), for the persistent XSS rules.
//! One instance lives for a scan run. Sinks are kept as the page requests to re-send
//! instead of ZAP's temporary history references.

use std::collections::HashMap;

use crate::http::Target;

pub const PREFIX: &str = "zApPX";
pub const POSTFIX: &str = "sS";

/// A page that displays stored input.
#[derive(Debug, Clone, PartialEq)]
pub struct Sink {
    pub target: Target,
    pub request: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SourceSink {
    next: u64,
    /// Unique value -> source key.
    values: HashMap<String, String>,
    /// Source key -> sinks.
    sinks: HashMap<String, Vec<Sink>>,
}

/// ZAP's `UserDataSource` key: the source request URL and the parameter name.
pub fn source_key(url: &str, param: &str) -> String {
    format!("{url}#{param}")
}

impl SourceSink {
    /// A new marker value (`zApPX<n>sS`) remembered as coming from `source`.
    pub fn unique_value(&mut self, source: String) -> String {
        let v = format!("{PREFIX}{}{POSTFIX}", self.next);
        self.next += 1;
        self.values.insert(v.clone(), source);
        v
    }

    /// Records `sink` for every known marker in `body`.
    pub fn test_for_sink(&mut self, body: &str, sink: &Sink) {
        let mut from = 0;
        while let Some(start) = body[from..].find(PREFIX).map(|i| from + i) {
            let Some(end) = body[start..].find(POSTFIX).map(|i| start + i) else { break };
            if let Some(source) = self.values.get(&body[start..end + POSTFIX.len()]) {
                let sinks = self.sinks.entry(source.clone()).or_default();
                if !sinks.contains(sink) {
                    sinks.push(sink.clone());
                }
            }
            from = end;
        }
    }

    pub fn sinks(&self, source: &str) -> Vec<Sink> {
        self.sinks.get(source).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_map_back_to_sources() {
        let mut ss = SourceSink::default();
        let a = ss.unique_value(source_key("http://a/x", "q"));
        let b = ss.unique_value(source_key("http://a/y", "n"));
        assert_eq!((a.as_str(), b.as_str()), ("zApPX0sS", "zApPX1sS"));
        let sink = Sink { target: Target::from_url("http://a/").unwrap(), request: b"GET /list".to_vec() };
        ss.test_for_sink(&format!("{a}<p>{b}</p> zApPX9sS zApPX"), &sink);
        ss.test_for_sink(&format!("again {a}"), &sink);
        assert_eq!(ss.sinks("http://a/x#q"), vec![sink.clone()]);
        assert_eq!(ss.sinks("http://a/y#n"), vec![sink]);
        assert!(ss.sinks("http://a/z#q").is_empty());
    }
}
