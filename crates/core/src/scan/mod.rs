//! Scanning: findings, the message model rules inspect, and the passive scanner.
//!
//! Passive rules are ported from OWASP ZAP's pscanrules add-on
//! (https://github.com/zaproxy/zap-extensions, Apache License 2.0). Each rule file
//! names the ZAP class it was ported from; alert texts are ZAP's.

pub mod findings_db;
pub mod message;
pub mod passive;

use serde::Serialize;

pub use message::Message;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Info,
    Low,
    Medium,
    High,
}

impl Risk {
    pub fn level(self) -> i64 {
        self as i64
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Info => "info",
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" | "informational" => Some(Risk::Info),
            "low" => Some(Risk::Low),
            "medium" => Some(Risk::Medium),
            "high" => Some(Risk::High),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// Static description of one alert type (ZAP "alert ref").
#[derive(Debug)]
pub struct AlertDef {
    pub alert_ref: &'static str,
    pub name: &'static str,
    pub risk: Risk,
    pub confidence: Confidence,
    pub cwe: u32,
    pub wasc: u32,
    pub description: &'static str,
    pub solution: &'static str,
    pub references: &'static [&'static str],
    pub tags: &'static [&'static str],
}

impl AlertDef {
    pub fn raise(&'static self, param: impl Into<String>, evidence: impl Into<String>) -> Finding {
        Finding {
            def: self,
            risk: self.risk,
            confidence: self.confidence,
            param: param.into(),
            evidence: evidence.into(),
            other_info: String::new(),
        }
    }
}

/// One detected issue in one message.
#[derive(Debug, Clone)]
pub struct Finding {
    pub def: &'static AlertDef,
    /// Usually the definition's risk; some rules adjust it per instance.
    pub risk: Risk,
    pub confidence: Confidence,
    pub param: String,
    pub evidence: String,
    pub other_info: String,
}

impl Finding {
    pub fn other_info(mut self, s: impl Into<String>) -> Self {
        self.other_info = s.into();
        self
    }

    pub fn risk(mut self, r: Risk) -> Self {
        self.risk = r;
        self
    }

    pub fn confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }
}

/// A passive rule: inspects one request/response pair without sending anything.
pub trait PassiveRule: Send + Sync {
    /// ZAP plugin id.
    fn id(&self) -> u32;
    fn name(&self) -> &'static str;
    /// Every alert this rule can raise (for `scan rules`).
    fn alerts(&self) -> &'static [&'static AlertDef];
    fn scan(&self, msg: &Message, out: &mut Vec<Finding>);
}
