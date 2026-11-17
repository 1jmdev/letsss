//! Findings produced by inspection modules and the overall verdict.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::options::Module;

const LOW_FINDINGS_FOR_SUSPICION: usize = 3;
const EVIDENCE_LIMIT: usize = 64;

/// Severity of a finding, ordered from least to most serious.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Returns the next higher severity, saturating at [`Severity::Critical`].
    pub fn raised(self) -> Self {
        match self {
            Self::Informational => Self::Low,
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
            Self::High | Self::Critical => Self::Critical,
        }
    }
}

/// A single piece of evidence supporting a finding.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    File {
        path: PathBuf,
        detail: Option<String>,
    },
    Memory {
        pid: u32,
        address: u64,
        excerpt: String,
    },
    Process {
        pid: u32,
        name: String,
        detail: Option<String>,
    },
    Registry {
        key: String,
        value: Option<String>,
    },
    Event {
        log: String,
        id: u32,
        record: String,
    },
    Text {
        detail: String,
    },
}

/// A detection or observation reported to the operator.
///
/// ```
/// use letsss_core::{Evidence, Finding, Module, Severity};
///
/// let finding = Finding::new(Module::Mods, Severity::High, "Cheat client in mod")
///     .with_client("Meteor Client")
///     .with_evidence(Evidence::Text { detail: "meteor.jar".into() });
/// assert_eq!(finding.client.as_deref(), Some("Meteor Client"));
/// ```
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub module: Module,
    pub severity: Severity,
    pub title: String,
    pub client: Option<String>,
    pub evidence: Vec<Evidence>,
    pub timestamp: Option<u64>,
}

impl Finding {
    pub fn new(module: Module, severity: Severity, title: impl Into<String>) -> Self {
        Self {
            module,
            severity,
            title: title.into(),
            client: None,
            evidence: Vec::new(),
            timestamp: None,
        }
    }

    pub fn with_client(mut self, client: impl Into<String>) -> Self {
        self.client = Some(client.into());
        self
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.push_evidence(evidence);
        self
    }

    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Appends evidence, discarding entries beyond a fixed limit to bound report size.
    pub fn push_evidence(&mut self, evidence: Evidence) {
        if self.evidence.len() < EVIDENCE_LIMIT {
            self.evidence.push(evidence);
        }
    }
}

/// Overall conclusion of an inspection session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Detected,
}

impl Verdict {
    /// Derives the verdict; evidence tampering raises it by one level.
    pub fn assess(findings: &[Finding]) -> Self {
        let highest = findings.iter().map(|finding| finding.severity).max();
        let lows = findings
            .iter()
            .filter(|finding| finding.severity == Severity::Low)
            .count();
        let base = match highest {
            Some(Severity::High | Severity::Critical) => Self::Detected,
            Some(Severity::Medium) => Self::Suspicious,
            _ if lows >= LOW_FINDINGS_FOR_SUSPICION => Self::Suspicious,
            _ => Self::Clean,
        };
        let tampered = findings.iter().any(|finding| {
            finding.module == Module::Bypass && finding.severity >= Severity::Medium
        });
        match (base, tampered) {
            (Self::Clean, true) => Self::Suspicious,
            (Self::Suspicious, true) => Self::Detected,
            _ => base,
        }
    }
}
