//! Aggregation of matches per signature subject and conversion into findings.

use std::collections::BTreeMap;

use crate::{
    finding::{Evidence, Finding, Severity},
    options::Module,
    signatures::{
        database::{Category, Database},
        matcher::{Hit, Subject},
    },
};

const LABEL_LIMIT: usize = 8;
const EVIDENCE_PER_SUBJECT: usize = 3;
const MODULE_WEIGHT_HIGH: u32 = 8;
const MODULE_COUNT_HIGH: usize = 4;
const MODULE_WEIGHT_MEDIUM: u32 = 4;

#[derive(Default)]
struct Entry {
    labels: Vec<String>,
    evidence: Vec<Evidence>,
}

/// Matches collected for one inspected target (process, archive, file).
#[derive(Default)]
pub struct Tally {
    entries: BTreeMap<Subject, Entry>,
}

impl Tally {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn has_client(&self) -> bool {
        self.entries
            .keys()
            .any(|subject| matches!(subject, Subject::Client(_)))
    }

    /// Records a hit; `evidence` is evaluated only while the subject still needs evidence.
    pub fn record(&mut self, hit: &Hit, evidence: impl FnOnce() -> Evidence) {
        let entry = self.insert(hit.subject, hit.label);
        if entry.evidence.len() < EVIDENCE_PER_SUBJECT {
            entry.evidence.push(evidence());
        }
    }

    /// Records a label without positional evidence, such as a PE import name.
    pub fn record_label(&mut self, subject: Subject, label: &str) {
        self.insert(subject, label);
    }

    pub fn merge(&mut self, other: Self) {
        for (subject, incoming) in other.entries {
            let entry = self.entries.entry(subject).or_default();
            for label in incoming.labels {
                if entry.labels.len() < LABEL_LIMIT && !entry.labels.contains(&label) {
                    entry.labels.push(label);
                }
            }
            let room = EVIDENCE_PER_SUBJECT.saturating_sub(entry.evidence.len());
            entry
                .evidence
                .extend(incoming.evidence.into_iter().take(room));
        }
    }

    /// Converts collected matches into findings for `target`.
    ///
    /// `client_severity` applies to client signatures outside the utility category.
    pub fn findings(
        self,
        database: &Database,
        module: Module,
        target: &str,
        client_severity: Severity,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut module_names = Vec::new();
        let mut module_evidence = Vec::new();
        let mut weight = 0;

        for (subject, entry) in self.entries {
            match subject {
                Subject::Client(index) => {
                    let client = &database.clients[index];
                    let severity = if client.category == Category::Utility {
                        Severity::Medium
                    } else {
                        client_severity
                    };
                    let mut finding = Finding::new(
                        module,
                        severity,
                        format!("{} signature in {target}", client.name),
                    )
                    .with_client(&client.name)
                    .with_evidence(matched(&entry.labels));
                    entry
                        .evidence
                        .into_iter()
                        .for_each(|evidence| finding.push_evidence(evidence));
                    findings.push(finding);
                }
                Subject::Module(index) => {
                    weight += database.modules[index].weight;
                    module_names.push(database.modules[index].name.as_str());
                    module_evidence.extend(entry.evidence.into_iter().take(1));
                }
                Subject::Rule(index) => {
                    let rule = &database.rules[index];
                    if entry.labels.len() < rule.minimum {
                        continue;
                    }
                    let mut finding = Finding::new(
                        module,
                        rule.severity,
                        format!("[{}] {} in {target}", rule.tag, rule.name),
                    )
                    .with_evidence(matched(&entry.labels));
                    entry
                        .evidence
                        .into_iter()
                        .for_each(|evidence| finding.push_evidence(evidence));
                    findings.push(finding);
                }
            }
        }

        if !module_names.is_empty() {
            let severity =
                if weight >= MODULE_WEIGHT_HIGH || module_names.len() >= MODULE_COUNT_HIGH {
                    Severity::High
                } else if weight >= MODULE_WEIGHT_MEDIUM {
                    Severity::Medium
                } else {
                    Severity::Low
                };
            let mut finding = Finding::new(
                module,
                severity,
                format!("{} cheat module names in {target}", module_names.len()),
            )
            .with_evidence(Evidence::Text {
                detail: module_names.join(", "),
            });
            module_evidence
                .into_iter()
                .for_each(|evidence| finding.push_evidence(evidence));
            findings.push(finding);
        }
        findings
    }

    fn insert(&mut self, subject: Subject, label: &str) -> &mut Entry {
        let entry = self.entries.entry(subject).or_default();
        if entry.labels.len() < LABEL_LIMIT && !entry.labels.iter().any(|known| known == label) {
            entry.labels.push(label.to_owned());
        }
        entry
    }
}

fn matched(labels: &[String]) -> Evidence {
    Evidence::Text {
        detail: format!("Matched: {}", labels.join(", ")),
    }
}
