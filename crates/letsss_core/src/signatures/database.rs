//! Decoding of the build-time signature blob into typed records.

use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    finding::{Evidence, Severity},
    signatures::{
        matcher::{Hit, Matcher, Settings, Subject},
        tally::Tally,
    },
};

include!(concat!(env!("OUT_DIR"), "/signature_key.rs"));

static ENCODED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/signatures.bin"));

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Blatant,
    Ghost,
    Crystal,
    Clicker,
    Macro,
    Utility,
    Loader,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Client {
    pub name: String,
    pub category: Category,
    #[serde(default)]
    pub strings: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    /// Lowercase fragments identifying the client in file and process names.
    #[serde(default)]
    pub file_names: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GenericModule {
    pub name: String,
    pub category: String,
    pub weight: u32,
    pub strings: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleScope {
    Binary,
    Archive,
    Both,
}

impl RuleScope {
    pub fn covers(self, target: Self) -> bool {
        self == Self::Both || self == target
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    pub tag: String,
    pub name: String,
    pub severity: Severity,
    pub scope: RuleScope,
    pub minimum: usize,
    #[serde(default)]
    pub strings: Vec<String>,
    #[serde(default)]
    pub imports: Vec<String>,
    #[serde(default)]
    pub sections: Vec<String>,
    /// Reports the rule only when a client or module signature also matched the target.
    #[serde(default)]
    pub corroborated: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LaunchFlag {
    pub prefix: String,
    pub severity: Severity,
    pub title: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MacroSoftware {
    pub process: String,
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceRating {
    Trusted,
    Review,
    Risky,
    Suspicious,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DownloadSource {
    pub host: String,
    pub rating: SourceRating,
}

/// Raw signature records as authored in `signatures/*.toml`.
#[derive(Clone, Debug, Deserialize)]
pub struct Database {
    #[serde(rename = "client")]
    pub clients: Vec<Client>,
    #[serde(rename = "module")]
    pub modules: Vec<GenericModule>,
    #[serde(rename = "rule")]
    pub rules: Vec<Rule>,
    #[serde(rename = "launch_flag")]
    pub launch_flags: Vec<LaunchFlag>,
    pub macro_software: Vec<MacroSoftware>,
    #[serde(rename = "download_source")]
    pub download_sources: Vec<DownloadSource>,
    pub legitimate_agents: Vec<String>,
    pub impersonated_mods: Vec<String>,
    pub forensic_domains: Vec<String>,
    pub trusted_module_directories: Vec<String>,
    pub trusted_module_names: Vec<String>,
}

impl Database {
    /// Rates a download URL or host by the first matching configured source.
    pub fn rate_source(&self, location: &str) -> Option<SourceRating> {
        let location = location.to_ascii_lowercase();
        self.download_sources
            .iter()
            .find(|source| location.contains(&source.host))
            .map(|source| source.rating)
    }

    /// Finds the client whose configured file-name fragment appears in `name`.
    pub fn client_for_file_name(&self, name: &str) -> Option<&Client> {
        let name = name.to_ascii_lowercase();
        self.clients.iter().find(|client| {
            client
                .file_names
                .iter()
                .any(|fragment| name.contains(fragment.as_str()))
        })
    }

    /// Finds the client owning a domain, matching the domain itself or any subdomain.
    pub fn client_for_domain(&self, domain: &str) -> Option<&Client> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.clients.iter().find(|client| {
            client.domains.iter().any(|known| {
                domain == *known
                    || domain
                        .strip_suffix(known.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
        })
    }
}

/// Signature database together with its compiled matchers.
///
/// ```
/// let signatures = letsss_core::Signatures::load().unwrap();
/// assert!(!signatures.database.clients.is_empty());
/// ```
pub struct Signatures {
    pub database: Database,
    pub clients: Matcher,
    pub modules: Matcher,
    pub rules: Matcher,
}

impl Signatures {
    pub fn load() -> Result<Self> {
        let decoded: Vec<u8> = ENCODED
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                byte ^ SIGNATURE_KEY[index % SIGNATURE_KEY.len()].wrapping_add(index as u8)
            })
            .collect();
        let database: Database = serde_json::from_slice(&decoded)?;

        let clients = Matcher::new(
            database
                .clients
                .iter()
                .enumerate()
                .flat_map(|(index, client)| {
                    client
                        .strings
                        .iter()
                        .chain(&client.domains)
                        .map(move |text| (Subject::Client(index), text.as_str()))
                }),
            Settings::default(),
        );
        let modules = Matcher::new(
            database
                .modules
                .iter()
                .enumerate()
                .flat_map(|(index, module)| {
                    module
                        .strings
                        .iter()
                        .map(move |text| (Subject::Module(index), text.as_str()))
                }),
            Settings {
                case_insensitive: false,
                boundary: true,
                fullwidth: true,
            },
        );
        let rules = Matcher::new(
            database.rules.iter().enumerate().flat_map(|(index, rule)| {
                rule.strings
                    .iter()
                    .map(move |text| (Subject::Rule(index), text.as_str()))
            }),
            Settings::default(),
        );

        Ok(Self {
            database,
            clients,
            modules,
            rules,
        })
    }

    /// Scans with client and module matchers, plus rules covering `scope` when given.
    pub fn scan<'a>(
        &'a self,
        haystack: &[u8],
        scope: Option<RuleScope>,
        mut visit: impl FnMut(Hit<'a>),
    ) {
        self.clients.scan(haystack, &mut visit);
        self.modules.scan(haystack, &mut visit);
        if let Some(scope) = scope {
            self.rules.scan(haystack, |hit| {
                if let Subject::Rule(index) = hit.subject
                    && self.database.rules[index].scope.covers(scope)
                {
                    visit(hit);
                }
            });
        }
    }

    /// Scans `haystack` and records every hit into `tally` with caller-built evidence.
    pub fn record(
        &self,
        tally: &mut Tally,
        haystack: &[u8],
        scope: Option<RuleScope>,
        evidence: impl Fn(&Hit) -> Evidence,
    ) {
        self.scan(haystack, scope, |hit| tally.record(&hit, || evidence(&hit)));
    }

    /// Records PE imports, ELF symbols, or section names against rules covering `scope`.
    pub fn record_symbols<'s>(
        &self,
        tally: &mut Tally,
        imports: impl IntoIterator<Item = &'s str>,
        sections: impl IntoIterator<Item = &'s str>,
        scope: RuleScope,
    ) {
        let imports: Vec<&str> = imports.into_iter().collect();
        let sections: Vec<&str> = sections.into_iter().collect();
        for (index, rule) in self.database.rules.iter().enumerate() {
            if !rule.scope.covers(scope) {
                continue;
            }
            rule.imports
                .iter()
                .filter(|import| imports.contains(&import.as_str()))
                .chain(
                    rule.sections
                        .iter()
                        .filter(|section| sections.contains(&section.as_str())),
                )
                .for_each(|label| tally.record_label(Subject::Rule(index), label));
        }
    }
}
