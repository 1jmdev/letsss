//! Hosts file manipulation and DNS cache entries for cheat client domains.

use std::fs;

use crate::{
    context::Context,
    error::Result,
    finding::{Evidence, Finding, Severity},
    options::Module,
    system,
};

#[cfg(windows)]
const HOSTS_FILE: &str = r"C:\Windows\System32\drivers\etc\hosts";
#[cfg(unix)]
const HOSTS_FILE: &str = "/etc/hosts";
const LOOPBACK_NAMES: [&str; 3] = ["localhost", "localhost.localdomain", "broadcasthost"];

pub fn inspect(context: &Context) -> Result<Vec<Finding>> {
    let mut findings = inspect_hosts(context);
    findings.extend(inspect_cache(context));
    Ok(findings)
}

fn inspect_hosts(context: &Context) -> Vec<Finding> {
    let database = &context.signatures.database;
    let Ok(text) = fs::read_to_string(HOSTS_FILE) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let mut fields = line.split_ascii_whitespace();
        let Some(address) = fields.next() else {
            continue;
        };
        for name in fields.filter(|name| !LOOPBACK_NAMES.contains(name)) {
            let lowercase = name.to_ascii_lowercase();
            let evidence = Evidence::Text {
                detail: format!("{address} {name}"),
            };
            if let Some(blocked) = database
                .forensic_domains
                .iter()
                .find(|domain| lowercase == **domain || lowercase.ends_with(&format!(".{domain}")))
            {
                findings.push(
                    Finding::new(
                        Module::Network,
                        Severity::High,
                        format!("Hosts file redirects {blocked}"),
                    )
                    .with_evidence(evidence),
                );
            } else if let Some(client) = database.client_for_domain(&lowercase) {
                findings.push(
                    Finding::new(
                        Module::Network,
                        Severity::Medium,
                        format!("Hosts file maps {} domain", client.name),
                    )
                    .with_client(&client.name)
                    .with_evidence(evidence),
                );
            }
        }
    }
    findings
}

fn inspect_cache(context: &Context) -> Vec<Finding> {
    let database = &context.signatures.database;
    let Some(output) = cache_listing() else {
        return vec![Finding::new(
            Module::Network,
            Severity::Informational,
            "DNS cache is not available on this system",
        )];
    };
    let mut domains: Vec<&str> = output
        .split(|character: char| character.is_whitespace() || character == ':')
        .filter(|token| {
            token.contains('.')
                && token
                    .chars()
                    .any(|character| character.is_ascii_alphabetic())
        })
        .collect();
    domains.sort_unstable();
    domains.dedup();

    let mut findings: Vec<Finding> = Vec::new();
    for domain in domains {
        let Some(client) = database.client_for_domain(domain) else {
            continue;
        };
        let evidence = Evidence::Text {
            detail: domain.trim_end_matches('.').to_owned(),
        };
        match findings
            .iter_mut()
            .find(|finding| finding.client.as_deref() == Some(client.name.as_str()))
        {
            Some(finding) => finding.push_evidence(evidence),
            None => findings.push(
                Finding::new(
                    Module::Network,
                    Severity::High,
                    format!("DNS cache contains {} domains", client.name),
                )
                .with_client(&client.name)
                .with_evidence(evidence),
            ),
        }
    }
    findings
}

#[cfg(windows)]
fn cache_listing() -> Option<String> {
    system::run_command("ipconfig", &["/displaydns"]).ok()
}

#[cfg(unix)]
fn cache_listing() -> Option<String> {
    system::run_command("resolvectl", &["show-cache"])
        .ok()
        .filter(|output| !output.trim().is_empty())
}
