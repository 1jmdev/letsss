//! Running process review: macro software, cheat-named processes, and emulation layers.

use crate::{
    context::Context,
    error::Result,
    finding::{Evidence, Finding, Severity},
    options::Module,
    signatures::{Subject, Tally},
};

const WINE_SERVER: &str = "wineserver";

pub fn inspect(context: &Context) -> Result<Vec<Finding>> {
    let signatures = context.signatures;
    let database = &signatures.database;
    let mut findings = Vec::new();

    for process in &context.system.processes {
        let name = process.name.to_ascii_lowercase();
        let evidence = || Evidence::Process {
            pid: process.pid,
            name: process.name.clone(),
            detail: process
                .executable
                .as_deref()
                .map(|path| path.display().to_string()),
        };

        if let Some(software) = database
            .macro_software
            .iter()
            .find(|software| name.contains(&software.process))
        {
            findings.push(
                Finding::new(
                    Module::Processes,
                    Severity::Low,
                    format!("Macro-capable software running: {}", software.name),
                )
                .with_evidence(evidence()),
            );
        }

        if let Some(client) = database.client_for_file_name(&name) {
            findings.push(
                Finding::new(
                    Module::Processes,
                    Severity::High,
                    format!("Process name matches {}", client.name),
                )
                .with_client(&client.name)
                .with_evidence(evidence()),
            );
        }

        if process.is_java() {
            continue;
        }
        let description = format!(
            "{} {}",
            process
                .executable
                .as_deref()
                .map(|path| path.to_string_lossy())
                .unwrap_or_default(),
            process.command.join(" ")
        );
        let mut tally = Tally::new();
        signatures.clients.scan(description.as_bytes(), |hit| {
            if matches!(hit.subject, Subject::Client(_)) {
                tally.record(&hit, evidence);
            }
        });
        findings.extend(tally.findings(
            database,
            Module::Processes,
            &format!("process {} ({})", process.name, process.pid),
            Severity::High,
        ));
    }

    let wine = context
        .system
        .processes
        .iter()
        .any(|process| process.name == WINE_SERVER);
    if wine
        && context
            .system
            .game_processes()
            .any(|process| process.name.ends_with(".exe"))
    {
        findings.push(Finding::new(
            Module::Processes,
            Severity::Low,
            "Minecraft is running under Wine",
        ));
    }
    Ok(findings)
}
