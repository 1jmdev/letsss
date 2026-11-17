//! Windows bypass checks: registry, event logs, Prefetch folder, and USN journal state.

use std::{env, fs, path::PathBuf};

use usn_journal_rs::volume::Volume;

use crate::{
    bypass::{events, registry},
    context::Context,
    error::Result,
    finding::{Evidence, Finding, Severity},
    options::Module,
    paths, system,
};

const PREFETCH_MINIMUM: usize = 10;

pub fn inspect(context: &Context) -> Result<Vec<Finding>> {
    context.report(Module::Bypass, 0.1, "Registry");
    let mut findings = registry::inspect(context);
    context.checkpoint()?;
    context.report(Module::Bypass, 0.5, "Event logs");
    findings.extend(events::inspect(context));
    context.checkpoint()?;
    context.report(Module::Bypass, 0.8, "Prefetch and journal state");
    findings.extend(inspect_prefetch());
    findings.extend(inspect_journal(context));
    Ok(findings)
}

fn inspect_prefetch() -> Vec<Finding> {
    let directory = env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("Prefetch");
    let Ok(entries) = fs::read_dir(&directory) else {
        return Vec::new();
    };
    let files: Vec<_> = entries
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("pf"))
        })
        .collect();
    let mut findings = Vec::new();
    if files.len() < PREFETCH_MINIMUM {
        findings.push(
            Finding::new(
                Module::Bypass,
                Severity::High,
                format!("Prefetch folder holds only {} files", files.len()),
            )
            .with_evidence(Evidence::File {
                path: directory,
                detail: None,
            }),
        );
    }
    let read_only: Vec<PathBuf> = files
        .iter()
        .filter(|entry| {
            entry
                .metadata()
                .is_ok_and(|metadata| metadata.permissions().readonly())
        })
        .map(|entry| entry.path())
        .collect();
    if !read_only.is_empty() {
        let mut finding = Finding::new(
            Module::Bypass,
            Severity::Medium,
            format!("{} Prefetch files are read-only", read_only.len()),
        );
        read_only
            .into_iter()
            .for_each(|path| finding.push_evidence(Evidence::File { path, detail: None }));
        findings.push(finding);
    }
    findings
}

fn inspect_journal(context: &Context) -> Option<Finding> {
    let drive = paths::system_drive();
    let queried = Volume::from_drive_letter(drive).and_then(|volume| volume.journal().query());
    match queried {
        Err(error) => Some(
            Finding::new(
                Module::Bypass,
                Severity::High,
                format!("USN journal on {drive}: is unavailable"),
            )
            .with_evidence(Evidence::Text {
                detail: error.to_string(),
            }),
        ),
        Ok(data) => {
            let created = system::filetime_to_unix(data.journal_id);
            (created > context.system.boot_time).then(|| {
                Finding::new(
                    Module::Bypass,
                    Severity::High,
                    format!("USN journal on {drive}: was recreated since boot"),
                )
                .with_evidence(Evidence::Text {
                    detail: format!("Created {}", system::format_time(created)),
                })
                .with_timestamp(created)
            })
        }
    }
}
