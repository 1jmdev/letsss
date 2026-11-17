//! Single-file analysis: signatures, behavioural rules, imports, and sections.

use std::{fs, path::Path};

use goblin::Object;

use crate::{
    context::Context,
    finding::{Evidence, Finding, Severity},
    mods::archive,
    options::Module,
    signatures::{RuleScope, Tally, excerpt},
};

const FILE_SIZE_LIMIT: u64 = 128 << 20;
const ZIP_SIGNATURE: &[u8] = b"PK\x03\x04";

/// Analyzes one file; returns no findings for unreadable or oversized files.
pub fn analyze(context: &Context, path: &Path) -> Vec<Finding> {
    let database = &context.signatures.database;
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    if fs::metadata(path).map_or(true, |metadata| metadata.len() > FILE_SIZE_LIMIT) {
        return Vec::new();
    }
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    if let Some(client) = database.client_for_file_name(&name) {
        findings.push(
            Finding::new(
                Module::Files,
                Severity::Medium,
                format!("File name {name} matches {}", client.name),
            )
            .with_client(&client.name)
            .with_evidence(Evidence::File {
                path: path.to_path_buf(),
                detail: None,
            }),
        );
    }

    if bytes.starts_with(ZIP_SIGNATURE) {
        if let Ok(report) = archive::analyze(context.signatures, &bytes, path) {
            findings.extend(
                report
                    .tally
                    .findings(database, Module::Files, &name, Severity::High),
            );
        }
        return findings;
    }

    let mut tally = Tally::new();
    context
        .signatures
        .record(&mut tally, &bytes, Some(RuleScope::Binary), |hit| {
            Evidence::File {
                path: path.to_path_buf(),
                detail: Some(excerpt(&bytes, hit.start, hit.end)),
            }
        });
    match Object::parse(&bytes) {
        Ok(Object::PE(pe)) => context.signatures.record_symbols(
            &mut tally,
            pe.imports.iter().map(|import| import.name.as_ref()),
            pe.sections.iter().filter_map(|section| section.name().ok()),
            RuleScope::Binary,
        ),
        Ok(Object::Elf(elf)) => context.signatures.record_symbols(
            &mut tally,
            elf.dynsyms
                .iter()
                .filter_map(|symbol| elf.dynstrtab.get_at(symbol.st_name)),
            elf.section_headers
                .iter()
                .filter_map(|section| elf.shdr_strtab.get_at(section.sh_name)),
            RuleScope::Binary,
        ),
        _ => {}
    }

    if tally.is_empty() || (!tally.has_client() && is_signed(path)) {
        return findings;
    }
    findings.extend(tally.findings(database, Module::Files, &name, Severity::High));
    findings
}

#[cfg(windows)]
fn is_signed(path: &Path) -> bool {
    crate::platform::is_signed(path)
}

#[cfg(unix)]
fn is_signed(_path: &Path) -> bool {
    false
}
