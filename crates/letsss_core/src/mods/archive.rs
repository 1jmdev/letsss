//! Recursive JAR analysis: class constants, resources, nested JARs, and mod identity.

use std::{
    io::{Cursor, Read},
    path::Path,
};

use serde_json::Value;
use zip::ZipArchive;

use crate::{
    error::{Error, Result},
    finding::Evidence,
    mods::classfile,
    signatures::{RuleScope, Signatures, Tally, excerpt},
};

const NESTING_LIMIT: usize = 3;
const ENTRY_SIZE_LIMIT: u64 = 64 << 20;
const TEXT_EXTENSIONS: [&str; 9] = [
    ".json",
    ".mf",
    ".txt",
    ".properties",
    ".toml",
    ".yml",
    ".yaml",
    ".cfg",
    ".refmap",
];
const MOD_DESCRIPTORS: [&str; 2] = ["fabric.mod.json", "quilt.mod.json"];
const FORGE_DESCRIPTORS: [&str; 2] = ["META-INF/mods.toml", "META-INF/neoforge.mods.toml"];
const CLASS_SUFFIX: &str = ".class";
const JAR_SUFFIX: &str = ".jar";

/// Results of inspecting one archive and every archive nested inside it.
#[derive(Default)]
pub struct ArchiveReport {
    pub tally: Tally,
    /// Class paths without the `.class` suffix, outer archive only.
    pub classes: Vec<String>,
    pub nested: Vec<String>,
    pub mod_id: Option<String>,
    /// Classes whose constant pool could not be parsed.
    pub malformed: usize,
}

pub fn analyze(signatures: &Signatures, bytes: &[u8], path: &Path) -> Result<ArchiveReport> {
    let mut report = ArchiveReport::default();
    let mut buffer = Vec::new();
    walk(signatures, bytes, path, "", 0, &mut report, &mut buffer).map_err(|source| {
        Error::Archive {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(report)
}

fn walk(
    signatures: &Signatures,
    bytes: &[u8],
    path: &Path,
    prefix: &str,
    depth: usize,
    report: &mut ArchiveReport,
    buffer: &mut Vec<u8>,
) -> zip::result::ZipResult<()> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_dir() || entry.size() > ENTRY_SIZE_LIMIT {
            continue;
        }
        let Ok(name) = entry.name().map(|name| name.into_owned()) else {
            continue;
        };
        let lowercase = name.to_ascii_lowercase();
        let class = lowercase.ends_with(CLASS_SUFFIX);
        let nested = lowercase.ends_with(JAR_SUFFIX);
        let descriptor = depth == 0
            && (MOD_DESCRIPTORS.contains(&name.as_str())
                || FORGE_DESCRIPTORS.contains(&name.as_str()));
        let text = TEXT_EXTENSIONS
            .iter()
            .any(|extension| lowercase.ends_with(extension));
        if !(class || nested || text) {
            continue;
        }

        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data)?;
        drop(entry);
        let location = format!("{prefix}{name}");

        if nested {
            report.nested.push(location.clone());
            if depth < NESTING_LIMIT {
                walk(
                    signatures,
                    &data,
                    path,
                    &format!("{location}!/"),
                    depth + 1,
                    report,
                    buffer,
                )?;
            }
            continue;
        }
        if descriptor {
            report.mod_id = report.mod_id.take().or_else(|| mod_id(&name, &data));
        }

        let haystack: &[u8] = if class {
            if depth == 0 {
                report
                    .classes
                    .push(name[..name.len() - CLASS_SUFFIX.len()].to_owned());
            }
            buffer.clear();
            let parsed = classfile::constants(&data, |constant| {
                buffer.extend_from_slice(constant);
                buffer.push(b'\n');
            });
            if parsed {
                buffer.as_slice()
            } else {
                report.malformed += 1;
                &data
            }
        } else {
            &data
        };
        signatures.record(
            &mut report.tally,
            haystack,
            Some(RuleScope::Archive),
            |hit| Evidence::File {
                path: path.to_path_buf(),
                detail: Some(format!(
                    "{location}: {}",
                    excerpt(haystack, hit.start, hit.end)
                )),
            },
        );
    }
    Ok(())
}

fn mod_id(name: &str, data: &[u8]) -> Option<String> {
    if MOD_DESCRIPTORS.contains(&name) {
        let descriptor: Value = serde_json::from_slice(data).ok()?;
        return descriptor
            .get("id")
            .or_else(|| descriptor.pointer("/quilt_loader/id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    String::from_utf8_lossy(data).lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "modId").then(|| value.trim().trim_matches('"').to_owned())
    })
}
