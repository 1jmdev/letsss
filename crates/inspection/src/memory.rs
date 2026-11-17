//! Chunked, parallel signature scanning of every readable region of each Minecraft process.

use std::{
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use rayon::prelude::*;

#[cfg(unix)]
use crate::platform::tracer;

use crate::{
    context::Context,
    error::Result,
    files,
    finding::{Evidence, Finding, Severity},
    options::Module,
    paths,
    platform::ProcessMemory,
    signatures::{Tally, excerpt},
    system::ProcessRecord,
};

const CHUNK_SIZE: usize = 16 << 20;
const DOS_SIGNATURE: &[u8] = b"MZ";
const PE_SIGNATURE: &[u8] = b"PE\0\0";
const PE_POINTER_OFFSET: usize = 0x3C;

/// A committed, readable region as reported by the operating system.
#[derive(Clone, Debug)]
pub struct Region {
    pub base: u64,
    pub size: usize,
    pub executable: bool,
    pub writable: bool,
    /// Anonymous memory not backed by an image or file mapping.
    pub private: bool,
}

impl Region {
    /// Private, writable, executable memory: where manually mapped code resides.
    pub fn is_injection_candidate(&self) -> bool {
        self.private && self.executable && self.writable
    }
}

#[derive(Default)]
struct RegionResult {
    tally: Tally,
    images: Vec<u64>,
}

impl RegionResult {
    fn merge(mut self, other: Self) -> Self {
        self.tally.merge(other.tally);
        self.images.extend(other.images);
        self
    }
}

pub fn inspect(context: &Context) -> Result<Vec<Finding>> {
    let targets: Vec<&ProcessRecord> = context.system.game_processes().collect();
    if targets.is_empty() {
        return Ok(vec![Finding::new(
            Module::Memory,
            Severity::Informational,
            "No running Minecraft process found",
        )]);
    }
    let mut findings = Vec::new();
    for (index, process) in targets.iter().enumerate() {
        context.checkpoint()?;
        findings.extend(inspect_process(context, process, index, targets.len())?);
    }
    Ok(findings)
}

fn inspect_process(
    context: &Context,
    process: &ProcessRecord,
    index: usize,
    count: usize,
) -> Result<Vec<Finding>> {
    let target = format!("{} ({})", process.name, process.pid);
    let memory = match ProcessMemory::open(process.pid) {
        Ok(memory) => memory,
        Err(error) => {
            return Ok(vec![
                Finding::new(
                    Module::Memory,
                    Severity::Low,
                    format!("Memory of {target} is not readable"),
                )
                .with_evidence(Evidence::Text {
                    detail: error.to_string(),
                }),
            ]);
        }
    };

    let regions = memory.regions();
    let total: u64 = regions
        .iter()
        .map(|region| region.size as u64)
        .sum::<u64>()
        .max(1);
    let scanned = AtomicU64::new(0);
    let signatures = context.signatures;
    let overlap = signatures
        .clients
        .longest()
        .max(signatures.modules.longest());

    let result = regions
        .par_iter()
        .map_init(
            || vec![0u8; CHUNK_SIZE + overlap],
            |buffer, region| {
                if context.checkpoint().is_err() {
                    return RegionResult::default();
                }
                let result = scan_region(context, &memory, process.pid, region, buffer, overlap);
                let done =
                    scanned.fetch_add(region.size as u64, Ordering::Relaxed) + region.size as u64;
                context.report(
                    Module::Memory,
                    (index as f32 + done as f32 / total as f32) / count as f32,
                    format!("Scanning {target}"),
                );
                result
            },
        )
        .reduce(RegionResult::default, RegionResult::merge);
    context.checkpoint()?;

    let mut findings = result.tally.findings(
        &signatures.database,
        Module::Memory,
        &target,
        Severity::Critical,
    );
    if !result.images.is_empty() {
        let mut finding = Finding::new(
            Module::Memory,
            Severity::High,
            format!("Executable image in private memory of {target}"),
        );
        result.images.iter().for_each(|address| {
            finding.push_evidence(Evidence::Memory {
                pid: process.pid,
                address: *address,
                excerpt: "Manually mapped PE image".to_owned(),
            })
        });
        findings.push(finding);
    }
    findings.extend(inspect_modules(context, process, &memory, &target));
    #[cfg(unix)]
    if let Some(tracer) = tracer(process.pid) {
        findings.push(
            Finding::new(
                Module::Memory,
                Severity::High,
                format!("{target} is being traced through ptrace"),
            )
            .with_evidence(Evidence::Process {
                pid: tracer,
                name: "tracer".to_owned(),
                detail: None,
            }),
        );
    }
    Ok(findings)
}

fn scan_region(
    context: &Context,
    memory: &ProcessMemory,
    pid: u32,
    region: &Region,
    buffer: &mut [u8],
    overlap: usize,
) -> RegionResult {
    let mut result = RegionResult::default();
    let mut offset = 0usize;
    while offset < region.size {
        let length = (CHUNK_SIZE + overlap).min(region.size - offset);
        let address = region.base + offset as u64;
        let Ok(read) = memory.read(address, &mut buffer[..length]) else {
            offset += CHUNK_SIZE;
            continue;
        };
        let chunk = &buffer[..read];
        if offset == 0 && region.is_injection_candidate() && is_pe_image(chunk) {
            result.images.push(address);
        }
        context
            .signatures
            .record(&mut result.tally, chunk, None, |hit| Evidence::Memory {
                pid,
                address: address + hit.start as u64,
                excerpt: excerpt(chunk, hit.start, hit.end),
            });
        offset += CHUNK_SIZE;
    }
    result
}

fn is_pe_image(chunk: &[u8]) -> bool {
    chunk.starts_with(DOS_SIGNATURE)
        && chunk
            .get(PE_POINTER_OFFSET..PE_POINTER_OFFSET + 4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
            .and_then(|pointer| chunk.get(pointer..pointer + PE_SIGNATURE.len()))
            == Some(PE_SIGNATURE)
}

fn inspect_modules(
    context: &Context,
    process: &ProcessRecord,
    memory: &ProcessMemory,
    target: &str,
) -> Vec<Finding> {
    let database = &context.signatures.database;
    let java_home = process
        .executable
        .as_deref()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(|home| home.to_string_lossy().to_ascii_lowercase());
    let foreign: Vec<_> = memory
        .modules()
        .into_iter()
        .filter(|module| {
            let normalized = module.to_string_lossy().to_ascii_lowercase();
            !paths::contains_any(module, &database.trusted_module_directories)
                && !paths::contains_any(module, &database.trusted_module_names)
                && java_home
                    .as_deref()
                    .is_none_or(|home| !normalized.starts_with(home))
        })
        .collect();
    if foreign.is_empty() {
        return Vec::new();
    }

    let mut listing = Finding::new(
        Module::Memory,
        Severity::Low,
        format!(
            "{} unrecognised native modules loaded in {target}",
            foreign.len()
        ),
    );
    foreign.iter().for_each(|module| {
        listing.push_evidence(Evidence::File {
            path: module.clone(),
            detail: None,
        })
    });
    let mut findings = vec![listing];
    findings.extend(
        foreign
            .iter()
            .flat_map(|module| files::analyze(context, module)),
    );
    findings
}
