//! Mod discovery, verification, and per-archive findings.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use rayon::prelude::*;
use serde::{Serialize, de::IgnoredAny};
use sha1::{Digest, Sha1};
use walkdir::{DirEntry, WalkDir};

use crate::{
    context::Context,
    error::Result,
    finding::{Evidence, Finding, Severity},
    launch_arguments,
    mods::{archive, logs, obfuscation},
    options::Module,
    paths,
    signatures::SourceRating,
    system,
};

const MOD_DIRECTORY: &str = "mods";
const VERSIONS_DIRECTORY: &str = "versions";
const DISABLED_SUFFIX: &str = ".disabled";
const ZIP_SIGNATURE: &[u8] = b"PK\x03\x04";
const HOLLOW_CLASS_LIMIT: usize = 3;
const ARCHIVE_SIZE_LIMIT: u64 = 256 << 20;
const ENDPOINT: &str = "https://api.modrinth.com/v2/version_files";
const USER_AGENT: &str = concat!("letsSS/", env!("CARGO_PKG_VERSION"));
const TIMEOUT: Duration = Duration::from_secs(20);
const ALGORITHM: &str = "sha1";
const ORIGIN_KEYS: [&str; 2] = ["HostUrl=", "ReferrerUrl="];

#[derive(Serialize)]
struct Request<'a> {
    hashes: &'a [String],
    algorithm: &'static str,
}

struct Candidate {
    path: PathBuf,
    bytes: Vec<u8>,
    hash: String,
}

pub fn inspect(context: &Context) -> Result<Vec<Finding>> {
    let directories = paths::game_directories(context.system);
    let mut findings = Vec::new();
    let mut archives = Vec::new();

    for directory in &directories {
        let mods = directory.join(MOD_DIRECTORY);
        collect_archives(&mods, 2, &mut archives);
        if let Some(finding) = modified_during_session(context, &mods) {
            findings.push(finding);
        }
        collect_archives(&directory.join(VERSIONS_DIRECTORY), 2, &mut archives);
    }
    archives.extend(
        context
            .system
            .game_processes()
            .flat_map(launch_arguments::classpath_archives)
            .filter(|path| path.is_file()),
    );
    for path in &context.options.paths {
        if path.is_dir() {
            collect_archives(path, 2, &mut archives);
        } else if path.extension().is_some_and(|extension| extension == "jar") {
            archives.push(path.clone());
        }
    }
    archives.sort_unstable();
    archives.dedup();

    let candidates: Vec<Candidate> = archives
        .into_par_iter()
        .filter_map(|path| {
            let bytes = fs::read(&path).ok()?;
            let hash = Sha1::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            Some(Candidate { path, bytes, hash })
        })
        .collect();

    let published = if context.options.online {
        let hashes: Vec<String> = candidates
            .iter()
            .map(|candidate| candidate.hash.clone())
            .collect();
        published(&hashes).unwrap_or_else(|error| {
            findings.push(
                Finding::new(
                    Module::Mods,
                    Severity::Informational,
                    "Modrinth verification unavailable",
                )
                .with_evidence(Evidence::Text {
                    detail: error.to_string(),
                }),
            );
            HashSet::new()
        })
    } else {
        HashSet::new()
    };

    let completed = AtomicUsize::new(0);
    let total = candidates.len().max(1);
    findings.extend(
        candidates
            .par_iter()
            .flat_map_iter(|candidate| {
                let findings = assess(context, candidate, published.contains(&candidate.hash));
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                context.report(
                    Module::Mods,
                    done as f32 / total as f32,
                    candidate.path.display().to_string(),
                );
                findings
            })
            .collect::<Vec<_>>(),
    );
    context.checkpoint()?;

    findings.push(
        Finding::new(
            Module::Mods,
            Severity::Informational,
            format!(
                "{} archives inspected, {} published on Modrinth",
                candidates.len(),
                published.len()
            ),
        )
        .with_evidence(Evidence::Text {
            detail: directories
                .iter()
                .map(|directory| directory.display().to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        }),
    );
    findings.extend(
        directories
            .iter()
            .flat_map(|directory| logs::inspect(context.signatures, directory)),
    );
    Ok(findings)
}

fn assess(context: &Context, candidate: &Candidate, published: bool) -> Vec<Finding> {
    let database = &context.signatures.database;
    let path = &candidate.path;
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let file_evidence = |detail: Option<String>| Evidence::File {
        path: path.clone(),
        detail,
    };
    let mut findings = Vec::new();

    if name.ends_with(DISABLED_SUFFIX) {
        findings.push(
            Finding::new(Module::Mods, Severity::Low, format!("Disabled mod {name}"))
                .with_evidence(file_evidence(None)),
        );
    }

    let report = match archive::analyze(context.signatures, &candidate.bytes, path) {
        Ok(report) => report,
        Err(error) => {
            findings.push(
                Finding::new(
                    Module::Mods,
                    Severity::Medium,
                    format!("Unreadable archive {name}"),
                )
                .with_evidence(file_evidence(Some(error.to_string()))),
            );
            return findings;
        }
    };

    if let Some(origin) = download_origin(path) {
        let severity = match database.rate_source(&origin) {
            Some(SourceRating::Suspicious) => Some(Severity::High),
            Some(SourceRating::Risky) => Some(Severity::Low),
            Some(SourceRating::Review) => Some(Severity::Informational),
            Some(SourceRating::Trusted) => None,
            None => Some(Severity::Low),
        };
        if let Some(severity) = severity {
            findings.push(
                Finding::new(
                    Module::Mods,
                    severity,
                    format!("{name} downloaded from {origin}"),
                )
                .with_evidence(file_evidence(Some(origin.clone()))),
            );
        }
    }

    let unpublished = context.options.online && !published;
    if let Some(identifier) = report.mod_id.as_deref()
        && unpublished
        && database
            .impersonated_mods
            .iter()
            .any(|known| known == identifier)
    {
        findings.push(
            Finding::new(
                Module::Mods,
                Severity::High,
                format!("{name} claims mod id \"{identifier}\" but is not a published build"),
            )
            .with_evidence(file_evidence(Some(candidate.hash.clone()))),
        );
    }

    if !published {
        if report.classes.len() <= HOLLOW_CLASS_LIMIT && !report.nested.is_empty() {
            findings.push(
                Finding::new(
                    Module::Mods,
                    Severity::Medium,
                    format!("Hollow loader archive {name}"),
                )
                .with_evidence(file_evidence(Some(report.nested.join(", ")))),
            );
        }
        findings.extend(obfuscation::assess(&report.classes, path, &name));
    }

    let has_client = report.tally.has_client();
    let mut matches = report
        .tally
        .findings(database, Module::Mods, &name, Severity::High);
    if published && !has_client {
        matches.iter_mut().for_each(|finding| {
            finding.severity = finding.severity.min(Severity::Low);
        });
    }
    findings.extend(matches);
    findings
}

fn collect_archives(directory: &Path, depth: usize, archives: &mut Vec<PathBuf>) {
    archives.extend(
        WalkDir::new(directory)
            .max_depth(depth)
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry.file_type().is_file()
                    && entry
                        .metadata()
                        .is_ok_and(|metadata| metadata.len() <= ARCHIVE_SIZE_LIMIT)
                    && is_zip(entry.path())
            })
            .map(DirEntry::into_path),
    );
}

fn is_zip(path: &Path) -> bool {
    let mut signature = [0u8; 4];
    fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut signature))
        .is_ok_and(|_| signature == ZIP_SIGNATURE)
}

fn modified_during_session(context: &Context, directory: &Path) -> Option<Finding> {
    let modified = system::unix_seconds(fs::metadata(directory).ok()?.modified().ok()?);
    let started = context
        .system
        .game_processes()
        .map(|process| process.start_time)
        .min()?;
    (modified > started).then(|| {
        Finding::new(
            Module::Mods,
            Severity::Medium,
            "Mods folder changed while the game was running",
        )
        .with_evidence(Evidence::File {
            path: directory.to_path_buf(),
            detail: None,
        })
        .with_timestamp(modified)
    })
}

/// URL the file was downloaded from, read from the NTFS `Zone.Identifier` stream.
fn download_origin(path: &Path) -> Option<String> {
    let stream = fs::read_to_string(format!("{}:Zone.Identifier", path.display())).ok()?;
    ORIGIN_KEYS.iter().find_map(|key| {
        stream
            .lines()
            .find_map(|line| line.trim().strip_prefix(key))
            .map(str::to_owned)
    })
}

/// Returns the subset of `hashes` that belong to files published on Modrinth.
fn published(hashes: &[String]) -> Result<HashSet<String>> {
    if hashes.is_empty() {
        return Ok(HashSet::new());
    }
    let client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(TIMEOUT)
        .build()?;
    let versions: HashMap<String, IgnoredAny> = client
        .post(ENDPOINT)
        .json(&Request {
            hashes,
            algorithm: ALGORITHM,
        })
        .send()?
        .error_for_status()?
        .json()?;
    Ok(versions.into_keys().collect())
}
