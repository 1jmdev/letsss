//! Windows Prefetch review backed by `frnsc-prefetch`, including MAM-compressed Windows 10+ files.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use forensic_rs::prelude::{StdVirtualFS, VirtualFileSystem};
use frnsc_prefetch::prelude::{PrefetchFile, read_prefetch_file};

use crate::{
    artifacts::inspection::listing,
    context::Context,
    finding::{Evidence, Finding, Severity},
    options::Module,
    platform::{self, Volume},
    signatures::{Subject, Tally},
    system,
};

const JAVA_EXECUTABLES: [&str; 2] = ["JAVA.EXE", "JAVAW.EXE"];
const LIBRARY_FRAGMENT: &str = "\\LIBRARIES\\";

pub fn inspect(context: &Context, volumes: &[Volume]) -> Vec<Finding> {
    let database = &context.signatures.database;
    let boot = context.system.boot_time;
    let directory = env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("Prefetch");
    let Ok(listing_entries) = fs::read_dir(&directory) else {
        return vec![Finding::new(
            Module::Artifacts,
            Severity::Low,
            "Prefetch folder is not readable; run as administrator",
        )];
    };
    let mut filesystem = StdVirtualFS::new();
    let entries: Vec<PrefetchFile> = listing_entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("pf"))
        })
        .filter_map(|path| parse(&mut filesystem, &path))
        .collect();

    let mut findings = Vec::new();
    let mut vanished = Vec::new();
    let mut missing_jars = Vec::new();
    let mut java_jars = Vec::new();

    for entry in &entries {
        let last_run = last_run(entry);
        let stamp = |detail: String| (detail, last_run);
        let mut tally = Tally::new();
        for file in entry.metrics.iter().map(|metric| &metric.file) {
            context.signatures.clients.scan(file.as_bytes(), |hit| {
                if matches!(hit.subject, Subject::Client(_)) {
                    tally.record(&hit, || Evidence::Text {
                        detail: file.clone(),
                    });
                }
            });
        }
        findings.extend(
            tally
                .findings(
                    database,
                    Module::Artifacts,
                    &format!("prefetch of {}", entry.name),
                    Severity::High,
                )
                .into_iter()
                .map(|finding| finding.with_timestamp(last_run)),
        );
        if let Some(client) = database.client_for_file_name(&entry.name) {
            findings.push(
                Finding::new(
                    Module::Artifacts,
                    Severity::High,
                    format!("{} was executed ({} runs)", entry.name, entry.run_count),
                )
                .with_client(&client.name)
                .with_timestamp(last_run),
            );
        }
        if last_run < boot {
            continue;
        }
        if let Some(image) = image_path(entry)
            && let Some(resolved) = platform::resolve(volumes, image)
            && !resolved.exists()
        {
            vanished.push(stamp(format!(
                "{} — last run {}",
                resolved.display(),
                system::format_time(last_run)
            )));
        }
        if JAVA_EXECUTABLES.contains(&entry.name.as_str()) {
            for jar in entry
                .metrics
                .iter()
                .map(|metric| &metric.file)
                .filter(|file| file.ends_with(".JAR") && !file.contains(LIBRARY_FRAGMENT))
            {
                let resolved = platform::resolve(volumes, jar);
                let detail = resolved
                    .as_deref()
                    .map_or_else(|| jar.clone(), |path| path.display().to_string());
                if resolved.is_some_and(|path| !path.exists()) {
                    missing_jars.push(stamp(detail));
                } else {
                    java_jars.push(stamp(detail));
                }
            }
        }
    }

    findings.extend(listing(
        Severity::Medium,
        "Programs executed since boot no longer exist".to_owned(),
        vanished,
    ));
    findings.extend(listing(
        Severity::High,
        "JARs loaded by Java since boot no longer exist".to_owned(),
        missing_jars,
    ));
    findings.extend(listing(
        Severity::Informational,
        "JARs loaded by Java since boot".to_owned(),
        java_jars,
    ));
    findings.push(Finding::new(
        Module::Artifacts,
        Severity::Informational,
        format!(
            "{} Prefetch entries parsed, {} executed since boot",
            entries.len(),
            entries
                .iter()
                .filter(|entry| last_run(entry) >= boot)
                .count()
        ),
    ));
    findings
}

fn parse(filesystem: &mut StdVirtualFS, path: &Path) -> Option<PrefetchFile> {
    let name = path.file_name()?.to_str()?;
    read_prefetch_file(name, filesystem.open(path).ok()?).ok()
}

fn last_run(entry: &PrefetchFile) -> u64 {
    entry
        .last_run_times
        .iter()
        .map(|time| system::filetime_to_unix(time.filetime()))
        .max()
        .unwrap_or(0)
}

fn image_path(entry: &PrefetchFile) -> Option<&str> {
    let suffix = format!("\\{}", entry.name);
    entry
        .metrics
        .iter()
        .map(|metric| metric.file.as_str())
        .find(|file| file.ends_with(&suffix))
}
