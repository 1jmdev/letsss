//! USN journal review: deleted Prefetch files and JARs replaced during the session.

use std::collections::HashSet;

use usn_journal_rs::{UsnError, UsnReason, volume::Volume};

use crate::{
    artifacts::inspection::{listing, tracked_extension},
    context::Context,
    finding::{Evidence, Finding, Severity},
    options::Module,
    paths, system,
};

#[derive(Default)]
struct Observations {
    prefetch_deleted: Vec<(String, u64)>,
    jars_removed: Vec<(String, u64)>,
    jars_removed_in_game: Vec<(String, u64)>,
    jars_modified_in_game: Vec<(String, u64)>,
    renamed_to_jar: Vec<(String, u64)>,
    client_files: Vec<(String, String, u64)>,
}

pub fn inspect(context: &Context) -> Vec<Finding> {
    match observe(context) {
        Ok(observations) => summarize(observations),
        Err(error) => vec![
            Finding::new(
                Module::Artifacts,
                Severity::Low,
                "USN journal could not be read",
            )
            .with_evidence(Evidence::Text {
                detail: error.to_string(),
            }),
        ],
    }
}

fn observe(context: &Context) -> Result<Observations, UsnError> {
    let database = &context.signatures.database;
    let boot = context.system.boot_time;
    let game_start = context
        .system
        .game_processes()
        .map(|process| process.start_time)
        .min();
    let volume = Volume::from_drive_letter(paths::system_drive())?;
    let journal = volume.journal();
    // Querying first guarantees the iterator below never creates a journal on a volume without one.
    journal.query()?;
    let resolver = volume.path_resolver();
    let mut seen = HashSet::new();
    let mut observations = Observations::default();

    for entry in journal.try_iter()?.flatten() {
        let timestamp = entry.time.to_unix_seconds().max(0) as u64;
        let name = entry.file_name.to_string_lossy();
        let Some(extension) = tracked_extension(&name).filter(|_| timestamp >= boot) else {
            continue;
        };
        let deleted = entry
            .reason
            .intersects(UsnReason::FILE_DELETE | UsnReason::RENAME_OLD_NAME);
        let modified = entry.reason.intersects(
            UsnReason::DATA_OVERWRITE | UsnReason::DATA_EXTEND | UsnReason::DATA_TRUNCATION,
        );
        let renamed_in = entry.reason.contains(UsnReason::RENAME_NEW_NAME);
        if !seen.insert((entry.fid, deleted, modified, renamed_in)) {
            continue;
        }
        let in_game = game_start.is_some_and(|start| timestamp >= start);
        let location = resolver
            .resolve_path(&entry)
            .map_or_else(|| name.to_string(), |path| path.display().to_string());
        let detail = (
            format!("{location} — {}", system::format_time(timestamp)),
            timestamp,
        );

        if let Some(client) = database.client_for_file_name(&name) {
            observations
                .client_files
                .push((client.name.clone(), detail.0.clone(), timestamp));
        }
        match extension.as_str() {
            "pf" if deleted => observations.prefetch_deleted.push(detail),
            "jar" if deleted && in_game => observations.jars_removed_in_game.push(detail),
            "jar" if deleted => observations.jars_removed.push(detail),
            "jar" if modified && in_game => observations.jars_modified_in_game.push(detail),
            "jar" if renamed_in => observations.renamed_to_jar.push(detail),
            _ => {}
        }
    }
    Ok(observations)
}

fn summarize(observations: Observations) -> Vec<Finding> {
    let mut findings: Vec<Finding> = [
        (
            Severity::High,
            "Prefetch files deleted since boot",
            observations.prefetch_deleted,
        ),
        (
            Severity::High,
            "JARs deleted or renamed while the game was running",
            observations.jars_removed_in_game,
        ),
        (
            Severity::High,
            "JARs modified while the game was running",
            observations.jars_modified_in_game,
        ),
        (
            Severity::Medium,
            "JARs deleted or renamed since boot",
            observations.jars_removed,
        ),
        (
            Severity::Low,
            "Files renamed to JAR since boot",
            observations.renamed_to_jar,
        ),
    ]
    .into_iter()
    .filter_map(|(severity, title, entries)| {
        let count = entries.len();
        listing(severity, format!("{title} ({count})"), entries)
    })
    .collect();

    findings.extend(
        observations
            .client_files
            .into_iter()
            .map(|(client, detail, timestamp)| {
                Finding::new(
                    Module::Artifacts,
                    Severity::High,
                    format!("File associated with {client} changed since boot"),
                )
                .with_client(client)
                .with_evidence(Evidence::Text { detail })
                .with_timestamp(timestamp)
            }),
    );
    findings
}
