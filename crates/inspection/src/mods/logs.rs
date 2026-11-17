//! Client signatures in game logs and crash reports, excluding chat lines.

use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::SystemTime,
};

use flate2::read::GzDecoder;

use crate::{
    finding::{Evidence, Finding, Severity},
    options::Module,
    signatures::{Signatures, Subject, Tally, excerpt},
    system,
};

const LOG_LIMIT: usize = 20;
const CHAT_MARKER: &str = "[CHAT]";
const LOG_DIRECTORIES: [&str; 2] = ["logs", "crash-reports"];
const LOG_EXTENSIONS: [&str; 3] = ["log", "gz", "txt"];

pub fn inspect(signatures: &Signatures, game_directory: &Path) -> Vec<Finding> {
    let mut logs: Vec<(SystemTime, PathBuf)> = LOG_DIRECTORIES
        .iter()
        .filter_map(|directory| fs::read_dir(game_directory.join(directory)).ok())
        .flatten()
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| LOG_EXTENSIONS.iter().any(|known| extension == *known))
        })
        .filter_map(|entry| Some((entry.metadata().ok()?.modified().ok()?, entry.path())))
        .collect();
    logs.sort_unstable_by(|left, right| right.0.cmp(&left.0));

    logs.into_iter()
        .take(LOG_LIMIT)
        .flat_map(|(modified, path)| {
            let Some(text) = read(&path) else {
                return Vec::new();
            };
            let mut tally = Tally::new();
            for line in text.lines().filter(|line| !line.contains(CHAT_MARKER)) {
                signatures.clients.scan(line.as_bytes(), |hit| {
                    if matches!(hit.subject, Subject::Client(_)) {
                        tally.record(&hit, || Evidence::File {
                            path: path.clone(),
                            detail: Some(excerpt(line.as_bytes(), hit.start, hit.end)),
                        });
                    }
                });
            }
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            tally
                .findings(
                    &signatures.database,
                    Module::Mods,
                    &format!("game log {name}"),
                    Severity::High,
                )
                .into_iter()
                .map(|finding| finding.with_timestamp(system::unix_seconds(modified)))
                .collect()
        })
        .collect()
}

fn read(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    if path.extension().is_some_and(|extension| extension == "gz") {
        GzDecoder::new(File::open(path).ok()?)
            .read_to_end(&mut bytes)
            .ok()?;
    } else {
        bytes = fs::read(path).ok()?;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}
