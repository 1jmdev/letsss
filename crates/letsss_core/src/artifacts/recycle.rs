//! Recently deleted files in the Windows Recycle Bin or the freedesktop Trash.

use std::fs;

use crate::{
    artifacts::inspection::{listing, tracked_extension},
    context::Context,
    finding::{Evidence, Finding, Severity},
    options::Module,
    paths, system,
};

const LOOKBACK_SECONDS: u64 = 7 * 86_400;

struct Deletion {
    path: String,
    timestamp: u64,
}

pub fn inspect(context: &Context) -> Vec<Finding> {
    let database = &context.signatures.database;
    let since = system::now().saturating_sub(LOOKBACK_SECONDS);
    let deletions: Vec<Deletion> = deletions()
        .into_iter()
        .filter(|deletion| {
            deletion.timestamp >= since && tracked_extension(&deletion.path).is_some()
        })
        .collect();

    let mut findings: Vec<Finding> = deletions
        .iter()
        .filter_map(|deletion| {
            let client = database.client_for_file_name(&deletion.path)?;
            Some(
                Finding::new(
                    Module::Artifacts,
                    Severity::High,
                    format!("File associated with {} in the recycle bin", client.name),
                )
                .with_client(&client.name)
                .with_evidence(Evidence::Text {
                    detail: deletion.path.clone(),
                })
                .with_timestamp(deletion.timestamp),
            )
        })
        .collect();
    let count = deletions.len();
    findings.extend(listing(
        Severity::Low,
        format!("{count} executables or archives deleted in the last 7 days"),
        deletions.into_iter().map(|deletion| {
            (
                format!(
                    "{} — {}",
                    deletion.path,
                    system::format_time(deletion.timestamp)
                ),
                deletion.timestamp,
            )
        }),
    ));
    findings
}

#[cfg(windows)]
fn deletions() -> Vec<Deletion> {
    let drive = paths::system_drive();
    let Ok(users) = fs::read_dir(format!("{drive}:\\$Recycle.Bin")) else {
        return Vec::new();
    };
    users
        .flatten()
        .filter_map(|user| fs::read_dir(user.path()).ok())
        .flatten()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("$I"))
        .filter_map(|entry| parse_index(&fs::read(entry.path()).ok()?))
        .collect()
}

#[cfg(windows)]
fn parse_index(data: &[u8]) -> Option<Deletion> {
    let version = u64::from_le_bytes(data.get(..8)?.try_into().ok()?);
    let filetime = u64::from_le_bytes(data.get(16..24)?.try_into().ok()?);
    let name = if version >= 2 {
        let length = u32::from_le_bytes(data.get(24..28)?.try_into().ok()?) as usize;
        data.get(28..28 + length * 2)?
    } else {
        data.get(24..)?
    };
    Some(Deletion {
        path: utf16(name).trim_end_matches('\0').to_owned(),
        timestamp: system::filetime_to_unix(filetime),
    })
}

#[cfg(unix)]
fn deletions() -> Vec<Deletion> {
    let Ok(entries) = fs::read_dir(paths::data().join("Trash").join("info")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let text = fs::read_to_string(entry.path()).ok()?;
            let path = text
                .lines()
                .find_map(|line| line.strip_prefix("Path="))?
                .to_owned();
            let timestamp = system::unix_seconds(entry.metadata().ok()?.modified().ok()?);
            Some(Deletion { path, timestamp })
        })
        .collect()
}

#[cfg(windows)]
fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}
