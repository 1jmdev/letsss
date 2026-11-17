//! Target collection for file analysis and deleted-path tracking.

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use rayon::prelude::*;
use walkdir::{DirEntry, WalkDir};

use crate::{
    context::Context,
    error::Result,
    files::binary,
    finding::{Evidence, Finding, Severity},
    options::Module,
};

const WALK_DEPTH: usize = 3;
const TARGET_LIMIT: usize = 6000;
const PATH_LIST_EXTENSION: &str = "txt";
const ARCHIVE_EXTENSION: &str = "jar";
const OWN_NAME_PREFIX: &str = "letsss";
const DELETED_MEDIUM_COUNT: usize = 10;
const EXTENSIONS: [&str; 14] = [
    "exe", "dll", "jar", "bat", "cmd", "ps1", "vbs", "ahk", "py", "sh", "appimage", "so", "scr",
    "com",
];
const SYSTEM_IMAGE_DIRECTORIES: [&str; 8] = [
    "\\windows\\",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib",
    "/snap/",
    "/nix/store/",
    "/opt/",
];
const VOLATILE_DIRECTORIES: [&str; 3] = ["\\temp\\", "\\appdata\\", "/tmp/"];

pub fn inspect(context: &Context) -> Result<Vec<Finding>> {
    let mut targets = Vec::new();
    let mut missing = Vec::new();
    let archives_owned_by_mods = context.options.modules.contains(&Module::Mods);

    for path in &context.options.paths {
        if path.is_dir() {
            walk(path, WALK_DEPTH, &mut targets);
            if archives_owned_by_mods {
                targets.retain(|target| {
                    target
                        .extension()
                        .is_none_or(|extension| extension != ARCHIVE_EXTENSION)
                });
            }
        } else if path
            .extension()
            .is_some_and(|extension| extension == PATH_LIST_EXTENSION)
        {
            read_path_list(path, &mut targets, &mut missing);
        } else if path.is_file() {
            targets.push(path.clone());
        }
    }
    targets.extend(
        context
            .system
            .processes
            .iter()
            .filter(|process| !process.is_java())
            .filter_map(|process| process.executable.clone())
            .filter(|path| {
                let normalized = path.to_string_lossy().to_ascii_lowercase();
                !SYSTEM_IMAGE_DIRECTORIES
                    .iter()
                    .any(|directory| normalized.contains(directory))
            }),
    );
    targets.sort_unstable();
    targets.dedup();
    let own = env::current_exe().ok();
    targets.retain(|target| {
        Some(target) != own.as_ref()
            && !target.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .to_ascii_lowercase()
                    .starts_with(OWN_NAME_PREFIX)
            })
    });
    targets.truncate(TARGET_LIMIT);

    let completed = AtomicUsize::new(0);
    let total = targets.len().max(1);
    let mut findings: Vec<Finding> = targets
        .par_iter()
        .flat_map_iter(|path| {
            if context.checkpoint().is_err() {
                return Vec::new();
            }
            let findings: Vec<Finding> = binary::analyze(context, path)
                .into_iter()
                .map(|finding| finding.with_target(path.display().to_string()))
                .collect();
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            context.report(
                Module::Files,
                done as f32 / total as f32,
                path.display().to_string(),
            );
            findings
        })
        .collect();
    context.checkpoint()?;

    if !missing.is_empty() {
        let volatile = missing.iter().any(|path: &PathBuf| {
            let normalized = path.to_string_lossy().to_ascii_lowercase();
            VOLATILE_DIRECTORIES
                .iter()
                .any(|directory| normalized.contains(directory))
        });
        let severity = if volatile || missing.len() >= DELETED_MEDIUM_COUNT {
            Severity::Medium
        } else {
            Severity::Low
        };
        let mut finding = Finding::new(
            Module::Files,
            severity,
            format!("{} listed paths no longer exist", missing.len()),
        );
        missing
            .into_iter()
            .for_each(|path| finding.push_evidence(Evidence::File { path, detail: None }));
        findings.push(finding);
    }
    findings.push(Finding::new(
        Module::Files,
        Severity::Informational,
        format!("{} files inspected", targets.len()),
    ));
    Ok(findings)
}

fn walk(directory: &Path, depth: usize, targets: &mut Vec<PathBuf>) {
    targets.extend(
        WalkDir::new(directory)
            .max_depth(depth)
            .into_iter()
            .flatten()
            .filter(|entry| entry.file_type().is_file() && has_target_extension(entry.path()))
            .map(DirEntry::into_path),
    );
}

fn has_target_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str()))
}

fn read_path_list(list: &Path, targets: &mut Vec<PathBuf>, missing: &mut Vec<PathBuf>) {
    let Ok(text) = fs::read_to_string(list) else {
        return;
    };
    for line in text
        .lines()
        .map(|line| line.trim().trim_matches('"'))
        .filter(|line| !line.is_empty())
    {
        let path = PathBuf::from(line);
        if !path.exists() {
            missing.push(path);
        } else if path.is_file() && has_target_extension(&path) {
            targets.push(path);
        }
    }
}
