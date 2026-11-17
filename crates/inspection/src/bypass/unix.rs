//! Linux anti-forensic configuration: discarded shell history and global preloads.

use std::fs;

use crate::{
    context::Context,
    error::Result,
    finding::{Evidence, Finding, Severity},
    options::Module,
    paths,
};

const HISTORY_FILES: [&str; 3] = [
    ".bash_history",
    ".zsh_history",
    ".local/share/fish/fish_history",
];
const GLOBAL_PRELOAD: &str = "/etc/ld.so.preload";
const NULL_DEVICE: &str = "/dev/null";
const SHELLS: [&str; 3] = ["bash", "zsh", "fish"];

pub fn inspect(context: &Context) -> Result<Vec<Finding>> {
    context.report(Module::Bypass, 0.5, "Shell and loader configuration");
    let home = paths::home();
    let mut findings = Vec::new();

    for relative in HISTORY_FILES {
        let path = home.join(relative);
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        let target = fs::read_link(&path).ok();
        if target
            .as_deref()
            .is_some_and(|target| target.as_os_str() == NULL_DEVICE)
        {
            findings.push(
                Finding::new(
                    Module::Bypass,
                    Severity::High,
                    "Shell history is redirected to /dev/null",
                )
                .with_evidence(Evidence::File { path, detail: None }),
            );
        } else if metadata.len() == 0 {
            findings.push(
                Finding::new(
                    Module::Bypass,
                    Severity::Medium,
                    "Shell history file is empty",
                )
                .with_evidence(Evidence::File { path, detail: None }),
            );
        }
    }

    if let Ok(preload) = fs::read_to_string(GLOBAL_PRELOAD)
        && !preload.trim().is_empty()
    {
        findings.push(
            Finding::new(
                Module::Bypass,
                Severity::High,
                "System-wide library preload is configured",
            )
            .with_evidence(Evidence::File {
                path: GLOBAL_PRELOAD.into(),
                detail: Some(preload.trim().to_owned()),
            }),
        );
    }

    for process in context
        .system
        .processes
        .iter()
        .filter(|process| SHELLS.contains(&process.name.as_str()))
    {
        let discarded = process.variable("HISTFILE") == Some(NULL_DEVICE)
            || process.variable("HISTSIZE") == Some("0");
        if discarded {
            findings.push(
                Finding::new(
                    Module::Bypass,
                    Severity::Medium,
                    "Shell session discards its history",
                )
                .with_evidence(Evidence::Process {
                    pid: process.pid,
                    name: process.name.clone(),
                    detail: None,
                }),
            );
        }
    }
    Ok(findings)
}
