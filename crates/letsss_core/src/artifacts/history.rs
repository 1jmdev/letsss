//! Linux shell history and recently used file records.

use std::{fs, path::Path};

use crate::{
    context::Context,
    finding::{Evidence, Finding, Severity},
    options::Module,
    paths,
    signatures::{Subject, Tally, excerpt},
};

const HISTORY_FILES: [&str; 4] = [
    ".bash_history",
    ".zsh_history",
    ".history",
    ".local/share/fish/fish_history",
];
const SUSPICIOUS_COMMANDS: [(&str, Severity); 14] = [
    ("xdotool", Severity::Medium),
    ("ydotool", Severity::Medium),
    ("LD_PRELOAD", Severity::High),
    ("gdb -p", Severity::High),
    ("ptrace", Severity::Medium),
    ("injector", Severity::High),
    ("java -jar", Severity::Low),
    ("-javaagent", Severity::High),
    ("history -c", Severity::High),
    ("unset HISTFILE", Severity::High),
    ("shred", Severity::Medium),
    ("/mods/", Severity::Low),
    ("rm -rf ~/.minecraft", Severity::Medium),
    ("journalctl --vacuum", Severity::High),
];
const RECENT_FILES: &str = ".local/share/recently-used.xbel";
const FILE_URI: &str = "href=\"file://";

pub fn inspect(context: &Context) -> Vec<Finding> {
    let home = paths::home();
    let mut findings = Vec::new();
    for relative in HISTORY_FILES {
        let path = home.join(relative);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        findings.extend(inspect_history(context, &path, &text));
    }
    findings.extend(inspect_recent(context, &home.join(RECENT_FILES)));
    findings
}

fn inspect_history(context: &Context, path: &Path, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (command, severity) in SUSPICIOUS_COMMANDS {
        let lines: Vec<&str> = text.lines().filter(|line| line.contains(command)).collect();
        if lines.is_empty() {
            continue;
        }
        let mut finding = Finding::new(
            Module::Artifacts,
            severity,
            format!("Shell history contains \"{command}\" ({})", lines.len()),
        )
        .with_evidence(Evidence::File {
            path: path.to_path_buf(),
            detail: None,
        });
        lines.into_iter().for_each(|line| {
            finding.push_evidence(Evidence::Text {
                detail: line.to_owned(),
            })
        });
        findings.push(finding);
    }
    let mut tally = Tally::new();
    context.signatures.clients.scan(text.as_bytes(), |hit| {
        if matches!(hit.subject, Subject::Client(_)) {
            tally.record(&hit, || Evidence::File {
                path: path.to_path_buf(),
                detail: Some(excerpt(text.as_bytes(), hit.start, hit.end)),
            });
        }
    });
    findings.extend(tally.findings(
        &context.signatures.database,
        Module::Artifacts,
        "shell history",
        Severity::High,
    ));
    findings
}

fn inspect_recent(context: &Context, path: &Path) -> Vec<Finding> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let database = &context.signatures.database;
    let mut findings = Vec::new();
    let mut missing = Vec::new();
    for location in text
        .split(FILE_URI)
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .filter(|location| location.ends_with(".jar") || location.ends_with(".AppImage"))
    {
        let decoded = location.replace("%20", " ");
        if let Some(client) = database.client_for_file_name(&decoded) {
            findings.push(
                Finding::new(
                    Module::Artifacts,
                    Severity::High,
                    format!("Recently used file associated with {}", client.name),
                )
                .with_client(&client.name)
                .with_evidence(Evidence::Text {
                    detail: decoded.clone(),
                }),
            );
        }
        if !Path::new(&decoded).exists() {
            missing.push(Evidence::Text { detail: decoded });
        }
    }
    if !missing.is_empty() {
        let mut finding = Finding::new(
            Module::Artifacts,
            Severity::Low,
            format!("{} recently used JARs no longer exist", missing.len()),
        );
        missing
            .into_iter()
            .for_each(|evidence| finding.push_evidence(evidence));
        findings.push(finding);
    }
    findings
}
