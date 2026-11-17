//! JVM command-line and environment analysis of running Java processes.

use std::path::{Path, PathBuf};

use crate::{
    context::Context,
    error::Result,
    finding::{Evidence, Finding, Severity},
    options::Module,
    paths,
    system::ProcessRecord,
};

const AGENT_PREFIXES: [&str; 3] = ["-javaagent:", "-agentpath:", "-agentlib:"];
const OPTION_VARIABLES: [&str; 3] = ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"];
const PRELOAD_VARIABLE: &str = "LD_PRELOAD";
const CLASSPATH_FLAGS: [&str; 3] = ["-cp", "-classpath", "--class-path"];
const CLASSPATH_PROPERTY: &str = "-Djava.class.path=";
const LIBRARY_DIRECTORY: &str = "libraries";

pub fn inspect(context: &Context) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for process in context.system.game_processes() {
        findings.extend(inspect_process(context, process));
    }
    Ok(findings)
}

/// JAR files on the class path of `process` that do not come from a launcher library store.
pub fn classpath_archives(process: &ProcessRecord) -> Vec<PathBuf> {
    let separator = if cfg!(windows) { ';' } else { ':' };
    let flagged = process
        .command
        .windows(2)
        .filter(|pair| CLASSPATH_FLAGS.contains(&pair[0].as_str()))
        .map(|pair| pair[1].as_str());
    let property = process
        .command
        .iter()
        .filter_map(|argument| argument.strip_prefix(CLASSPATH_PROPERTY));
    flagged
        .chain(property)
        .flat_map(|classpath| classpath.split(separator))
        .map(PathBuf::from)
        .filter(|entry| {
            entry
                .extension()
                .is_some_and(|extension| extension == "jar")
                && !entry
                    .components()
                    .any(|component| component.as_os_str() == LIBRARY_DIRECTORY)
        })
        .collect()
}

fn inspect_process(context: &Context, process: &ProcessRecord) -> Vec<Finding> {
    let database = &context.signatures.database;
    let target = format!("{} ({})", process.name, process.pid);
    let evidence = |detail: &str| Evidence::Process {
        pid: process.pid,
        name: process.name.clone(),
        detail: Some(detail.to_owned()),
    };
    let mut findings = Vec::new();

    for argument in &process.command {
        let Some(flag) = database
            .launch_flags
            .iter()
            .find(|flag| argument.starts_with(&flag.prefix))
        else {
            continue;
        };
        let agent = AGENT_PREFIXES
            .iter()
            .any(|prefix| argument.starts_with(prefix));
        let legitimate = agent
            && database
                .legitimate_agents
                .iter()
                .any(|known| argument.to_ascii_lowercase().contains(known.as_str()));
        let severity = if legitimate {
            Severity::Informational
        } else {
            flag.severity
        };
        findings.push(
            Finding::new(
                Module::LaunchArguments,
                severity,
                format!("{} in {target}", flag.title),
            )
            .with_evidence(evidence(argument)),
        );
    }

    for variable in OPTION_VARIABLES {
        let Some(value) = process.variable(variable) else {
            continue;
        };
        let severity = if AGENT_PREFIXES.iter().any(|prefix| value.contains(prefix)) {
            Severity::High
        } else {
            Severity::Low
        };
        findings.push(
            Finding::new(
                Module::LaunchArguments,
                severity,
                format!("JVM options injected through {variable} in {target}"),
            )
            .with_evidence(evidence(value)),
        );
    }

    if let Some(value) = process
        .variable(PRELOAD_VARIABLE)
        .filter(|value| !value.is_empty())
    {
        findings.push(
            Finding::new(
                Module::LaunchArguments,
                Severity::High,
                format!("Shared library preloaded into {target}"),
            )
            .with_evidence(evidence(value)),
        );
    }

    let attach_file = paths::temp().join(format!(".attach_pid{}", process.pid));
    if attach_file.exists() {
        findings.push(
            Finding::new(
                Module::LaunchArguments,
                Severity::Medium,
                format!("JVM attach handshake performed on {target}"),
            )
            .with_evidence(Evidence::File {
                path: attach_file,
                detail: Some("Runtime agent injection uses this mechanism".to_owned()),
            }),
        );
    }

    let foreign: Vec<PathBuf> = classpath_archives(process)
        .into_iter()
        .filter(|entry| !in_versions_directory(entry))
        .collect();
    if !foreign.is_empty() {
        let mut finding = Finding::new(
            Module::LaunchArguments,
            Severity::Medium,
            format!("Class path of {target} contains JARs outside the launcher library store"),
        );
        foreign
            .into_iter()
            .for_each(|path| finding.push_evidence(Evidence::File { path, detail: None }));
        findings.push(finding);
    }
    findings
}

fn in_versions_directory(path: &Path) -> bool {
    path.parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .is_some_and(|name| name == "versions")
}
