//! Artifact module entry point and helpers shared by artifact parsers.

use std::path::Path;

#[cfg(unix)]
use crate::artifacts::history;
use crate::{
    artifacts::recycle,
    context::Context,
    error::Result,
    finding::{Evidence, Finding, Severity},
    options::Module,
};
#[cfg(windows)]
use crate::{
    artifacts::{execution, journal, prefetch},
    platform,
};

pub const TRACKED_EXTENSIONS: [&str; 12] = [
    "jar", "exe", "dll", "pf", "bat", "cmd", "ps1", "ahk", "py", "zip", "rar", "7z",
];
#[cfg(windows)]
const VOLATILE_FRAGMENTS: [&str; 6] = [
    "\\temp\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\appdata\\",
    "/tmp/",
    "/downloads/",
];

pub fn inspect(context: &Context) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    #[cfg(windows)]
    {
        let volumes = platform::volumes();
        context.report(Module::Artifacts, 0.1, "Prefetch");
        findings.extend(prefetch::inspect(context, &volumes));
        context.checkpoint()?;
        context.report(Module::Artifacts, 0.4, "USN journal");
        findings.extend(journal::inspect(context));
        context.checkpoint()?;
        context.report(Module::Artifacts, 0.7, "Background activity moderator");
        findings.extend(execution::inspect(context, &volumes));
    }
    #[cfg(unix)]
    {
        context.report(Module::Artifacts, 0.3, "Shell history");
        findings.extend(history::inspect(context));
    }
    context.report(Module::Artifacts, 0.9, "Recycle bin");
    findings.extend(recycle::inspect(context));
    Ok(findings)
}

/// Lowercase extension of a file name when it is one of [`TRACKED_EXTENSIONS`].
pub fn tracked_extension(name: &str) -> Option<String> {
    let extension = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    TRACKED_EXTENSIONS
        .contains(&extension.as_str())
        .then_some(extension)
}

#[cfg(windows)]
pub fn is_volatile(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase();
    VOLATILE_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

/// Builds one finding listing `entries`, stamped with the latest entry time.
pub fn listing(
    severity: Severity,
    title: String,
    entries: impl IntoIterator<Item = (String, u64)>,
) -> Option<Finding> {
    let mut finding = Finding::new(Module::Artifacts, severity, title);
    let mut latest = None;
    for (detail, timestamp) in entries {
        latest = latest.max(Some(timestamp));
        finding.push_evidence(Evidence::Text { detail });
    }
    latest.map(|timestamp| finding.with_timestamp(timestamp))
}
