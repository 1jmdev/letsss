//! Event log records of log clearing, journal deletion, and clock or service tampering.

use crate::{
    context::Context,
    finding::{Evidence, Finding, Severity},
    options::Module,
    system,
};

const RECORD_LIMIT: &str = "/c:20";
const RECORD_SEPARATOR: &str = "Event[";
const TIME_SERVICE_PROCESS: &str = "svchost.exe";

struct EventCheck {
    log: &'static str,
    id: u32,
    severity: Severity,
    title: &'static str,
    /// Only records containing one of these fragments count; empty accepts every record.
    required: &'static [&'static str],
    /// Records containing any of these fragments are ignored.
    excluded: &'static [&'static str],
}

const EVENT_CHECKS: [EventCheck; 6] = [
    EventCheck {
        log: "Security",
        id: 1102,
        severity: Severity::High,
        title: "Security log was cleared",
        required: &[],
        excluded: &[],
    },
    EventCheck {
        log: "System",
        id: 104,
        severity: Severity::High,
        title: "An event log was cleared",
        required: &[],
        excluded: &[],
    },
    EventCheck {
        log: "Application",
        id: 3079,
        severity: Severity::High,
        title: "USN journal was deleted",
        required: &[],
        excluded: &[],
    },
    EventCheck {
        log: "System",
        id: 1,
        severity: Severity::High,
        title: "FileInfo filter driver was unloaded",
        required: &["FileInfo"],
        excluded: &[],
    },
    EventCheck {
        log: "System",
        id: 7040,
        severity: Severity::High,
        title: "Forensic service start type was changed",
        required: &[
            "SysMain",
            "Superfetch",
            "Windows Event Log",
            "Background Activity",
            "Program Compatibility",
        ],
        excluded: &[],
    },
    EventCheck {
        log: "Security",
        id: 4616,
        severity: Severity::Medium,
        title: "System time was changed manually",
        required: &[],
        excluded: &[TIME_SERVICE_PROCESS],
    },
];

pub fn inspect(context: &Context) -> Vec<Finding> {
    let window = system::now()
        .saturating_sub(context.system.boot_time)
        .max(1)
        * 1_000;
    EVENT_CHECKS
        .iter()
        .filter_map(|check| {
            let query = format!(
                "/q:*[System[(EventID={}) and TimeCreated[timediff(@SystemTime) <= {window}]]]",
                check.id
            );
            let output = system::run_command(
                "wevtutil",
                &["qe", check.log, &query, "/f:text", "/rd:true", RECORD_LIMIT],
            )
            .ok()?;
            let records: Vec<&str> = output
                .split(RECORD_SEPARATOR)
                .map(str::trim)
                .filter(|record| !record.is_empty())
                .filter(|record| {
                    check.required.is_empty()
                        || check
                            .required
                            .iter()
                            .any(|fragment| record.contains(fragment))
                })
                .filter(|record| {
                    !check
                        .excluded
                        .iter()
                        .any(|fragment| record.contains(fragment))
                })
                .collect();
            if records.is_empty() {
                return None;
            }
            let mut finding = Finding::new(
                Module::Bypass,
                check.severity,
                format!("{} since boot ({})", check.title, records.len()),
            );
            records.into_iter().for_each(|record| {
                finding.push_evidence(Evidence::Event {
                    log: check.log.to_owned(),
                    id: check.id,
                    record: record.to_owned(),
                })
            });
            Some(finding)
        })
        .collect()
}
