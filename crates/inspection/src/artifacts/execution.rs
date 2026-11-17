//! Background Activity Moderator records of programs executed per user.

use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

use crate::{
    artifacts::inspection::{is_volatile, listing},
    context::Context,
    finding::{Evidence, Finding, Severity},
    options::Module,
    platform::{self, Volume},
    system,
};

const BAM_KEYS: [&str; 2] = [
    r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
];
const DEVICE_PREFIX: &str = r"\Device\";

struct Execution {
    path: String,
    timestamp: u64,
}

pub fn inspect(context: &Context, volumes: &[Volume]) -> Vec<Finding> {
    let database = &context.signatures.database;
    let boot = context.system.boot_time;
    let executions = read_executions();
    let mut findings = Vec::new();
    let mut vanished = Vec::new();
    let mut user_folders = Vec::new();

    for execution in &executions {
        let detail = || {
            (
                format!(
                    "{} — {}",
                    execution.path,
                    system::format_time(execution.timestamp)
                ),
                execution.timestamp,
            )
        };
        if let Some(client) = database.client_for_file_name(&execution.path) {
            findings.push(
                Finding::new(
                    Module::Artifacts,
                    Severity::High,
                    format!("{} executed according to BAM", client.name),
                )
                .with_client(&client.name)
                .with_evidence(Evidence::Text { detail: detail().0 })
                .with_timestamp(execution.timestamp),
            );
        }
        if execution.timestamp < boot {
            continue;
        }
        let resolved = platform::resolve(volumes, &execution.path);
        if resolved.as_ref().is_some_and(|path| !path.exists()) {
            vanished.push(detail());
        }
        if is_volatile(&execution.path) {
            user_folders.push(detail());
        }
    }

    findings.extend(listing(
        Severity::Medium,
        "Programs recorded by BAM since boot no longer exist".to_owned(),
        vanished,
    ));
    findings.extend(listing(
        Severity::Informational,
        "Programs executed since boot from user folders".to_owned(),
        user_folders,
    ));
    findings
}

fn read_executions() -> Vec<Execution> {
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    BAM_KEYS
        .iter()
        .filter_map(|path| machine.open_subkey(path).ok())
        .flat_map(|settings| {
            settings
                .enum_keys()
                .flatten()
                .filter_map(|sid| settings.open_subkey(sid).ok())
                .collect::<Vec<_>>()
        })
        .flat_map(|user| {
            user.enum_values()
                .flatten()
                .filter(|(name, value)| name.starts_with(DEVICE_PREFIX) && value.bytes.len() >= 8)
                .map(|(name, value)| Execution {
                    path: name,
                    timestamp: system::filetime_to_unix(u64::from_le_bytes(
                        value.bytes[..8].try_into().expect("length checked above"),
                    )),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}
