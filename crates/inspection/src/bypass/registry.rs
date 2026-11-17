//! Registry policies, service configuration, and hijacks that blind forensic tooling.

use std::iter;

use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
};

use crate::{
    context::Context,
    finding::{Evidence, Finding, Severity},
    options::Module,
    system,
};

const LAST_WRITE_TOLERANCE_SECONDS: u64 = 15;
const RESTRICTED_ZONE: u32 = 4;
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
const PREFETCH_PARAMETERS: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";
const IMAGE_FILE_EXECUTION_OPTIONS: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const ZONE_MAP_DOMAINS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains";
const RUN_KEYS: [&str; 2] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];
const DESTRUCTIVE_COMMANDS: [&str; 5] = ["taskkill", "tskill", "fsutil", "wevtutil", "vssadmin"];
const BROWSER_POLICIES: [&str; 4] = [
    r"Software\Policies\Google\Chrome\URLBlocklist",
    r"Software\Policies\Microsoft\Edge\URLBlocklist",
    r"Software\Policies\BraveSoftware\Brave\URLBlocklist",
    r"Software\Policies\Vivaldi\URLBlocklist",
];
const WATCHED_SERVICES: [&str; 3] = ["SysMain", "EventLog", "bam"];

#[derive(Clone, Copy)]
enum Hive {
    Machine,
    User,
}

impl Hive {
    fn key(self) -> RegKey {
        RegKey::predef(match self {
            Self::Machine => HKEY_LOCAL_MACHINE,
            Self::User => HKEY_CURRENT_USER,
        })
    }

    fn label(self) -> &'static str {
        match self {
            Self::Machine => "HKLM",
            Self::User => "HKCU",
        }
    }
}

#[derive(Clone, Copy)]
enum Condition {
    Equals(u32),
    Differs(u32),
    Nonzero,
    Present,
}

struct ValueCheck {
    hive: Hive,
    path: &'static str,
    value: &'static str,
    condition: Condition,
    severity: Severity,
    title: &'static str,
}

const VALUE_CHECKS: [ValueCheck; 26] = [
    check(
        Hive::Machine,
        PREFETCH_PARAMETERS,
        "EnablePrefetcher",
        Condition::Differs(3),
        Severity::High,
        "Prefetch is disabled or restricted",
    ),
    check(
        Hive::Machine,
        r"SYSTEM\CurrentControlSet\Services\SysMain",
        "Start",
        Condition::Equals(4),
        Severity::High,
        "SysMain service is disabled",
    ),
    check(
        Hive::Machine,
        r"SYSTEM\CurrentControlSet\Services\EventLog",
        "Start",
        Condition::Equals(4),
        Severity::High,
        "Event Log service is disabled",
    ),
    check(
        Hive::Machine,
        r"SYSTEM\CurrentControlSet\Services\bam",
        "Start",
        Condition::Equals(4),
        Severity::High,
        "Background Activity Moderator is disabled",
    ),
    check(
        Hive::Machine,
        r"SYSTEM\CurrentControlSet\Services\dam",
        "Start",
        Condition::Equals(4),
        Severity::Medium,
        "Desktop Activity Moderator is disabled",
    ),
    check(
        Hive::Machine,
        r"SYSTEM\CurrentControlSet\Services\PcaSvc",
        "Start",
        Condition::Equals(4),
        Severity::Medium,
        "Program Compatibility Assistant is disabled",
    ),
    check(
        Hive::Machine,
        r"SYSTEM\CurrentControlSet\Services\DPS",
        "Start",
        Condition::Equals(4),
        Severity::Low,
        "Diagnostic Policy Service is disabled",
    ),
    check(
        Hive::Machine,
        r"SYSTEM\CurrentControlSet\Services\USBSTOR",
        "Start",
        Condition::Equals(4),
        Severity::Low,
        "USB storage driver is disabled",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableTaskMgr",
        Condition::Nonzero,
        Severity::Medium,
        "Task Manager is blocked",
    ),
    check(
        Hive::Machine,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableTaskMgr",
        Condition::Nonzero,
        Severity::Medium,
        "Task Manager is blocked",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableRegistryTools",
        Condition::Nonzero,
        Severity::Medium,
        "Registry editor is blocked",
    ),
    check(
        Hive::Machine,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableRegistryTools",
        Condition::Nonzero,
        Severity::Medium,
        "Registry editor is blocked",
    ),
    check(
        Hive::User,
        r"Software\Policies\Microsoft\Windows\System",
        "DisableCMD",
        Condition::Nonzero,
        Severity::Medium,
        "Command Prompt is blocked",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoRun",
        Condition::Nonzero,
        Severity::Medium,
        "Run dialog is disabled",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "DisallowRun",
        Condition::Nonzero,
        Severity::Medium,
        "Program execution blocklist is active",
    ),
    check(
        Hive::Machine,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "DisallowRun",
        Condition::Nonzero,
        Severity::Medium,
        "Program execution blocklist is active",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoControlPanel",
        Condition::Nonzero,
        Severity::Medium,
        "Control Panel is blocked",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoFolderOptions",
        Condition::Nonzero,
        Severity::Low,
        "Folder Options are hidden",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoFind",
        Condition::Nonzero,
        Severity::Low,
        "Windows Search is disabled",
    ),
    check(
        Hive::Machine,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "SettingsPageVisibility",
        Condition::Present,
        Severity::Medium,
        "Settings pages are hidden",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Comdlg32",
        "NoFileMru",
        Condition::Nonzero,
        Severity::Medium,
        "Open/Save dialog history is disabled",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32",
        "NotFileMru",
        Condition::Nonzero,
        Severity::Medium,
        "Open/Save dialog history is disabled",
    ),
    check(
        Hive::User,
        r"Software\Microsoft\Command Processor",
        "AutoRun",
        Condition::Present,
        Severity::Medium,
        "Command Prompt AutoRun command is configured",
    ),
    check(
        Hive::Machine,
        r"Software\Microsoft\Command Processor",
        "AutoRun",
        Condition::Present,
        Severity::Medium,
        "Command Prompt AutoRun command is configured",
    ),
    check(
        Hive::Machine,
        r"SYSTEM\CurrentControlSet\Control\CI\Policy",
        "VerifiedAndReputablePolicyState",
        Condition::Equals(1),
        Severity::Low,
        "Smart App Control blocks unsigned tools",
    ),
    check(
        Hive::Machine,
        r"Software\Policies\Microsoft\Windows\PowerShell",
        "EnableScripts",
        Condition::Equals(0),
        Severity::Low,
        "PowerShell scripting is disabled by policy",
    ),
];

impl ValueCheck {
    fn evaluate(&self) -> Option<Finding> {
        let key = self.hive.key().open_subkey(self.path).ok()?;
        let detail = match self.condition {
            Condition::Present => {
                let value = key.get_raw_value(self.value).ok()?;
                format!("{value}")
            }
            condition => {
                let number: u32 = key.get_value(self.value).ok()?;
                let matched = match condition {
                    Condition::Equals(expected) => number == expected,
                    Condition::Differs(expected) => number != expected,
                    _ => number != 0,
                };
                if !matched {
                    return None;
                }
                number.to_string()
            }
        };
        Some(
            Finding::new(Module::Bypass, self.severity, self.title).with_evidence(
                Evidence::Registry {
                    key: format!("{}\\{}\\{}", self.hive.label(), self.path, self.value),
                    value: Some(detail),
                },
            ),
        )
    }
}

pub fn inspect(context: &Context) -> Vec<Finding> {
    let mut findings: Vec<Finding> = VALUE_CHECKS
        .iter()
        .filter_map(ValueCheck::evaluate)
        .collect();
    findings.extend(modified_since_boot(context));
    findings.extend(debugger_hijacks());
    findings.extend(destructive_autoruns());
    findings.extend(restricted_domains());
    findings.extend(browser_blocklists());
    findings.extend(invisible_console());
    findings
}

const fn check(
    hive: Hive,
    path: &'static str,
    value: &'static str,
    condition: Condition,
    severity: Severity,
    title: &'static str,
) -> ValueCheck {
    ValueCheck {
        hive,
        path,
        value,
        condition,
        severity,
        title,
    }
}

fn last_write(key: &RegKey) -> Option<u64> {
    let info = key.query_info().ok()?;
    let filetime = (u64::from(info.last_write_time.dwHighDateTime) << 32)
        | u64::from(info.last_write_time.dwLowDateTime);
    Some(system::filetime_to_unix(filetime))
}

fn modified_since_boot(context: &Context) -> Vec<Finding> {
    let machine = Hive::Machine.key();
    let threshold = context.system.boot_time + LAST_WRITE_TOLERANCE_SECONDS;
    let watched = iter::once((PREFETCH_PARAMETERS.to_owned(), Severity::High)).chain(
        WATCHED_SERVICES
            .iter()
            .map(|service| (format!("{SERVICES}\\{service}"), Severity::Medium)),
    );
    watched
        .filter_map(|(path, severity)| {
            let written = last_write(&machine.open_subkey(&path).ok()?)?;
            (written > threshold).then(|| {
                Finding::new(
                    Module::Bypass,
                    severity,
                    "Forensic configuration key modified since boot",
                )
                .with_evidence(Evidence::Registry {
                    key: format!("HKLM\\{path}"),
                    value: Some(system::format_time(written)),
                })
                .with_timestamp(written)
            })
        })
        .collect()
}

fn debugger_hijacks() -> Vec<Finding> {
    let Ok(options) = Hive::Machine
        .key()
        .open_subkey(IMAGE_FILE_EXECUTION_OPTIONS)
    else {
        return Vec::new();
    };
    options
        .enum_keys()
        .flatten()
        .filter_map(|image| {
            let debugger: String = options
                .open_subkey(&image)
                .ok()?
                .get_value("Debugger")
                .ok()?;
            Some(
                Finding::new(
                    Module::Bypass,
                    Severity::High,
                    format!("Execution of {image} is redirected"),
                )
                .with_evidence(Evidence::Registry {
                    key: format!("HKLM\\{IMAGE_FILE_EXECUTION_OPTIONS}\\{image}\\Debugger"),
                    value: Some(debugger),
                }),
            )
        })
        .collect()
}

fn destructive_autoruns() -> Vec<Finding> {
    [Hive::Machine, Hive::User]
        .into_iter()
        .flat_map(|hive| RUN_KEYS.iter().map(move |path| (hive, *path)))
        .filter_map(|(hive, path)| Some((hive, path, hive.key().open_subkey(path).ok()?)))
        .flat_map(|(hive, path, key)| {
            key.enum_values()
                .flatten()
                .filter_map(|(name, value)| {
                    let command = value.to_string().to_ascii_lowercase();
                    DESTRUCTIVE_COMMANDS
                        .iter()
                        .any(|known| command.contains(known))
                        .then(|| {
                            Finding::new(
                                Module::Bypass,
                                Severity::High,
                                "Startup entry runs a destructive command",
                            )
                            .with_evidence(Evidence::Registry {
                                key: format!("{}\\{path}\\{name}", hive.label()),
                                value: Some(command),
                            })
                        })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn restricted_domains() -> Option<Finding> {
    let domains = Hive::User.key().open_subkey(ZONE_MAP_DOMAINS).ok()?;
    let restricted: Vec<String> = domains
        .enum_keys()
        .flatten()
        .filter(|domain| {
            domains.open_subkey(domain).is_ok_and(|key| {
                let direct = key
                    .enum_values()
                    .flatten()
                    .any(|(_, value)| u32_value(&value.bytes) == Some(RESTRICTED_ZONE));
                let nested = key.enum_keys().flatten().any(|child| {
                    key.open_subkey(child).is_ok_and(|child| {
                        child
                            .enum_values()
                            .flatten()
                            .any(|(_, value)| u32_value(&value.bytes) == Some(RESTRICTED_ZONE))
                    })
                });
                direct || nested
            })
        })
        .collect();
    (!restricted.is_empty()).then(|| {
        Finding::new(
            Module::Bypass,
            Severity::Medium,
            "Domains forced into the Restricted zone",
        )
        .with_evidence(Evidence::Registry {
            key: format!("HKCU\\{ZONE_MAP_DOMAINS}"),
            value: Some(restricted.join(", ")),
        })
    })
}

fn browser_blocklists() -> Vec<Finding> {
    [Hive::Machine, Hive::User]
        .into_iter()
        .flat_map(|hive| BROWSER_POLICIES.iter().map(move |path| (hive, *path)))
        .filter_map(|(hive, path)| {
            let key = hive.key().open_subkey(path).ok()?;
            let entries: Vec<String> = key
                .enum_values()
                .flatten()
                .map(|(_, value)| value.to_string())
                .collect();
            (!entries.is_empty()).then(|| {
                Finding::new(
                    Module::Bypass,
                    Severity::Medium,
                    "Browser URL blocklist policy is active",
                )
                .with_evidence(Evidence::Registry {
                    key: format!("{}\\{path}", hive.label()),
                    value: Some(entries.join(", ")),
                })
            })
        })
        .collect()
}

fn invisible_console() -> Option<Finding> {
    let colors: u32 = Hive::User
        .key()
        .open_subkey("Console")
        .ok()?
        .get_value("ScreenColors")
        .ok()?;
    (colors & 0x0F == (colors >> 4) & 0x0F).then(|| {
        Finding::new(
            Module::Bypass,
            Severity::Low,
            "Console text colour matches its background",
        )
        .with_evidence(Evidence::Registry {
            key: r"HKCU\Console\ScreenColors".to_owned(),
            value: Some(format!("{colors:#04x}")),
        })
    })
}

fn u32_value(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}
