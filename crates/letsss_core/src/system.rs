//! One-time snapshot of the host: processes, boot time, and privilege level.

#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::{
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

use jiff::Timestamp;
#[cfg(windows)]
use nt_time::FileTime;
use serde::Serialize;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::{
    error::{Error, Result},
    platform,
};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const JAVA_NAMES: [&str; 4] = ["java", "javaw", "java.exe", "javaw.exe"];
const GAME_MARKERS: [&str; 6] = [
    "net.minecraft",
    "--gameDir",
    "--accessToken",
    "--assetsDir",
    "minecraft",
    "lunar",
];

#[derive(Clone, Debug, Serialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub parent: Option<u32>,
    pub name: String,
    pub executable: Option<PathBuf>,
    pub command: Vec<String>,
    pub environment: Vec<String>,
    pub start_time: u64,
}

impl ProcessRecord {
    pub fn is_java(&self) -> bool {
        let stem = self
            .executable
            .as_deref()
            .and_then(Path::file_name)
            .and_then(OsStr::to_str)
            .unwrap_or(&self.name)
            .to_ascii_lowercase();
        JAVA_NAMES.contains(&stem.as_str())
    }

    /// Java process running Minecraft, recognised by its launch arguments.
    pub fn is_game(&self) -> bool {
        self.is_java()
            && self
                .command
                .iter()
                .any(|argument| GAME_MARKERS.iter().any(|marker| argument.contains(marker)))
    }

    /// Value following `flag` in the command line, such as `--gameDir <path>`.
    pub fn argument(&self, flag: &str) -> Option<&str> {
        self.command
            .iter()
            .position(|argument| argument == flag)
            .and_then(|index| self.command.get(index + 1))
            .map(String::as_str)
    }

    pub fn variable(&self, name: &str) -> Option<&str> {
        self.environment.iter().find_map(|entry| {
            entry
                .split_once('=')
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        })
    }
}

/// Host state captured at session start and shared by every module.
#[derive(Clone, Debug, Serialize)]
pub struct SystemSnapshot {
    pub os: String,
    pub host: String,
    pub boot_time: u64,
    pub elevated: bool,
    pub processes: Vec<ProcessRecord>,
}

impl SystemSnapshot {
    pub fn capture() -> Result<Self> {
        let mut system = System::new()?;
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always)
                .with_environ(UpdateKind::Always),
        );
        let mut processes: Vec<ProcessRecord> = system
            .processes()
            .values()
            .filter(|process| process.thread_kind().is_none())
            .map(|process| ProcessRecord {
                pid: process.pid().as_u32(),
                parent: process.parent().map(|parent| parent.as_u32()),
                name: process.name().to_string_lossy().into_owned(),
                executable: process.exe().map(Path::to_path_buf),
                command: lossy(process.cmd()),
                environment: lossy(process.environ()),
                start_time: process.start_time(),
            })
            .collect();
        processes.sort_unstable_by_key(|process| process.pid);

        Ok(Self {
            os: System::long_os_version().unwrap_or_else(|_| env::consts::OS.to_owned()),
            host: System::host_name().unwrap_or_default(),
            boot_time: System::boot_time()?,
            elevated: platform::is_elevated(),
            processes,
        })
    }

    pub fn game_processes(&self) -> impl Iterator<Item = &ProcessRecord> {
        self.processes.iter().filter(|process| process.is_game())
    }
}

fn lossy(values: &[impl AsRef<OsStr>]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_ref().to_string_lossy().into_owned())
        .collect()
}

/// Converts a Windows FILETIME to Unix seconds, clamping times before 1970 to zero.
#[cfg(windows)]
pub fn filetime_to_unix(filetime: u64) -> u64 {
    FileTime::new(filetime).to_unix_time_secs().max(0) as u64
}

/// Converts a [`SystemTime`] to Unix seconds, clamping times before 1970 to zero.
pub fn unix_seconds(time: SystemTime) -> u64 {
    Timestamp::try_from(time).map_or(0, |timestamp| timestamp.as_second().max(0) as u64)
}

pub fn now() -> u64 {
    Timestamp::now().as_second().max(0) as u64
}

/// Formats Unix seconds as an RFC 3339 UTC timestamp.
pub fn format_time(seconds: u64) -> String {
    Timestamp::from_second(seconds as i64)
        .map_or_else(|_| seconds.to_string(), |timestamp| timestamp.to_string())
}

/// Runs a system utility without a visible console window and returns its standard output.
pub fn run_command(program: &'static str, arguments: &[&str]) -> Result<String> {
    let mut command = Command::new(program);
    command.args(arguments);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let output = command
        .output()
        .map_err(|source| Error::Command { program, source })?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
