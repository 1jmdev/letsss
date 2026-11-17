//! Well-known user and Minecraft directories on Windows and Linux.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use crate::system::SystemSnapshot;

#[cfg(windows)]
const DEFAULT_SYSTEM_DRIVE: char = 'C';

/// Home directory of the inspected user, resolving `sudo` to the invoking user on Linux.
pub fn home() -> PathBuf {
    match env::var_os("SUDO_USER").filter(|_| cfg!(unix)) {
        Some(user) => Path::new("/home").join(user),
        None => dirs::home_dir().unwrap_or_default(),
    }
}

/// Per-user application data root: `%APPDATA%` or `~/.local/share`.
pub fn data() -> PathBuf {
    match env::var_os("SUDO_USER").filter(|_| cfg!(unix)) {
        Some(_) => home().join(".local").join("share"),
        None => dirs::data_dir().unwrap_or_else(|| home().join(".local").join("share")),
    }
}

/// Letter of the Windows system volume.
#[cfg(windows)]
pub fn system_drive() -> char {
    env::var("SystemDrive")
        .ok()
        .and_then(|drive| drive.chars().next())
        .unwrap_or(DEFAULT_SYSTEM_DRIVE)
}

pub fn temp() -> PathBuf {
    env::temp_dir()
}

/// Directories commonly holding downloaded or recently executed tools.
pub fn user_drop_zones() -> Vec<PathBuf> {
    let mut zones: Vec<PathBuf> = [dirs::download_dir(), dirs::desktop_dir(), Some(temp())]
        .into_iter()
        .flatten()
        .collect();
    if cfg!(windows) {
        zones.extend(dirs::data_local_dir().map(|local| local.join("Temp")));
        zones.push(data());
    }
    zones.sort_unstable();
    zones.dedup();
    zones
}

/// Minecraft game directories: the default root, launcher instances, and `--gameDir` of running games.
pub fn game_directories(system: &SystemSnapshot) -> Vec<PathBuf> {
    let home = home();
    let data = data();
    let mut directories = vec![
        if cfg!(windows) {
            data.join(".minecraft")
        } else {
            home.join(".minecraft")
        },
        home.join(".lunarclient").join("offline"),
        data.join(".feather"),
        data.join(".tlauncher"),
    ];
    let instance_roots = [
        data.join("PrismLauncher").join("instances"),
        data.join("MultiMC").join("instances"),
        data.join("multimc").join("instances"),
        data.join("ATLauncher").join("instances"),
        data.join("ModrinthApp").join("profiles"),
        data.join("com.modrinth.theseus").join("profiles"),
        home.join("curseforge").join("minecraft").join("Instances"),
        home.join(".var/app/org.prismlauncher.PrismLauncher/data/PrismLauncher/instances"),
    ];
    for root in instance_roots {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for instance in entries.flatten().map(|entry| entry.path()) {
            let nested = [instance.join(".minecraft"), instance.join("minecraft")];
            match nested.into_iter().find(|path| path.is_dir()) {
                Some(path) => directories.push(path),
                None => directories.push(instance),
            }
        }
    }
    directories.extend(
        system
            .game_processes()
            .filter_map(|process| process.argument("--gameDir"))
            .map(PathBuf::from),
    );
    directories.retain(|directory| directory.is_dir());
    directories.sort_unstable();
    directories.dedup();
    directories
}

/// Case-insensitive check whether `path` lies under any of the given lowercase fragments.
pub fn contains_any(path: &Path, fragments: &[String]) -> bool {
    let normalized = path.to_string_lossy().to_ascii_lowercase();
    fragments
        .iter()
        .any(|fragment| normalized.contains(fragment.as_str()))
}
