//! Linux implementations based on procfs.

use std::{fs::File, io, os::unix::fs::FileExt, path::PathBuf};

use procfs::process::{MMPermissions, MMapPath, MemoryMap, Process};

use crate::memory::Region;

pub struct ProcessMemory {
    process: Process,
    memory: File,
}

impl ProcessMemory {
    pub fn open(pid: u32) -> io::Result<Self> {
        let process = Process::new(pid as i32).map_err(io::Error::other)?;
        let memory = process.mem().map_err(io::Error::other)?;
        Ok(Self { process, memory })
    }

    pub fn regions(&self) -> Vec<Region> {
        self.mappings()
            .into_iter()
            .filter(|map| {
                map.perms.contains(MMPermissions::READ)
                    && !matches!(map.pathname, MMapPath::Vvar | MMapPath::Vsyscall)
            })
            .map(|map| Region {
                base: map.address.0,
                size: (map.address.1 - map.address.0) as usize,
                executable: map.perms.contains(MMPermissions::EXECUTE),
                writable: map.perms.contains(MMPermissions::WRITE),
                private: !matches!(map.pathname, MMapPath::Path(_)),
            })
            .collect()
    }

    pub fn read(&self, address: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.memory.read_at(buffer, address)
    }

    pub fn modules(&self) -> Vec<PathBuf> {
        let mut modules: Vec<PathBuf> = self
            .mappings()
            .into_iter()
            .filter_map(|map| match map.pathname {
                MMapPath::Path(path) => Some(path),
                _ => None,
            })
            .filter(|path| path.to_string_lossy().contains(".so"))
            .collect();
        modules.sort_unstable();
        modules.dedup();
        modules
    }

    fn mappings(&self) -> Vec<MemoryMap> {
        self.process
            .maps()
            .map(|maps| maps.into_iter().collect())
            .unwrap_or_default()
    }
}

pub fn is_elevated() -> bool {
    Process::myself()
        .and_then(|process| process.status())
        .is_ok_and(|status| status.euid == 0)
}

/// PID of the process tracing `pid` through ptrace, if any.
pub fn tracer(pid: u32) -> Option<u32> {
    let status = Process::new(pid as i32).ok()?.status().ok()?;
    (status.tracerpid != 0).then_some(status.tracerpid as u32)
}
