//! Foreign process memory access through `ReadProcessMemory`.

use std::{
    ffi::{OsString, c_void},
    io, mem,
    os::windows::ffi::OsStringExt,
    path::PathBuf,
};

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, HMODULE},
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{
            MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY,
            PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
        },
        ProcessStatus::{EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

use crate::memory::Region;

const MODULE_CAPACITY: usize = 2048;
const PATH_CAPACITY: usize = 1024;

pub struct ProcessMemory {
    handle: HANDLE,
}

impl ProcessMemory {
    pub fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: OpenProcess has no pointer arguments; the returned handle is owned and closed on drop.
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }?;
        Ok(Self { handle })
    }

    pub fn regions(&self) -> Vec<Region> {
        let readable = (PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY)
            .0;
        let executable = (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY).0;
        let writable =
            (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY).0;

        let mut regions = Vec::new();
        let mut address = 0usize;
        loop {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: `info` is a writable MEMORY_BASIC_INFORMATION and its exact size is passed.
            let written = unsafe {
                VirtualQueryEx(
                    self.handle,
                    Some(address as *const c_void),
                    &mut info,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                break;
            }
            let protection = info.Protect.0;
            if info.State == MEM_COMMIT
                && protection & PAGE_GUARD.0 == 0
                && protection & readable != 0
            {
                regions.push(Region {
                    base: info.BaseAddress as u64,
                    size: info.RegionSize,
                    executable: protection & executable != 0,
                    writable: protection & writable != 0,
                    private: info.Type == MEM_PRIVATE,
                });
            }
            match (info.BaseAddress as usize).checked_add(info.RegionSize) {
                Some(next) if next > address => address = next,
                _ => break,
            }
        }
        regions
    }

    /// Reads up to `buffer.len()` bytes; a partially readable range returns the readable prefix.
    pub fn read(&self, address: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let mut read = 0usize;
        // SAFETY: `buffer` is valid for `buffer.len()` writable bytes; the remote range is only read.
        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const c_void,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                Some(&mut read),
            )
        };
        match result {
            Ok(()) => Ok(read),
            Err(_) if read > 0 => Ok(read),
            Err(error) => Err(error.into()),
        }
    }

    pub fn modules(&self) -> Vec<PathBuf> {
        let mut handles = vec![HMODULE::default(); MODULE_CAPACITY];
        let mut needed = 0u32;
        // SAFETY: `handles` provides exactly the byte capacity passed as `cb`.
        let listed = unsafe {
            EnumProcessModulesEx(
                self.handle,
                handles.as_mut_ptr(),
                (handles.len() * mem::size_of::<HMODULE>()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if listed.is_err() {
            return Vec::new();
        }
        let count = (needed as usize / mem::size_of::<HMODULE>()).min(handles.len());
        handles[..count]
            .iter()
            .filter_map(|module| {
                let mut name = [0u16; PATH_CAPACITY];
                // SAFETY: `name` is a writable UTF-16 buffer whose length the binding passes along.
                let length =
                    unsafe { GetModuleFileNameExW(Some(self.handle), Some(*module), &mut name) };
                (length > 0).then(|| PathBuf::from(OsString::from_wide(&name[..length as usize])))
            })
            .collect()
    }
}

// SAFETY: a process handle is a kernel object reference; ReadProcessMemory, VirtualQueryEx and
// EnumProcessModulesEx may be called on it concurrently from any thread.
unsafe impl Send for ProcessMemory {}

// SAFETY: see the `Send` implementation; no method mutates the handle.
unsafe impl Sync for ProcessMemory {}

impl Drop for ProcessMemory {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `open` and is closed exactly once here.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
