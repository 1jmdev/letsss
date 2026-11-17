//! Volume serial and device mapping, and Authenticode verification of files.

use std::{
    iter, mem,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use windows::{
    Win32::{
        Foundation::HWND,
        Security::WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
            WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
        },
        Storage::FileSystem::{GetLogicalDrives, GetVolumeInformationW, QueryDosDeviceW},
    },
    core::PCWSTR,
};

const DEVICE_CAPACITY: usize = 512;
const VOLUME_PREFIX: &str = "\\VOLUME{";

/// A mounted drive with its serial number and NT device path.
#[derive(Clone, Debug)]
pub struct Volume {
    pub letter: char,
    pub serial: u32,
    pub device: String,
}

pub fn volumes() -> Vec<Volume> {
    // SAFETY: GetLogicalDrives takes no arguments and only returns a bit mask.
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|index| mask & (1 << index) != 0)
        .filter_map(|index| {
            let letter = char::from(b'A' + index);
            let root = wide(&format!("{letter}:\\"));
            let mut serial = 0u32;
            // SAFETY: `root` is NUL-terminated and `serial` is a writable u32.
            unsafe {
                GetVolumeInformationW(
                    PCWSTR(root.as_ptr()),
                    None,
                    Some(&mut serial),
                    None,
                    None,
                    None,
                )
            }
            .ok()?;
            let name = wide(&format!("{letter}:"));
            let mut device = [0u16; DEVICE_CAPACITY];
            // SAFETY: `name` is NUL-terminated and `device` is a writable UTF-16 buffer.
            let length =
                unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut device)) } as usize;
            let device = String::from_utf16_lossy(&device[..length.min(DEVICE_CAPACITY)]);
            Some(Volume {
                letter,
                serial,
                device: device.split('\0').next().unwrap_or_default().to_owned(),
            })
        })
        .collect()
}

/// Resolves `\VOLUME{<time>-<serial>}\...` and `\Device\HarddiskVolumeN\...` paths to drive paths.
pub fn resolve(volumes: &[Volume], path: &str) -> Option<PathBuf> {
    if let Some(rest) = path.strip_prefix(VOLUME_PREFIX) {
        let (identifier, remainder) = rest.split_once('}')?;
        let serial = u32::from_str_radix(identifier.rsplit('-').next()?, 16).ok()?;
        let volume = volumes.iter().find(|volume| volume.serial == serial)?;
        return Some(PathBuf::from(format!("{}:{remainder}", volume.letter)));
    }
    volumes.iter().find_map(|volume| {
        let remainder = path.strip_prefix(volume.device.as_str())?;
        remainder
            .starts_with('\\')
            .then(|| PathBuf::from(format!("{}:{remainder}", volume.letter)))
    })
}

/// Verifies the embedded Authenticode signature of `path` without network revocation checks.
pub fn is_signed(path: &Path) -> bool {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` points at `file`, which points at the NUL-terminated `wide`; all outlive both calls.
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: releases the state allocated by the verification call above with the same structures.
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
    }
    status == 0
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(iter::once(0)).collect()
}
