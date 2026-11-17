//! Win32 implementations.

mod memory;
mod storage;

pub use memory::ProcessMemory;
pub use storage::{Volume, is_signed, resolve, volumes};
