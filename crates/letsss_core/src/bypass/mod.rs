//! Detection of anti-forensic tampering and inspection blockers.

#[cfg(windows)]
mod events;
#[cfg(windows)]
mod registry;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::inspect;
#[cfg(windows)]
pub use windows::inspect;
