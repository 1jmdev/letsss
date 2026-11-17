//! Execution and deletion artifacts left by the operating system.

#[cfg(windows)]
mod execution;
#[cfg(unix)]
mod history;
mod inspection;
#[cfg(windows)]
mod journal;
#[cfg(windows)]
mod prefetch;
mod recycle;

pub use inspection::inspect;
