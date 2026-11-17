//! Operating-system specific primitives behind one interface.

#[cfg(windows)]
mod win32;
#[cfg(windows)]
pub use is_elevated::is_elevated;
#[cfg(windows)]
pub use win32::{ProcessMemory, Volume, is_signed, resolve, volumes};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{ProcessMemory, is_elevated, tracer};
