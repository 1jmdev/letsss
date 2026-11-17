//! Executable and script analysis for user folders, running images, and operator paths.

mod binary;
mod inspection;

pub use binary::analyze;
pub use inspection::inspect;
