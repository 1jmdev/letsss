//! Minecraft mod, version JAR, and game log analysis.

pub mod archive;
mod classfile;
mod inspection;
mod logs;
mod obfuscation;

pub use inspection::inspect;
