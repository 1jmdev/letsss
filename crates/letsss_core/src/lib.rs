//! Platform-neutral Minecraft screenshare inspection core for letsSS.
//!
//! [`run`] executes the selected [`Module`]s and returns a [`Report`].

mod artifacts;
mod bypass;
mod context;
mod error;
mod files;
mod finding;
mod launch_arguments;
mod memory;
mod mods;
mod network;
mod options;
mod orchestrator;
mod paths;
mod platform;
mod processes;
pub mod signatures;
mod system;

pub use context::{Observer, Progress};
pub use error::{Error, Result};
pub use finding::{Evidence, Finding, Severity, Verdict};
pub use options::{Module, Options};
pub use orchestrator::{HostSummary, Report, run};
pub use signatures::Signatures;
pub use system::{ProcessRecord, SystemSnapshot};
