//! Operator-selected inspection options.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// An independently runnable inspection module.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Module {
    Memory,
    LaunchArguments,
    Processes,
    Mods,
    Files,
    Artifacts,
    Network,
    Bypass,
}

impl Module {
    pub const ALL: [Self; 8] = [
        Self::Memory,
        Self::LaunchArguments,
        Self::Processes,
        Self::Mods,
        Self::Files,
        Self::Artifacts,
        Self::Network,
        Self::Bypass,
    ];

    /// Human-readable module name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Memory => "Process memory",
            Self::LaunchArguments => "Launch arguments",
            Self::Processes => "Processes",
            Self::Mods => "Mods",
            Self::Files => "Executable files",
            Self::Artifacts => "Execution artifacts",
            Self::Network => "Network",
            Self::Bypass => "Bypass detection",
        }
    }
}

/// Parameters of one inspection session.
///
/// ```
/// use letsss_core::{Module, Options};
///
/// let options = Options { modules: vec![Module::Mods], ..Options::default() };
/// assert!(options.online);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    pub modules: Vec<Module>,
    /// Additional files, directories, or path-list `.txt` files to inspect.
    pub paths: Vec<PathBuf>,
    /// Permits hash lookups against Modrinth.
    pub online: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            modules: Module::ALL.to_vec(),
            paths: Vec::new(),
            online: true,
        }
    }
}
