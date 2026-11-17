//! Error type shared by every inspection module.

use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to access memory of process {pid}")]
    ProcessAccess {
        pid: u32,
        #[source]
        source: io::Error,
    },
    #[error("invalid archive {path}")]
    Archive {
        path: PathBuf,
        #[source]
        source: zip::result::ZipError,
    },
    #[error("signature database is malformed")]
    Signatures(#[from] serde_json::Error),
    #[error("hash verification request failed")]
    Verification(#[from] reqwest::Error),
    #[error("external command {program} failed")]
    Command {
        program: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("system information is unavailable")]
    System(#[from] sysinfo::Error),
    #[error("inspection was cancelled")]
    Cancelled,
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
