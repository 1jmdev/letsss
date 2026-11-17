//! Shared state handed to every module during a session.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use crate::{
    error::{Error, Result},
    finding::Finding,
    options::{Module, Options},
    signatures::Signatures,
    system::SystemSnapshot,
};

/// Progress of one module, as a fraction in `0.0..=1.0`.
#[derive(Clone, Debug, Serialize)]
pub struct Progress {
    pub module: Module,
    pub fraction: f32,
    pub detail: String,
}

/// Receives progress and findings while a session runs.
pub trait Observer: Sync {
    fn progress(&self, progress: Progress);
    fn finding(&self, finding: &Finding);
}

pub struct Context<'a> {
    pub options: &'a Options,
    pub signatures: &'a Signatures,
    pub system: &'a SystemSnapshot,
    observer: &'a dyn Observer,
    cancelled: &'a AtomicBool,
}

impl<'a> Context<'a> {
    pub fn new(
        options: &'a Options,
        signatures: &'a Signatures,
        system: &'a SystemSnapshot,
        observer: &'a dyn Observer,
        cancelled: &'a AtomicBool,
    ) -> Self {
        Self {
            options,
            signatures,
            system,
            observer,
            cancelled,
        }
    }

    pub fn report(&self, module: Module, fraction: f32, detail: impl Into<String>) {
        self.observer.progress(Progress {
            module,
            fraction: fraction.clamp(0.0, 1.0),
            detail: detail.into(),
        });
    }

    /// Returns [`Error::Cancelled`] once the operator has cancelled the session.
    pub fn checkpoint(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
}
