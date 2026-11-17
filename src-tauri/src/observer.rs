use std::{collections::HashMap, sync::Mutex};

use letsss_core::{Finding, Module, Observer, Progress};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

pub const PROGRESS_EVENT: &str = "inspection://progress";
pub const FINDING_EVENT: &str = "inspection://finding";
pub const COMPLETE_EVENT: &str = "inspection://complete";

const PROGRESS_STEP: f32 = 0.01;

#[derive(Clone, Serialize)]
pub struct SessionPayload<T> {
    pub session: u32,
    #[serde(flatten)]
    pub payload: T,
}

pub struct EventObserver {
    app: AppHandle,
    session: u32,
    emitted: Mutex<HashMap<Module, f32>>,
}

impl EventObserver {
    pub fn new(app: AppHandle, session: u32) -> Self {
        Self {
            app,
            session,
            emitted: Mutex::new(HashMap::new()),
        }
    }

    pub fn send<T: Serialize + Clone>(&self, event: &str, payload: T) {
        let _ = self.app.emit(
            event,
            SessionPayload {
                session: self.session,
                payload,
            },
        );
    }
}

impl Observer for EventObserver {
    fn progress(&self, progress: Progress) {
        let mut emitted = self
            .emitted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = emitted.entry(progress.module).or_insert(-1.0);
        if progress.fraction - *previous < PROGRESS_STEP && progress.fraction < 1.0 {
            return;
        }
        *previous = progress.fraction;
        drop(emitted);
        self.send(PROGRESS_EVENT, progress);
    }

    fn finding(&self, finding: &Finding) {
        self.send(FINDING_EVENT, finding.clone());
    }
}
