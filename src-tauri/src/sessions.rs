use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

use inspection::Report;

#[derive(Default)]
pub struct Sessions {
    next: AtomicU32,
    entries: Mutex<HashMap<u32, Session>>,
}

struct Session {
    cancelled: Arc<AtomicBool>,
    report: Option<Report>,
}

impl Sessions {
    pub fn open(&self) -> (u32, Arc<AtomicBool>) {
        let identifier = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let cancelled = Arc::new(AtomicBool::new(false));
        self.lock().insert(
            identifier,
            Session {
                cancelled: Arc::clone(&cancelled),
                report: None,
            },
        );
        (identifier, cancelled)
    }

    pub fn complete(&self, identifier: u32, report: Report) {
        if let Some(session) = self.lock().get_mut(&identifier) {
            session.report = Some(report);
        }
    }

    pub fn cancel(&self, identifier: u32) -> bool {
        self.lock()
            .get(&identifier)
            .map(|session| session.cancelled.store(true, Ordering::Relaxed))
            .is_some()
    }

    pub fn report(&self, identifier: u32) -> Option<Report> {
        self.lock()
            .get(&identifier)
            .and_then(|session| session.report.clone())
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u32, Session>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
