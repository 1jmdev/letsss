use std::{fs, path::PathBuf, thread};

use inspection::{HostSummary, Options, Report, SystemSnapshot};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::{
    observer::{COMPLETE_EVENT, EventObserver},
    sessions::Sessions,
};

#[derive(Clone, Serialize)]
struct Completion {
    report: Option<Report>,
    error: Option<String>,
}

#[tauri::command]
pub fn system_information() -> Result<HostSummary, String> {
    SystemSnapshot::capture()
        .map(|system| HostSummary::from_snapshot(&system))
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn start_inspection(app: AppHandle, sessions: State<Sessions>, options: Options) -> u32 {
    let (session, cancelled) = sessions.open();
    thread::spawn(move || {
        let observer = EventObserver::new(app.clone(), session);
        let result = inspection::run(&options, &observer, &cancelled);
        let completion = match result {
            Ok(report) => {
                app.state::<Sessions>().complete(session, report.clone());
                Completion {
                    report: Some(report),
                    error: None,
                }
            }
            Err(error) => Completion {
                report: None,
                error: Some(error.to_string()),
            },
        };
        observer.send(COMPLETE_EVENT, completion);
    });
    session
}

#[tauri::command]
pub fn cancel_inspection(sessions: State<Sessions>, session: u32) -> bool {
    sessions.cancel(session)
}

#[tauri::command]
pub fn session_report(sessions: State<Sessions>, session: u32) -> Option<Report> {
    sessions.report(session)
}

#[tauri::command]
pub fn export_report(sessions: State<Sessions>, session: u32, path: PathBuf) -> Result<(), String> {
    let report = sessions
        .report(session)
        .ok_or_else(|| format!("session {session} has no completed report"))?;
    let json = report.to_json().map_err(|error| error.to_string())?;
    fs::write(&path, json).map_err(|error| format!("failed to write {}: {error}", path.display()))
}
