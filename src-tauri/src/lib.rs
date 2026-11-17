mod commands;
mod observer;
mod sessions;

use sessions::Sessions;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Sessions::default())
        .invoke_handler(tauri::generate_handler![
            commands::system_information,
            commands::start_inspection,
            commands::cancel_inspection,
            commands::session_report,
            commands::export_report,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
