use std::env;

use tauri_build::{Attributes, WindowsAttributes};

const ADMINISTRATOR_MANIFEST: &str = include_str!("windows/app.manifest");

fn main() {
    let mut attributes = Attributes::new();
    if env::var("PROFILE").is_ok_and(|profile| profile == "release") {
        attributes = attributes
            .windows_attributes(WindowsAttributes::new().app_manifest(ADMINISTRATOR_MANIFEST));
    }
    tauri_build::try_build(attributes).expect("tauri build configuration is valid");
}
