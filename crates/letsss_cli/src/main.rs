//! Command-line interface for letsSS.

mod display;
mod progress;

#[cfg(windows)]
use std::env;
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};

use anyhow::Context;
use clap::Parser;
use letsss_core::{Module, Options};

/// Inspects this machine for Minecraft cheat clients and anti-forensic tampering.
#[derive(Parser)]
#[command(name = "letsss", version)]
struct Arguments {
    /// Files, directories, or .txt path lists (for example an Everything export) to inspect.
    paths: Vec<PathBuf>,
    /// Modules to run; all modules run when omitted.
    #[arg(short, long, value_enum, value_delimiter = ',')]
    modules: Vec<ModuleArgument>,
    /// Inspect mods and logs only in this .minecraft folder of the current session.
    #[arg(short, long, value_name = "PATH", conflicts_with = "all_installations")]
    game_dir: Option<PathBuf>,
    /// Inspect every Minecraft installation without asking.
    #[arg(long)]
    all_installations: bool,
    /// Skip Modrinth hash verification.
    #[arg(long)]
    offline: bool,
    /// Show informational findings and every piece of evidence.
    #[arg(short, long)]
    verbose: bool,
    /// Also write the full report as JSON to this file.
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,
    /// Exit immediately instead of waiting for Enter.
    #[arg(long)]
    no_pause: bool,
    /// Do not request administrator rights on Windows.
    #[arg(long)]
    no_elevate: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ModuleArgument {
    Memory,
    LaunchArguments,
    Processes,
    Mods,
    Files,
    Artifacts,
    Network,
    Bypass,
}

impl From<ModuleArgument> for Module {
    fn from(argument: ModuleArgument) -> Self {
        match argument {
            ModuleArgument::Memory => Self::Memory,
            ModuleArgument::LaunchArguments => Self::LaunchArguments,
            ModuleArgument::Processes => Self::Processes,
            ModuleArgument::Mods => Self::Mods,
            ModuleArgument::Files => Self::Files,
            ModuleArgument::Artifacts => Self::Artifacts,
            ModuleArgument::Network => Self::Network,
            ModuleArgument::Bypass => Self::Bypass,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    #[cfg(windows)]
    if !arguments.no_elevate && !is_elevated::is_elevated() {
        return relaunch_elevated();
    }
    let modules: Vec<Module> = match arguments.modules.is_empty() {
        true => Module::ALL.to_vec(),
        false => arguments
            .modules
            .iter()
            .copied()
            .map(Module::from)
            .collect(),
    };
    display::banner();
    let game_directory = match arguments.game_dir {
        Some(directory) => Some(directory),
        None if arguments.all_installations => None,
        None => display::choose_game_directory()?,
    };
    let options = Options {
        modules,
        paths: arguments.paths,
        online: !arguments.offline,
        game_directory,
    };
    let progress = progress::ModuleProgress::new(&options.modules);
    let report = letsss_core::run(&options, &progress, &AtomicBool::new(false))
        .context("running inspection")?;
    progress.finish();
    display::report(&report, arguments.verbose);

    if let Some(path) = &arguments.json {
        fs::write(path, report.to_json()?)
            .with_context(|| format!("writing report to {}", path.display()))?;
        println!("Full report written to {}", path.display());
    }
    if cfg!(windows) && !arguments.no_pause {
        display::wait_for_enter();
    }
    Ok(())
}

/// Restarts this executable through a UAC prompt with the original arguments.
#[cfg(windows)]
fn relaunch_elevated() -> anyhow::Result<()> {
    let executable = env::current_exe().context("locating the running executable")?;
    runas::Command::new(executable)
        .args(&env::args_os().skip(1).collect::<Vec<_>>())
        .arg("--no-elevate")
        .status()
        .context("requesting administrator rights")?;
    Ok(())
}
