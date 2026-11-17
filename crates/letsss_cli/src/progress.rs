//! Live per-module progress bars.

use std::{collections::HashMap, time::Duration};

use console::style;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use letsss_core::{Finding, Module, Observer, Progress, Severity};

const RESOLUTION: u64 = 1000;
const TICK: Duration = Duration::from_millis(120);
const DETAIL_WIDTH: usize = 48;
const TEMPLATE: &str =
    "{spinner:.cyan} {prefix:<20.bold} [{bar:30.cyan/blue}] {percent:>3}%  {msg:.dim}";

/// One progress bar per selected module, updated from the inspection observer.
pub struct ModuleProgress {
    container: MultiProgress,
    bars: HashMap<Module, ProgressBar>,
}

impl ModuleProgress {
    pub fn new(modules: &[Module]) -> Self {
        let container = MultiProgress::new();
        let style = ProgressStyle::with_template(TEMPLATE)
            .expect("progress template is valid")
            .progress_chars("━╸ ");
        let bars = modules
            .iter()
            .map(|module| {
                let bar = container.add(ProgressBar::new(RESOLUTION));
                bar.set_style(style.clone());
                bar.set_prefix(module.label());
                bar.set_message("waiting");
                bar.enable_steady_tick(TICK);
                (*module, bar)
            })
            .collect();
        Self { container, bars }
    }

    /// Completes every bar and removes the progress area from the terminal.
    pub fn finish(&self) {
        self.bars.values().for_each(ProgressBar::finish_and_clear);
        let _ = self.container.clear();
    }
}

impl Observer for ModuleProgress {
    fn progress(&self, progress: Progress) {
        let Some(bar) = self.bars.get(&progress.module) else {
            return;
        };
        bar.set_position((progress.fraction * RESOLUTION as f32) as u64);
        if progress.fraction >= 1.0 {
            bar.set_message("done");
        } else {
            bar.set_message(truncate(&progress.detail));
        }
    }

    fn finding(&self, finding: &Finding) {
        if finding.severity >= Severity::High {
            let client = finding
                .client
                .as_deref()
                .map(|client| format!(" [{client}]"))
                .unwrap_or_default();
            self.container
                .println(format!(
                    "{} {}{}",
                    style("●").red().bold(),
                    finding.title,
                    style(client).magenta()
                ))
                .ok();
        }
    }
}

fn truncate(detail: &str) -> String {
    let count = detail.chars().count();
    if count <= DETAIL_WIDTH {
        return detail.to_owned();
    }
    let tail: String = detail.chars().skip(count - DETAIL_WIDTH + 1).collect();
    format!("…{tail}")
}
