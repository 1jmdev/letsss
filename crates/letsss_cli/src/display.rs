//! Human-readable terminal rendering of the inspection report.

use std::path::PathBuf;

use comfy_table::{
    Attribute, Cell, Color, ContentArrangement, Table, presets::UTF8_FULL_CONDENSED,
};
use console::{Style, Term, style};
use dialoguer::{Input, Select, theme::ColorfulTheme};
use letsss_core::{Evidence, Finding, Module, Report, Severity, Verdict};

const EVIDENCE_PREVIEW: usize = 3;
const EVIDENCE_WIDTH: usize = 160;
const SEVERITIES: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Informational,
];

pub fn banner() {
    println!();
    println!(
        "  {}  {}",
        style(" letsSS ").black().on_cyan().bold(),
        style("Minecraft screenshare inspection").bold()
    );
    println!();
}

/// Asks whether to inspect every installation or one `.minecraft` folder; `None` means every installation.
///
/// Without an interactive terminal every installation is inspected.
pub fn choose_game_directory() -> anyhow::Result<Option<PathBuf>> {
    if !Term::stdout().is_term() {
        return Ok(None);
    }
    let theme = ColorfulTheme::default();
    let choice = Select::with_theme(&theme)
        .with_prompt("Which Minecraft installations should be inspected?")
        .items([
            "Every installation on this machine",
            "Only the .minecraft folder of the current session",
        ])
        .default(0)
        .interact()?;
    if choice == 0 {
        return Ok(None);
    }
    let path: String = Input::with_theme(&theme)
        .with_prompt("Path to the .minecraft folder")
        .validate_with(|input: &String| {
            if PathBuf::from(input.trim().trim_matches('"')).is_dir() {
                Ok(())
            } else {
                Err("folder does not exist")
            }
        })
        .interact_text()?;
    println!();
    Ok(Some(PathBuf::from(path.trim().trim_matches('"'))))
}

pub fn report(report: &Report, verbose: bool) {
    print_host(report);
    let visible: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| verbose || finding.severity > Severity::Informational)
        .collect();

    for module in Module::ALL {
        let findings: Vec<&&Finding> = visible
            .iter()
            .filter(|finding| finding.module == module)
            .collect();
        if findings.is_empty() {
            continue;
        }
        println!(
            "\n{} {} {}",
            style("■").cyan(),
            style(module.label()).bold().underlined(),
            style(format!("({})", findings.len())).dim()
        );
        for finding in findings {
            print_finding(finding, verbose);
        }
    }
    if visible.is_empty() {
        println!("\n  {}", style("Nothing suspicious was found.").green());
    }
    print_summary(report);
}

pub fn wait_for_enter() {
    println!("\n{}", style("Press Enter to exit").dim());
    let _ = Term::stdout().read_line();
}

fn print_host(report: &Report) {
    let host = &report.host;
    let mut table = Table::new();
    table
        .load_style(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic);
    let administrator = if host.elevated {
        Cell::new("yes").fg(Color::Green)
    } else {
        Cell::new("no — run as administrator for full coverage").fg(Color::Yellow)
    };
    table.add_row(vec![
        Cell::new("Host").add_attribute(Attribute::Bold),
        Cell::new(&host.host),
    ]);
    table.add_row(vec![
        Cell::new("System").add_attribute(Attribute::Bold),
        Cell::new(&host.os),
    ]);
    table.add_row(vec![
        Cell::new("Administrator").add_attribute(Attribute::Bold),
        administrator,
    ]);
    table.add_row(vec![
        Cell::new("Minecraft processes").add_attribute(Attribute::Bold),
        Cell::new(host.game_processes),
    ]);
    table.add_row(vec![
        Cell::new("Duration").add_attribute(Attribute::Bold),
        Cell::new(format!(
            "{} s",
            report.finished.saturating_sub(report.started)
        )),
    ]);
    println!("{table}");
}

fn print_finding(finding: &Finding, verbose: bool) {
    let client = finding
        .client
        .as_deref()
        .map(|client| format!("  {}", style(format!("[{client}]")).magenta().bold()))
        .unwrap_or_default();
    println!("  {} {}{client}", badge(finding.severity), finding.title);
    let limit = if verbose {
        usize::MAX
    } else {
        EVIDENCE_PREVIEW
    };
    for evidence in finding.evidence.iter().take(limit) {
        println!(
            "      {} {}",
            style("›").dim(),
            style(describe(evidence)).dim()
        );
    }
    if finding.evidence.len() > limit {
        println!(
            "      {}",
            style(format!(
                "… {} more (use --verbose)",
                finding.evidence.len() - limit
            ))
            .dim()
        );
    }
}

fn print_summary(report: &Report) {
    let mut table = Table::new();
    table
        .load_style(UTF8_FULL_CONDENSED)
        .set_header(vec!["Severity", "Findings"]);
    for severity in SEVERITIES {
        let count = report
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count();
        table.add_row(vec![
            Cell::new(label(severity)).fg(color(severity)),
            Cell::new(count),
        ]);
    }
    println!("\n{table}");

    let (verdict, verdict_style) = match report.verdict {
        Verdict::Clean => ("CLEAN", Style::new().black().on_green()),
        Verdict::Suspicious => ("SUSPICIOUS", Style::new().black().on_yellow()),
        Verdict::Detected => ("DETECTED", Style::new().white().on_red()),
    };
    println!(
        "\n  Verdict  {}{}",
        verdict_style.bold().apply_to(format!(" {verdict} ")),
        if report.cancelled {
            "  (cancelled)"
        } else {
            ""
        }
    );
}

fn badge(severity: Severity) -> String {
    let text = format!(" {:<8} ", label(severity));
    let styled = match severity {
        Severity::Critical => style(text).white().on_red().bold(),
        Severity::High => style(text).red().bold(),
        Severity::Medium => style(text).yellow().bold(),
        Severity::Low => style(text).cyan(),
        Severity::Informational => style(text).dim(),
    };
    styled.to_string()
}

fn label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Informational => "INFO",
    }
}

fn color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Informational => Color::Grey,
    }
}

fn describe(evidence: &Evidence) -> String {
    let text = match evidence {
        Evidence::File {
            path,
            detail: Some(detail),
        } => format!("{} — {detail}", path.display()),
        Evidence::File { path, detail: None } => path.display().to_string(),
        Evidence::Memory {
            pid,
            address,
            excerpt,
        } => format!("pid {pid} at {address:#x}: {excerpt}"),
        Evidence::Process { pid, name, detail } => {
            format!(
                "{name} (pid {pid}) {}",
                detail.as_deref().unwrap_or_default()
            )
        }
        Evidence::Registry { key, value } => {
            format!("{key} = {}", value.as_deref().unwrap_or_default())
        }
        Evidence::Event { log, id, record } => {
            format!(
                "{log} event {id}: {}",
                record.split_whitespace().collect::<Vec<_>>().join(" ")
            )
        }
        Evidence::Text { detail } => detail.clone(),
    };
    text.chars().take(EVIDENCE_WIDTH).collect()
}
