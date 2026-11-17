//! Runs the selected modules in parallel and assembles the session report.

use std::sync::atomic::AtomicBool;

use rayon::prelude::*;
use serde::Serialize;

use crate::{
    artifacts, bypass,
    context::{Context, Observer},
    error::{Error, Result},
    files,
    finding::{Evidence, Finding, Severity, Verdict},
    launch_arguments, memory, mods, network,
    options::{Module, Options},
    processes,
    signatures::Signatures,
    system::{self, SystemSnapshot},
};

#[derive(Clone, Debug, Serialize)]
pub struct HostSummary {
    pub os: String,
    pub host: String,
    pub boot_time: u64,
    pub elevated: bool,
    pub game_processes: usize,
}

impl HostSummary {
    pub fn from_snapshot(system: &SystemSnapshot) -> Self {
        Self {
            os: system.os.clone(),
            host: system.host.clone(),
            boot_time: system.boot_time,
            elevated: system.elevated,
            game_processes: system.game_processes().count(),
        }
    }
}

/// Complete result of one inspection session, ordered most severe first.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub verdict: Verdict,
    pub host: HostSummary,
    pub modules: Vec<Module>,
    pub started: u64,
    pub finished: u64,
    pub cancelled: bool,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Runs an inspection session to completion or cancellation.
///
/// ```no_run
/// use std::sync::atomic::AtomicBool;
///
/// use inspection::{Finding, Observer, Options, Progress};
///
/// struct Silent;
///
/// impl Observer for Silent {
///     fn progress(&self, _: Progress) {}
///     fn finding(&self, _: &Finding) {}
/// }
///
/// let report = inspection::run(&Options::default(), &Silent, &AtomicBool::new(false)).unwrap();
/// println!("{:?}", report.verdict);
/// ```
pub fn run(options: &Options, observer: &dyn Observer, cancelled: &AtomicBool) -> Result<Report> {
    let started = system::now();
    let signatures = Signatures::load()?;
    let system = SystemSnapshot::capture()?;
    let context = Context::new(options, &signatures, &system, observer, cancelled);

    let mut findings: Vec<Finding> = Vec::new();
    if !system.elevated {
        findings.push(Finding::new(
            Module::Bypass,
            Severity::Informational,
            "Inspection is running without administrator privileges; coverage is reduced",
        ));
    }

    let mut was_cancelled = false;
    let results: Vec<(Module, Result<Vec<Finding>>)> = options
        .modules
        .par_iter()
        .map(|module| (*module, dispatch(&context, *module)))
        .collect();
    for (module, result) in results {
        match result {
            Ok(module_findings) => {
                module_findings
                    .iter()
                    .for_each(|finding| observer.finding(finding));
                findings.extend(module_findings);
            }
            Err(Error::Cancelled) => was_cancelled = true,
            Err(error) => findings.push(
                Finding::new(
                    module,
                    Severity::Informational,
                    format!("{} could not complete", module.label()),
                )
                .with_evidence(Evidence::Text {
                    detail: error.to_string(),
                }),
            ),
        }
        context.report(module, 1.0, "Complete");
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.module.cmp(&right.module))
    });
    Ok(Report {
        verdict: Verdict::assess(&findings),
        host: HostSummary::from_snapshot(&system),
        modules: options.modules.clone(),
        started,
        finished: system::now(),
        cancelled: was_cancelled,
        findings,
    })
}

fn dispatch(context: &Context, module: Module) -> Result<Vec<Finding>> {
    context.report(module, 0.0, "Starting");
    match module {
        Module::Memory => memory::inspect(context),
        Module::LaunchArguments => launch_arguments::inspect(context),
        Module::Processes => processes::inspect(context),
        Module::Mods => mods::inspect(context),
        Module::Files => files::inspect(context),
        Module::Artifacts => artifacts::inspect(context),
        Module::Network => network::inspect(context),
        Module::Bypass => bypass::inspect(context),
    }
}
