//! Statistical class-name obfuscation metrics for one archive.

use std::path::Path;

use crate::{
    finding::{Evidence, Finding, Severity},
    options::Module,
};

const MINIMUM_CLASSES: usize = 10;
const SHORT_NAME_LENGTH: usize = 2;
const SHORT_RATIO: f32 = 0.5;
const CONFUSION_RATIO: f32 = 0.3;
const NUMERIC_RATIO: f32 = 0.3;
const NON_ASCII_RATIO: f32 = 0.2;
const SHORT_PACKAGE_RATIO: f32 = 0.6;
const CONFUSION_CHARACTERS: [char; 6] = ['I', 'l', '1', 'O', '0', '_'];
const MIXIN_MARKER: &str = "mixin";

#[derive(Default)]
struct Metrics {
    classes: usize,
    short: usize,
    numeric: usize,
    non_ascii: usize,
    japanese: usize,
    confusion: usize,
    short_packages: usize,
}

pub fn assess(classes: &[String], path: &Path, target: &str) -> Vec<Finding> {
    let metrics = measure(classes);
    if metrics.classes < MINIMUM_CLASSES {
        return Vec::new();
    }
    let ratio = |count: usize| count as f32 / metrics.classes as f32;
    let evidence = |detail: String| Evidence::File {
        path: path.to_path_buf(),
        detail: Some(detail),
    };
    let mut findings = Vec::new();

    if metrics.japanese > 0 {
        findings.push(
            Finding::new(
                Module::Mods,
                Severity::High,
                format!("Japanese-character class names in {target}"),
            )
            .with_evidence(evidence(format!(
                "{} of {} classes",
                metrics.japanese, metrics.classes
            ))),
        );
    }

    let indicators: Vec<String> = [
        (
            ratio(metrics.short) > SHORT_RATIO,
            "short names",
            metrics.short,
        ),
        (
            ratio(metrics.confusion) > CONFUSION_RATIO,
            "confusable characters",
            metrics.confusion,
        ),
        (
            ratio(metrics.numeric) > NUMERIC_RATIO,
            "numeric names",
            metrics.numeric,
        ),
        (
            ratio(metrics.non_ascii) > NON_ASCII_RATIO,
            "non-ASCII names",
            metrics.non_ascii,
        ),
        (
            ratio(metrics.short_packages) > SHORT_PACKAGE_RATIO,
            "single-letter packages",
            metrics.short_packages,
        ),
    ]
    .into_iter()
    .filter(|(exceeded, _, _)| *exceeded)
    .map(|(_, label, count)| format!("{label}: {count}/{}", metrics.classes))
    .collect();
    if !indicators.is_empty() {
        findings.push(
            Finding::new(
                Module::Mods,
                Severity::Medium,
                format!("Heavy class name obfuscation in {target}"),
            )
            .with_evidence(evidence(indicators.join(", "))),
        );
    }
    findings
}

fn measure(classes: &[String]) -> Metrics {
    let mut metrics = Metrics::default();
    for class in classes {
        if class.to_ascii_lowercase().contains(MIXIN_MARKER) {
            continue;
        }
        let (package, name) = class.rsplit_once('/').unwrap_or(("", class));
        let name = name.split('$').next().unwrap_or(name);
        metrics.classes += 1;
        metrics.short += usize::from(name.chars().count() <= SHORT_NAME_LENGTH);
        metrics.numeric +=
            usize::from(!name.is_empty() && name.chars().all(|c| c.is_ascii_digit()));
        metrics.non_ascii += usize::from(!name.is_ascii());
        metrics.japanese += usize::from(name.chars().any(|c| matches!(c, '\u{3040}'..='\u{30FF}')));
        metrics.confusion += usize::from(
            name.chars().count() > SHORT_NAME_LENGTH
                && name.chars().all(|c| CONFUSION_CHARACTERS.contains(&c)),
        );
        metrics.short_packages += usize::from(
            !package.is_empty()
                && package
                    .split('/')
                    .all(|segment| segment.chars().count() == 1),
        );
    }
    metrics
}
