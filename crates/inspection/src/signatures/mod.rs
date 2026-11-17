//! Embedded signature database and multi-pattern matchers.

mod database;
mod matcher;
mod tally;

pub use database::{
    Category, Client, Database, DownloadSource, GenericModule, LaunchFlag, MacroSoftware, Rule,
    RuleScope, Signatures, SourceRating,
};
pub use matcher::{Hit, Matcher, Settings, Subject, excerpt};
pub use tally::Tally;
