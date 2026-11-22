//! The window's state, as the view draws it and `--automation` reports it.

use super::Settings;
use crate::data::{Period, Report, Schedule, Update};
use crate::pantry::Problem;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Page {
    #[default]
    Attention,
    Results,
    History,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Filter {
    #[default]
    All,
    Fixable,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    System,
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    /// The dry run failed, so it will not run.
    NotReady,
    Waiting,
    Running,
    /// The fix command finished; the check comes after the last one.
    Ran,
    Failed,
    /// Cancelled or out of time part way: it may have partly run.
    Stopped,
    Skipped,
    Fixed,
    StillOpen,
    Unconfirmed,
}

#[derive(Serialize)]
pub struct BatchItem {
    pub id: String,
    pub key: String,
    pub component: String,
    pub command: String,
    pub status: BatchStatus,
    pub message: String,
    /// What the scanner said when this item did not work, for Show details.
    pub details: String,
    pub show_details: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStage {
    Confirm,
    Running,
    Done,
}

/// "Fix all": every fix Pantry can run, confirmed once, run one at a time
/// through the same single-fix path, then one check scan.
#[derive(Serialize)]
pub struct Batch {
    pub scan: i64,
    pub stage: BatchStage,
    pub items: Vec<BatchItem>,
    pub message: String,
}

#[derive(Serialize)]
pub struct PendingFix {
    pub id: String,
    pub scan: i64,
    pub command: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A complete scan of the same scope no longer finds it.
    Fixed,
    StillOpen,
    /// The fix ran, but the check could not confirm it.
    Unconfirmed,
}

#[derive(Serialize)]
pub struct FixResult {
    pub component: String,
    pub outcome: Outcome,
    pub message: String,
}

#[derive(Serialize)]
pub struct State {
    pub page: Page,
    pub search: String,
    pub filter: Filter,
    pub selected: Option<String>,
    pub report: Option<Report>,
    pub report_error: Option<Problem>,
    pub schedule: Option<Schedule>,
    pub schedule_error: Option<Problem>,
    pub editing_schedule: bool,
    pub period: Period,
    pub at: String,
    pub light: bool,
    pub details: bool,
    pub include_personal_files: bool,
    pub status: String,
    pub error: Option<Problem>,
    pub show_error_details: bool,
    pub pending_fix: Option<PendingFix>,
    pub show_fix_details: bool,
    pub last_fix_output: Option<String>,
    pub fix_result: Option<FixResult>,
    pub batch: Option<Batch>,
    pub show_lower: bool,
    pub update: Option<Update>,
    /// The version the scanner reports, from `version --json` on each
    /// reload and from each update check: what the sidebar shows as
    /// "Pantry X". `None` until the scanner has said, or when it could not.
    pub scanner_version: Option<String>,
    pub settings: Settings,
    pub scanner_found: bool,
}
