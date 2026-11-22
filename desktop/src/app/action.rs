//! Everything a person (or the automation driver) can ask the window to do.

use super::{Filter, Page, ThemeChoice};
use crate::data::Period;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Refresh,
    Scan {
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        offline: bool,
        #[serde(default)]
        include_personal_files: Option<bool>,
    },
    /// Scan the latest report's scope again, for checks that did not finish.
    Retry,
    /// Repeat the last scan started here with saved data only, after it
    /// could not reach the internet. A machine scan when none was started.
    RetryOffline,
    Cancel,
    SetPersonalFiles {
        include: bool,
    },
    OpenScanAccess,
    Show {
        page: Page,
    },
    Search {
        text: String,
    },
    SetFilter {
        filter: Filter,
    },
    Select {
        id: String,
    },
    CloseFinding,
    SetLight {
        light: bool,
    },
    SetDetails {
        on: bool,
    },
    EditSchedule {
        open: bool,
    },
    SetPeriod {
        every: Period,
    },
    SetTime {
        at: String,
    },
    SaveSchedule,
    RemoveSchedule,
    #[serde(alias = "fix_it")]
    PreviewFix,
    ConfirmFix,
    /// Get every fix Pantry can run ready, for one confirm.
    FixAll,
    ConfirmFixAll,
    CancelFixAll,
    DismissFixAll,
    ShowLowerPriority {
        open: bool,
    },
    /// `system`, `light` or `dark`.
    SetTheme {
        theme: ThemeChoice,
    },
    CancelFix,
    ToggleFixDetails,
    CopyFix,
    CopyWatchCommand,
    /// Open the security notice for one of the selected finding's public
    /// ids (its own or an alias) in the browser.
    OpenAdvisory {
        id: String,
    },
    /// Copy the selected finding's main public id (CVE first).
    CopyId,
    /// Scan again the folder an earlier scan found this problem in.
    RescanEarlier {
        id: String,
    },
    /// Hide a problem from an earlier scan (reversible).
    DismissEarlier {
        id: String,
    },
    /// Show a dismissed problem from an earlier scan again.
    RestoreEarlier {
        id: String,
    },
    /// Show or hide one Fix all item's raw output.
    ToggleBatchDetails {
        id: String,
    },
    DismissError,
    ToggleErrorDetails,
    DismissFixResult,
    CheckCache,
    CheckUpdates,
    CopyUpdate,
    OpenRelease,
    OpenDownload,
    #[serde(rename = "open_github")]
    OpenGitHub,
    OpenSupport,
}
