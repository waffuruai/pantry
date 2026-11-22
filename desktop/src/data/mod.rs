//! What the scanner reports, as the window reads it: the `report all --json`
//! envelope, the schedule and the update answer.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

mod cache;
mod report;
mod time;

pub use cache::{cache_path, cache_stamp};
pub use time::local_time;

#[derive(Default, Deserialize, Serialize)]
pub struct Report {
    pub schema: i64,
    pub scan: Scan,
    pub findings: Vec<Finding>,
    pub fix_plan: Vec<Fix>,
    pub checked: BTreeMap<String, i64>,
    pub unfixed: i64,
    pub history: History,
}

#[derive(Default, Deserialize, Serialize)]
pub struct Scan {
    #[serde(default)]
    pub id: i64,
    pub when: String,
    pub scope: String,
    pub fails: i64,
    pub warns: i64,
    pub unchecked: i64,
}

#[derive(Default, Deserialize, Serialize)]
pub struct History {
    pub scans: Vec<Scan>,
    pub exposures: Vec<Exposure>,
    #[serde(default)]
    pub fixes: Vec<FixRecord>,
}

#[derive(Deserialize, Serialize)]
pub struct FixRecord {
    pub when: String,
    pub command: String,
    pub ok: bool,
    pub verified_scan: Option<i64>,
    pub targets: Vec<String>,
}

impl FixRecord {
    pub fn target_names<'a>(&self, components: &HashMap<String, &'a str>) -> Vec<&'a str> {
        let mut seen = HashSet::new();
        self.targets
            .iter()
            .filter_map(|key| components.get(key).copied())
            .filter(|name| !name.is_empty() && seen.insert(*name))
            .collect()
    }
}

#[derive(Deserialize, Serialize)]
pub struct Exposure {
    #[serde(flatten)]
    pub finding: Finding,
    pub resolved: Option<String>,
    /// The scope of the scan that last saw it, such as `repos:/a`; "" from
    /// an older scanner.
    #[serde(default)]
    pub scope: String,
}

#[derive(Deserialize, Serialize)]
pub struct Finding {
    #[serde(default)]
    pub id: String,
    pub kind: String,
    pub component: String,
    pub version: String,
    pub location: String,
    pub vuln_id: String,
    pub status: String,
    pub note: String,
    pub fixed: String,
    pub severity: String,
    pub kev: bool,
    pub fix_cmd: String,
    #[serde(default)]
    pub fix_auto: bool,
    /// An `unchecked` finding for an area the user chose to skip, such as
    /// personal folders. Not a gap: it never counts as an incomplete check.
    #[serde(default)]
    pub excluded: bool,
    /// The advisory's own one-line summary as published, cleaned by the
    /// scanner; "" from an older scanner or without one.
    #[serde(default)]
    pub summary: String,
    /// The advisory's other ids (CVE, GHSA, OSV).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Weakness types, such as `CWE-787`.
    #[serde(default)]
    pub cwe: Vec<String>,
    /// The advisory range the installed version fell in (`>=1.0, <1.4.9`).
    #[serde(default)]
    pub affected_range: String,
    #[serde(default)]
    pub cvss: Option<f64>,
    #[serde(default)]
    pub cvss_version: String,
    /// The EPSS probability (0 to 1) of exploitation in the next 30 days.
    #[serde(default)]
    pub epss: Option<f64>,
    /// `runtime`, `dev`, `optional` or `unknown`.
    #[serde(default)]
    pub dep_scope: String,
    #[serde(default)]
    pub dep_direct: Option<bool>,
}

#[derive(Deserialize, Serialize)]
pub struct Fix {
    pub id: String,
    pub how: String,
    pub run: String,
    pub fix_cmd: String,
}

#[derive(Deserialize, Serialize)]
pub struct Schedule {
    pub schema: i64,
    pub installed: bool,
    pub backend: String,
    pub enabled: Option<bool>,
    /// macOS: whether launchd still holds the job, even with no plist (a
    /// removal whose bootout failed). Absent from older scanners.
    #[serde(default)]
    pub loaded: Option<bool>,
    pub interval: Option<String>,
    pub every: Option<Period>,
    pub at: Option<String>,
    pub last_run: Option<String>,
}

/// `wpantry version --json`: the scanner's own version, so the window shows
/// the back end it really talks to.
///
/// ```text
/// {"version": "0.6.0", "impl": "rust", "schema": 1}
/// ```
#[derive(Deserialize)]
pub struct ScannerVersion {
    pub version: String,
}

#[derive(Deserialize, Serialize)]
pub struct Update {
    pub current: String,
    pub latest: String,
    pub available: bool,
    pub assets: Option<Vec<String>>,
    /// When the answer was fetched, `YYYY-MM-DD HH:MM UTC`.
    #[serde(default)]
    pub checked_at: Option<String>,
    /// True when the scanner could not ask and answered from an older copy.
    #[serde(default)]
    pub stale: bool,
}

#[derive(Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Period {
    Hour,
    #[default]
    Day,
    Week,
    Month,
    Quarter,
    Year,
}

impl Update {
    /// True when the scanner that answered is the one this app was built
    /// with. A copy with parts from two versions offers no update.
    pub fn matches_app(&self) -> bool {
        self.current == env!("CARGO_PKG_VERSION")
    }
}

impl Period {
    pub const ALL: [Self; 6] = [
        Self::Hour,
        Self::Day,
        Self::Week,
        Self::Month,
        Self::Quarter,
        Self::Year,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Quarter => "quarter",
            Self::Year => "year",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Hour => "Every hour",
            Self::Day => "Every day",
            Self::Week => "Every week",
            Self::Month => "Every month",
            Self::Quarter => "Every quarter",
            Self::Year => "Every year",
        }
    }
}
