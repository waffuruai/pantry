//! A finding: one thing a scan found, as the report, the cache and the
//! fixes see it.

use crate::component::Component;
use crate::utils::json::{J, obj};

/// One thing that applies (`specs/cli-contract.md#finding`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Finding {
    pub kind: String,
    pub component: String,
    pub version: String,
    pub location: String,
    pub vuln_id: String,
    /// fail | warn
    pub status: String,
    pub fixed: String,
    pub kev: bool,
    pub severity: String,
    pub note: String,
    pub fix_cmd: String,
    pub fix_auto: bool,
    /// How the vulnerable dependency is depended on: `runtime`, `dev`,
    /// `optional`, or "" (reported `unknown`) where the lockfile doesn't say.
    pub dep_scope: String,
    /// The project's own dependency (true) or one another pulled in
    /// (false); None where unknown.
    pub dep_direct: Option<bool>,
    /// The advisory's range the installed version fell in (`>=7.2.0, <9.0.0`),
    /// so a reader sees why it applies; "" for findings without one.
    pub affected_range: String,
    /// The CVSS base score of the advisory (or of a record it is an alias
    /// of), and the version it was scored by ("3.1", "4.0"); None and ""
    /// without one.
    pub cvss: Option<f64>,
    pub cvss_version: String,
    /// EPSS: the probability (0–1) that the CVE is exploited in the next 30
    /// days, and its percentile among all scored CVEs; None without a CVE
    /// EPSS scores.
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
}

impl Finding {
    /// A finding about a component: its kind, name, version and path.
    pub fn of(c: &Component) -> Finding {
        Finding {
            kind: c.kind.clone(),
            component: c.name.clone(),
            version: c.version.clone(),
            location: c.path.clone(),
            dep_scope: c.scope.clone(),
            dep_direct: c.direct,
            ..Default::default()
        }
    }

    /// `dep_scope` as the contract spells it: `unknown` for "".
    pub fn dep_scope_name(&self) -> &str {
        if self.dep_scope.is_empty() { "unknown" } else { &self.dep_scope }
    }

    pub fn to_json(&self) -> J {
        obj([
            ("kind", self.kind.as_str().into()),
            ("component", self.component.as_str().into()),
            ("version", self.version.as_str().into()),
            ("location", self.location.as_str().into()),
            ("vuln_id", self.vuln_id.as_str().into()),
            ("status", self.status.as_str().into()),
            ("fixed", self.fixed.as_str().into()),
            ("kev", self.kev.into()),
            ("severity", self.severity.as_str().into()),
            ("cvss", self.cvss.map(J::Float).unwrap_or(J::Null)),
            ("cvss_version", self.cvss_version.as_str().into()),
            ("epss", self.epss.map(J::Float).unwrap_or(J::Null)),
            ("epss_percentile", self.epss_percentile.map(J::Float).unwrap_or(J::Null)),
            ("note", self.note.as_str().into()),
            ("fix_cmd", self.fix_cmd.as_str().into()),
            ("fix_auto", self.fix_auto.into()),
            ("dep_scope", self.dep_scope_name().into()),
            ("dep_direct", self.dep_direct.map(J::Bool).unwrap_or(J::Null)),
            ("affected_range", self.affected_range.as_str().into()),
        ])
    }
}
