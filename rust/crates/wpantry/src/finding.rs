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
    /// The EPSS copy the score came from: its score date and model version
    /// (`v2026.06.15`), so a score that moved because the model changed can
    /// be told from one that moved because the risk did; "" without a score.
    pub epss_date: String,
    pub epss_model: String,
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

    /// What keeps a finding the same finding from scan to scan: its kind,
    /// component, location and advisory or rule.
    pub fn key(&self) -> String {
        format!("{}|{}|{}|{}", self.kind, self.component, self.location, self.vuln_id)
    }

    /// A short handle for the finding, the same in every scan that sees it:
    /// `F-` and ten hex digits of its key's SHA-256. `wpantry fix F-…`
    /// takes it.
    pub fn id(&self) -> String {
        format!("F-{}", &crate::utils::sha256::hex(self.key().as_bytes())[..10])
    }

    pub fn to_json(&self) -> J {
        obj([
            ("id", self.id().into()),
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
            ("epss_date", self.epss_date.as_str().into()),
            ("epss_model", self.epss_model.as_str().into()),
            ("note", self.note.as_str().into()),
            ("fix_cmd", self.fix_cmd.as_str().into()),
            ("fix_auto", self.fix_auto.into()),
            ("dep_scope", self.dep_scope_name().into()),
            ("dep_direct", self.dep_direct.map(J::Bool).unwrap_or(J::Null)),
            ("affected_range", self.affected_range.as_str().into()),
        ])
    }
}
