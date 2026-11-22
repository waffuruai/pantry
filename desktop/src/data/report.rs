//! What a report says beyond its fields: the headline's problems, the
//! earlier scans' ones, gaps and skipped areas, and what Pantry can fix.

use super::{Exposure, Finding, Fix, Report};
use std::collections::{HashMap, HashSet};

impl Finding {
    fn key(&self) -> (&str, &str, &str, &str) {
        (&self.kind, &self.component, &self.location, &self.vuln_id)
    }

    pub fn priority(&self) -> (bool, bool, u8) {
        let severity = match self.severity.to_ascii_lowercase().as_str() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        };
        (!self.kev, self.status != "fail", severity)
    }

    /// A source that failed or a path that could not be read.
    pub fn is_gap(&self) -> bool {
        self.kind == "unchecked" && !self.excluded
    }

    /// An area left out on purpose (`--no-personal-files`).
    pub fn is_skipped(&self) -> bool {
        self.kind == "unchecked" && self.excluded
    }

    /// The key the scanner uses to follow one finding across scans.
    pub fn key_string(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.kind, self.component, self.location, self.vuln_id
        )
    }
}

impl Report {
    pub fn components_by_key(&self) -> HashMap<String, &str> {
        self.history
            .exposures
            .iter()
            .map(|e| &e.finding)
            .chain(&self.findings)
            .map(|f| (f.key_string(), f.component.as_str()))
            .collect()
    }

    /// Checks that could not finish in the latest scan. Skipped areas are
    /// left out. Counted from the findings so an older scanner, which has no
    /// `excluded` field, still reports every unchecked source.
    pub fn gaps(&self) -> i64 {
        self.findings.iter().filter(|f| f.is_gap()).count() as i64
    }

    /// True when the latest scan read CISA's list of flaws used in attacks
    /// (KEV). The scanner files the list as an unchecked source named
    /// `CISA KEV (…)` when it could not, and then marks no finding as
    /// exploited, so "not on the list" would claim something unknown.
    pub fn kev_checked(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|f| f.kind == "unchecked" && f.component.starts_with("CISA KEV"))
    }

    /// Warnings in the latest scan, not counting skipped areas (the
    /// scanner files those as warnings).
    pub fn warnings(&self) -> i64 {
        let skipped = self.skipped().iter().filter(|f| f.status == "warn").count() as i64;
        (self.scan.warns - skipped).max(0)
    }

    /// Areas the latest scan skipped because the user asked it to.
    pub fn skipped(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.is_skipped()).collect()
    }

    /// The latest scan's problems: what the headline counts.
    pub fn open(&self) -> Vec<(&Finding, String)> {
        let mut seen = HashSet::new();
        let mut rows = Vec::new();
        for finding in self.findings.iter().filter(|item| item.kind != "unchecked") {
            if seen.insert(finding.key()) {
                rows.push((finding, finding.id.clone()));
            }
        }
        rows.sort_by_key(|(finding, _)| finding.priority());
        rows
    }

    /// Problems earlier scans of other folders found that no scan has
    /// cleared, not in the latest scan and not dismissed (`dismissed`
    /// holds exposure ids). Shown apart, never in the headline.
    pub fn earlier(&self, dismissed: &[String]) -> Vec<&Exposure> {
        self.earlier_all()
            .into_iter()
            .filter(|exposure| !dismissed.contains(&exposure.finding.id))
            .collect()
    }

    /// Every open earlier problem, dismissed or not.
    pub fn earlier_all(&self) -> Vec<&Exposure> {
        let mut seen: HashSet<_> = self
            .findings
            .iter()
            .filter(|item| item.kind != "unchecked")
            .map(|item| item.key())
            .collect();
        let mut rows: Vec<&Exposure> = self
            .history
            .exposures
            .iter()
            .filter(|exposure| {
                exposure.resolved.is_none()
                    && exposure.finding.kind != "unchecked"
                    && seen.insert(exposure.finding.key())
            })
            .collect();
        rows.sort_by_key(|exposure| exposure.finding.priority());
        rows
    }

    /// The fix plan entry for a finding id, if the scan planned one.
    pub fn plan_for(&self, id: &str) -> Option<&Fix> {
        self.fix_plan.iter().find(|item| item.id == id)
    }

    /// True when Pantry can run this finding's fix itself.
    pub fn can_fix(&self, finding: &Finding, id: &str) -> bool {
        finding.fix_auto
            && !id.starts_with("earlier-")
            && self.plan_for(id).is_some_and(|plan| plan.how == "wpantry")
    }

    /// The latest scan's problems Pantry can fix itself, in headline order:
    /// what Fix all runs.
    pub fn fixable(&self) -> Vec<String> {
        self.open()
            .into_iter()
            .filter(|(finding, id)| self.can_fix(finding, id))
            .map(|(_, id)| id)
            .collect()
    }
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
