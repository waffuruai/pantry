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
    /// An `unchecked` finding for an area the user left out on purpose
    /// (`--no-personal-files`), not a source that failed. It is part of the
    /// scan's scope, so it doesn't stop the scan resolving exposures or
    /// verifying fixes ([`crate::history`]). False for every other finding.
    pub excluded: bool,
    /// The advisory's own one-line summary as published (OSV's `summary`,
    /// a CVE record's title, else CISA KEV's name for it), cleaned by
    /// [`clean_summary`]; "" without one.
    pub summary: String,
    /// The advisory's other ids (CVE, GHSA, OSV and distro ids), the
    /// `vuln_id` itself left out; empty without any.
    pub aliases: Vec<String>,
    /// The weakness types the advisory names (`CWE-787`), from OSV's
    /// `database_specific.cwe_ids` or a CVE record's `problemTypes`.
    pub cwe: Vec<String>,
}

/// The longest summary kept, in characters (an ellipsis marks a cut).
pub const SUMMARY_MAX: usize = 300;

/// An advisory's summary made safe to show on one line: control and
/// invisible formatting characters (bidi overrides, zero-width marks) and
/// HTML tags (with a script's or style's body) removed, whitespace runs collapsed to one space, and cut to
/// [`SUMMARY_MAX`] characters.
///
/// ```ignore
/// assert_eq!(clean_summary("Heap <b>overflow</b>\n in\u{202e} parser"), "Heap overflow in parser");
/// ```
pub fn clean_summary(raw: &str) -> String {
    // Tags first: `<` then a letter, `/` or `!`, up to a `>` within 512
    // characters. A bare `<` (`versions <1.2`) is text and stays.
    let mut text = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('<') {
        text.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let tag = after.chars().next().is_some_and(|n| n.is_ascii_alphabetic() || n == '/' || n == '!');
        match after.char_indices().take(512).find(|(_, c)| *c == '>') {
            Some((end, _)) if tag => {
                text.push(' ');
                rest = &after[end + 1..];
                // A script's or style's body is code, not words: dropped
                // with it, up to its closing tag (or the end).
                let name: String =
                    after.chars().take_while(char::is_ascii_alphabetic).collect::<String>().to_ascii_lowercase();
                if name == "script" || name == "style" {
                    let close = format!("</{name}");
                    rest = match rest.to_ascii_lowercase().find(&close) {
                        Some(i) => rest[i..].find('>').map_or("", |j| &rest[i + j + 1..]),
                        None => "",
                    };
                }
            }
            _ => {
                text.push('<');
                rest = after;
            }
        }
    }
    text.push_str(rest);
    let invisible = |c: char| {
        (c.is_control() && !c.is_whitespace())
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}' | '\u{00ad}')
    };
    let kept: String = text.chars().filter(|c| !invisible(*c)).collect();
    let line = kept.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() <= SUMMARY_MAX {
        return line;
    }
    let cut: String = line.chars().take(SUMMARY_MAX - 1).collect();
    format!("{}…", cut.trim_end())
}

/// An id safe to show and to put in a link: letters, digits and `-_.:`,
/// at most 64 characters.
pub fn plain_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

/// A CWE id in its usual spelling (`CWE-787`), or None for anything else
/// (`NVD-CWE-Other`, `CWE-noinfo`).
pub fn cwe_id(raw: &str) -> Option<String> {
    let t = raw.trim();
    let digits = t.strip_prefix("CWE-").or_else(|| t.strip_prefix("cwe-"))?;
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok().map(|n| format!("CWE-{n}"))
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

    /// A gap in the evidence: an `unchecked` finding for a source that
    /// failed or a path that couldn't be read, as opposed to an area the
    /// user chose to skip (`excluded`).
    pub fn is_gap(&self) -> bool {
        self.kind == "unchecked" && !self.excluded
    }

    /// `dep_scope` as the contract spells it: `unknown` for "".
    pub fn dep_scope_name(&self) -> &str {
        if self.dep_scope.is_empty() { "unknown" } else { &self.dep_scope }
    }

    /// What keeps a finding the same finding from scan to scan: its kind,
    /// component, location and advisory or rule.
    pub fn key(&self) -> String {
        Self::key_for(&self.kind, &self.component, &self.location, &self.vuln_id)
    }

    fn key_for(kind: &str, component: &str, location: &str, vuln_id: &str) -> String {
        format!("{kind}|{component}|{location}|{vuln_id}")
    }

    /// A short handle for the finding, the same in every scan that sees it:
    /// `F-` and ten hex digits of its key's SHA-256. `wpantry fix F-…`
    /// takes it.
    pub fn id(&self) -> String {
        Self::id_for(&self.kind, &self.component, &self.location, &self.vuln_id)
    }

    pub(crate) fn id_for(kind: &str, component: &str, location: &str, vuln_id: &str) -> String {
        let key = Self::key_for(kind, component, location, vuln_id);
        format!("F-{}", &crate::utils::sha256::hex(key.as_bytes())[..10])
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
            ("excluded", self.excluded.into()),
            ("summary", self.summary.as_str().into()),
            ("aliases", J::Arr(self.aliases.iter().map(|a| a.as_str().into()).collect())),
            ("cwe", J::Arr(self.cwe.iter().map(|c| c.as_str().into()).collect())),
        ])
    }
}

#[cfg(test)]
#[path = "finding_tests.rs"]
mod tests;
