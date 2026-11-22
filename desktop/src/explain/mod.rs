//! What a finding means for a person who is not a security expert: one
//! plain sentence about what could happen, whether attackers are using it
//! now, and the public ids to look it up.
//!
//! The sentence comes from, in order:
//! 1. the advisory's weakness type (CWE id), from [`WEAKNESSES`](weaknesses::WEAKNESSES);
//! 2. words in the advisory's own summary ([`KEYWORDS`](keywords::KEYWORDS)), such as "remote
//!    code execution";
//! 3. the finding's kind or marker, for Pantry's own checks ([`kind_sentence`](kinds::kind_sentence));
//! 4. a neutral sentence that claims nothing specific ([`GENERIC`]).
//!
//! Example:
//! ```ignore
//! let f = Finding { vuln_id: "CVE-2026-1".into(), cwe: vec!["CWE-787".into()], ..finding };
//! let e = explain(&f);
//! assert_eq!(e.source, Source::Cwe);
//! assert!(e.sentence.contains("run their own programs"));
//! ```

use crate::data::Finding;
use keywords::keyword_sentence;
use kinds::kind_sentence;
use serde::Serialize;
use weaknesses::{main_cwe, weakness};

mod ids;
mod keywords;
mod kinds;
mod weaknesses;

pub use ids::{EPSS_LABEL, epss_text, identifiers};
pub use kinds::{is_advisory, is_malicious, own_lead};
pub use weaknesses::cwe_name;

/// Where a finding's plain sentence came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Cwe,
    Keyword,
    Kind,
    Generic,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Explanation {
    /// What could happen, in one plain sentence.
    pub sentence: String,
    pub source: Source,
}

/// The sentence when nothing more specific is known, for a flaw with a
/// released fix and for one without.
pub const GENERIC: &str = "This version has a publicly known security flaw. Updating removes it.";
pub const GENERIC_UNFIXED: &str =
    "This version has a publicly known security flaw. No fixed version has been released yet.";
/// For a finding that is not a public advisory and has no kind sentence.
pub const GENERIC_CHECK: &str = "Pantry found something here that is worth a look.";

/// What a finding means, and where that sentence came from.
pub fn explain(f: &Finding) -> Explanation {
    let made = |sentence: &str, source| Explanation {
        sentence: sentence.to_owned(),
        source,
    };
    if f.kind == "unchecked" {
        return made(
            if f.excluded {
                "You chose to skip this area, so Pantry did not look here."
            } else {
                "Pantry could not finish this check, so it does not know whether there is a problem here."
            },
            Source::Kind,
        );
    }
    if is_advisory(f) {
        if let Some((_, _, sentence)) = main_cwe(&f.cwe).and_then(weakness) {
            return made(sentence, Source::Cwe);
        }
        let words = if f.summary.trim().is_empty() {
            &f.note
        } else {
            &f.summary
        };
        if let Some(sentence) = keyword_sentence(words) {
            return made(sentence, Source::Keyword);
        }
        return made(
            if f.fixed.is_empty() {
                GENERIC_UNFIXED
            } else {
                GENERIC
            },
            Source::Generic,
        );
    }
    match kind_sentence(f) {
        Some(sentence) => made(sentence, Source::Kind),
        None => made(GENERIC_CHECK, Source::Generic),
    }
}

pub const EXPLOITED: &str = "Attackers are using this in real attacks right now.";
pub const NOT_LISTED: &str = "It is not on the public list of flaws known to be used in attacks.";
pub const KEV_UNKNOWN: &str = "Pantry could not check whether attackers are using this.";

/// Whether attackers are using it now (CISA KEV), in plain words.
/// `kev_checked` is whether the scan that found it read the KEV list: a
/// scan that could not leaves `kev` false for every finding, which says
/// nothing. None for Pantry's own checks and for known harmful packages
/// (their lead sentence already says to remove them).
///
/// ```ignore
/// assert_eq!(attacks(&cve, false), Some(KEV_UNKNOWN));
/// assert_eq!(attacks(&eol_marker, true), None);
/// ```
pub fn attacks(f: &Finding, kev_checked: bool) -> Option<&'static str> {
    if f.kind == "unchecked" || is_malicious(f) {
        None
    } else if f.kev {
        Some(EXPLOITED)
    } else if !is_advisory(f) {
        None
    } else if kev_checked {
        Some(NOT_LISTED)
    } else {
        Some(KEV_UNKNOWN)
    }
}

/// The consequence for a home row, when one is known: the weakness or
/// summary sentence, never the neutral one.
pub fn short_consequence(f: &Finding) -> Option<String> {
    let e = explain(f);
    matches!(e.source, Source::Cwe | Source::Keyword).then_some(e.sentence)
}

#[cfg(test)]
mod tests;
