//! Checks on each persisted program: who signed it, its quarantine
//! attribute, and whether it runs from a temporary or hidden place.

use super::{Inventory, Roots, programs};
use crate::checks::machine::clipper::odd_place;
use crate::utils::parallel;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Who signed a program, from `codesign -dv`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    Apple,
    /// The leaf authority (`Developer ID Application: …`, the App Store).
    Signed(String),
    AdHoc,
    Unsigned,
    /// Signed, but `codesign --verify` rejects it: changed after signing.
    Invalid(String),
    Unknown,
}

impl Signature {
    pub fn describe(&self) -> String {
        match self {
            Signature::Apple => "signed by Apple".into(),
            Signature::Signed(who) => format!("signed ({who})"),
            Signature::AdHoc => "ad-hoc signed (no developer identity)".into(),
            Signature::Unsigned => "not signed".into(),
            Signature::Invalid(why) => format!("its signature doesn't verify ({why})"),
            Signature::Unknown => "signature not read".into(),
        }
    }
}

/// What `codesign -dv --verbose=2` says about who signed it.
pub fn signature_of(display: &str) -> Signature {
    if display.contains("not signed at all") {
        return Signature::Unsigned;
    }
    if display.lines().any(|l| l.trim() == "Signature=adhoc") {
        return Signature::AdHoc;
    }
    let Some(leaf) = display.lines().find_map(|l| l.trim().strip_prefix("Authority=")) else {
        return Signature::Unknown;
    };
    if leaf == "Apple Mac OS Application Signing" {
        Signature::Signed("the App Store".into())
    } else if leaf == "Software Signing"
        || leaf == "macOS Software Signing"
        || (leaf.starts_with("Apple ") && display.contains("Platform identifier="))
    {
        Signature::Apple
    } else {
        Signature::Signed(leaf.to_string())
    }
}

/// What the checks found about one program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vetted {
    pub signature: Signature,
    /// Carries `com.apple.quarantine`; None off macOS or when unreadable.
    pub quarantined: Option<bool>,
    /// Runs from a temporary or hidden place.
    pub hidden: bool,
}

impl Vetted {
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.signature != Signature::Unknown {
            parts.push(self.signature.describe());
        }
        match self.quarantined {
            Some(true) => parts.push("still quarantined (downloaded)".into()),
            Some(false) => parts.push("no quarantine attribute".into()),
            None => {}
        }
        if self.hidden {
            parts.push("from a temporary or hidden place".into());
        }
        parts.join(", ")
    }
}

pub fn vet(r: &Roots, program: &Path) -> Vetted {
    let hidden = odd_place(&r.home, program);
    if !r.macos {
        return Vetted { signature: Signature::Unknown, quarantined: None, hidden };
    }
    let p = program.to_string_lossy();
    let mut signature = signature_of(&(r.runner)(&["codesign", "-dv", "--verbose=2", &p]));
    if matches!(signature, Signature::Apple | Signature::Signed(_) | Signature::AdHoc) {
        let verify = (r.runner)(&["codesign", "--verify", "--strict", &p]);
        if let Some(why) = verify.lines().map(str::trim).find(|l| !l.is_empty()) {
            let why = why.rsplit(": ").next().unwrap_or(why);
            signature = Signature::Invalid(why.to_string());
        }
    }
    let x = (r.runner)(&["xattr", "-p", "com.apple.quarantine", &p]);
    let quarantined = if x.contains("No such xattr") {
        Some(false)
    } else if x.trim().is_empty() || x.contains("No such file") {
        None
    } else {
        Some(true)
    };
    Vetted { signature, quarantined, hidden }
}

/// Check every persisted program (four at a time).
pub fn vet_all(r: &Roots, inv: &Inventory) -> BTreeMap<PathBuf, Vetted> {
    let progs: Vec<PathBuf> = programs(inv).into_iter().filter(|p| p.exists()).collect();
    let results = parallel::par_map(&progs, 4, |p| vet(r, p));
    progs.into_iter().zip(results).collect()
}

#[cfg(test)]
#[path = "vet_tests.rs"]
mod tests;
