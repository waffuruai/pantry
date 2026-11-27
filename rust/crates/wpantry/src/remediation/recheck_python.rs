//! The narrow re-check of a Python runtime (kind `runtime`, component
//! `python`, found by the package inventory): the one interpreter the
//! finding names is asked again, alone, and its version now is judged by
//! the same OSV, end-of-life and cached-record logic as a catalog tool
//! (`recheck::judge_component`).
//!
//! The interpreter is read the way the scan reads it
//! ([`packages::python_now`]): the file at the finding's location is run
//! with `-I -S -c` and the one JSON line it prints is read (its version
//! and the interpreter that answered). Nothing else is run: no package
//! manager, no version manager, no pip. A version manager's shim answers for
//! whichever interpreter it picks now, so a shim moved to a new version
//! reads as that version.
//!
//! * the file is not there: `gone` (`removed`) when the place it lived in
//!   (the manager's folder of installs, [`anchor`]) is still there, `unknown`
//!   (`unreachable`) when that is gone too;
//! * the file is there but does not answer with a version: `unknown`
//!   (`unreadable`);
//! * something else (Homebrew, the OS) vouches for the interpreter that
//!   answers now: `unknown` (`unsupported`), as a scan reports no runtime
//!   for it and that manager's own finding is checked on its own;
//! * otherwise the version is judged: `gone` (`fixed`), `still_present`
//!   (`affected`), or `unknown` for an answer the cache never held.
//!
//! A new install beside the old one does not make the old one's finding
//! gone: the old path still answers with the old version.

use super::recheck::Verdict;
use crate::checks::machine::packages::{self, PythonNow};
use crate::component::Component;
use std::path::{Path, PathBuf};

/// Whether a finding of this kind and component is a Python runtime.
pub(super) fn applies(kind: &str, component: &str) -> bool {
    kind == "runtime" && component == "python"
}

/// The folder a Python install lives in, whose presence says an install
/// missing from it was removed rather than its volume unmounted: the
/// version manager's own folder of installs (`pyenv/versions`, `uv/python`,
/// `asdf/installs/python`, a conda `envs`), else the one
/// [`super::recheck::anchor_of`] gives.
fn anchor(location: &Path) -> PathBuf {
    let text = location.to_string_lossy().replace('\\', "/");
    for marker in ["/.pyenv/versions", "/uv/python", "/.asdf/installs/python", "/envs"] {
        // The folder holding the installs, only when something follows it.
        if let Some(at) = text.find(&format!("{marker}/")) {
            return PathBuf::from(&text[..at + marker.len()]);
        }
    }
    super::recheck::anchor_of(location)
}

/// The runtime a scan would report at `location` now, or the verdict when
/// it can't be had. `probe` and `vouched` are [`packages::ask_python`] and
/// [`crate::utils::files::owner`] on a machine.
pub(super) fn read(
    location: &str,
    probe: &dyn Fn(&str) -> String,
    vouched: &dyn Fn(&str) -> &'static str,
) -> std::result::Result<Component, Verdict> {
    let shown = Path::new(location);
    if !shown.is_absolute() {
        let why =
            format!("python at {location} has no narrow check: it is not an absolute path; only a scan checks it.");
        return Err(Verdict::unknown("unsupported", why));
    }
    // `metadata` follows a link: one that goes nowhere is a Python that is gone.
    match std::fs::metadata(shown) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Err(Verdict::unknown("unreadable", format!("{location} is not a file to run."))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(super::recheck::vanished(shown, &anchor(shown)));
        }
        Err(e) => return Err(Verdict::unknown("unreadable", format!("{location} can't be read: {e}."))),
    }
    match packages::python_now(location, probe, vouched) {
        PythonNow::Runtime(c) => Ok(*c),
        PythonNow::Unreadable => {
            let why = format!("{location} is there, but it did not answer with its version.");
            Err(Verdict::unknown("unreadable", why))
        }
        PythonNow::Vouched(who) => {
            let why = format!(
                "{location} now starts an interpreter that {who} vouches for, which a scan checks as that manager's package, not as a runtime."
            );
            Err(Verdict::unknown("unsupported", why))
        }
    }
}
