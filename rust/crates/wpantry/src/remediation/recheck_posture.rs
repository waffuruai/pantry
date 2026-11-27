//! The narrow re-check of a posture finding (a machine setting): the one
//! probe the scan ran for that rule, run again alone, over the same
//! command runner. Nothing else of the posture pass runs.
//!
//! * the probe passes: `gone` (reason `fixed`);
//! * the probe fails: `still_present` (reason `setting`);
//! * the probe cannot read the setting (needs rights it lacks, or a
//!   person's eyes), or gives no usable answer: `unknown` (`unreadable`);
//! * this machine has no probe by that id (the scan was made elsewhere, or
//!   by a version with a rule this one lacks): `unknown` (`unsupported`).

use super::recheck::Verdict;
use crate::checks::machine::settings::{self, Runner, Status};

/// The verdict for the posture finding `id` titled `title`.
pub(super) fn judge(id: &str, title: &str, runner: Runner) -> Verdict {
    let Some((_, out)) = settings::probe_one(id, runner) else {
        return Verdict::unknown(
            "unsupported",
            format!("{title} has no check on this machine; only a scan on the machine it was found on checks it."),
        );
    };
    match out.status {
        Status::Pass => Verdict::gone("fixed", format!("{title}: {}.", out.evidence)),
        Status::Fail => Verdict::still("setting", format!("{title}: {}.", out.evidence)),
        Status::Manual | Status::Unknown => {
            Verdict::unknown("unreadable", format!("{title} can't be read here: {}.", out.evidence))
        }
    }
}
