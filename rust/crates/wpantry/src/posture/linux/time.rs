//! The clock: synchronised over NTP.

use super::super::{Check, Outcome, Runner, Severity, admin};

fn time_sync(r: Runner) -> Outcome {
    let out = r(&["timedatectl", "show", "-p", "NTPSynchronized", "--value"]);
    match out.trim() {
        "yes" => Outcome::pass("the clock is synchronised"),
        "no" => Outcome::fail("the clock is not synchronised (NTP off)"),
        _ => Outcome::unknown("timedatectl gave no answer"),
    }
}

pub(super) const TIME_SYNC: Check = Check {
    id: "POSTURE-TIME-SYNC",
    cis: "2.1.1",
    title: "Clock synchronised",
    severity: Severity::Low,
    probe: time_sync,
    fix: admin("sudo timedatectl set-ntp true"),
    explain: "Certificates and logs line up",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::Status;
    use crate::posture::testing::machine;

    #[test]
    fn ntp_synchronised_or_not() {
        assert_eq!(time_sync(&machine(&[("NTPSynchronized", "yes\n")])).status, Status::Pass);
        assert_eq!(time_sync(&machine(&[("NTPSynchronized", "no\n")])).status, Status::Fail);
        assert_eq!(time_sync(&machine(&[])).status, Status::Unknown);
    }
}
