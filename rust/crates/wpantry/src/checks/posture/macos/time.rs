//! The clock: set automatically from a time server.

use super::super::{Check, Outcome, Runner, Severity, admin};

/// "Set time and date automatically": certificates, Kerberos and logs need
/// a right clock. systemsetup needs admin; without it (or `sudo -n`) the
/// time server is all that can be read.
fn time_sync(r: Runner) -> Outcome {
    for argv in [&["systemsetup", "-getusingnetworktime"][..], &["sudo", "-n", "systemsetup", "-getusingnetworktime"]] {
        let out = r(argv);
        if let Some(line) = out.lines().find(|l| l.contains("Network Time:")) {
            let line = line.trim();
            return if line.ends_with("On") { Outcome::pass(line) } else { Outcome::fail(line) };
        }
    }
    let ntp = std::fs::read_to_string("/etc/ntp.conf").unwrap_or_default();
    match ntp.lines().find_map(|l| l.trim().strip_prefix("server ")) {
        Some(server) => Outcome::manual(format!(
            "the time server is {}; whether \"Set time and date automatically\" is on needs admin to read (sudo systemsetup -getusingnetworktime)",
            server.trim().trim_end_matches('.')
        )),
        None => Outcome::unknown("systemsetup needs admin, and /etc/ntp.conf names no server"),
    }
}

pub(super) const TIME_SYNC: Check = Check {
    id: "POSTURE-TIME-SYNC",
    cis: "2.3.2.1",
    title: "Time and date set automatically",
    severity: Severity::Medium,
    probe: time_sync,
    fix: admin(
        "sudo systemsetup -setusingnetworktime on  (System Settings → General → Date & Time → Set time and date automatically)",
    ),
    explain: "Certificate checks, logins and logs rely on a right clock",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::posture::Status;
    use crate::checks::posture::testing::machine;

    #[test]
    fn time_sync_without_admin() {
        // Time sync without admin: systemsetup refuses, sudo -n has no ticket.
        let refused =
            machine(&[("getusingnetworktime", "You need administrator access to run this tool... exiting!\n")]);
        assert!(matches!(time_sync(&refused).status, Status::Manual | Status::Unknown));
    }
}
