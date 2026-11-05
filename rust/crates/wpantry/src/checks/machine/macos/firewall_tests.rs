use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn firewall_logging_by_socketfilterfw_or_profile() {
    // Firewall logging after macOS 15: a profile, or nothing to read.
    let profile = machine(&[("--getloggingmode", "usage: socketfilterfw [-h]\n"), ("EnableLogging", "1\n")]);
    assert_eq!(firewall_logging(&profile).status, Status::Pass);
    let none = machine(&[("--getloggingmode", "usage: socketfilterfw [-h]\n")]);
    assert_eq!(firewall_logging(&none).status, Status::Manual);
}
