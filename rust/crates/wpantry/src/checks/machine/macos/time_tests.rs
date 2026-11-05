use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn time_sync_without_admin() {
    // Time sync without admin: systemsetup refuses, sudo -n has no ticket.
    let refused = machine(&[("getusingnetworktime", "You need administrator access to run this tool... exiting!\n")]);
    assert!(matches!(time_sync(&refused).status, Status::Manual | Status::Unknown));
}
