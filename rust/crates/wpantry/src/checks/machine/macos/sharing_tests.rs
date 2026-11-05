use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn airdrop_disabled_off_or_never_set() {
    // AirDrop: disabled outright, off, or never set.
    assert_eq!(
        airdrop(&machine(&[("DisableAirDrop", "1\n"), ("DiscoverableMode", "Everyone\n")])).status,
        Status::Pass
    );
    assert_eq!(airdrop(&machine(&[("DiscoverableMode", "Off\n")])).status, Status::Pass);
    assert_eq!(airdrop(&machine(&[])).evidence, "AirDrop receives from contacts only (default)");
}
