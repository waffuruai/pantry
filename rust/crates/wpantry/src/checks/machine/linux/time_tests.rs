use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn ntp_synchronised_or_not() {
    assert_eq!(time_sync(&machine(&[("NTPSynchronized", "yes\n")])).status, Status::Pass);
    assert_eq!(time_sync(&machine(&[("NTPSynchronized", "no\n")])).status, Status::Fail);
    assert_eq!(time_sync(&machine(&[])).status, Status::Unknown);
}
