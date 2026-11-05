use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn luks_volume_or_none() {
    assert_eq!(disk_encryption(&machine(&[("lsblk", "disk\npart crypto_LUKS\ncrypt ext4\n")])).status, Status::Pass);
    assert_eq!(disk_encryption(&machine(&[("lsblk", "disk\npart ext4\n")])).status, Status::Fail);
    assert_eq!(disk_encryption(&machine(&[])).status, Status::Unknown);
}
