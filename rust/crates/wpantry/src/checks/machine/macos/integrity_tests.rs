use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn reduced_security_is_a_choice_not_a_failure() {
    // Reduced Security is a choice some kexts need: a warning, not a failure.
    let reduced = secure_boot(&machine(&[("SPiBridgeDataType", "        Secure Boot: Reduced Security\n")]));
    assert_eq!(reduced.status, Status::Manual);
}
