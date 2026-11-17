use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn xprotect_versions_and_age() {
    let v = xprotect_verdict(Some("5371".into()), Some("170".into()), Some(3));
    assert_eq!(v, Outcome::pass("XProtect 5371, updated 3 days ago; XProtect Remediator 170"));
    assert_eq!(xprotect_verdict(Some("5371".into()), Some("170".into()), Some(90)).status, Status::Fail);
    let missing = xprotect_verdict(Some("5371".into()), None, Some(3));
    assert_eq!(missing.status, Status::Fail);
    assert!(missing.evidence.contains("Remediator is missing"), "{}", missing.evidence);
    assert_eq!(xprotect_verdict(None, Some("170".into()), Some(3)).status, Status::Unknown);
    assert_eq!(
        bundle_version(&machine(&[("CFBundleShortVersionString", "170\n")]), XPROTECT_REMEDIATOR).as_deref(),
        Some("170")
    );
    assert_eq!(
        bundle_version(
            &machine(&[("CFBundleShortVersionString", "The domain/default pair of (x) does not exist")]),
            XPROTECT_REMEDIATOR
        ),
        None
    );
}
