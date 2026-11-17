use super::*;

#[test]
fn every_check_is_named() {
    assert!(CHECKS.iter().all(|c| c.id.starts_with("POSTURE-") && !c.title.is_empty()));
}
