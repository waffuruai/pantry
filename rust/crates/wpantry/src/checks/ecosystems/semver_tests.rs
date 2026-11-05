use super::*;
use crate::checks::ecosystems::assert_sorted;

#[test]
fn semver_org_precedence() {
    // semver.org §11, in order.
    assert_sorted(cmp, &["1.0.0", "2.0.0", "2.1.0", "2.1.1"]);
    assert_sorted(
        cmp,
        &[
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ],
    );
}

#[test]
fn build_metadata_and_leniency() {
    assert_eq!(cmp("1.0.0+20130313144700", "1.0.0"), Ordering::Equal);
    assert_eq!(cmp("1.0.0-beta+exp.sha.5114f85", "1.0.0-beta"), Ordering::Equal);
    assert_eq!(cmp("v1.2.3", "1.2.3"), Ordering::Equal);
    assert_eq!(cmp("1.2", "1.2.0"), Ordering::Equal);
    assert_eq!(cmp("4.0.0.1", "4.0.0"), Ordering::Greater);
    assert_eq!(cmp("1.9.0", "1.10.0"), Ordering::Less);
    assert_eq!(cmp("0.0.0-20230101", "0.0.0"), Ordering::Less);
    assert!(parse("1.0.0-").is_none() && parse("1.a.0").is_none() && parse("1.0.0+").is_none());
    assert_eq!(cmp("not a version", "1.0.0"), Ordering::Less, "falls back to the generic order");
}
