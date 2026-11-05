use super::*;

#[test]
fn normalisation() {
    // packaging's normalisation cases: each pair is the same version.
    for (a, b) in [
        ("1.0a", "1.0a0"),
        ("1.0.alpha1", "1.0a1"),
        ("1.0-beta.2", "1.0b2"),
        ("1.0pre1", "1.0rc1"),
        ("1.0preview1", "1.0rc1"),
        ("1.0-c1", "1.0rc1"),
        ("1.0-1", "1.0.post1"),
        ("1.0.rev1", "1.0.post1"),
        ("1.0-r", "1.0.post0"),
        ("1.0.dev", "1.0.dev0"),
        ("1.0_dev_1", "1.0.dev1"),
        ("v1.0", "1.0"),
        ("1.0.0", "1"),
        ("01.002", "1.2"),
        ("1.0+ubuntu-1", "1.0+ubuntu.1"),
        ("1.0RC1", "1.0rc1"),
        ("0!1.0", "1.0"),
    ] {
        assert_eq!(cmp(a, b), Ordering::Equal, "{a} == {b}");
    }
    for bad in ["", "1.0+", "1.0+_", "french toast", "1.0-", "1..0"] {
        assert!(parse(bad).is_none(), "{bad:?} is invalid");
    }
}
