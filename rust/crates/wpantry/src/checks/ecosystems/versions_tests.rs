use super::*;

#[test]
fn only_one_plain_version_token_is_safe() {
    for ok in ["4.17.21", "1.0.0-beta.1+build.5", "2:1.35+dfsg-3ubuntu0.4", "v2", "20260101", "1.2.3_r1~pre"] {
        assert!(is_safe_token(ok), "{ok}");
    }
    for bad in
        ["", "4.17.21 evil-pkg", "--registry=evil", "-1", "1'; rm -rf /", "1.0\n2.0", "1.0\t", "a/b", "1.0$", "é.1"]
    {
        assert!(!is_safe_token(bad), "{bad:?}");
    }
    assert!(!is_safe_token(&"9".repeat(101)));
}

// The test vectors the Python implementation had (`Versions`).
#[test]
fn order() {
    assert!(lt("1.2.3", "1.2.10"));
    assert!(lt("1.2.3rc1", "1.2.3"));
    assert!(lt("v3.12.13", "v3.12.14"));
    assert!(lt("curl-8_7_1", "curl-8_11_1"));
    assert!(!lt("2.0.0", "2.0.0"));
    assert!(lt("1:1.0", "2.0"), "the epoch is dropped");
    assert!(lt("1.0+build9", "1.0.1"));
    assert_eq!(cmp("V1.0", "1.0"), Ordering::Equal);
    assert!(lt("99999999999999999999999", "100000000000000000000000"));
}

#[test]
fn pick_safe_prefers_same_line() {
    assert_eq!(pick_safe("24.22.1", &["26.12.2", "24.22.2", "22.23.5"]).as_deref(), Some("24.22.2"));
    assert_eq!(pick_safe("1.0.9", &["1.0.10", "1.0.11"]).as_deref(), Some("1.0.10"));
    assert_eq!(pick_safe("2.0.0", &["1.9.0"]), None);
    assert_eq!(pick_safe("2.0.0", &["", "2.0.0"]), None);
}

#[test]
fn same_or_newer_ignores_extra_digits() {
    assert!(same_or_newer("2026.1", "2026.1.0"));
    assert!(!same_or_newer("3.0.20", "3.0.24"));
    assert!(same_or_newer("x", "1.0"));
}

#[test]
fn common_prefix_counts_leading_numbers() {
    assert_eq!(common_prefix("v3.12.13", "v3.12.15"), 2);
    assert_eq!(common_prefix("1.02", "1.2.0"), 2);
    assert_eq!(numbers("v1.2.3+meta.4"), ["1", "2", "3"]);
}

#[test]
fn java_8s_two_spellings_compare_as_one() {
    let behind = |have: &str, latest: &str| !current("java", have, latest);
    assert!(behind("1.8.0_412", "8u472-b08"));
    assert!(!behind("1.8.0_472", "8u472-b08"));
    assert!(!behind("1.8.0_480", "8u472"));
    assert!(behind("1.8.0", "8u472"), "no update is update 0");
    // 9 and later as before: build metadata is not a newer release.
    assert!(!behind("21.0.5", "21.0.5+11"));
    assert!(behind("21.0.4", "21.0.5+11"));
    assert_eq!(java8("21.0.5+11"), "21.0.5+11");
    for odd in ["1.8.0_", "1.8.0_x", "1.8.0-b1", "8u", "8ux", "18u1", "1.8.01"] {
        assert_eq!(java8(odd), odd, "{odd}");
    }
    assert_eq!(java8("8u472+1"), "8.0.472");
    // Only the java tool is read this way.
    assert!(!current("node", "1.8.0_412", "8u472"), "other tools compare as before");
    assert!(!current("node", "18.0.0", "18.1.0"));
}

/// Risk: a git tag's `v` reaches a command or a sentence ("update to
/// v3.14.10"). Oracle: the release's own number, as a person writes it.
#[test]
fn bare_takes_a_tags_v_and_nothing_else() {
    for (given, want) in [
        ("v3.14.10", "3.14.10"),
        ("V3.14.10", "3.14.10"),
        ("3.14.10", "3.14.10"),
        ("v2", "2"),
        ("OTP-27.3.3", "OTP-27.3.3"),
        ("vim", "vim"),
        ("v", "v"),
        ("", ""),
        ("vv1.2", "vv1.2"),
        ("1.0.0-v2", "1.0.0-v2"),
    ] {
        assert_eq!(bare(given), want, "{given:?}");
    }
}
