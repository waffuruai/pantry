use super::*;
use crate::checks::ecosystems::assert_sorted;

fn eq(a: &str, b: &str) {
    assert_eq!(cmp(a, b), Ordering::Equal, "{a} == {b}");
    assert_eq!(cmp(b, a), Ordering::Equal, "{b} == {a}");
    assert_eq!(parse(a), parse(b), "{a} and {b} parse alike");
}

fn lt(a: &str, b: &str) {
    assert_eq!(cmp(a, b), Ordering::Less, "{a} < {b}");
    assert_eq!(cmp(b, a), Ordering::Greater, "{b} > {a}");
}

// The vectors of maven-artifact's ComparableVersionTest (Apache-2.0,
// apache/maven maven-3.9.x).
#[test]
fn comparable_version_test() {
    assert_sorted(
        cmp,
        &[
            "1-alpha2snapshot",
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ],
    );
    assert_sorted(
        cmp,
        &[
            "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1", "2.2",
            "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m",
        ],
    );
    // testVersionsEqual
    for (a, b) in [
        ("1", "1"),
        ("1", "1.0"),
        ("1", "1.0.0"),
        ("1.0", "1.0.0"),
        ("1", "1-0"),
        ("1", "1.0-0"),
        ("1.0", "1.0-0"),
        ("1a", "1-a"),
        ("1a", "1.0-a"),
        ("1a", "1.0.0-a"),
        ("1.0a", "1-a"),
        ("1.0.0a", "1-a"),
        ("1x", "1-x"),
        ("1x", "1.0-x"),
        ("1x", "1.0.0-x"),
        ("1.0x", "1-x"),
        ("1.0.0x", "1-x"),
        ("1ga", "1"),
        ("1release", "1"),
        ("1final", "1"),
        ("1cr", "1rc"),
        ("1a1", "1-alpha-1"),
        ("1b2", "1-beta-2"),
        ("1m3", "1-milestone-3"),
        ("1X", "1x"),
        ("1A", "1a"),
        ("1B", "1b"),
        ("1M", "1m"),
        ("1Ga", "1"),
        ("1GA", "1"),
        ("1RELEASE", "1"),
        ("1release", "1"),
        ("1RELeaSE", "1"),
        ("1Final", "1"),
        ("1FinaL", "1"),
        ("1FINAL", "1"),
        ("1Cr", "1Rc"),
        ("1cR", "1rC"),
        ("1m3", "1Milestone3"),
        ("1m3", "1MileStone3"),
        ("1m3", "1MILESTONE3"),
        ("1-abcdefghijklmnopqrstuvwxyz", "1-ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ] {
        eq(a, b);
    }
    // testVersionComparing
    for (a, b) in [
        ("1", "2"),
        ("1.5", "2"),
        ("1", "2.5"),
        ("1.0", "1.1"),
        ("1.1", "1.2"),
        ("1.0.0", "1.1"),
        ("1.0.1", "1.1"),
        ("1.1", "1.2.0"),
        ("1.0-alpha-1", "1.0"),
        ("1.0-alpha-1", "1.0-alpha-2"),
        ("1.0-alpha-1", "1.0-beta-1"),
        ("1.0-beta-1", "1.0-SNAPSHOT"),
        ("1.0-SNAPSHOT", "1.0"),
        ("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"),
        ("1.0", "1.0-1"),
        ("1.0-1", "1.0-2"),
        ("1.0.0", "1.0-1"),
        ("2.0-1", "2.0.1"),
        ("2.0.1-klm", "2.0.1-lmn"),
        ("2.0.1", "2.0.1-xyz"),
        ("2.0.1", "2.0.1-123"),
        ("2.0.1-xyz", "2.0.1-123"),
        // MNG-5568
        ("6.1.0rc3", "6.1.0"),
        ("6.1.0rc3", "6.1H.5-beta"),
        ("6.1.0", "6.1H.5-beta"),
        // MNG-6572
        ("20190126.230843", "1234567890.12345"),
        ("1234567890.12345", "123456789012345.1H.5-beta"),
        ("20190126.230843", "123456789012345.1H.5-beta"),
        ("123456789012345.1H.5-beta", "12345678901234567890.1H.5-beta"),
        ("1234567890.12345", "12345678901234567890.1H.5-beta"),
        ("20190126.230843", "12345678901234567890.1H.5-beta"),
        // MNG-6964
        ("1-0.alpha", "1"),
        ("1-0.beta", "1"),
        ("1-0.alpha", "1-0.beta"),
    ] {
        lt(a, b);
    }
    // testVersionEqualWithLeadingZeroes, testVersionZeroEqualWithLeadingZeroes
    for n in 1..=19 {
        eq(&format!("{}1", "0".repeat(n - 1)), "1");
        eq(&"0".repeat(n), "0");
    }
    // testMng7644
    for x in ["abc", "alpha", "a", "beta", "b", "def", "milestone", "m", "RC"] {
        lt(&format!("1.0.0.{x}1"), &format!("1.0.0-{x}2"));
        eq(&format!("2-{x}"), &format!("2.0.{x}"));
        eq(&format!("2-{x}"), &format!("2.0.0.{x}"));
        eq(&format!("2.0.{x}"), &format!("2.0.0.{x}"));
    }
}

#[test]
fn odd_input_never_panics() {
    for v in ["", "-", ".", "..-", "é", "1-é2", "--1", "1..", "v1.2"] {
        let _ = cmp(v, "1.0");
    }
    assert_eq!(cmp("", "0"), Ordering::Equal);
}
