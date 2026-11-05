use super::*;
use crate::checks::ecosystems::assert_sorted;

#[test]
fn dpkg_t_version_cases() {
    // From dpkg's lib/dpkg/t/t-version.c and deb-version(7).
    let cases: &[(&str, &str, Ordering)] = &[
        ("0", "0", Ordering::Equal),
        ("0:0", "0:0", Ordering::Equal),
        ("0:0-", "0:0-", Ordering::Equal),
        ("0:0-0", "0:0-0", Ordering::Equal),
        ("0:0.0-0.0", "0:0.0-0.0", Ordering::Equal),
        ("1.0", "0:1.0", Ordering::Equal),
        ("0:1.0", "1:1.0", Ordering::Less),
        ("1:0.9", "0:2.0", Ordering::Greater),
        ("0:1-0", "0:1-1", Ordering::Less),
        ("0:1.0-1", "0:1.0-2", Ordering::Less),
        ("0:0-0", "0:0", Ordering::Equal),
        ("0:0-0", "0:0-00", Ordering::Equal),
        ("0:0-a", "0:0-b", Ordering::Less),
        ("0:0-a", "0:0-0", Ordering::Greater),
        ("0:0-0", "0:0-1", Ordering::Less),
        ("0:0-a0", "0:0-a1", Ordering::Less),
        ("0:0.0~", "0:0.0", Ordering::Less),
        ("0:0~~", "0:0~", Ordering::Less),
        ("0:0~a", "0:0~", Ordering::Greater),
        ("1.2.3-1", "1.2.3-1+deb12u1", Ordering::Less),
        ("3.0.11-1~deb12u2", "3.0.11-1", Ordering::Less),
        ("2.36-9+deb12u7", "2.36-9+deb12u10", Ordering::Less),
        ("1.0+dfsg-1", "1.0-1", Ordering::Greater),
        ("7.88.1-10+deb12u5", "7.88.1-10+deb12u12", Ordering::Less),
    ];
    for (a, b, want) in cases {
        assert_eq!(cmp(a, b), *want, "{a} vs {b}");
        assert_eq!(cmp(b, a), want.reverse(), "{b} vs {a}");
    }
    // deb-version(7): ~~ < ~~a < ~ < (nothing) < a
    assert_sorted(cmp, &["1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a"]);
}
