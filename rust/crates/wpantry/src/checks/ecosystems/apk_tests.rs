use super::*;
use crate::checks::ecosystems::assert_sorted;

#[test]
fn apk_version_data() {
    // Cases from apk-tools' test/version.data (`apk version -t`).
    let cases: &[(&str, &str, Ordering)] = &[
        ("2.34", "0.1.0_alpha", Ordering::Greater),
        ("0.1.0_alpha", "0.1.0_alpha", Ordering::Equal),
        ("0.1.0_alpha", "0.1.3_alpha", Ordering::Less),
        ("0.1.3_alpha", "0.1.0_alpha", Ordering::Greater),
        ("0.1.0_alpha2", "0.1.0_alpha", Ordering::Greater),
        ("0.1.0_alpha", "0.1.0_alpha2", Ordering::Less),
        ("0.1.0_alpha", "0.1.0_beta", Ordering::Less),
        ("0.1.0_beta", "0.1.0_alpha", Ordering::Greater),
        ("0.1.0_rc1", "0.1.0", Ordering::Less),
        ("1.0", "1.0_p1", Ordering::Less),
        ("1.0_p1", "1.1", Ordering::Less),
        ("1.0-r1", "1.0-r2", Ordering::Less),
        ("1.0-r9", "1.0-r10", Ordering::Less),
        ("1.0", "1.0-r1", Ordering::Less),
        ("1.0a", "1.0", Ordering::Greater),
        ("1.0a", "1.0b", Ordering::Less),
        ("1.0a", "1.0.1", Ordering::Less),
        ("1.0", "1.0.1", Ordering::Less),
        ("2.4.10", "2.4.9", Ordering::Greater),
        ("3.0.15-r0", "3.1.0-r0", Ordering::Less),
        ("1.2.3_rc1-r0", "1.2.3-r0", Ordering::Less),
        ("3.3.2-r0", "3.3.2-r0", Ordering::Equal),
        ("1.36.1-r29", "1.36.1-r30", Ordering::Less),
    ];
    for (a, b, want) in cases {
        assert_eq!(cmp(a, b), *want, "{a} vs {b}");
        assert_eq!(cmp(b, a), want.reverse(), "{b} vs {a}");
    }
    assert_sorted(
        cmp,
        &["1.0_alpha", "1.0_beta", "1.0_pre", "1.0_rc", "1.0", "1.0_cvs", "1.0_svn", "1.0_git", "1.0_hg", "1.0_p"],
    );
}

#[test]
fn odd_input_never_panics() {
    let odd = ["", "1.0\u{0}x", "1.0a1", "1.0+1", "1.0_rc1.2", "1.00", "1234567890123456789", "1.0_foo", "1.0-", "_"];
    for a in odd {
        for b in odd {
            assert_eq!(cmp(a, b), cmp(b, a).reverse(), "{a:?} vs {b:?}");
        }
        assert_eq!(cmp(a, a), Ordering::Equal, "{a:?}");
    }
    assert_eq!(cmp("", "1"), Ordering::Less);
    assert_eq!(cmp("1.0\u{0}x", "1.0"), Ordering::Equal, "apk reads up to a NUL");
    assert_eq!(cmp("1.0a1", "1.0a2"), Ordering::Less, "a digit after a letter");
    assert_eq!(cmp("1.00", "1.0"), Ordering::Less, "leading zeros count against a part");
    assert_eq!(cmp("1234567890123456789", "1"), Ordering::Less, "too many digits is invalid");
    assert_eq!(cmp("1.0_foo", "1.0"), Ordering::Less, "an unknown suffix is invalid");
    assert_eq!(cmp("1.0_rc1.2", "1.0_rc1"), Ordering::Greater, "a part after a suffix number is invalid");
}

/// `version.data` lines (`a < b`, `a > b`, `a = b`; `#` comments) checked
/// against [`cmp`]: how many were.
fn check_vectors(text: &str) -> usize {
    let mut n = 0;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let w: Vec<&str> = line.split_whitespace().collect();
        let [a, op, b] = w.as_slice() else { continue };
        let want = match *op {
            "<" => Ordering::Less,
            ">" => Ordering::Greater,
            "=" => Ordering::Equal,
            _ => continue,
        };
        assert_eq!(cmp(a, b), want, "{a} {op} {b}");
        n += 1;
    }
    n
}

#[test]
fn version_data_lines_are_read() {
    assert_eq!(check_vectors("# comment\n1.0 < 1.1 # trailing\n1.0 = 1.0\n1.1 > 1.0\n1.0 ? 1.0\nnot a case\n"), 3);
}

/// The whole of apk-tools' test/version.data (GPL-2.0, so not vendored
/// here): `WPANTRY_APK_VECTORS=path/to/version.data cargo test -- --ignored`.
#[test]
#[ignore]
fn apk_version_data_file() {
    let path = std::env::var("WPANTRY_APK_VECTORS").expect("WPANTRY_APK_VECTORS");
    let n = check_vectors(&std::fs::read_to_string(path).unwrap());
    assert!(n > 700, "{n} cases");
}
