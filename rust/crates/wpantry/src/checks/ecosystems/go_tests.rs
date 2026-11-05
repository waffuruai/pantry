use super::*;

/// x/mod/semver's semver_test.go `tests`, in its order: each entry is
/// (version, canonical form, "" when invalid). The test asserts that
/// Compare follows the list order, with equal canonical forms equal.
const TESTS: &[(&str, &str)] = &[
    ("bad", ""),
    ("v1-alpha.beta.gamma", ""),
    ("v1-pre", ""),
    ("v1+meta", ""),
    ("v1-pre+meta", ""),
    ("v1.2-pre", ""),
    ("v1.2+meta", ""),
    ("v1.2-pre+meta", ""),
    ("v1.0.0-alpha", "v1.0.0-alpha"),
    ("v1.0.0-alpha.1", "v1.0.0-alpha.1"),
    ("v1.0.0-alpha.beta", "v1.0.0-alpha.beta"),
    ("v1.0.0-beta", "v1.0.0-beta"),
    ("v1.0.0-beta.2", "v1.0.0-beta.2"),
    ("v1.0.0-beta.11", "v1.0.0-beta.11"),
    ("v1.0.0-rc.1", "v1.0.0-rc.1"),
    ("v1", "v1.0.0"),
    ("v1.0", "v1.0.0"),
    ("v1.0.0", "v1.0.0"),
    ("v1.2", "v1.2.0"),
    ("v1.2.0", "v1.2.0"),
    ("v1.2.3-456", "v1.2.3-456"),
    ("v1.2.3-456.789", "v1.2.3-456.789"),
    ("v1.2.3-456-789", "v1.2.3-456-789"),
    ("v1.2.3-456a", "v1.2.3-456a"),
    ("v1.2.3-pre", "v1.2.3-pre"),
    ("v1.2.3-pre+meta", "v1.2.3-pre"),
    ("v1.2.3-pre.1", "v1.2.3-pre.1"),
    ("v1.2.3-zzz", "v1.2.3-zzz"),
    ("v1.2.3", "v1.2.3"),
    ("v1.2.3+meta", "v1.2.3"),
    ("v1.2.3+meta-pre", "v1.2.3"),
    ("v1.2.3+meta-pre.sha.256a", "v1.2.3"),
];

#[test]
fn x_mod_semver_order() {
    for (i, (a, ca)) in TESTS.iter().enumerate() {
        for (j, (b, cb)) in TESTS.iter().enumerate() {
            let want = if ca == cb { Ordering::Equal } else { i.cmp(&j) };
            assert_eq!(cmp(a, b), want, "{a} vs {b}");
        }
    }
}

#[test]
fn osv_forms() {
    assert_eq!(cmp("1.2.3", "v1.2.3"), Ordering::Equal);
    assert_eq!(cmp("0.0.0-20191109021931-daa7c04131f5", "0.1.0"), Ordering::Less);
    assert_eq!(cmp("2.0.0+incompatible", "2.0.0"), Ordering::Equal);
    assert_eq!(cmp("1.21.3", "1.21.10"), Ordering::Less);
    assert_eq!(cmp("v1.02.0", "v0.1.0"), Ordering::Less, "leading zeros are invalid");
}
