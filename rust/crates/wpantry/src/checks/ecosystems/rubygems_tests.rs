use super::*;

fn segs(v: &str) -> Vec<Seg<'static>> {
    let n: &'static str = Box::leak(normalize(v).unwrap().into_boxed_str());
    canonical(n)
}

// The vectors of rubygems' test/rubygems/test_gem_version.rb (MIT).
#[test]
fn rubygems_test_gem_version() {
    use Ordering::*;
    // test_initialize, test_empty_version, test_class_correct
    for good in ["1.0", "1.0 ", " 1.0 ", "1.0\n", "\n1.0\n"] {
        assert_eq!(cmp("1.0", good), Equal, "{good:?}");
    }
    for empty in ["", "   ", " "] {
        assert_eq!(normalize(empty).as_deref(), Some("0"));
    }
    assert!(normalize("5.1").is_some() && normalize("an incorrect version").is_none());
    // test_initialize_invalid
    for bad in ["junk", "1.0\n2.0", "1..2", "1.2 3.4", "2.3422222.222.222222222.22222.ads0as.dasd0.ddd2222.2.qd3e."] {
        assert!(normalize(bad).is_none(), "{bad:?}");
    }
    // test_equals2, test_hash, test_eql_eh (== ignores eql?)
    assert_eq!(cmp("1.2", "1.2"), Equal);
    assert_ne!(cmp("1.2", "1.3"), Equal);
    assert_eq!(cmp("1.2.b1", "1.2.b.1"), Equal);
    assert_eq!(cmp("1.2", "1.2.0"), Equal);
    assert_eq!(cmp("1.2.pre.1", "1.2.0.pre.1.0"), Equal);
    // test_spaceship
    let spaceship = [
        ("1.0", "1.0.0", Equal),
        ("1.0", "1.0.a", Greater),
        ("1.8.2", "0.0.0", Greater),
        ("1.8.2", "1.8.2.a", Greater),
        ("1.8.2.b", "1.8.2.a", Greater),
        ("1.8.2.a", "1.8.2", Less),
        ("1.8.2.a10", "1.8.2.a9", Greater),
        ("", "0", Equal),
        ("0.beta.1", "0.0.beta.1", Equal),
        ("0.0.beta", "0.0.beta.1", Less),
        ("0.0.beta", "0.beta.1", Less),
        ("5.a", "5.0.0.rc2", Less),
        ("5.x", "5.0.0.rc2", Greater),
        ("1.9.3", "1.9.3", Equal),
        ("1.9.3", "1.9.2.99", Greater),
        ("1.9.3", "1.9.3.1", Less),
    ];
    for (a, b, want) in spaceship {
        assert_eq!(cmp(a, b), want, "{a} <=> {b}");
        assert_eq!(cmp(b, a), want.reverse(), "{b} <=> {a}");
    }
    // test_semver
    for (a, b) in [
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-beta.2"),
        ("1.0.0-beta.2", "1.0.0-beta.11"),
        ("1.0.0-beta.11", "1.0.0-rc.1"),
        ("1.0.0-rc1", "1.0.0"),
        ("1.0.0-1", "1"),
    ] {
        assert_eq!(cmp(a, b), Less, "{a} < {b}");
    }
    // test_sort_key_*: timestamps, segments over the radix, many segments
    assert_eq!(cmp("1.0.0", "0.0.1.20220404083012"), Greater);
    assert_eq!(cmp("0.7.0", "0.6.63000"), Greater);
    assert_eq!(cmp("18.0.1", "18.0.2"), Less);
    assert_eq!(cmp("2.30.1.250000", "2.30.1.249999"), Greater);
    assert_eq!(cmp("1.1.1.1.1.1.1", "1.1.1.1.1.1"), Greater);
    // test_canonical_segments
    assert_eq!(segs("1.0.0"), [Seg::Num("1")]);
    assert_eq!(segs("1.0.0.a.1.0"), [Seg::Num("1"), Seg::Word("a"), Seg::Num("1")]);
    assert_eq!(segs("1.2.3-1"), [Seg::Num("1"), Seg::Num("2"), Seg::Num("3"), Seg::Word("pre"), Seg::Num("1")]);
    // test_prerelease ordering against its release
    for pre in ["1.2.0.a", "2.9.b", "22.1.50.0.d", "1.2.d.42", "1.A", "1-1", "1-a"] {
        assert!(normalize(pre).unwrap().bytes().any(|b| b.is_ascii_alphabetic()), "{pre}");
    }
}

#[test]
fn never_panics_and_falls_back() {
    assert_eq!(cmp("junk", "1.0"), crate::checks::ecosystems::versions::cmp("junk", "1.0"));
    assert_eq!(cmp("99999999999999999999999.0", "99999999999999999999998.9"), Ordering::Greater);
    assert_eq!(
        cmp("1.0.0-x86_64-linux", "1.0.0"),
        crate::checks::ecosystems::versions::cmp("1.0.0-x86_64-linux", "1.0.0")
    );
}
