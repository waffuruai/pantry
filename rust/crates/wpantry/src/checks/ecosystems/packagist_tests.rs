use super::*;

// composer/semver tests/VersionParserTest.php (MIT):
// successfulNormalizedVersions and failingNormalizedVersions.
#[test]
fn version_parser_normalize() {
    let ok = [
        ("1.0.0", "1.0.0.0"),
        ("1.2.3.4", "1.2.3.4"),
        ("1.0.0RC1dev", "1.0.0.0-RC1-dev"),
        ("1.0.0-rC15-dev", "1.0.0.0-RC15-dev"),
        ("1.0.0.RC.15-dev", "1.0.0.0-RC15-dev"),
        ("1.0.0-rc1", "1.0.0.0-RC1"),
        ("1.0.0.pl3-dev", "1.0.0.0-patch3-dev"),
        ("1.0-dev", "1.0.0.0-dev"),
        ("0", "0.0.0.0"),
        ("99999", "99999.0.0.0"),
        ("10.4.13-beta", "10.4.13.0-beta"),
        ("10.4.13beta2", "10.4.13.0-beta2"),
        ("10.4.13beta.2", "10.4.13.0-beta2"),
        ("v1.13.11-beta.0", "1.13.11.0-beta0"),
        ("1.13.11.0-beta0", "1.13.11.0-beta0"),
        ("10.4.13-b", "10.4.13.0-beta"),
        ("10.4.13-b5", "10.4.13.0-beta5"),
        ("v1.0.0", "1.0.0.0"),
        ("2010.01", "2010.01.0.0"),
        ("2010.01.02", "2010.01.02.0"),
        ("2010.1.555", "2010.1.555.0"),
        ("2010.10.200", "2010.10.200.0"),
        ("20230131.0.0", "20230131.0.0"),
        ("202301310000.0.0", "202301310000.0.0"),
        ("v20100102", "20100102"),
        ("20100102", "20100102"),
        ("20100102.0", "20100102.0"),
        ("20100102.1.0", "20100102.1.0"),
        ("20100102.0.3", "20100102.0.3"),
        ("100000", "100000"),
        ("2010-01-02-10-20-30.0.3", "2010.01.02.10.20.30.0.3"),
        ("2010-01-02-10-20-30.5", "2010.01.02.10.20.30.5"),
        ("2010-01-02", "2010.01.02"),
        ("2012.06.07", "2012.06.07.0"),
        ("2010-01-02.5", "2010.01.02.5"),
        ("20100102-203040", "20100102.203040"),
        ("20100102.x-dev", "20100102.9999999.9999999.9999999-dev"),
        ("20100102.203040.x-dev", "20100102.203040.9999999.9999999-dev"),
        ("20100102203040-10", "20100102203040.10"),
        ("20100102-203040-p1", "20100102.203040-patch1"),
        ("201903.0", "201903.0"),
        ("201903.x-dev", "201903.9999999.9999999.9999999-dev"),
        ("201903.0-p2", "201903.0-patch2"),
        ("dev-master", "dev-master"),
        ("master", "dev-master"),
        ("dev-trunk", "dev-trunk"),
        ("1.x-dev", "1.9999999.9999999.9999999-dev"),
        ("dev-feature-foo", "dev-feature-foo"),
        ("DEV-FOOBAR", "dev-FOOBAR"),
        ("dev-feature/foo", "dev-feature/foo"),
        ("dev-feature+issue-1", "dev-feature+issue-1"),
        ("dev-master as 1.0.0", "dev-master"),
        ("dev-load-varnish-only-when-used as ^2.0", "dev-load-varnish-only-when-used"),
        ("dev-load-varnish-only-when-used@dev as ^2.0@dev", "dev-load-varnish-only-when-used"),
        ("1.0.0+foo@dev", "1.0.0.0"),
        ("dev-load-varnish-only-when-used@stable", "dev-load-varnish-only-when-used"),
        ("1.0.0-beta.5+foo", "1.0.0.0-beta5"),
        ("1.0.0+foo", "1.0.0.0"),
        ("1.0.0-alpha.3.1+foo", "1.0.0.0-alpha3.1"),
        ("1.0.0-alpha2.1+foo", "1.0.0.0-alpha2.1"),
        ("1.0.0-alpha-2.1-3+foo", "1.0.0.0-alpha2.1-3"),
        ("1.0.0+foo as 2.0", "1.0.0.0"),
        ("00.01.03.04", "00.01.03.04"),
        ("000.001.003.004", "000.001.003.004"),
        ("0.000.103.204", "0.000.103.204"),
        ("0700", "0700.0.0.0"),
        ("041.x-dev", "041.9999999.9999999.9999999-dev"),
        ("dev-041.003", "dev-041.003"),
        ("dev-1.0.0-dev<1.0.5-dev", "dev-1.0.0-dev<1.0.5-dev"),
        ("dev-foo bar", "dev-foo bar"),
        (" 1.0.0", "1.0.0.0"),
        ("1.0.0 ", "1.0.0.0"),
    ];
    for (input, want) in ok {
        assert_eq!(normalize(input).as_deref(), Some(want), "{input:?}");
    }
    let bad = [
        "",
        "a",
        "1.0.0-meh",
        "1.0.0.0.0",
        "feature-foo",
        "1.0.0+foo bar",
        "1.0.1-SNAPSHOT",
        "1.0.0<1.0.5-dev",
        "1.0.0-dev<1.0.5-dev",
        "foo bar-dev",
        "1.0 .2",
        " as ",
        " as 1.2",
        "^",
        "^8 || ^",
        "~",
        "~1 ~",
        "~1",
        "^1",
        "1.*",
        "20100102.0.3.4",
        "100000.0.0.0",
        "2023013.0.0",
        "202301311.0.0",
        "20230131000.0.0",
        "2023013100000.0.0",
    ];
    for input in bad {
        assert_eq!(normalize(input), None, "{input:?}");
    }
}

// composer/semver tests/ComparatorTest.php compareProvider (MIT), on raw
// strings as Comparator::compare passes them to version_compare.
#[test]
fn comparator_test() {
    use Ordering::*;
    let cases = [
        ("1.25.0", "1.24.0", Greater),
        ("1.25.0", "1.25.0", Equal),
        ("1.25.0", "1.26.0", Less),
        ("1.25.0-beta2.1", "1.25.0-b.3", Less),
        ("1.25.0-b2.1", "1.25.0beta.3", Less),
        ("1.25.0-b-2.1", "1.25.0-rc", Less),
        ("1.25.0-beta2.1", "1.25.0-b.2.1", Equal),
        ("1.25.0beta2.1", "1.25.0-b2.1", Equal),
        ("1.0.0", "1.2-dev", Less),
        ("dev-foo", "1.26.0", Less),
        ("1.26.0", "dev-foo", Greater),
    ];
    for (a, b, want) in cases {
        assert_eq!(version_compare(a.as_bytes(), b.as_bytes()), want, "{a} vs {b}");
        assert_eq!(cmp(a, b), want, "{a} vs {b} normalized");
    }
}

// composer/semver tests/SemverTest.php sortProvider (MIT).
#[test]
fn semver_sort() {
    let mut v = vec!["1.0", "0.1", "0.1", "3.2.1", "2.4.0-alpha", "2.4.0"];
    v.sort_by(|a, b| cmp(a, b));
    assert_eq!(v, ["0.1", "0.1", "1.0", "2.4.0-alpha", "2.4.0", "3.2.1"]);
    let mut v = vec!["dev-foo", "dev-master", "1.0", "50.2"];
    v.sort_by(|a, b| cmp(a, b));
    assert_eq!(v, ["dev-foo", "1.0", "50.2", "dev-master"]);
}

#[test]
fn lockfile_spellings() {
    assert_eq!(cmp("v6.4.0", "6.4.0"), Ordering::Equal);
    assert_eq!(cmp("v6.4.1", "6.4.0"), Ordering::Greater);
    assert_eq!(cmp("2.0.0-RC1", "2.0.0"), Ordering::Less);
    assert_eq!(cmp("2.0.0", "2.0.0-p1"), Ordering::Less);
    assert_eq!(cmp("not a version", "1.0"), crate::checks::ecosystems::versions::cmp("not a version", "1.0"));
    let _ = cmp(&"9".repeat(4000), "1");
}
