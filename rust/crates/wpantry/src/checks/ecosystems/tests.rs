use super::*;

#[test]
fn ecosystems() {
    assert_eq!(order("Debian:12"), Comparator::Dpkg);
    assert_eq!(order("Ubuntu:24.04:LTS"), Comparator::Dpkg);
    assert_eq!(order("Alpine:v3.20"), Comparator::Apk);
    assert_eq!(order("openSUSE:Leap 15.6"), Comparator::Rpm);
    assert_eq!(order("PyPI"), Comparator::Pep440);
    assert_eq!(order("RubyGems"), Comparator::RubyGems);
    assert_eq!(order("Maven"), Comparator::Maven);
    assert_eq!(order("Packagist"), Comparator::Packagist);
    assert_eq!(order("ConanCenter"), Comparator::Generic);
    assert_eq!(order("GIT"), Comparator::Generic);
    assert_eq!(order("VSCode:https://open-vsx.org"), Comparator::Generic);
    assert_eq!(order("crates.io"), Comparator::Semver);
    assert_eq!(Comparator::Semver.cmp("1.0.0-rc.1", "1.0.0"), Ordering::Less);
}

#[test]
fn each_name_is_listed_once() {
    for (i, e) in ECOSYSTEMS.iter().enumerate() {
        assert!(ECOSYSTEMS[..i].iter().all(|f| f.osv != e.osv), "{} twice", e.osv);
    }
}

#[test]
fn sources_name_ecosystems_their_own_way() {
    assert_eq!(deps_dev("crates.io"), Some("cargo"));
    assert_eq!(deps_dev("PyPI"), Some("pypi"));
    assert_eq!(deps_dev("Packagist"), None);
    assert_eq!(deps_dev("Debian:12"), None);
    assert_eq!(openssf("VSCode"), Some("vscode"));
    assert_eq!(openssf("VSCode:https://open-vsx.org"), Some("vscode:open-vsx.org"));
    assert_eq!(openssf("VSCode:https://example.com"), None, "only an exact name has a directory");
    assert_eq!(openssf("Hex"), None);
    assert_eq!(normalize("PyPI", "Foo__Bar.baz"), "foo-bar-baz");
    assert_eq!(normalize("npm", "Trailing_"), "trailing_");
}

#[test]
fn each_comparator_dispatches_to_its_ecosystem() {
    assert_eq!(Comparator::Pep440.cmp("1.0a1", "1.0"), Ordering::Less);
    assert_eq!(Comparator::Go.cmp("v1.2.0", "v1.10.0"), Ordering::Less);
    assert_eq!(Comparator::Dpkg.cmp("1:1.0", "2.0"), Ordering::Greater);
    assert_eq!(Comparator::Apk.cmp("1.0_rc1", "1.0"), Ordering::Less);
    assert_eq!(Comparator::Rpm.cmp("1.0-1.el9", "1.0-2.el9"), Ordering::Less);
    assert_eq!(Comparator::RubyGems.cmp("1.0.0.pre", "1.0.0"), Ordering::Less);
    assert_eq!(Comparator::Maven.cmp("1.0-SNAPSHOT", "1.0"), Ordering::Less);
    assert_eq!(Comparator::Packagist.cmp("1.0.0-beta", "1.0.0"), Ordering::Less);
    assert_eq!(Comparator::Generic.cmp("1.2", "1.10"), Ordering::Less);
    assert_eq!(Comparator::Generic.cmp("2.0", "2.0"), Ordering::Equal);
}
