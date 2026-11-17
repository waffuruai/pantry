use super::*;

fn pins(text: &str) -> Vec<(String, String)> {
    parse(text).unwrap().0.into_iter().map(|p| (p.name, p.version)).collect()
}

#[test]
fn the_file_name_says_dev_or_nothing() {
    use super::super::Scope;
    for dev in ["requirements-dev.txt", "requirements_test.txt", "requirements.docs.txt", "requirements-ci.txt"] {
        assert_eq!(scope_of_file(dev), Scope::Dev, "{dev}");
    }
    for plain in ["requirements.txt", "requirements-prod.txt", "requirements.lock.txt"] {
        assert_eq!(scope_of_file(plain), Scope::Unknown, "{plain}");
    }
}

#[test]
fn only_exact_pins() {
    let text = "\
# a comment
Flask==2.0.1
requests[security,socks] == 2.31.0 ; python_version >= \"3.8\"
urllib3>=1.26
idna==3.*
six==1.16.0,!=1.15
zope.interface===5.4.0
numpy==1.26.0 \\
    --hash=sha256:aaa \\
    --hash=sha256:bbb
-e ./local
-e git+https://github.com/x/y.git#egg=y
pkg @ https://example.com/pkg-1.0.tar.gz
./wheels/foo-1.0-py3-none-any.whl
--index-url https://pypi.org/simple
attrs==23.1.0  # trailing comment
name-with#hash==1.0 # and a comment
token==${VERSION}
Pillow (==10.0.0)
";
    assert_eq!(
        pins(text),
        [
            ("flask".into(), "2.0.1".into()),
            ("requests".into(), "2.31.0".into()),
            ("zope-interface".into(), "5.4.0".into()),
            ("numpy".into(), "1.26.0".into()),
            ("attrs".into(), "23.1.0".into()),
            ("pillow".into(), "10.0.0".into()),
        ]
    );
    let (_, inc) =
        parse("-r base.txt\n--requirement=dev.txt\n--requirement more.txt\n-rother.txt\n-c c.txt\n").unwrap();
    assert_eq!(inc, ["base.txt", "dev.txt", "more.txt", "other.txt"]);
}

#[test]
fn includes_stay_in_the_repo_and_cycles_end() {
    let tmp = crate::utils::temp::TempDir::new("requirements").unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(tmp.path().join("outside.txt"), "evil==6.6.6\n").unwrap();
    std::fs::write(root.join("requirements.txt"), "-r sub/requirements-dev.txt\na==1.0\n").unwrap();
    std::fs::write(
        root.join("sub/requirements-dev.txt"),
        "-r ../requirements.txt\n-r ../../outside.txt\n-r missing.txt\nb==2.0\n",
    )
    .unwrap();
    let got: Vec<String> = parse_file(&root.join("requirements.txt"), &root)
        .unwrap()
        .iter()
        .map(|p| format!("{} {}", p.name, p.version))
        .collect();
    assert_eq!(got, ["a 1.0", "b 2.0"]);
    // Through the default root (the file's own directory) the parent is out of reach.
    let only_dev = crate::checks::lockfiles::extract(&root.join("sub/requirements-dev.txt")).unwrap().unwrap();
    assert_eq!(only_dev, [Package::new("PyPI", "b", "2.0").scoped(super::super::Scope::Dev)]);
    assert!(parse_file(&root.join("nope.txt"), &root).is_err(), "a missing top file is an error");
}
