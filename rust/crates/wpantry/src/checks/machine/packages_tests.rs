use super::*;
use crate::utils::temp;

#[test]
fn global_packages_reads_npm_root() {
    let d = crate::utils::temp::TempDir::new("npmroot").unwrap();
    let pkg = |dir: &str, json: &str| {
        std::fs::create_dir_all(d.path().join(dir)).unwrap();
        std::fs::write(d.path().join(dir).join("package.json"), json).unwrap();
    };
    pkg("typescript", r#"{"name": "typescript", "version": "5.9.3"}"#);
    pkg("npm", r#"{"name": "npm", "version": "11.20.0"}"#);
    pkg("@openai/codex", r#"{"name": "@openai/codex", "version": "0.70.0"}"#);
    std::fs::create_dir_all(d.path().join(".bin")).unwrap();
    std::fs::create_dir_all(d.path().join("half-installed")).unwrap();
    // `npm link` leaves a symlink to the package's own folder.
    let linked = crate::utils::temp::TempDir::new("linked").unwrap();
    std::fs::write(linked.path().join("package.json"), r#"{"name": "mine", "version": "1.0.0"}"#).unwrap();
    std::os::unix::fs::symlink(linked.path(), d.path().join("mine")).unwrap();
    let got = global_packages(d.path()).unwrap();
    let want = [("npm", "11.20.0"), ("@openai/codex", "0.70.0"), ("mine", "1.0.0"), ("typescript", "5.9.3")];
    assert_eq!(got, want.map(|(n, v)| (n.to_string(), v.to_string())));
    assert_eq!(global_packages(&d.path().join("nowhere")), None);
}

#[test]
fn json_inside_noisy_output() {
    assert_eq!(json_in("WARNING: x\n[{\"name\": \"pip\"}]\nnotice", '[', ']').unwrap()[0]["name"], "pip");
    assert_eq!(json_in("nothing", '{', '}'), None);
    assert_eq!(json_in("} {", '{', '}'), None);
}

#[test]
fn installed_distributions_from_metadata() {
    let d = temp::TempDir::new("sites").unwrap();
    let (venv, user) = (d.path().join("venv"), d.path().join("user"));
    let put = |p: std::path::PathBuf, text: &str| {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    };
    put(
        venv.join("pip-26.2.2.dist-info/METADATA"),
        "Metadata-Version: 2.1\nName: pip\nVersion: 26.2.2\n\nVersion: 0 (body)\n",
    );
    put(venv.join("Jinja2-3.1.4.dist-info/METADATA"), "Name: Jinja2\nVersion: 3.1.4\n");
    put(venv.join("old.egg-info/PKG-INFO"), "Name: old\nVersion: 0.1\n");
    put(venv.join("legacy-1.0-py3.9.egg-info"), "Name: legacy\nVersion: 1.0\n");
    put(venv.join("broken.dist-info/METADATA"), "Name: broken\n");
    std::fs::create_dir_all(venv.join("half-1.0.dist-info")).unwrap();
    put(venv.join("review_hook.pth"), "import os; os.system('never run')\n");
    put(user.join("jinja2-2.0.dist-info/METADATA"), "Name: jinja2\nVersion: 2.0\n");
    let sites = [venv.display().to_string(), user.display().to_string(), "/nonexistent".into()];
    let (got, gaps) = installed(&sites);
    assert_eq!(
        got,
        [
            ("Jinja2".to_string(), "3.1.4".to_string()),
            ("legacy".into(), "1.0".into()),
            ("old".into(), "0.1".into()),
            ("pip".into(), "26.2.2".into())
        ],
        "the first of a name on the path wins; nothing without a version"
    );
    assert_eq!(gaps.len(), 2, "metadata without a version, and a dist-info without metadata: {gaps:?}");
    assert!(gaps[0].contains("broken.dist-info/METADATA: no Version"), "{gaps:?}");
    assert!(gaps[1].contains("half-1.0.dist-info/METADATA"), "{gaps:?}");
}

/// The probe lists the base interpreter's site-packages for a venv made
/// with `--system-site-packages`, and not otherwise, on every Python
/// here (from 3.14 a venv is `sys.prefix` even under `-S`).
#[test]
fn the_probe_lists_the_sites_a_venv_inherits() {
    let d = temp::TempDir::new("venvs").unwrap();
    let mut pythons: Vec<String> = which("python3").into_iter().map(|p| p.display().to_string()).collect();
    pythons.extend(
        ["python3.12", "python3.13", "python3.14", "python3.15"]
            .iter()
            .filter_map(|n| which(n))
            .map(|p| p.display().to_string()),
    );
    let sites_of = |py: &str| -> Vec<String> {
        let raw = sh(&[py, "-I", "-S", "-c", PY_INFO], 30);
        let info = json_in(raw.trim().lines().last().unwrap_or(""), '{', '}').unwrap_or(Value::Null);
        crate::utils::json::strs_at(&info, "sites")
    };
    for (i, py) in pythons.iter().enumerate() {
        // The user site first, then the interpreter's own.
        let base: Vec<String> = sites_of(py).into_iter().skip(1).collect();
        if base.is_empty() {
            continue;
        }
        for (flag, inherits) in [("--system-site-packages", true), ("--without-pip", false)] {
            let venv = d.path().join(format!("{i}{flag}"));
            let made = sh(&[py, "-m", "venv", "--without-pip", flag, &venv.display().to_string()], 60);
            let vpy = venv.join("bin/python3");
            if !vpy.exists() {
                panic!("{py} -m venv {flag}: {made}");
            }
            let sites = sites_of(&vpy.display().to_string());
            let own = format!("{i}{flag}/lib/python"); // the probe may resolve the temp dir's symlink
            assert!(sites.iter().any(|s| s.contains(&own)), "{py} {flag}: no venv site in {sites:?}");
            let has_base = base.iter().any(|b| sites.contains(b));
            assert_eq!(has_base, inherits, "{py} {flag}: base {base:?}, venv sites {sites:?}");
        }
    }
}

#[test]
fn gem_and_cargo_lines() {
    let gem = Regex::new(r"^(\S+) \((?:default: )?([^,)\s]+)");
    let m = gem.match_start("json (default: 2.7.2, 2.6.1)").unwrap();
    assert_eq!((m.get(1), m.get(2)), ("json", "2.7.2"));
    let cargo = Regex::new(r"(\S+) (\S+) \(registry\+");
    let m = cargo.match_start("ripgrep 14.1.1 (registry+https://github.com/rust-lang/crates.io-index)").unwrap();
    assert_eq!((m.get(1), m.get(2)), ("ripgrep", "14.1.1"));
}

#[test]
fn json_strings_of_a_value() {
    let v = serde_json::json!({"s": "x", "n": null, "i": 3});
    assert_eq!(str_of(&v, "s"), "x");
    assert_eq!(str_of(&v, "n"), "");
    assert_eq!(str_of(&v, "missing"), "");
    assert_eq!(str_of(&v, "i"), "3");
}

/// An executable script at `dir/name` answering by its first arguments.
#[cfg(unix)]
fn script(dir: &Path, name: &str, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    files::realpath(&p.display().to_string()) // the probes resolve symlinks (/var on macOS)
}

/// The probe's JSON for each interpreter becomes a runtime and its
/// packages; interpreters that resolve to the same file are one; a
/// probe that fails is skipped; what couldn't be read is reported.
#[test]
fn pythons_from_probe_answers() {
    let home = files::test_home();
    let d = temp::TempDir::new("pyprobe").unwrap();
    let site = d.path().join("site-packages");
    std::fs::create_dir_all(site.join("requests-2.32.0.dist-info")).unwrap();
    std::fs::write(site.join("requests-2.32.0.dist-info/METADATA"), "Name: requests\nVersion: 2.32.0\n").unwrap();
    std::fs::create_dir_all(site.join("pip-25.0.dist-info")).unwrap();
    std::fs::write(site.join("pip-25.0.dist-info/METADATA"), "Name: pip\nVersion: 25.0\n").unwrap();
    std::fs::create_dir_all(site.join("half-1.dist-info")).unwrap();
    let (plain, managed, uv) = ("/x/bin/python3", "/usr/bin/python3.13", "/x/uv/python/cpython-3.13/bin/python3");
    let info = |exe: &str, managed: bool| {
        format!(
            "warning\n{{\"v\": \"3.13.2\", \"exe\": \"{exe}\", \"sites\": [\"{}\"], \"managed\": {managed}}}",
            site.display()
        )
    };
    let probe = move |shown: &str| match shown {
        "/x/bin/python3" => info("/x/bin/python3.13", false),
        "/x/bin/python3.13" => info("/x/bin/python3.13", false),
        "/usr/bin/python3.13" => info("/usr/bin/python3.13", true),
        "/x/uv/python/cpython-3.13/bin/python3" => info("/x/uv/python/cpython-3.13/bin/python3", true),
        _ => "Traceback: boom\n".to_string(),
    };
    let found: Vec<(String, String)> = [plain, "/x/bin/python3.13", managed, uv, "/nowhere/python3"]
        .iter()
        .map(|p| (p.to_string(), p.to_string()))
        .collect();
    let (got, unread) = pythons_from(found, &probe);
    let runtimes: Vec<&str> = got.iter().filter(|c| c.kind == "runtime").map(|c| c.path.as_str()).collect();
    assert_eq!(runtimes, [plain, managed, uv], "the second path to the same interpreter is skipped");
    let rt = &got[0];
    assert_eq!((rt.name.as_str(), rt.version.as_str()), ("python", "3.13.2"));
    assert_eq!(rt.osv, Some(("GIT".into(), github("python/cpython"), "v3.13.2".into())));
    assert_eq!(rt.eol, Some(("python".into(), "3.13".into())));
    let pkgs = |py: &str| -> Vec<(String, String, String, bool)> {
        got.iter()
            .filter(|c| c.path == py && c.kind != "runtime")
            .map(|c| (c.kind.clone(), c.name.clone(), c.fix.clone(), c.auto))
            .collect()
    };
    assert_eq!(
        pkgs(plain),
        [
            (
                "pkgmgr".to_string(),
                "pip".to_string(),
                format!("{plain} -m pip install --upgrade 'pip>={{safe}}'"),
                true
            ),
            (
                "package".into(),
                "pip:requests".into(),
                format!("{plain} -m pip install --upgrade 'requests>={{safe}}'"),
                true
            ),
        ]
    );
    assert_eq!(
        pkgs(managed)[1],
        (
            "package".into(),
            "pip:requests".into(),
            format!("Upgrade requests through the package manager that owns {managed}"),
            false
        )
    );
    let (uv_fix, uv_auto) = updater(uv, "python");
    assert_eq!(pkgs(uv)[0], ("pkgmgr".into(), "pip".into(), uv_fix, uv_auto), "uv's pip comes with its Python");
    assert_eq!(unread.len(), 3, "{unread:?}");
    assert!(unread.iter().all(|(py, gaps)| gaps.len() == 1 && gaps[0].contains("half-1.dist-info") && !py.is_empty()));
    drop(home);
}

/// The real interpreters on this machine, probed for real: every
/// runtime has a version, and nothing is listed twice.
#[test]
fn pythons_on_this_machine_are_consistent() {
    let (got, _) = pythons();
    let runtimes: Vec<&Component> = got.iter().filter(|c| c.kind == "runtime").collect();
    assert!(runtimes.iter().all(|c| c.name == "python" && !c.version.is_empty()));
    let mut paths: Vec<&str> = runtimes.iter().map(|c| c.path.as_str()).collect();
    paths.dedup();
    assert_eq!(paths.len(), runtimes.len());
}

#[cfg(unix)]
#[test]
fn npm_globals_from_the_root_or_npm_ls() {
    let bin = temp::TempDir::new("nodebin").unwrap();
    let root = temp::TempDir::new("npmroot2").unwrap();
    for (dir, json) in [
        ("npm", r#"{"name": "npm", "version": "11.1.0"}"#),
        ("corepack", r#"{"version": "0.30.0"}"#),
        ("left-pad", r#"{"version": "1.3.0"}"#),
        ("broken", r#"{"name": "broken"}"#),
    ] {
        std::fs::create_dir_all(root.path().join(dir)).unwrap();
        std::fs::write(root.path().join(dir).join("package.json"), json).unwrap();
    }
    let node = script(bin.path(), "node", "echo v22.0.0\n");
    let n = Component::new("runtime", "node", "22.0.0", &node);
    assert!(npm_globals(&n).is_empty(), "no npm beside node");
    let npm = script(bin.path(), "npm", &format!("case \"$1\" in root) echo \"{}\";; esac\n", root.path().display()));
    let got = node_packages(&[n.clone(), Component::new("runtime", "ruby", "3", "/x")]);
    let names: Vec<(&str, &str, &str)> =
        got.iter().map(|c| (c.kind.as_str(), c.name.as_str(), c.version.as_str())).collect();
    assert_eq!(
        names,
        [("pkgmgr", "npm", "11.1.0"), ("pkgmgr", "corepack", "0.30.0"), ("package", "npm:left-pad", "1.3.0")]
    );
    assert_eq!(got[2].osv, Some(("npm".into(), "left-pad".into(), "1.3.0".into())));
    assert_eq!(got[2].fix, format!("{npm} install -g left-pad@{{safe}}"));
    assert!(got[2].auto && got[2].path == npm);
    // No usable root: `npm ls -g --json`, with npm's own version asked separately.
    let ls = r#"{"dependencies": {"typescript": {"version": "5.9.3"}, "odd": {}}}"#;
    script(
        bin.path(),
        "npm",
        &format!("case \"$1\" in root) echo 'npm warn nothing';; ls) echo '{ls}';; --version) echo 11.2.0;; esac\n"),
    );
    let got = npm_globals(&n);
    let names: Vec<(&str, &str)> = got.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
    assert_eq!(names, [("npm:typescript", "5.9.3"), ("npm", "11.2.0")]);
    script(
        bin.path(),
        "npm",
        "case \"$1\" in ls) echo '{\"dependencies\": {\"npm\": {\"version\": \"11.3.0\"}}}';; esac\n",
    );
    let got = npm_globals(&n);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].kind.as_str(), got[0].version.as_str()), ("pkgmgr", "11.3.0"));
}

#[test]
fn cargo_installs_from_crates2_json() {
    let home = files::test_home();
    let cargo = files::home().join(".cargo");
    assert!(cargo_installs_in(&cargo).is_empty(), "no .crates2.json yet");
    std::fs::create_dir_all(&cargo).unwrap();
    std::fs::write(
        cargo.join(".crates2.json"),
        r#"{"installs": {
                "ripgrep 14.1.1 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["rg"]},
                "mine 0.1.0 (path+file:///x/mine)": {"bins": ["mine"]},
                "tool 2.0.0 (git+https://github.com/x/tool#abc)": {"bins": ["tool"]}
            }}"#,
    )
    .unwrap();
    let got = cargo_installs_in(&cargo);
    assert_eq!(got.len(), 1, "only registry installs have a version to check: {got:?}");
    let c = &got[0];
    assert_eq!((c.kind.as_str(), c.name.as_str(), c.version.as_str()), ("package", "cargo:ripgrep", "14.1.1"));
    assert_eq!(c.osv, Some(("crates.io".into(), "ripgrep".into(), "14.1.1".into())));
    assert_eq!(c.fix, "cargo install --locked ripgrep@{safe}");
    assert!(c.auto && c.path == cargo.join(".crates2.json").display().to_string());
    std::fs::write(cargo.join(".crates2.json"), "{}").unwrap();
    assert!(cargo_installs_in(&cargo).is_empty());
    // The real cargo home: $CARGO_HOME when set, else ~/.cargo (the temp home here).
    let real = cargo_installs();
    if std::env::var("CARGO_HOME").is_ok_and(|h| !h.is_empty()) {
        assert!(real.iter().all(|c| c.name.starts_with("cargo:")));
    } else {
        assert!(real.is_empty());
    }
    drop(home);
}

#[test]
fn pipx_venvs_from_the_listing() {
    let listing = r#"{"pipx_spec_version": "0.1", "venvs": {
            "black": {"metadata": {"main_package": {"package": "black", "package_version": "24.1.0"}}},
            "hatch": {"metadata": {"main_package": {"package_version": "1.9.0"}}},
            "odd": {"metadata": {"main_package": {"package": "odd"}}},
            "none": {}
        }}"#;
    let got = pipx_from("/opt/pipx", listing);
    let names: Vec<(&str, &str)> = got.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
    assert_eq!(names, [("pipx:black", "24.1.0"), ("pipx:hatch", "1.9.0")]);
    assert_eq!(got[0].osv, Some(("PyPI".into(), "black".into(), "24.1.0".into())));
    assert_eq!(
        got[1].osv,
        Some(("PyPI".into(), "hatch".into(), "1.9.0".into())),
        "the venv's name when the package isn't given"
    );
    assert_eq!(got[0].fix, "/opt/pipx upgrade black");
    assert!(got[0].auto && got[0].path == "/opt/pipx");
    assert!(pipx_from("/opt/pipx", "not json").is_empty());
    // Whatever this machine has (nothing in CI).
    assert!(pipx_packages().iter().all(|c| c.name.starts_with("pipx:")));
}

#[cfg(unix)]
#[test]
fn gems_of_each_ruby() {
    let bin = temp::TempDir::new("rubybin").unwrap();
    let ruby = script(bin.path(), "ruby", "echo ruby 3.3.0\n");
    let r = Component::new("runtime", "ruby", "3.3.0", &ruby);
    let not_ruby = Component::new("runtime", "node", "22", &ruby);
    assert!(gems(&[r.clone(), not_ruby.clone()]).is_empty(), "no gem beside ruby");
    let gem = script(
        bin.path(),
        "gem",
        "echo '*** LOCAL GEMS ***'\necho\necho 'json (default: 2.7.2, 2.6.1)'\necho 'rake (13.2.1)'\necho 'bundler (2.5.6)'\necho\n",
    );
    let got = gems(&[r, not_ruby]);
    let names: Vec<(&str, &str)> = got.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
    assert_eq!(names, [("gem:json", "2.7.2"), ("gem:rake", "13.2.1"), ("gem:bundler", "2.5.6")]);
    assert_eq!(got[1].osv, Some(("RubyGems".into(), "rake".into(), "13.2.1".into())));
    assert_eq!(got[1].fix, format!("{gem} update rake"));
    assert!(got[1].auto && got[1].path == gem);
}
