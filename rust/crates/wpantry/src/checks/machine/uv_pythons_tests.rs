use super::*;
use crate::checks::fix_with;

const PLAIN: &str = "cpython-3.11.15-macos-aarch64-none    /h/.local/share/uv/python/cpython-3.11-macos-aarch64-none/bin/python3.11\n\
cpython-3.12.13-macos-aarch64-none    /h/.local/share/uv/python/cpython-3.12-macos-aarch64-none/bin/python3.12\n\
cpython-3.12.12-macos-aarch64-none    <download available>\n";

/// A uv that knows `newest` for `line`, as the scan's answer.
fn knows(line: &str, newest: &str) -> UvPythons {
    UvPythons { uv: "0.10.12".into(), newest: BTreeMap::from([(line.to_string(), newest.to_string())]) }
}

/// A uv-managed python 3.12.13 stamped with `known` (None: never asked),
/// fixed by `uv python upgrade`; and the `pip` bundled with it.
fn managed(known: Option<&UvPythons>, bundled: bool) -> Component {
    let mut c = Component::new(
        if bundled { "pkgmgr" } else { "runtime" },
        if bundled { "pip" } else { "python" },
        "3.12.13",
        "/h/uv/python/x/bin/python3",
    );
    c.fix = UPGRADE.into();
    c.auto = true;
    if let Some(k) = known {
        stamp(&mut c, k, "3.12", "3.12.13", bundled);
    }
    c
}

/// Risk: the parser reads the wrong column or counts a Python uv cannot
/// install. Oracle: the real `uv python list` lines (uv 0.10.12): installed
/// builds name a path, downloads say `<download available>`.
#[test]
fn plain_list_gives_the_newest_patch_per_line() {
    let got = parse_plain(PLAIN);
    assert_eq!(got.get("3.12").map(String::as_str), Some("3.12.13"));
    assert_eq!(got.get("3.11").map(String::as_str), Some("3.11.15"));
    // A newer download wins; another manager's Python and odd lines do not count.
    let more = format!(
        "{PLAIN}cpython-3.12.14-macos-aarch64-none    <download available>\n\
         cpython-3.11.18-macos-aarch64-none    /opt/homebrew/bin/python3.11 -> ../Cellar/python@3.11/3.11.18/bin/python3.11\n\
         cpython-3.13.1+freethreaded-macos-aarch64-none    <download available>\n\
         cpython-3.15.0a1-macos-aarch64-none    <download available>\n\
         pypy-3.10.14-macos-aarch64-none    <download available>\n\
         warning: something\n"
    );
    let got = parse_plain(&more);
    assert_eq!(got.get("3.12").map(String::as_str), Some("3.12.14"));
    assert_eq!(got.get("3.11").map(String::as_str), Some("3.11.15"), "Homebrew's 3.11.18 is not uv's");
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(parse_plain("").is_empty() && parse_plain("error: unexpected argument").is_empty());
}

/// Oracle: the shape `uv python list --output-format json` printed on uv
/// 0.10.12 (a download has `url`, an installed build a `path`).
#[test]
fn json_list_gives_the_newest_patch_per_line() {
    let text = r#"warning: x
[{"key":"cpython-3.11.18-macos-aarch64-none","version":"3.11.18","path":"/opt/homebrew/bin/python3.11","symlink":"../Cellar/python@3.11/3.11.18/bin/python3.11","url":null,"implementation":"cpython","variant":"default"},
 {"key":"cpython-3.11.15-macos-aarch64-none","version":"3.11.15","path":"/h/.local/share/uv/python/cpython-3.11-macos-aarch64-none/bin/python3.11","symlink":null,"url":null,"implementation":"cpython","variant":"default"},
 {"key":"cpython-3.12.12-macos-aarch64-none","version":"3.12.12","path":null,"symlink":null,"url":"https://example.invalid/x.tar.gz","implementation":"cpython","variant":"default"},
 {"key":"cpython-3.12.13-macos-aarch64-none","version":"3.12.13","path":"/h/.local/share/uv/python/cpython-3.12-macos-aarch64-none/bin/python3.12","symlink":null,"url":null,"implementation":"cpython","variant":"default"},
 {"key":"cpython-3.13.1+freethreaded-macos-aarch64-none","version":"3.13.1","path":null,"url":"https://example.invalid/y","implementation":"cpython","variant":"freethreaded"},
 {"key":"pypy-3.10.14-macos-aarch64-none","version":"3.10.14","path":null,"url":"https://example.invalid/z","implementation":"pypy","variant":"default"}]"#;
    let got = parse_json(text).unwrap();
    assert_eq!(got, parse_plain(PLAIN), "both forms say the same");
    assert!(parse_json("error: unexpected argument '--output-format'").is_none());
}

/// Oracle: JSON is used when uv understands it, the plain list when not,
/// and no answer at all is unknown (None), never "nothing newer".
#[test]
fn ask_uses_json_then_plain_and_no_answer_is_unknown() {
    let calls = std::cell::RefCell::new(Vec::new());
    let old_uv = |args: &[&str]| {
        calls.borrow_mut().push(args.join(" "));
        match args {
            ["python", "list", "--all-versions"] => PLAIN.to_string(),
            ["--version"] => "uv 0.4.0 (abc 2024-01-01 aarch64-apple-darwin)\n".to_string(),
            _ => "error: unexpected argument '--output-format'\n".to_string(),
        }
    };
    let got = ask_with(&old_uv).unwrap();
    assert_eq!((got.uv.as_str(), got.newest.get("3.12").map(String::as_str)), ("0.4.0", Some("3.12.13")));
    assert_eq!(calls.borrow().len(), 3);
    assert!(ask_with(&|_| String::new()).is_none());
    assert!(ask_with(&|_| "error: boom".to_string()).is_none());
}

/// Risk: an unattended fix that changes nothing. Oracle: 3.12.13 is the
/// newest this uv knows, the fix is 3.12.14, so `uv python upgrade` would do nothing.
#[test]
fn runtime_fix_is_unattended_only_when_uv_knows_a_fixing_release() {
    let none = knows("3.12", "3.12.13");
    let (cmd, auto) = fix_with(&managed(Some(&none), false), "3.12.14");
    assert!(!auto, "{cmd}");
    assert!(cmd.contains("uv 0.10.12") && cmd.contains("Update uv first, then run uv python upgrade"), "{cmd}");
    assert!(cmd.contains("3.12.13") && cmd.contains("3.12.14"), "{cmd}");
    // A release at or above the fix: unchanged.
    for newest in ["3.12.14", "3.12.20"] {
        let (cmd, auto) = fix_with(&managed(Some(&knows("3.12", newest)), false), "3.12.14");
        assert_eq!((cmd.as_str(), auto), (UPGRADE, true), "{newest}");
    }
    // Unknown (never answered, or no entry for the line): today's behaviour.
    assert_eq!(fix_with(&managed(None, false), "3.12.14"), (UPGRADE.to_string(), true));
    assert_eq!(fix_with(&managed(Some(&knows("3.13", "3.13.1")), false), "3.12.14"), (UPGRADE.to_string(), true));
    // A fix on another line, or a `v` tag, is judged the same way.
    assert_eq!(fix_with(&managed(Some(&none), false), "3.13.2"), (UPGRADE.to_string(), true));
    assert!(!fix_with(&managed(Some(&none), false), "v3.12.14").1);
}

/// Oracle: whether a newer Python build carries a newer pip cannot be
/// known beforehand, so the bundled pip follows the runtime's availability.
#[test]
fn bundled_pip_follows_whether_a_newer_build_exists() {
    let (cmd, auto) = fix_with(&managed(Some(&knows("3.12", "3.12.13")), true), "26.1");
    assert!(!auto, "{cmd}");
    assert!(cmd.contains("uv 0.10.12") && cmd.contains("Update uv first, then run uv python upgrade"), "{cmd}");
    assert!(cmd.contains("newer pip") && cmd.contains("re-check"), "{cmd}");
    let newer = managed(Some(&knows("3.12", "3.12.14")), true);
    assert_eq!(fix_with(&newer, "26.1"), (UPGRADE.to_string(), true));
    assert!(bundled_note(&newer, UPGRADE, true).unwrap().contains("re-check confirms it"));
    assert!(bundled_note(&managed(Some(&knows("3.12", "3.12.14")), false), UPGRADE, true).is_none());
    assert_eq!(fix_with(&managed(None, true), "26.1"), (UPGRADE.to_string(), true));
}

/// Other managers' commands are never touched.
#[test]
fn other_fixes_are_unchanged() {
    let mut c = managed(Some(&knows("3.12", "3.12.13")), false);
    c.fix = "mise install python@{safe}".into();
    assert_eq!(fix_with(&c, "3.12.14"), ("mise install python@3.12.14".to_string(), true));
}

/// The scan stamps the answer on a uv-managed Python and its bundled pip,
/// asks uv once however many there are, and not at all without one.
#[cfg(unix)]
#[test]
fn pythons_ask_uv_once_and_stamp_only_uv_managed_ones() {
    let d = crate::utils::temp::TempDir::new("uvpy").unwrap();
    let site = d.path().join("site-packages");
    std::fs::create_dir_all(site.join("pip-25.0.dist-info")).unwrap();
    std::fs::write(site.join("pip-25.0.dist-info/METADATA"), "Name: pip\nVersion: 25.0\n").unwrap();
    let probe = |shown: &str| {
        let (exe, v) = match shown {
            "/x/uv/python/cpython-3.12-a/bin/python3" => ("/x/uv/python/cpython-3.12-a/bin/python3", "3.12.13"),
            "/x/uv/python/cpython-3.13-a/bin/python3" => ("/x/uv/python/cpython-3.13-a/bin/python3", "3.13.12"),
            _ => ("/x/bin/python3", "3.12.13"),
        };
        format!("{{\"v\": \"{v}\", \"exe\": \"{exe}\", \"sites\": [\"{}\"], \"managed\": true}}", site.display())
    };
    let asked = std::cell::Cell::new(0);
    let ask = || {
        asked.set(asked.get() + 1);
        Some(UvPythons {
            uv: "0.10.12".into(),
            newest: BTreeMap::from([("3.12".into(), "3.12.13".into()), ("3.13".into(), "3.13.14".into())]),
        })
    };
    let paths =
        ["/x/uv/python/cpython-3.12-a/bin/python3", "/x/uv/python/cpython-3.13-a/bin/python3", "/x/bin/python3"];
    let found: Vec<(String, String)> = paths.iter().map(|p| (p.to_string(), p.to_string())).collect();
    let (got, _) = crate::checks::machine::packages::pythons_with_uv(found, &probe, &|_| "", &ask);
    assert_eq!(asked.get(), 1);
    let stamp_of = |path: &str, kind: &str| {
        got.iter()
            .find(|c| c.path == path && (c.kind == "runtime") == (kind == "runtime"))
            .map(|c| c.extra.get(NEWEST).cloned())
    };
    assert_eq!(stamp_of(paths[0], "runtime"), Some(Some("3.12.13".into())));
    assert_eq!(stamp_of(paths[0], "pip"), Some(Some("3.12.13".into())));
    assert_eq!(stamp_of(paths[1], "runtime"), Some(Some("3.13.14".into())));
    assert_eq!(stamp_of(paths[2], "runtime"), Some(None), "not uv's");
    let pip = got.iter().find(|c| c.path == paths[0] && c.name == "pip").unwrap();
    assert!(pip.extra.contains_key(BUNDLED));
    // No answer from uv: nothing is stamped.
    let found: Vec<(String, String)> = paths[..1].iter().map(|p| (p.to_string(), p.to_string())).collect();
    let (got, _) = crate::checks::machine::packages::pythons_with_uv(found, &probe, &|_| "", &|| None);
    assert!(got.iter().all(|c| !c.extra.contains_key(NEWEST)));
}
