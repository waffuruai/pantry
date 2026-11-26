use super::*;

#[test]
fn maps_formulae_and_strips_revisions() {
    assert_eq!(catalog_tool("openssl@3").map(|t| t.name), Some("openssl"));
    assert_eq!(catalog_tool("node@22").map(|t| t.name), Some("node"));
    assert_eq!(catalog_tool("postgresql@17").map(|t| t.name), Some("postgres"));
    assert_eq!(catalog_tool("openssh").map(|t| t.name), Some("ssh"));
    assert_eq!(catalog_tool("awscli").map(|t| t.name), Some("aws"));
    assert!(catalog_tool("python@3.13").is_none(), "pythons are inventoried with pip");
    assert!(catalog_tool("mise").is_none(), "always checked from PATH");
    assert!(catalog_tool("jq").is_none());
    assert_eq!(version_of("1.8.2_1"), "1.8.2");
    assert_eq!(version_of("22.1.0"), "22.1.0");
    assert_eq!(version_of("1.0.0_rc1"), "1.0.0_rc1", "not a revision");
}

#[test]
fn reads_a_cellar_highest_version_first() {
    let d = crate::utils::temp::TempDir::new("cellar").unwrap();
    let cellar = d.path().join("Cellar");
    for v in ["openssl@3/3.6.0", "openssl@3/3.5.4", "node@22/22.1.0_1", "jq/1.8.1", "oniguruma/6.9.10", "empty"] {
        std::fs::create_dir_all(cellar.join(v)).unwrap();
    }
    std::fs::write(cellar.join(".DS_Store"), "").unwrap();
    let mise = d.path().join("mise/installs");
    std::fs::create_dir_all(mise.join("brew-node@22")).unwrap();
    let inv = read(&cellar, &mise);
    assert_eq!(inv.unmapped, vec!["jq".to_string(), "oniguruma".to_string()]);
    assert_eq!(inv.components.len(), 2, "{:?}", inv.components);
    let node = &inv.components[0];
    assert_eq!((node.kind.as_str(), node.name.as_str(), node.version.as_str()), ("brew", "node", "22.1.0"));
    assert_eq!(node.fix, "mise upgrade brew:node@22");
    assert_eq!(node.osv.as_ref().map(|o| o.2.as_str()), Some("v22.1.0"));
    assert_eq!(node.eol.as_ref().map(|e| e.1.as_str()), Some("22"));
    assert_eq!(node.extra.get("formula").map(String::as_str), Some("node@22"));
    let ssl = &inv.components[1];
    assert_eq!((ssl.name.as_str(), ssl.version.as_str()), ("openssl", "3.6.0"));
    assert_eq!(
        ssl.fix,
        "Run `brew upgrade openssl@3`. If another tool installed this copy (mise's brew: engine), update it there instead: `mise upgrade brew:openssl@3`."
    );
    assert!(!ssl.auto);
    assert_eq!(ssl.path, cellar.join("openssl@3").to_string_lossy());
    assert_eq!(read(&d.path().join("nowhere"), &mise), Inventory::default());
    let (found, inv2) = inventory_in(cellar.clone(), &mise).unwrap();
    assert_eq!((found, inv2), (cellar, inv));
    assert_eq!(inventory_in(d.path().join("nowhere"), &mise), None, "an empty Cellar is no inventory");
}

#[test]
fn the_cellar_is_the_variables_then_the_standard_prefixes() {
    let d = crate::utils::temp::TempDir::new("cellar").unwrap();
    let here = d.path().join("Cellar");
    std::fs::create_dir_all(&here).unwrap();
    let os = |p: &Path| Some(OsString::from(p));
    let standard = [here.to_string_lossy().into_owned()];
    let standard: Vec<&str> = standard.iter().map(String::as_str).collect();
    assert_eq!(find_cellar_from(os(Path::new("/c")), os(Path::new("/p")), &standard), Some(PathBuf::from("/c")));
    assert_eq!(
        find_cellar_from(Some(OsString::new()), os(Path::new("/p")), &standard),
        Some(PathBuf::from("/p/Cellar"))
    );
    assert_eq!(find_cellar_from(None, Some(OsString::new()), &standard), Some(here.clone()));
    assert_eq!(find_cellar_from(None, None, &["/nonexistent/Cellar"]), None);
    let _home = crate::utils::files::test_home();
    assert_eq!(mise_installs_from(os(Path::new("/m"))), PathBuf::from("/m/installs"));
    assert_eq!(mise_installs_from(Some(OsString::new())), home().join(".local/share/mise/installs"));
    assert_eq!(mise_installs(), mise_installs_from(std::env::var_os("MISE_DATA_DIR")));
    assert_eq!(
        find_cellar(),
        find_cellar_from(std::env::var_os("HOMEBREW_CELLAR"), std::env::var_os("HOMEBREW_PREFIX"), STANDARD_CELLARS)
    );
}

#[test]
fn a_cellar_go_is_also_its_toolchain() {
    let d = crate::utils::temp::TempDir::new("gotc").unwrap();
    let cellar = d.path().join("Cellar");
    std::fs::create_dir_all(cellar.join("go/1.26.10")).unwrap();
    let inv = read(&cellar, &d.path().join("mise/installs"));
    let go = &inv.components[0];
    assert_eq!(go.osv, Some(("Go".into(), "stdlib".into(), "1.26.10".into())));
    assert_eq!(go.osv_also, [("Go".to_string(), "toolchain".to_string(), "1.26.10".to_string())]);
}

/// Risk: a hand step in the maintainer's words ("poured without brew") that
/// names no command, for a formula that `brew upgrade` fixes. Oracle: what
/// someone would type, and the one tool that owns each copy: mise's brew:
/// engine leaves an `installs/brew-<formula>` folder; Homebrew's own prefix
/// has `bin/brew`. Nothing runs: only files are laid out in a temp dir.
// Homebrew runs on macOS and Linux only.
#[cfg(unix)]
#[test]
fn the_step_says_what_to_run_and_who_owns_the_copy() {
    let d = crate::utils::temp::TempDir::new("step").unwrap();
    let cellar = d.path().join("opt/homebrew/Cellar");
    let mise = d.path().join("mise/installs");
    std::fs::create_dir_all(&cellar).unwrap();
    std::fs::create_dir_all(&mise).unwrap();
    let neither = upgrade_step("openssl@3", &cellar, &mise);
    assert_eq!(
        neither,
        (
            "Run `brew upgrade openssl@3`. If another tool installed this copy (mise's brew: engine), update it there instead: `mise upgrade brew:openssl@3`."
                .to_string(),
            false
        ),
        "brew first, then the other tool, and nothing run unattended when it can't tell"
    );
    // brew sits in the Cellar's own prefix but not on PATH: its full path, as an automatic fix.
    let brew = d.path().join("opt/homebrew/bin/brew");
    std::fs::create_dir_all(brew.parent().unwrap()).unwrap();
    executable(&brew);
    assert_eq!(upgrade_step("openssl@3", &cellar, &mise), (format!("{} upgrade openssl@3", brew.display()), true));
    // mise's engine made it: that is the owner, whatever else is there.
    std::fs::create_dir_all(mise.join("brew-openssl@3")).unwrap();
    assert_eq!(upgrade_step("openssl@3", &cellar, &mise), ("mise upgrade brew:openssl@3".to_string(), false));
    // A name that isn't one word never reaches a command.
    let (odd, auto) = upgrade_step("a;b", &cellar, &mise);
    assert!(odd.starts_with("Upgrade a;b") && !auto, "{odd}");
    // A prefix whose path needs quoting is a step for a person, not an unattended command.
    let spaced = d.path().join("my prefix/Cellar");
    std::fs::create_dir_all(&spaced).unwrap();
    std::fs::create_dir_all(d.path().join("my prefix/bin")).unwrap();
    executable(&d.path().join("my prefix/bin/brew"));
    let (step, auto) = upgrade_step("jq", &spaced, &mise);
    assert!(step.starts_with("Run `") && step.ends_with(" upgrade jq`.") && !auto, "{step}");
}

/// The Cellar scan's components carry the step: an inventory with `bin/brew`
/// beside the Cellar is fixed with that brew, automatically.
// Homebrew runs on macOS and Linux only.
#[cfg(unix)]
#[test]
fn a_cellar_formula_beside_its_brew_is_an_automatic_fix() {
    let d = crate::utils::temp::TempDir::new("cellar-brew").unwrap();
    let cellar = d.path().join("prefix/Cellar");
    std::fs::create_dir_all(cellar.join("openssl@3/3.5.9")).unwrap();
    std::fs::create_dir_all(d.path().join("prefix/bin")).unwrap();
    executable(&d.path().join("prefix/bin/brew"));
    let inv = read(&cellar, &d.path().join("mise/installs"));
    let ssl = &inv.components[0];
    assert_eq!(ssl.fix, format!("{} upgrade openssl@3", d.path().join("prefix/bin/brew").display()));
    assert!(ssl.auto);
}

/// #326: "poured without brew" said of a keg Homebrew installed. Oracle: its
/// own receipt. A keg whose `INSTALL_RECEIPT.json` names a `homebrew_version`
/// is Homebrew's, whatever PATH this scan had and whatever mise has beside it;
/// one with no such version (mise's engine writes none) is not claimed.
// Homebrew runs on macOS and Linux only.
#[cfg(unix)]
#[test]
fn a_keg_with_a_homebrew_receipt_is_never_poured_without_brew() {
    let d = crate::utils::temp::TempDir::new("receipt").unwrap();
    let cellar = d.path().join("prefix/Cellar");
    let mise = d.path().join("mise/installs");
    std::fs::create_dir_all(cellar.join("openssl@3/3.5.9")).unwrap();
    std::fs::create_dir_all(cellar.join("node@22/22.1.0")).unwrap();
    std::fs::write(cellar.join("openssl@3/3.5.9/INSTALL_RECEIPT.json"), r#"{"homebrew_version": "7.0.9"}"#).unwrap();
    std::fs::write(cellar.join("node@22/22.1.0/INSTALL_RECEIPT.json"), r#"{"poured_from_bottle": true}"#).unwrap();
    // A stale mise folder for it changes nothing.
    std::fs::create_dir_all(mise.join("brew-openssl@3")).unwrap();
    assert!(homebrew_receipt(&cellar, "openssl@3"));
    assert!(!homebrew_receipt(&cellar, "node@22"));
    assert!(!homebrew_receipt(&cellar, "nothing"));
    let (step, auto) = upgrade_step("openssl@3", &cellar, &mise);
    assert_eq!(step, "Homebrew installed this copy: run `brew upgrade openssl@3` where Homebrew is.");
    assert!(!auto && !step.contains("poured") && !step.contains("mise"), "{step}");
    // The brew beside the Cellar makes it the automatic fix.
    let brew = d.path().join("prefix/bin/brew");
    executable(&brew);
    assert_eq!(upgrade_step("openssl@3", &cellar, &mise), (format!("{} upgrade openssl@3", brew.display()), true));
    // The same Cellar read as an inventory carries the step on the component.
    let inv = read(&cellar, &mise);
    let ssl = inv.components.iter().find(|c| c.name == "openssl").unwrap();
    assert_eq!(ssl.fix, format!("{} upgrade openssl@3", brew.display()));
    assert!(ssl.auto);
}

/// Homebrew has no Windows build, and the Windows scan never reads a Cellar.
/// Even so, nothing here may offer a Windows path as its `brew`: there is no
/// Cellar there (whatever HOMEBREW_CELLAR says), and the step never names a
/// `bin/brew` beside one. Runs on every platform; it asserts only on Windows.
#[test]
fn windows_has_no_cellar_and_never_a_brew_step() {
    if cfg!(windows) {
        assert_eq!(find_cellar(), None);
        assert!(inventory().is_none());
        let d = crate::utils::temp::TempDir::new("winbrew").unwrap();
        let cellar = d.path().join("prefix").join("Cellar");
        std::fs::create_dir_all(cellar.join("openssl@3").join("3.5.9")).unwrap();
        std::fs::create_dir_all(d.path().join("prefix").join("bin")).unwrap();
        std::fs::write(d.path().join("prefix").join("bin").join("brew"), "").unwrap();
        let (step, auto) = upgrade_step("openssl@3", &cellar, &d.path().join("mise"));
        assert!(!auto && !step.contains("bin/brew") && !step.contains("bin\\brew"), "{step}");
    }
}

/// A stand-in `brew`: a script the owner may run.
#[cfg(unix)]
fn executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Risk: a `bin/brew` beside the Cellar that cannot run (a leftover file, a
/// failed copy, a folder's mode) is named in the fix as an unattended
/// command, so `wpantry fix` plans it as automatic and then fails on it with
/// "was not found, or is not executable". Oracle: only a brew that could be
/// run is put in an automatic command; a file that is not executable gets the
/// step a person reads, as if there were no brew there.
// Homebrew runs on macOS and Linux only.
#[cfg(unix)]
#[test]
fn a_brew_that_is_not_executable_is_not_offered_as_the_automatic_fix() {
    let d = crate::utils::temp::TempDir::new("cellar-brew-mode").unwrap();
    let cellar = d.path().join("prefix/Cellar");
    let mise = d.path().join("mise/installs");
    std::fs::create_dir_all(&cellar).unwrap();
    std::fs::create_dir_all(d.path().join("prefix/bin")).unwrap();
    std::fs::write(d.path().join("prefix/bin/brew"), "#!/bin/sh\n").unwrap();
    let (step, auto) = upgrade_step("jq", &cellar, &mise);
    assert!(!auto && !step.contains("prefix/bin/brew"), "{step}");
    assert!(step.starts_with("Run `brew upgrade jq`."), "{step}");
    executable(&d.path().join("prefix/bin/brew"));
    let (step, auto) = upgrade_step("jq", &cellar, &mise);
    assert!(auto && step.ends_with("prefix/bin/brew upgrade jq"), "{step}");
}
