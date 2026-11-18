use super::*;
use crate::checks::machine::catalog::MISE_FIX;

#[test]
fn every_catalog_pattern_compiles_and_reads_its_tool() {
    for t in TOOLS {
        Regex::with_flags(t.pattern, "m");
    }
    let read = |name: &str, out: &str| {
        let t = TOOLS.iter().find(|t| t.name == name).unwrap();
        Regex::with_flags(t.pattern, "m").search(out).map(|c| c.get(1).to_string())
    };
    // The test vector the Python implementation had (`Mise.test_version_and_tag`).
    assert_eq!(read("mise", "2026.10.19 macos-arm64 (2026-10-24)").as_deref(), Some("2026.10.19"));
    assert_eq!(read("node", "v24.11.1\n").as_deref(), Some("24.11.1"));
    assert_eq!(read("go", "go1.24.7\n").as_deref(), Some("1.24.7"));
    assert_eq!(read("ssh", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024").as_deref(), Some("9.6p1"));
    assert_eq!(read("postgres", "postgres (PostgreSQL) 17.4").as_deref(), Some("17.4"));
    assert_eq!(read("mysql", "mysql  Ver 15.1 Distrib 10.11.6-MariaDB"), None);
    assert_eq!(read("mariadb", "mysql  Ver 15.1 Distrib 10.11.6-MariaDB, for debian").as_deref(), Some("10.11.6"));
    assert_eq!(read("pi", "0.9.1").as_deref(), Some("0.9.1"));
    // FreeSWITCH's `-version`: a release, a build from git past one, and a
    // -dev build (no release to compare: not read).
    assert_eq!(read("freeswitch", "FreeSWITCH version: 1.10.12-release~64bit ( 64bit)\n").as_deref(), Some("1.10.12"));
    assert_eq!(
        read("freeswitch", "FreeSWITCH version: 1.10.7-release-19-883d2cb662~64bit (-release-19-883d2cb662 64bit)")
            .as_deref(),
        Some("1.10.7")
    );
    assert_eq!(read("freeswitch", "FreeSWITCH version: 1.11.4-dev~64bit ( 64bit)"), None);
    // UnrealIRCd's embedded version string: three or four parts, a debug
    // build's suffix; a release candidate or anything else is not read.
    assert_eq!(read("unrealircd", "UnrealIRCd-6.1.8").as_deref(), Some("6.1.8"));
    assert_eq!(read("unrealircd", "UnrealIRCd-%s\nUnrealIRCd-6.2.7.1").as_deref(), Some("6.2.7.1"));
    assert_eq!(read("unrealircd", "UnrealIRCd-6.2.7.1+(debug)(Debug)").as_deref(), Some("6.2.7.1"));
    assert_eq!(read("unrealircd", "UnrealIRCd-6.2.8-rc1"), None);
    assert_eq!(read("unrealircd", "UnrealIRCd-6.2.18-rc1"), None);
    assert_eq!(read("unrealircd", "UnrealIRCd-6.2.7.1 is out"), None);
}

/// A catalog tool, by name.
fn tool(name: &str) -> Tool {
    *TOOLS.iter().find(|t| t.name == name).unwrap()
}

#[test]
fn self_hosted_servers_are_catalog_tools() {
    let fs = tool("freeswitch");
    assert_eq!(
        (fs.args, fs.osv, fs.eol),
        (&["-version"][..], Some(("GIT", "https://github.com/signalwire/freeswitch.git", "v{v}")), None)
    );
    assert_eq!(tag(fs.osv.unwrap().2, "1.10.12"), "v1.10.12");
    let irc = tool("unrealircd");
    // Never run (even `-v` creates directories): read from its bytes.
    assert_eq!((irc.args, irc.osv), (&[][..], None));
    assert!(READ_BINARY.iter().any(|(n, p)| *n == "unrealircd" && !p.is_empty()));
    assert_eq!(irc.eol.map(|(p, c)| (p, c.of("6.2.7.1"))), Some(("unrealircd", "6".to_string())));
    // A distro or Homebrew copy is left to the OS update check or brew vulns.
    assert!(!fs.always && !irc.always);
}

#[test]
fn tags() {
    assert_eq!(tag("v{v}", "2026.10.19"), "v2026.10.19");
    assert_eq!(tag("v{v3}", "8.10"), "v8.10.0");
    assert_eq!(tag("curl-{u}", "8.11.1"), "curl-8_11_1");
    assert_eq!(tag("V_{ssh}", "9.6p1"), "V_9_6_P1");
    let mise = TOOLS.iter().find(|t| t.name == "mise").unwrap();
    assert_eq!(mise.osv.unwrap().1, "https://github.com/jdx/mise.git");
    assert_eq!((mise.fix, mise.always), (MISE_FIX, true));
}

#[test]
fn updaters() {
    assert_eq!(updater("/x/.volta/tools/image/node/24/bin/node", "node"), ("volta install node@{safe}".into(), true));
    assert_eq!(updater("/usr/local/bin/x", "x"), ("Upgrade x at /usr/local/bin/x to {safe}".into(), false));
}

#[test]
fn updaters_under_home() {
    let home = crate::utils::files::test_home();
    let h = crate::utils::files::home().display().to_string();
    assert_eq!(updater(&format!("{h}/.cargo/bin/cargo"), "cargo"), ("rustup update".into(), true));
    assert_eq!(updater(&format!("{h}/.local/bin/python3"), "python"), ("uv python upgrade".into(), true));
    assert_eq!(updater("/opt/miniconda3/bin/python", "python"), ("conda update --name base python".into(), false));
    assert_eq!(updater("/h/.nvm/versions/node/v24/bin/node", "node"), ("nvm install {safe}".into(), false));
    drop(home);
}

#[cfg(unix)]
fn script(path: &Path, out: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\necho '{out}'\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
const FAKE: Tool = Tool {
    name: "wpantry-fake",
    kind: "tool",
    bins: &["wpantry-fake", "wpantry-fake-alias"],
    args: &["--version"],
    pattern: r"fake (\d+\.\d+\.\d+)",
    osv: Some(("GIT", "https://github.com/x/fake.git", "v{v}")),
    eol: Some(("fake", crate::checks::machine::catalog::Cycle::Minor)),
    always: false,
    paths: &[],
    fix: "",
};

#[cfg(unix)]
#[test]
fn find_runs_each_copy_and_reads_its_version() {
    let d = crate::utils::temp::TempDir::new("tools").unwrap();
    let bin = d.path().join("bin");
    script(&bin.join("wpantry-fake"), "fake 1.2.3 (2026)");
    script(&bin.join("wpantry-fake-alias"), "not a version");
    // Homebrew's copy is brew vulns' to check, not ours.
    script(&d.path().join("Cellar/wpantry-fake/1.2.4/bin/wpantry-fake"), "fake 1.2.4");
    let dirs = [bin.display().to_string(), d.path().join("Cellar/wpantry-fake/1.2.4/bin").display().to_string()];
    let found = find(&FAKE, &dirs);
    assert_eq!(found.len(), 1, "{found:?}");
    let c = &found[0];
    assert_eq!(
        (c.kind.as_str(), c.name.as_str(), c.version.as_str(), c.path.as_str()),
        ("tool", "wpantry-fake", "1.2.3", &*bin.join("wpantry-fake").display().to_string())
    );
    assert_eq!(c.osv, Some(("GIT".into(), "https://github.com/x/fake.git".into(), "v1.2.3".into())));
    assert_eq!(c.eol, Some(("fake".into(), "1.2".into())));
    assert_eq!(
        (c.fix.as_str(), c.auto),
        (
            &*format!(
                "Upgrade wpantry-fake at {} to {{safe}}",
                files::realpath(&bin.join("wpantry-fake").display().to_string())
            ),
            false
        )
    );
}

#[cfg(unix)]
#[test]
fn find_checks_brew_and_app_copies_when_nobody_else_does() {
    let d = crate::utils::temp::TempDir::new("tools").unwrap();
    script(&d.path().join("Cellar/wpantry-fake/1.2.4/bin/wpantry-fake"), "fake 1.2.4");
    script(&d.path().join("Fake.app/Contents/MacOS/wpantry-fake"), "fake 1.2.5");
    let dirs = [
        d.path().join("Cellar/wpantry-fake/1.2.4/bin").display().to_string(),
        d.path().join("Fake.app/Contents/MacOS").display().to_string(),
    ];
    let always = Tool { always: true, ..FAKE };
    let found = find(&always, &dirs);
    let got: Vec<(&str, &str, bool)> = found.iter().map(|c| (c.version.as_str(), c.fix.as_str(), c.auto)).collect();
    assert_eq!(got, [("1.2.4", "brew upgrade wpantry-fake", true), ("1.2.5", "Update Fake", false)]);
    // A catalog fix overrides the detected one and is never unattended.
    let manual = Tool { always: true, fix: "Update it by hand", ..FAKE };
    let found = find(&manual, &dirs);
    assert!(found.iter().all(|c| c.fix == "Update it by hand" && !c.auto), "{found:?}");
}

#[cfg(unix)]
#[test]
fn a_server_built_from_source_is_read_and_a_packaged_one_is_left_to_its_owner() {
    let d = crate::utils::temp::TempDir::new("servers").unwrap();
    let prefix = d.path().join("freeswitch/bin");
    let cellar = d.path().join("Cellar/freeswitch/1.10.12/bin");
    script(&prefix.join("wpantry-fake-freeswitch"), "FreeSWITCH version: 1.10.11-release~64bit ( 64bit)");
    script(&cellar.join("wpantry-fake-freeswitch"), "FreeSWITCH version: 1.10.12-release~64bit ( 64bit)");
    let fs = Tool { bins: &["wpantry-fake-freeswitch"], paths: &[], ..tool("freeswitch") };
    let found = find(&fs, &[prefix.display().to_string(), cellar.display().to_string()]);
    // Homebrew's copy is brew vulns' to check.
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0].name.as_str(), found[0].version.as_str()), ("freeswitch", "1.10.11"));
    let osv = Some(("GIT".into(), "https://github.com/signalwire/freeswitch.git".into(), "v1.10.11".into()));
    assert_eq!(found[0].osv, osv);
    let irc_dir = d.path().join("unrealircd/bin");
    let marker = d.path().join("ran");
    let fake = irc_dir.join("wpantry-fake-unrealircd");
    // An executable that, if run, would leave a marker and print another
    // version; the version it holds is the NUL-terminated string.
    let mut bytes = format!("#!/bin/sh\ntouch '{}'\necho UnrealIRCd-9.9.9\nexit 0\n", marker.display()).into_bytes();
    bytes.extend_from_slice(b"\0UnrealIRCd-%s\0UnrealIRCd-6.1.8\0tail");
    std::fs::create_dir_all(&irc_dir).unwrap();
    std::fs::write(&fake, &bytes).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let irc = Tool { bins: &["wpantry-fake-unrealircd"], paths: &[], ..tool("unrealircd") };
    let found = find(&irc, &[irc_dir.display().to_string()]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0].version.as_str(), found[0].eol.clone()), ("6.1.8", Some(("unrealircd".into(), "6".into()))));
    assert!(!marker.exists(), "the binary was run");
    // The distro's binaries are the OS update check's whenever it can vouch.
    let os = if crate::utils::os::os_vouches() { "os" } else { "" };
    assert_eq!((owner("/usr/bin/freeswitch"), owner("/usr/sbin/unrealircd")), (os, os));
    // Nothing installed: nothing found.
    assert!(find(&irc, &[d.path().join("empty").display().to_string()]).is_empty());
}

#[test]
fn embedded_strings_are_read_from_the_bytes_up_to_their_nul() {
    let d = crate::utils::temp::TempDir::new("embedded").unwrap();
    let at = |name: &str, bytes: &[u8]| {
        let p = d.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        embedded(&p.display().to_string(), "UnrealIRCd-")
    };
    assert_eq!(
        at("bin", b"\x7fELF\0UnrealIRCd-%s\0junk UnrealIRCd-6.2.8-rc1\0UnrealIRCd-6.2.7.1\0"),
        "UnrealIRCd-%s\nUnrealIRCd-6.2.8-rc1\nUnrealIRCd-6.2.7.1"
    );
    // Not NUL-terminated (a script, a text file, the end of the file), or
    // too long to be a version string: nothing.
    assert_eq!(at("script", b"#!/bin/sh\necho UnrealIRCd-6.2.7.1\n"), "");
    // A line of text that happens to end near a NUL is still text.
    assert_eq!(at("text", b"echo UnrealIRCd-6.2.7.1\nexit 0\n\0"), "");
    let long = [b"UnrealIRCd-".as_slice(), &[b'1'; 80], b"\0"].concat();
    assert_eq!(at("long", &long), "");
    assert_eq!(at("short", b"Unreal"), "");
    // Missing, or over the cap (a sparse file: nothing is read), is nothing.
    assert_eq!(embedded(&d.path().join("missing").display().to_string(), "UnrealIRCd-"), "");
    let big = d.path().join("big");
    std::fs::File::create(&big).unwrap().set_len(MAX_BINARY + 1).unwrap();
    assert_eq!(embedded(&big.display().to_string(), "UnrealIRCd-"), "");
}

#[test]
fn nvm_from_its_repo() {
    let d = crate::utils::temp::TempDir::new("nvm").unwrap();
    let root = d.path().join(".nvm");
    assert!(nvm_at(&root.display().to_string()).is_empty());
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("package.json"), r#"{"version": "git"}"#).unwrap();
    assert!(nvm_at(&root.display().to_string()).is_empty());
    std::fs::write(root.join("package.json"), r#"{"version": "0.40.1"}"#).unwrap();
    let found = nvm_at(&root.display().to_string());
    assert_eq!(found.len(), 1);
    let c = &found[0];
    assert_eq!((c.kind.as_str(), c.name.as_str(), c.version.as_str()), ("manager", "nvm", "0.40.1"));
    assert_eq!(c.osv, Some(("GIT".into(), "https://github.com/nvm-sh/nvm.git".into(), "v0.40.1".into())));
    assert!(c.fix.contains("nvm-sh/nvm#upgrading"));
}

#[cfg(unix)]
#[test]
fn nvm_under_home_unless_nvm_dir_says_otherwise() {
    let home = crate::utils::files::test_home();
    let root = crate::utils::files::home().join(".nvm");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("package.json"), r#"{"version": "0.40.1"}"#).unwrap();
    let found = nvm();
    if std::env::var_os("NVM_DIR").is_none_or(|d| d.is_empty()) {
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, root.display().to_string());
    }
    drop(home);
}

#[cfg(unix)]
#[test]
fn dedupe_counts_one_install_once() {
    let d = crate::utils::temp::TempDir::new("dedupe").unwrap();
    std::fs::create_dir_all(d.path().join("a")).unwrap();
    std::fs::write(d.path().join("a/postgres"), "").unwrap();
    std::fs::write(d.path().join("a/psql"), "").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(d.path().join("a"), d.path().join("b")).unwrap();
    let at = |rel: &str| Component::new("datastore", "postgres", "17.4", &d.path().join(rel).display().to_string());
    let mut all = vec![at("a/postgres"), at("a/psql"), at("b/postgres"), Component::new("tool", "x", "1", "")];
    all.push(Component::new("tool", "x", "1", ""));
    let mut other = at("a/postgres");
    other.version = "16.1".into();
    all.push(other);
    let out = dedupe(all);
    let got: Vec<(&str, &str)> = out.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
    assert_eq!(got, [("postgres", "17.4"), ("x", "1"), ("postgres", "16.1")]);
}

/// A Go install is asked about as Go's `toolchain` too, at its version.
#[cfg(unix)]
#[test]
fn an_installed_go_is_also_its_toolchain() {
    let go = Tool { name: "wpantry-fakego", bins: &["wpantry-fakego"], ..catalog_tool("go") };
    let d = crate::utils::temp::TempDir::new("gotc").unwrap();
    let bin = d.path().join("bin");
    script(&bin.join("wpantry-fakego"), "go1.26.10");
    let found = find(&go, &[bin.display().to_string()]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].osv, Some(("Go".into(), "stdlib".into(), "1.26.10".into())));
    assert_eq!(found[0].osv_also, [("Go".to_string(), "toolchain".to_string(), "1.26.10".to_string())]);
}

#[cfg(unix)]
fn catalog_tool(name: &str) -> Tool {
    *crate::checks::machine::catalog::TOOLS.iter().find(|t| t.name == name).unwrap()
}
