use super::*;

#[cfg(unix)]
#[test]
fn capped_reads_refuse_devices_and_oversize() {
    let dir = TempDir::new("read").unwrap();
    let f = dir.path().join("f");
    std::fs::write(&f, b"hello").unwrap();
    assert_eq!(read_capped(&f, 5).unwrap(), "hello");
    assert!(read_capped(&f, 4).is_err());
    #[cfg(unix)]
    {
        // A symlink into a repo pointing at a device: not a file, so never read.
        let link = dir.path().join("zero");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert!(read_capped_bytes(&link, 1 << 20).is_err());
        assert!(read_capped_bytes(Path::new("/dev/zero"), 1 << 20).is_err());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777, 0o700);
    }
}

#[test]
fn globs_like_python() {
    let d = TempDir::new("glob").unwrap();
    for f in ["a/x/package.json", "a/y/package.json", "a/.hidden/package.json", "b.app/Contents/x"] {
        let p = d.path().join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "{}").unwrap();
    }
    let root = d.path().display().to_string();
    let got = glob(&format!("{root}/a/*/package.json"));
    assert_eq!(got, [format!("{root}/a/x/package.json"), format!("{root}/a/y/package.json")]);
    assert_eq!(glob(&format!("{root}/*.app")), [format!("{root}/b.app")]);
    assert_eq!(glob(&format!("{root}/a/.hidden/package.json")).len(), 1);
    assert!(glob(&format!("{root}/nope/*")).is_empty());
    assert!(fnmatch("python3.*", "python3.12") && !fnmatch("*", ".git") && fnmatch("V?", "V1"));
}

#[test]
fn owners() {
    assert_eq!(owner("/opt/homebrew/Cellar/node/24.1.0/bin/node"), "brew");
    assert_eq!(owner("/home/u/.npm-global/lib/node_modules/x/bin/x"), "npm");
    assert_eq!(owner("/Applications/Slack.app/Contents/MacOS/Slack"), "app");
    assert_eq!(owner("/home/u/.local/bin/mise"), "");
    // Fedora's and RHEL's libraries are the distro's too.
    assert_eq!(owner("/usr/lib64/firefox/firefox"), owner("/usr/lib/firefox/firefox"));
    assert_eq!(owner("/usr/lib64/firefox/firefox"), if crate::utils::os::os_vouches() { "os" } else { "" });
}

#[test]
fn command_paths_drop_the_verbatim_prefix() {
    assert_eq!(command_path(Path::new(r"\\?\C:\code\app")), "C:/code/app");
    assert_eq!(strip_verbatim(r"\\?\UNC\server\share\app"), r"\\server\share\app");
    assert_eq!(command_path(Path::new("/w/butter/rust")), "/w/butter/rust");
    assert_eq!(short(r"\\?\C:\keep"), r"C:\keep");
}

#[test]
fn fingerprint_changes_with_files() {
    let d = TempDir::new("fp").unwrap();
    let f = d.path().join("a");
    let before = fingerprint(&[&f]);
    std::fs::write(&f, "x").unwrap();
    let after = fingerprint(&[&f]);
    assert_ne!(before, after);
    std::fs::write(&f, "xy").unwrap();
    assert_ne!(after, fingerprint(&[&f]));
}

#[test]
fn short_paths() {
    let _home = test_home();
    let home = home().display().to_string();
    assert_eq!(short(&format!("{home}/.cargo/bin")), "~/.cargo/bin");
    assert_eq!(short("/usr/bin/git"), "/usr/bin/git");
}

#[test]
fn relative_globs_read_the_working_directory() {
    // cargo runs tests from the crate root, where Cargo.toml is.
    assert_eq!(glob("Cargo.toml"), ["Cargo.toml"]);
    assert_eq!(glob("Cargo.tom?"), ["Cargo.toml"]);
    assert!(glob("Cargo.toml/*").is_empty());
}

#[test]
fn more_owners() {
    assert_eq!(owner("/home/u/.local/pipx/venvs/x/bin/x"), "pipx");
    assert_eq!(owner("/Library/Developer/CommandLineTools/usr/bin/git"), if MACOS { "os" } else { "" });
    let os = owner("/usr/bin/ssh");
    assert_eq!(os, if os_vouches() { "os" } else { "" });
}
