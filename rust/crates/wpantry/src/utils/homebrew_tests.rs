use super::super::temp::TempDir;
use super::*;

#[test]
fn caskroom_lists_one_version_per_cask() {
    let d = TempDir::new("caskroom").unwrap();
    for v in ["firefox/150.0", "firefox/.metadata", "1password-cli/2.41.1", ".DS_Store"] {
        std::fs::create_dir_all(d.path().join(v)).unwrap();
    }
    // A cask's `latest`, and a renamed cask's old token: links brew skips.
    std::os::unix::fs::symlink(d.path().join("firefox/150.0"), d.path().join("firefox/latest")).unwrap();
    std::os::unix::fs::symlink(d.path().join("firefox"), d.path().join("firefox-old")).unwrap();
    let got = caskroom(d.path()).unwrap();
    assert_eq!(
        got.into_iter().collect::<Vec<_>>(),
        [("1password-cli".into(), "2.41.1".into()), ("firefox".into(), "150.0".into())]
    );
    std::fs::create_dir_all(d.path().join("firefox/151.0")).unwrap();
    assert_eq!(caskroom(d.path()), None, "two versions: brew list says which");
    assert_eq!(caskroom(&d.path().join("nowhere")), None);
}

#[cfg(unix)]
fn executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn brew_prefix_and_casks_from_a_fake_brew() {
    let d = TempDir::new("brew").unwrap();
    let brew = d.path().join("prefix/bin/brew");
    executable(
        &brew,
        "#!/bin/sh\nif [ \"$1\" = --prefix ]; then echo /opt/x; else printf 'firefox 150.0\\nslack 4.41.0 4.42.0\\nbad\\n'; fi\n",
    );
    assert_eq!(brew_prefix_of(Some(brew.clone())), "/opt/x");
    assert_eq!(brew_prefix_of(None), "");
    let listed = brew_casks_in(Some(d.path().join("prefix")), Some(&brew));
    assert_eq!(
        listed.into_iter().collect::<Vec<_>>(),
        [("firefox".into(), "150.0".into()), ("slack".into(), "4.42.0".into())],
        "no Caskroom: brew list says"
    );
    std::fs::create_dir_all(d.path().join("prefix/Caskroom/firefox/150.0")).unwrap();
    let from_caskroom = brew_casks_in(Some(d.path().join("prefix")), Some(&brew));
    assert_eq!(from_caskroom.into_iter().collect::<Vec<_>>(), [("firefox".into(), "150.0".into())]);
    assert!(brew_casks_in(None, None).is_empty());
    // The prefix is HOMEBREW_PREFIX when set, else the folder above brew's bin.
    let want = std::env::var_os("HOMEBREW_PREFIX").map(PathBuf::from).unwrap_or_else(|| d.path().join("prefix"));
    assert_eq!(homebrew_prefix(&brew), Some(want));
}
