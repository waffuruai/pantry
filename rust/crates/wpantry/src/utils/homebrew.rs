//! Homebrew's prefix and its installed casks, read without starting brew
//! where the Caskroom says.

use super::process::{run, which};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn brew_prefix() -> String {
    brew_prefix_of(which("brew"))
}

/// What the `brew` at `brew` says its prefix is, or "" without one.
fn brew_prefix_of(brew: Option<PathBuf>) -> String {
    match brew {
        Some(b) => run(&[b.as_os_str(), "--prefix".as_ref()], Duration::from_secs(15)).trim().to_string(),
        None => String::new(),
    }
}

/// Homebrew's prefix: HOMEBREW_PREFIX, else the folder above the `bin` the
/// `brew` on PATH is in (how brew finds its own).
pub fn homebrew_prefix(brew: &Path) -> Option<PathBuf> {
    std::env::var_os("HOMEBREW_PREFIX")
        .map(PathBuf::from)
        .or_else(|| brew.parent().and_then(Path::parent).map(Path::to_path_buf))
}

/// {cask: version} from the Caskroom, what `brew list --cask --versions`
/// says without starting Homebrew's Ruby. Symlinks are skipped, as brew
/// does: a renamed cask's old token, a cask's `latest`. None when there's
/// no Caskroom or a cask has more than one version installed (brew says
/// which it lists).
pub fn caskroom(dir: &Path) -> Option<BTreeMap<String, String>> {
    let entries = |d: &Path| -> Option<Vec<std::fs::DirEntry>> {
        Some(
            std::fs::read_dir(d)
                .ok()?
                .filter_map(|e| e.ok())
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .filter(|e| !e.file_type().is_ok_and(|t| t.is_symlink()))
                .collect(),
        )
    };
    let mut out = BTreeMap::new();
    for cask in entries(dir)? {
        let name = cask.file_name().to_string_lossy().into_owned();
        let versions: Vec<String> =
            entries(&cask.path())?.iter().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        let [v] = versions.as_slice() else { return None };
        out.insert(name, v.clone());
    }
    Some(out)
}

/// {cask token: installed version} for Homebrew-installed casks.
pub fn brew_casks() -> BTreeMap<String, String> {
    let brew = which("brew");
    brew_casks_in(brew.as_deref().and_then(homebrew_prefix), brew.as_deref())
}

/// [`brew_casks`] for the Homebrew at `prefix` with its `brew` command.
fn brew_casks_in(prefix: Option<PathBuf>, brew: Option<&Path>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(b) = brew {
        if let Some(casks) = prefix.and_then(|p| caskroom(&p.join("Caskroom"))) {
            return casks;
        }
        for line in
            run(&[b.as_os_str(), "list".as_ref(), "--cask".as_ref(), "--versions".as_ref()], Duration::from_secs(60))
                .lines()
        {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                out.insert(parts[0].to_string(), parts[parts.len() - 1].to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
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
}
