//! Files and paths: `$HOME` (and a temporary one for tests), reading a
//! file with a size cap, globs, `realpath`, a fingerprint of a set of
//! files, and who vouches for a binary by where it lives.

use super::os::{MACOS, os_vouches};
use super::sha256::Sha256;
use super::temp::TempDir;
use crate::error::{Error, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

thread_local! {
    static HOME_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// A temporary $HOME for the current thread, for tests (changing the real
/// environment needs `unsafe`, which this crate forbids). Restored on drop.
#[doc(hidden)]
pub struct TestHome(#[allow(dead_code)] TempDir);

#[doc(hidden)]
pub fn test_home() -> TestHome {
    let dir = TempDir::new("home").expect("a temp dir");
    HOME_OVERRIDE.with(|h| *h.borrow_mut() = Some(dir.path().to_path_buf()));
    TestHome(dir)
}

impl Drop for TestHome {
    fn drop(&mut self) {
        HOME_OVERRIDE.with(|h| *h.borrow_mut() = None);
    }
}

/// $HOME (Python: `os.path.expanduser("~")`).
pub fn home() -> PathBuf {
    if let Some(h) = HOME_OVERRIDE.with(|h| h.borrow().clone()) {
        return h;
    }
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

/// `~/x` for paths under $HOME, as the report shows them. Matches Python's
/// plain string-prefix test.
pub fn short(p: &str) -> String {
    let home = home();
    let home = home.to_string_lossy();
    match p.strip_prefix(home.as_ref()) {
        Some(rest) if !home.is_empty() => format!("~{rest}"),
        _ => p.to_string(),
    }
}

/// A file's text, refusing anything over `max` bytes (S7).
pub fn read_capped(path: &Path, max: u64) -> Result<String> {
    Ok(String::from_utf8_lossy(&read_capped_bytes(path, max)?).into_owned())
}

/// A file's bytes, refusing anything over `max` bytes and anything that
/// isn't a regular file: the size is read from the opened handle and the
/// read stops at the cap, so a device or FIFO a repo links to (`/dev/zero`)
/// can't be read without end.
pub fn read_capped_bytes(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::Invalid(format!("{} is not a regular file", path.display())));
    }
    if meta.len() > max {
        return Err(Error::Invalid(format!("{} is over {} bytes", path.display(), max)));
    }
    let mut bytes = Vec::with_capacity(meta.len().min(max) as usize);
    (&mut file).take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(Error::Invalid(format!("{} is over {} bytes", path.display(), max)));
    }
    Ok(bytes)
}

/// Changes when any file is added, removed, touched or resized.
pub fn fingerprint<P: AsRef<Path>>(files: &[P]) -> String {
    let mut h = Sha256::new();
    for f in files {
        let f = f.as_ref();
        if let Ok(st) = std::fs::metadata(f) {
            let mtime_ns =
                st.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0);
            h.update(format!("{}:{}:{}\n", f.display(), mtime_ns, st.len()).as_bytes());
        }
    }
    h.hex()
}

/// Python's `fnmatch` for one path component: `*` and `?`; a leading dot
/// must be matched literally (as `glob` does).
fn fnmatch(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    fn go(p: &[char], n: &[char]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some('*'), _) => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
            (Some('?'), Some(_)) => go(&p[1..], &n[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &n[1..]),
            _ => false,
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    go(&p, &n)
}

/// Paths matching one glob (`~` expanded; `*` and `?` within a component,
/// `**` like `*`, as Python's non-recursive `glob`), sorted.
pub fn glob(pattern: &str) -> Vec<String> {
    let pattern = match pattern.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", home().display()),
        None if pattern == "~" => home().display().to_string(),
        None => pattern.to_string(),
    };
    let absolute = pattern.starts_with('/');
    let mut found = vec![if absolute { "/".to_string() } else { String::new() }];
    for part in pattern.split('/').filter(|p| !p.is_empty()) {
        let mut next = Vec::new();
        for base in &found {
            let join = |name: &str| {
                if base.is_empty() {
                    name.to_string()
                } else if base.ends_with('/') {
                    format!("{base}{name}")
                } else {
                    format!("{base}/{name}")
                }
            };
            if part.contains(['*', '?']) {
                let dir = if base.is_empty() { "." } else { base.as_str() };
                let Ok(rd) = std::fs::read_dir(dir) else { continue };
                let mut names: Vec<String> = rd
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| fnmatch(part, n))
                    .collect();
                names.sort();
                next.extend(names.iter().map(|n| join(n)));
            } else {
                let p = join(part);
                if std::fs::symlink_metadata(&p).is_ok() {
                    next.push(p);
                }
            }
        }
        found = next;
    }
    found.retain(|p| !p.is_empty() && p != "/" || pattern == "/");
    found.sort();
    found
}

/// Existing paths matching ~-relative globs, in order, without repeats.
pub fn expand<S: AsRef<str>>(patterns: &[S]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for g in patterns {
        for p in glob(g.as_ref()) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// A JSON file, or None when it's missing, unreadable or malformed.
pub fn read_json(path: &Path) -> Option<serde_json::Value> {
    let text = read_capped(path, 64 << 20).ok()?;
    crate::utils::json::parse(text.as_bytes(), crate::utils::json::MAX_DOCUMENT).ok()
}

/// `realpath`: symlinks resolved, or the path as given when it can't be.
pub fn realpath(p: &str) -> String {
    std::fs::canonicalize(p).map(|r| r.to_string_lossy().into_owned()).unwrap_or_else(|_| p.to_string())
}

const SYSTEM_DIRS: &[&str] = &["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/libexec/", "/usr/lib/", "/System/"];
const APPLE_DIRS: &[&str] = &["/Library/Developer/CommandLineTools/", "/Applications/Xcode"];

/// Who vouches for this binary, or "" when we check it ourselves: brew
/// (`brew vulns`), npm or pipx (their package listings), app (the app
/// check), os (OS updates).
pub fn owner(real: &str) -> &'static str {
    if real.contains("/Cellar/") {
        return "brew";
    }
    if real.contains("/node_modules/") {
        return "npm";
    }
    if real.contains("/pipx/venvs/") {
        return "pipx";
    }
    let apple = APPLE_DIRS.iter().any(|d| real.starts_with(d));
    if real.contains(".app/Contents/") && !apple {
        return "app";
    }
    if SYSTEM_DIRS.iter().any(|d| real.starts_with(d)) || (MACOS && apple) {
        return if os_vouches() { "os" } else { "" };
    }
    ""
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
