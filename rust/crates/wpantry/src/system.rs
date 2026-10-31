//! Shared ground: the Component every finder returns, and small helpers for
//! processes, paths, the OS and fingerprints. Programs always run from an
//! argument vector, never a shell string (S6), with `NO_COLOR=1`.

use crate::error::{Error, Result};
use crate::sha256::Sha256;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MACOS: bool = cfg!(target_os = "macos");

/// Where a scan says what it is doing right now ("Reading ~/app/Cargo.lock"):
/// transient progress for a human, never part of the report. Called from
/// worker threads too, hence `Sync`.
pub type Status<'a> = &'a (dyn Fn(&str) + Sync);

/// A [`Status`] that shows nothing.
pub fn quiet(_: &str) {}

/// Something installed or locked that can be checked.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Component {
    /// runtime, compiler, manager, pkgmgr, tool, datastore, harness, package, app, project, os, mcp, …
    pub kind: String,
    pub name: String,
    pub version: String,
    pub path: String,
    /// (ecosystem, package, version as OSV knows it)
    pub osv: Option<(String, String, String)>,
    /// (endoflife.date product, cycle)
    pub eol: Option<(String, String)>,
    /// The command (or step) that updates it; "{safe}" is the fixed version.
    pub fix: String,
    /// `wpantry --update` may run `fix` unattended.
    pub auto: bool,
    pub extra: BTreeMap<String, String>,
}

impl Component {
    pub fn new(kind: &str, name: &str, version: &str, path: &str) -> Component {
        Component {
            kind: kind.into(),
            name: name.into(),
            version: version.into(),
            path: path.into(),
            ..Default::default()
        }
    }
}

/// Seconds since the Unix epoch, as Python's `time.time()`.
pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

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

pub fn github(repo: &str) -> String {
    format!("https://github.com/{repo}.git")
}

/// The first executable called `name` on PATH (Python: `shutil.which`).
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return is_executable(&p).then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// What a finished program printed.
#[derive(Debug, Default)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// The most of a program's stdout or stderr kept; the rest is read and
/// dropped, so the program never blocks on a full pipe.
pub const MAX_OUTPUT: u64 = 64 << 20;

/// How many probes (subprocesses, mostly) run at once in [`par_map`].
pub const PROBES: usize = 8;

/// `f` over `items`, at most `width` at once, the results in `items`' order.
/// For probes that wait on a subprocess or the network: an inventory that
/// runs a few hundred of them one after another spends seconds waiting.
pub fn par_map<T: Sync, R: Send>(items: &[T], width: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done = std::sync::Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|s| {
        for _ in 0..width.clamp(1, items.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { return };
                    let r = f(item);
                    done.lock().expect("lock").push((i, r));
                }
            });
        }
    });
    let mut done = done.into_inner().expect("lock");
    done.sort_by_key(|(i, _)| *i);
    done.into_iter().map(|(_, r)| r).collect()
}

/// Run `argv` with stdin closed and `NO_COLOR=1`, killing it after
/// `timeout`. An error only when it can't start or times out. The deadline
/// covers the program and its output: a process it started in the
/// background that keeps the pipes open (a daemon, a `sleep &`) doesn't
/// hold the call past `timeout` (plus a second's grace once it's killed).
pub fn exec(argv: &[&OsStr], env: &[(&str, &str)], timeout: Duration) -> Result<Output> {
    let (prog, args) = argv.split_first().ok_or_else(|| Error::Failed("empty command".into()))?;
    let mut cmd = Command::new(prog);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).env("NO_COLOR", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| Error::Failed(format!("{}: {e}", prog.to_string_lossy())))?;
    let drain = |pipe: Box<dyn Read + Send>| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut pipe = pipe;
            let _ = pipe.by_ref().take(MAX_OUTPUT).read_to_end(&mut buf);
            let _ = std::io::copy(&mut pipe, &mut std::io::sink());
            let _ = tx.send(buf);
        });
        rx
    };
    let out = drain(Box::new(child.stdout.take().expect("piped stdout")));
    let err = drain(Box::new(child.stderr.take().expect("piped stderr")));
    let start = Instant::now();
    let timed_out = || Error::Failed(format!("{} timed out after {}s", prog.to_string_lossy(), timeout.as_secs()));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(timed_out());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // The program has exited; its output ends when the last process holding
    // the pipes does. A reader still blocked at the deadline is left to end
    // with that process, and the call reports the timeout.
    let deadline = (start + timeout).max(Instant::now() + Duration::from_secs(1));
    let collect = |rx: std::sync::mpsc::Receiver<Vec<u8>>| {
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).map_err(|_| timed_out())
    };
    let stdout = String::from_utf8_lossy(&collect(out)?).into_owned();
    let stderr = String::from_utf8_lossy(&collect(err)?).into_owned();
    Ok(Output { code: status.code(), stdout, stderr })
}

/// stdout and stderr of `argv`, or "" when it can't run (Python: `system.run`).
pub fn run<S: AsRef<OsStr>>(argv: &[S], timeout: Duration) -> String {
    let argv: Vec<&OsStr> = argv.iter().map(AsRef::as_ref).collect();
    match exec(&argv, &[], timeout) {
        Ok(o) => o.stdout + &o.stderr,
        Err(_) => String::new(),
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

/// /etc/os-release as a map (empty off Linux).
pub fn os_release() -> BTreeMap<String, String> {
    std::fs::read_to_string("/etc/os-release").map(|t| parse_os_release(&t)).unwrap_or_default()
}

pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    out
}

fn release_ids(rel: &BTreeMap<String, String>) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for key in ["ID", "ID_LIKE"] {
        if let Some(v) = rel.get(key) {
            ids.extend(v.split_whitespace().map(str::to_string));
        }
    }
    ids
}

/// Which source checks this Linux distro's packages: "osv" (the package
/// database and the distro trackers in OSV), "dnf" (dnf's, or yum's, own
/// security advisories), "arch" (the Arch security tracker), or "".
pub fn os_family(rel: &BTreeMap<String, String>) -> &'static str {
    let ids = release_ids(rel);
    let any = |set: &[&str]| ids.iter().any(|i| set.contains(&i.as_str()));
    if any(&[
        "debian",
        "ubuntu",
        "alpine",
        "wolfi",
        "chainguard",
        "opensuse",
        "opensuse-tumbleweed",
        "opensuse-leap",
        "sles",
        "suse",
    ]) {
        "osv"
    } else if any(&["fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn"]) {
        "dnf"
    } else if any(&["arch", "archlinux"]) {
        "arch"
    } else {
        ""
    }
}

/// How to update one OS package on this distro.
pub fn os_fix(rel: &BTreeMap<String, String>, name: &str) -> String {
    let ids = release_ids(rel);
    let any = |set: &[&str]| ids.iter().any(|i| set.contains(&i.as_str()));
    if any(&["debian", "ubuntu"]) {
        format!("sudo apt-get update && sudo apt-get install --only-upgrade {name}")
    } else if any(&["alpine", "wolfi", "chainguard"]) {
        format!("sudo apk upgrade {name}")
    } else if ids.iter().any(|i| i.contains("suse")) {
        format!("sudo zypper update {name}")
    } else if any(&["arch", "archlinux"]) {
        "sudo pacman -Syu".to_string() // Arch doesn't support partial upgrades
    } else {
        format!("sudo {} upgrade {name}", if which("dnf").is_some() { "dnf" } else { "yum" })
    }
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
    crate::json::parse(text.as_bytes(), crate::json::MAX_DOCUMENT).ok()
}

/// `realpath`: symlinks resolved, or the path as given when it can't be.
pub fn realpath(p: &str) -> String {
    std::fs::canonicalize(p).map(|r| r.to_string_lossy().into_owned()).unwrap_or_else(|_| p.to_string())
}

const SYSTEM_DIRS: &[&str] = &["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/libexec/", "/usr/lib/", "/System/"];
const APPLE_DIRS: &[&str] = &["/Library/Developer/CommandLineTools/", "/Applications/Xcode"];

/// Whether the OS update check covers files the OS package manager owns.
pub fn os_vouches() -> bool {
    MACOS || !os_family(&os_release()).is_empty()
}

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

/// Every distinct executable called `name` on PATH, then in the `extra`
/// directory globs, as (shown path, real path).
pub fn on_path<S: AsRef<str>>(name: &str, extra: &[S]) -> Vec<(String, String)> {
    let mut dirs: Vec<String> = std::env::var("PATH").unwrap_or_default().split(':').map(str::to_string).collect();
    dirs.extend(expand(extra));
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for d in dirs {
        let p = if d.is_empty() { name.to_string() } else { format!("{}/{name}", d.trim_end_matches('/')) };
        if is_executable(Path::new(&p)) {
            let real = realpath(&p);
            if !seen.contains(&real) {
                seen.push(real.clone());
                out.push((p, real));
            }
        }
    }
    out
}

pub fn brew_prefix() -> String {
    match which("brew") {
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
    let mut out = BTreeMap::new();
    if let Some(b) = which("brew") {
        if let Some(casks) = homebrew_prefix(&b).and_then(|p| caskroom(&p.join("Caskroom"))) {
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

/// A CLI shipped inside an installed macOS app, or "".
pub fn app_cli(app_names: &[&str], cli_rel: &str) -> String {
    for name in app_names {
        for root in ["/Applications".to_string(), format!("{}/Applications", home().display())] {
            let cli = format!("{root}/{name}.app/Contents/Resources/app/{cli_rel}");
            if Path::new(&cli).exists() {
                return cli;
            }
        }
    }
    String::new()
}

/// A directory removed (with its contents) when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Result<TempDir> {
        static N: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "wpantry-{label}-{}-{}-{}",
            std::process::id(),
            stamp,
            N.fetch_add(1, Ordering::Relaxed)
        ));
        // Exclusive and private: a path someone else made first is an error,
        // never reused, and nothing extracted there is readable by others.
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir)?;
        Ok(TempDir(dir))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

    #[test]
    fn par_map_keeps_order_and_runs_at_once() {
        let items: Vec<u64> = (0..24).collect();
        let start = Instant::now();
        let out = par_map(&items, 8, |&i| {
            std::thread::sleep(Duration::from_millis(50));
            i * 2
        });
        assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
        // 24 sleeps of 50 ms, 8 at a time, take about 150 ms, not 1.2 s.
        assert!(start.elapsed() < Duration::from_millis(900), "{:?}", start.elapsed());
        assert!(par_map(&[] as &[u8], 8, |&b| b).is_empty());
    }

    #[test]
    fn exec_captures_and_times_out() {
        let o = exec(
            &[OsStr::new("sh"), OsStr::new("-c"), OsStr::new("echo out; echo err >&2; echo $NO_COLOR; exit 3")],
            &[],
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!((o.code, o.stdout.as_str(), o.stderr.as_str()), (Some(3), "out\n1\n", "err\n"));
        assert!(exec(&[OsStr::new("sleep"), OsStr::new("5")], &[], Duration::from_millis(100)).is_err());
        assert_eq!(run(&["/nonexistent/binary"], Duration::from_secs(1)), "");
    }

    /// A background process holding the pipes doesn't hold the call: not
    /// when the program is killed at the deadline, nor when it exits first.
    #[test]
    fn exec_deadline_covers_processes_left_holding_the_pipes() {
        for script in ["sleep 5 & wait", "sleep 5 &"] {
            let start = Instant::now();
            let got = exec(&[OsStr::new("sh"), OsStr::new("-c"), OsStr::new(script)], &[], Duration::from_millis(100));
            assert!(got.is_err(), "{script}");
            assert!(start.elapsed() < Duration::from_secs(3), "{script}: {:?}", start.elapsed());
        }
    }

    #[test]
    fn os_release_families_and_fixes() {
        let rel = parse_os_release("NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"22\"\n");
        assert_eq!(rel["ID_LIKE"], "ubuntu debian");
        assert_eq!(os_family(&rel), "osv");
        assert!(os_fix(&rel, "openssl").starts_with("sudo apt-get update"));
        assert_eq!(os_family(&parse_os_release("ID=fedora\n")), "dnf");
        assert_eq!(os_family(&parse_os_release("ID=arch\n")), "arch");
        assert_eq!(os_family(&parse_os_release("ID=nixos\n")), "");
        assert_eq!(
            os_fix(&parse_os_release("ID=opensuse-leap\nID_LIKE=\"suse opensuse\"\n"), "curl"),
            "sudo zypper update curl"
        );
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
}
