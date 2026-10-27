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
    /// `wscanner --update` may run `fix` unattended.
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

/// $HOME (Python: `os.path.expanduser("~")`).
pub fn home() -> PathBuf {
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

/// Run `argv` with stdin closed and `NO_COLOR=1`, killing it after
/// `timeout`. An error only when it can't start or times out.
pub fn exec(argv: &[&OsStr], env: &[(&str, &str)], timeout: Duration) -> Result<Output> {
    let (prog, args) = argv.split_first().ok_or_else(|| Error::Failed("empty command".into()))?;
    let mut cmd = Command::new(prog);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).env("NO_COLOR", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| Error::Failed(format!("{}: {e}", prog.to_string_lossy())))?;
    let mut out = child.stdout.take().expect("piped stdout");
    let mut err = child.stderr.take().expect("piped stderr");
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err.read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            let _ = err_reader.join();
            return Err(Error::Failed(format!("{} timed out after {}s", prog.to_string_lossy(), timeout.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = String::from_utf8_lossy(&reader.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).into_owned();
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
    let meta = std::fs::metadata(path)?;
    if meta.len() > max {
        return Err(Error::Invalid(format!("{} is over {} bytes", path.display(), max)));
    }
    let bytes = std::fs::read(path)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
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

/// A directory removed (with its contents) when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Result<TempDir> {
        static N: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "wscanner-{label}-{}-{}-{}",
            std::process::id(),
            stamp,
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir)?;
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
