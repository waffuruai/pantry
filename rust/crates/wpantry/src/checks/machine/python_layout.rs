//! What an interpreter the OS or a package manager vouches for looks like on
//! disk, read without running it. wpantry never starts such a Python: on a
//! Mac without the Command Line Tools `/usr/bin/python3` is Apple's stub,
//! which opens the install dialog, scheduled scans included. All the scan
//! needs from one is its release line, whether it is externally managed
//! (PEP 668) and where `pip install --user` puts packages, and all three
//! follow from where it is installed.

use crate::utils::files;
use crate::utils::re::Regex;
use std::path::{Path, PathBuf};

/// A vouched-for interpreter, as its install layout shows it.
#[derive(Debug, PartialEq, Eq)]
pub enum Layout {
    /// `runs` is the interpreter a fix starts (its real path), `line` its
    /// release line (`3.12`), `user` the user site it reads (None for a venv
    /// without system site-packages), `managed` an `EXTERNALLY-MANAGED`
    /// marker in its standard library.
    Read { runs: String, line: String, user: Option<String>, managed: bool },
    /// No interpreter behind the path: Apple's `/usr/bin/python3` stub with
    /// no developer folder holding a Python.
    Absent,
    /// The release line cannot be told without running it; the sentence says why.
    Unknown(String),
}

/// What a vouched-for interpreter's paths depend on, apart from the path.
pub struct Env {
    pub home: PathBuf,
    /// `std::env::consts::OS`: "macos", "linux", "windows", ...
    pub os: &'static str,
    /// `PYTHONUSERBASE`, which Python's own `site` honours (the probe's `-I`
    /// does not turn it off), so the user site moves with it.
    pub user_base: Option<PathBuf>,
    /// `%APPDATA%`, the Windows user base's parent.
    pub appdata: Option<PathBuf>,
    /// The folder Apple's `/usr/bin/python3` stub hands over to: `DEVELOPER_DIR`,
    /// else `xcode-select`'s link, else the Command Line Tools.
    pub developer_dir: Option<PathBuf>,
}

impl Env {
    /// This machine's.
    pub fn here() -> Env {
        let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        let developer_dir = var("DEVELOPER_DIR")
            .or_else(|| std::fs::canonicalize("/var/db/xcode_select_link").ok())
            .or_else(|| Some(PathBuf::from("/Library/Developer/CommandLineTools")));
        Env {
            home: files::home(),
            os: std::env::consts::OS,
            user_base: var("PYTHONUSERBASE"),
            appdata: var("APPDATA"),
            developer_dir,
        }
    }
}

/// Apple's interpreter stubs, which start the developer folder's Python.
const APPLE_STUBS: &[&str] = &["/usr/bin/python3"];

/// The layout of the interpreter `shown`, whose real path is `real`.
pub fn read(shown: &str, real: &str, env: &Env) -> Layout {
    let mut exe = real.to_string();
    if env.os == "macos" && APPLE_STUBS.contains(&real) {
        let Some(dev) = &env.developer_dir else { return Layout::Absent };
        let behind = dev.join("usr/bin/python3");
        if !behind.is_file() {
            return Layout::Absent;
        }
        exe = files::realpath(&behind.display().to_string());
    }
    // A venv (pipx's): its own config names the version, and it reads no
    // user site unless it includes the system site-packages.
    if let Some(cfg) = venv_cfg(shown).or_else(|| venv_cfg(&exe)) {
        let text = std::fs::read_to_string(&cfg).unwrap_or_default();
        let value = |key: &str| {
            text.lines().find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim().eq_ignore_ascii_case(key)).then(|| v.trim().to_string())
            })
        };
        if !value("include-system-site-packages").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            let line = value("version_info").or_else(|| value("version")).map(|v| minor(&v)).unwrap_or_default();
            return Layout::Read { runs: exe, line, user: None, managed: false };
        }
    }
    let Some((line, t)) = line_of(&exe) else {
        return Layout::Unknown(format!(
            "its version cannot be read from where it is installed ({exe}), and wpantry does not run an interpreter the OS or a package manager looks after"
        ));
    };
    let prefix = prefix_of(&exe);
    let stdlib = if env.os == "windows" { prefix.join("Lib") } else { prefix.join(format!("lib/python{line}{t}")) };
    let managed = stdlib.join("EXTERNALLY-MANAGED").is_file();
    let framework = env.os == "macos" && exe.contains(".framework/");
    let user = user_site(env, &line, t, framework);
    Layout::Read { runs: exe, line, user: Some(user.display().to_string()), managed }
}

/// `pyvenv.cfg` beside the interpreter or one folder up, as `site` finds it.
fn venv_cfg(exe: &str) -> Option<PathBuf> {
    let dir = Path::new(exe).parent()?;
    [dir.join("pyvenv.cfg"), dir.parent()?.join("pyvenv.cfg")].into_iter().find(|c| c.is_file())
}

/// `3.12` of `3.12.4` (or of `3.12`).
fn minor(v: &str) -> String {
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// The release line and the free-threading suffix (`t` or ""), from the
/// file name (`python3.12`, `python3.13t`, `python312.exe`), else a
/// framework's `Versions/3.12`, a keg's `python@3.12`, or the one
/// `lib/python3.N` with an `os.py` under its prefix.
fn line_of(exe: &str) -> Option<(String, &'static str)> {
    let name = Path::new(exe).file_name()?.to_string_lossy().to_lowercase();
    let found = |c: crate::utils::re::Captures| {
        let t = if c.get(3).is_empty() { "" } else { "t" };
        (format!("{}.{}", c.get(1), c.get(2)), t)
    };
    for pattern in [r"python(\d)\.(\d+)(t?)", r"python(\d)(\d+)(t?)\.exe"] {
        if let Some(c) = Regex::new(pattern).fullmatch(&name) {
            return Some(found(c));
        }
    }
    for pattern in [r"/Versions/(\d)\.(\d+)()/", r"/python@(\d)\.(\d+)()/"] {
        if let Some(c) = Regex::new(pattern).search(exe) {
            return Some(found(c));
        }
    }
    // Windows: `python312.dll` beside the interpreter.
    let dir = Path::new(exe).parent()?.display().to_string();
    let dlls: Vec<(String, &str)> = files::glob(&format!("{dir}/python3*.dll"))
        .iter()
        .filter_map(|p| Regex::new(r"python(\d)(\d+)(t?)\.dll").fullmatch(&base(p).to_lowercase()).map(found))
        .collect();
    if let [one] = dlls.as_slice() {
        return Some(one.clone());
    }
    let lib = prefix_of(exe).join("lib");
    let libs: Vec<String> = files::glob(&format!("{}/python3.*/os.py", lib.display()))
        .iter()
        .filter_map(|p| Path::new(p).parent().map(|d| base(&d.display().to_string())))
        .filter_map(|n| n.strip_prefix("python").map(str::to_string))
        .filter(|v| Regex::new(r"\d\.\d+").fullmatch(v).is_some())
        .collect();
    match libs.as_slice() {
        [one] => Some((one.clone(), "")),
        _ => None,
    }
}

/// The last part of a path.
fn base(p: &str) -> String {
    Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// The install prefix: the folder holding `bin/` (POSIX), or the
/// interpreter's own folder on Windows (`C:\Python312\python.exe`).
fn prefix_of(exe: &str) -> PathBuf {
    let dir = Path::new(exe).parent().unwrap_or(Path::new(""));
    if dir.file_name().is_some_and(|n| n == "bin") {
        dir.parent().unwrap_or(dir).to_path_buf()
    } else {
        dir.to_path_buf()
    }
}

/// Where `site.getusersitepackages()` points for this release line.
fn user_site(env: &Env, line: &str, t: &str, framework: bool) -> PathBuf {
    let nodot = line.replace('.', "");
    if env.os == "windows" {
        let base = env.user_base.clone().or_else(|| env.appdata.as_ref().map(|a| a.join("Python")));
        let base = base.unwrap_or_else(|| env.home.join("AppData").join("Roaming").join("Python"));
        return base.join(format!("Python{nodot}{t}")).join("site-packages");
    }
    if framework {
        let base = env.user_base.clone().unwrap_or_else(|| env.home.join(format!("Library/Python/{line}")));
        return base.join("lib/python/site-packages");
    }
    let base = env.user_base.clone().unwrap_or_else(|| env.home.join(".local"));
    base.join(format!("lib/python{line}{t}/site-packages"))
}

#[cfg(test)]
#[path = "python_layout_tests.rs"]
mod tests;
