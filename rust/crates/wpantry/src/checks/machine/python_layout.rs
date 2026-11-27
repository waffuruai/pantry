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
        let value = |key: &str| venv_value(&text, key);
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
pub(crate) fn venv_cfg(exe: &str) -> Option<PathBuf> {
    let dir = Path::new(exe).parent()?;
    [dir.join("pyvenv.cfg"), dir.parent()?.join("pyvenv.cfg")].into_iter().find(|c| c.is_file())
}

/// The value of `key` in a `pyvenv.cfg`'s text (`home = /opt/py/bin`), keys
/// compared without case, as `site` reads them.
pub(crate) fn venv_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim().eq_ignore_ascii_case(key)).then(|| v.trim().to_string())
    })
}

/// The full version (`3.12.4`, `3.13.0rc1`) of the interpreter whose real
/// path is `exe`, read from the files its install keeps, never by running
/// it; on `Err`, the sentence saying why it cannot be read. `os` is
/// `std::env::consts::OS`. Every one of these that is there is read, and
/// they must agree with each other and with the release line the install's
/// layout gives ([`line_of`]):
///
/// * `include/pythonX.Y[t]/patchlevel.h` under the prefix (`include\patchlevel.h`
///   on Windows): the `PY_VERSION` the interpreter was built with, which is
///   what `platform.python_version()` reports;
/// * a framework build's `Versions/X.Y/Resources/Info.plist`
///   (`CFBundleShortVersionString`, else `CFBundleVersion`);
/// * a conda prefix's `conda-meta/python-*.json` (`version`), the record
///   conda keeps of the package it installed;
/// * a uv-managed install's folder name (`cpython-3.12.4-macos-aarch64-none`):
///   uv names every install it manages by its full key, version included,
///   and links a release line's folder (`cpython-3.12-…`) to it, so the
///   real folder's name is the exact version. No other manager's folder
///   name is relied on alone: pyenv, asdf and mise also keep folders named
///   by aliases and environments.
///
/// Example: `/opt/py/bin/python3.12` with `/opt/py/include/python3.12/patchlevel.h`
/// holding `#define PY_VERSION "3.12.4"` reads as `Ok("3.12.4")`.
pub fn version_of(exe: &str, os: &str) -> Result<String, String> {
    let line = line_of(exe);
    let prefix = prefix_of(exe);
    let mut found: Vec<(String, String)> = Vec::new();
    let mut add = |what: String, v: Option<String>| {
        if let Some(v) = v.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
            found.push((what, v));
        }
    };
    let headers: Vec<PathBuf> = if os == "windows" {
        vec![prefix.join("include").join("patchlevel.h")]
    } else if let Some((line, t)) = &line {
        vec![prefix.join(format!("include/python{line}{t}/patchlevel.h"))]
    } else {
        let all = files::glob(&format!("{}/include/python3.*/patchlevel.h", prefix.display()));
        // More than one release line's headers under one prefix name no one version.
        if all.len() > 1 {
            return Err(format!("{} holds the headers of more than one release line", prefix.display()));
        }
        all.into_iter().map(PathBuf::from).collect()
    };
    for h in headers.iter().filter(|h| h.is_file()) {
        let text = std::fs::read_to_string(h).unwrap_or_default();
        let v = Regex::new(r#"#define\s+PY_VERSION\s+"([^"]+)""#).search(&text).map(|c| c.get(1).to_string());
        add(h.display().to_string(), v);
    }
    if os == "macos" && exe.contains(".framework/Versions/") {
        let plist = prefix.join("Resources/Info.plist");
        let text = std::fs::read_to_string(&plist).unwrap_or_default();
        let key = |k: &str| {
            Regex::new(&format!(r"<key>{k}</key>\s*<string>([^<]*)</string>"))
                .search(&text)
                .map(|c| c.get(1).to_string())
        };
        add(plist.display().to_string(), key("CFBundleShortVersionString").or_else(|| key("CFBundleVersion")));
    }
    for record in files::glob(&format!("{}/conda-meta/python-*.json", prefix.display())) {
        let Some(meta) = files::read_json(Path::new(&record)) else { continue };
        if meta.get("name").and_then(|n| n.as_str()) == Some("python") {
            add(record, meta.get("version").and_then(|v| v.as_str()).map(str::to_string));
        }
    }
    let parent = prefix.parent().unwrap_or(Path::new(""));
    let uv = parent.ends_with("uv/python");
    if uv {
        let name = base(&prefix.display().to_string());
        let key = Regex::new(r"cpython-(\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?)(?:\+[a-z]+)?-.+").fullmatch(&name);
        add(prefix.display().to_string(), key.map(|c| c.get(1).to_string()));
    }
    let Some((from, v)) = found.first().cloned() else {
        return Err(format!(
            "its install ({}) keeps no file that names its full version (patchlevel.h, a framework's Info.plist, conda's record)",
            prefix.display()
        ));
    };
    if Regex::new(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?\+?").fullmatch(&v).is_none() {
        return Err(format!("{from} names a version that is not one ({v})"));
    }
    if let Some((other, w)) = found.iter().find(|(_, w)| *w != v) {
        return Err(format!("{from} says {v} and {other} says {w}"));
    }
    if let Some((line, _)) = line.filter(|(line, _)| minor(&v) != *line) {
        return Err(format!("{from} says {v}, but the install is laid out for {line}"));
    }
    Ok(v)
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
