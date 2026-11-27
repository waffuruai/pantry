//! The narrow re-check of a Python runtime (kind `runtime`, component
//! `python`, found by the package inventory): the install the finding's
//! location belongs to is found and its version read again, from files
//! alone, then judged by the same OSV, end-of-life and cached-record logic
//! as a catalog tool (`recheck::judge_component`).
//!
//! No interpreter is run, nor any other program: no version manager, no
//! package manager, no pip. The location is resolved to the interpreter it
//! stands for, then to the install that interpreter belongs to:
//!
//! * a real interpreter, or a link (a chain of them) to one: the file it
//!   leads to;
//! * a pyenv shim (`$PYENV_ROOT/shims/…`, a script naming pyenv): the version
//!   pyenv would pick here, from `PYENV_VERSION`, else the nearest
//!   `.python-version` from the current folder (or `PYENV_DIR`) up, else
//!   `$PYENV_ROOT/version`, else `system`; a prefix such as `3.12` is the
//!   newest installed `3.12.N`, as `pyenv latest` picks it. The interpreter
//!   is `versions/<name>/bin/<command>`, the first of the names that has
//!   it; `system` is the next `<command>` on `PATH` after the shims;
//! * an asdf shim (`…/shims/…`, a script naming asdf): `ASDF_PYTHON_VERSION`,
//!   else the nearest `.tool-versions` (or the file
//!   `ASDF_DEFAULT_TOOL_VERSIONS_FILENAME` names) with a `python` line from
//!   the current folder up, else the one in the home folder; the
//!   interpreter is `installs/python/<version>/bin/<command>`;
//! * a mise shim, an asdf set up to read legacy version files, or an asdf
//!   `ref:` version: `unknown` (`unreadable`), since which interpreter it
//!   starts follows configuration this check does not read;
//! * a virtual environment's interpreter (a `pyvenv.cfg` beside it or one
//!   folder up): its base interpreter, the one its link leads to, else the
//!   one in the folder its `home` names. Its own `version` is not used: it is
//!   the base's version when the environment was made, and a base upgraded
//!   in place since has another.
//!
//! The install's version is then read by
//! [`python_layout::version_of`] (`patchlevel.h`, a framework's
//! `Info.plist`, conda's record, a uv install's folder name). The answers:
//!
//! * the file is not there: `gone` (`removed`) when the place it lived in
//!   (the manager's folder of installs, [`anchor`]) is still there, `unknown`
//!   (`unreachable`) when that is gone too;
//! * the file is there but the version cannot be read from files, or a shim
//!   picks a version that is not installed: `unknown` (`unreadable`), never
//!   a guess;
//! * something else (Homebrew, the OS) vouches for the interpreter the
//!   location leads to: `unknown` (`unsupported`), as a scan reports no
//!   runtime for it and that manager's own finding is checked on its own;
//! * otherwise the version is judged: `gone` (`fixed`), `still_present`
//!   (`affected`), or `unknown` for an answer the cache never held.
//!
//! A new install beside the old one does not make the old one's finding
//! gone: the old path still reads as the old version.

use super::recheck::Verdict;
use crate::checks::machine::packages;
use crate::checks::machine::python_layout;
use crate::component::Component;
use crate::utils::files;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Whether a finding of this kind and component is a Python runtime.
pub(super) fn applies(kind: &str, component: &str) -> bool {
    kind == "runtime" && component == "python"
}

/// What resolving a shim depends on, apart from the files: the folder it is
/// resolved from and the environment variables version managers read.
pub(super) struct Here {
    pub home: PathBuf,
    pub cwd: PathBuf,
    /// `std::env::consts::OS`.
    pub os: &'static str,
    /// The variables in [`VARS`] that are set and not empty.
    pub vars: HashMap<String, String>,
}

/// The environment variables a shim's resolution reads.
const VARS: &[&str] = &[
    "PATH",
    "PYENV_VERSION",
    "PYENV_DIR",
    "ASDF_PYTHON_VERSION",
    "ASDF_DEFAULT_TOOL_VERSIONS_FILENAME",
    "ASDF_CONFIG_FILE",
];

impl Here {
    /// This process's.
    pub fn now() -> Here {
        let vars = VARS
            .iter()
            .filter_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| (k.to_string(), v)))
            .collect();
        Here { home: files::home(), cwd: std::env::current_dir().unwrap_or_default(), os: std::env::consts::OS, vars }
    }

    fn var(&self, k: &str) -> Option<&str> {
        self.vars.get(k).map(String::as_str)
    }
}

/// The folder a Python install lives in, whose presence says an install
/// missing from it was removed rather than its volume unmounted: the
/// version manager's own folder of installs (`pyenv/versions`, `uv/python`,
/// `asdf/installs/python`, a conda `envs`), else the one
/// [`super::recheck::anchor_of`] gives.
fn anchor(location: &Path) -> PathBuf {
    let text = location.to_string_lossy().replace('\\', "/");
    for marker in ["/.pyenv/versions", "/uv/python", "/.asdf/installs/python", "/envs"] {
        // The folder holding the installs, only when something follows it.
        if let Some(at) = text.find(&format!("{marker}/")) {
            return PathBuf::from(&text[..at + marker.len()]);
        }
    }
    super::recheck::anchor_of(location)
}

/// The runtime a scan would report at `location` now, or the verdict when
/// it can't be had, from files alone. `vouched` is
/// [`crate::utils::files::owner`] on a machine, `here` is [`Here::now`].
pub(super) fn read(
    location: &str,
    vouched: &dyn Fn(&str) -> &'static str,
    here: &Here,
) -> std::result::Result<Component, Verdict> {
    let shown = Path::new(location);
    if !shown.is_absolute() {
        let why =
            format!("python at {location} has no narrow check: it is not an absolute path; only a scan checks it.");
        return Err(Verdict::unknown("unsupported", why));
    }
    // `metadata` follows a link: one that goes nowhere is a Python that is gone.
    match std::fs::metadata(shown) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Err(Verdict::unknown("unreadable", format!("{location} is not an interpreter file."))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(super::recheck::vanished(shown, &anchor(shown)));
        }
        Err(e) => return Err(Verdict::unknown("unreadable", format!("{location} can't be read: {e}."))),
    }
    let unreadable = |why: String| Verdict::unknown("unreadable", format!("{location} is there, but {why}."));
    // The interpreter the location stands for: a shim's pick, else itself.
    let exe = match shim_of(shown) {
        Some(kind) => resolve_shim(&kind, shown, here).map_err(unreadable)?,
        None => shown.to_path_buf(),
    };
    let real = files::realpath(&exe.display().to_string());
    let who = vouched(&real);
    if !who.is_empty() {
        let why = format!(
            "{location} leads to an interpreter that {who} vouches for, which a scan checks as that manager's package, not as a runtime."
        );
        return Err(Verdict::unknown("unsupported", why));
    }
    let base = base_of(&exe, &real).map_err(unreadable)?;
    let who = vouched(&base);
    if !who.is_empty() {
        let why = format!(
            "{location} is a virtual environment of an interpreter that {who} vouches for, which a scan checks as that manager's package, not as a runtime."
        );
        return Err(Verdict::unknown("unsupported", why));
    }
    let version = python_layout::version_of(&base, here.os)
        .map_err(|why| unreadable(format!("its version can't be read without running it: {why}")))?;
    Ok(packages::runtime_component(location, &base, &version))
}

/// A version manager whose shim decides which interpreter starts.
#[derive(Debug, PartialEq)]
enum Shim {
    /// pyenv, with its root (the folder holding `shims` and `versions`).
    Pyenv(PathBuf),
    /// asdf, with its data folder (holding `shims` and `installs`).
    Asdf(PathBuf),
    Mise,
}

/// Which manager's shim `shown` is, read from the file: a file in a `shims`
/// folder that is a link to `mise`, or a script that names pyenv or asdf.
/// None for anything else, which is then read as an interpreter.
fn shim_of(shown: &Path) -> Option<Shim> {
    let dir = shown.parent()?;
    if dir.file_name()? != "shims" {
        return None;
    }
    let root = dir.parent()?.to_path_buf();
    if let Ok(target) = std::fs::read_link(shown) {
        let name = target.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        if name == "mise" || name == "mise.exe" {
            return Some(Shim::Mise);
        }
    }
    let head = files::read_capped(shown, 16 << 10).unwrap_or_default();
    if head.contains("pyenv") {
        Some(Shim::Pyenv(root))
    } else if head.contains("asdf") {
        Some(Shim::Asdf(root))
    } else {
        None
    }
}

/// The interpreter the shim `shown` of `kind` would start here, or why it
/// can't be told.
fn resolve_shim(kind: &Shim, shown: &Path, here: &Here) -> Result<PathBuf, String> {
    let command = shown.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let shims = shown.parent().unwrap_or(Path::new(""));
    match kind {
        Shim::Mise => {
            Err("it is a mise shim, whose interpreter follows mise's configuration, which a re-check does not read"
                .into())
        }
        Shim::Pyenv(root) => {
            let (names, from) = pyenv_names(root, here);
            pick(&names, &from, "pyenv", &command, shims, here, &|name| {
                let dir = root.join("versions").join(name);
                let dir = if dir.exists() { Some(dir) } else { newest_of(&root.join("versions"), name) };
                Ok(dir.map(|d| d.join("bin").join(&command)))
            })
        }
        Shim::Asdf(root) => {
            let rc = here.var("ASDF_CONFIG_FILE").map(PathBuf::from).unwrap_or_else(|| here.home.join(".asdfrc"));
            let legacy = std::fs::read_to_string(&rc).unwrap_or_default().lines().any(|l| {
                l.split_once('=').is_some_and(|(k, v)| k.trim() == "legacy_version_file" && v.trim() == "yes")
            });
            if legacy {
                return Err(format!(
                    "asdf is set to read legacy version files ({}), which a re-check does not read",
                    rc.display()
                ));
            }
            let Some((names, from)) = asdf_names(here) else {
                return Err("asdf has no python version set here".into());
            };
            pick(&names, &from, "asdf", &command, shims, here, &|name| {
                if let Some(dir) = name.strip_prefix("path:") {
                    return Ok(Some(PathBuf::from(dir).join("bin").join(&command)));
                }
                if name.starts_with("ref:") {
                    return Err(format!("asdf's version {name} ({from}) is built from source on demand"));
                }
                Ok(Some(root.join("installs/python").join(name).join("bin").join(&command)))
            })
        }
    }
}

/// The first of `names` (a manager's versions, set in `from`) whose
/// interpreter `at` gives and is a file; `system` is the next `command` on
/// `PATH` after the `shims` folder.
fn pick(
    names: &[String],
    from: &str,
    manager: &str,
    command: &str,
    shims: &Path,
    here: &Here,
    at: &dyn Fn(&str) -> Result<Option<PathBuf>, String>,
) -> Result<PathBuf, String> {
    for name in names {
        let exe = if name == "system" { system(command, shims, here) } else { at(name)? };
        match exe {
            Some(exe) if exe.is_file() => return Ok(exe),
            Some(_) => {}
            None if name == "system" => {}
            None => return Err(format!("{manager}'s version {name} ({from}) is not installed")),
        }
    }
    Err(format!("none of {manager}'s versions here ({}, from {from}) has {command}", names.join(", ")))
}

/// The versions pyenv would use here, with where they were set, as
/// `pyenv version-name` reads them.
fn pyenv_names(root: &Path, here: &Here) -> (Vec<String>, String) {
    if let Some(v) = here.var("PYENV_VERSION") {
        return (v.split(':').filter(|n| !n.is_empty()).map(str::to_string).collect(), "PYENV_VERSION".into());
    }
    let start = here.var("PYENV_DIR").map(PathBuf::from).unwrap_or_else(|| here.cwd.clone());
    let file = start
        .ancestors()
        .map(|d| d.join(".python-version"))
        .find(|f| f.is_file())
        .unwrap_or_else(|| root.join("version"));
    let text = std::fs::read_to_string(&file).unwrap_or_default();
    // The first word of each line, comments left out (`pyenv-version-file-read`).
    let names: Vec<String> = text
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| !w.starts_with('#'))
        .map(str::to_string)
        .collect();
    if names.is_empty() {
        return (vec!["system".into()], file.display().to_string());
    }
    (names, file.display().to_string())
}

/// The newest installed `name.N…` in `versions`, when `name` is a release
/// prefix (`3.12`), as `pyenv latest` resolves one: only plain numbered
/// releases count, never a `-dev`, a pre-release or an environment.
fn newest_of(versions: &Path, name: &str) -> Option<PathBuf> {
    let numbers = |v: &str| -> Option<Vec<u64>> { v.split('.').map(|p| p.parse().ok()).collect() };
    numbers(name)?;
    let entries = std::fs::read_dir(versions).ok()?;
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.strip_prefix(name).is_some_and(|rest| rest.starts_with('.')))
        .filter_map(|n| numbers(&n).map(|k| (k, n)))
        .max()
        .map(|(_, n)| versions.join(n))
}

/// The python versions asdf would use here, with where they were set.
fn asdf_names(here: &Here) -> Option<(Vec<String>, String)> {
    if let Some(v) = here.var("ASDF_PYTHON_VERSION") {
        return Some((v.split_whitespace().map(str::to_string).collect(), "ASDF_PYTHON_VERSION".into()));
    }
    let name = here.var("ASDF_DEFAULT_TOOL_VERSIONS_FILENAME").unwrap_or(".tool-versions");
    let python_in = |file: &Path| -> Option<Vec<String>> {
        let text = std::fs::read_to_string(file).ok()?;
        text.lines().find_map(|l| {
            let l = l.split('#').next().unwrap_or("");
            let mut words = l.split_whitespace();
            (words.next() == Some("python")).then(|| words.map(str::to_string).collect::<Vec<_>>())
        })
    };
    let dirs = here.cwd.ancestors().filter(|d| d.parent().is_some()).chain(std::iter::once(here.home.as_path()));
    for dir in dirs {
        let file = dir.join(name);
        if let Some(names) = python_in(&file).filter(|n| !n.is_empty()) {
            return Some((names, file.display().to_string()));
        }
    }
    None
}

/// The first `command` on `PATH` that is not in the `shims` folder.
fn system(command: &str, shims: &Path, here: &Here) -> Option<PathBuf> {
    let shims = files::realpath(&shims.display().to_string());
    let path = here.var("PATH")?;
    std::env::split_paths(path)
        .filter(|d| !d.as_os_str().is_empty() && files::realpath(&d.display().to_string()) != shims)
        .map(|d| d.join(command))
        .find(|p| p.is_file())
}

/// The base interpreter `exe` (real path `real`) runs as: itself, or for a
/// virtual environment's interpreter the one it links to, else the one in
/// the folder its `pyvenv.cfg` names as `home`. As a real path.
fn base_of(exe: &Path, real: &str) -> Result<String, String> {
    let shown = exe.display().to_string();
    let Some(cfg) = python_layout::venv_cfg(&shown) else { return Ok(real.to_string()) };
    let venv = cfg.parent().unwrap_or(Path::new(""));
    let venv_real = files::realpath(&venv.display().to_string());
    if !Path::new(real).starts_with(&venv_real) {
        // A link out of the environment: its base.
        return Ok(real.to_string());
    }
    // A copy (`--copies`, Windows): `home` names the base's folder.
    let text = std::fs::read_to_string(&cfg).unwrap_or_default();
    let Some(home) = python_layout::venv_value(&text, "home") else {
        return Err(format!("its virtual environment's {} names no home", cfg.display()));
    };
    let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let base = [name.as_str(), "python3", "python", "python.exe"]
        .iter()
        .map(|n| Path::new(&home).join(n))
        .find(|p| p.is_file())
        .ok_or_else(|| format!("the home its {} names ({home}) holds no interpreter", cfg.display()))?;
    Ok(files::realpath(&base.display().to_string()))
}
