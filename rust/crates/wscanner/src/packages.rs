//! Packages installed into this machine's runtimes, outside any project:
//! every Python (with its pip packages), npm and global npm packages for
//! every Node, `cargo install`s, pipx-installed tools and global Ruby gems.

use crate::catalog::{Cycle, PYTHON_DIRS};
use crate::re::Regex;
use crate::system::{self, Component, expand, github, on_path, owner, read_json, run, which};
use crate::tools::updater;
use serde_json::Value;
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

const PY_INFO: &str = "import json, platform, sys, sysconfig, os;\
print(json.dumps({'v': platform.python_version(), 'exe': sys.executable,\
'managed': os.path.exists(os.path.join(sysconfig.get_path('stdlib'), 'EXTERNALLY-MANAGED'))}))";

fn sh(argv: &[&str], timeout: u64) -> String {
    run(&argv.iter().map(OsStr::new).collect::<Vec<_>>(), Duration::from_secs(timeout))
}

/// The JSON value in tool output that may carry warnings around it.
pub fn json_in(text: &str, open: char, close: char) -> Option<Value> {
    let (a, b) = (text.find(open)?, text.rfind(close)?);
    (a <= b).then(|| serde_json::from_str(&text[a..=b]).ok()).flatten()
}

fn str_of(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(o) => o.to_string(),
    }
}

/// Every Python on PATH or installed by a version manager, with pip and its
/// packages.
pub fn pythons() -> Vec<Component> {
    let mut dirs: Vec<String> = std::env::var("PATH").unwrap_or_default().split(':').map(str::to_string).collect();
    dirs.extend(expand(PYTHON_DIRS));
    let minor = Regex::new(r"python3\.\d+");
    let mut names: Vec<String> = dirs
        .iter()
        .flat_map(|d| system::glob(&format!("{d}/python3.*")))
        .filter_map(|p| Path::new(&p).file_name().map(|n| n.to_string_lossy().into_owned()))
        .filter(|n| minor.fullmatch(n).is_some())
        .collect();
    names.sort();
    names.dedup();
    names.insert(0, "python3".into());
    let mut out = Vec::new();
    let mut seen = Vec::new();
    for n in names {
        for (shown, real) in on_path(&n, PYTHON_DIRS) {
            if !owner(&real).is_empty() {
                continue;
            }
            let raw = sh(&[&shown, "-I", "-c", PY_INFO], 15);
            let last = raw.trim().lines().last().unwrap_or("");
            let Some(info) = json_in(last, '{', '}') else { continue };
            let exe = system::realpath(&str_of(&info, "exe"));
            if seen.contains(&exe) {
                continue;
            }
            seen.push(exe);
            let v = str_of(&info, "v");
            let (fix, auto) = updater(&real, "python");
            let mut c = Component::new("runtime", "python", &v, &shown);
            c.osv = Some(("GIT".into(), github("python/cpython"), format!("v{v}")));
            c.eol = Some(("python".into(), Cycle::Minor.of(&v)));
            c.fix = fix.clone();
            c.auto = auto;
            out.push(c);
            out.extend(pip(&shown, info.get("managed") == Some(&Value::Bool(true)), (fix, auto)));
        }
    }
    out
}

fn pip(py: &str, managed: bool, runtime_fix: (String, bool)) -> Vec<Component> {
    let raw = sh(&[py, "-m", "pip", "list", "--format=json", "--disable-pip-version-check"], 60);
    let list = json_in(&raw, '[', ']').and_then(|v| v.as_array().cloned()).unwrap_or_default();
    let real = system::realpath(py);
    let mut out = Vec::new();
    for p in list {
        let (name, ver) = (str_of(&p, "name"), str_of(&p, "version"));
        if name.is_empty() || ver.is_empty() {
            continue;
        }
        let (fix, auto) = if managed && real.contains("/uv/") {
            runtime_fix.clone() // uv's Python builds bundle pip; a newer build brings a newer one
        } else if managed {
            (format!("Upgrade {name} through the package manager that owns {py}"), false)
        } else {
            (format!("{py} -m pip install --upgrade '{name}>={{safe}}'"), true)
        };
        let is_pip = name.eq_ignore_ascii_case("pip");
        let shown = if is_pip { name.clone() } else { format!("pip:{name}") };
        let mut c = Component::new(if is_pip { "pkgmgr" } else { "package" }, &shown, &ver, py);
        c.osv = Some(("PyPI".into(), name, ver));
        c.fix = fix;
        c.auto = auto;
        out.push(c);
    }
    out
}

/// npm itself and the global npm packages of each Node in `found`.
pub fn node_packages(found: &[Component]) -> Vec<Component> {
    let mut out = Vec::new();
    let version = Regex::new(r"(\d+\.\d+\.\d+)$");
    for node in found.iter().filter(|c| c.name == "node") {
        let real = system::realpath(&node.path);
        let npm = Path::new(&real).with_file_name("npm").display().to_string();
        if !Path::new(&npm).exists() {
            continue;
        }
        // npm doesn't always list itself.
        let v = sh(&[&npm, "--version"], 15);
        if let Some(m) = v.trim().lines().last().and_then(|l| version.match_start(l)) {
            let mut c = Component::new("pkgmgr", "npm", m.get(1), &npm);
            c.osv = Some(("npm".into(), "npm".into(), m.get(1).into()));
            c.fix = format!("{npm} install -g npm@{{safe}}");
            c.auto = true;
            out.push(c);
        }
        let deps = json_in(&sh(&[&npm, "ls", "-g", "--json", "--depth=0"], 60), '{', '}').unwrap_or(Value::Null);
        if let Some(map) = deps.get("dependencies").and_then(Value::as_object) {
            for (name, d) in map {
                let ver = str_of(d, "version");
                if name == "npm" || ver.is_empty() {
                    continue;
                }
                let kind = if name == "corepack" { "pkgmgr" } else { "package" };
                let shown = if kind == "pkgmgr" { name.clone() } else { format!("npm:{name}") };
                let mut c = Component::new(kind, &shown, &ver, &npm);
                c.osv = Some(("npm".into(), name.clone(), ver));
                c.fix = format!("{npm} install -g {name}@{{safe}}");
                c.auto = true;
                out.push(c);
            }
        }
    }
    out
}

pub fn cargo_installs() -> Vec<Component> {
    let home = std::env::var("CARGO_HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| format!("{}/.cargo", system::home().display()));
    let f = Path::new(&home).join(".crates2.json");
    let re = Regex::new(r"(\S+) (\S+) \(registry\+");
    let mut out = Vec::new();
    if let Some(installs) = read_json(&f).and_then(|j| j.get("installs").and_then(Value::as_object).cloned()) {
        for k in installs.keys() {
            if let Some(m) = re.match_start(k) {
                let (name, ver) = (m.get(1), m.get(2));
                let mut c = Component::new("package", &format!("cargo:{name}"), ver, &f.display().to_string());
                c.osv = Some(("crates.io".into(), name.into(), ver.into()));
                c.fix = format!("cargo install --locked {name}@{{safe}}");
                c.auto = true;
                out.push(c);
            }
        }
    }
    out
}

/// Tools installed with pipx: each lives in its own venv.
pub fn pipx_packages() -> Vec<Component> {
    let Some(exe) = which("pipx") else { return Vec::new() };
    let exe = exe.display().to_string();
    let data = json_in(&sh(&[&exe, "list", "--json"], 60), '{', '}').unwrap_or(Value::Null);
    let mut out = Vec::new();
    if let Some(venvs) = data.get("venvs").and_then(Value::as_object) {
        for (name, v) in venvs {
            let meta = v.get("metadata").and_then(|m| m.get("main_package")).cloned().unwrap_or(Value::Null);
            let ver = str_of(&meta, "package_version");
            if ver.is_empty() {
                continue;
            }
            let pkg = match str_of(&meta, "package") {
                p if p.is_empty() => name.clone(),
                p => p,
            };
            let mut c = Component::new("package", &format!("pipx:{name}"), &ver, &exe);
            c.osv = Some(("PyPI".into(), pkg, ver));
            c.fix = format!("{exe} upgrade {name}");
            c.auto = true;
            out.push(c);
        }
    }
    out
}

/// Global gems of each Ruby we check (Apple's system Ruby is the OS's).
pub fn gems(found: &[Component]) -> Vec<Component> {
    let re = Regex::new(r"^(\S+) \((?:default: )?([^,)\s]+)");
    let mut out = Vec::new();
    for ruby in found.iter().filter(|c| c.name == "ruby") {
        let gem = Path::new(&system::realpath(&ruby.path)).with_file_name("gem").display().to_string();
        if !Path::new(&gem).exists() {
            continue;
        }
        for line in sh(&[&gem, "list", "--local"], 60).lines() {
            if let Some(m) = re.match_start(line) {
                let (name, ver) = (m.get(1), m.get(2));
                let mut c = Component::new("package", &format!("gem:{name}"), ver, &gem);
                c.osv = Some(("RubyGems".into(), name.into(), ver.into()));
                c.fix = format!("{gem} update {name}");
                c.auto = true;
                out.push(c);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_inside_noisy_output() {
        assert_eq!(json_in("WARNING: x\n[{\"name\": \"pip\"}]\nnotice", '[', ']').unwrap()[0]["name"], "pip");
        assert_eq!(json_in("nothing", '{', '}'), None);
        assert_eq!(json_in("} {", '{', '}'), None);
    }

    #[test]
    fn gem_and_cargo_lines() {
        let gem = Regex::new(r"^(\S+) \((?:default: )?([^,)\s]+)");
        let m = gem.match_start("json (default: 2.7.2, 2.6.1)").unwrap();
        assert_eq!((m.get(1), m.get(2)), ("json", "2.7.2"));
        let cargo = Regex::new(r"(\S+) (\S+) \(registry\+");
        let m = cargo.match_start("ripgrep 14.1.1 (registry+https://github.com/rust-lang/crates.io-index)").unwrap();
        assert_eq!((m.get(1), m.get(2)), ("ripgrep", "14.1.1"));
    }
}
