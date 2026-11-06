//! Packages installed into this machine's runtimes, outside any project:
//! every Python (with its pip packages), npm and global npm packages for
//! every Node, `cargo install`s, pipx-installed tools and global Ruby gems.

use crate::checks::machine::catalog::{Cycle, PYTHON_DIRS};
use crate::checks::machine::tools::updater;
use crate::component::Component;
use crate::utils::files::expand;
use crate::utils::files::owner;
use crate::utils::files::read_json;
use crate::utils::net::github;
use crate::utils::process::on_path;
use crate::utils::process::run;
use crate::utils::process::which;
use crate::utils::re::Regex;
use crate::utils::{files, parallel};
use serde_json::Value;
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

/// What we need from an interpreter, asked with `-I -S`: no site
/// processing, so no `.pth` startup hook in its site-packages runs (and no
/// pip). With `-S` Python doesn't apply a venv itself, so its
/// `pyvenv.cfg` is read here, as `site.venv` would. `sites` are the
/// directories `pip list` reads, in sys.path order. The base interpreter's
/// site-packages are asked for by its base prefixes: from 3.14 a venv is
/// `sys.prefix` even under `-S`, so the plain call would give the venv's
/// own directories and leave out the system ones it inherits.
const PY_INFO: &str = r#"import json, os, platform, site, sys, sysconfig
exe = os.path.dirname(os.path.abspath(sys.executable))
cfg = next((c for c in (os.path.join(d, "pyvenv.cfg") for d in (exe, os.path.dirname(exe))) if os.path.isfile(c)), None)
base = [site.getusersitepackages()] + site.getsitepackages([sys.base_prefix, sys.base_exec_prefix])
sites = base
if cfg:
    system = False
    for line in open(cfg, encoding="utf-8", errors="replace"):
        k, _, v = line.partition("=")
        if k.strip().lower() == "include-system-site-packages":
            system = v.strip().lower() == "true"
    ver = "python%d.%d" % sys.version_info[:2]
    venv = os.path.dirname(cfg)
    own = [os.path.join(venv, lib, ver + t, "site-packages") for lib in ("lib", "lib64") for t in ("", "t")]
    sites = own + [os.path.join(venv, "Lib", "site-packages")] + (base if system else [])
print(json.dumps({"v": platform.python_version(), "exe": sys.executable, "sites": sites,
    "managed": os.path.exists(os.path.join(sysconfig.get_path("stdlib"), "EXTERNALLY-MANAGED"))}))"#;

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
/// packages; and, per Python, the installed distributions whose metadata
/// couldn't be read, for the scan to report unchecked (incomplete metadata
/// must never read as fewer packages).
pub fn pythons() -> (Vec<Component>, Vec<(String, Vec<String>)>) {
    pythons_from(find_pythons(), &|shown| sh(&[shown, "-I", "-S", "-c", PY_INFO], 15))
}

/// Every Python on PATH or installed by a version manager, as (shown path,
/// real path), without the ones the OS or a package manager vouches for.
fn find_pythons() -> Vec<(String, String)> {
    let mut dirs: Vec<String> = std::env::var("PATH").unwrap_or_default().split(':').map(str::to_string).collect();
    dirs.extend(expand(PYTHON_DIRS));
    let minor = Regex::new(r"python3\.\d+");
    let mut names: Vec<String> = dirs
        .iter()
        .flat_map(|d| files::glob(&format!("{d}/python3.*")))
        .filter_map(|p| Path::new(&p).file_name().map(|n| n.to_string_lossy().into_owned()))
        .filter(|n| minor.fullmatch(n).is_some())
        .collect();
    names.sort();
    names.dedup();
    names.insert(0, "python3".into());
    names.iter().flat_map(|n| on_path(n, PYTHON_DIRS)).filter(|(_, real)| owner(real).is_empty()).collect()
}

/// `pythons` for the interpreters `found`, each asked `PY_INFO` by `probe`.
fn pythons_from(
    found: Vec<(String, String)>,
    probe: &(dyn Fn(&str) -> String + Sync),
) -> (Vec<Component>, Vec<(String, Vec<String>)>) {
    let probed = parallel::par_map(&found, parallel::PROBES, |(shown, _)| probe(shown));
    let mut out = Vec::new();
    let mut unread = Vec::new();
    let mut seen = Vec::new();
    for ((shown, real), raw) in found.into_iter().zip(probed) {
        let last = raw.trim().lines().last().unwrap_or("");
        let Some(info) = json_in(last, '{', '}') else { continue };
        let exe = files::realpath(&str_of(&info, "exe"));
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
        let sites: Vec<String> = crate::utils::json::strs_at(&info, "sites");
        let (pkgs, gaps) = pip(&shown, &sites, info.get("managed") == Some(&Value::Bool(true)), (fix, auto));
        out.extend(pkgs);
        if !gaps.is_empty() {
            unread.push((shown, gaps));
        }
    }
    (out, unread)
}

/// The distributions installed in `sites` (what `pip list` shows), read
/// from their metadata: `*.dist-info/METADATA`, `*.egg-info/PKG-INFO` or a
/// bare `*.egg-info` file. The first of a name on the path wins, as on
/// import. Nothing is run. With them, the distributions that couldn't be
/// read: metadata that is missing, unreadable or names no version is a
/// gap in the inventory, never a package that isn't there.
pub fn installed(sites: &[String]) -> (Vec<(String, String)>, Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut gaps = Vec::new();
    let mut dirs: Vec<&String> = Vec::new();
    for d in sites {
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    for dir in dirs {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        let mut entries: Vec<std::path::PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        entries.sort();
        for e in entries {
            let name = e.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let meta = if name.ends_with(".dist-info") {
                e.join("METADATA")
            } else if name.ends_with(".egg-info") && e.is_dir() {
                e.join("PKG-INFO")
            } else if name.ends_with(".egg-info") {
                e.clone()
            } else {
                continue;
            };
            let text = match files::read_capped(&meta, 1 << 20) {
                Ok(text) => text,
                Err(e) => {
                    gaps.push(format!("{}: {e}", meta.display()));
                    continue;
                }
            };
            let (mut n, mut v) = (String::new(), String::new());
            for line in text.lines() {
                if line.trim().is_empty() {
                    break; // the headers end at the first blank line
                }
                if let Some(x) = line.strip_prefix("Name:") {
                    n = x.trim().to_string();
                } else if let Some(x) = line.strip_prefix("Version:") {
                    v = x.trim().to_string();
                }
            }
            if n.is_empty() || v.is_empty() {
                let field = if v.is_empty() { "Version" } else { "Name" };
                gaps.push(format!("{}: no {field} in its metadata", meta.display()));
            } else if seen.insert(crate::checks::ecosystems::pypi::normalize(&n)) {
                out.push((n, v));
            }
        }
    }
    (out, gaps)
}

/// pip and the packages installed for one Python, and what couldn't be read.
fn pip(py: &str, sites: &[String], managed: bool, runtime_fix: (String, bool)) -> (Vec<Component>, Vec<String>) {
    let real = files::realpath(py);
    let mut out = Vec::new();
    let (found, gaps) = installed(sites);
    for (name, ver) in found {
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
    (out, gaps)
}

/// npm itself and the global npm packages of each Node in `found`.
pub fn node_packages(found: &[Component]) -> Vec<Component> {
    let nodes: Vec<&Component> = found.iter().filter(|c| c.name == "node").collect();
    parallel::par_map(&nodes, parallel::PROBES, |node| npm_globals(node)).concat()
}

/// npm and the global packages of one node install.
fn npm_globals(node: &Component) -> Vec<Component> {
    let mut out = Vec::new();
    let version = Regex::new(r"(\d+\.\d+\.\d+)$");
    let real = files::realpath(&node.path);
    let npm = Path::new(&real).with_file_name("npm").display().to_string();
    if !Path::new(&npm).exists() {
        return out;
    }
    // The global packages are the folders under `npm root -g` (it honours
    // npm's prefix config), read directly: `npm ls -g` takes most of a
    // second to say the same. npm ls is the fallback.
    let root = sh(&[&npm, "root", "-g"], 15).trim().lines().last().unwrap_or("").to_string();
    let globals = if root.starts_with('/') { global_packages(Path::new(&root)) } else { None };
    let globals = globals.unwrap_or_else(|| {
        let deps = json_in(&sh(&[&npm, "ls", "-g", "--json", "--depth=0"], 60), '{', '}').unwrap_or(Value::Null);
        let mut v: Vec<(String, String)> = deps
            .get("dependencies")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(name, d)| (name.clone(), str_of(d, "version"))).collect())
            .unwrap_or_default();
        // npm doesn't always list itself.
        if !v.iter().any(|(n, _)| n == "npm") {
            let said = sh(&[&npm, "--version"], 15);
            if let Some(m) = said.trim().lines().last().and_then(|l| version.match_start(l)) {
                v.push(("npm".into(), m.get(1).into()));
            }
        }
        v
    });
    for (name, ver) in globals {
        if ver.is_empty() {
            continue;
        }
        let mut c = match name.as_str() {
            "npm" => Component::new("pkgmgr", "npm", &ver, &npm),
            "corepack" => Component::new("pkgmgr", "corepack", &ver, &npm),
            _ => Component::new("package", &format!("npm:{name}"), &ver, &npm),
        };
        c.osv = Some(("npm".into(), name.clone(), ver));
        c.fix = format!("{npm} install -g {name}@{{safe}}");
        c.auto = true;
        out.push(c);
    }
    out
}

/// (name, version) of each package installed under a global node_modules
/// (`@scope/name` included), sorted, npm first; None when it can't be read.
fn global_packages(root: &Path) -> Option<Vec<(String, String)>> {
    let mut names = Vec::new();
    for e in std::fs::read_dir(root).ok()?.filter_map(|e| e.ok()) {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if name.starts_with('@') {
            for s in std::fs::read_dir(e.path()).ok()?.filter_map(|e| e.ok()) {
                names.push(format!("{name}/{}", s.file_name().to_string_lossy()));
            }
        } else {
            names.push(name);
        }
    }
    let mut out: Vec<(String, String)> = names
        .into_iter()
        .filter_map(|n| {
            let pkg = read_json(&root.join(&n).join("package.json"))?;
            Some((n, str_of(&pkg, "version")))
        })
        .collect();
    out.sort_by(|a, b| (a.0 != "npm", &a.0).cmp(&(b.0 != "npm", &b.0)));
    Some(out)
}

pub fn cargo_installs() -> Vec<Component> {
    let home = std::env::var("CARGO_HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| format!("{}/.cargo", files::home().display()));
    cargo_installs_in(Path::new(&home))
}

/// The `cargo install`s recorded in a cargo home's `.crates2.json`.
fn cargo_installs_in(home: &Path) -> Vec<Component> {
    let f = home.join(".crates2.json");
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
    pipx_from(&exe, &sh(&[&exe, "list", "--json"], 60))
}

/// The packages in `pipx list --json`'s output `listing`.
fn pipx_from(exe: &str, listing: &str) -> Vec<Component> {
    let data = json_in(listing, '{', '}').unwrap_or(Value::Null);
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
            let mut c = Component::new("package", &format!("pipx:{name}"), &ver, exe);
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
        let gem = Path::new(&files::realpath(&ruby.path)).with_file_name("gem").display().to_string();
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
#[path = "packages_tests.rs"]
mod tests;
