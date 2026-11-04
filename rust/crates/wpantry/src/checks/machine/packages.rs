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
            } else if seen.insert(crate::checks::supply_chain::malicious::norm("PyPI", &n)) {
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
mod tests {
    use super::*;
    use crate::utils::temp;

    #[test]
    fn global_packages_reads_npm_root() {
        let d = crate::utils::temp::TempDir::new("npmroot").unwrap();
        let pkg = |dir: &str, json: &str| {
            std::fs::create_dir_all(d.path().join(dir)).unwrap();
            std::fs::write(d.path().join(dir).join("package.json"), json).unwrap();
        };
        pkg("typescript", r#"{"name": "typescript", "version": "5.9.3"}"#);
        pkg("npm", r#"{"name": "npm", "version": "11.20.0"}"#);
        pkg("@openai/codex", r#"{"name": "@openai/codex", "version": "0.70.0"}"#);
        std::fs::create_dir_all(d.path().join(".bin")).unwrap();
        std::fs::create_dir_all(d.path().join("half-installed")).unwrap();
        // `npm link` leaves a symlink to the package's own folder.
        let linked = crate::utils::temp::TempDir::new("linked").unwrap();
        std::fs::write(linked.path().join("package.json"), r#"{"name": "mine", "version": "1.0.0"}"#).unwrap();
        std::os::unix::fs::symlink(linked.path(), d.path().join("mine")).unwrap();
        let got = global_packages(d.path()).unwrap();
        let want = [("npm", "11.20.0"), ("@openai/codex", "0.70.0"), ("mine", "1.0.0"), ("typescript", "5.9.3")];
        assert_eq!(got, want.map(|(n, v)| (n.to_string(), v.to_string())));
        assert_eq!(global_packages(&d.path().join("nowhere")), None);
    }

    #[test]
    fn json_inside_noisy_output() {
        assert_eq!(json_in("WARNING: x\n[{\"name\": \"pip\"}]\nnotice", '[', ']').unwrap()[0]["name"], "pip");
        assert_eq!(json_in("nothing", '{', '}'), None);
        assert_eq!(json_in("} {", '{', '}'), None);
    }

    #[test]
    fn installed_distributions_from_metadata() {
        let d = temp::TempDir::new("sites").unwrap();
        let (venv, user) = (d.path().join("venv"), d.path().join("user"));
        let put = |p: std::path::PathBuf, text: &str| {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        put(
            venv.join("pip-26.2.2.dist-info/METADATA"),
            "Metadata-Version: 2.1\nName: pip\nVersion: 26.2.2\n\nVersion: 0 (body)\n",
        );
        put(venv.join("Jinja2-3.1.4.dist-info/METADATA"), "Name: Jinja2\nVersion: 3.1.4\n");
        put(venv.join("old.egg-info/PKG-INFO"), "Name: old\nVersion: 0.1\n");
        put(venv.join("legacy-1.0-py3.9.egg-info"), "Name: legacy\nVersion: 1.0\n");
        put(venv.join("broken.dist-info/METADATA"), "Name: broken\n");
        std::fs::create_dir_all(venv.join("half-1.0.dist-info")).unwrap();
        put(venv.join("review_hook.pth"), "import os; os.system('never run')\n");
        put(user.join("jinja2-2.0.dist-info/METADATA"), "Name: jinja2\nVersion: 2.0\n");
        let sites = [venv.display().to_string(), user.display().to_string(), "/nonexistent".into()];
        let (got, gaps) = installed(&sites);
        assert_eq!(
            got,
            [
                ("Jinja2".to_string(), "3.1.4".to_string()),
                ("legacy".into(), "1.0".into()),
                ("old".into(), "0.1".into()),
                ("pip".into(), "26.2.2".into())
            ],
            "the first of a name on the path wins; nothing without a version"
        );
        assert_eq!(gaps.len(), 2, "metadata without a version, and a dist-info without metadata: {gaps:?}");
        assert!(gaps[0].contains("broken.dist-info/METADATA: no Version"), "{gaps:?}");
        assert!(gaps[1].contains("half-1.0.dist-info/METADATA"), "{gaps:?}");
    }

    /// The probe lists the base interpreter's site-packages for a venv made
    /// with `--system-site-packages`, and not otherwise, on every Python
    /// here (from 3.14 a venv is `sys.prefix` even under `-S`).
    #[test]
    fn the_probe_lists_the_sites_a_venv_inherits() {
        let d = temp::TempDir::new("venvs").unwrap();
        let mut pythons: Vec<String> = which("python3").into_iter().map(|p| p.display().to_string()).collect();
        pythons.extend(
            ["python3.12", "python3.13", "python3.14", "python3.15"]
                .iter()
                .filter_map(|n| which(n))
                .map(|p| p.display().to_string()),
        );
        let sites_of = |py: &str| -> Vec<String> {
            let raw = sh(&[py, "-I", "-S", "-c", PY_INFO], 30);
            let info = json_in(raw.trim().lines().last().unwrap_or(""), '{', '}').unwrap_or(Value::Null);
            crate::utils::json::strs_at(&info, "sites")
        };
        for (i, py) in pythons.iter().enumerate() {
            // The user site first, then the interpreter's own.
            let base: Vec<String> = sites_of(py).into_iter().skip(1).collect();
            if base.is_empty() {
                continue;
            }
            for (flag, inherits) in [("--system-site-packages", true), ("--without-pip", false)] {
                let venv = d.path().join(format!("{i}{flag}"));
                let made = sh(&[py, "-m", "venv", "--without-pip", flag, &venv.display().to_string()], 60);
                let vpy = venv.join("bin/python3");
                if !vpy.exists() {
                    panic!("{py} -m venv {flag}: {made}");
                }
                let sites = sites_of(&vpy.display().to_string());
                let own = format!("{i}{flag}/lib/python"); // the probe may resolve the temp dir's symlink
                assert!(sites.iter().any(|s| s.contains(&own)), "{py} {flag}: no venv site in {sites:?}");
                let has_base = base.iter().any(|b| sites.contains(b));
                assert_eq!(has_base, inherits, "{py} {flag}: base {base:?}, venv sites {sites:?}");
            }
        }
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

    #[test]
    fn json_strings_of_a_value() {
        let v = serde_json::json!({"s": "x", "n": null, "i": 3});
        assert_eq!(str_of(&v, "s"), "x");
        assert_eq!(str_of(&v, "n"), "");
        assert_eq!(str_of(&v, "missing"), "");
        assert_eq!(str_of(&v, "i"), "3");
    }

    /// An executable script at `dir/name` answering by its first arguments.
    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        files::realpath(&p.display().to_string()) // the probes resolve symlinks (/var on macOS)
    }

    /// The probe's JSON for each interpreter becomes a runtime and its
    /// packages; interpreters that resolve to the same file are one; a
    /// probe that fails is skipped; what couldn't be read is reported.
    #[test]
    fn pythons_from_probe_answers() {
        let home = files::test_home();
        let d = temp::TempDir::new("pyprobe").unwrap();
        let site = d.path().join("site-packages");
        std::fs::create_dir_all(site.join("requests-2.32.0.dist-info")).unwrap();
        std::fs::write(site.join("requests-2.32.0.dist-info/METADATA"), "Name: requests\nVersion: 2.32.0\n").unwrap();
        std::fs::create_dir_all(site.join("pip-25.0.dist-info")).unwrap();
        std::fs::write(site.join("pip-25.0.dist-info/METADATA"), "Name: pip\nVersion: 25.0\n").unwrap();
        std::fs::create_dir_all(site.join("half-1.dist-info")).unwrap();
        let (plain, managed, uv) = ("/x/bin/python3", "/usr/bin/python3.13", "/x/uv/python/cpython-3.13/bin/python3");
        let info = |exe: &str, managed: bool| {
            format!(
                "warning\n{{\"v\": \"3.13.2\", \"exe\": \"{exe}\", \"sites\": [\"{}\"], \"managed\": {managed}}}",
                site.display()
            )
        };
        let probe = move |shown: &str| match shown {
            "/x/bin/python3" => info("/x/bin/python3.13", false),
            "/x/bin/python3.13" => info("/x/bin/python3.13", false),
            "/usr/bin/python3.13" => info("/usr/bin/python3.13", true),
            "/x/uv/python/cpython-3.13/bin/python3" => info("/x/uv/python/cpython-3.13/bin/python3", true),
            _ => "Traceback: boom\n".to_string(),
        };
        let found: Vec<(String, String)> = [plain, "/x/bin/python3.13", managed, uv, "/nowhere/python3"]
            .iter()
            .map(|p| (p.to_string(), p.to_string()))
            .collect();
        let (got, unread) = pythons_from(found, &probe);
        let runtimes: Vec<&str> = got.iter().filter(|c| c.kind == "runtime").map(|c| c.path.as_str()).collect();
        assert_eq!(runtimes, [plain, managed, uv], "the second path to the same interpreter is skipped");
        let rt = &got[0];
        assert_eq!((rt.name.as_str(), rt.version.as_str()), ("python", "3.13.2"));
        assert_eq!(rt.osv, Some(("GIT".into(), github("python/cpython"), "v3.13.2".into())));
        assert_eq!(rt.eol, Some(("python".into(), "3.13".into())));
        let pkgs = |py: &str| -> Vec<(String, String, String, bool)> {
            got.iter()
                .filter(|c| c.path == py && c.kind != "runtime")
                .map(|c| (c.kind.clone(), c.name.clone(), c.fix.clone(), c.auto))
                .collect()
        };
        assert_eq!(
            pkgs(plain),
            [
                (
                    "pkgmgr".to_string(),
                    "pip".to_string(),
                    format!("{plain} -m pip install --upgrade 'pip>={{safe}}'"),
                    true
                ),
                (
                    "package".into(),
                    "pip:requests".into(),
                    format!("{plain} -m pip install --upgrade 'requests>={{safe}}'"),
                    true
                ),
            ]
        );
        assert_eq!(
            pkgs(managed)[1],
            (
                "package".into(),
                "pip:requests".into(),
                format!("Upgrade requests through the package manager that owns {managed}"),
                false
            )
        );
        let (uv_fix, uv_auto) = updater(uv, "python");
        assert_eq!(pkgs(uv)[0], ("pkgmgr".into(), "pip".into(), uv_fix, uv_auto), "uv's pip comes with its Python");
        assert_eq!(unread.len(), 3, "{unread:?}");
        assert!(
            unread.iter().all(|(py, gaps)| gaps.len() == 1 && gaps[0].contains("half-1.dist-info") && !py.is_empty())
        );
        drop(home);
    }

    /// The real interpreters on this machine, probed for real: every
    /// runtime has a version, and nothing is listed twice.
    #[test]
    fn pythons_on_this_machine_are_consistent() {
        let (got, _) = pythons();
        let runtimes: Vec<&Component> = got.iter().filter(|c| c.kind == "runtime").collect();
        assert!(runtimes.iter().all(|c| c.name == "python" && !c.version.is_empty()));
        let mut paths: Vec<&str> = runtimes.iter().map(|c| c.path.as_str()).collect();
        paths.dedup();
        assert_eq!(paths.len(), runtimes.len());
    }

    #[cfg(unix)]
    #[test]
    fn npm_globals_from_the_root_or_npm_ls() {
        let bin = temp::TempDir::new("nodebin").unwrap();
        let root = temp::TempDir::new("npmroot2").unwrap();
        for (dir, json) in [
            ("npm", r#"{"name": "npm", "version": "11.1.0"}"#),
            ("corepack", r#"{"version": "0.30.0"}"#),
            ("left-pad", r#"{"version": "1.3.0"}"#),
            ("broken", r#"{"name": "broken"}"#),
        ] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
            std::fs::write(root.path().join(dir).join("package.json"), json).unwrap();
        }
        let node = script(bin.path(), "node", "echo v22.0.0\n");
        let n = Component::new("runtime", "node", "22.0.0", &node);
        assert!(npm_globals(&n).is_empty(), "no npm beside node");
        let npm =
            script(bin.path(), "npm", &format!("case \"$1\" in root) echo \"{}\";; esac\n", root.path().display()));
        let got = node_packages(&[n.clone(), Component::new("runtime", "ruby", "3", "/x")]);
        let names: Vec<(&str, &str, &str)> =
            got.iter().map(|c| (c.kind.as_str(), c.name.as_str(), c.version.as_str())).collect();
        assert_eq!(
            names,
            [("pkgmgr", "npm", "11.1.0"), ("pkgmgr", "corepack", "0.30.0"), ("package", "npm:left-pad", "1.3.0")]
        );
        assert_eq!(got[2].osv, Some(("npm".into(), "left-pad".into(), "1.3.0".into())));
        assert_eq!(got[2].fix, format!("{npm} install -g left-pad@{{safe}}"));
        assert!(got[2].auto && got[2].path == npm);
        // No usable root: `npm ls -g --json`, with npm's own version asked separately.
        let ls = r#"{"dependencies": {"typescript": {"version": "5.9.3"}, "odd": {}}}"#;
        script(
            bin.path(),
            "npm",
            &format!(
                "case \"$1\" in root) echo 'npm warn nothing';; ls) echo '{ls}';; --version) echo 11.2.0;; esac\n"
            ),
        );
        let got = npm_globals(&n);
        let names: Vec<(&str, &str)> = got.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
        assert_eq!(names, [("npm:typescript", "5.9.3"), ("npm", "11.2.0")]);
        script(
            bin.path(),
            "npm",
            "case \"$1\" in ls) echo '{\"dependencies\": {\"npm\": {\"version\": \"11.3.0\"}}}';; esac\n",
        );
        let got = npm_globals(&n);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].kind.as_str(), got[0].version.as_str()), ("pkgmgr", "11.3.0"));
    }

    #[test]
    fn cargo_installs_from_crates2_json() {
        let home = files::test_home();
        let cargo = files::home().join(".cargo");
        assert!(cargo_installs_in(&cargo).is_empty(), "no .crates2.json yet");
        std::fs::create_dir_all(&cargo).unwrap();
        std::fs::write(
            cargo.join(".crates2.json"),
            r#"{"installs": {
                "ripgrep 14.1.1 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["rg"]},
                "mine 0.1.0 (path+file:///x/mine)": {"bins": ["mine"]},
                "tool 2.0.0 (git+https://github.com/x/tool#abc)": {"bins": ["tool"]}
            }}"#,
        )
        .unwrap();
        let got = cargo_installs_in(&cargo);
        assert_eq!(got.len(), 1, "only registry installs have a version to check: {got:?}");
        let c = &got[0];
        assert_eq!((c.kind.as_str(), c.name.as_str(), c.version.as_str()), ("package", "cargo:ripgrep", "14.1.1"));
        assert_eq!(c.osv, Some(("crates.io".into(), "ripgrep".into(), "14.1.1".into())));
        assert_eq!(c.fix, "cargo install --locked ripgrep@{safe}");
        assert!(c.auto && c.path == cargo.join(".crates2.json").display().to_string());
        std::fs::write(cargo.join(".crates2.json"), "{}").unwrap();
        assert!(cargo_installs_in(&cargo).is_empty());
        // The real cargo home: $CARGO_HOME when set, else ~/.cargo (the temp home here).
        let real = cargo_installs();
        if std::env::var("CARGO_HOME").is_ok_and(|h| !h.is_empty()) {
            assert!(real.iter().all(|c| c.name.starts_with("cargo:")));
        } else {
            assert!(real.is_empty());
        }
        drop(home);
    }

    #[test]
    fn pipx_venvs_from_the_listing() {
        let listing = r#"{"pipx_spec_version": "0.1", "venvs": {
            "black": {"metadata": {"main_package": {"package": "black", "package_version": "24.1.0"}}},
            "hatch": {"metadata": {"main_package": {"package_version": "1.9.0"}}},
            "odd": {"metadata": {"main_package": {"package": "odd"}}},
            "none": {}
        }}"#;
        let got = pipx_from("/opt/pipx", listing);
        let names: Vec<(&str, &str)> = got.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
        assert_eq!(names, [("pipx:black", "24.1.0"), ("pipx:hatch", "1.9.0")]);
        assert_eq!(got[0].osv, Some(("PyPI".into(), "black".into(), "24.1.0".into())));
        assert_eq!(
            got[1].osv,
            Some(("PyPI".into(), "hatch".into(), "1.9.0".into())),
            "the venv's name when the package isn't given"
        );
        assert_eq!(got[0].fix, "/opt/pipx upgrade black");
        assert!(got[0].auto && got[0].path == "/opt/pipx");
        assert!(pipx_from("/opt/pipx", "not json").is_empty());
        // Whatever this machine has (nothing in CI).
        assert!(pipx_packages().iter().all(|c| c.name.starts_with("pipx:")));
    }

    #[cfg(unix)]
    #[test]
    fn gems_of_each_ruby() {
        let bin = temp::TempDir::new("rubybin").unwrap();
        let ruby = script(bin.path(), "ruby", "echo ruby 3.3.0\n");
        let r = Component::new("runtime", "ruby", "3.3.0", &ruby);
        let not_ruby = Component::new("runtime", "node", "22", &ruby);
        assert!(gems(&[r.clone(), not_ruby.clone()]).is_empty(), "no gem beside ruby");
        let gem = script(
            bin.path(),
            "gem",
            "echo '*** LOCAL GEMS ***'\necho\necho 'json (default: 2.7.2, 2.6.1)'\necho 'rake (13.2.1)'\necho 'bundler (2.5.6)'\necho\n",
        );
        let got = gems(&[r, not_ruby]);
        let names: Vec<(&str, &str)> = got.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
        assert_eq!(names, [("gem:json", "2.7.2"), ("gem:rake", "13.2.1"), ("gem:bundler", "2.5.6")]);
        assert_eq!(got[1].osv, Some(("RubyGems".into(), "rake".into(), "13.2.1".into())));
        assert_eq!(got[1].fix, format!("{gem} update rake"));
        assert!(got[1].auto && got[1].path == gem);
    }
}
