//! `scan project`: the runtimes one project runs on, and only those.
//!
//! A machine scan checks every runtime installed, active or not. A project
//! scan reads what the project says it uses ([`pins`]): the version its pin
//! files name (`mise.toml`, `.tool-versions`, `.ruby-version`, `.nvmrc`,
//! `rust-toolchain.toml`, `go.mod`, …), or, with no pin, the fact that it
//! uses the runtime at all (a `Gemfile`, a `package.json`). [`choose`] turns
//! each into the one install to check ([`all`] gathers them for the root and
//! the packages below it): the installed copy the pin names,
//! the pinned version itself when it isn't installed here, or the first
//! copy on PATH when nothing is pinned.

use crate::checks::Scan;
use crate::checks::machine::catalog::{Cycle, PYTHON_DIRS, TOOLS, Tool};
use crate::checks::machine::{components, software_cves, tools};
use crate::component::Component;
use crate::error::Result;
use crate::utils::files::{read_capped, read_json, short};
use crate::utils::re::Regex;
use crate::utils::toml;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The largest pin file or manifest read.
const MAX: u64 = 1 << 20;

/// Python as a catalog tool. The machine scan lists Pythons with their pip
/// packages ([`crate::checks::machine::packages`]); a project scan wants
/// only the interpreter.
const PYTHON: Tool = Tool {
    name: "python",
    kind: "runtime",
    bins: &["python3", "python"],
    args: &["--version"],
    pattern: r#"Python (\d+\.\d+\.\d+)"#,
    osv: Some(("GIT", "https://github.com/python/cpython.git", "v{v}")),
    eol: Some(("python", Cycle::Minor)),
    always: false,
    paths: PYTHON_DIRS,
    fix: "",
};

/// A runtime a project can use: the catalog tool, the files that pin its
/// version, and the manifests that say the project uses it.
struct Runtime {
    tool: &'static str,
    pins: &'static [&'static str],
    manifests: &'static [&'static str],
}

const RUNTIMES: &[Runtime] = &[
    Runtime { tool: "ruby", pins: &[".ruby-version"], manifests: &["Gemfile", "Gemfile.lock"] },
    Runtime { tool: "node", pins: &[".node-version", ".nvmrc"], manifests: &["package.json"] },
    Runtime {
        tool: "python",
        pins: &[".python-version"],
        manifests: &["pyproject.toml", "requirements.txt", "setup.py", "Pipfile", "uv.lock", "poetry.lock"],
    },
    Runtime { tool: "go", pins: &[".go-version"], manifests: &["go.mod"] },
    Runtime { tool: "rust", pins: &["rust-toolchain.toml", "rust-toolchain"], manifests: &["Cargo.toml"] },
    Runtime { tool: "java", pins: &[".java-version"], manifests: &["pom.xml", "build.gradle", "build.gradle.kts"] },
    Runtime { tool: "php", pins: &[".php-version"], manifests: &["composer.json"] },
    Runtime { tool: "deno", pins: &[], manifests: &["deno.json", "deno.jsonc"] },
    Runtime { tool: "bun", pins: &[".bun-version"], manifests: &["bun.lock", "bun.lockb"] },
    Runtime { tool: "swift", pins: &[".swift-version"], manifests: &["Package.swift"] },
];

/// What mise and asdf call a runtime, when it isn't the catalog's name.
const ALIASES: &[(&str, &str)] = &[("nodejs", "node"), ("golang", "go")];

/// What may stand before the digits of a pinned version: `v20.11.0`,
/// `go1.22.3`, `ruby-3.3.5`, `temurin-21.0.2`. Anything else (`lts/iron`,
/// `stable`, `nightly-2026-01-01`, `system`) names no version.
const PREFIXES: &[&str] = &[
    "",
    "v",
    "go",
    "ruby-",
    "node-",
    "python-",
    "cpython-",
    "php-",
    "swift-",
    "temurin-",
    "openjdk-",
    "corretto-",
    "zulu-",
    "liberica-",
];

/// One runtime a project uses.
#[derive(Clone, Debug, PartialEq)]
pub struct Pin {
    /// The catalog tool's name.
    pub tool: &'static str,
    /// The version pinned, as far as the file gives it ("3.3.5", "22"); ""
    /// when the project uses the runtime without pinning it.
    pub version: String,
    /// The file that says so.
    pub file: PathBuf,
}

/// The version a pin file's text names, or "".
///
/// ```ignore
/// assert_eq!(version("v20.11.0\n"), "20.11.0");
/// assert_eq!(version("ruby-3.3.5"), "3.3.5");
/// assert_eq!(version("lts/iron"), "");
/// ```
pub fn version(raw: &str) -> String {
    let word = raw.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or("");
    let word = word.split_whitespace().next().unwrap_or("");
    let Some(m) = Regex::new(r"^([A-Za-z-]*)(\d+(?:\.\d+){0,2})").search(word) else { return String::new() };
    if PREFIXES.contains(&m.get(1)) { m.get(2).to_string() } else { String::new() }
}

fn catalog_name(name: &str) -> Option<&'static str> {
    let name = ALIASES.iter().find(|(a, _)| *a == name).map(|(_, n)| *n).unwrap_or(name);
    RUNTIMES.iter().map(|r| r.tool).find(|t| *t == name)
}

fn text(path: &Path) -> Option<String> {
    read_capped(path, MAX).ok()
}

/// `[tools]` of a mise file: `ruby = "3.3"`, `node = ["22", "20"]` (the
/// first is the one in use), `python = { version = "3.12" }`. Only that
/// table's lines are read: the tasks beside it hold multi-line strings
/// that aren't ours to parse.
fn mise(path: &Path) -> Vec<(&'static str, String)> {
    let Some(text) = text(path) else { return Vec::new() };
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line.split('#').next().unwrap_or("").trim() == "[tools]";
            continue;
        }
        let Some((key, val)) = line.split_once('=').filter(|_| inside && !line.starts_with('#')) else { continue };
        let Some(tool) = catalog_name(key.trim().trim_matches(['"', '\''])) else { continue };
        let val = val.trim();
        let raw = if val.starts_with('{') {
            toml::inline(val)
                .into_iter()
                .find(|(k, _)| k == "version")
                .and_then(|(_, v)| v.as_str().map(str::to_string))
                .unwrap_or_default()
        } else if val.starts_with('[') {
            toml::strings(val).into_iter().next().unwrap_or_default()
        } else {
            toml::string(val).map(|(s, _)| s).unwrap_or_default()
        };
        out.push((tool, version(&raw)));
    }
    out
}

/// `.tool-versions`: `nodejs 20.11.0` a line.
fn tool_versions(path: &Path) -> Vec<(&'static str, String)> {
    let Some(text) = text(path) else { return Vec::new() };
    text.lines()
        .filter_map(|l| {
            let mut words = l.split('#').next().unwrap_or("").split_whitespace();
            let tool = catalog_name(words.next()?)?;
            Some((tool, version(words.next().unwrap_or(""))))
        })
        .collect()
}

/// A version the project's own manifests name outright: `go.mod`'s
/// `toolchain` (else its `go` line), `Gemfile.lock`'s `RUBY VERSION`,
/// `package.json`'s Volta pin, `rust-toolchain.toml`'s channel.
fn manifest_version(tool: &str, root: &Path) -> Option<(String, PathBuf)> {
    let found = |file: &str, v: String| (!v.is_empty()).then(|| (v, root.join(file)));
    match tool {
        "go" => {
            let t = text(&root.join("go.mod"))?;
            let line = |word: &str| {
                t.lines().find_map(|l| l.trim().strip_prefix(word).filter(|r| r.starts_with(' ')).map(version))
            };
            found("go.mod", line("toolchain").filter(|v| !v.is_empty()).or_else(|| line("go")).unwrap_or_default())
        }
        "ruby" => {
            let t = text(&root.join("Gemfile.lock"))?;
            let at = t.lines().position(|l| l.trim() == "RUBY VERSION")?;
            let v = t.lines().nth(at + 1).and_then(|l| l.trim().strip_prefix("ruby ")).map(version)?;
            found("Gemfile.lock", v)
        }
        "node" => {
            let j = read_json(&root.join("package.json"))?;
            found("package.json", version(j.get("volta")?.get("node")?.as_str()?))
        }
        _ => None,
    }
}

/// `rust-toolchain.toml`'s `channel`, or the bare `rust-toolchain` file.
fn rust_toolchain(path: &Path) -> String {
    let Some(t) = text(path) else { return String::new() };
    match toml::parse(&t) {
        Ok(tables) => tables
            .iter()
            .find(|tb| tb.name == "toolchain")
            .map(|tb| version(tb.str("channel")))
            .unwrap_or_else(|| version(&t)),
        Err(_) => version(&t),
    }
}

/// The versions `dir`'s pin files name, the strongest first: mise, then
/// asdf's `.tool-versions`, then each runtime's own file.
fn pinned(dir: &Path) -> Vec<Pin> {
    let mut out: Vec<Pin> = Vec::new();
    let mut add = |tool: &'static str, version: String, file: PathBuf| {
        if !version.is_empty() && !out.iter().any(|p| p.tool == tool) {
            out.push(Pin { tool, version, file });
        }
    };
    for name in ["mise.toml", ".mise.toml"] {
        for (tool, v) in mise(&dir.join(name)) {
            add(tool, v, dir.join(name));
        }
    }
    for (tool, v) in tool_versions(&dir.join(".tool-versions")) {
        add(tool, v, dir.join(".tool-versions"));
    }
    for r in RUNTIMES {
        for name in r.pins {
            let path = dir.join(name);
            let v = if r.tool == "rust" {
                rust_toolchain(&path)
            } else {
                text(&path).map(|t| version(&t)).unwrap_or_default()
            };
            add(r.tool, v, path);
        }
        if let Some((v, file)) = manifest_version(r.tool, dir) {
            add(r.tool, v, file);
        }
    }
    out
}

/// The runtimes the project at `root` uses: each one a pin file at `root`
/// names, and each one a manifest there implies. A runtime used but not
/// pinned at `root` takes the pin of the nearest folder above that has one,
/// as the version managers do.
pub fn pins(root: &Path) -> Vec<Pin> {
    let mut out = pinned(root);
    for r in RUNTIMES {
        if out.iter().any(|p| p.tool == r.tool) {
            continue;
        }
        let Some(manifest) = r.manifests.iter().map(|m| root.join(m)).find(|p| p.is_file()) else { continue };
        let above = root.ancestors().skip(1).find_map(|dir| pinned(dir).into_iter().find(|p| p.tool == r.tool));
        out.push(above.unwrap_or(Pin { tool: r.tool, version: String::new(), file: manifest }));
    }
    out
}

/// How far below a project's root its packages are looked for.
pub const DEPTH: usize = 4;

/// Every runtime the project at `root` uses: [`pins`] for the root and for
/// each folder below it (to [`DEPTH`]) that holds a pin file or a manifest,
/// so a monorepo's `rust/rust-toolchain.toml` and `web/.nvmrc` both count.
pub fn all(root: &Path) -> Vec<Pin> {
    let named = |name: &String| {
        ["mise.toml", ".mise.toml", ".tool-versions"].contains(&name.as_str())
            || RUNTIMES.iter().any(|r| r.pins.contains(&name.as_str()) || r.manifests.contains(&name.as_str()))
    };
    let mut out: Vec<Pin> = Vec::new();
    for (dir, names) in crate::utils::walk::walk(root, DEPTH) {
        if dir != root && !names.iter().any(named) {
            continue;
        }
        for pin in pins(&dir) {
            if !out.contains(&pin) {
                out.push(pin);
            }
        }
    }
    out
}

/// What a pin came to.
#[derive(Clone, Debug, PartialEq)]
pub enum Choice {
    /// The install to check.
    Check(Component),
    /// Pinned to part of a version (`22`, `3.12`) that no install here
    /// matches: which release it means can't be told, so no CVE is asked
    /// about. With enough of it to name the release line, that line (the
    /// component, at the pin file) is still checked for end of life.
    Missing(Option<Component>),
    /// Used, not pinned, and not installed: nothing to check.
    Nothing,
}

fn matches(installed: &str, pin: &str) -> bool {
    installed == pin || installed.strip_prefix(pin).is_some_and(|rest| rest.starts_with('.'))
}

/// The one install a pin means, from the tool's `installs` in PATH order.
///
/// - Pinned: the newest install the pin matches (`3.3` matches 3.3.5). When
///   none does and the pin is a full version, that version itself, located
///   at the pin file: the project runs on it wherever it is built. Part of
///   a version that no install matches is [`Choice::Missing`].
/// - Not pinned: the first install on PATH.
pub fn choose(pin: &Pin, tool: &Tool, installs: &[Component]) -> Choice {
    if pin.version.is_empty() {
        return installs.first().cloned().map_or(Choice::Nothing, Choice::Check);
    }
    let newest = installs
        .iter()
        .filter(|c| matches(&c.version, &pin.version))
        .max_by(|a, b| crate::checks::ecosystems::versions::cmp(&a.version, &b.version));
    if let Some(c) = newest {
        return Choice::Check(c.clone());
    }
    let file = pin.file.to_string_lossy();
    let mut c = Component::new(tool.kind, tool.name, &pin.version, &file);
    c.fix = format!("Pin {} to {{safe}} in {}", tool.name, short(&file));
    let parts = pin.version.matches('.').count() + 1;
    if parts < 3 {
        // A release line needs its minor, unless the product counts by major.
        let line = tool.eol.filter(|(_, cycle)| parts == 2 || *cycle != Cycle::Minor);
        return Choice::Missing(line.map(|(product, cycle)| {
            c.eol = Some((product.to_string(), cycle.of(&pin.version)));
            c
        }));
    }
    if let Some((eco, pkg, fmt)) = tool.osv {
        c.osv = Some((eco.to_string(), pkg.to_string(), tools::tag(fmt, &pin.version)));
        c.osv_also = c.osv.as_ref().map(crate::sources::osv::also).unwrap_or_default();
    }
    if let Some((product, cycle)) = tool.eol {
        c.eol = Some((product.to_string(), cycle.of(&pin.version)));
    }
    Choice::Check(c)
}

/// The catalog's entry for a runtime.
pub fn tool(name: &str) -> Option<&'static Tool> {
    if name == PYTHON.name { Some(&PYTHON) } else { TOOLS.iter().find(|t| t.name == name) }
}

/// The project's runtimes against OSV, end of life and the CVE records;
/// returns them, for the supply-chain sweep.
pub fn run(scan: &mut Scan) -> Result<Vec<Component>> {
    run_with(scan, &tools::find_any)
}

/// [`run`], with the machine's installs of a tool from `installs`.
pub(crate) fn run_with(scan: &mut Scan, installs: &dyn Fn(&Tool) -> Vec<Component>) -> Result<Vec<Component>> {
    scan.status("Reading the project's runtime pins");
    let roots: Vec<PathBuf> = scan.repos.iter().map(|(_, r)| r.clone()).collect();
    let mut found: HashMap<&'static str, Vec<Component>> = HashMap::new();
    let mut chosen: Vec<Component> = Vec::new();
    let mut said: Vec<String> = Vec::new();
    let mut lines: Vec<Component> = Vec::new();
    for pin in roots.iter().flat_map(|r| all(r)) {
        let Some(t) = tool(pin.tool) else { continue };
        if !found.contains_key(pin.tool) {
            scan.status(&format!("Finding the {} this project uses", pin.tool));
            found.insert(pin.tool, installs(t));
        }
        let from = short(&pin.file.to_string_lossy());
        match choose(&pin, t, &found[pin.tool]) {
            Choice::Check(c) => {
                if chosen.iter().any(|k| (&k.name, &k.version, &k.path) == (&c.name, &c.version, &c.path)) {
                    continue;
                }
                let how =
                    if pin.version.is_empty() { "first on PATH".to_string() } else { format!("pinned in {from}") };
                said.push(format!("{} {} ({how})", c.name, c.version));
                chosen.push(c);
            }
            Choice::Missing(line) => {
                scan.unchecked(
                    &format!("{} {} ({from})", pin.tool, pin.version),
                    "the project pins part of a version and no install here matches it, so no CVE is asked about: install it, or pin a full version",
                );
                lines.extend(line.filter(|c| !lines.contains(c)));
            }
            Choice::Nothing => {}
        }
    }
    scan.count("project runtimes", chosen.len() as i64);
    if !said.is_empty() {
        (scan.log)(&format!("  project runtimes: {}", said.join(", ")));
    }
    let osv = components::components(scan, &chosen)?;
    software_cves::tools(scan, &chosen, &osv)?;
    // A release line alone: past its end of life or not, never "outdated".
    for c in &lines {
        scan.eol(c, true)?;
    }
    Ok(chosen)
}

#[cfg(test)]
#[path = "project_tests.rs"]
mod tests;
