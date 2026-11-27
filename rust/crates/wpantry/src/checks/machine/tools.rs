//! Find the tools in [`catalog::TOOLS`] on this machine: every copy on PATH
//! and every runtime a version manager has installed, active or not.
//!
//! A binary is only ours to check when nothing else vouches for it (see
//! [`files::owner`]): Homebrew formulae go to `brew vulns`, npm and pipx
//! installs to their package listings, Apple's and the distro's files to the
//! OS update check, and binaries inside an app bundle to the app check.
//!
//! A tool in [`READ_BINARY`] is never run: its version is read from the
//! strings its binary holds.

use crate::checks::ecosystems::versions;
use crate::checks::machine::catalog::{READ_BINARY, TOOLS, Tool};
use crate::component::Component;
use crate::utils::files::home;
use crate::utils::files::owner;
use crate::utils::files::read_json;
use crate::utils::process::on_path;
use crate::utils::process::run;
use crate::utils::re::Regex;
use crate::utils::{files, net, parallel};
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

/// A release tag from a tag format and a version.
pub fn tag(fmt: &str, v: &str) -> String {
    let v3 = if v.matches('.').count() >= 2 { v.to_string() } else { format!("{v}.0") };
    let u = v.replace('.', "_");
    let ssh = u.replace('p', "_P");
    // Ruby 4 switched its upstream tags from underscores to dots.
    let ruby = if v.split('.').next().and_then(|major| major.parse::<u32>().ok()).is_some_and(|major| major >= 4) {
        v
    } else {
        &u
    };
    fmt.replace("{v3}", &v3).replace("{v}", v).replace("{u}", &u).replace("{ssh}", &ssh).replace("{ruby}", ruby)
}

/// (path marker, update command, safe to run unattended). "{safe}" is the
/// fix; a marker starting with "~/" is under $HOME.
const MANAGED_BY: &[(&str, &str, bool)] = &[
    ("/.nvm/", "nvm install {safe}", false), // nvm is a shell function
    ("/.volta/", "volta install {name}@{safe}", true),
    ("/fnm/", "fnm install {safe}", true),
    ("/.asdf/", "asdf install {name} {safe}", false),
    ("/mise/", "mise install {name}@{safe}", true),
    ("/.rustup/", "rustup update", true),
    ("~/.cargo/bin", "rustup update", true),
    ("/uv/python/", "uv python upgrade", true),
    ("~/.local/bin/python", "uv python upgrade", true),
    ("/.pyenv/", "pyenv install {safe}", false),
    ("/.rbenv/", "rbenv install {safe}", false),
    ("/.rvm/", "rvm install {safe}", false),
    ("conda", "conda update --name base {name}", false),
    ("/.sdkman/", "sdk install java {safe}", false),
];

/// (how to update, safe to run unattended) for a binary we check.
pub fn updater(path: &str, name: &str) -> (String, bool) {
    let home = home().display().to_string();
    for (marker, cmd, auto) in MANAGED_BY {
        let marker = match marker.strip_prefix("~/") {
            Some(rest) => format!("{home}/{rest}"),
            None => marker.to_string(),
        };
        if path.contains(&marker) {
            return (cmd.replace("{name}", name), *auto);
        }
    }
    (format!("Upgrade {name} at {path} to {{safe}}"), false)
}

/// A mise runtime's fix, leaving no vulnerable install behind: install the
/// fixed version, then `mise uninstall` the old one (a second line, which
/// the plan never runs unattended: a mise.toml or .tool-versions may still
/// pin it). When the fixed version is already installed beside it, the fix
/// is the uninstall alone, also for a person to run. Any other command is
/// returned as it was.
///
/// Example: python 3.14.9 under `~/.local/share/mise/installs/python/3.14.9`
/// fixed by 3.14.10 gives `mise install python@3.14.10` then
/// `mise uninstall python@3.14.9`. The same Python reached through
/// `installs/python/3.14` (a link to it) gives the same two lines.
pub fn with_uninstall(c: &Component, cmd: String, auto: bool) -> (String, bool) {
    let Some((name, fixed)) = cmd.strip_prefix("mise install ").and_then(|r| r.split_once('@')) else {
        return (cmd, auto);
    };
    let marker = format!("/installs/{name}/");
    // Where the install really is, not how PATH spells it: mise also keeps
    // `installs/node/lts`, `installs/ruby/3.4` and `installs/python/latest`
    // as links to an install, and `mise uninstall node@lts` removes whatever
    // the alias means when it runs, which after the install is the fixed
    // version. Forward slashes whatever the platform wrote the path with.
    let path = files::strip_verbatim(&files::realpath(&c.path)).replace('\\', "/");
    let Some(at) = path.find(&marker).filter(|_| path.contains("/mise/")) else { return (cmd, auto) };
    let dir = &path[..at + marker.len()];
    let old = path[at + marker.len()..].split('/').next().unwrap_or("");
    // Still a link after resolving (one that goes nowhere): no version to name.
    let alias = std::fs::symlink_metadata(format!("{dir}{old}")).is_ok_and(|m| m.file_type().is_symlink());
    if old.is_empty() || alias || old == fixed || fixed == "latest" || !versions::is_safe_token(old) {
        return (cmd, auto);
    }
    let uninstall = format!("mise uninstall {name}@{old}");
    if Path::new(&format!("{dir}{fixed}")).is_dir() {
        (uninstall, false)
    } else {
        (format!("{cmd}\n{uninstall}"), auto)
    }
}

/// The largest binary read for its embedded version.
pub const MAX_BINARY: u64 = 64 << 20;

/// The C strings in `path` that start with `prefix`, each up to its NUL
/// (one per line), without running it. Nothing when the file is over
/// [`MAX_BINARY`] or unreadable. Only a printable, NUL-terminated string
/// counts: a script or a text file that mentions the prefix has none.
///
/// Example: a binary holding `UnrealIRCd-6.2.7.1\0` gives
/// "UnrealIRCd-6.2.7.1".
pub fn embedded(path: &str, prefix: &str) -> String {
    let Ok(bytes) = files::read_capped_bytes(Path::new(path), MAX_BINARY) else { return String::new() };
    let p = prefix.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while let Some(at) = bytes[i..].windows(p.len()).position(|w| w == p) {
        let start = i + at;
        // A version string is short: a longer run is something else.
        let rest = &bytes[start..bytes.len().min(start + 64)];
        // Printable up to its NUL: a newline or other control byte first
        // means this is text that mentions the prefix, not a C string.
        if let Some(end) = rest.iter().position(|b| !(0x20..0x7f).contains(b))
            && rest[end] == 0
        {
            out.push(String::from_utf8_lossy(&rest[..end]).into_owned());
        }
        i = start + p.len();
    }
    out.join("\n")
}

/// Components for one catalog tool.
pub fn find(t: &Tool, extra_dirs: &[String]) -> Vec<Component> {
    find_owned(t, extra_dirs, false)
}

/// Every copy of one catalog tool, whoever installed it: PATH first, then
/// the version managers' folders. A project scan asks this: it runs no
/// `brew vulns` or OS update check to leave the vouched-for copies to.
pub fn find_any(t: &Tool) -> Vec<Component> {
    find_owned(t, &[], true)
}

/// [`find`]; with `any`, the copies something else vouches for as well.
fn find_owned(t: &Tool, extra_dirs: &[String], any: bool) -> Vec<Component> {
    let mut dirs: Vec<String> = t.paths.iter().map(|p| p.to_string()).collect();
    dirs.extend(extra_dirs.iter().cloned());
    let mut out = Vec::new();
    for b in t.bins {
        for (shown, real) in on_path(b, &dirs) {
            out.extend(component_at(t, &shown, &real, any));
        }
    }
    out
}

/// The component for the copy of catalog tool `t` that PATH or a version
/// manager's folder shows as `shown` and that resolves to `real`: who owns
/// it, how its version is read, how it is updated, how OSV and endoflife.date
/// know it. None when something else vouches for the copy (unless `any`, or
/// the tool is `always` checked), or when its version can't be read. The one
/// place a copy's version is read: a scan reads every copy through it, and
/// `wpantry recheck` reads one.
pub fn component_at(t: &Tool, shown: &str, real: &str, any: bool) -> Option<Component> {
    let re = Regex::with_flags(t.pattern, "m");
    let who = owner(real);
    if !any && !who.is_empty() && !(t.always && (who == "brew" || who == "app")) {
        return None;
    }
    let said = match READ_BINARY.iter().find(|(n, _)| *n == t.name) {
        Some((_, prefix)) => embedded(real, prefix),
        None => {
            let mut argv: Vec<&OsStr> = vec![OsStr::new(shown)];
            argv.extend(t.args.iter().map(OsStr::new));
            run(&argv, Duration::from_secs(15))
        }
    };
    let m = re.search(&said)?;
    let v = m.get(1).to_string();
    let (mut fix, mut auto) = updater(real, t.name);
    if who == "brew" {
        let formula = real.split("/Cellar/").nth(1).and_then(|r| r.split('/').next()).unwrap_or(t.name);
        (fix, auto) = (format!("brew upgrade {formula}"), true);
    } else if who == "app" {
        let app = Regex::new(r"([^/]+)[.]app/").search(real).map(|c| c.get(1).to_string()).unwrap_or_default();
        (fix, auto) = (format!("Update {app}"), false);
    }
    if !t.fix.is_empty() {
        (fix, auto) = (t.fix.to_string(), false);
    }
    let mut c = Component::new(t.kind, t.name, &v, shown);
    c.fix = fix;
    c.auto = auto;
    if let Some((eco, pkg, fmt)) = t.osv {
        c.osv = Some((eco.to_string(), pkg.to_string(), tag(fmt, &v)));
        c.osv_also = c.osv.as_ref().map(crate::sources::osv::also).unwrap_or_default();
    }
    if let Some((product, cycle)) = t.eol {
        c.eol = Some((product.to_string(), cycle.of(&v)));
    }
    Some(c)
}

/// Every catalog tool found, plus nvm, one entry per install.
pub fn tools() -> Vec<Component> {
    let mut found: Vec<Component> = parallel::par_map(TOOLS, parallel::PROBES, |t| find(t, &[])).concat();
    found.extend(nvm());
    dedupe(found)
}

/// nvm is a shell function, not a binary: read its version from its repo.
pub fn nvm() -> Vec<Component> {
    let root =
        std::env::var("NVM_DIR").ok().filter(|d| !d.is_empty()).unwrap_or_else(|| format!("{}/.nvm", home().display()));
    nvm_at(&root)
}

/// The nvm installed at `root` (its repo), if any.
fn nvm_at(root: &str) -> Vec<Component> {
    let v = read_json(&Path::new(root).join("package.json"))
        .and_then(|p| p.get("version").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_default();
    if Regex::new(r"\d+\.\d+\.\d+").fullmatch(&v).is_none() {
        return Vec::new();
    }
    let mut c = Component::new("manager", "nvm", &v, root);
    c.osv = Some(("GIT".into(), net::github("nvm-sh/nvm"), format!("v{v}")));
    c.fix = "Upgrade nvm: https://github.com/nvm-sh/nvm#upgrading".into();
    vec![c]
}

/// One entry per install: `postgres` and `psql` from one directory, or one
/// binary reached through several PATH entries, count once.
pub fn dedupe(components: Vec<Component>) -> Vec<Component> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for c in components {
        let dir = if c.path.is_empty() {
            String::new()
        } else {
            Path::new(&files::realpath(&c.path)).parent().map(|p| p.display().to_string()).unwrap_or_default()
        };
        let k = (c.name.clone(), c.version.clone(), dir);
        if !seen.contains(&k) {
            seen.push(k);
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
#[path = "tools_tests.rs"]
mod tests;
