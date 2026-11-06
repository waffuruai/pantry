//! Find the tools in [`catalog::TOOLS`] on this machine: every copy on PATH
//! and every runtime a version manager has installed, active or not.
//!
//! A binary is only ours to check when nothing else vouches for it (see
//! [`files::owner`]): Homebrew formulae go to `brew vulns`, npm and pipx
//! installs to their package listings, Apple's and the distro's files to the
//! OS update check, and binaries inside an app bundle to the app check.

use crate::checks::machine::catalog::{TOOLS, Tool};
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
    fmt.replace("{v3}", &v3).replace("{v}", v).replace("{u}", &u).replace("{ssh}", &ssh)
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

/// Components for one catalog tool.
pub fn find(t: &Tool, extra_dirs: &[String]) -> Vec<Component> {
    let re = Regex::with_flags(t.pattern, "m");
    let mut dirs: Vec<String> = t.paths.iter().map(|p| p.to_string()).collect();
    dirs.extend(extra_dirs.iter().cloned());
    let mut out = Vec::new();
    for b in t.bins {
        for (shown, real) in on_path(b, &dirs) {
            let who = owner(&real);
            if !who.is_empty() && !(t.always && (who == "brew" || who == "app")) {
                continue;
            }
            let mut argv: Vec<&OsStr> = vec![OsStr::new(&shown)];
            argv.extend(t.args.iter().map(OsStr::new));
            let Some(m) = re.search(&run(&argv, Duration::from_secs(15))) else { continue };
            let v = m.get(1).to_string();
            let (mut fix, mut auto) = updater(&real, t.name);
            if who == "brew" {
                let formula = real.split("/Cellar/").nth(1).and_then(|r| r.split('/').next()).unwrap_or(t.name);
                (fix, auto) = (format!("brew upgrade {formula}"), true);
            } else if who == "app" {
                let app = Regex::new(r"([^/]+)[.]app/").search(&real).map(|c| c.get(1).to_string()).unwrap_or_default();
                (fix, auto) = (format!("Update {app}"), false);
            }
            if !t.fix.is_empty() {
                (fix, auto) = (t.fix.to_string(), false);
            }
            let mut c = Component::new(t.kind, t.name, &v, &shown);
            c.fix = fix;
            c.auto = auto;
            if let Some((eco, pkg, fmt)) = t.osv {
                c.osv = Some((eco.to_string(), pkg.to_string(), tag(fmt, &v)));
            }
            if let Some((product, cycle)) = t.eol {
                c.eol = Some((product.to_string(), cycle.of(&v)));
            }
            out.push(c);
        }
    }
    out
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
