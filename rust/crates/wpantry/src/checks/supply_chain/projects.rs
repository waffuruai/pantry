//! Each repo's locked dependencies against OSV, and how to move one to
//! its fixed version (a step in the repo, never run unattended).

use crate::checks::supply_chain::repos::Repo;
use crate::checks::supply_chain::typosquat::typosquats;
use crate::checks::supply_chain::{licenses, quote, repos};
use crate::checks::{Scan, as_source, lockfiles};
use crate::component::Component;
use crate::error::Result;
use crate::sources::osv;
use crate::sources::osv::Item;
use crate::utils::files::short;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// How to move one locked dependency to `safe` (a step in the repo, never
/// run unattended).
pub fn project_fix(lock: &Path, eco: &str, name: &str, safe: &str) -> String {
    let d = quote(&lock.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default());
    let file = lock.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match (eco, file) {
        ("crates.io", _) => format!("cd {d} && cargo update -p {name} --precise {safe}"),
        (_, "pnpm-lock.yaml") => format!("cd {d} && pnpm update {name}@{safe}"),
        ("npm", "yarn.lock") if yarn_berry(lock) => format!("cd {d} && yarn up {}", quote(&format!("{name}@{safe}"))),
        ("npm", "yarn.lock") => format!("cd {d} && yarn upgrade {}", quote(&format!("{name}@{safe}"))),
        ("npm", "bun.lock") => format!("cd {d} && bun update {}", quote(name)),
        ("npm", "deno.lock") => format!("Update npm:{name} to {safe} in {}", lock.display()),
        ("npm", _) => format!("cd {d} && npm install {name}@{safe}"),
        ("PyPI", "uv.lock") => format!("cd {d} && uv lock --upgrade-package {name}=={safe}"),
        ("PyPI", "poetry.lock") => format!("cd {d} && poetry update {}", quote(name)),
        ("PyPI", "Pipfile.lock") => format!("cd {d} && pipenv update {}", quote(name)),
        ("Go", _) => format!("cd {d} && go get {name}@v{} && go mod tidy", safe.trim_start_matches('v')),
        ("RubyGems", _) => format!("cd {d} && bundle update --conservative {}", quote(name)),
        ("Packagist", _) => format!("cd {d} && composer update {} --with-dependencies", quote(name)),
        ("Pub", _) => format!("cd {d} && dart pub upgrade {}", quote(name)),
        ("Hex", _) => format!("cd {d} && mix deps.update {}", quote(name)),
        ("Maven", "gradle.lockfile") => format!("cd {d} && gradle dependencies --update-locks {}", quote(name)),
        ("NuGet", _) => format!("cd {d} && dotnet add package {} --version {}", quote(name), quote(safe)),
        _ => format!("Update {name} to {safe} in {}", lock.display()),
    }
}

/// Whether a yarn.lock is Yarn 2+'s (berry), which `yarn up` updates.
fn yarn_berry(lock: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 4096];
    let n = std::fs::File::open(lock).and_then(|mut f| f.read(&mut head)).unwrap_or(0);
    String::from_utf8_lossy(&head[..n]).lines().any(|l| l.trim_end() == "__metadata:")
}

// The scanned repos -----------------------------------------------------------

pub fn projects(scan: &mut Scan, repos: &[Repo]) -> Result<()> {
    // (repo root, lockfile): a requirements file may include others from its repo.
    let files: Vec<(&Path, PathBuf)> = repos
        .iter()
        .flat_map(|(name, r)| {
            scan.status(&format!("Finding lockfiles in {name}"));
            repos::lockfiles(r).into_iter().map(move |f| (r.as_path(), f))
        })
        .collect();
    if files.is_empty() {
        return Ok(());
    }
    let mut read: Vec<(PathBuf, Vec<lockfiles::Package>)> = Vec::new();
    let mut unsupported: BTreeMap<String, usize> = BTreeMap::new();
    for (root, f) in &files {
        scan.status(&format!("Reading {}", short(&f.to_string_lossy())));
        match lockfiles::extract_within(f, root).map_err(as_source) {
            Ok(Some(pkgs)) => read.push((f.clone(), pkgs)),
            Ok(None) => {
                *unsupported.entry(f.file_name().unwrap_or_default().to_string_lossy().into_owned()).or_default() += 1
            }
            Err(e) if e.is_source() => {
                scan.unchecked(&format!("repo dependencies in {}", short(&f.to_string_lossy())), &e.to_string())
            }
            Err(e) => return Err(e),
        }
    }
    typosquats(scan, &read);
    if !unsupported.is_empty() {
        let kinds: Vec<String> = unsupported.iter().map(|(k, n)| format!("{k} ({n})")).collect();
        scan.unchecked(
            "repo dependencies in lockfiles wpantry can't read",
            &format!("{}: no extractor for this kind", kinds.join(", ")),
        );
    }
    let total: usize = read.iter().map(|(_, p)| p.len()).sum();
    scan.count("project dependencies", total as i64);
    let items: Vec<Item> = read
        .iter()
        .flat_map(|(_, ps)| ps.iter().map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone())))
        .collect();
    let answers = scan.lookup(&items, "repo dependencies against OSV")?;
    for (f, pkgs) in &read {
        for p in pkgs {
            let item = (p.ecosystem.clone(), p.name.clone(), p.version.clone());
            let Some(recs) = answers.get(&item) else { continue };
            if recs.is_empty() {
                continue;
            }
            let mut c = Component::new("project", &p.name, &p.version, &f.to_string_lossy());
            c.fix = project_fix(f, &p.ecosystem, &p.name, "{safe}");
            c.osv = Some(item);
            if p.scope != lockfiles::Scope::Unknown {
                c.scope = p.scope.as_str().to_string();
            }
            c.direct = p.direct;
            scan.advisories(&c, &[], None, "fail", Some(osv::group_by_alias(recs)));
        }
    }
    if scan.opts.licenses {
        licenses::licenses(scan, &read)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "projects_tests.rs"]
mod tests;
