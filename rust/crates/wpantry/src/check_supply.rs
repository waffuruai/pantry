//! Supply-chain checks: the scanned repos' dependencies (read by the
//! lockfile extractors, asked of OSV directly), install scripts and
//! committed secrets, the container images they name, the MCP servers they
//! configure, and every package name against the malicious-package index;
//! dependency licenses (deps.dev) with `--licenses`; on a machine scan also
//! the editor extensions, harness plugins and the breach check.

use crate::check::{Finding, REMOVE, Scan, as_source};
use crate::error::{Error, Result};
use crate::json::str_at;
use crate::lockfiles;
use crate::osv::{self, Item};
use crate::repos::{self, Repo};
use crate::system::{self, Component, run as sh, short, which};
use crate::{harnesses, hooks, leaks, malicious};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const GITLEAKS_INSTALL: &str = "https://github.com/gitleaks/gitleaks#installing";
/// How the report names the policy files (their paths vary; the flag doesn't).
pub const LICENSES: &str = "the licenses allowlist (--licenses)";
pub const INSTALL_SCRIPTS: &str = "the install-scripts allowlist (--install-scripts)";

/// The repo checks always; the editor, harness and breach checks only on a
/// machine scan. `found` is what the machine inventory found.
pub fn run(scan: &mut Scan, found: &[Component]) -> Result<()> {
    let repos = scan.repos.clone();
    let git: Vec<Repo> = repos.iter().filter(|(_, r)| repos::is_git(r)).cloned().collect();
    // gitleaks is local and CPU-bound: the repos whose cached scan is stale
    // are scanned, a few at once, while `projects` waits on the network.
    let jobs = secret_jobs(scan, &git)?;
    let todo: Vec<(usize, &leaks::Job)> = jobs
        .iter()
        .enumerate()
        .filter_map(|(i, (j, stale))| j.as_ref().ok().filter(|_| *stale).map(|j| (i, j)))
        .collect();
    let ran = std::thread::scope(|s| -> Result<Vec<Option<Result<Value>>>> {
        let at_once = gitleaks_at_once(scan);
        let todo = &todo;
        let running = s.spawn(move || system::par_map(todo, at_once, |(_, job)| leaks::run_job(job)));
        projects(scan, &repos)?;
        if !todo.is_empty() {
            scan.status(&format!("Scanning {} repos' git history for secrets (gitleaks)", todo.len()));
        }
        let mut ran: Vec<Option<Result<Value>>> = jobs.iter().map(|_| None).collect();
        let results = running.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        for ((i, _), r) in todo.iter().zip(results) {
            ran[*i] = Some(r);
        }
        Ok(ran)
    })?;
    secrets(scan, &git, jobs, ran)?;
    repo_hooks(scan, &git);
    install_scripts(scan, &repos, found);
    images(scan, &repos)?;
    let exts = if scan.opts.machine { extensions(scan)? } else { Vec::new() };
    let refs = mcp(scan, &repos)?;
    if scan.opts.machine {
        bundles(scan, &exts)?;
    }
    let mut known: Vec<Component> = found.to_vec();
    known.extend(exts);
    sweep(scan, &known, &refs)?;
    if scan.opts.machine {
        breach(scan)?;
    }
    Ok(())
}

/// POSIX shell quoting, as Python's `shlex.quote`.
pub fn quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c)) {
        return s.into();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

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
        licenses(scan, &read)?;
    }
    Ok(())
}

/// Dependencies whose license isn't in the allowlist warn; ones with no
/// identifiable license are counted (`--licenses`).
fn licenses(scan: &mut Scan, read: &[(PathBuf, Vec<lockfiles::Package>)]) -> Result<()> {
    let allowed = scan.opts.policy.licenses();
    let items: Vec<Item> = read
        .iter()
        .flat_map(|(_, ps)| ps.iter().map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone())))
        .collect();
    scan.status(&format!("Checking {} dependencies' licenses", items.len()));
    let status = scan.status;
    let found = match crate::licenses::lookup(&scan.cache, scan.net, &items, scan.opts.offline, status) {
        Ok(f) => f,
        Err(e) if e.is_source() => {
            scan.unchecked("dependency licenses (deps.dev)", &e.to_string());
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut i = 0;
    for (f, ps) in read {
        for p in ps {
            let verdict = crate::licenses::judge(&found[i], &allowed);
            i += 1;
            match verdict {
                None => {}
                Some(v) if v == ["UNKNOWN"] => scan.unknown_licenses += 1,
                Some(v) => scan.add(Finding {
                    kind: "license".into(),
                    component: p.name.clone(),
                    version: p.version.clone(),
                    location: f.to_string_lossy().into_owned(),
                    vuln_id: "LICENSE".into(),
                    status: "warn".into(),
                    note: format!("license {} isn't in {LICENSES}", v.join(", ")),
                    fix_cmd: format!("Review {}: replace it, or approve its license in {LICENSES}", p.name),
                    ..Default::default()
                }),
            }
        }
    }
    Ok(())
}

/// gitleaks scans run at once on a first run (`--jobs`): each is CPU-bound,
/// so together they get the machine's cores, not each of them all of them.
fn gitleaks_at_once(scan: &Scan) -> usize {
    scan.opts.jobs.unwrap_or_else(|| (system::cores() / 2).clamp(1, 4))
}

/// Each repo's gitleaks job, its fingerprint and ref tips read at once, and
/// whether its cached result is stale.
fn secret_jobs(scan: &Scan, repos: &[Repo]) -> Result<Vec<(Result<leaks::Job>, bool)>> {
    if repos.is_empty() {
        return Ok(Vec::new());
    }
    let config = scan.opts.policy.gitleaks_config(&scan.cache)?;
    let threads = (system::cores() / gitleaks_at_once(scan)).max(1);
    repos
        .iter()
        .map(|(_, root)| {
            let job = leaks::job(&scan.cache, root, &config, threads);
            let stale = match &job {
                Ok(j) => leaks::stale(j, scan.opts.refresh, scan.opts.offline),
                Err(_) => false,
            };
            Ok((job, stale))
        })
        .collect()
}

/// Secrets committed anywhere in the repos' history, from the jobs
/// [`secret_jobs`] made and the scans run ahead (`ran`), in the repos'
/// order. A provider-specific rule (AWS, GitHub, OpenAI, …) fails; a generic
/// one asks for review.
fn secrets(
    scan: &mut Scan,
    repos: &[Repo],
    jobs: Vec<(Result<leaks::Job>, bool)>,
    ran: Vec<Option<Result<Value>>>,
) -> Result<()> {
    let (refresh, offline) = (scan.opts.refresh, scan.opts.offline);
    for (((name, root), (job, _)), ran) in repos.iter().zip(jobs).zip(ran) {
        scan.status(&format!("Scanning {name}'s git history for secrets (gitleaks)"));
        if job.as_ref().is_ok_and(|j| j.own_policy) {
            scan.add(Finding {
                kind: "secret".into(),
                component: format!("{name}/.gitleaks.toml"),
                vuln_id: "REPO-POLICY".into(),
                status: "warn".into(),
                note: "the repo's own gitleaks config was ignored; the scan used your policy".into(),
                fix_cmd: "Review the repo's .gitleaks.toml; pass it with --gitleaks-config to scan with it".into(),
                ..Default::default()
            });
        }
        let found = match job.and_then(|job| leaks::finish(&scan.cache, &job, ran, refresh, offline)) {
            Ok(f) => f,
            Err(Error::Missing(_)) => {
                let has_brew = which("brew").is_some();
                scan.add(Finding {
                    kind: "tool".into(),
                    component: "gitleaks".into(),
                    vuln_id: "MISSING".into(),
                    status: "fail".into(),
                    note: "secrets in the repos' history can't be checked".into(),
                    fix_auto: has_brew,
                    fix_cmd: if has_brew {
                        "brew install gitleaks".into()
                    } else {
                        format!("Install gitleaks: {GITLEAKS_INSTALL}")
                    },
                    ..Default::default()
                });
                return Ok(());
            }
            Err(e) if e.is_source() => {
                scan.unchecked(&format!("secrets in {name}'s history (gitleaks)"), &e.to_string());
                continue;
            }
            Err(e) => return Err(e),
        };
        scan.count("repos scanned for secrets", 1);
        for f in found {
            let generic = leaks::GENERIC.contains(&f.rule.as_str());
            scan.add(Finding {
                kind: "secret".into(),
                component: format!("{name}/{}", f.file),
                location: format!("line {}, commit {}", f.line, f.commit),
                vuln_id: f.rule.clone(),
                status: if generic { "warn" } else { "fail" }.into(),
                note: format!("{}{}", f.description, if generic { " (review: generic rule)" } else { "" }),
                fix_cmd: format!(
                    "If it's real: rotate it, then purge it from history. If not: add {} to {}/.gitleaksignore",
                    f.fingerprint,
                    short(&root.to_string_lossy())
                ),
                ..Default::default()
            });
        }
    }
    Ok(())
}

/// Code each repo runs when it is opened, installed or built (agent hooks,
/// MCP servers in the repo, editor tasks on open, install scripts, native
/// addons), and the markers of known hijacked-repo campaigns. Running a file
/// kept in the repo fails; running a command at all warns.
pub fn repo_hooks(scan: &mut Scan, repos: &[Repo]) {
    if repos.is_empty() {
        return;
    }
    scan.status("Looking for code the repos run on open or install");
    let iocs = hooks::Indicators::parse(&scan.opts.policy.repo_hooks());
    let found: Vec<Vec<hooks::Hook>> = system::par_map(repos, system::PROBES, |(_, root)| {
        let mut h = hooks::scan_repo(root, &iocs);
        h.extend(hooks::campaign_markers(root));
        h
    });
    for ((name, root), hooks) in repos.iter().zip(found) {
        scan.count("repos checked for hooks", 1);
        for h in hooks {
            let fails = h.fails();
            let (status, fix_cmd) = if fails {
                (
                    "fail",
                    format!(
                        "Don't open {} in an agent or editor until you've read {}: remove the hook, or review what it runs",
                        short(&root.to_string_lossy()),
                        h.file
                    ),
                )
            } else if h.id == "MARKER" {
                (
                    "warn",
                    "If this isn't yours: treat the repo and every token it could reach as compromised, remove the persistence first, then rotate".into(),
                )
            } else {
                (
                    "warn",
                    format!(
                        "Read {} before opening or installing this repo; remove the hook if you don't need it",
                        h.file
                    ),
                )
            };
            scan.add(Finding {
                kind: "repo-hook".into(),
                component: format!("{name}/{}", h.file),
                location: h.when.clone(),
                vuln_id: h.id.into(),
                status: status.into(),
                note: if h.command.is_empty() { h.note } else { format!("{}: `{}`", h.note, h.command) },
                fix_cmd,
                ..Default::default()
            });
        }
    }
}

/// Dependencies that run code at install time, outside the allowlist, and
/// whether npm runs them by default on this machine.
pub fn install_scripts(scan: &mut Scan, repos: &[Repo], found: &[Component]) {
    scan.status("Checking which dependencies run install scripts");
    let allowed: HashSet<String> = scan.opts.policy.install_scripts().into_iter().collect();
    let files: Vec<PathBuf> = repos.iter().flat_map(|(_, r)| repos::lockfiles(r)).collect();
    for (where_, name) in repos::install_scripts(&files) {
        if allowed.contains(&name) {
            continue;
        }
        scan.add(Finding {
            kind: "install-script".into(),
            component: name.clone(),
            location: where_.to_string_lossy().into_owned(),
            vuln_id: "INSTALL-SCRIPT".into(),
            status: "warn".into(),
            note: "runs code when installed".into(),
            fix_cmd: format!("Check what {name}'s install script does; then allow it in {INSTALL_SCRIPTS}, or drop it from the build allowlist"),
            ..Default::default()
        });
    }
    let npm = found.iter().find(|c| c.name == "npm" && !c.path.is_empty()).map(|c| c.path.clone());
    if let Some(npm) = npm
        && sh(
            &[OsStr::new(&npm), OsStr::new("config"), OsStr::new("get"), OsStr::new("ignore-scripts")],
            Duration::from_secs(15),
        )
        .trim()
        .ends_with("false")
    {
        scan.add(Finding {
            kind: "config".into(),
            component: "npm ignore-scripts".into(),
            location: npm.clone(),
            vuln_id: "NPM-SCRIPTS".into(),
            status: "warn".into(),
            note: "npm runs every dependency's install scripts (how most npm attacks run)".into(),
            fix_cmd: format!("{npm} config set ignore-scripts true  (then allow builds per project)"),
            ..Default::default()
        });
    }
}

/// Images behind running containers (machine scans), and the ones the repos
/// build from or run, when they exist locally (pulling is left to the user),
/// scanned with the same extractors as everything else (F12).
pub fn images(scan: &mut Scan, repos: &[Repo]) -> Result<()> {
    let Some(engine) = crate::images::engine() else { return Ok(()) };
    scan.status("Looking for container images");
    let mut refs: Vec<(String, String)> = Vec::new();
    if scan.opts.machine {
        for r in crate::apps::running_images() {
            refs.push((r.clone(), format!("docker pull {r}, then recreate its containers")));
        }
    }
    for (r, f) in repos::repo_images(repos) {
        if !refs.iter().any(|(x, _)| *x == r) {
            let fix = format!(
                "docker pull {r} (the tag may already carry the fixes); if not, bump it in {}; then rebuild",
                short(&f.to_string_lossy())
            );
            refs.push((r, fix));
        }
    }
    refs.sort();
    for (r, fix) in refs {
        let id = crate::images::image_id(&engine, &r);
        if id.is_empty() {
            continue;
        }
        scan.status(&format!("Reading image {r}"));
        let (pkgs, gaps) =
            match crate::images::packages(&scan.cache, &engine, &r, &id, scan.opts.refresh, scan.opts.offline) {
                Ok(p) => p,
                Err(e) if e.is_source() || matches!(e, Error::Missing(_)) => {
                    scan.unchecked(&format!("image {r}"), &e.to_string());
                    continue;
                }
                Err(e) => return Err(e),
            };
        if !gaps.is_empty() {
            scan.unchecked(&format!("image {r}"), &gaps.join("; "));
        }
        let pkgs: Vec<_> = pkgs.into_iter().filter(|p| !crate::images::host_kernel(p)).collect();
        scan.count("image packages", pkgs.len() as i64);
        let items: Vec<Item> = pkgs.iter().map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone())).collect();
        let answers = scan.lookup(&items, &format!("image {r} against OSV"))?;
        for (p, item) in pkgs.iter().zip(items) {
            let Some(recs) = answers.get(&item).filter(|x| !x.is_empty()) else { continue };
            let mut c = Component::new("image", &format!("{r} › {}", p.name), &p.version, &p.source);
            c.fix = fix.clone();
            c.osv = Some(item);
            scan.advisories(&c, &[], None, "fail", Some(osv::group_by_alias(recs)));
        }
    }
    Ok(())
}

// Editors and AI harnesses ----------------------------------------------------

/// Malicious or deprecated per the lists VS Code itself uses (and OSV),
/// behind their marketplace's latest, and the npm packages they bundle.
pub fn extensions(scan: &mut Scan) -> Result<Vec<Component>> {
    scan.status("Reading editor extensions");
    let mut exts = crate::editors::extensions();
    if exts.is_empty() {
        return Ok(exts);
    }
    scan.count("editor extensions", exts.len() as i64);
    scan.status("Fetching VS Code's malicious-extension list");
    let r = crate::feeds::vscode_lists(&scan.cache, scan.net, scan.opts.offline).map(Some);
    let lists = scan.guard("VS Code's malicious-extension list", r, None)?;
    let items: Vec<Item> = exts.iter().filter_map(|e| e.osv.clone()).collect();
    let answers = scan.lookup(&items, "editor extensions against OSV")?;
    let mut latest: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for market in ["vscode", "openvsx"] {
        let ids: Vec<String> = exts
            .iter()
            .filter(|e| e.extra.get("market").map(String::as_str) == Some(market))
            .map(|e| e.name.clone())
            .collect();
        if !ids.is_empty() {
            scan.status(&format!("Fetching the latest extension versions ({market})"));
            let r =
                crate::feeds::latest_extensions(&scan.cache, scan.net, &ids, market == "openvsx", scan.opts.offline);
            latest.extend(scan.guard(&format!("latest extension versions ({market})"), r, Default::default())?);
        }
    }
    for e in &mut exts {
        let id = e.extra.get("id").cloned().unwrap_or_default();
        let editor = e.extra.get("editor").cloned().unwrap_or_default();
        let cli = e.extra.get("cli").cloned().unwrap_or_default();
        let lower = id.to_lowercase();
        e.name = format!("{id} ({editor})"); // how the report names it
        let uninstall = format!("{cli} --uninstall-extension {id}");
        if lists.as_ref().is_some_and(|l| l.malicious.contains(&lower)) {
            scan.add(Finding {
                vuln_id: "MALICIOUS".into(),
                status: "fail".into(),
                kev: true,
                severity: "MALICIOUS".into(),
                fix_cmd: uninstall,
                fix_auto: true,
                note: "known malicious extension (removed from the marketplace)".into(),
                ..Finding::of(e)
            });
            continue;
        }
        (e.fix, e.auto) = (uninstall.clone(), true);
        let recs = e.osv.as_ref().and_then(|o| answers.get(o)).cloned().unwrap_or_default();
        if scan.advisories(e, &recs, None, "fail", None) {
            continue;
        }
        e.fix = format!("{cli} --install-extension {id} --force");
        if let Some(repl) = lists.as_ref().and_then(|l| l.deprecated.get(&lower)) {
            scan.add(Finding {
                vuln_id: "DEPRECATED".into(),
                status: "warn".into(),
                note: if repl.is_empty() { "deprecated".into() } else { format!("deprecated; use {repl}") },
                fix_cmd: uninstall,
                ..Finding::of(e)
            });
        }
        if let Some(newest) = latest.get(&lower)
            && !crate::versions::same_or_newer(&e.version, newest)
        {
            scan.add(Finding {
                vuln_id: "OUTDATED".into(),
                status: "warn".into(),
                fixed: newest.clone(),
                note: format!("latest release is {newest}"),
                fix_cmd: e.fix.clone(),
                fix_auto: true,
                ..Finding::of(e)
            });
        }
    }
    Ok(exts)
}

/// npm packages bundled in editor extensions, harness plugins and desktop
/// extensions, plus lockfiles shipped in those and in skills. A vulnerable
/// bundle warns (only its vendor can fix it); malicious fails.
pub fn bundles(scan: &mut Scan, exts: &[Component]) -> Result<()> {
    scan.status("Reading the packages extensions and plugins bundle");
    let mut dirs: Vec<(String, String, String)> =
        exts.iter().map(|e| (e.name.clone(), e.extra.get("dir").cloned().unwrap_or_default(), e.fix.clone())).collect();
    for (h, d) in crate::harnesses::plugin_dirs() {
        let base = Path::new(&d).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        dirs.push((
            format!("{h} plugin {base}"),
            d.clone(),
            format!("Update or remove the {h} plugin in {}", short(&d)),
        ));
    }
    let pkgs: Vec<Vec<(String, String)>> =
        dirs.iter().map(|(_, d, _)| crate::editors::bundled_npm(Path::new(d))).collect();
    let items: Vec<Item> = pkgs.iter().flatten().map(|(n, v)| ("npm".to_string(), n.clone(), v.clone())).collect();
    let answers = scan.lookup(&items, "bundled npm packages against OSV")?;
    for ((label, d, fix), ps) in dirs.iter().zip(&pkgs) {
        for (n, v) in ps {
            let item = ("npm".to_string(), n.clone(), v.clone());
            let mut c = Component::new("bundled", &format!("{label} › {n}"), v, d);
            c.fix = fix.clone();
            let recs = answers.get(&item).cloned().unwrap_or_default();
            c.osv = Some(item);
            scan.advisories(&c, &recs, None, "warn", None);
        }
    }
    let mut roots: Vec<String> = dirs.iter().map(|(_, d, _)| d.clone()).collect();
    roots.extend(crate::harnesses::skill_dirs().into_iter().map(|(_, d)| d));
    let mut read: Vec<(PathBuf, Vec<lockfiles::Package>)> = Vec::new();
    for root in &roots {
        for f in repos::lockfiles(Path::new(root)) {
            if let Ok(Some(p)) = lockfiles::extract(&f) {
                read.push((f, p));
            }
        }
    }
    scan.count("packages in extension, plugin and skill lockfiles", read.iter().map(|(_, p)| p.len() as i64).sum());
    let items: Vec<Item> = read
        .iter()
        .flat_map(|(_, ps)| ps.iter().map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone())))
        .collect();
    let answers = scan.lookup(&items, "lockfiles inside extensions, plugins and skills")?;
    for (f, ps) in &read {
        let parent = short(&f.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default());
        for p in ps {
            let item = (p.ecosystem.clone(), p.name.clone(), p.version.clone());
            let Some(recs) = answers.get(&item).filter(|r| !r.is_empty()) else { continue };
            let mut c = Component::new("bundled", &format!("{parent} › {}", p.name), &p.version, &f.to_string_lossy());
            c.fix = format!("Update or remove what ships {}", short(&f.to_string_lossy()));
            c.osv = Some(item);
            scan.advisories(&c, &[], None, "warn", Some(osv::group_by_alias(recs)));
        }
    }
    Ok(())
}

/// The opt-in email breach check.
pub fn breach(scan: &mut Scan) -> Result<()> {
    let ask = if scan.opts.ask { scan.asker } else { None };
    if crate::breach::consent(&scan.cache, ask)? != Some(true) {
        return Ok(());
    }
    scan.status("Checking your email against breach data");
    for (email, names) in crate::breach::check(&scan.cache, scan.net, scan.opts.offline)? {
        let shown = names.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
        let more = if names.len() > 6 { format!(" and {} more", names.len() - 6) } else { String::new() };
        scan.add(Finding {
            kind: "account".into(),
            component: email,
            location: "breach data".into(),
            vuln_id: "BREACH".into(),
            status: "warn".into(),
            note: format!("in {} breaches: {shown}{more}", names.len()),
            fix_cmd: "Change any password reused from those sites; turn on 2FA".into(),
            ..Default::default()
        });
    }
    Ok(())
}

/// MCP servers the repos start through a package runner. Pinned ones are
/// checked like any package; unpinned ones run whatever is latest on every
/// launch, so they warn (and fail if the name is known malicious).
pub fn mcp(scan: &mut Scan, repos: &[Repo]) -> Result<Vec<Component>> {
    scan.status("Reading the repos' MCP server configs");
    let servers = harnesses::mcp_servers(repos, scan.opts.machine);
    scan.count("MCP servers", servers.len() as i64);
    let mut refs = Vec::new();
    for s in &servers {
        let Some((eco, name, ver)) = harnesses::package_ref(&s.command, &s.args) else { continue };
        let mut c = Component::new(
            "mcp",
            &format!("{name} ({}: {})", s.harness, s.name),
            if ver.is_empty() { "unpinned" } else { &ver },
            &s.file,
        );
        if !ver.is_empty() {
            c.osv = Some((eco.clone(), name.clone(), ver.clone()));
        }
        c.extra.insert("eco".into(), eco.clone());
        c.extra.insert("pkg".into(), name.clone());
        c.extra.insert("ver".into(), ver.clone());
        c.fix = format!(
            "Pin {name} to a reviewed version in {}{}",
            short(&s.file),
            if ver.is_empty() { "" } else { " ({safe} fixes it)" }
        );
        if ver.is_empty() {
            scan.add(Finding {
                vuln_id: "UNPINNED".into(),
                status: "warn".into(),
                fix_cmd: c.fix.clone(),
                note: format!("`{} {name}` runs the latest release on every launch", s.command),
                ..Finding::of(&c)
            });
        }
        refs.push(c);
    }
    let items: Vec<Item> = refs.iter().filter_map(|c| c.osv.clone()).collect();
    let answers = scan.lookup(&items, "MCP server packages against OSV")?;
    if scan.opts.machine {
        scan.count("harness skills", crate::harnesses::skill_dirs().len() as i64);
    }
    for c in &refs {
        if let Some(item) = &c.osv {
            let recs = answers.get(item).cloned().unwrap_or_default();
            scan.advisories(c, &recs, None, "fail", None);
        }
    }
    Ok(refs)
}

/// Every package name we know against the local malicious-package index,
/// which also covers what OSV couldn't be asked about (offline, unpinned).
pub fn sweep(scan: &mut Scan, found: &[Component], refs: &[Component]) -> Result<()> {
    scan.status("Updating the malicious-package index (OpenSSF)");
    let synced = malicious::sync(&scan.cache, scan.opts.offline);
    if scan.guard("malicious-package index (OpenSSF)", synced.map(Some), None)?.is_none() {
        return Ok(());
    }
    let mut flagged: HashSet<(String, String)> =
        scan.findings.iter().map(|f| (f.component.clone(), f.vuln_id.clone())).collect();
    let mut items: Vec<(&Component, String, String, String)> =
        found.iter().filter_map(|c| c.osv.as_ref().map(|(e, n, v)| (c, e.clone(), n.clone(), v.clone()))).collect();
    let extra = |c: &Component, k: &str| c.extra.get(k).cloned().unwrap_or_default();
    items.extend(refs.iter().map(|c| (c, extra(c, "eco"), extra(c, "pkg"), extra(c, "ver"))));
    let total = items.len();
    let mut unread = Vec::new();
    for (n, (c, eco, name, ver)) in items.into_iter().enumerate() {
        scan.status(&format!("Checking {name} against the malicious-package index ({}/{total})", n + 1));
        let found = malicious::reports(&scan.cache, scan.net, &eco, &name, &ver, scan.opts.offline)?;
        unread.extend(found.unknown.iter().map(|id| format!("{name} {ver} ({id})")));
        for rec in found.matched {
            let id = str_at(&rec, "id").to_string();
            if flagged.insert((c.name.clone(), id.clone())) {
                let summary = str_at(&rec, "summary");
                scan.add(Finding {
                    vuln_id: id,
                    status: "fail".into(),
                    kev: true,
                    severity: "MALICIOUS".into(),
                    note: if summary.is_empty() { format!("known malicious package {name}") } else { summary.into() },
                    fix_cmd: REMOVE.replace("{}", &name),
                    ..Finding::of(c)
                });
            }
        }
    }
    if !unread.is_empty() {
        unread.sort();
        unread.dedup();
        scan.unchecked(
            "packages named in the malicious-package index",
            &format!("couldn't read the report to tell whether these versions are covered: {}", unread.join(", ")),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The test vectors the Python implementation had (`Plan.test_project_fixes_stay_manual_and_per_ecosystem`).
    #[test]
    fn project_fixes_stay_manual_and_per_ecosystem() {
        assert_eq!(
            project_fix(Path::new("/w/butter/rust/Cargo.lock"), "crates.io", "webpki-roots", "1.0.10"),
            "cd /w/butter/rust && cargo update -p webpki-roots --precise 1.0.10"
        );
        assert_eq!(
            project_fix(Path::new("/w/docs/pnpm-lock.yaml"), "npm", "vite", "8.2.3"),
            "cd /w/docs && pnpm update vite@8.2.3"
        );
        assert_eq!(
            project_fix(Path::new("/w/my app/go.mod"), "Go", "golang.org/x/net", "0.23.0"),
            "cd '/w/my app' && go get golang.org/x/net@v0.23.0 && go mod tidy"
        );
        assert_eq!(quote("it's"), "'it'\"'\"'s'");
    }

    #[test]
    fn project_fixes_for_the_later_lockfiles() {
        let fix = |lock: &str, eco: &str, name: &str, safe: &str| project_fix(Path::new(lock), eco, name, safe);
        assert_eq!(
            fix("/w/rb/Gemfile.lock", "RubyGems", "rack", "2.2.8.1"),
            "cd /w/rb && bundle update --conservative rack"
        );
        assert_eq!(
            fix("/w/php/composer.lock", "Packagist", "symfony/yaml", "v6.4.1"),
            "cd /w/php && composer update symfony/yaml --with-dependencies"
        );
        assert_eq!(fix("/w/py/poetry.lock", "PyPI", "jinja2", "3.1.4"), "cd /w/py && poetry update jinja2");
        assert_eq!(fix("/w/py/Pipfile.lock", "PyPI", "jinja2", "3.1.4"), "cd /w/py && pipenv update jinja2");
        assert_eq!(
            fix("/w/py/requirements.txt", "PyPI", "jinja2", "3.1.4"),
            "Update jinja2 to 3.1.4 in /w/py/requirements.txt"
        );
        assert_eq!(fix("/w/js/yarn.lock", "npm", "lodash", "4.17.21"), "cd /w/js && yarn upgrade lodash@4.17.21");
        assert_eq!(fix("/w/js/bun.lock", "npm", "lodash", "4.17.21"), "cd /w/js && bun update lodash");
        assert_eq!(fix("/w/dart/pubspec.lock", "Pub", "http", "1.2.1"), "cd /w/dart && dart pub upgrade http");
        assert_eq!(fix("/w/ex/mix.lock", "Hex", "plug", "1.15.4"), "cd /w/ex && mix deps.update plug");
        assert_eq!(
            fix("/w/jvm/gradle.lockfile", "Maven", "junit:junit", "4.13.2"),
            "cd /w/jvm && gradle dependencies --update-locks junit:junit"
        );
        assert_eq!(
            fix("/w/jvm/pom.xml", "Maven", "junit:junit", "4.13.2"),
            "Update junit:junit to 4.13.2 in /w/jvm/pom.xml"
        );
        assert_eq!(
            fix("/w/cs/packages.lock.json", "NuGet", "Newtonsoft.Json", "13.0.1"),
            "cd /w/cs && dotnet add package Newtonsoft.Json --version 13.0.1"
        );
        assert_eq!(
            fix("/w/x/Gemfile.lock", "RubyGems", "evil;rm", "1"),
            "cd /w/x && bundle update --conservative 'evil;rm'"
        );
        let tmp = crate::system::TempDir::new("yarn-fix").unwrap();
        std::fs::write(tmp.path().join("yarn.lock"), "# comment\n\n__metadata:\n  version: 8\n").unwrap();
        assert_eq!(
            project_fix(&tmp.path().join("yarn.lock"), "npm", "@scope/x", "1.0.1"),
            format!("cd {} && yarn up @scope/x@1.0.1", quote(&tmp.path().to_string_lossy()))
        );
    }
}
