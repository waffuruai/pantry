//! The repos a scan covers: every git checkout found by a bounded walk of
//! $HOME (or of each `--path`), their lockfiles, the container images their
//! Dockerfiles and compose files name, and the dependencies that run code
//! when installed. The walk rules are the contract's
//! (`specs/cli-contract.md#scope-walk`).

use crate::component::Status;
use crate::utils::files::short;
use crate::utils::privacy;
use crate::utils::walk::{MAC_MEDIA_FOLDERS, media_bundle, skip, walk};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "deno.lock",
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "go.mod",
    "Package.resolved",
    "Gemfile.lock",
    "composer.lock",
    "pubspec.lock",
    "mix.lock",
    "gradle.lockfile",
    "pom.xml",
    "packages.lock.json",
    "packages.config",
    "conan.lock",
];
/// ~/a/b/c/d/e/f/.git is the deepest repo found.
pub const DISCOVER_DEPTH: usize = 6;

/// Every git repo at or under `root`, sorted. A directory holding a `.git`
/// directory with a `HEAD` in it is a repo and is not descended into (an
/// empty `.git`, as a downloaded template has, is not a repo). A `.git` file (a linked
/// worktree or a submodule) also ends the descent, but only counts when it
/// is `root` itself. Symlinks are not followed, and only directory entries
/// are looked at.
pub fn discover(root: &Path) -> Vec<PathBuf> {
    discover_with(root, &crate::component::quiet)
}

/// [`discover`], saying which directory it is looking in.
pub fn discover_with(root: &Path, status: Status) -> Vec<PathBuf> {
    discover_excluding(root, &Excluded::default(), status)
}

/// What the default search of `$HOME` leaves out beyond the name rules:
/// whole folders by path, and on macOS the media library bundles.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Excluded {
    pub paths: Vec<PathBuf>,
    pub media_bundles: bool,
}

/// [`Excluded`] for a search: nothing when the user named `--path`s (they
/// are walked as asked); for the default search of `home`, the personal
/// folders with `--no-personal-files` (on macOS every folder it guards,
/// [`privacy::folders`]), and on macOS (`mac`) the media folders and
/// library bundles.
pub(crate) fn default_excluded(home: &Path, explicit_paths: bool, no_personal_files: bool, mac: bool) -> Excluded {
    if explicit_paths {
        return Excluded::default();
    }
    let mut paths = Vec::new();
    if no_personal_files {
        paths.extend(privacy::folders(home, mac));
    }
    if mac {
        paths.extend(MAC_MEDIA_FOLDERS.iter().map(|folder| home.join(folder)));
    }
    Excluded { paths, media_bundles: mac }
}

/// The folders an unattended scan leaves out ([`privacy::folders`]: the
/// personal ones, and on macOS the other guarded ones) that lie strictly
/// under `root`, spelled from `home` as given and from its canonical path
/// (a `--path` root is canonical, `home` may not be). A root inside or
/// equal to one of them gives nothing: a folder the user named is scanned.
///
/// Example: home `/h`, root `/h` gives `/h/Downloads`, `/h/Desktop`,
/// `/h/Documents` (and on macOS `/h/Pictures`, `/h/Library/Mail`, ...);
/// root `/h/Documents/x` gives none.
pub(crate) fn personal_under(home: &Path, root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for f in privacy::folders(home, cfg!(target_os = "macos")) {
        if f != root && f.starts_with(root) && !out.contains(&f) {
            out.push(f);
        }
    }
    out
}

fn discover_excluding(root: &Path, excluded: &Excluded, status: Status) -> Vec<PathBuf> {
    fn visit(d: &Path, level: usize, found: &mut Vec<PathBuf>, excluded: &Excluded, status: Status) {
        // By path, before the folder is listed: listing it raises the prompt.
        if excluded.paths.iter().any(|path| d.starts_with(path)) || privacy::is_left_out(d) {
            return;
        }
        if excluded.media_bundles && d.file_name().is_some_and(|n| media_bundle(&n.to_string_lossy())) {
            return;
        }
        status(&format!("Looking for git repos in {} ({} found)", short(&d.to_string_lossy()), found.len()));
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let entries: Vec<std::fs::DirEntry> = rd.filter_map(|e| e.ok()).collect();
        if let Some(git) = entries.iter().find(|e| e.file_name() == ".git") {
            let dir = git.file_type().is_ok_and(|t| t.is_dir());
            if (dir && git.path().join("HEAD").is_file()) || (level == 0 && !dir) {
                found.push(d.to_path_buf());
            }
            return;
        }
        if level >= DISCOVER_DEPTH {
            return;
        }
        let parent = d.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.file_type().is_ok_and(|t| t.is_dir()) && !skip(&parent, &name) {
                visit(&e.path(), level + 1, found, excluded, status);
            }
        }
    }
    let mut found = Vec::new();
    // A root that is a left-out folder, or a link into one, is not listed: the
    // folders below it are checked by path as they come, but this one is read first.
    if privacy::reaches_left_out(root) {
        return found;
    }
    // The top level fans out: each of root's folders is searched on its own
    // thread (a home directory has a few dozen, each a tree of its own).
    let Ok(rd) = std::fs::read_dir(root) else { return found };
    let entries: Vec<std::fs::DirEntry> = rd.filter_map(|e| e.ok()).collect();
    if entries.iter().any(|e| e.file_name() == ".git") {
        visit(root, 0, &mut found, excluded, status);
    } else if DISCOVER_DEPTH > 0 {
        let parent = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut tops: Vec<PathBuf> = entries
            .iter()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|e| !skip(&parent, &e.file_name().to_string_lossy()))
            .map(|e| e.path())
            .filter(|p| !excluded.paths.iter().any(|x| p.starts_with(x)) && !privacy::is_left_out(p))
            .collect();
        tops.sort();
        status(&format!("Looking for git repos in {} ({} folders)", short(&root.to_string_lossy()), tops.len()));
        let seen = std::sync::atomic::AtomicUsize::new(0);
        let per_top = crate::utils::parallel::par_map(&tops, crate::utils::parallel::PROBES, |top| {
            let mut mine = Vec::new();
            visit(top, 1, &mut mine, excluded, &crate::component::quiet);
            let n = seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            status(&format!(
                "Looking for git repos in {} ({}/{} folders)",
                short(&top.to_string_lossy()),
                n,
                tops.len()
            ));
            mine
        });
        found.extend(per_top.into_iter().flatten());
    }
    found.sort();
    found
}

/// One repo in scope: how the report names it, and where it is.
pub type Repo = (String, PathBuf);

/// The repos a scan covers. With no paths, every git checkout under `home`.
/// With paths, the checkouts at or under each one; a path holding no
/// checkout is scanned as one project (without the git-history checks).
/// Missing paths are skipped with a one-line `note`.
pub fn scope(
    paths: Option<&[PathBuf]>,
    home: &Path,
    log: &dyn Fn(&str),
    note: &dyn Fn(&str),
    status: Status,
) -> Vec<Repo> {
    scan_scope(paths, home, false, log, note, status)
}

pub(crate) fn scan_scope(
    paths: Option<&[PathBuf]>,
    home: &Path,
    no_personal_files: bool,
    log: &dyn Fn(&str),
    note: &dyn Fn(&str),
    status: Status,
) -> Vec<Repo> {
    let mut roots = Vec::new();
    match paths {
        None => roots.push(home.to_path_buf()),
        Some(paths) => {
            for p in paths {
                let p = expand_user(p, home);
                if p.is_dir() {
                    roots.push(std::fs::canonicalize(&p).unwrap_or(p));
                } else {
                    note(&format!("· skipping --path {}: no such directory", p.display()));
                }
            }
        }
    }
    let mut found = BTreeSet::new();
    let defaults = default_excluded(home, paths.is_some(), no_personal_files, cfg!(target_os = "macos"));
    for root in &roots {
        // A --path that holds a personal folder (`--path ~`) leaves it out
        // under --no-personal-files too; a --path inside one is walked as asked.
        let mut excluded = Excluded { paths: defaults.paths.clone(), media_bundles: defaults.media_bundles };
        if no_personal_files && paths.is_some() {
            excluded.paths.extend(personal_under(home, root));
        }
        let repos = discover_excluding(root, &excluded, status);
        if repos.is_empty() {
            if paths.is_some() {
                found.insert(root.clone());
            }
        } else {
            found.extend(repos);
        }
    }
    let where_ = if roots.is_empty() {
        "(no paths to search)".to_string()
    } else {
        format!("under {}", roots.iter().map(|r| short(&r.to_string_lossy())).collect::<Vec<_>>().join(", "))
    };
    log(&format!("  found {} git repos {where_}", found.iter().filter(|r| is_git(r)).count()));
    found.into_iter().map(|r| (short(&r.to_string_lossy()), r)).collect()
}

fn expand_user(p: &Path, home: &Path) -> PathBuf {
    match p.strip_prefix("~") {
        Ok(rest) => home.join(rest),
        Err(_) => p.to_path_buf(),
    }
}

pub fn is_git(path: &Path) -> bool {
    let git = path.join(".git");
    git.is_file() || git.join("HEAD").is_file()
}

pub(crate) fn is_lockfile(name: &str) -> bool {
    LOCKFILES.contains(&name)
        || crate::checks::lockfiles::csproj::is_project_file(name)
        || (name.starts_with("requirements") && name.ends_with(".txt") && name.len() >= "requirements.txt".len())
}

/// Every lockfile under root, sorted. Where a directory has both, npm reads
/// `npm-shrinkwrap.json` and ignores `package-lock.json`, so only the
/// shrinkwrap counts. Gradle build scripts and `gradle/*.versions.toml`
/// catalogs count where no `gradle.lockfile` covers them: beside a
/// script, or anywhere in a catalog's project
/// ([`gradle_build::scanned`](crate::checks::lockfiles::gradle_build::scanned)).
pub fn lockfiles(root: &Path) -> Vec<PathBuf> {
    let dirs = walk(root, 5);
    // Gradle build files only where no gradle.lockfile says more.
    let locked: Vec<PathBuf> =
        dirs.iter().filter(|(_, files)| files.iter().any(|f| f == "gradle.lockfile")).map(|(d, _)| d.clone()).collect();
    let mut out: Vec<PathBuf> = dirs
        .into_iter()
        .flat_map(|(d, files)| {
            let shrinkwrap = files.iter().any(|f| f == "npm-shrinkwrap.json");
            let gradle: Vec<String> = files
                .iter()
                .filter(|f| crate::checks::lockfiles::gradle_build::scanned(&d, f, &locked))
                .cloned()
                .collect();
            files
                .into_iter()
                .filter(move |f| (is_lockfile(f) && !(shrinkwrap && f == "package-lock.json")) || gradle.contains(f))
                .map(move |f| d.join(f))
        })
        .collect();
    out.sort();
    out
}

/// Extensions that mark a file as something other than a Dockerfile when
/// they follow `Dockerfile.` or `Containerfile.` (`Dockerfile.py` is a
/// Python module named after Docker, not a build file). What follows the
/// dot in a real Dockerfile is a label for the variant: `dev`, `prod`, `ci`.
const NOT_DOCKERFILE_SUFFIX: &[&str] = &[
    "py", "pyi", "pyc", "rs", "js", "mjs", "cjs", "ts", "tsx", "jsx", "go", "rb", "java", "kt", "swift", "c", "h",
    "cc", "cpp", "cs", "php", "pl", "lua", "sh", "bash", "zsh", "ps1", "bat", "cmd", "md", "txt", "rst", "json", "yml",
    "yaml", "toml", "xml", "html", "lock", "log", "csv", "ini", "orig", "bak", "swp", "tmp", "diff", "patch",
];

/// A Dockerfile by name: `Dockerfile` or `Containerfile`, `Dockerfile.LABEL`
/// or `Containerfile.LABEL` (LABEL not a source or document extension, see
/// [`NOT_DOCKERFILE_SUFFIX`]), `NAME.dockerfile` or `NAME.containerfile`;
/// any case. The name alone is not proof: [`from_lines`] reads only the
/// lines that are a `FROM` instruction.
fn is_dockerfile(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let labelled = |s: &str| {
        lower.strip_prefix(s).and_then(|r| r.strip_prefix('.')).is_some_and(|label| {
            !label.is_empty() && !NOT_DOCKERFILE_SUFFIX.contains(&label.rsplit('.').next().unwrap_or(""))
        })
    };
    lower == "dockerfile"
        || lower == "containerfile"
        || labelled("dockerfile")
        || labelled("containerfile")
        || (lower.ends_with(".dockerfile") && lower.len() > ".dockerfile".len())
        || (lower.ends_with(".containerfile") && lower.len() > ".containerfile".len())
}

fn is_compose(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let rest = lower.strip_prefix("docker-").unwrap_or(&lower);
    let Some(rest) = rest.strip_prefix("compose") else { return false };
    let mid = rest.strip_suffix(".yaml").or_else(|| rest.strip_suffix(".yml"));
    match mid {
        Some("") => true,
        Some(m) => m.starts_with('.') && m.len() > 1,
        None => false,
    }
}

/// [(image ref, file)]: the base images the repos' Dockerfiles build FROM
/// and the images their compose files run.
pub fn repo_images(repos: &[Repo]) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for (_, root) in repos {
        for (d, files) in walk(root, 5) {
            for f in files {
                let path = d.join(&f);
                if is_dockerfile(&f) {
                    out.extend(from_lines(&path).into_iter().map(|r| (r, path.clone())));
                } else if is_compose(&f) {
                    out.extend(compose_images(&path).into_iter().map(|r| (r, path.clone())));
                }
            }
        }
    }
    out
}

fn text(path: &Path) -> String {
    crate::utils::files::read_capped(path, 16 << 20).unwrap_or_default()
}

/// The images a Dockerfile builds FROM, without build stages, `scratch` or
/// references to build arguments.
pub fn from_lines(path: &Path) -> Vec<String> {
    let mut stages = BTreeSet::new();
    let mut refs = Vec::new();
    for line in text(path).lines() {
        let line = line.trim_start();
        let mut words = line.split_whitespace();
        let Some(first) = words.next() else { continue };
        if !first.eq_ignore_ascii_case("FROM") || line.len() == first.len() {
            continue;
        }
        let rest: Vec<&str> = words.collect();
        let mut i = 0;
        while i + 1 < rest.len() && rest[i].starts_with("--") {
            i += 1;
        }
        let Some(r) = rest.get(i) else { continue };
        // The instruction is `FROM [--flag=value]... IMAGE [AS STAGE]`: one
        // word, or three with AS in the middle. Anything else is not a
        // Dockerfile line (`from importlib.metadata import version`).
        let stage = match rest.len() - i {
            1 => None,
            3 if rest[i + 1].eq_ignore_ascii_case("AS") => Some(rest[i + 2]),
            _ => continue,
        };
        if !r.eq_ignore_ascii_case("scratch") && !r.contains('$') && !stages.contains(*r) {
            refs.push(r.to_string());
        }
        if let Some(s) = stage {
            stages.insert(s.to_string());
        }
    }
    refs
}

/// The images a compose file runs (`image:` lines without variables).
pub fn compose_images(path: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for line in text(path).lines() {
        let Some(rest) = line.trim_start().strip_prefix("image:") else { continue };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix(['\'', '"']).unwrap_or(rest);
        let r: String = rest.chars().take_while(|c| !matches!(c, '\'' | '"' | '#') && !c.is_whitespace()).collect();
        if !r.is_empty() && !r.contains('$') {
            out.push(r);
        }
    }
    out
}

/// A dependency that runs code at install time: the lockfile or workspace
/// file that says so, the package, and the versions the lockfile pins
/// (empty when none could be read).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstallScript {
    pub file: PathBuf,
    pub name: String,
    pub versions: Vec<String>,
}

/// The dependencies that run code at install time: npm's `hasInstallScript`
/// (with the entry's `version`), and the builds a pnpm workspace allows
/// (pnpm 10+ blocks the rest), at the versions the sibling `pnpm-lock.yaml`
/// pins.
pub fn install_scripts(files: &[PathBuf]) -> Vec<InstallScript> {
    let mut out: BTreeMap<(PathBuf, String), BTreeSet<String>> = BTreeMap::new();
    for f in files {
        match f.file_name().and_then(|n| n.to_str()) {
            Some("package-lock.json" | "npm-shrinkwrap.json") => {
                let Ok(bytes) = crate::utils::files::read_capped_bytes(f, crate::utils::json::MAX_DOCUMENT as u64)
                else {
                    continue;
                };
                let Ok(data) = crate::utils::json::parse(&bytes, crate::utils::json::MAX_DOCUMENT) else { continue };
                if let Some(pkgs) = data.get("packages").and_then(|p| p.as_object()) {
                    for (k, v) in pkgs {
                        let truthy = v
                            .get("hasInstallScript")
                            .is_some_and(|h| !matches!(h, serde_json::Value::Null | serde_json::Value::Bool(false)));
                        if !k.is_empty() && truthy {
                            let name = k.rsplit("node_modules/").next().unwrap_or(k);
                            let versions = out.entry((f.clone(), name.to_string())).or_default();
                            if let Some(ver) = v.get("version").and_then(|x| x.as_str()) {
                                versions.insert(ver.to_string());
                            }
                        }
                    }
                }
            }
            Some("pnpm-lock.yaml") => {
                let ws = f.with_file_name("pnpm-workspace.yaml");
                let allowed = pnpm_allowed_builds(&ws);
                if allowed.is_empty() {
                    continue;
                }
                let locked = crate::checks::lockfiles::pnpm::parse(&text(f)).unwrap_or_default();
                for name in allowed {
                    let versions = out.entry((ws.clone(), name.clone())).or_default();
                    versions.extend(locked.iter().filter(|p| p.name == name).map(|p| p.version.clone()));
                }
            }
            _ => {}
        }
    }
    out.into_iter()
        .map(|((file, name), versions)| InstallScript { file, name, versions: versions.into_iter().collect() })
        .collect()
}

/// Names under `onlyBuiltDependencies:` (a list) or `allowBuilds:` (a map of
/// true values) in pnpm-workspace.yaml.
pub fn pnpm_allowed_builds(ws: &Path) -> Vec<String> {
    let unquote = |s: &str| s.trim().trim_matches(['\'', '"']).to_string();
    let mut out = Vec::new();
    let mut section = String::new();
    for line in text(ws).lines() {
        if line.chars().next().is_some_and(|c| !c.is_whitespace()) {
            section = line.split(':').next().unwrap_or("").trim().to_string();
            continue;
        }
        let item = line.trim();
        if section == "onlyBuiltDependencies" && item.starts_with("- ") {
            out.push(unquote(&item[2..]));
        } else if section == "allowBuilds"
            && let Some((name, val)) = item.rsplit_once(':')
            && val.trim().eq_ignore_ascii_case("true")
        {
            out.push(unquote(name));
        }
    }
    out
}

#[cfg(test)]
#[path = "repos_tests.rs"]
mod tests;
