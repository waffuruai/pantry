//! The repos a scan covers: every git checkout found by a bounded walk of
//! $HOME (or of each `--path`), their lockfiles, the container images their
//! Dockerfiles and compose files name, and the dependencies that run code
//! when installed. The walk rules are the contract's
//! (`specs/cli-contract.md#scope-walk`).

use crate::system::{Status, short};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
    "conan.lock",
];
pub const PRUNE: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".build",
    "vendor",
    ".cache",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
];
/// The repo search also skips caches, toolchains and app data that hold
/// other people's checkouts (crate sources, Go modules, npm stores) or are huge.
const DISCOVER_PRUNE: &[&str] = &["Library", ".Trash", ".rustup", ".npm", ".pnpm-store"];
/// (parent, dir)
const DISCOVER_PRUNE_PAIRS: &[(&str, &str)] =
    &[("go", "pkg"), (".cargo", "registry"), (".cargo", "git"), (".local", "share")];
/// ~/a/b/c/d/e/f/.git is the deepest repo found.
pub const DISCOVER_DEPTH: usize = 6;

fn skip(parent: &str, name: &str) -> bool {
    PRUNE.contains(&name)
        || DISCOVER_PRUNE.contains(&name)
        || name.ends_with(".app")
        || DISCOVER_PRUNE_PAIRS.contains(&(parent, name))
}

/// Every git repo at or under `root`, sorted. A directory holding a `.git`
/// directory is a repo and is not descended into. A `.git` file (a linked
/// worktree or a submodule) also ends the descent, but only counts when it
/// is `root` itself. Symlinks are not followed, and only directory entries
/// are looked at.
pub fn discover(root: &Path) -> Vec<PathBuf> {
    discover_with(root, &crate::system::quiet)
}

/// [`discover`], saying which directory it is looking in.
pub fn discover_with(root: &Path, status: Status) -> Vec<PathBuf> {
    fn visit(d: &Path, level: usize, found: &mut Vec<PathBuf>, status: Status) {
        status(&format!("Looking for git repos in {} ({} found)", short(&d.to_string_lossy()), found.len()));
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let entries: Vec<std::fs::DirEntry> = rd.filter_map(|e| e.ok()).collect();
        if let Some(git) = entries.iter().find(|e| e.file_name() == ".git") {
            if level == 0 || git.file_type().is_ok_and(|t| t.is_dir()) {
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
                visit(&e.path(), level + 1, found, status);
            }
        }
    }
    let mut found = Vec::new();
    // The top level fans out: each of root's folders is searched on its own
    // thread (a home directory has a few dozen, each a tree of its own).
    let Ok(rd) = std::fs::read_dir(root) else { return found };
    let entries: Vec<std::fs::DirEntry> = rd.filter_map(|e| e.ok()).collect();
    if entries.iter().any(|e| e.file_name() == ".git") {
        visit(root, 0, &mut found, status);
    } else if DISCOVER_DEPTH > 0 {
        let parent = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut tops: Vec<PathBuf> = entries
            .iter()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|e| !skip(&parent, &e.file_name().to_string_lossy()))
            .map(|e| e.path())
            .collect();
        tops.sort();
        status(&format!("Looking for git repos in {} ({} folders)", short(&root.to_string_lossy()), tops.len()));
        let seen = std::sync::atomic::AtomicUsize::new(0);
        let per_top = crate::system::par_map(&tops, crate::system::PROBES, |top| {
            let mut mine = Vec::new();
            visit(top, 1, &mut mine, &crate::system::quiet);
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
    for root in &roots {
        let repos = discover_with(root, status);
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
    path.join(".git").exists()
}

/// (dir, files) under root, skipping build output and dependency dirs.
/// Memoised for the process: the lockfile, install-script and image
/// checks each want the same listing of every repo; [`forget_walks`]
/// drops the memo between scans.
pub fn walk(root: &Path, depth: usize) -> Vec<(PathBuf, Vec<String>)> {
    let key = (root.to_path_buf(), depth);
    if let Some(hit) = WALKS.lock().expect("lock").get(&key).cloned() {
        return (*hit).clone();
    }
    let out = Arc::new(walk_uncached(root, depth));
    WALKS.lock().expect("lock").insert(key, out.clone());
    (*out).clone()
}

type Walks = HashMap<(PathBuf, usize), Arc<Vec<(PathBuf, Vec<String>)>>>;
static WALKS: std::sync::LazyLock<Mutex<Walks>> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Drop the memoised listings: a new scan may see changed files.
pub fn forget_walks() {
    WALKS.lock().expect("lock").clear();
}

fn walk_uncached(root: &Path, depth: usize) -> Vec<(PathBuf, Vec<String>)> {
    fn visit(d: &Path, level: usize, depth: usize, out: &mut Vec<(PathBuf, Vec<String>)>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let (mut dirs, mut files) = (Vec::new(), Vec::new());
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(t) = e.file_type() else { continue };
            // As os.walk: a symlink to a directory is listed but not walked.
            let is_dir =
                if t.is_symlink() { std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir()) } else { t.is_dir() };
            if !is_dir {
                files.push(name);
            } else if !t.is_symlink() && !PRUNE.contains(&name.as_str()) && level < depth {
                dirs.push(e.path());
            }
        }
        files.sort();
        dirs.sort();
        out.push((d.to_path_buf(), files));
        for sub in dirs {
            visit(&sub, level + 1, depth, out);
        }
    }
    let mut out = Vec::new();
    visit(root, 0, depth, &mut out);
    out
}

fn is_lockfile(name: &str) -> bool {
    LOCKFILES.contains(&name)
        || (name.starts_with("requirements") && name.ends_with(".txt") && name.len() >= "requirements.txt".len())
}

/// Every lockfile under root, sorted. Where a directory has both, npm reads
/// `npm-shrinkwrap.json` and ignores `package-lock.json`, so only the
/// shrinkwrap counts.
pub fn lockfiles(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = walk(root, 5)
        .into_iter()
        .flat_map(|(d, files)| {
            let shrinkwrap = files.iter().any(|f| f == "npm-shrinkwrap.json");
            files
                .into_iter()
                .filter(move |f| is_lockfile(f) && !(shrinkwrap && f == "package-lock.json"))
                .map(move |f| d.join(f))
        })
        .collect();
    out.sort();
    out
}

fn is_dockerfile(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stem_ok = |s: &str| lower == s || lower.starts_with(&format!("{s}.")) && lower.len() > s.len() + 1;
    stem_ok("dockerfile")
        || stem_ok("containerfile")
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
    crate::system::read_capped(path, 16 << 20).unwrap_or_default()
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
        let stage = (rest.len() > i + 2 && rest[i + 1].eq_ignore_ascii_case("AS")).then(|| rest[i + 2]);
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

/// [(lockfile or workspace file, package)] for dependencies that run code at
/// install time: npm's `hasInstallScript`, and the builds a pnpm workspace
/// allows (pnpm 10+ blocks the rest).
pub fn install_scripts(files: &[PathBuf]) -> Vec<(PathBuf, String)> {
    let mut out = BTreeSet::new();
    for f in files {
        match f.file_name().and_then(|n| n.to_str()) {
            Some("package-lock.json" | "npm-shrinkwrap.json") => {
                let Ok(bytes) = crate::system::read_capped_bytes(f, crate::json::MAX_DOCUMENT as u64) else { continue };
                let Ok(data) = crate::json::parse(&bytes, crate::json::MAX_DOCUMENT) else { continue };
                if let Some(pkgs) = data.get("packages").and_then(|p| p.as_object()) {
                    for (k, v) in pkgs {
                        let truthy = v
                            .get("hasInstallScript")
                            .is_some_and(|h| !matches!(h, serde_json::Value::Null | serde_json::Value::Bool(false)));
                        if !k.is_empty() && truthy {
                            let name = k.rsplit("node_modules/").next().unwrap_or(k);
                            out.insert((f.clone(), name.to_string()));
                        }
                    }
                }
            }
            Some("pnpm-lock.yaml") => {
                let ws = f.with_file_name("pnpm-workspace.yaml");
                for name in pnpm_allowed_builds(&ws) {
                    out.insert((ws.clone(), name));
                }
            }
            _ => {}
        }
    }
    out.into_iter().collect()
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
mod tests {
    use super::*;
    use crate::system::TempDir;
    use std::cell::RefCell;

    fn git_repo(path: &Path, worktree: bool) -> PathBuf {
        std::fs::create_dir_all(path).unwrap();
        if worktree {
            std::fs::write(path.join(".git"), "gitdir: /elsewhere\n").unwrap();
        } else {
            std::fs::create_dir(path.join(".git")).unwrap();
        }
        path.to_path_buf()
    }

    // The Scope tests the Python implementation had (`Scope`).
    #[test]
    fn default_scope_walks_home_and_prunes_caches() {
        let tmp = TempDir::new("scope").unwrap();
        let h = tmp.path().join("home");
        let mut wanted = vec![
            git_repo(&h.join("code/app"), false),
            git_repo(&h.join("a/b/c/d/e/f"), false),
            git_repo(&h.join(".dotfiles"), false),
        ];
        git_repo(&h.join("code/app/vendored/inner"), false);
        git_repo(&h.join("code/app-feature"), true);
        for pruned in [
            "Library/x",
            ".Trash/x",
            "go/pkg/mod/x",
            ".cargo/registry/x",
            ".cargo/git/x",
            ".rustup/x",
            ".npm/x",
            ".pnpm-store/x",
            ".cache/x",
            ".local/share/x",
            "code/node_modules/x",
            "Foo.app/x",
            "a/b/c/d/e/f2/g",
        ] {
            git_repo(&h.join(pruned), false);
        }
        let outside = git_repo(&tmp.path().join("outside"), false);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, h.join("link")).unwrap();
        let lines = RefCell::new(Vec::new());
        let got = scope(None, &h, &|m| lines.borrow_mut().push(m.to_string()), &|_| {}, &|_| {});
        wanted.sort();
        assert_eq!(got.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>(), wanted);
        assert!(lines.borrow()[0].contains("found 3 git repos"));
    }

    #[test]
    fn path_scopes_to_those_dirs_and_skips_missing_ones() {
        let tmp = TempDir::new("scope").unwrap();
        let h = tmp.path().join("home");
        let a = git_repo(&h.join("a"), false);
        let b = git_repo(&h.join("w/b"), false);
        let elsewhere = git_repo(&h.join("elsewhere"), false);
        let notes = RefCell::new(Vec::new());
        let paths = [h.join("w"), a.clone(), a.join(".."), h.join("missing")];
        let got = scope(Some(&paths), &h, &|_| {}, &|m| notes.borrow_mut().push(m.to_string()), &|_| {});
        let canon = |p: &Path| std::fs::canonicalize(p).unwrap();
        let mut want = vec![canon(&a), canon(&b), canon(&elsewhere)];
        want.sort();
        assert_eq!(got.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>(), want);
        assert_eq!(notes.borrow().len(), 1);
        assert!(notes.borrow()[0].contains("missing"));
        let only = scope(Some(&[h.join("w")]), &h, &|_| {}, &|_| {}, &|_| {});
        assert_eq!(only.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>(), [canon(&b)]);
    }

    #[test]
    fn explicit_worktree_and_plain_project_paths() {
        let tmp = TempDir::new("scope").unwrap();
        let h = tmp.path().join("home");
        let wt = git_repo(&h.join("wt"), true);
        let plain = h.join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        let got = scope(Some(&[wt.clone(), plain.clone()]), &h, &|_| {}, &|_| {}, &|_| {});
        let canon = |p: &Path| std::fs::canonicalize(p).unwrap();
        assert_eq!(got.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>(), [canon(&plain), canon(&wt)]);
        assert!(is_git(&wt) && !is_git(&plain));
    }

    #[test]
    fn dockerfile_from_lines_and_compose_images() {
        let tmp = TempDir::new("images").unwrap();
        let f = tmp.path().join("Dockerfile");
        std::fs::write(&f, "ARG BASE=debian:13\nFROM --platform=$BUILDPLATFORM rust:1.98-slim AS build\nFROM ${BASE}\nFROM build AS test\nFROM scratch\nFROM ubuntu:24.04\n").unwrap();
        assert_eq!(from_lines(&f), ["rust:1.98-slim", "ubuntu:24.04"]);
        let c = tmp.path().join("compose.yml");
        std::fs::write(&c, "services:\n  db:\n    image: postgres:18\n  app:\n    image: \"${APP}\"\n").unwrap();
        assert_eq!(compose_images(&c), ["postgres:18"]);
        assert!(is_dockerfile("Dockerfile.dev") && is_dockerfile("api.Containerfile") && !is_dockerfile("Dockerfile."));
        assert!(is_compose("docker-compose.yml") && is_compose("compose.prod.yaml") && !is_compose("compose.json"));
    }

    #[test]
    fn install_scripts_from_npm_and_pnpm() {
        let tmp = TempDir::new("scripts").unwrap();
        let d = tmp.path();
        let lock = d.join("package-lock.json");
        std::fs::write(&lock, r#"{"packages": {"": {}, "node_modules/esbuild": {"hasInstallScript": true}, "node_modules/@x/y": {"hasInstallScript": true}, "node_modules/z": {}}}"#).unwrap();
        std::fs::write(d.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        std::fs::write(d.join("pnpm-workspace.yaml"), "packages:\n  - .\nonlyBuiltDependencies:\n  - sharp\n  - 'unrs-resolver'\nallowBuilds:\n  workerd: true\n  core-js: false\n").unwrap();
        let mut got: Vec<String> =
            install_scripts(&[lock, d.join("pnpm-lock.yaml")]).into_iter().map(|(_, n)| n).collect();
        got.sort();
        assert_eq!(got, ["@x/y", "esbuild", "sharp", "unrs-resolver", "workerd"]);
    }

    #[test]
    fn lockfiles_skip_dependency_dirs() {
        let tmp = TempDir::new("locks").unwrap();
        let d = tmp.path();
        for f in [
            "Cargo.lock",
            "web/pnpm-lock.yaml",
            "node_modules/x/package-lock.json",
            "py/requirements-dev.txt",
            "notes.txt",
        ] {
            let p = d.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "").unwrap();
        }
        let got: Vec<String> = lockfiles(d).iter().map(|p| p.strip_prefix(d).unwrap().display().to_string()).collect();
        assert_eq!(got, ["Cargo.lock", "py/requirements-dev.txt", "web/pnpm-lock.yaml"]);
        // npm-shrinkwrap.json is a lockfile, and wins over package-lock.json beside it.
        for f in ["a/npm-shrinkwrap.json", "b/npm-shrinkwrap.json", "b/package-lock.json", "c/package-lock.json"] {
            let p = d.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "").unwrap();
        }
        // The listing is memoised for a scan; a new scan forgets it.
        assert_eq!(lockfiles(d).len(), 3, "memoised");
        forget_walks();
        let got: Vec<String> = lockfiles(d).iter().map(|p| p.strip_prefix(d).unwrap().display().to_string()).collect();
        assert_eq!(
            got,
            [
                "Cargo.lock",
                "a/npm-shrinkwrap.json",
                "b/npm-shrinkwrap.json",
                "c/package-lock.json",
                "py/requirements-dev.txt",
                "web/pnpm-lock.yaml"
            ]
        );
    }
}
