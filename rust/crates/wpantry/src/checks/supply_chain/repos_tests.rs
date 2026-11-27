use super::*;
use crate::utils::temp::TempDir;
use crate::utils::walk::forget_walks;
use std::cell::RefCell;

fn git_repo(path: &Path, worktree: bool) -> PathBuf {
    std::fs::create_dir_all(path).unwrap();
    if worktree {
        std::fs::write(path.join(".git"), "gitdir: /elsewhere\n").unwrap();
    } else {
        std::fs::create_dir(path.join(".git")).unwrap();
        std::fs::write(path.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
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
    // A downloaded template's empty .git: not a repo.
    std::fs::create_dir_all(h.join("Downloads/template/.git")).unwrap();
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
    #[cfg(unix)]
    std::os::unix::fs::symlink(git_repo(&tmp.path().join("outside"), false), h.join("link")).unwrap();
    let lines = RefCell::new(Vec::new());
    let got = scope(None, &h, &|m| lines.borrow_mut().push(m.to_string()), &|_| {}, &|_| {});
    wanted.sort();
    assert_eq!(got.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>(), wanted);
    assert!(lines.borrow()[0].contains("found 3 git repos"));
}

#[test]
fn limited_machine_scan_does_not_discover_projects_in_personal_folders() {
    let tmp = TempDir::new("personal-scope").unwrap();
    let home = tmp.path();
    let code = git_repo(&home.join("code/app"), false);
    let docs = git_repo(&home.join("Documents/private/app"), false);
    git_repo(&home.join("Desktop/app"), false);
    git_repo(&home.join("Downloads/app"), false);
    let quiet = |_: &str| {};
    let limited = scan_scope(None, home, true, &quiet, &quiet, &quiet);
    assert_eq!(limited.into_iter().map(|(_, path)| path).collect::<Vec<_>>(), [code]);
    assert_eq!(scan_scope(None, home, false, &quiet, &quiet, &quiet).len(), 4);
    let explicit = scan_scope(Some(std::slice::from_ref(&docs)), home, true, &quiet, &quiet, &quiet);
    assert_eq!(explicit[0].1, docs.canonicalize().unwrap());
}

/// Oracle: which repos the search returns from a home holding a repo in
/// each media place. On macOS the default search of `$HOME` leaves out
/// `~/Pictures`, `~/Music`, `~/Movies` and any `*.photoslibrary` or
/// `*.musiclibrary` bundle; a `--path` inside one is walked as asked; other
/// platforms keep them. Known-bad check: the same home searched with no
/// exclusions finds every planted repo, so the tree really holds them.
#[test]
fn the_default_macos_search_leaves_out_media_folders_and_library_bundles() {
    let tmp = TempDir::new("media-scope").unwrap();
    let home = tmp.path();
    let code = git_repo(&home.join("code/app"), false);
    let pictures = git_repo(&home.join("Pictures/app"), false);
    git_repo(&home.join("Music/app"), false);
    git_repo(&home.join("Movies/app"), false);
    git_repo(&home.join("elsewhere/Photos Library.photoslibrary/app"), false);
    git_repo(&home.join("elsewhere/Music Library.musiclibrary/app"), false);
    // A folder merely named like a bundle's suffix is not one.
    let plain = git_repo(&home.join("elsewhere/.photoslibrary-notes"), false);
    let quiet = |_: &str| {};
    let found = |ex: &Excluded| {
        let mut f = discover_excluding(home, ex, &quiet);
        f.sort();
        f
    };
    assert_eq!(found(&Excluded::default()).len(), 7, "every planted repo is findable");
    let mac = default_excluded(home, false, false, true);
    assert_eq!(mac.paths, ["Pictures", "Music", "Movies"].map(|d| home.join(d)));
    let mut want = vec![code.clone(), plain.clone()];
    want.sort();
    assert_eq!(found(&mac), want);
    // Elsewhere, and with explicit paths, nothing extra is left out.
    assert_eq!(default_excluded(home, false, false, false), Excluded::default());
    assert_eq!(default_excluded(home, true, true, true), Excluded::default());
    // The real search: a --path inside ~/Pictures is walked on every platform.
    let explicit = scan_scope(Some(std::slice::from_ref(&pictures)), home, true, &quiet, &quiet, &quiet);
    assert_eq!(explicit.len(), 1);
    assert_eq!(explicit[0].1, pictures.canonicalize().unwrap());
    let default = scan_scope(None, home, false, &quiet, &quiet, &quiet).len();
    assert_eq!(default, if cfg!(target_os = "macos") { 2 } else { 7 });
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
    std::fs::write(&lock, r#"{"packages": {"": {}, "node_modules/esbuild": {"version": "0.28.1", "hasInstallScript": true}, "node_modules/@x/y": {"hasInstallScript": true}, "node_modules/z": {"version": "1.0.0"}}}"#).unwrap();
    std::fs::write(
        d.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n\npackages:\n\n  sharp@0.35.5:\n    resolution: {integrity: sha512-x}\n\n  workerd@1.20261019.1:\n    resolution: {integrity: sha512-y}\n\n  workerd@1.20261031.1:\n    resolution: {integrity: sha512-z}\n",
    )
    .unwrap();
    std::fs::write(d.join("pnpm-workspace.yaml"), "packages:\n  - .\nonlyBuiltDependencies:\n  - sharp\n  - 'unrs-resolver'\nallowBuilds:\n  workerd: true\n  core-js: false\n").unwrap();
    let got: Vec<(String, Vec<String>)> =
        install_scripts(&[lock, d.join("pnpm-lock.yaml")]).into_iter().map(|s| (s.name, s.versions)).collect();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(
        got,
        [
            ("@x/y".to_string(), s(&[])),
            ("esbuild".to_string(), s(&["0.28.1"])),
            ("sharp".to_string(), s(&["0.35.5"])),
            ("unrs-resolver".to_string(), s(&[])),
            ("workerd".to_string(), s(&["1.20261019.1", "1.20261031.1"])),
        ],
        "npm entries carry their version, pnpm builds the lock's versions, unknown ones none"
    );
}

#[test]
fn lockfiles_skip_dependency_dirs() {
    let tmp = TempDir::new("locks").unwrap();
    let d = tmp.path();
    for f in
        ["Cargo.lock", "web/pnpm-lock.yaml", "node_modules/x/package-lock.json", "py/requirements-dev.txt", "notes.txt"]
    {
        let p = d.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "").unwrap();
    }
    let got: Vec<String> =
        lockfiles(d).iter().map(|p| p.strip_prefix(d).unwrap().display().to_string().replace('\\', "/")).collect();
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
    let got: Vec<String> =
        lockfiles(d).iter().map(|p| p.strip_prefix(d).unwrap().display().to_string().replace('\\', "/")).collect();
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

/// A multi-module Gradle build locks each module, not the root: the
/// lockfiles are read and the root catalog is not (it would repeat what
/// they list, at versions Gradle may not resolve), nor a locked module's
/// script. A build with no lockfile anywhere keeps its script and catalog.
#[test]
fn a_module_lockfile_covers_the_catalog() {
    let tmp = TempDir::new("gradle-modules").unwrap();
    let d = tmp.path();
    for f in [
        "multi/settings.gradle",
        "multi/build.gradle",
        "multi/gradle/libs.versions.toml",
        "multi/app/build.gradle",
        "multi/app/gradle.lockfile",
        "multi/lib/build.gradle.kts",
        "multi/lib/gradle.lockfile",
        "single/build.gradle",
        "single/gradle/libs.versions.toml",
    ] {
        let p = d.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "").unwrap();
    }
    let got: Vec<String> =
        lockfiles(d).iter().map(|p| p.strip_prefix(d).unwrap().display().to_string().replace('\\', "/")).collect();
    assert_eq!(
        got,
        [
            "multi/app/gradle.lockfile",
            "multi/build.gradle",
            "multi/lib/gradle.lockfile",
            "single/build.gradle",
            "single/gradle/libs.versions.toml"
        ]
    );
}

/// Oracle: under `--no-personal-files` an explicit `--path` that
/// holds `~/Documents` (here the home folder itself) finds no repo inside
/// it, while a `--path` inside Documents is scanned as asked; without the
/// flag both are found. Known bad: before the fix explicit paths excluded
/// nothing, so `--path ~` found the Documents repo too.
#[test]
fn no_personal_files_keeps_documents_out_of_a_path_that_holds_it() {
    let tmp = TempDir::new("scope").unwrap();
    let h = tmp.path().join("home");
    let code = git_repo(&h.join("code/a"), false);
    let docs = git_repo(&h.join("Documents/b"), false);
    git_repo(&h.join("Desktop/c"), false);
    let quiet = |_: &str| {};
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap();
    let roots = |r: Vec<Repo>| r.into_iter().map(|(_, p)| p).collect::<Vec<_>>();
    let home = [h.clone()];
    assert_eq!(roots(scan_scope(Some(&home), &h, true, &quiet, &quiet, &quiet)), [canon(&code)]);
    assert_eq!(roots(scan_scope(Some(&home), &h, false, &quiet, &quiet, &quiet)).len(), 3);
    let inside = [docs.clone()];
    assert_eq!(roots(scan_scope(Some(&inside), &h, true, &quiet, &quiet, &quiet)), [canon(&docs)]);
    assert_eq!(personal_under(&h, &h.join("Documents")), Vec::<PathBuf>::new(), "a named folder is scanned");
}

/// A source file named after Docker is not a Dockerfile (`Dockerfile.py`
/// matched the `Dockerfile.` prefix and its `from x import y` lines were
/// read as `FROM`), and a line is a `FROM` only when it has the shape of the
/// instruction: `FROM [--flag]... IMAGE [AS STAGE]`.
#[test]
fn a_python_file_named_after_docker_is_not_a_dockerfile() {
    for name in [
        "Dockerfile",
        "dockerfile",
        "Dockerfile.dev",
        "Dockerfile.prod.ci",
        "Containerfile.base",
        "api.Dockerfile",
        "web.containerfile",
    ] {
        assert!(is_dockerfile(name), "{name}");
    }
    for name in [
        "Dockerfile.py",
        "dockerfile.PY",
        "Dockerfile.dev.py",
        "Containerfile.rs",
        "Dockerfile.md",
        "Dockerfile.",
        "Dockerfile.json",
        ".dockerfile",
    ] {
        assert!(!is_dockerfile(name), "{name}");
    }
    let tmp = TempDir::new("py-dockerfile").unwrap();
    let py = tmp.path().join("Dockerfile.py");
    let source = "from importlib.metadata import version\nfrom . import x\nfrom os import *\nfrom a.b import (c,\n    d)\nprint(version('x'))\n";
    std::fs::write(&py, source).unwrap();
    assert!(from_lines(&py).is_empty(), "no line of that file is a FROM instruction");
    assert!(repo_images(&[("app".into(), tmp.path().to_path_buf())]).is_empty());
    // Real Dockerfile lines still count, however spelled.
    let df = tmp.path().join("Dockerfile");
    std::fs::write(&df, "from debian:12\nFROM --platform=linux/amd64 nginx:1.27 as web\nFROM web AS again\nFROM x y\nfrom a import b\nFROM\n").unwrap();
    assert_eq!(from_lines(&df), ["debian:12", "nginx:1.27"]);
}

/// Risk: the repo search lists a search root before it asks whether it is left
/// out, so a root that is a link into a left-out folder (`~/code ->
/// ~/Documents/code`) was listed and its repos found. Oracle: a repo planted
/// in the folder is found through the link without a guard, and not with one.
/// Cannot notice a stat: it sees what was found. Known bad: no check on the
/// root before `read_dir`.
#[cfg(unix)]
#[test]
fn a_search_root_that_is_a_link_into_a_left_out_folder_finds_nothing() {
    let tmp = TempDir::new("root-link").unwrap();
    let h = std::fs::canonicalize(tmp.path()).unwrap().join("home");
    git_repo(&h.join("Documents/code/app"), false);
    std::os::unix::fs::symlink("Documents/code", h.join("code")).unwrap();
    let quiet = |_: &str| {};
    assert_eq!(
        discover_excluding(&h.join("code"), &Excluded::default(), &quiet).len(),
        1,
        "findable without the guard"
    );
    let _guard = crate::utils::privacy::leave_out(vec![h.join("Documents")], Vec::new());
    assert!(discover_excluding(&h.join("code"), &Excluded::default(), &quiet).is_empty());
}
