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
