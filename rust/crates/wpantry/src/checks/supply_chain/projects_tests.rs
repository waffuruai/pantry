use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::checks::supply_chain::testing::CARGO_LOCK;
use crate::utils::temp::TempDir;

/// Lockfiles are read, their packages asked of OSV (a hit fails with
/// the per-ecosystem fix), a package one keystroke from a popular one
/// in the same lockfile fails as a typosquat, and a lockfile linking
/// out of the repo is reported unchecked rather than read.
#[test]
fn projects_reads_the_lockfiles_and_reports_osv_hits() {
    let d = TempDir::new("projects").unwrap();
    let net = testing::osv_net(&[("crates.io", "serde"), ("npm", "lodash")]);
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "app");
    testing::write(&root, "Cargo.lock", CARGO_LOCK);
    testing::write(
        &root,
        "package-lock.json",
        r#"{"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app", "devDependencies": {"lodash": "4.17.20"}}, "node_modules/lodash": {"version": "4.17.20", "dev": true}}}"#,
    );
    let outside = d.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("requirements.txt"), "requests==2.0.0\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.join("requirements.txt"), root.join("requirements.txt")).unwrap();
    projects(&mut s, &[(name, root.clone())]).unwrap();
    assert!(s.counts.contains(&("project dependencies".to_string(), 3)), "{:?}", s.counts);
    let dev = testing::by_id(&s, "GHSA-lodash");
    assert_eq!(dev.len(), 1, "{:?}", s.findings);
    assert_eq!((dev[0].dep_scope.as_str(), dev[0].dep_direct), ("dev", Some(true)));
    let hit = testing::by_id(&s, "GHSA-serde");
    assert_eq!(hit.len(), 1, "{:?}", s.findings);
    let f = hit[0];
    assert_eq!(
        (f.kind.as_str(), f.component.as_str(), f.version.as_str(), f.status.as_str(), f.fixed.as_str()),
        ("project", "serde", "1.0.0", "fail", "9.9.9")
    );
    assert_eq!(f.location, root.join("Cargo.lock").to_string_lossy());
    assert_eq!(f.fix_cmd, format!("cd {} && cargo update -p serde --precise 9.9.9", quote(&root.to_string_lossy())));
    let squat = testing::by_id(&s, "SUSPECT-TYPOSQUAT");
    assert_eq!(squat.len(), 1, "{:?}", s.findings);
    assert_eq!((squat[0].component.as_str(), squat[0].status.as_str()), ("sedre (crates.io)", "fail"));
    assert!(squat[0].note.contains("both are in the lockfile"), "{}", squat[0].note);
    #[cfg(unix)]
    assert_eq!(
        testing::unchecked(&s),
        [format!("repo dependencies in {}", short(&root.join("requirements.txt").to_string_lossy()))]
    );
    assert!(!s.findings.iter().any(|f| f.kind == "license"), "licenses only with --licenses");
}

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
    assert_eq!(quote(""), "''");
    assert_eq!(
        project_fix(Path::new("/w/js/deno.lock"), "npm", "lodash", "4.17.21"),
        "Update npm:lodash to 4.17.21 in /w/js/deno.lock"
    );
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
    let tmp = crate::utils::temp::TempDir::new("yarn-fix").unwrap();
    std::fs::write(tmp.path().join("yarn.lock"), "# comment\n\n__metadata:\n  version: 8\n").unwrap();
    assert_eq!(
        project_fix(&tmp.path().join("yarn.lock"), "npm", "@scope/x", "1.0.1"),
        format!("cd {} && yarn up @scope/x@1.0.1", quote(&tmp.path().to_string_lossy()))
    );
}
