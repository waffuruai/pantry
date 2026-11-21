use super::*;
#[cfg(unix)]
use crate::checks::Options;
#[cfg(unix)]
use crate::checks::supply_chain::testing;
#[cfg(unix)]
use crate::checks::supply_chain::testing::CARGO_LOCK;
#[cfg(unix)]
use crate::utils::temp::TempDir;

/// Lockfiles are read, their packages asked of OSV (a hit fails with
/// the per-ecosystem fix), a package one keystroke from a popular one
/// in the same lockfile fails as a typosquat, and a lockfile linking
/// out of the repo is reported unchecked rather than read.
#[cfg(unix)]
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
    // `Path` only splits `\` on Windows. The string form is tested in utils::files::command_path.
    #[cfg(windows)]
    assert_eq!(
        project_fix(Path::new(r"\\?\C:\code\app\Cargo.lock"), "crates.io", "regex", "1.5.5"),
        "cd C:/code/app && cargo update -p regex --precise 1.5.5"
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
        fix("/w/cs/App.csproj", "NuGet", "Newtonsoft.Json", "13.0.1"),
        "cd /w/cs && dotnet add App.csproj package Newtonsoft.Json --version 13.0.1"
    );
    assert_eq!(
        fix("/w/cs/packages.config", "NuGet", "log4net", "2.0.15"),
        "Update log4net to 2.0.15 in /w/cs/packages.config"
    );
    assert_eq!(
        fix("/w/cs/Directory.Build.props", "NuGet", "log4net", "2.0.15"),
        "Update log4net to 2.0.15 in /w/cs/Directory.Build.props"
    );
    assert_eq!(
        fix("/w/x/Gemfile.lock", "RubyGems", "evil;rm", "1"),
        "cd /w/x && bundle update --conservative 'evil;rm'"
    );
    let tmp = crate::utils::temp::TempDir::new("yarn-fix").unwrap();
    std::fs::write(tmp.path().join("yarn.lock"), "# comment\n\n__metadata:\n  version: 8\n").unwrap();
    assert_eq!(
        project_fix(&tmp.path().join("yarn.lock"), "npm", "@scope/x", "1.0.1"),
        format!("cd {} && yarn up @scope/x@1.0.1", quote(&command_path(tmp.path())))
    );
}

/// A go.mod's Go is checked as its toolchain too, at the version Go builds
/// with (the `toolchain` directive, else `go`): a toolchain-only advisory
/// fails it, one filed under `stdlib` and `toolchain` is one finding, and
/// a fixed release is clean.
#[test]
fn a_go_mod_is_checked_as_its_toolchain_too() {
    use crate::checks::supply_chain::testing;
    let d = crate::utils::temp::TempDir::new("gotc").unwrap();
    let net = crate::checks::machine::testing::go_osv();
    let mut s = testing::scan(&net, &d, crate::checks::Options::default());
    let (old, old_root) = testing::repo(&d, "old");
    testing::write(&old_root, "go.mod", "module example.com/old\n\ngo 1.22\n\ntoolchain go1.26.10\n");
    let (new, new_root) = testing::repo(&d, "new");
    testing::write(&new_root, "go.mod", "module example.com/new\n\ngo 1.27.4\n");
    projects(&mut s, &[(old, old_root.clone()), (new, new_root)]).unwrap();
    // One dependency per go.mod: the toolchain isn't a second one.
    assert!(s.counts.contains(&("project dependencies".to_string(), 2)), "{:?}", s.counts);
    let got: Vec<(&str, &str, &str, &str)> = s
        .findings
        .iter()
        .map(|f| (f.component.as_str(), f.vuln_id.as_str(), f.version.as_str(), f.fixed.as_str()))
        .collect();
    assert_eq!(
        got,
        [("stdlib", "CVE-2026-0002", "1.26.10", "1.26.11"), ("stdlib", "CVE-2026-0001", "1.26.10", "1.26.11")],
        "{:?}",
        s.findings
    );
    assert!(s.findings.iter().all(|f| f.location == command_path(&old_root.join("go.mod"))), "{:?}", s.findings);
    // The fix raises the toolchain line, the one that sets the version.
    let want = format!("cd {} && go get toolchain@go1.26.11", quote(&command_path(&old_root)));
    assert!(s.findings.iter().all(|f| f.fix_cmd == want), "{:?}", s.findings);
}

/// A go.mod's Go is raised on the line that sets it: the `toolchain` line
/// when there is one, else the `go` line; a module's fix stays `go get`
/// of that module.
#[test]
fn a_go_mod_go_version_is_raised_on_the_line_that_sets_it() {
    let d = crate::utils::temp::TempDir::new("gotcfix").unwrap();
    let write = |dir: &str, text: &str| {
        let p = d.path().join(dir).join("go.mod");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        p
    };
    let with = write("with", "module m\n\ngo 1.22\n\ntoolchain go1.26.10 // pinned\n");
    let without = write("without", "module m\n\ngo 1.27.3\n\n// toolchain go1.20 is only a comment\n");
    let dir = |p: &Path| quote(&command_path(p.parent().unwrap()));
    let fill = |cmd: String| crate::checks::fill(&cmd, "1.26.11");
    assert_eq!(
        fill(project_fix(&with, "Go", "stdlib", "{safe}")),
        format!("cd {} && go get toolchain@go1.26.11", dir(&with))
    );
    assert_eq!(
        fill(project_fix(&without, "Go", "stdlib", "{safe}")),
        format!("cd {} && go get go@1.26.11", dir(&without))
    );
    assert_eq!(
        project_fix(&with, "Go", "golang.org/x/net", "0.23.0"),
        format!("cd {} && go get golang.org/x/net@v0.23.0 && go mod tidy", dir(&with))
    );
}

/// .NET projects without a lock: versions on the reference, through
/// central package management and in packages.config go to OSV; a
/// version through an undefined property is a not-checked row, not a
/// clean project; a project with its own packages.lock.json is read
/// through the lock only.
#[cfg(unix)]
#[test]
fn dotnet_projects_without_a_lock_are_read() {
    let d = TempDir::new("projects-dotnet").unwrap();
    let net = testing::osv_net(&[("NuGet", "Newtonsoft.Json"), ("NuGet", "System.Text.Json"), ("NuGet", "log4net")]);
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "dotnet");
    let refs = |items: &str| format!("<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup>{items}</ItemGroup></Project>");
    testing::write(&root, "app/App.csproj", refs(r#"<PackageReference Include="Newtonsoft.Json" Version="9.0.1" />"#));
    testing::write(
        &root,
        "Directory.Packages.props",
        r#"<Project><ItemGroup><PackageVersion Include="System.Text.Json" Version="8.0.0" /></ItemGroup></Project>"#,
    );
    testing::write(&root, "svc/Svc.csproj", refs(r#"<PackageReference Include="System.Text.Json" />"#));
    testing::write(&root, "legacy/packages.config", r#"<packages><package id="log4net" version="2.0.8" /></packages>"#);
    testing::write(&root, "bad/Bad.csproj", refs(r#"<PackageReference Include="Foo" Version="$(Undefined)" />"#));
    testing::write(&root, "locked/Locked.csproj", refs(r#"<PackageReference Include="Bar" Version="$(Undefined)" />"#));
    testing::write(&root, "locked/packages.lock.json", r#"{"version": 1, "dependencies": {"net8.0": {}}}"#);
    // Locked and not readable here: the lock is read, the project never is.
    testing::write(&root, "locked2/Odd.csproj", "<Project");
    testing::write(&root, "locked2/packages.lock.json", r#"{"version": 1, "dependencies": {"net8.0": {}}}"#);
    projects(&mut s, &[(name, root.clone())]).unwrap();
    assert!(s.counts.contains(&("project dependencies".to_string(), 3)), "{:?}", s.counts);
    for (id, file, version) in [
        ("GHSA-Newtonsoft.Json", "app/App.csproj", "9.0.1"),
        ("GHSA-System.Text.Json", "svc/Svc.csproj", "8.0.0"),
        ("GHSA-log4net", "legacy/packages.config", "2.0.8"),
    ] {
        let hit = testing::by_id(&s, id);
        assert_eq!(hit.len(), 1, "{id}: {:?}", s.findings);
        assert_eq!((hit[0].status.as_str(), hit[0].version.as_str()), ("fail", version));
        assert_eq!(hit[0].location, root.join(file).to_string_lossy());
    }
    assert_eq!(
        testing::unchecked(&s),
        [format!("repo dependencies in {}", short(&root.join("bad/Bad.csproj").to_string_lossy()))]
    );
    let row = s.findings.iter().find(|f| f.kind == "unchecked").unwrap();
    assert!(row.note.starts_with("not exact or not resolved: Foo $(Undefined)"), "{}", row.note);
}

/// A reference in Directory.Build.props is one finding at that file per
/// (package, version), however many projects import it; one whose
/// version each project sets is one finding per version. The fix edits
/// the props file.
#[cfg(unix)]
#[test]
fn a_props_reference_is_reported_once() {
    let d = TempDir::new("projects-props").unwrap();
    let net = testing::osv_net(&[("NuGet", "Newtonsoft.Json"), ("NuGet", "log4net")]);
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "dotnet");
    testing::write(
        &root,
        "Directory.Build.props",
        r#"<Project><ItemGroup>
  <PackageReference Include="Newtonsoft.Json" Version="9.0.1" />
  <PackageReference Include="log4net" Version="$(LogVersion)" />
</ItemGroup></Project>"#,
    );
    let with = |v: &str| format!("<Project><PropertyGroup><LogVersion>{v}</LogVersion></PropertyGroup></Project>");
    for (dir, v) in [("a/A.csproj", "2.0.8"), ("b/B.csproj", "2.0.8"), ("c/C.csproj", "2.0.10")] {
        testing::write(&root, dir, with(v));
    }
    projects(&mut s, &[(name, root.clone())]).unwrap();
    let props = root.join("Directory.Build.props").to_string_lossy().into_owned();
    let json = testing::by_id(&s, "GHSA-Newtonsoft.Json");
    assert_eq!(json.len(), 1, "{:?}", s.findings);
    assert_eq!(json[0].location, props);
    assert!(json[0].fix_cmd.starts_with("Update Newtonsoft.Json to "), "{}", json[0].fix_cmd);
    assert!(json[0].fix_cmd.ends_with("Directory.Build.props"), "{}", json[0].fix_cmd);
    let mut log: Vec<(&str, &str)> =
        testing::by_id(&s, "GHSA-log4net").iter().map(|f| (f.version.as_str(), f.location.as_str())).collect();
    log.sort();
    assert_eq!(log, [("2.0.10", props.as_str()), ("2.0.8", props.as_str())]);
    assert!(s.counts.contains(&("project dependencies".to_string(), 3)), "{:?}", s.counts);
}

/// OSV as it answers for Log4Shell (an advisory aliasing CVE-2021-44228,
/// fixed in 2.15.0) and for jackson-databind 2.9.8 (one fixed in 2.9.9).
#[cfg(unix)]
fn jvm_osv(r: &crate::utils::net::Request) -> Result<crate::utils::net::Response> {
    use crate::utils::net::Response;
    use serde_json::{Value, json};
    let advisories = [
        ("org.apache.logging.log4j:log4j-core", "GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "2.0-beta9", "2.15.0"),
        ("com.fasterxml.jackson.core:jackson-databind", "GHSA-test-jackson", "CVE-2019-12086", "2.9.0", "2.9.9"),
    ];
    if r.url.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
        return Ok(Response::not_found());
    }
    if r.url.ends_with("/v1/querybatch") {
        let body: Value = serde_json::from_slice(r.body.as_ref().unwrap()).unwrap();
        let results: Vec<Value> = body["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| {
                match advisories.iter().find(|a| q["package"]["name"] == a.0 && q["package"]["ecosystem"] == "Maven") {
                    Some(a) => json!({"vulns": [{"id": a.1, "modified": "2026-01-01T00:00:00Z"}]}),
                    None => json!({}),
                }
            })
            .collect();
        return Ok(Response::ok(json!({"results": results}).to_string()));
    }
    let id = r.url.strip_prefix("https://api.osv.dev/v1/vulns/").unwrap_or_else(|| panic!("unexpected {}", r.url));
    let a = advisories.iter().find(|a| a.1 == id).unwrap_or_else(|| panic!("unexpected {id}"));
    let rec = json!({
        "id": a.1, "aliases": [a.2], "modified": "2026-01-01T00:00:00Z", "summary": format!("{} is vulnerable", a.0),
        "database_specific": {"severity": "CRITICAL"},
        "affected": [{"package": {"ecosystem": "Maven", "name": a.0},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": a.3}, {"fixed": a.4}]}]}]
    });
    Ok(Response::ok(rec.to_string()))
}

/// A Gradle build without a lockfile: a log4j-core 2.14.1 literal warns
/// on CVE-2021-44228 marked exploited, a catalog's jackson-databind 2.9.8
/// warns, each noting the version is declared, not resolved (a BOM can
/// raise it); the interpolated `"org.x:y:$ver"` is counted not checked
/// without an `unchecked` row (which would stop history resolving
/// anything); a module with a `gradle.lockfile` is read from the lockfile
/// alone, and the same log4j-core locked there still fails.
#[cfg(unix)]
#[test]
fn gradle_builds_without_a_lockfile_are_read() {
    let d = TempDir::new("projects-gradle").unwrap();
    let net = crate::utils::net::Fake::new(jvm_osv);
    let logged = std::cell::RefCell::new(Vec::<String>::new());
    let log = |m: &str| logged.borrow_mut().push(m.to_string());
    let mut s = testing::scan(&net, &d, Options::default());
    s.kev = ["CVE-2021-44228".to_string()].into();
    let (name, root) = testing::repo(&d, "jvm");
    testing::write(
        &root,
        "build.gradle",
        "plugins { id 'java' }\ndependencies {\n    implementation 'org.apache.logging.log4j:log4j-core:2.14.1'\n    implementation \"org.x:y:$ver\"\n}\n",
    );
    testing::write(
        &root,
        "kts/build.gradle.kts",
        "plugins { java }\ndependencies { implementation(libs.jackson.databind) }\n",
    );
    testing::write(
        &root,
        "kts/gradle/libs.versions.toml",
        "[versions]\njackson = \"2.9.8\"\n\n[libraries]\njackson-databind = { module = \"com.fasterxml.jackson.core:jackson-databind\", version.ref = \"jackson\" }\n",
    );
    testing::write(&root, "locked/build.gradle", "dependencies { implementation \"org.z:z:$v\" }\n");
    testing::write(
        &root,
        "locked/gradle.lockfile",
        "org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath\nempty=\n",
    );
    s.log = &log;
    projects(&mut s, &[(name, root.clone())]).unwrap();
    assert!(s.counts.contains(&("project dependencies".to_string(), 3)), "{:?}", s.counts);
    let log4shell = testing::by_id(&s, "CVE-2021-44228");
    assert_eq!(log4shell.len(), 2, "{:?}", s.findings);
    let locked = log4shell.iter().find(|f| f.location.ends_with("gradle.lockfile")).unwrap();
    assert_eq!((locked.status.as_str(), locked.kev), ("fail", true), "a locked version is resolved");
    assert!(!locked.note.contains("declared"), "{}", locked.note);
    let f = log4shell.iter().find(|f| f.location.ends_with("build.gradle")).unwrap();
    assert_eq!(
        (f.component.as_str(), f.version.as_str(), f.status.as_str(), f.fixed.as_str(), f.kev),
        ("org.apache.logging.log4j:log4j-core", "2.14.1", "warn", "2.15.0", true)
    );
    assert!(f.note.ends_with(&format!("({})", lockfiles::gradle_build::DECLARED)), "{}", f.note);
    assert_eq!(f.dep_direct, Some(true));
    assert_eq!(f.location, root.join("build.gradle").to_string_lossy());
    assert_eq!(
        f.fix_cmd,
        format!("Update org.apache.logging.log4j:log4j-core to 2.15.0 in {}", root.join("build.gradle").display())
    );
    let jackson = testing::by_id(&s, "CVE-2019-12086");
    assert_eq!(jackson.len(), 1, "{:?}", s.findings);
    assert_eq!((jackson[0].version.as_str(), jackson[0].status.as_str(), jackson[0].kev), ("2.9.8", "warn", false));
    assert!(jackson[0].note.contains("not resolved"), "{}", jackson[0].note);
    assert_eq!(jackson[0].location, root.join("kts/gradle/libs.versions.toml").to_string_lossy());
    // The variable is not checked, and only where no lockfile covers it:
    // counted and logged, not an `unchecked` row.
    assert!(testing::unchecked(&s).is_empty(), "{:?}", testing::unchecked(&s));
    assert!(s.counts.contains(&(GRADLE_UNRESOLVED.to_string(), 1)), "{:?}", s.counts);
    let logged = logged.borrow();
    let line = logged.iter().find(|l| l.contains("not checked")).unwrap();
    assert!(line.contains("build.gradle: 1 not checked"), "{line}");
    assert!(line.contains("implementation \"org.x:y:$ver\" (version from a variable)"), "{line}");
    assert_eq!(logged.iter().filter(|l| l.contains("not checked")).count(), 1, "{logged:?}");
}
