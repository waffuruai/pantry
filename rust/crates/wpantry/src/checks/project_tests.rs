use super::*;
use crate::checks::machine::testing::{self, write};
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;

fn pin(tool: &'static str, version: &str, file: &Path) -> Pin {
    Pin { tool, version: version.into(), file: file.to_path_buf() }
}

fn install(name: &str, version: &str, path: &str) -> Component {
    Component::new("runtime", name, version, path)
}

#[test]
fn a_pinned_version_is_read_whatever_stands_before_it() {
    for (raw, want) in [
        ("3.3.5\n", "3.3.5"),
        ("v20.11.0", "20.11.0"),
        ("ruby-3.3.5", "3.3.5"),
        ("go1.22.3", "1.22.3"),
        ("temurin-21.0.2+13", "21.0.2"),
        ("# the team's node\n22\n", "22"),
        ("3.12 3.11", "3.12"),
        // Names, not versions.
        ("lts/iron", ""),
        ("stable", ""),
        ("nightly-2026-01-01", ""),
        ("system", ""),
        ("", ""),
    ] {
        assert_eq!(version(raw), want, "{raw:?}");
    }
}

#[test]
fn each_pin_file_names_its_runtime() {
    let d = TempDir::new("pins").unwrap();
    let r = d.path();
    write(&r.join(".ruby-version"), "3.3.5\n");
    write(&r.join(".nvmrc"), "v20.11.0\n");
    write(&r.join(".python-version"), "3.12\n");
    write(&r.join("rust-toolchain.toml"), "[toolchain]\nchannel = \"1.90.0\"\ncomponents = [\"clippy\"]\n");
    write(&r.join("go.mod"), "module x\n\ngo 1.25\n\ntoolchain go1.25.4\n");
    write(&r.join(".java-version"), "21\n");
    assert_eq!(
        pins(r),
        [
            pin("ruby", "3.3.5", &r.join(".ruby-version")),
            pin("node", "20.11.0", &r.join(".nvmrc")),
            pin("python", "3.12", &r.join(".python-version")),
            pin("go", "1.25.4", &r.join("go.mod")),
            pin("rust", "1.90.0", &r.join("rust-toolchain.toml")),
            pin("java", "21", &r.join(".java-version")),
        ]
    );
}

#[test]
fn mise_wins_over_tool_versions_which_wins_over_a_runtimes_own_file() {
    let d = TempDir::new("pins").unwrap();
    let r = d.path();
    // The tasks' multi-line strings aren't read, and don't stop the read.
    write(
        &r.join("mise.toml"),
        "[tools]\nnode = \"26.12.1\"  # the viewer tests\n\"python\" = { version = \"3.15.2\" }\ngo = [\"1.25.4\", \"1.24.9\"]\nshellcheck = \"0.11.0\"\nruby = \"latest\"\n\n[tasks.test]\nrun = '''\ncase x in\n  all) y ;;\nesac\n'''\n",
    );
    write(&r.join(".tool-versions"), "nodejs 20.11.0\nruby 3.3.5 # ours\ngolang 1.22.0\nunknown 1.0\n");
    write(&r.join(".ruby-version"), "3.2.0\n");
    write(&r.join(".node-version"), "18.0.0\n");
    assert_eq!(
        pins(r),
        [
            pin("node", "26.12.1", &r.join("mise.toml")),
            pin("python", "3.15.2", &r.join("mise.toml")),
            pin("go", "1.25.4", &r.join("mise.toml")),
            // mise's `latest` names no version: asdf's file is next.
            pin("ruby", "3.3.5", &r.join(".tool-versions")),
        ]
    );
}

#[test]
fn a_manifest_says_the_runtime_is_used_and_may_name_its_version() {
    let d = TempDir::new("pins").unwrap();
    let r = d.path();
    write(&r.join("Gemfile"), "source 'https://rubygems.org'\n");
    write(&r.join("Gemfile.lock"), "GEM\n\nRUBY VERSION\n   ruby 3.3.5p100\n\nBUNDLED WITH\n   2.5.0\n");
    write(&r.join("package.json"), r#"{"name": "x", "volta": {"node": "22.1.0"}}"#);
    write(&r.join("pyproject.toml"), "[project]\nname = \"x\"\n");
    write(&r.join("Cargo.toml"), "[package]\nname = \"x\"\n");
    write(&r.join("rust-toolchain"), "stable\n");
    write(&r.join("go.mod"), "module x\n\ngo 1.25\n");
    assert_eq!(
        pins(r),
        [
            pin("ruby", "3.3.5", &r.join("Gemfile.lock")),
            pin("node", "22.1.0", &r.join("package.json")),
            pin("go", "1.25", &r.join("go.mod")),
            // Used, not pinned: `stable` is whatever is installed.
            pin("python", "", &r.join("pyproject.toml")),
            pin("rust", "", &r.join("Cargo.toml")),
        ]
    );
    // Nothing a runtime is read from: no runtime.
    let empty = TempDir::new("pins").unwrap();
    write(&empty.path().join("README.md"), "# x\n");
    write(&empty.path().join("package.json"), "not json");
    assert_eq!(pins(empty.path()), [pin("node", "", &empty.path().join("package.json"))]);
    assert_eq!(pins(&empty.path().join("nowhere")), []);
}

#[test]
fn a_package_takes_the_pin_of_the_folder_above_and_every_package_counts() {
    let d = TempDir::new("pins").unwrap();
    let r = d.path();
    write(&r.join(".tool-versions"), "nodejs 22.1.0\n");
    write(&r.join("web/package.json"), "{}");
    write(&r.join("api/package.json"), "{}");
    write(&r.join("api/.nvmrc"), "20.11.0\n");
    write(&r.join("rust/Cargo.toml"), "[workspace]\n");
    write(&r.join("rust/rust-toolchain.toml"), "[toolchain]\nchannel = \"1.90.0\"\n");
    write(&r.join("docs/guide.md"), "# guide\n");
    // Dependency folders aren't the project's packages.
    write(&r.join("web/node_modules/dep/package.json"), "{}");
    write(&r.join("web/node_modules/dep/.nvmrc"), "4.0.0\n");
    assert_eq!(pins(&r.join("web")), [pin("node", "22.1.0", &r.join(".tool-versions"))]);
    let mut found = all(r);
    found.sort_by(|a, b| (a.tool, &a.version).cmp(&(b.tool, &b.version)));
    assert_eq!(
        found,
        [
            pin("node", "20.11.0", &r.join("api/.nvmrc")),
            pin("node", "22.1.0", &r.join(".tool-versions")),
            pin("rust", "1.90.0", &r.join("rust/rust-toolchain.toml")),
        ]
    );
}

#[test]
fn a_pin_picks_the_newest_install_it_matches() {
    let ruby = tool("ruby").unwrap();
    let installs = [
        install("ruby", "2.6.10", "/usr/bin/ruby"),
        install("ruby", "3.3.1", "/h/.rbenv/versions/3.3.1/bin/ruby"),
        install("ruby", "3.3.5", "/h/.rbenv/versions/3.3.5/bin/ruby"),
        install("ruby", "3.30.0", "/h/.rbenv/versions/3.30.0/bin/ruby"),
    ];
    let file = Path::new("/p/.ruby-version");
    assert_eq!(choose(&pin("ruby", "3.3.1", file), ruby, &installs), Choice::Check(installs[1].clone()));
    // Part of a version: the newest of that line, and 3.30 isn't 3.3.
    assert_eq!(choose(&pin("ruby", "3.3", file), ruby, &installs), Choice::Check(installs[2].clone()));
    // Not pinned: the first on PATH, old as it is.
    assert_eq!(choose(&pin("ruby", "", file), ruby, &installs), Choice::Check(installs[0].clone()));
    assert_eq!(choose(&pin("ruby", "", file), ruby, &[]), Choice::Nothing);
}

#[test]
fn a_full_pin_that_isnt_installed_is_checked_as_pinned() {
    let file = Path::new("/p/.ruby-version");
    let Choice::Check(c) = choose(&pin("ruby", "3.1.4", file), tool("ruby").unwrap(), &[]) else { panic!("checked") };
    assert_eq!(
        (c.kind.as_str(), c.name.as_str(), c.version.as_str(), c.path.as_str()),
        ("runtime", "ruby", "3.1.4", "/p/.ruby-version")
    );
    assert_eq!(c.osv, Some(("GIT".into(), "https://github.com/ruby/ruby.git".into(), "v3_1_4".into())));
    assert_eq!(c.eol, Some(("ruby".into(), "3.1".into())));
    assert_eq!((c.fix.as_str(), c.auto), ("Pin ruby to {safe} in /p/.ruby-version", false));
    // Go is filed under two OSV packages.
    let Choice::Check(go) = choose(&pin("go", "1.26.10", Path::new("/p/go.mod")), tool("go").unwrap(), &[]) else {
        panic!("checked")
    };
    assert_eq!(go.osv_also, [("Go".to_string(), "toolchain".to_string(), "1.26.10".to_string())]);
    // Python is ours, not the catalog's.
    let Choice::Check(py) = choose(&pin("python", "3.12.4", Path::new("/p/mise.toml")), tool("python").unwrap(), &[])
    else {
        panic!("checked")
    };
    assert_eq!(py.eol, Some(("python".into(), "3.12".into())));
    assert!(tool("cobol").is_none());
}

#[test]
fn part_of_a_version_with_no_install_keeps_only_its_release_line() {
    let line = |tool_name: &'static str, v: &str| match choose(
        &pin(tool_name, v, Path::new("/p/pin")),
        tool(tool_name).unwrap(),
        &[],
    ) {
        Choice::Missing(c) => c.map(|c| (c.osv.clone(), c.eol.clone().unwrap().1)),
        other => panic!("{other:?}"),
    };
    // Node counts by major, Ruby by minor: `3` names no Ruby line.
    assert_eq!(line("node", "18"), Some((None, "18".into())));
    assert_eq!(line("ruby", "2.7"), Some((None, "2.7".into())));
    assert_eq!(line("ruby", "3"), None);
    // endoflife.date has no Rust page.
    assert_eq!(line("rust", "1.90"), None);
}

/// OSV with one advisory for Ruby 3.1.4, and nothing else reachable.
fn ruby_osv() -> Fake {
    Fake::new(|r| {
        let url = r.url.as_str();
        if url.ends_with("/querybatch") {
            let body = r.body.clone().unwrap_or_default();
            return Ok(testing::querybatch(&body, &|_, v| if v == "v3_1_4" { vec!["CVE-2026-0101"] } else { vec![] }));
        }
        if url == "https://api.osv.dev/v1/vulns/CVE-2026-0101" {
            let rec = serde_json::json!({"id": "CVE-2026-0101", "modified": "m", "summary": "Ruby bug",
                "affected": [{"package": {"ecosystem": "GIT", "name": "https://github.com/ruby/ruby.git"},
                              "ranges": [{"type": "GIT", "repo": "https://github.com/ruby/ruby.git",
                                          "events": [{"introduced": "0"}, {"fixed": "abc"}]}],
                              "versions": ["v3_1_4"]}]});
            return Ok(Response::ok(rec.to_string()));
        }
        Ok(Response::not_found())
    })
}

#[test]
fn a_project_scan_checks_the_runtimes_it_uses_and_no_other() {
    let d = TempDir::new("project").unwrap();
    let root = d.path().join("app");
    write(&root.join(".ruby-version"), "3.1.4\n");
    write(&root.join("package.json"), "{}");
    write(&root.join("web/.nvmrc"), "18\n");
    write(&root.join("web/package.json"), "{}");
    write(&root.join("Cargo.toml"), "[package]\n");
    let net = ruby_osv();
    let mut s = testing::scan(&net, &d);
    let ended = serde_json::json!([
        {"cycle": "3.4", "eol": "2099-01-01", "latest": "3.4.9"},
        {"cycle": "3.1", "eol": "2025-03-31", "latest": "3.1.7"},
    ]);
    crate::sources::endoflife::store_for_tests(&s.cache, "ruby", &ended);
    let node = serde_json::json!([
        {"cycle": "22", "eol": "2099-01-01", "latest": "22.9.0"},
        {"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8"},
    ]);
    crate::sources::endoflife::store_for_tests(&s.cache, "nodejs", &node);
    s.repos = vec![("app".into(), root.clone())];
    let said = std::sync::Mutex::new(Vec::new());
    let log = |m: &str| said.lock().unwrap().push(m.to_string());
    s.log = &log;
    // The machine: three Rubies and two Nodes; the project names neither
    // Ruby installed, and its root uses whatever Node is first.
    let asked = std::sync::Mutex::new(Vec::new());
    let installs = |t: &Tool| {
        asked.lock().unwrap().push(t.name);
        match t.name {
            "ruby" => vec![
                install("ruby", "2.6.10", "/usr/bin/ruby"),
                install("ruby", "3.4.9", "/h/.rbenv/versions/3.4.9/bin/ruby"),
            ],
            "node" => vec![
                install("node", "22.9.0", "/h/bin/node"),
                install("node", "16.0.0", "/h/.nvm/versions/node/v16.0.0/bin/node"),
            ],
            _ => Vec::new(),
        }
    };
    let chosen = run_with(&mut s, &installs).unwrap();
    let names: Vec<(&str, &str)> = chosen.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
    assert_eq!(names, [("ruby", "3.1.4"), ("node", "22.9.0")]);
    // Each tool's installs are found once, whatever number of packages use it.
    assert_eq!(*asked.lock().unwrap(), ["ruby", "node", "rust"]);
    let pinned_in = crate::utils::files::short(&root.join(".ruby-version").to_string_lossy());
    assert_eq!(
        *said.lock().unwrap(),
        [format!("  project runtimes: ruby 3.1.4 (pinned in {pinned_in}), node 22.9.0 (first on PATH)")]
    );
    assert!(s.counts.contains(&("project runtimes".to_string(), 2)));
    let mut got = testing::kinds(&s);
    got.sort();
    let node18 = format!("node 18 ({})", crate::utils::files::short(&root.join("web/.nvmrc").to_string_lossy()));
    assert_eq!(
        got,
        [
            ("node".to_string(), "EOL".to_string(), "fail".to_string()),
            (node18.clone(), "UNCHECKED".to_string(), "warn".to_string()),
            ("ruby".to_string(), "CVE-2026-0101".to_string(), "fail".to_string()),
            ("ruby".to_string(), "EOL".to_string(), "fail".to_string()),
        ]
    );
    assert!(testing::unchecked_note(&s, &node18).starts_with("the project pins part of a version"));
    // The pinned Ruby sits at its pin file; the old ones installed aren't reported.
    let ruby = s.findings.iter().find(|f| f.vuln_id == "CVE-2026-0101").unwrap();
    assert_eq!(ruby.location, root.join(".ruby-version").to_string_lossy());
    assert!(s.findings.iter().all(|f| f.version != "2.6.10" && f.version != "16.0.0"));
}

#[test]
fn a_project_with_no_runtime_checks_none() {
    let d = TempDir::new("project").unwrap();
    write(&d.path().join("docs/README.md"), "# x\n");
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    s.repos = vec![("docs".into(), d.path().join("docs"))];
    assert_eq!(run_with(&mut s, &|_| panic!("no runtime to find")).unwrap(), []);
    assert!(s.findings.is_empty() && s.counts.is_empty());
}
