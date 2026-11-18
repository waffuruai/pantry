use super::*;

#[test]
fn cycles_name_a_release_line() {
    assert_eq!(Cycle::Major.of("3.12.4"), "3");
    assert_eq!(Cycle::Minor.of("3.12.4"), "3.12");
    assert_eq!(Cycle::Minor.of("3"), "3");
    assert_eq!(Cycle::Java.of("1.8.0_392"), "8");
    assert_eq!(Cycle::Java.of("1."), "");
    assert_eq!(Cycle::Java.of("21.0.5"), "21");
}

/// What OSV answered for one version of each catalog GIT mapping,
/// recorded (see the file's header).
const OSV_GIT: &str = include_str!("../../../tests/osv-git-mappings.toml");

/// Guards the catalog's GIT mappings: OSV resolves a release tag to
/// advisories only when its records carry ranges for that repo, and when
/// they don't the answer is empty, which reads as clean. Every mapping has a
/// recorded answer; an empty one must be marked, either `empty` (broken for
/// a version a named CVE affects) or `unverified`. A tool marked `empty`
/// whose records the CVE-record check reads is covered there
/// (`software_cves::OSV_FIRST`); the others are listed here so a new broken
/// mapping can't join them unseen.
#[test]
fn every_catalog_git_mapping_has_a_recorded_osv_answer() {
    use crate::checks::machine::software_cves::{OSV_FIRST, TOOLS as CVE_TOOLS};
    use crate::utils::toml;
    const BROKEN_NOT_COVERED: &[&str] = &["gem", "gradle", "mariadb", "maven", "nginx", "ruby"];
    let rows: Vec<toml::Table> =
        toml::parse(OSV_GIT).expect("fixture parses").into_iter().filter(|t| t.name == "mapping").collect();
    let mapped: Vec<&Tool> = TOOLS.iter().filter(|t| t.osv.is_some_and(|o| o.0 == "GIT")).collect();
    let mut problems: Vec<String> = Vec::new();
    for t in &mapped {
        let fmt = t.osv.unwrap().2;
        let mine: Vec<&toml::Table> = rows.iter().filter(|r| r.str("tool") == t.name).collect();
        let [r] = mine.as_slice() else {
            problems.push(format!("{}: {} recorded rows, want 1", t.name, mine.len()));
            continue;
        };
        if crate::checks::machine::tools::tag(fmt, r.str("version")) != r.str("tag") {
            problems.push(format!(
                "{}: the tag format {fmt} doesn't make {} of {}",
                t.name,
                r.str("tag"),
                r.str("version")
            ));
        }
        let answers: u64 = match r.get("answers") {
            Some(toml::Val::Raw(n)) => n.trim().parse().unwrap_or(u64::MAX),
            _ => u64::MAX,
        };
        match (r.str("status"), answers) {
            ("answers", 1..=100_000) if r.str("example").starts_with("CVE-") => {}
            ("empty", 0) if r.str("affected_by").starts_with("CVE-") => {}
            ("unverified", 0) => {}
            (status, n) => problems.push(format!("{}: status {status:?} with {n} answers", t.name)),
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(rows.len(), mapped.len(), "a recorded row for a tool the catalog doesn't map");
    // The broken ones: covered by the CVE-record check, or known and listed.
    let mut broken: Vec<&str> = rows.iter().filter(|r| r.str("status") == "empty").map(|r| r.str("tool")).collect();
    broken.sort();
    let (covered, rest): (Vec<&str>, Vec<&str>) = broken.iter().copied().partition(|t| OSV_FIRST.contains(t));
    assert_eq!(covered, ["php", "rust"]);
    assert!(covered.iter().all(|t| CVE_TOOLS.iter().any(|(name, _, _)| name == t)));
    assert_eq!(rest, BROKEN_NOT_COVERED, "a newly broken mapping: cover it or list it");
}

#[test]
fn java_keeps_java_8s_update_and_is_looked_for_in_linux_jvm_dirs() {
    let t = TOOLS.iter().find(|t| t.name == "java").unwrap();
    let re = crate::utils::re::Regex::with_flags(t.pattern, "m");
    for (out, want) in [
        ("openjdk version \"1.8.0_412\"\nOpenJDK Runtime Environment (build 1.8.0_412-b08)", "1.8.0_412"),
        ("openjdk version \"1.8.0\"", "1.8.0"),
        ("openjdk version \"21.0.5\" 2024-10-15 LTS", "21.0.5"),
        ("java version \"17.0.11\" 2024-04-16 LTS", "17.0.11"),
        ("openjdk version \"25\" 2025-09-16", "25"),
    ] {
        assert_eq!(re.search(out).map(|m| m.get(1).to_string()).as_deref(), Some(want), "{out}");
    }
    assert_eq!(Cycle::Java.of("1.8.0_412"), "8");
    for dir in ["/usr/lib/jvm/*/bin", "/usr/lib64/jvm/*/bin", "~/.sdkman/candidates/java/*/bin"] {
        assert!(JAVA_DIRS.contains(&dir), "{dir}");
    }
}
