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
