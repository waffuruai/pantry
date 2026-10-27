//! S1: every dependency is pinned `=x.y.z`, from the PRD's allowlist only,
//! and the toolchain is exact.

const WORKSPACE: &str = include_str!("../../../Cargo.toml");
const TOOLCHAIN: &str = include_str!("../../../rust-toolchain.toml");
const ALLOWED: &[&str] = &["serde", "serde_json", "rusqlite", "ureq", "rustls", "wscanner"];

fn section<'a>(toml: &'a str, header: &str) -> Vec<&'a str> {
    toml.lines()
        .skip_while(|l| l.trim() != header)
        .skip(1)
        .take_while(|l| !l.starts_with('['))
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .collect()
}

#[test]
fn workspace_dependencies_are_exact_and_allowed() {
    let deps = section(WORKSPACE, "[workspace.dependencies]");
    assert!(!deps.is_empty());
    for line in deps {
        let name = line.split('=').next().unwrap().trim();
        assert!(ALLOWED.contains(&name), "{name} is not on the PRD's dependency allowlist");
        let version = line.split("version = \"").nth(1).and_then(|v| v.split('"').next()).unwrap_or("");
        assert!(
            version.starts_with('=') && version[1..].split('.').count() == 3,
            "{name} is not pinned =x.y.z: {line}"
        );
    }
}

#[test]
fn crates_take_dependencies_only_from_the_workspace() {
    for manifest in [include_str!("../Cargo.toml"), include_str!("../../wscanner-cli/Cargo.toml")] {
        for header in ["[dependencies]", "[dev-dependencies]", "[build-dependencies]"] {
            for line in section(manifest, header) {
                assert!(line.contains(".workspace = true"), "{line}: declare it in [workspace.dependencies]");
            }
        }
    }
}

#[test]
fn toolchain_is_exact() {
    let channel = TOOLCHAIN.lines().find_map(|l| l.strip_prefix("channel = \"")).unwrap().trim_end_matches('"');
    assert_eq!(channel.split('.').count(), 3, "rust-toolchain.toml channel {channel} is not an exact version");
}
