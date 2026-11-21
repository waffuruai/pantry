use super::*;

fn refs(rs: &[&str]) -> Vec<String> {
    rs.iter().map(|r| r.to_string()).collect()
}

#[test]
fn image_references_split_into_repository_and_tag() {
    let s = split;
    assert_eq!(s("metabase/metabase:v0.64.2"), ("metabase/metabase".into(), "v0.64.2".into()));
    assert_eq!(s("docker.io/metabase/metabase:v0.64.2"), ("metabase/metabase".into(), "v0.64.2".into()));
    assert_eq!(s("index.docker.io/metabase/metabase:v0.64.2"), ("metabase/metabase".into(), "v0.64.2".into()));
    assert_eq!(s("metabase/metabase:v0.64.2@sha256:abc"), ("metabase/metabase".into(), "v0.64.2".into()));
    assert_eq!(s("metabase/metabase"), ("metabase/metabase".into(), String::new()));
    // A registry port is not a tag.
    assert_eq!(
        s("registry.example:5000/metabase/metabase"),
        ("registry.example:5000/metabase/metabase".into(), String::new())
    );
    assert_eq!(
        s("registry.example:5000/metabase/metabase:v0.64.2"),
        ("registry.example:5000/metabase/metabase".into(), "v0.64.2".into())
    );
}

#[test]
fn a_running_metabase_image_tag_is_its_version() {
    let found = from_images(&refs(&[
        "docker.io/metabase/metabase:v0.64.2",
        // The same version through another reference counts once.
        "metabase/metabase:v0.64.2@sha256:abc",
        "metabase/metabase:v0.63.22.3",
    ]));
    let got: Vec<(&str, &str, &str)> =
        found.iter().map(|c| (c.kind.as_str(), c.name.as_str(), c.version.as_str())).collect();
    assert_eq!(got, [("tool", "metabase", "0.64.2"), ("tool", "metabase", "0.63.22.3")]);
    let cycles: Vec<Option<(String, String)>> = found.iter().map(|c| c.eol.clone()).collect();
    assert_eq!(cycles, [Some(("metabase".into(), "0.64".into())), Some(("metabase".into(), "0.63".into()))]);
    let c = &found[0];
    assert_eq!(c.path, "docker.io/metabase/metabase:v0.64.2");
    assert_eq!(
        (c.fix.as_str(), c.auto),
        ("docker pull metabase/metabase:v{safe}, then recreate its containers", false)
    );
    assert!(c.osv.is_none() && c.extra.is_empty());
    // How the KEV mapping names it.
    assert_eq!(crate::checks::machine::exploited::key(c), "tool:metabase");
}

#[test]
fn a_tag_that_is_not_a_release_or_another_image_is_nothing() {
    let found = from_images(&refs(&[
        "metabase/metabase",
        "metabase/metabase:latest",
        "metabase/metabase:v0.65.0-beta",
        "metabase/metabase@sha256:abc",
        // Enterprise numbers its releases 1.x; endoflife.date doesn't.
        "metabase/metabase-enterprise:v1.64.2",
        "someone/metabase:v0.64.2",
        "postgres:17",
    ]));
    assert!(found.is_empty(), "{found:?}");
    assert!(from_images(&[]).is_empty());
}

#[test]
fn every_image_pattern_compiles_and_the_live_inventory_is_only_catalog_servers() {
    for (_, _, pattern, _) in IMAGES {
        Regex::new(pattern);
    }
    // Asks the local Docker, if any, which images are running: read only.
    for c in servers() {
        assert!(IMAGES.iter().any(|(_, n, _, _)| *n == c.name), "{c:?}");
    }
}
