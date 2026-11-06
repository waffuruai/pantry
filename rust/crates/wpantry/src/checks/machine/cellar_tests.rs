use super::*;

#[test]
fn maps_formulae_and_strips_revisions() {
    assert_eq!(catalog_tool("openssl@3").map(|t| t.name), Some("openssl"));
    assert_eq!(catalog_tool("node@22").map(|t| t.name), Some("node"));
    assert_eq!(catalog_tool("postgresql@17").map(|t| t.name), Some("postgres"));
    assert_eq!(catalog_tool("openssh").map(|t| t.name), Some("ssh"));
    assert_eq!(catalog_tool("awscli").map(|t| t.name), Some("aws"));
    assert!(catalog_tool("python@3.13").is_none(), "pythons are inventoried with pip");
    assert!(catalog_tool("mise").is_none(), "always checked from PATH");
    assert!(catalog_tool("jq").is_none());
    assert_eq!(version_of("1.8.2_1"), "1.8.2");
    assert_eq!(version_of("22.1.0"), "22.1.0");
    assert_eq!(version_of("1.0.0_rc1"), "1.0.0_rc1", "not a revision");
}

#[test]
fn reads_a_cellar_highest_version_first() {
    let d = crate::utils::temp::TempDir::new("cellar").unwrap();
    let cellar = d.path().join("Cellar");
    for v in ["openssl@3/3.6.0", "openssl@3/3.5.4", "node@22/22.1.0_1", "jq/1.8.1", "oniguruma/6.9.10", "empty"] {
        std::fs::create_dir_all(cellar.join(v)).unwrap();
    }
    std::fs::write(cellar.join(".DS_Store"), "").unwrap();
    let mise = d.path().join("mise/installs");
    std::fs::create_dir_all(mise.join("brew-node@22")).unwrap();
    let inv = read(&cellar, &mise);
    assert_eq!(inv.unmapped, vec!["jq".to_string(), "oniguruma".to_string()]);
    assert_eq!(inv.components.len(), 2, "{:?}", inv.components);
    let node = &inv.components[0];
    assert_eq!((node.kind.as_str(), node.name.as_str(), node.version.as_str()), ("brew", "node", "22.1.0"));
    assert_eq!(node.fix, "mise upgrade brew:node@22");
    assert_eq!(node.osv.as_ref().map(|o| o.2.as_str()), Some("v22.1.0"));
    assert_eq!(node.eol.as_ref().map(|e| e.1.as_str()), Some("22"));
    assert_eq!(node.extra.get("formula").map(String::as_str), Some("node@22"));
    let ssl = &inv.components[1];
    assert_eq!((ssl.name.as_str(), ssl.version.as_str()), ("openssl", "3.6.0"));
    assert!(ssl.fix.starts_with("Upgrade openssl@3 in the Cellar at "), "{}", ssl.fix);
    assert!(!ssl.auto);
    assert_eq!(ssl.path, cellar.join("openssl@3").to_string_lossy());
    assert_eq!(read(&d.path().join("nowhere"), &mise), Inventory::default());
    let (found, inv2) = inventory_in(cellar.clone(), &mise).unwrap();
    assert_eq!((found, inv2), (cellar, inv));
    assert_eq!(inventory_in(d.path().join("nowhere"), &mise), None, "an empty Cellar is no inventory");
}

#[test]
fn the_cellar_is_the_variables_then_the_standard_prefixes() {
    let d = crate::utils::temp::TempDir::new("cellar").unwrap();
    let here = d.path().join("Cellar");
    std::fs::create_dir_all(&here).unwrap();
    let os = |p: &Path| Some(OsString::from(p));
    let standard = [here.to_string_lossy().into_owned()];
    let standard: Vec<&str> = standard.iter().map(String::as_str).collect();
    assert_eq!(find_cellar_from(os(Path::new("/c")), os(Path::new("/p")), &standard), Some(PathBuf::from("/c")));
    assert_eq!(
        find_cellar_from(Some(OsString::new()), os(Path::new("/p")), &standard),
        Some(PathBuf::from("/p/Cellar"))
    );
    assert_eq!(find_cellar_from(None, Some(OsString::new()), &standard), Some(here.clone()));
    assert_eq!(find_cellar_from(None, None, &["/nonexistent/Cellar"]), None);
    let _home = crate::utils::files::test_home();
    assert_eq!(mise_installs_from(os(Path::new("/m"))), PathBuf::from("/m/installs"));
    assert_eq!(mise_installs_from(Some(OsString::new())), home().join(".local/share/mise/installs"));
    assert_eq!(mise_installs(), mise_installs_from(std::env::var_os("MISE_DATA_DIR")));
    assert_eq!(
        find_cellar(),
        find_cellar_from(std::env::var_os("HOMEBREW_CELLAR"), std::env::var_os("HOMEBREW_PREFIX"), STANDARD_CELLARS)
    );
}
