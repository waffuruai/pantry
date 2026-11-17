use super::*;

#[test]
fn registry_releases_only() {
    let text = r#"{"packages": [
            {"name": "symfony/yaml", "version": "v6.4.0", "dist": {"type": "zip"}},
            {"name": "example/local", "version": "1.0.0", "dist": {"type": "path", "url": "local"}},
            {"name": "example/branch", "version": "dev-main", "source": {"type": "git"}},
            {"name": "example/alias", "version": "2.1.x-dev"}],
          "packages-dev": [{"name": "psr/container", "version": "2.0.2"}]}"#;
    assert_eq!(
        parse(text).unwrap(),
        [
            Package::new("Packagist", "symfony/yaml", "v6.4.0").scoped(Scope::Runtime),
            Package::new("Packagist", "psr/container", "2.0.2").scoped(Scope::Dev)
        ]
    );
}
