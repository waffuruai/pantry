use super::*;

#[test]
fn report_paths_use_forward_slashes_on_every_host() {
    let d = crate::utils::temp::TempDir::new("persistence-paths").unwrap();
    let root = d.path().join("root");
    let home = root.join("home").join("person");
    let roots = Roots {
        home: home.clone(),
        root: root.clone(),
        macos: false,
        runner: &crate::checks::machine::settings::real_runner,
    };
    assert_eq!(
        roots.show(&home.join(".config").join("autostart").join("example.desktop")),
        "~/.config/autostart/example.desktop"
    );
    assert_eq!(roots.show(&root.join("etc").join("cron.d").join("example")), "/etc/cron.d/example");
    let outside = d.path().join("elsewhere").join("example");
    assert_eq!(roots.show(&outside), outside.to_string_lossy().replace('\\', "/"));
}
