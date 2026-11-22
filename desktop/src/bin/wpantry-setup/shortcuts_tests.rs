use super::*;
use crate::tests::Scratch;

// Oracle: Desktop Entry spec, "The Exec key" quoting rules, applied
// after the string-value escapes.
#[test]
fn desktop_exec_quoting() {
    assert_eq!(
        desktop_exec_quote("/home/a b/x").unwrap(),
        "\"/home/a b/x\""
    );
    assert_eq!(
        desktop_exec_quote("/h/$\"`\\%").unwrap(),
        "\"/h/\\\\$\\\\\"\\\\`\\\\\\\\%%\""
    );
    assert!(desktop_exec_quote("/h/\nx").is_err());
    let entry = desktop_entry(Path::new("/opt/p/wpantry-desktop"), "1.0.0").unwrap();
    assert!(
        entry.contains("\nExec=\"/opt/p/wpantry-desktop\"\n"),
        "{entry}"
    );
    assert!(entry.contains(&format!("\nStartupWMClass={LINUX_WM_CLASS}\n")));
}

// Oracle: a desktop entry without Setup's key is the user's and stays.
#[test]
fn remove_shortcuts_keeps_foreign_entries() {
    let scratch = Scratch::new();
    let entry = scratch.0.join(LINUX_ENTRY);
    fs::create_dir_all(entry.parent().unwrap()).unwrap();
    fs::write(&entry, "[Desktop Entry]\nName=Mine\n").unwrap();
    remove_shortcuts(&scratch.0).unwrap();
    assert!(entry.is_file());
    if cfg!(target_os = "linux") {
        create_shortcuts(&scratch.0, Path::new("/opt/pantry"), "1.0.0").unwrap();
        assert!(scratch.0.join(LINUX_ICON).is_file());
        remove_shortcuts(&scratch.0).unwrap();
        assert!(!entry.exists() && !scratch.0.join(LINUX_ICON).exists());
    }
}
