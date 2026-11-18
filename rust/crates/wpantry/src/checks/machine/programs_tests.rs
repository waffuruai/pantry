use super::*;
use crate::checks::machine::testing::machine;

/// `reg query /s` output as Windows prints it (CRLF line ends), with an
/// entry without a name, an update filed under another program, and a
/// value with no data.
pub(crate) const MACHINE_64: &str = "\r
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{0A1B}\r
    DisplayName    REG_SZ    PowerStudio SCADA Wave\r
    DisplayVersion    REG_SZ    24.10.3.0\r
    Publisher    REG_SZ    CIRCUTOR, SA\r
    EstimatedSize    REG_DWORD    0x3a98\r
    Comments    REG_SZ\r
\r
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Driver\r
    SystemComponent    REG_DWORD    0x1\r
\r
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\KB000001\r
    DisplayName    REG_SZ    Security Update for Example Viewer\r
    ParentKeyName    REG_SZ    ExampleViewer\r
\r
";

pub(crate) const MACHINE_32: &str = "
HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ExampleViewer
    DisplayName    REG_SZ    Example Viewer (x86)
    DisplayVersion    REG_SZ    2.4.1
    Publisher    REG_SZ    Example Software, Inc.
";

/// The user's own: the same program as the machine's 64-bit view, once.
pub(crate) const USER: &str = "
ERROR: stray line before any key
HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PowerStudio
    DisplayName    REG_SZ    PowerStudio SCADA Wave
    DisplayVersion    REG_SZ    24.10.3.0
    Publisher    REG_SZ    CIRCUTOR, SA
HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NoVersion
    DisplayName    REG_SZ    Portable Tool
";

pub(crate) const ANSWERS: &[(&str, &str)] = &[
    (r"query HKLM\SOFTWARE\Microsoft", MACHINE_64),
    (r"query HKLM\SOFTWARE\WOW6432Node", MACHINE_32),
    (r"query HKCU\SOFTWARE\Microsoft", USER),
];

#[test]
fn a_reg_query_listing_is_read() {
    let found = parse(MACHINE_64);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0],
        Program {
            name: "PowerStudio SCADA Wave".into(),
            version: "24.10.3.0".into(),
            publisher: "CIRCUTOR, SA".into(),
            key: r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{0A1B}".into(),
        }
    );
    assert!(parse("").is_empty());
    assert!(parse("ERROR: The system was unable to find the specified registry key or value.").is_empty());
}

#[test]
fn every_uninstall_key_is_read_once_each_program() {
    let run = machine(ANSWERS);
    let found = programs(&run);
    let names: Vec<(&str, &str, &str)> =
        found.iter().map(|p| (p.name.as_str(), p.version.as_str(), p.publisher.as_str())).collect();
    assert_eq!(
        names,
        [
            ("Example Viewer (x86)", "2.4.1", "Example Software, Inc."),
            ("Portable Tool", "", ""),
            ("PowerStudio SCADA Wave", "24.10.3.0", "CIRCUTOR, SA"),
        ]
    );
}

#[test]
fn reg_is_run_by_its_full_path_read_only() {
    let asked = std::sync::Mutex::new(Vec::new());
    let run = |argv: &[&str]| {
        asked.lock().unwrap().push(argv.join(" "));
        String::new()
    };
    assert!(programs(&run).is_empty());
    let asked = asked.into_inner().unwrap();
    assert_eq!(asked.len(), KEYS.len());
    for (a, key) in asked.iter().zip(KEYS) {
        assert!(a.ends_with(&format!(r"\System32\reg.exe query {key} /s")), "{a}");
    }
}
