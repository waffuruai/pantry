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

fn installed(name: &str, version: &str, publisher: &str) -> Program {
    Program { name: name.into(), version: version.into(), publisher: publisher.into(), key: format!(r"HKCU\x\{name}") }
}

#[test]
fn only_the_programs_table_maps_a_program() {
    let row = |n: &str, v: &str, p: &str| mapped(&installed(n, v, p));
    assert_eq!(
        row("PowerStudio SCADA Wave", "24.10.3.0", "CIRCUTOR, SA"),
        Some(("Circutor", "PowerStudio SCADA Wave"))
    );
    assert_eq!(row("IntelliJ IDEA 2026.2.1", "262.8665.42", "JetBrains s.r.o."), Some(("JetBrains", "IntelliJ IDEA")));
    assert_eq!(
        row("IntelliJ IDEA Community Edition 2026.2", "262.1", "JetBrains s.r.o."),
        Some(("JetBrains", "IntelliJ IDEA"))
    );
    assert_eq!(row("VMware Workstation", "17.5.1", "Broadcom Inc."), Some(("VMware", "Workstation")));
    assert_eq!(row("VMware Workstation", "17.5.1", "VMware, Inc."), Some(("VMware", "Workstation")));
    assert_eq!(row("Armoury Crate", "6.1.18", "ASUSTeK COMPUTER INC."), Some(("ASUS", "Armoury Crate")));
    // Another product of a listed vendor, a listed product by someone
    // else, and a program nobody listed: none.
    assert_eq!(row("PowerStudio Deluxe", "1.0", "CIRCUTOR, SA"), None);
    assert_eq!(row("IntelliJ IDEA", "2026.2", "Example Software"), None);
    assert_eq!(row("Example Viewer", "2.4.1", "Example Software, Inc."), None);
    assert_eq!(row("Portable Tool", "", ""), None);
    // The subject carries the row's vendor and product, not the Publisher.
    let x = subject(&installed("VMware Workstation", "17.5.1", "Broadcom Inc.")).unwrap();
    assert_eq!((x.vendors, x.product.as_deref()), (vec!["vmware".to_string()], Some("Workstation")));
    assert!(subject(&installed("Example Viewer", "2.4.1", "Example Software, Inc.")).is_none());
}

/// A JetBrains record of the IntelliJ IDEA shape: fixed in the 2026.3
/// release.
fn intellij_record() -> serde_json::Value {
    let mut rec = crate::sources::cve_records::tests::circutor_record();
    rec["cveMetadata"]["cveId"] = "CVE-2026-1".into();
    rec["containers"]["cna"]["title"] = "IntelliJ IDEA example issue".into();
    rec["containers"]["cna"]["affected"] = serde_json::json!([{
        "vendor": "JetBrains",
        "product": "IntelliJ IDEA",
        "versions": [{"status": "affected", "version": "0", "lessThan": "2026.3", "versionType": "custom"}],
        "defaultStatus": "unaffected"
    }]);
    rec
}

/// The index: Circutor's and JetBrains' products and records, any other
/// vendor unknown; every request kept.
fn index() -> crate::utils::net::Fake {
    use crate::sources::cve_records::tests::{circutor_record, page};
    use crate::utils::net::{Fake, Response};
    Fake::new(|r| {
        Ok(if r.url.ends_with("/browse/circutor") {
            Response::ok(r#"["powerstudio scada wave"]"#)
        } else if r.url.ends_with("/browse/jetbrains") {
            Response::ok(r#"["intellij idea", "intellij idea ultimate"]"#)
        } else if r.url.contains("/browse/") {
            Response::ok("[]")
        } else if r.url.contains("search/circutor/powerstudio%20scada%20wave") {
            Response::ok(page(&[circutor_record()], 1))
        } else if r.url.contains("search/jetbrains/intellij%20idea") {
            Response::ok(page(&[intellij_record()], 1))
        } else {
            Response::not_found()
        })
    })
}

/// Eric's #230 item 1: a Publisher can be a person or an internal tool, so
/// only the table's vendor and product names may reach the index.
#[test]
fn no_unmapped_publisher_or_program_reaches_the_index() {
    let d = crate::utils::temp::TempDir::new("programs-mapped").unwrap();
    let net = index();
    let mut s = crate::checks::machine::testing::scan(&net, &d);
    let found = vec![
        installed("PowerStudio SCADA Wave", "24.10.3.0", "CIRCUTOR, SA"),
        installed("IntelliJ IDEA 2026.2.1", "2026.2.1", "JetBrains s.r.o."),
        // A per-user install by a person, and an in-house tool.
        installed("Budget Sheet Helper", "1.2", "Jane Example"),
        installed("Example Corp Deploy Agent", "4.0", "Example Corp IT"),
        installed("Example Viewer (x86)", "2.4.1", "Example Software, Inc."),
    ];
    check(&mut s, &found).unwrap();
    assert_eq!(s.counts, [("installed programs".to_string(), 5)], "every program is still counted");
    let urls: Vec<String> = net.requests().iter().map(|r| r.url.to_lowercase()).collect();
    for word in ["jane", "budget", "example", "deploy", "viewer"] {
        assert!(!urls.iter().any(|u| u.split(['/', '?']).any(|seg| seg.contains(word))), "{word} sent: {urls:?}");
    }
    let mut browsed: Vec<&str> = urls.iter().filter_map(|u| u.split_once("/browse/").map(|(_, v)| v)).collect();
    // The prefetch asks in parallel; the order is not fixed.
    browsed.sort();
    assert_eq!(browsed, ["circutor", "jetbrains"], "{urls:?}");
    let failed: Vec<(&str, &str)> = s.findings.iter().map(|f| (f.component.as_str(), f.vuln_id.as_str())).collect();
    assert_eq!(failed, [("PowerStudio SCADA Wave", "CVE-2026-120387"), ("IntelliJ IDEA 2026.2.1", "CVE-2026-1")]);
}

/// Eric's #230 item 2: JetBrains writes the build (`262.x`) as
/// DisplayVersion while its records name releases (`2026.3`); a current
/// IntelliJ is "not checked", not failed.
#[test]
fn an_intellij_build_number_is_not_compared_with_release_numbers() {
    use crate::checks::machine::software_cves::unjudged;
    let d = crate::utils::temp::TempDir::new("programs-jetbrains").unwrap();
    let net = index();
    let mut s = crate::checks::machine::testing::scan(&net, &d);
    check(&mut s, &[installed("IntelliJ IDEA 2026.3", "263.4567.12", "JetBrains s.r.o.")]).unwrap();
    assert!(s.findings.iter().all(|f| f.vuln_id != "CVE-2026-1"), "{:?}", s.findings);
    assert_eq!(crate::checks::machine::testing::unchecked_note(&s, &unjudged(WHAT)), "IntelliJ IDEA 2026.3");
    // The release numbered as the records are: judged, and 2026.3 is clean.
    let mut s = crate::checks::machine::testing::scan(&net, &d);
    check(&mut s, &[installed("IntelliJ IDEA 2026.3", "2026.3", "JetBrains s.r.o.")]).unwrap();
    assert!(s.findings.is_empty(), "{:?}", s.findings);
}
