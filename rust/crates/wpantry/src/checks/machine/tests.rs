use super::*;

#[test]
fn a_probe_result_is_joined() {
    assert_eq!(std::thread::scope(|s| joined(s.spawn(|| 41 + 1))), 42);
}

/// On Windows the installed programs are read and asked about; the rest
/// of the inventory is said not to be read.
#[test]
fn windows_reads_its_programs_and_says_what_it_does_not_read() {
    let d = crate::utils::temp::TempDir::new("windows").unwrap();
    let net = crate::utils::net::Fake::offline();
    let mut s = testing::scan(&net, &d);
    windows(&mut s, &testing::machine(programs::tests::ANSWERS)).unwrap();
    assert_eq!(s.counts, [("installed programs".to_string(), 3)]);
    assert_eq!(
        testing::unchecked_note(&s, &software_cves::unreached(programs::WHAT)),
        "Example Viewer (x86), PowerStudio SCADA Wave"
    );
    assert!(testing::unchecked_note(&s, "machine inventory on Windows").starts_with("winget, Scoop and Chocolatey"));
}
