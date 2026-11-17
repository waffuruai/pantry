use super::*;

#[test]
fn os_release_families_and_fixes() {
    let rel = parse_os_release("NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"22\"\n");
    assert_eq!(rel["ID_LIKE"], "ubuntu debian");
    assert_eq!(os_family(&rel), "osv");
    assert!(os_fix(&rel, "openssl").starts_with("sudo apt-get update"));
    assert_eq!(os_family(&parse_os_release("ID=fedora\n")), "dnf");
    assert_eq!(os_family(&parse_os_release("ID=arch\n")), "arch");
    assert_eq!(os_family(&parse_os_release("ID=nixos\n")), "");
    assert_eq!(
        os_fix(&parse_os_release("ID=opensuse-leap\nID_LIKE=\"suse opensuse\"\n"), "curl"),
        "sudo zypper update curl"
    );
}

#[test]
fn os_release_is_the_file_or_nothing() {
    let rel = os_release();
    match std::fs::read_to_string("/etc/os-release") {
        Ok(text) => assert_eq!(rel, parse_os_release(&text)),
        Err(_) => assert!(rel.is_empty()),
    }
}

#[test]
fn os_fixes_per_family() {
    assert_eq!(os_fix(&parse_os_release("ID=alpine\n"), "openssl"), "sudo apk upgrade openssl");
    assert_eq!(os_fix(&parse_os_release("ID=arch\n"), "openssl"), "sudo pacman -Syu");
    let fedora = os_fix(&parse_os_release("ID=fedora\n"), "openssl");
    assert!(fedora == "sudo dnf upgrade openssl" || fedora == "sudo yum upgrade openssl", "{fedora}");
}
