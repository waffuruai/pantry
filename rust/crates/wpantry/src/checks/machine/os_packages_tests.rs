use super::*;
use crate::utils::os::parse_os_release;

fn eco(text: &str) -> std::result::Result<String, String> {
    ecosystem(&parse_os_release(text))
}

/// osv-scalibr's extractor/filesystem/os/ecosystem tests (MakeEcosystem),
/// for the distros this reads.
#[test]
fn scalibr_conformance() {
    assert_eq!(eco("ID=debian\nVERSION_ID=\"12\"\n"), Ok("Debian:12".into()));
    assert_eq!(eco("ID=alpine\nVERSION_ID=4.5.6\n"), Ok("Alpine:v4.5".into()));
    assert_eq!(eco("ID=alpine\nVERSION_ID=4\n"), Ok("Alpine:v4".into()));
    assert_eq!(eco("ID=wolfi\n"), Ok("Wolfi".into()));
    assert_eq!(eco("ID=chainguard\n"), Ok("Chainguard".into()));
    assert_eq!(eco("ID=opensuse-leap\nVERSION_ID=\"15.5\"\n"), Ok("openSUSE:Leap 15.5".into()));
    assert_eq!(eco("ID=sles\nVERSION_ID=\"15.5\"\n"), Ok("SUSE:15.5".into()));
    assert_eq!(
        eco("ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.5 LTS (Noble Numbat)\"\n"),
        Ok("Ubuntu:24.04".into())
    );
    // OpenWrt and other IDs have no OSV ecosystem.
    assert!(eco("ID=openwrt\nVERSION_ID=22.03.5\n").is_err());
}

#[test]
fn unmapped_is_unchecked_never_clean() {
    assert!(eco("ID=debian\n").is_err(), "sid has no release to match");
    assert!(eco("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=22\n").is_err(), "derivatives aren't guessed");
    assert!(eco("").is_err());
}

#[test]
fn dpkg_source_packages() {
    let status = "Package: libssl3t64\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.13-0ubuntu3.5\nDescription: x\n continued line: not a field\n\nPackage: openssl\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.5\n\nPackage: libgcc-s1\nStatus: install ok installed\nSource: gcc-14 (14.2.0-4ubuntu2~24.04)\nVersion: 14.2.0-4ubuntu2~24.04\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n";
    let got: Vec<(String, String)> = dpkg(status).into_iter().map(|p| (p.name, p.version)).collect();
    assert_eq!(
        got,
        [("gcc-14".into(), "14.2.0-4ubuntu2~24.04".into()), ("openssl".into(), "3.0.13-0ubuntu3.5".into())]
    );
}

#[test]
fn apk_origins() {
    let db =
        "C:Q1x=\nP:libcrypto3\nV:3.3.2-r0\no:openssl\n\nP:busybox\nV:1.36.1-r29\n\nP:libssl3\nV:3.3.2-r0\no:openssl\n";
    let got: Vec<(String, String)> = apk(db).into_iter().map(|p| (p.name, p.version)).collect();
    assert_eq!(got, [("busybox".into(), "1.36.1-r29".into()), ("openssl".into(), "3.3.2-r0".into())]);
}

#[test]
fn rpm_names() {
    let got = rpm_listing("curl 0:8.6.0-150600.4.6.1\ngpg-pubkey 0:39db7c82-5f68629b\nfoo 1:2.0-1\n");
    let got: Vec<(String, String)> = got.into_iter().map(|p| (p.name, p.version)).collect();
    assert_eq!(got, [("curl".into(), "8.6.0-150600.4.6.1".into()), ("foo".into(), "1:2.0-1".into())]);
}

#[cfg(unix)]
#[test]
fn installed_reads_whichever_database_the_machine_has() {
    use std::os::unix::fs::PermissionsExt;
    let d = crate::utils::temp::TempDir::new("osdb").unwrap();
    let (dpkg_status, apk_db, nowhere) = (d.path().join("status"), d.path().join("installed"), d.path().join("no"));
    std::fs::write(&dpkg_status, "Package: openssl\nStatus: install ok installed\nVersion: 3.0.13\n").unwrap();
    std::fs::write(&apk_db, "P:busybox\nV:1.36.1-r29\n").unwrap();
    let rpm = d.path().join("rpm");
    std::fs::write(&rpm, "#!/bin/sh\necho 'curl 0:8.6.0-1'\n").unwrap();
    std::fs::set_permissions(&rpm, std::fs::Permissions::from_mode(0o755)).unwrap();
    let names = |r: Result<Option<(String, Vec<Package>)>>| {
        r.unwrap().map(|(from, pkgs)| (from, pkgs.into_iter().map(|p| p.name).collect::<Vec<_>>()))
    };
    let ubuntu = parse_os_release("ID=ubuntu\n");
    let suse = parse_os_release("ID=opensuse-leap\n");
    let no_rpm = || None;
    let fake_rpm = || Some(rpm.clone());
    let dpkg_from = dpkg_status.to_string_lossy().into_owned();
    assert_eq!(
        names(installed_from(&ubuntu, &dpkg_status, &apk_db, &no_rpm)),
        Some((dpkg_from, vec!["openssl".into()]))
    );
    let apk_from = apk_db.to_string_lossy().into_owned();
    assert_eq!(names(installed_from(&ubuntu, &nowhere, &apk_db, &no_rpm)), Some((apk_from, vec!["busybox".into()])));
    assert_eq!(names(installed_from(&ubuntu, &nowhere, &nowhere, &fake_rpm)), None, "no database we read");
    assert!(matches!(installed_from(&suse, &nowhere, &nowhere, &no_rpm), Err(Error::Missing(_))));
    assert_eq!(names(installed_from(&suse, &nowhere, &nowhere, &fake_rpm)), Some(("rpm".into(), vec!["curl".into()])));
}

#[cfg(unix)]
#[test]
fn a_failing_rpm_is_a_source_error() {
    use std::os::unix::fs::PermissionsExt;
    let d = crate::utils::temp::TempDir::new("osdb").unwrap();
    let rpm = d.path().join("rpm");
    std::fs::write(&rpm, "#!/bin/sh\necho broken >&2\nexit 1\n").unwrap();
    std::fs::set_permissions(&rpm, std::fs::Permissions::from_mode(0o755)).unwrap();
    let nowhere = d.path().join("no");
    let got = installed_from(&parse_os_release("ID=sles\n"), &nowhere, &nowhere, &|| Some(rpm.clone()));
    match got {
        Err(Error::Failed(m)) => assert_eq!(m, "rpm -qa exited Some(1): broken"),
        other => panic!("{other:?}"),
    }
}
