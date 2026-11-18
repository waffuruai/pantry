use super::*;
use crate::checks::machine::components::components;
use crate::checks::machine::testing;
use crate::utils::files::realpath;
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;

/// An OTP install under `root` (`<root>/bin/erl`, `<root>/erts-*/bin/erl`)
/// for `version`, with `start_erl.data` naming its major.
fn otp(root: &Path, version: &str) {
    let major = version.split('.').next().unwrap();
    testing::write(&root.join("bin/erl"), "#!/bin/sh\nexit 1\n");
    testing::write(&root.join("erts-15.2.6/bin/erl"), "#!/bin/sh\nexit 1\n");
    testing::write(&root.join("releases/start_erl.data"), &format!("15.2.6 {major}\n"));
    testing::write(&root.join(format!("releases/{major}/OTP_VERSION")), &format!("{version}\n"));
}

fn shown(p: &Path) -> (String, String) {
    (p.display().to_string(), realpath(&p.display().to_string()))
}

#[test]
fn roots_from_the_bin_folder_or_erts() {
    assert_eq!(root_of(Path::new("/x/lib/erlang/bin/erl")), Some(PathBuf::from("/x/lib/erlang")));
    assert_eq!(root_of(Path::new("/x/lib/erlang/erts-15.2.6/bin/erl")), Some(PathBuf::from("/x/lib/erlang")));
    assert_eq!(root_of(Path::new("/x/shims/erl")), None);
    assert_eq!(root_of(Path::new("erl")), None);
}

#[test]
fn version_from_otp_version_by_the_current_major() {
    let d = TempDir::new("otp").unwrap();
    let r = d.path().join("lib/erlang");
    otp(&r, "27.3.2");
    // An older major left beside it: start_erl.data says which is current.
    testing::write(&r.join("releases/26/OTP_VERSION"), "26.2.5.13\n");
    assert_eq!(version(&r).as_deref(), Ok("27.3.2"));
    // Without start_erl.data, the one major there is.
    std::fs::remove_file(r.join("releases/start_erl.data")).unwrap();
    assert!(version(&r).unwrap_err().contains("several releases"));
    std::fs::remove_dir_all(r.join("releases/26")).unwrap();
    assert_eq!(version(&r).as_deref(), Ok("27.3.2"));
    // Four-part patch releases.
    testing::write(&r.join("releases/27/OTP_VERSION"), "27.3.4.1\n");
    assert_eq!(version(&r).as_deref(), Ok("27.3.4.1"));
}

#[test]
fn missing_or_odd_release_files_are_reasons_not_versions() {
    let d = TempDir::new("otp").unwrap();
    let r = d.path().join("otp");
    std::fs::create_dir_all(&r).unwrap();
    assert!(version(&r).unwrap_err().starts_with("no releases/<major>/OTP_VERSION under "));
    otp(&r, "27.3.2");
    testing::write(&r.join("releases/27/OTP_VERSION"), "27.x\n");
    assert!(version(&r).unwrap_err().ends_with("doesn't name an OTP 27 version"));
    testing::write(&r.join("releases/27/OTP_VERSION"), "26.2.1\n");
    assert!(version(&r).unwrap_err().ends_with("doesn't name an OTP 27 version"));
    testing::write(&r.join("releases/start_erl.data"), "15.2.6 ../27\n");
    assert!(version(&r).unwrap_err().ends_with("names no OTP major"));
    testing::write(&r.join("releases/start_erl.data"), "15.2.6 28\n");
    assert!(version(&r).unwrap_err().ends_with("can't be read"));
}

#[cfg(unix)]
#[test]
fn installs_through_symlinks_once_with_their_updater() {
    let home = crate::utils::files::test_home();
    let h = crate::utils::files::home();
    // asdf's layout: the version's bin/erl links into lib/erlang.
    let asdf = h.join(".asdf/installs/erlang/27.3.2");
    otp(&asdf.join("lib/erlang"), "27.3.2");
    std::fs::create_dir_all(asdf.join("bin")).unwrap();
    std::os::unix::fs::symlink("../lib/erlang/bin/erl", asdf.join("bin/erl")).unwrap();
    let other = h.join("otp/bin/erl");
    otp(&h.join("otp"), "26.2.5.13");
    let shim = h.join(".asdf/shims/erl");
    testing::write(&shim, "");
    let brew = h.join("Cellar/erlang/27.3.2/lib/erlang");
    otp(&brew, "27.3.2");
    let bare = h.join("tools/erl");
    testing::write(&bare, "");
    let found = vec![
        shown(&asdf.join("bin/erl")),
        shown(&asdf.join("lib/erlang/bin/erl")),
        shown(&asdf.join("lib/erlang/erts-15.2.6/bin/erl")),
        shown(&other),
        shown(&shim),
        shown(&brew.join("bin/erl")),
        shown(&bare),
    ];
    let (got, unread) = from(found);
    let rows: Vec<(&str, &str, &str)> =
        got.iter().map(|c| (c.name.as_str(), c.version.as_str(), c.path.as_str())).collect();
    let asdf_erl = asdf.join("bin/erl").display().to_string();
    let other_erl = other.display().to_string();
    assert_eq!(rows, [("erlang", "27.3.2", asdf_erl.as_str()), ("erlang", "26.2.5.13", other_erl.as_str())]);
    let c = &got[0];
    assert_eq!(c.kind, "runtime");
    assert_eq!(c.osv, Some(("GIT".into(), "https://github.com/erlang/otp.git".into(), "OTP-27.3.2".into())));
    assert_eq!(c.eol, Some(("erlang".into(), "27".into())));
    assert_eq!((c.fix.as_str(), c.auto), ("asdf install erlang {safe}", false));
    // An erl outside any OTP layout is reported, not skipped and not clean.
    assert_eq!(unread.len(), 1, "{unread:?}");
    assert_eq!(unread[0].0, bare.display().to_string());
    assert!(unread[0].1.ends_with("is not in an OTP install's bin folder"));
    drop(home);
}

#[cfg(unix)]
#[test]
fn installs_reads_kerls_list_and_reports_installs_without_a_version() {
    let home = crate::utils::files::test_home();
    let h = crate::utils::files::home();
    let built = h.join("kerl/27.3.2");
    otp(&built, "27.3.2");
    let broken = h.join("kerl/broken");
    testing::write(&broken.join("bin/erl"), "#!/bin/sh\n");
    use std::os::unix::fs::PermissionsExt;
    for erl in [built.join("bin/erl"), broken.join("bin/erl")] {
        std::fs::set_permissions(&erl, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    testing::write(
        &h.join(".kerl/otp_installations"),
        &format!("27.3.2 {}\nbroken {}/\nnot-a-path relative/dir\njunk\n", built.display(), broken.display()),
    );
    assert_eq!(
        kerl_installs(&h.join(".kerl/otp_installations")),
        [format!("{}/bin", built.display()), format!("{}/bin", broken.display())]
    );
    let (got, unread) = installs();
    assert!(
        got.iter().any(|c| c.version == "27.3.2" && c.path == built.join("bin/erl").display().to_string()),
        "{got:?}"
    );
    let why =
        unread.iter().find(|(erl, _)| erl == &broken.join("bin/erl").display().to_string()).map(|(_, w)| w.clone());
    assert!(why.is_some_and(|w| w.starts_with("no releases/<major>/OTP_VERSION under ")), "{unread:?}");
    drop(home);
}

/// The RST oracle: OTP 27.3.2 fails CVE-2025-32433 (the SSH daemon's
/// pre-auth code execution), marked known exploited, with the first later
/// tag OSV stops reporting it for as the fix; 27.3.3 passes the same harness.
#[test]
fn otp_27_3_2_fails_the_ssh_pre_auth_cve_with_kev_and_27_3_3_passes() {
    const OTP: &str = "https://github.com/erlang/otp.git";
    let d = TempDir::new("otp").unwrap();
    let net = Fake::new(|req| {
        let url = req.url.as_str();
        if url.ends_with("/querybatch") {
            let body = req.body.clone().unwrap_or_default();
            return Ok(testing::querybatch(&body, &|pkg, v| match (pkg, v) {
                (OTP, "OTP-27.3.2") => vec!["CVE-2025-32433"],
                _ => vec![],
            }));
        }
        if url.contains("/vulns/") {
            let id = url.rsplit('/').next().unwrap_or("");
            return Ok(Response::ok(
                serde_json::json!({"id": id, "modified": "m", "summary": "Erlang/OTP SSH server pre-auth code execution",
                    "affected": [{"ranges": [{"type": "GIT", "repo": OTP, "events": [{"introduced": "abc"}]}]}]})
                .to_string(),
            ));
        }
        if url == "https://endoflife.date/api/erlang.json" {
            return Ok(Response::ok(
                serde_json::json!([{"cycle": "27", "eol": "2027-05-20", "latest": "27.3.3"}]).to_string(),
            ));
        }
        if url.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
            return Ok(Response::not_found());
        }
        panic!("unexpected request {url}")
    });
    let mut s = testing::scan(&net, &d);
    s.kev.insert("CVE-2025-32433".into());
    s.cache.put_run(&format!("tags:{OTP}"), "", &serde_json::json!(["OTP-27.3.3"])).unwrap();
    let at = |v: &str| {
        let mut c = Component::new("runtime", "erlang", v, "/x/bin/erl");
        c.osv = Some(("GIT".into(), OTP.into(), format!("OTP-{v}")));
        c.eol = Some(("erlang".into(), "27".into()));
        c
    };
    components(&mut s, &[at("27.3.2"), at("27.3.3")]).unwrap();
    let got = testing::kinds(&s);
    assert_eq!(got, [("erlang".to_string(), "CVE-2025-32433".to_string(), "fail".to_string())], "{got:?}");
    let f = &s.findings[0];
    assert_eq!((f.version.as_str(), f.kev, f.fixed.as_str()), ("27.3.2", true, "OTP-27.3.3"));
}
