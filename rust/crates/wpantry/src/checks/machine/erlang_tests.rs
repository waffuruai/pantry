use super::*;
use crate::checks::TAG_PREFIX;
use crate::checks::machine::components::components;
use crate::checks::machine::testing;
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

/// (shown path, real path), as `on_path` gives them; only the Unix tests,
/// which make symlinks, use it.
#[cfg(unix)]
fn shown(p: &Path) -> (String, String) {
    (p.display().to_string(), crate::utils::files::realpath(&p.display().to_string()))
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
    assert_eq!(c.extra.get(TAG_PREFIX).map(String::as_str), Some("OTP-"));
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
        c.extra.insert(TAG_PREFIX.into(), "OTP-".into());
        c
    };
    components(&mut s, &[at("27.3.2"), at("27.3.3")]).unwrap();
    let got = testing::kinds(&s);
    assert_eq!(got, [("erlang".to_string(), "CVE-2025-32433".to_string(), "fail".to_string())], "{got:?}");
    let f = &s.findings[0];
    assert_eq!((f.version.as_str(), f.kev, f.fixed.as_str()), ("27.3.2", true, "27.3.3"));
}

/// mise's shims are links to the mise binary: the path as shown is the
/// shim, the real one isn't under `shims/`. Neither is reported.
#[cfg(unix)]
#[test]
fn mise_shims_are_skipped_by_the_path_shown() {
    let home = crate::utils::files::test_home();
    let h = crate::utils::files::home();
    let mise = h.join(".local/bin/mise");
    testing::write(&mise, "#!/bin/sh\n");
    let shim = h.join(".local/share/mise/shims/erl");
    std::fs::create_dir_all(shim.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&mise, &shim).unwrap();
    let found = shown(&shim);
    assert!(!found.1.contains("/shims/"), "{found:?}");
    let (got, unread) = from(vec![found]);
    assert!(got.is_empty() && unread.is_empty(), "{got:?} {unread:?}");
    drop(home);
}

/// OTP's release tags from 25 on (`git ls-remote`, 2026-11-18), without
/// the `OTP-`.
const OTP_TAGS: &str = "25.0 25.0-rc1 25.0.1 25.0.2 25.0.3 25.0.4 25.1 25.1.1 25.1.2 25.1.2.1 25.2 25.2.1 25.2.2 25.2.3 \
    25.3 25.3.1 25.3.2 25.3.2.1 25.3.2.2 25.3.2.3 25.3.2.4 25.3.2.5 25.3.2.6 25.3.2.7 25.3.2.8 25.3.2.9 25.3.2.10 \
    25.3.2.11 25.3.2.12 25.3.2.13 25.3.2.14 25.3.2.15 25.3.2.16 25.3.2.17 25.3.2.18 25.3.2.19 25.3.2.20 25.3.2.21 \
    26.0 26.0-rc1 26.0.1 26.0.2 26.1 26.1.1 26.1.2 26.2 26.2.1 26.2.2 26.2.3 26.2.4 26.2.5 26.2.5.1 26.2.5.2 26.2.5.3 \
    26.2.5.4 26.2.5.5 26.2.5.6 26.2.5.7 26.2.5.8 26.2.5.9 26.2.5.10 26.2.5.11 26.2.5.12 26.2.5.13 26.2.5.14 26.2.5.15 \
    26.2.5.16 26.2.5.17 26.2.5.18 26.2.5.19 26.2.5.20 26.2.5.21 27.0 27.0-rc1 27.0.1 27.1 27.1.1 27.1.2 27.1.3 27.2 \
    27.2.1 27.2.2 27.2.3 27.2.4 27.3 27.3.1 27.3.2 27.3.3 27.3.4 27.3.4.1 27.3.4.2 27.3.4.3 27.3.4.4 27.3.4.5 27.3.4.6 \
    27.3.4.7 27.3.4.8 27.3.4.9 27.3.4.10 27.3.4.11 27.3.4.12 27.3.4.13 27.3.4.14 27.3.4.15 27.3.4.16 27.3.4.17 \
    27.3.4.18 27.3.4.19 28.0 28.0-rc1 28.0.1 28.0.2 28.0.3 28.0.4 28.1 28.1.1 28.2 28.3 28.3.1 28.3.2 28.3.3 28.4 \
    28.4.1 28.4.2 28.4.3 28.5 28.5.0.1 28.5.0.2 28.5.0.3 28.5.0.4 28.5.0.5 28.5.0.6 28.5.0.7 28.5.0.8";

/// The tags OSV's record for CVE-2025-32433 lists as affected from 20 on
/// (osv.dev, 2026-11-18): no side-branch patch (`27.0.1`, `27.2.4`) and
/// not `26.2.1` or `26.2.2`.
#[cfg(unix)]
const LISTED_32433: &str = "20.0 21.0 22.0 23.0 24.0 25.0 25.1 25.2 25.3 25.3.1 25.3.2 25.3.2.1 25.3.2.2 25.3.2.3 \
    25.3.2.4 25.3.2.5 25.3.2.6 25.3.2.7 25.3.2.8 25.3.2.9 25.3.2.10 25.3.2.11 25.3.2.12 25.3.2.13 25.3.2.14 25.3.2.15 \
    25.3.2.16 25.3.2.17 25.3.2.18 25.3.2.19 26.0 26.1 26.2 26.2.3 26.2.4 26.2.5 26.2.5.1 26.2.5.2 26.2.5.3 26.2.5.4 \
    26.2.5.5 26.2.5.6 26.2.5.7 26.2.5.8 26.2.5.9 26.2.5.10 27.0 27.1 27.2 27.3 27.3.1 27.3.2";

/// The tags from 25 on that OSV answered no advisory at all for
/// (querybatch, 2026-11-18); every other tag got at least one.
#[cfg(unix)]
const OSV_EMPTY: &str = "25.0.2 25.0.3 25.0.4 25.1.1 25.1.2 25.1.2.1 25.2.1 25.2.2 25.2.3 25.3.2.21 26.0.1 26.0.2 \
    26.1.1 26.1.2 26.2.1 26.2.2 26.2.5.21 27.0.1 27.2.4 27.3.4.19 28.0.1 28.0.2 28.0.3 28.0.4 28.1.1 28.2 28.3.2 28.3.3 \
    28.4.3 28.5.0.8";

fn otp_tags(list: &str) -> Vec<String> {
    list.split_whitespace().map(|v| format!("OTP-{v}")).collect()
}

/// Inside CVE-2025-32433's ranges as its CVE record gives them: before
/// 25.3.2.20, from 26.0 before 26.2.5.11, from 27.0 before 27.3.3.
#[cfg(unix)]
fn in_32433_ranges(tag: &str) -> bool {
    let v = tag.trim_start_matches("OTP-");
    let lt = crate::checks::ecosystems::versions::lt;
    match v.split('.').next() {
        Some("25") => lt(v, "25.3.2.20"),
        Some("26") => lt(v, "26.2.5.11"),
        Some("27") => lt(v, "27.3.3"),
        Some(m) => m.parse::<u32>().is_ok_and(|m| m < 25),
        None => false,
    }
}

/// A CVE-2025-32433 finding: (installed version, fix version, fix command).
#[cfg(unix)]
type Fixed = (String, String, String);

/// Scans OTP installs of `versions` (asdf's for all but the first, mise's
/// for it) against a fake OSV: `affected(tag)` says whether a tag gets
/// CVE-2025-32433, `empty(tag)` whether it gets nothing at all (every other
/// tag gets another advisory), and the record lists `listed`. Returns the
/// scan's CVE-2025-32433 findings (OTP's tags being `tags`) as (version, fixed, fix command) and its
/// not-checked lines as (version, note).
#[cfg(unix)]
fn scan_otp(
    versions: &[&str],
    affected: fn(&str) -> bool,
    empty: fn(&str) -> bool,
    listed: Vec<String>,
    tags: Vec<String>,
) -> (Vec<Fixed>, Vec<(String, String)>) {
    const OTP: &str = "https://github.com/erlang/otp.git";
    let home = crate::utils::files::test_home();
    let h = crate::utils::files::home();
    let mut found = Vec::new();
    for (i, v) in versions.iter().enumerate() {
        let root = if i == 0 {
            h.join(".local/share/mise/installs/erlang").join(v)
        } else {
            h.join(".asdf/installs/erlang").join(v)
        };
        otp(&root, v);
        found.push(shown(&root.join("bin/erl")));
    }
    let (comps, unread) = from(found);
    assert!(unread.is_empty(), "{unread:?}");
    let d = TempDir::new("otp").unwrap();
    let net = Fake::new(move |req| {
        let url = req.url.as_str();
        if url.ends_with("/querybatch") {
            let body = req.body.clone().unwrap_or_default();
            return Ok(testing::querybatch(&body, &|pkg, tag| {
                assert_eq!(pkg, OTP);
                if empty(tag) {
                    vec![]
                } else if affected(tag) {
                    vec!["CVE-2025-32433", "OSV-OTHER"]
                } else {
                    vec!["OSV-OTHER"]
                }
            }));
        }
        if url.ends_with("/vulns/CVE-2025-32433") {
            return Ok(Response::ok(
                serde_json::json!({"id": "CVE-2025-32433", "modified": "m", "summary": "Erlang/OTP SSH server pre-auth code execution",
                    "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/erlang/otp",
                        "events": [{"introduced": "0"}, {"fixed": "ae0052c7f891ce805e2b53493a5304e2ee008aeb"}]}],
                        "versions": listed.iter().map(String::as_str).chain(["OTP_R16B", "patch-base-26"]).collect::<Vec<_>>()}]})
                .to_string(),
            ));
        }
        if url.ends_with("/vulns/OSV-OTHER") {
            return Ok(Response::ok(
                serde_json::json!({"id": "OSV-OTHER", "modified": "m", "summary": "another advisory",
                    "affected": [{"ranges": [{"type": "GIT", "repo": OTP, "events": [{"introduced": "abc"}]}]}]})
                .to_string(),
            ));
        }
        if url == "https://endoflife.date/api/erlang.json" {
            let cycles: Vec<_> =
                ["25", "26", "27", "28"].iter().map(|c| serde_json::json!({"cycle": c, "eol": false})).collect();
            return Ok(Response::ok(serde_json::Value::Array(cycles).to_string()));
        }
        if url.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
            return Ok(Response::not_found());
        }
        panic!("unexpected request {url}")
    });
    let mut s = testing::scan(&net, &d);
    s.cache.put_run(&format!("tags:{OTP}"), "", &serde_json::json!(tags)).unwrap();
    components(&mut s, &comps).unwrap();
    let mut cves: Vec<Fixed> = s
        .findings
        .iter()
        .filter(|f| f.vuln_id == "CVE-2025-32433")
        .map(|f| (f.version.clone(), f.fixed.clone(), f.fix_cmd.clone()))
        .collect();
    cves.sort();
    let mut unchecked: Vec<(String, String)> = s
        .findings
        .iter()
        .filter(|f| f.kind == "unchecked")
        .map(|f| {
            let v =
                comps.iter().find(|c| f.component == format!("Erlang/OTP at {}", c.path)).map(|c| c.version.clone());
            (v.unwrap_or_else(|| f.component.clone()), f.note.clone())
        })
        .collect();
    unchecked.sort();
    drop(home);
    (cves, unchecked)
}

/// The RST oracle for fix versions, on OSV's real lists for CVE-2025-32433
/// (fixed in 25.3.2.20, 26.2.5.11 and 27.3.3): each install is told the
/// lowest fix of its own line, never a tag OSV merely doesn't list
/// (`27.0.1`, which OSV answers nothing for, is as vulnerable). The fix
/// command names the version, not the tag. Side-branch patches, and
/// `26.2.1` that OSV answers nothing for, are reported not checked; the
/// fixed and newest releases are clean.
#[cfg(unix)]
#[test]
fn osv_lists_for_cve_2025_32433_give_fixes_outside_its_ranges() {
    static LISTED: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| otp_tags(LISTED_32433));
    static EMPTY: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| otp_tags(OSV_EMPTY));
    let (cves, unchecked) = scan_otp(
        &[
            "26.2.5",
            "27.3.2",
            "25.3.2.19",
            "27.0",
            "27.0.1",
            "27.2.4",
            "27.2.3",
            "26.2.1",
            "26.2.5.11",
            "27.3.3",
            "28.5.0.8",
        ],
        |t| LISTED.iter().any(|l| l == t),
        |t| EMPTY.iter().any(|l| l == t),
        LISTED.clone(),
        otp_tags(OTP_TAGS),
    );
    let s = |a: &str, b: &str, c: &str| (a.to_string(), b.to_string(), c.to_string());
    assert_eq!(
        cves,
        [
            s("25.3.2.19", "25.3.2.20", "asdf install erlang 25.3.2.20"),
            s("26.2.5", "26.2.5.11", "mise install erlang@26.2.5.11"),
            s("27.0", "27.3.3", "asdf install erlang 27.3.3"),
            s("27.3.2", "27.3.3", "asdf install erlang 27.3.3"),
        ]
    );
    let got: Vec<(&str, &str)> = unchecked.iter().map(|(v, n)| (v.as_str(), n.as_str())).collect();
    assert_eq!(
        got,
        [
            (
                "26.2.1",
                "OSV lists no advisory for OTP-26.2.1 though OTP-26.2.5.21 came after it: OSV's lists for OTP leave some releases out"
            ),
            (
                "27.0.1",
                "OTP-27.0.1 is a patch on a side branch (OTP-27.1 came after the release it patches), which OSV's lists for OTP leave out"
            ),
            (
                "27.2.3",
                "OTP-27.2.3 is a patch on a side branch (OTP-27.3 came after the release it patches), which OSV's lists for OTP leave out"
            ),
            (
                "27.2.4",
                "OTP-27.2.4 is a patch on a side branch (OTP-27.3 came after the release it patches), which OSV's lists for OTP leave out"
            ),
        ]
    );
}

/// The same oracle where OSV answers by CVE-2025-32433's real ranges for
/// every tag (side branches included): 26.2.5 is told 26.2.5.11 and 27.0.1
/// is told 27.3.3, both outside every range; the 25 line 25.3.2.20.
#[cfg(unix)]
#[test]
fn cve_2025_32433_ranges_tell_26_2_5_its_patch_and_27_0_1_27_3_3() {
    static LISTED: std::sync::LazyLock<Vec<String>> =
        std::sync::LazyLock::new(|| otp_tags(OTP_TAGS).into_iter().filter(|t| in_32433_ranges(t)).collect());
    let (cves, _) =
        scan_otp(&["26.2.5", "27.0.1", "25.3.2"], in_32433_ranges, |_| false, LISTED.clone(), otp_tags(OTP_TAGS));
    let s = |a: &str, b: &str, c: &str| (a.to_string(), b.to_string(), c.to_string());
    assert_eq!(
        cves,
        [
            s("25.3.2", "25.3.2.20", "asdf install erlang 25.3.2.20"),
            s("26.2.5", "26.2.5.11", "mise install erlang@26.2.5.11"),
            s("27.0.1", "27.3.3", "asdf install erlang 27.3.3"),
        ]
    );
}

#[test]
fn side_branches_and_unlisted_releases_from_the_tag_list() {
    let tags = otp_tags(OTP_TAGS);
    assert_eq!(side_branch("OTP-27.0.1", &tags).as_deref(), Some("OTP-27.1"));
    assert_eq!(side_branch("OTP-25.1.2.1", &tags).as_deref(), Some("OTP-25.2"));
    assert_eq!(side_branch("OTP-28.3.3", &tags).as_deref(), Some("OTP-28.4"));
    for mainline in ["OTP-26.2.5.11", "OTP-27.3.4.5", "OTP-28.5.0.3", "OTP-27.0", "OTP-27.0-rc1", "27.0.1"] {
        assert_eq!(side_branch(mainline, &tags), None, "{mainline}");
    }
    let at = |v: &str| Component::new("runtime", "erlang", v, "/x/bin/erl");
    let none: Vec<serde_json::Value> = Vec::new();
    let why = unlisted(&at("27.3.3"), Some(&none), &[]).unwrap();
    assert_eq!(why, "OTP's release tags couldn't be listed, so whether OSV's lists include OTP-27.3.3 isn't known");
    // The newest release has no advisory to list; OSV not answering is its
    // own gap, reported with the lookup.
    assert_eq!(unlisted(&at("28.5.0.8"), Some(&none), &tags), None);
    assert_eq!(unlisted(&at("26.2.1"), None, &tags), None);
    assert!(unlisted(&at("26.2.1"), Some(&none), &tags).is_some());
}

/// Before 26.2.5.11 was tagged, 26.2.5's own line had no fix: the fix is a
/// later line's mainline release, never a side-branch patch such as
/// `27.0.1`, which OSV answers nothing for and whose line lists nothing
/// later.
#[cfg(unix)]
#[test]
fn without_a_fix_on_its_line_26_2_5_is_never_told_a_side_branch_patch() {
    static LISTED: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| otp_tags(LISTED_32433));
    static EMPTY: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| otp_tags(OSV_EMPTY));
    let tags: Vec<String> = otp_tags(OTP_TAGS)
        .into_iter()
        .filter(|t| !t.starts_with("OTP-26.2.5.") || crate::checks::ecosystems::versions::lt(t, "OTP-26.2.5.11"))
        .collect();
    let (cves, _) = scan_otp(
        &["26.2.5"],
        |t| LISTED.iter().any(|l| l == t),
        |t| EMPTY.iter().any(|l| l == t),
        LISTED.clone(),
        tags,
    );
    assert_eq!(cves, [("26.2.5".to_string(), "27.3.4.19".to_string(), "mise install erlang@27.3.4.19".to_string())]);
}
