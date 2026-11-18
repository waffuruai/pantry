use super::*;
use crate::checks::machine::components::components;
use crate::checks::machine::testing;
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;

/// A .NET root with the given (folder, version, marker file) installs.
fn root(at: &Path, installs: &[(&str, &str, &str)]) {
    for (dir, v, marker) in installs {
        testing::write(&at.join(dir).join(v).join(marker), "{}");
    }
}

const NETCORE: &str = "shared/Microsoft.NETCore.App";
const ASPNET: &str = "shared/Microsoft.AspNetCore.App";
const NETCORE_DEPS: &str = "Microsoft.NETCore.App.deps.json";
const ASPNET_DEPS: &str = "Microsoft.AspNetCore.App.deps.json";

#[test]
fn runtime_identifiers_name_the_runtime_packs() {
    assert_eq!(rid_of("macos", "aarch64").as_deref(), Some("osx-arm64"));
    assert_eq!(rid_of("macos", "x86_64").as_deref(), Some("osx-x64"));
    assert_eq!(rid_of("linux", "x86_64").as_deref(), Some("linux-x64"));
    assert_eq!(rid_of("linux", "aarch64").as_deref(), Some("linux-arm64"));
    assert_eq!(rid_of("linux", "arm").as_deref(), Some("linux-arm"));
    assert_eq!(rid_of("windows", "x86").as_deref(), Some("win-x86"));
    assert_eq!(rid_of("freebsd", "x86_64"), None);
    assert_eq!(rid_of("linux", "riscv64"), None);
}

#[test]
fn runtimes_and_sdks_from_their_version_folders() {
    let d = TempDir::new("dotnet").unwrap();
    let r = d.path().join("dotnet");
    root(
        &r,
        &[
            (NETCORE, "8.0.10", NETCORE_DEPS),
            (NETCORE, "10.0.0-rc.2.25502.107", NETCORE_DEPS),
            (ASPNET, "8.0.10", ASPNET_DEPS),
            ("sdk", "8.0.403", "dotnet.dll"),
        ],
    );
    // Not installs: a folder whose name isn't a version, a leftover folder
    // without the runtime's files, and a stray file.
    std::fs::create_dir_all(r.join(NETCORE).join("current")).unwrap();
    testing::write(&r.join(NETCORE).join("latest").join(NETCORE_DEPS), "{}");
    std::fs::create_dir_all(r.join(NETCORE).join("8.0.9")).unwrap();
    testing::write(&r.join("sdk").join("NuGetFallbackFolder").join("dotnet.dll"), "");
    testing::write(&r.join("sdk").join("9.0.100"), "");
    let rs = realpath(&r.display().to_string());
    let found = at_roots(&[r.display().to_string()], Some("osx-arm64"));
    let got: Vec<(&str, &str, &str)> =
        found.iter().map(|c| (c.kind.as_str(), c.name.as_str(), c.version.as_str())).collect();
    assert_eq!(
        got,
        [
            ("runtime", "dotnet-runtime", "10.0.0-rc.2.25502.107"),
            ("runtime", "dotnet-runtime", "8.0.10"),
            ("runtime", "aspnetcore-runtime", "8.0.10"),
            ("compiler", "dotnet-sdk", "8.0.403"),
        ]
    );
    let c = &found[1];
    assert_eq!(c.path, format!("{rs}/{NETCORE}/8.0.10"));
    assert_eq!(c.osv, Some(("NuGet".into(), "Microsoft.NETCore.App.Runtime.osx-arm64".into(), "8.0.10".into())));
    assert_eq!(c.eol, Some(("dotnet".into(), "8".into())));
    assert_eq!((c.fix.as_str(), c.auto), (&*format!("{FIX} {rs}/{NETCORE}/8.0.10"), false));
    assert_eq!(found[0].eol, Some(("dotnet".into(), "10".into())));
    assert_eq!(found[2].osv.as_ref().unwrap().1, "Microsoft.AspNetCore.App.Runtime.osx-arm64");
    // The SDK has no OSV package: only its end of life is judged.
    assert_eq!((found[3].osv.clone(), found[3].eol.clone()), (None, Some(("dotnet".into(), "8".into()))));
    // No runtime identifier for this machine: no OSV mapping, end of life still.
    let bare = at_roots(&[r.display().to_string()], None);
    assert!(bare.iter().all(|c| c.osv.is_none() && c.eol.is_some()), "{bare:?}");
}

#[cfg(unix)]
#[test]
fn each_root_once_and_vouched_roots_left_to_their_owner() {
    let d = TempDir::new("dotnet").unwrap();
    let r = d.path().join("dotnet");
    root(&r, &[(NETCORE, "8.0.10", NETCORE_DEPS)]);
    std::os::unix::fs::symlink(&r, d.path().join("alias")).unwrap();
    // A Homebrew formula's root: `brew vulns` checks it.
    let brew = d.path().join("Cellar/dotnet/8.0.10/libexec");
    root(&brew, &[(NETCORE, "8.0.10", NETCORE_DEPS)]);
    let roots = [
        r.display().to_string(),
        d.path().join("alias").display().to_string(),
        format!("{}/", r.display()),
        brew.display().to_string(),
        d.path().join("missing").display().to_string(),
    ];
    let found = at_roots(&roots, Some("linux-x64"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].osv.as_ref().unwrap().1, "Microsoft.NETCore.App.Runtime.linux-x64");
}

#[test]
fn installs_reads_the_install_script_folder_under_home() {
    let home = crate::utils::files::test_home();
    let r = crate::utils::files::home().join(".dotnet");
    root(&r, &[(ASPNET, "9.0.5", ASPNET_DEPS)]);
    let found = installs();
    let want = realpath(&r.join(ASPNET).join("9.0.5").display().to_string());
    assert!(found.iter().any(|c| c.name == "aspnetcore-runtime" && c.path == want), "{found:?}");
    drop(home);
}

/// An OSV record for a NuGet runtime pack, fixed in `fixed`.
fn nuget_rec(id: &str, pack: &str, fixed: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "modified": "m", "summary": format!("{id} summary"),
        "affected": [{"package": {"ecosystem": "NuGet", "name": pack},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "8.0.0"}, {"fixed": fixed}]}]}]})
}

/// The RST oracle: 8.0.10 fails its runtime packs' advisories and .NET 8's
/// end of life (2026-11-10); 10.0.15, the latest release at the time, the
/// same harness passes.
#[test]
fn runtime_8_0_10_fails_advisories_and_end_of_life_and_10_0_15_passes() {
    let d = TempDir::new("dotnet").unwrap();
    let r = d.path().join("dotnet");
    root(
        &r,
        &[
            (NETCORE, "8.0.10", NETCORE_DEPS),
            (ASPNET, "8.0.10", ASPNET_DEPS),
            (NETCORE, "10.0.15", NETCORE_DEPS),
            (ASPNET, "10.0.15", ASPNET_DEPS),
        ],
    );
    let net = Fake::new(|req| {
        let url = req.url.as_str();
        if url.ends_with("/querybatch") {
            let body = req.body.clone().unwrap_or_default();
            return Ok(testing::querybatch(&body, &|pkg, v| match (pkg, v) {
                ("Microsoft.NETCore.App.Runtime.osx-arm64", "8.0.10") => vec!["GHSA-net1"],
                ("Microsoft.AspNetCore.App.Runtime.osx-arm64", "8.0.10") => vec!["GHSA-asp1"],
                _ => vec![],
            }));
        }
        if url.contains("/vulns/") {
            let id = url.rsplit('/').next().unwrap_or("");
            let pack = if id == "GHSA-net1" {
                "Microsoft.NETCore.App.Runtime.osx-arm64"
            } else {
                "Microsoft.AspNetCore.App.Runtime.osx-arm64"
            };
            return Ok(Response::ok(nuget_rec(id, pack, "8.0.11").to_string()));
        }
        if url == "https://endoflife.date/api/dotnet.json" {
            return Ok(Response::ok(
                serde_json::json!([{"cycle": "10", "eol": "2028-11-14", "latest": "10.0.15"},
                                   {"cycle": "8", "eol": "2026-11-10", "latest": "8.0.34"}])
                .to_string(),
            ));
        }
        if url.starts_with("https://osv-vulnerabilities.storage.googleapis.com/") {
            return Ok(Response::not_found());
        }
        panic!("unexpected request {url}")
    });
    let mut s = testing::scan(&net, &d);
    let found = at_roots(&[r.display().to_string()], Some("osx-arm64"));
    assert_eq!(found.len(), 4, "{found:?}");
    components(&mut s, &found).unwrap();
    let got: Vec<(String, String, String, String)> = s
        .findings
        .iter()
        .map(|f| (f.component.clone(), f.version.clone(), f.vuln_id.clone(), f.status.clone()))
        .collect();
    let row = |c: &str, v: &str, id: &str| (c.to_string(), v.to_string(), id.to_string(), "fail".to_string());
    assert_eq!(
        got,
        [
            row("dotnet-runtime", "8.0.10", "GHSA-net1"),
            row("dotnet-runtime", "8.0.10", "EOL"),
            row("aspnetcore-runtime", "8.0.10", "GHSA-asp1"),
            row("aspnetcore-runtime", "8.0.10", "EOL"),
        ],
        "{got:?}"
    );
    assert_eq!(s.findings[0].fixed, "8.0.11");
    assert!(
        s.findings[0]
            .fix_cmd
            .starts_with("Install .NET 8.0.11 (https://dotnet.microsoft.com/download/dotnet), then remove ")
    );
    assert_eq!(s.findings[1].note, "dotnet 8 reached end of life on 2026-11-10; supported: 10");
}
