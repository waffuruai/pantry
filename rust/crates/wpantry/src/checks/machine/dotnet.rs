//! .NET runtimes and SDKs, read from the install folders: one `dotnet` root
//! holds every runtime and SDK installed side by side, as version folders
//! under `shared/Microsoft.NETCore.App/`, `shared/Microsoft.AspNetCore.App/`
//! and `sdk/`. Nothing is run: `dotnet --list-runtimes` prints the same
//! folders, and reading them avoids the CLI's first-run work.
//!
//! A runtime is checked against OSV as the NuGet runtime pack for this
//! machine (`Microsoft.NETCore.App.Runtime.osx-arm64`), which the .NET
//! advisories name, and against endoflife.date's `dotnet` by major. An SDK
//! has no package of its own in OSV, so only its end of life is judged.

use crate::checks::machine::catalog::DOTNET_DIRS;
use crate::component::Component;
use crate::utils::files::{expand, owner, realpath};
use crate::utils::process::on_path;
use crate::utils::re::Regex;
use std::path::Path;

/// (folder under the root, component name, OSV runtime pack prefix, file
/// every real install of it has). The pack is None for the SDK.
const PARTS: &[(&str, &str, Option<&str>, &str)] = &[
    (
        "shared/Microsoft.NETCore.App",
        "dotnet-runtime",
        Some("Microsoft.NETCore.App.Runtime"),
        "Microsoft.NETCore.App.deps.json",
    ),
    (
        "shared/Microsoft.AspNetCore.App",
        "aspnetcore-runtime",
        Some("Microsoft.AspNetCore.App.Runtime"),
        "Microsoft.AspNetCore.App.deps.json",
    ),
    ("sdk", "dotnet-sdk", None, "dotnet.dll"),
];

/// How to update: Microsoft's download page; installs side by side, so the
/// old version stays until removed. Never run unattended.
const FIX: &str = "Install .NET {safe} (https://dotnet.microsoft.com/download/dotnet), then remove";

/// The .NET runtime identifier for an OS and CPU (`std::env::consts`
/// names), as the runtime packs are named; None where .NET has none.
pub fn rid_of(os: &str, arch: &str) -> Option<String> {
    let os = match os {
        "macos" => "osx",
        "linux" => "linux",
        "windows" => "win",
        _ => return None,
    };
    let arch = match arch {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "arm" => "arm",
        "x86" => "x86",
        _ => return None,
    };
    Some(format!("{os}-{arch}"))
}

/// Every .NET install on this machine: `$DOTNET_ROOT`, the root of each
/// `dotnet` on PATH, and the usual install folders.
pub fn installs() -> Vec<Component> {
    let mut roots: Vec<String> = std::env::var("DOTNET_ROOT").ok().filter(|r| !r.is_empty()).into_iter().collect();
    for (_, real) in on_path("dotnet", &[] as &[&str]) {
        if let Some(dir) = Path::new(&real).parent() {
            roots.push(dir.display().to_string());
        }
    }
    roots.extend(expand(DOTNET_DIRS));
    at_roots(&roots, rid_of(std::env::consts::OS, std::env::consts::ARCH).as_deref())
}

/// The runtimes and SDKs under each root, each root once. A root someone
/// else vouches for (a Homebrew formula, the distro's package) is theirs to
/// check, judged by the `dotnet` it holds.
pub fn at_roots(roots: &[String], rid: Option<&str>) -> Vec<Component> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for r in roots {
        let real = realpath(r);
        if seen.contains(&real) || !Path::new(&real).is_dir() {
            continue;
        }
        seen.push(real.clone());
        if !owner(&format!("{}/dotnet", real.trim_end_matches('/'))).is_empty() {
            continue;
        }
        out.extend(at(Path::new(&real), rid));
    }
    out
}

/// The runtimes and SDKs in one root, in folder-name order. A folder
/// whose name isn't a version, or that lacks the files an install has, is
/// skipped: a leftover folder is not an install.
fn at(root: &Path, rid: Option<&str>) -> Vec<Component> {
    let version = Regex::new(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?");
    let mut out = Vec::new();
    for (dir, name, pack, marker) in PARTS {
        let Ok(rd) = std::fs::read_dir(root.join(dir)) else { continue };
        let mut found: Vec<String> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|v| version.fullmatch(v).is_some())
            .filter(|v| root.join(dir).join(v).join(marker).is_file())
            .collect();
        found.sort();
        for v in found {
            let path = root.join(dir).join(&v).display().to_string();
            let mut c = Component::new(if pack.is_some() { "runtime" } else { "compiler" }, name, &v, &path);
            if let (Some(pack), Some(rid)) = (pack, rid) {
                c.osv = Some(("NuGet".into(), format!("{pack}.{rid}"), v.clone()));
            }
            c.eol = Some(("dotnet".into(), v.split('.').next().unwrap_or("").to_string()));
            c.fix = format!("{FIX} {path}");
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
#[path = "dotnet_tests.rs"]
mod tests;
