//! The external tools this implementation runs, for `wpantry tools`
//! (`specs/cli-contract.md#tools---json`). The list is per implementation:
//! the Rust one reads lockfiles, package databases and image contents
//! itself, so osv-scanner is not on it.

use crate::json::{J, obj};
use crate::system::{run, which};
use std::time::Duration;

/// (name, required, version arguments, what wpantry uses it for)
pub const TOOLS: &[(&str, bool, &[&str], &str)] = &[
    ("gitleaks", true, &["version"], "secrets in the repos' git history"),
    ("clamscan", false, &["--version"], "malware signatures over documents and images (ClamAV)"),
    ("git", true, &["--version"], "repo HEADs, upstream release tags, the malicious-package index"),
    ("openssl", true, &["version"], "the CA trust check"),
    (
        "brew",
        false,
        &["--version"],
        "Homebrew's own patch awareness (brew vulns); without it, formulae are read from the Cellar and checked against OSV",
    ),
    ("docker", false, &["--version"], "the Docker engine and local container images (or podman)"),
    ("rpm", false, &["--version"], "openSUSE and SUSE package databases"),
];

#[derive(Clone, Debug, PartialEq)]
pub struct Tool {
    pub name: String,
    pub required: bool,
    pub found: bool,
    pub path: String,
    pub version: String,
    pub purpose: String,
}

impl Tool {
    pub fn to_json(&self) -> J {
        obj([
            ("name", self.name.as_str().into()),
            ("required", self.required.into()),
            ("found", self.found.into()),
            ("path", self.path.as_str().into()),
            ("version", self.version.as_str().into()),
            ("purpose", self.purpose.as_str().into()),
        ])
    }
}

/// The first dotted version number in a tool's output.
pub fn version_in(text: &str) -> String {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            let mut end = i;
            let mut parts = 0;
            loop {
                while end < b.len() && b[end].is_ascii_digit() {
                    end += 1;
                }
                parts += 1;
                if end + 1 < b.len() && b[end] == b'.' && b[end + 1].is_ascii_digit() {
                    end += 1;
                } else {
                    break;
                }
            }
            if parts >= 2 {
                return text[start..end].to_string();
            }
            i = end;
        } else {
            i += 1;
        }
    }
    String::new()
}

/// Every tool in [`TOOLS`] order, found or not.
pub fn tools() -> Vec<Tool> {
    TOOLS
        .iter()
        .map(|(name, required, args, purpose)| {
            let exe = which(name);
            let version = exe
                .as_ref()
                .map(|e| {
                    let mut argv = vec![e.as_os_str()];
                    argv.extend(args.iter().map(std::ffi::OsStr::new));
                    version_in(&run(&argv, Duration::from_secs(15)))
                })
                .unwrap_or_default();
            Tool {
                name: name.to_string(),
                required: *required,
                found: exe.is_some(),
                path: exe.map(|e| e.to_string_lossy().into_owned()).unwrap_or_default(),
                version,
                purpose: purpose.to_string(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_in_tool_output() {
        assert_eq!(version_in("git version 2.43.0"), "2.43.0");
        assert_eq!(version_in("v8.30.1"), "8.30.1");
        assert_eq!(version_in("RPM version 4.19.1.1"), "4.19.1.1");
        assert_eq!(version_in("Docker version 27.3.1, build ce12230"), "27.3.1");
        assert_eq!(version_in("build 7 of 12"), "");
    }
}
