use super::*;
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Response};

// The test vectors the Python implementation had (`Parsers.test_dnf_parsing`).
#[test]
fn dnf_parsing() {
    assert_eq!(split_nevra("openssl-libs-1:3.5.9-1.fc44.aarch64"), ("openssl-libs".into(), "1:3.5.9-1.fc44".into()));
    assert_eq!(
        split_nevra("ca-certificates-2026.2.92_v9.0.319-2.fc44.noarch"),
        ("ca-certificates".into(), "2026.2.92_v9.0.319-2.fc44".into())
    );
    assert_eq!(
        dnf4_line("RLSA-2025:23343 Moderate/Sec.  binutils-2.35.2-67.el9_7.1.aarch64"),
        Some(("RLSA-2025:23343".into(), "Moderate".into(), "binutils-2.35.2-67.el9_7.1.aarch64".into()))
    );
    assert_eq!(dnf4_line("Last metadata expiration check"), None);
}

#[test]
fn nevra_edge_cases() {
    let none = (String::new(), String::new());
    assert_eq!(split_nevra("bash"), none);
    assert_eq!(split_nevra("bash.x86_64"), none);
    assert_eq!(split_nevra("bash-5.2.x86_64"), none);
    assert_eq!(split_nevra("-5.2-1.x86_64"), none, "no name");
    assert_eq!(split_nevra("bash-1:-1.x86_64"), none, "no version after the epoch");
    assert_eq!(dnf4_line("RLSA-1 /Sec. x"), None, "no severity");
    assert_eq!(dnf4_line("RLSA-1 Moderate/Sec."), None);
}

#[test]
fn advisories_from_json_default_every_field() {
    let a = from_json(&json!({"packages": 3, "unfixed": 1, "vulnerable": [{"name": "x", "issues": ["CVE-1", 7]}]}));
    assert_eq!(a.packages, 3);
    assert_eq!(a.unfixed, 1);
    assert_eq!(a.vulnerable[0].issues, ["CVE-1"]);
    assert_eq!(a.vulnerable[0].severity, "");
    assert_eq!(from_json(&json!({})), Advisories::default());
}

/// A fake tool: a shell script printing what the real one would.
fn tool(dir: &std::path::Path, name: &str, script: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{script}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

const RPM: &str = "printf 'openssl-libs 1:3.5.9-1.fc44\\nbinutils 0:2.35.2-67.el9_7.1\\nbash 0:5.2-1\\n'";

#[test]
fn dnf5_answers_in_json_dnf4_and_yum_in_text() {
    let d = crate::utils::temp::TempDir::new("dnf").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let rpm = tool(d.path(), "rpm", RPM);
    let dnf5 = tool(
        d.path(),
        "dnf5",
        concat!(
            "case \"$*\" in *--json*) echo '[{\"name\": \"FEDORA-2026-1\", \"severity\": \"Important\", ",
            "\"nevra\": \"openssl-libs-1:3.6.0-1.fc44.aarch64\"}, {\"name\": \"FEDORA-2026-2\", \"severity\": \"Low\", ",
            "\"nevra\": \"notinstalled-1.0-1.fc44.noarch\"}]';; *) exit 1;; esac"
        ),
    );
    let got = dnf_advisories_with(&c, false, false, Some(dnf5), None, Some(rpm.clone())).unwrap();
    assert_eq!(got.packages, 3);
    assert_eq!(
        got.vulnerable,
        [Vulnerable {
            name: "openssl-libs".into(),
            installed: "1:3.5.9-1.fc44".into(),
            fixed: "1:3.6.0-1.fc44".into(),
            advisory: "FEDORA-2026-1".into(),
            severity: "IMPORTANT".into(),
            issues: vec![],
        }]
    );
    // The day's answer is reused for the same installed set, even offline.
    let broken = tool(d.path(), "broken", "exit 7");
    assert_eq!(dnf_advisories_with(&c, false, true, Some(broken.clone()), None, Some(rpm.clone())).unwrap(), got);
    assert_eq!(dnf_advisories_with(&c, false, false, Some(broken), None, Some(rpm.clone())).unwrap(), got);
    // dnf4 (no --json) and yum answer in text; a refresh asks again.
    let dnf4 = tool(
        d.path(),
        "dnf4",
        concat!(
            "case \"$*\" in *--json*) exit 1;; *) printf 'Last metadata expiration check: 0:01:00 ago\\n",
            "RLSA-2025:23343 Moderate/Sec.  binutils-2.35.2-67.el9_7.2.aarch64\\n';; esac"
        ),
    );
    let got = dnf_advisories_with(&c, true, false, Some(dnf4), None, Some(rpm.clone())).unwrap();
    assert_eq!((got.vulnerable[0].name.as_str(), got.vulnerable[0].severity.as_str()), ("binutils", "MODERATE"));
    assert_eq!(got.vulnerable[0].fixed, "2.35.2-67.el9_7.2");
    let yum = tool(d.path(), "yum", "echo 'ALSA-1 Critical/Sec. bash-5.2-2.el9.x86_64'");
    let got = dnf_advisories_with(&c, true, false, None, Some(yum), Some(rpm)).unwrap();
    assert_eq!((got.vulnerable[0].advisory.as_str(), got.vulnerable[0].installed.as_str()), ("ALSA-1", "5.2-1"));
}

#[test]
fn dnf_failures_are_never_cached_as_clean() {
    let d = crate::utils::temp::TempDir::new("dnf").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let rpm = tool(d.path(), "rpm", RPM);
    assert!(matches!(dnf_advisories_with(&c, false, false, None, None, None), Err(Error::Offline(_))));
    assert!(matches!(dnf_advisories_with(&c, false, false, None, None, Some(rpm.clone())), Err(Error::Offline(_))));
    let dnf = tool(d.path(), "dnf", "echo 'Error: Failed to download metadata' >&2; exit 1");
    let e = dnf_advisories_with(&c, false, false, Some(dnf), None, Some(rpm.clone())).unwrap_err();
    assert_eq!(e.to_string(), "dnf: dnf couldn't load security advisories: Error: Failed to download metadata");
    assert!(matches!(dnf_advisories_with(&c, false, true, None, None, Some(rpm)), Err(Error::Offline(_))));
    let missing = d.path().join("no-such-rpm");
    assert!(dnf_advisories_with(&c, false, false, Some(missing.clone()), None, Some(missing)).is_err());
}

#[test]
fn arch_groups_apply_to_installed_packages() {
    let d = crate::utils::temp::TempDir::new("arch").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let groups = json!([
        {"name": "ASA-1", "packages": ["openssl", "ghost"], "fixed": "3.6.0-1", "affected": "3.5.9-1", "status": "Fixed",
         "severity": "High", "type": "arbitrary code execution", "issues": ["CVE-2026-1"]},
        {"name": "ASA-2", "packages": ["bash"], "fixed": "", "affected": "5.2-1", "status": "Vulnerable", "severity": "Low"},
        {"name": "ASA-3", "packages": ["curl"], "fixed": "9", "affected": "8.0-1", "status": "Testing", "severity": "Medium"},
        {"name": "ASA-4", "packages": ["bash"], "fixed": "", "affected": "5.3-1", "status": "Vulnerable"}
    ]);
    assert!(matches!(arch_advisories_with(&c, &groups, None, None), Err(Error::Offline(_))));
    let pacman = tool(d.path(), "pacman", "printf 'openssl 3.5.9-1\\nbash 5.2-1\\ncurl 8.0-1\\nodd\\n'");
    // Without vercmp, our own comparison decides.
    let got = arch_advisories_with(&c, &groups, Some(pacman.clone()), None).unwrap();
    assert_eq!((got.packages, got.unfixed), (3, 1));
    let names: Vec<(&str, &str)> = got.vulnerable.iter().map(|v| (v.name.as_str(), v.advisory.as_str())).collect();
    assert_eq!(names, [("openssl", "ASA-1"), ("curl", "ASA-3")]);
    assert_eq!(got.vulnerable[0].issues, ["CVE-2026-1"]);
    assert_eq!(got.vulnerable[0].severity, "HIGH");
    let stored = c.vuln("ASA-3").unwrap().unwrap();
    assert_eq!(stored["summary"], "vulnerability in curl");
    assert_eq!(c.vuln("ASA-1").unwrap().unwrap()["summary"], "arbitrary code execution in openssl");
    // pacman's vercmp, when present, is asked instead (here: nothing is older).
    let vercmp = tool(d.path(), "vercmp", "echo 0");
    let got = arch_advisories_with(&c, &groups, Some(pacman.clone()), Some(vercmp)).unwrap();
    assert_eq!((got.vulnerable.len(), got.unfixed), (0, 2));
    let garbage = tool(d.path(), "vercmp-garbage", "echo nope");
    assert_eq!(arch_advisories_with(&c, &groups, Some(pacman), Some(garbage)).unwrap().unfixed, 2);
    assert!(arch_advisories_with(&c, &json!({}), Some(d.path().join("missing")), None).is_err());
}

#[test]
fn arch_tracker_must_answer_with_groups() {
    let (_d, c) = cache();
    assert!(matches!(arch(&c, &Fake::new(|_| Ok(Response::ok("[]"))), false), Err(Error::Offline(_))));
    assert!(matches!(arch(&c, &Fake::new(|_| Ok(Response::ok("{}"))), false), Err(Error::Offline(_))));
    let net = Fake::new(|_| Ok(Response::ok(json!([{"name": "ASA-1"}]).to_string())));
    assert_eq!(arch(&c, &net, false).unwrap()[0]["name"], "ASA-1");
    assert_eq!(arch(&c, &Fake::offline(), true).unwrap()[0]["name"], "ASA-1");
}
