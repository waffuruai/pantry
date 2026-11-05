//! Linux distros whose advisories aren't in OSV, through their own sources:
//! dnf's (or yum's) security advisories for Fedora, RHEL, CentOS, Rocky,
//! Alma, Oracle and Amazon Linux, and the Arch security tracker. Unchanged
//! from Python (F6).

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::sources::file::url;
use crate::utils::json::{self, str_at};
use crate::utils::net::{self, Net};
use crate::utils::process::exec;
use crate::utils::process::which;
use crate::utils::sha256;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

/// One applicable distro advisory.
#[derive(Clone, Debug, PartialEq)]
pub struct Vulnerable {
    pub name: String,
    pub installed: String,
    pub fixed: String,
    pub advisory: String,
    pub severity: String,
    pub issues: Vec<String>,
}

#[derive(Debug, Default, PartialEq)]
pub struct Advisories {
    pub packages: i64,
    pub vulnerable: Vec<Vulnerable>,
    pub unfixed: i64,
}

/// ("openssl-libs", "1:3.5.9-1.fc44") from "openssl-libs-1:3.5.9-1.fc44.aarch64".
pub fn split_nevra(nevra: &str) -> (String, String) {
    let Some((nevr, _arch)) = nevra.rsplit_once('.') else { return Default::default() };
    let Some((nev, release)) = nevr.rsplit_once('-') else { return Default::default() };
    let Some((name, version)) = nev.rsplit_once('-') else { return Default::default() };
    if name.is_empty() || version.is_empty() || release.is_empty() || release.contains('-') {
        return Default::default();
    }
    let ver = version.split_once(':').map(|(_, v)| v).unwrap_or(version);
    if ver.is_empty() {
        return Default::default();
    }
    (name.to_string(), format!("{version}-{release}"))
}

/// (advisory, severity, nevra) from a dnf4 or yum `updateinfo list` line.
pub fn dnf4_line(line: &str) -> Option<(String, String, String)> {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        [adv, sev, nevra] => sev
            .strip_suffix("/Sec.")
            .filter(|s| !s.is_empty())
            .map(|s| (adv.to_string(), s.to_string(), nevra.to_string())),
        _ => None,
    }
}

fn run(argv: &[&OsStr], timeout: u64) -> Result<crate::utils::process::Output> {
    exec(argv, &[], Duration::from_secs(timeout))
}

/// Advisories dnf says apply to installed packages and have an update.
/// dnf5 answers in JSON; dnf4 and yum in text. A failure (no repo
/// metadata, no network) is never cached as a clean result.
pub fn dnf_advisories(cache: &Cache, refresh: bool, offline: bool) -> Result<Advisories> {
    dnf_advisories_with(cache, refresh, offline, which("dnf"), which("yum"), which("rpm"))
}

/// [`dnf_advisories`] with the tools found (or not) on PATH.
fn dnf_advisories_with(
    cache: &Cache,
    refresh: bool,
    offline: bool,
    dnf: Option<PathBuf>,
    yum: Option<PathBuf>,
    rpm: Option<PathBuf>,
) -> Result<Advisories> {
    let Some(rpm) = rpm.filter(|_| dnf.is_some() || yum.is_some()) else {
        return Err(Error::Offline("neither dnf nor yum is installed".into()));
    };
    let listing = run(
        &[rpm.as_os_str(), "-qa".as_ref(), "--qf".as_ref(), "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n".as_ref()],
        300,
    )?;
    let mut installed = BTreeMap::new();
    for line in listing.stdout.lines() {
        let (name, ver) = line.split_once(' ').unwrap_or((line, ""));
        installed.insert(name.to_string(), ver.strip_prefix("0:").unwrap_or(ver).to_string());
    }
    let scan = || -> Result<Value> {
        let mut rows: Vec<(String, String, String)> = Vec::new();
        let dnf5 = match &dnf {
            Some(d) => Some(run(
                &[
                    d.as_os_str(),
                    "-q".as_ref(),
                    "advisory".as_ref(),
                    "list".as_ref(),
                    "--security".as_ref(),
                    "--updates".as_ref(),
                    "--json".as_ref(),
                ],
                900,
            )?),
            None => None,
        };
        match dnf5 {
            Some(p) if p.code == Some(0) && p.stdout.trim_start().starts_with('[') => {
                for a in
                    json::parse(p.stdout.as_bytes(), json::MAX_DOCUMENT)?.as_array().map(Vec::as_slice).unwrap_or(&[])
                {
                    rows.push((str_at(a, "name").into(), str_at(a, "severity").into(), str_at(a, "nevra").into()));
                }
            }
            _ => {
                // dnf4 or yum (a dnf5 that failed fails the same way here)
                let p = match (&dnf, &yum) {
                    (Some(d), _) => run(
                        &[
                            d.as_os_str(),
                            "-q".as_ref(),
                            "updateinfo".as_ref(),
                            "list".as_ref(),
                            "--security".as_ref(),
                            "--available".as_ref(),
                        ],
                        900,
                    )?,
                    (None, Some(y)) => run(
                        &[y.as_os_str(), "-q".as_ref(), "updateinfo".as_ref(), "list".as_ref(), "security".as_ref()],
                        900,
                    )?,
                    (None, None) => unreachable!("checked above"),
                };
                if p.code != Some(0) {
                    let tail = p.stderr.trim().lines().last().unwrap_or("no output").to_string();
                    return Err(Error::Offline(format!("dnf couldn't load security advisories: {tail}")));
                }
                rows.extend(p.stdout.lines().filter_map(|l| dnf4_line(l.trim())));
            }
        }
        let mut out = Vec::new();
        for (advisory, severity, nevra) in rows {
            let (name, fixed) = split_nevra(&nevra);
            if let Some(have) = installed.get(&name) {
                out.push(json!({"name": name, "installed": have, "fixed": fixed, "advisory": advisory, "severity": severity.to_uppercase()}));
            }
        }
        Ok(json!({"packages": installed.len(), "vulnerable": out}))
    };
    let fp = sha256::hex(installed.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join("\n").as_bytes());
    let res = cache.memo("dnf", scan, DAY, &fp, refresh, offline)?;
    Ok(from_json(&res))
}

fn from_json(res: &Value) -> Advisories {
    Advisories {
        packages: res.get("packages").and_then(Value::as_i64).unwrap_or(0),
        unfixed: res.get("unfixed").and_then(Value::as_i64).unwrap_or(0),
        vulnerable: json::arr_at(res, "vulnerable")
            .iter()
            .map(|p| Vulnerable {
                name: str_at(p, "name").into(),
                installed: str_at(p, "installed").into(),
                fixed: str_at(p, "fixed").into(),
                advisory: str_at(p, "advisory").into(),
                severity: str_at(p, "severity").into(),
                issues: json::strs_at(p, "issues"),
            })
            .collect(),
    }
}

/// Tracker groups that apply to installed packages, compared with pacman's
/// own vercmp.
pub fn arch_advisories(cache: &Cache, groups: &Value) -> Result<Advisories> {
    arch_advisories_with(cache, groups, which("pacman"), which("vercmp"))
}

/// [`arch_advisories`] with the tools found (or not) on PATH.
fn arch_advisories_with(
    cache: &Cache,
    groups: &Value,
    pacman: Option<PathBuf>,
    vercmp: Option<PathBuf>,
) -> Result<Advisories> {
    let pacman = pacman.ok_or_else(|| Error::Offline("pacman isn't installed".into()))?;
    let listing = run(&[pacman.as_os_str(), "-Q".as_ref()], 60)?;
    let installed: BTreeMap<String, String> =
        listing.stdout.lines().filter_map(|l| l.split_once(' ')).map(|(n, v)| (n.to_string(), v.to_string())).collect();
    let older = |a: &str, b: &str| -> bool {
        match &vercmp {
            None => crate::checks::ecosystems::versions::lt(a, b),
            Some(v) => {
                run(&[v.as_os_str(), a.as_ref(), b.as_ref()], 15)
                    .ok()
                    .and_then(|o| o.stdout.trim().parse::<i64>().ok())
                    .unwrap_or(0)
                    < 0
            }
        }
    };
    let mut out = Advisories { packages: installed.len() as i64, ..Default::default() };
    for g in groups.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let (fixed, affected) = (str_at(g, "fixed"), str_at(g, "affected"));
        for name in json::strs_at(g, "packages") {
            let Some(have) = installed.get(&name) else { continue };
            if !fixed.is_empty() && older(have, fixed) {
                let issues = json::strs_at(g, "issues");
                let ty = match str_at(g, "type") {
                    "" => "vulnerability",
                    t => t,
                };
                cache.put_vuln(
                    &json!({"id": str_at(g, "name"), "aliases": issues, "summary": format!("{ty} in {name}"),
                                       "affected": [{"package": {"ecosystem": "Arch", "name": name}}],
                                       "database_specific": {"severity": str_at(g, "severity")}}),
                )?;
                out.vulnerable.push(Vulnerable {
                    name: name.clone(),
                    installed: have.clone(),
                    fixed: fixed.into(),
                    advisory: str_at(g, "name").into(),
                    severity: str_at(g, "severity").to_uppercase(),
                    issues,
                });
            } else if fixed.is_empty()
                && str_at(g, "status") == "Vulnerable"
                && !affected.is_empty()
                && !older(have, affected)
            {
                out.unfixed += 1;
            }
        }
    }
    cache.commit()?;
    Ok(out)
}

/// The Arch Linux security tracker's advisory groups.
pub fn arch(cache: &Cache, net: &dyn Net, offline: bool) -> Result<Value> {
    let fetch = || match net::get_json(net, url("arch-security"), &[])? {
        Some(Value::Array(groups)) if !groups.is_empty() => Ok(Value::Array(groups)),
        _ => Err(Error::Offline("the Arch security tracker returned nothing".into())),
    };
    cache.memo("arch-tracker", fetch, DAY, "", false, offline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::testing::cache;
    use crate::utils::net::{Fake, Response};

    // The test vectors the Python implementation had (`Parsers.test_dnf_parsing`).
    #[test]
    fn dnf_parsing() {
        assert_eq!(
            split_nevra("openssl-libs-1:3.5.9-1.fc44.aarch64"),
            ("openssl-libs".into(), "1:3.5.9-1.fc44".into())
        );
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
}
