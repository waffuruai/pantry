//! Linux distros whose advisories aren't in OSV, through their own sources:
//! dnf's (or yum's) security advisories for Fedora, RHEL, CentOS, Rocky,
//! Alma, Oracle and Amazon Linux, and the Arch security tracker. Unchanged
//! from Python (F6).

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::json::{self, str_at};
use crate::sha256;
use crate::system::{exec, which};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsStr;
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

fn run(argv: &[&OsStr], timeout: u64) -> Result<crate::system::Output> {
    exec(argv, &[], Duration::from_secs(timeout))
}

/// Advisories dnf says apply to installed packages and have an update.
/// dnf5 answers in JSON; dnf4 and yum in text. A failure (no repo
/// metadata, no network) is never cached as a clean result.
pub fn dnf_advisories(cache: &Cache, refresh: bool, offline: bool) -> Result<Advisories> {
    let (dnf, yum, rpm) = (which("dnf"), which("yum"), which("rpm"));
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
    let pacman = which("pacman").ok_or_else(|| Error::Offline("pacman isn't installed".into()))?;
    let vercmp = which("vercmp");
    let listing = run(&[pacman.as_os_str(), "-Q".as_ref()], 60)?;
    let installed: BTreeMap<String, String> =
        listing.stdout.lines().filter_map(|l| l.split_once(' ')).map(|(n, v)| (n.to_string(), v.to_string())).collect();
    let older = |a: &str, b: &str| -> bool {
        match &vercmp {
            None => crate::versions::lt(a, b),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
