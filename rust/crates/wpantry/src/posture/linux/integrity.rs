//! What confines programs and keeps commands from being planted:
//! AppArmor or SELinux, and world-writable directories on PATH.

use super::super::{Check, Outcome, Runner, Severity, admin};

fn mandatory_access_control(r: Runner) -> Outcome {
    let aa = r(&["aa-enabled"]);
    if aa.trim().starts_with("Yes") {
        return Outcome::pass("AppArmor is enabled");
    }
    let se = r(&["getenforce"]);
    match se.trim() {
        "Enforcing" => Outcome::pass("SELinux is enforcing"),
        "Permissive" => Outcome::fail("SELinux is permissive"),
        "Disabled" => Outcome::fail("SELinux is disabled"),
        _ if aa.trim().starts_with("No") => Outcome::fail("AppArmor is installed but not enabled"),
        _ => Outcome::manual("neither AppArmor nor SELinux answered"),
    }
}

fn path_dirs(_: Runner) -> Outcome {
    path_dirs_of(&std::env::var("PATH").unwrap_or_default())
}

/// The world-writable directories among a PATH's entries.
fn path_dirs_of(path: &str) -> Outcome {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bad: Vec<String> = path
            .split(':')
            .filter(|d| !d.is_empty())
            .filter(|d| std::fs::metadata(d).is_ok_and(|m| m.is_dir() && m.permissions().mode() & 0o002 != 0))
            .map(str::to_string)
            .collect();
        if bad.is_empty() {
            return Outcome::pass("no directory on PATH is writable by everyone");
        }
        return Outcome::fail(format!("writable by everyone and on PATH: {}", bad.join(", ")));
    }
    #[allow(unreachable_code)]
    {
        let _ = path;
        Outcome::manual("not checked on this platform")
    }
}

pub(super) const MAC: Check = Check {
    id: "POSTURE-MAC",
    cis: "1.6",
    title: "AppArmor or SELinux enforcing",
    severity: Severity::Medium,
    probe: mandatory_access_control,
    fix: admin(
        "sudo aa-enforce /etc/apparmor.d/*  (or: sudo setenforce 1 and SELINUX=enforcing in /etc/selinux/config)",
    ),
    explain: "Confined programs can't reach beyond their profile",
};

pub(super) const PATH_WRITABLE: Check = Check {
    id: "POSTURE-PATH-WRITABLE",
    cis: "6.2",
    title: "No world-writable directory on PATH",
    severity: Severity::Medium,
    probe: path_dirs,
    fix: admin("chmod o-w <dir>  for each directory listed"),
    explain: "Nobody can plant a command you'd run",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::Status;
    use crate::posture::testing::machine;

    #[test]
    fn apparmor_or_selinux() {
        assert_eq!(mandatory_access_control(&machine(&[("aa-enabled", "Yes\n")])).status, Status::Pass);
        assert_eq!(mandatory_access_control(&machine(&[("getenforce", "Permissive\n")])).status, Status::Fail);
        assert_eq!(mandatory_access_control(&machine(&[])).status, Status::Manual);
        assert_eq!(
            mandatory_access_control(&machine(&[("aa-enabled", "No - disabled at boot.\n")])).status,
            Status::Fail
        );
        assert_eq!(mandatory_access_control(&machine(&[("getenforce", "Enforcing\n")])).status, Status::Pass);
        assert_eq!(mandatory_access_control(&machine(&[("getenforce", "Disabled\n")])).status, Status::Fail);
    }

    #[test]
    fn world_writable_path_dirs() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = crate::system::TempDir::new("path").unwrap();
            let (safe, open) = (d.path().join("safe"), d.path().join("open"));
            std::fs::create_dir(&safe).unwrap();
            std::fs::create_dir(&open).unwrap();
            std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
            let path = |dirs: &[&std::path::Path]| {
                dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>().join(":")
            };
            assert_eq!(path_dirs_of(&path(&[&safe])).status, Status::Pass);
            let o = path_dirs_of(&path(&[&safe, &open]));
            assert_eq!(o.status, Status::Fail);
            assert!(o.evidence.contains("open"), "{}", o.evidence);
        }
        // This process's PATH, read for real.
        assert!(matches!(path_dirs(&machine(&[])).status, Status::Pass | Status::Fail));
    }
}
