use super::*;
use crate::checks::machine::settings::Status;
use crate::checks::machine::testing::machine;

#[test]
fn apparmor_or_selinux() {
    assert_eq!(mandatory_access_control(&machine(&[("aa-enabled", "Yes\n")])).status, Status::Pass);
    assert_eq!(mandatory_access_control(&machine(&[("getenforce", "Permissive\n")])).status, Status::Fail);
    assert_eq!(mandatory_access_control(&machine(&[])).status, Status::Manual);
    assert_eq!(mandatory_access_control(&machine(&[("aa-enabled", "No - disabled at boot.\n")])).status, Status::Fail);
    assert_eq!(mandatory_access_control(&machine(&[("getenforce", "Enforcing\n")])).status, Status::Pass);
    assert_eq!(mandatory_access_control(&machine(&[("getenforce", "Disabled\n")])).status, Status::Fail);
}

#[test]
fn world_writable_path_dirs() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::utils::temp::TempDir::new("path").unwrap();
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
    let actual = path_dirs(&machine(&[]));
    if cfg!(unix) {
        assert!(matches!(actual.status, Status::Pass | Status::Fail));
    } else {
        assert_eq!(actual.status, Status::Manual);
        assert_eq!(actual.evidence, "not checked on this platform");
    }
}
