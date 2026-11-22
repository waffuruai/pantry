use super::*;
use crate::utils::temp::TempDir;

#[test]
fn a_root_holding_a_place_left_out_is_read_around_it() {
    let d = TempDir::new("roots").unwrap();
    let base = d.path().join("Users");
    for p in ["me/code", "other/docs", "Shared"] {
        std::fs::create_dir_all(base.join(p)).unwrap();
    }
    std::fs::write(base.join("top.txt"), "x").unwrap();
    let home = base.join("me");
    let mut out = Vec::new();
    cover(&base, std::slice::from_ref(&home), &mut out);
    assert_eq!(
        out,
        [
            Root { path: base.clone(), depth: 0 },
            Root { path: base.join("Shared"), depth: DEPTH },
            Root { path: base.join("other"), depth: DEPTH },
        ],
        "its own files, then each other folder; never the place left out"
    );
    let mut none = Vec::new();
    cover(&home, std::slice::from_ref(&home), &mut none);
    assert!(none.is_empty(), "a place left out is never a root");
    let mut whole = Vec::new();
    cover(&base.join("other"), std::slice::from_ref(&home), &mut whole);
    assert_eq!(whole, [Root { path: base.join("other"), depth: DEPTH }], "nothing to leave out: the folder whole");
}

#[test]
fn deep_reads_home_first_then_the_rest_once() {
    let d = TempDir::new("roots-deep").unwrap();
    let home = d.path().join("home/me");
    let disk = d.path().join("disk");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(disk.join("opt")).unwrap();
    std::fs::create_dir_all(disk.join("net/share")).unwrap();
    set_test_system(vec![d.path().join("home"), disk.clone()], vec![disk.join("net")]);
    let roots = deep(&home);
    assert_eq!(roots[0], Root { path: home.clone(), depth: DEPTH }, "~ first");
    let paths: Vec<&Path> = roots.iter().map(|r| r.path.as_path()).collect();
    assert!(paths.contains(&disk.join("opt").as_path()));
    assert!(!paths.iter().any(|p| p.starts_with(disk.join("net"))), "a network mount is never read: {paths:?}");
    assert_eq!(paths.iter().filter(|p| **p == home.as_path()).count(), 1, "~ once: {paths:?}");
    set_test_system(Vec::new(), Vec::new());
}

#[test]
fn macos_reads_the_data_volume_and_local_volumes() {
    let firmlinks = "/AppleInternal\tAppleInternal\n/Applications\tApplications\n/Library\tLibrary\n\
                     /System/Library/Caches\tSystem/Library/Caches\n/Users\tUsers\n/Volumes\tVolumes\n\
                     /opt\topt\n/private\tprivate\n/usr/local\tusr/local\n";
    let mounts = "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n\
                  devfs on /dev (devfs, local, nobrowse)\n\
                  /dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse, protect, root data)\n\
                  /dev/disk3s3 on /Volumes/Recovery (apfs, local, journaled, nobrowse)\n\
                  /dev/disk4s1 on /Volumes/Backup Disk (apfs, local, nodev, nosuid, journaled)\n\
                  //me@nas/share on /Volumes/share (smbfs, nodev, nosuid, mounted by me)\n";
    let got: Vec<String> = macos_bases(firmlinks, mounts).iter().map(|p| p.to_string_lossy().into_owned()).collect();
    assert_eq!(
        got,
        [
            "/AppleInternal",
            "/Applications",
            "/Library",
            "/Users",
            "/opt",
            "/private",
            "/usr/local",
            "/Volumes/Backup Disk"
        ],
        "never the system volume, its caches, the system's own volumes or a network share"
    );
}

#[test]
fn linux_leaves_out_pseudo_and_network_mounts() {
    let mounts = "sysfs /sys sysfs rw 0 0\nproc /proc proc rw 0 0\n/dev/nvme0n1p2 / ext4 rw 0 0\n\
                  /dev/nvme0n1p1 /boot/efi vfat rw 0 0\nnas:/export /mnt/nas nfs4 rw 0 0\n\
                  //nas/share /mnt/my\\040share cifs rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n\
                  binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw 0 0\n";
    let got: Vec<String> = linux_avoid(mounts).iter().map(|p| p.to_string_lossy().into_owned()).collect();
    assert_eq!(got, ["/proc", "/sys", "/dev", "/run", "/mnt/nas", "/mnt/my share"]);
}
