use super::*;
use crate::checks::machine::any::persistence::inventory_in;
use crate::checks::machine::testing::{roots, write};
use crate::utils::temp;

#[test]
fn a_linux_inventory_reads_units_cron_autostart_and_preload() {
    let d = temp::TempDir::new("persist").unwrap();
    let none = |_: &[&str]| String::new();
    let r = roots(d.path(), false, &none);
    write(&r.home.join(".config/systemd/user/sync.service"), "[Service]\nExecStart=/usr/bin/true --x\n");
    write(
        &r.sys("/etc/systemd/system/backdoor.service"),
        "[Service]\nEnvironment=LD_PRELOAD=/lib/x.so\nExecStart=/bin/true\n",
    );
    write(&r.sys("/etc/systemd/system/backup.timer"), "[Timer]\nOnCalendar=daily\n");
    write(&r.home.join(".config/autostart/app.desktop"), "[Desktop Entry]\nExec=/usr/bin/true\n");
    write(&r.sys("/etc/cron.d/job"), "SHELL=/bin/sh\n0 * * * * root /usr/bin/true\n");
    write(&r.sys("/etc/cron.daily/logrotate"), "#!/bin/sh\n");
    write(&r.sys("/etc/ld.so.preload"), "# none\n/lib/libevil.so\n");
    write(&r.sys("/etc/profile.d/x.sh"), "export X=1\n");
    let inv = inventory_in(&r);
    let by = |s: Source| inv.items.iter().filter(|i| i.source == s).collect::<Vec<_>>();
    let units: Vec<&str> = by(Source::Systemd).iter().map(|i| i.location.as_str()).collect();
    assert_eq!(
        units,
        [
            "~/.config/systemd/user/sync.service",
            "/etc/systemd/system/backdoor.service",
            "/etc/systemd/system/backup.timer"
        ]
    );
    assert_eq!(by(Source::Systemd)[1].injects, ["LD_PRELOAD"]);
    assert_eq!(by(Source::Autostart).len(), 1);
    let cron: Vec<&str> = by(Source::Cron).iter().map(|i| i.location.as_str()).collect();
    assert_eq!(cron, ["/etc/cron.d/job", "/etc/cron.daily/logrotate"]);
    assert_eq!(by(Source::Preload)[0].line, 2);
    assert_eq!(by(Source::Shell)[0].location, "/etc/profile.d/x.sh");
    assert!(by(Source::LoginItem).is_empty(), "macOS only");
}

/// Risk: the preload library was stat'ed (`exists`) when the spelling said it
/// was outside the left-out folders, so one behind `~/lib -> ~/Documents/lib`
/// was stat'ed inside `~/Documents`. Oracle: the folder is mode 000, so such a
/// stat fails and the item loses its program; asked through the link first,
/// the program is kept without any stat (so the report can say it was not
/// checked). Notices a stat whose failure steers the answer, not one whose
/// result is thrown away. Skipped as root. Known bad: `is_left_out` in place
/// of `reaches_left_out`.
#[cfg(unix)]
#[test]
fn a_preload_library_behind_a_link_into_a_left_out_folder_is_kept_without_a_stat() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    if crate::utils::process::is_root() {
        return;
    }
    let d = temp::TempDir::new("preload-link").unwrap();
    let none = |_: &[&str]| String::new();
    let r = roots(&std::fs::canonicalize(d.path()).unwrap(), false, &none);
    write(&r.home.join("Documents/libx.so"), "x");
    symlink("Documents", r.home.join("lib")).unwrap();
    let lib = r.home.join("lib/libx.so");
    write(&r.sys("/etc/ld.so.preload"), &format!("{}\n", lib.display()));
    let _guard = crate::utils::privacy::leave_out(vec![r.home.join("Documents")], Vec::new());
    let _reopen = crate::utils::temp::Reopen(r.home.join("Documents"));
    std::fs::set_permissions(r.home.join("Documents"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let inv = inventory_in(&r);
    let item = inv.items.iter().find(|i| i.source == Source::Preload).expect("the preload item");
    assert_eq!(item.program.as_deref(), Some(lib.as_path()));
}
