//! Linux's own place to persist, beside the units, cron, at and startup
//! files every OS shares ([`crate::posture::any::persistence`]):
//! `/etc/ld.so.preload`.

use crate::posture::any::persistence::{Inventory, Item, Roots, Source};
use crate::system;
use std::path::Path;

/// Read every Linux-only source into `inv`.
pub(crate) fn collect(r: &Roots, inv: &mut Inventory) {
    preload(r, inv);
}

/// `/etc/ld.so.preload`: libraries the dynamic linker loads into every
/// program on the system.
fn preload(r: &Roots, inv: &mut Inventory) {
    let path = r.sys("/etc/ld.so.preload");
    if let Ok(text) = system::read_capped(&path, 1 << 20) {
        for (i, lib) in text.lines().map(str::trim).enumerate() {
            if lib.is_empty() || lib.starts_with('#') {
                continue;
            }
            inv.items.push(Item {
                source: Source::Preload,
                location: r.show(&path),
                ident: lib.to_string(),
                program: Some(r.rebase(Path::new(lib))).filter(|p| p.exists()),
                injects: vec!["ld.so.preload".into()],
                line: i + 1,
            });
        }
    }
    inv.read.push(Source::Preload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::any::persistence::inventory_in;
    use crate::posture::testing::{roots, write};
    use crate::system;

    #[test]
    fn a_linux_inventory_reads_units_cron_autostart_and_preload() {
        let d = system::TempDir::new("persist").unwrap();
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
}
