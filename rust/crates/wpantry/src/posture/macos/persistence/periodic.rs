//! periodic's scripts and emond's rules.

use crate::posture::any::persistence::{Inventory, Roots, Source, entries, file_item};

/// periodic's scripts and local files, and emond's rules and clients (emond
/// is gone from macOS 13; a rule on a newer system is left over or planted).
pub(super) fn periodic_and_emond(r: &Roots, inv: &mut Inventory) {
    for base in ["/etc/periodic", "/usr/local/etc/periodic"] {
        for when in ["daily", "weekly", "monthly"] {
            for path in entries(&r.sys(&format!("{base}/{when}")), |_| true) {
                inv.items.push(file_item(r, Source::Periodic, &path));
            }
        }
    }
    for f in [
        "/etc/periodic.conf",
        "/etc/periodic.conf.local",
        "/etc/daily.local",
        "/etc/weekly.local",
        "/etc/monthly.local",
    ] {
        let path = r.sys(f);
        if path.is_file() {
            inv.items.push(file_item(r, Source::Periodic, &path));
        }
    }
    inv.read.push(Source::Periodic);
    for dir in ["/etc/emond.d/rules", "/private/var/db/emondClients"] {
        for path in entries(&r.sys(dir), |_| true) {
            let mut item = file_item(r, Source::Emond, &path);
            item.program = None;
            inv.items.push(item);
        }
    }
    inv.read.push(Source::Emond);
}
