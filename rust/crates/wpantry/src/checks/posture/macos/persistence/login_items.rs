//! Login items and the launch agents and daemons apps carry in their bundles.

use crate::checks::machine::clipper::program_file;
use crate::checks::posture::any::persistence::units::command_of;
use crate::checks::posture::any::persistence::{INJECT, Inventory, Item, Roots, Source, entries, file_item};

/// The login items and launch agents and daemons apps carry inside
/// their bundles, which `SMAppService` and `SMLoginItemSetEnabled`
/// register: `Contents/Library/LaunchAgents`, `LaunchDaemons` and
/// `LoginItems` of every app in `/Applications` (and `Utilities`) and
/// `~/Applications`. Background Task Management records which of them are
/// enabled, but `sfltool dumpbtm`, the only reader, asks for an
/// administrator's password every time; so these are what apps can start,
/// enabled or not. A new one is still a new way back in.
pub(super) fn login_items(r: &Roots, inv: &mut Inventory) {
    let dirs = [r.sys("/Applications"), r.sys("/Applications/Utilities"), r.home.join("Applications")];
    for dir in dirs {
        for app in entries(&dir, |n| n.ends_with(".app")) {
            let lib = app.join("Contents/Library");
            for sub in ["LaunchAgents", "LaunchDaemons"] {
                for plist in entries(&lib.join(sub), |n| n.ends_with(".plist")) {
                    let v = crate::utils::plist::read(&plist);
                    let program = match v.get("BundleProgram").and_then(|p| p.as_str()) {
                        Some(rel) => Some(app.join(rel)),
                        None => program_file(&command_of(&plist)),
                    };
                    let mut injects: Vec<String> = v
                        .get("EnvironmentVariables")
                        .and_then(|e| e.as_object())
                        .map(|e| e.keys().filter(|k| INJECT.contains(&k.as_str())).cloned().collect())
                        .unwrap_or_default();
                    injects.sort();
                    inv.items.push(Item {
                        source: Source::LoginItem,
                        location: r.show(&plist),
                        ident: program.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
                        program,
                        injects,
                        line: 0,
                    });
                }
            }
            for helper in entries(&lib.join("LoginItems"), |n| n.ends_with(".app")) {
                inv.items.push(file_item(r, Source::LoginItem, &helper));
            }
        }
    }
    inv.read.push(Source::LoginItem);
}
