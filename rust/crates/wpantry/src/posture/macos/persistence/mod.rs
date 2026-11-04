//! macOS's own places to persist, beside the launch agents, cron, at and
//! startup files every OS shares ([`crate::posture::any::persistence`]):
//! [`login_items`] apps carry, the plugin and system [`extensions`] the
//! system loads, [`periodic`] and emond, and the session's
//! `DYLD_INSERT_LIBRARIES`.

use crate::posture::any::persistence::{Inventory, Item, Roots, Source};
use std::path::Path;

mod extensions;
mod login_items;
mod periodic;

/// Read every macOS-only source into `inv`.
pub(crate) fn collect(r: &Roots, inv: &mut Inventory) {
    login_items::login_items(r, inv);
    extensions::bundles(r, inv);
    extensions::system_extensions(r, inv);
    periodic::periodic_and_emond(r, inv);
    launchd_env(r, inv);
}

/// `launchctl setenv DYLD_INSERT_LIBRARIES`: every app the session starts
/// loads the library.
fn launchd_env(r: &Roots, inv: &mut Inventory) {
    let value = (r.runner)(&["launchctl", "getenv", "DYLD_INSERT_LIBRARIES"]);
    let value = value.trim();
    if !value.is_empty() {
        inv.items.push(Item {
            source: Source::LaunchdEnv,
            location: "launchctl getenv DYLD_INSERT_LIBRARIES".into(),
            ident: value.to_string(),
            program: Some(r.rebase(Path::new(value.split(':').next().unwrap_or(value)))).filter(|p| p.exists()),
            injects: vec!["DYLD_INSERT_LIBRARIES".into()],
            line: 0,
        });
    }
    inv.read.push(Source::LaunchdEnv);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::any::persistence::{inventory_in, programs};
    use crate::posture::testing::{roots, write};
    use crate::system;
    use std::path::PathBuf;

    const AGENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.example.helper</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>true</string></array>
<key>EnvironmentVariables</key><dict><key>DYLD_INSERT_LIBRARIES</key><string>/tmp/x.dylib</string></dict>
</dict></plist>"#;

    const SM_AGENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.example.agent</string>
<key>BundleProgram</key><string>Contents/Resources/agent</string>
</dict></plist>"#;

    const SYSEXT: &str = "1 extension(s)\n--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tTEAM123\tcom.example.vpn.ext (1.0/1)\tExample VPN\t[activated enabled]\n";

    fn mac_runner(argv: &[&str]) -> String {
        match argv.join(" ").as_str() {
            "crontab -l" => {
                "# m h dom mon dow cmd\n*/5 * * * * /bin/sh /tmp/x.sh\nMAILTO=\"\"\n@reboot /usr/bin/true\n".into()
            }
            "atq" => "3\tWed Nov  4 10:00:00 2026\n".into(),
            "systemextensionsctl list" => SYSEXT.into(),
            "launchctl getenv DYLD_INSERT_LIBRARIES" => String::new(),
            _ => String::new(),
        }
    }

    #[test]
    fn a_mac_inventory_reads_every_source() {
        let d = system::TempDir::new("persist").unwrap();
        let r = roots(d.path(), true, &mac_runner);
        write(&r.home.join("Library/LaunchAgents/com.example.helper.plist"), AGENT);
        write(
            &r.home.join(".zshrc"),
            "# comment\nexport PATH=$HOME/bin:$PATH\n\nexport DYLD_INSERT_LIBRARIES=/x.dylib\n",
        );
        write(&r.sys("/Library/Security/SecurityAgentPlugins/Evil.bundle/Contents/Info.plist"), "<plist/>");
        write(&r.sys("/Library/Extensions/Foo.kext/Contents/Info.plist"), "<plist/>");
        write(&r.home.join("Library/QuickLook/Q.qlgenerator/x"), "");
        write(&r.sys("/Library/Spotlight/S.mdimporter/x"), "");
        write(&r.sys("/etc/periodic/daily/999.local"), "#!/bin/sh\n");
        write(&r.sys("/etc/emond.d/rules/r.plist"), "<plist/>");
        let app = r.sys("/Applications/Example App.app/Contents/Library");
        write(&app.join("LaunchAgents/com.example.agent.plist"), SM_AGENT);
        write(&app.join("LoginItems/Helper.app/Contents/Info.plist"), "<plist/>");
        write(&r.sys("/Applications/Plain.app/Contents/Info.plist"), "<plist/>");
        let inv = inventory_in(&r);
        let by = |s: Source| inv.items.iter().filter(|i| i.source == s).collect::<Vec<_>>();
        let launchd = by(Source::Launchd);
        assert_eq!(launchd.len(), 1);
        assert_eq!(launchd[0].location, "~/Library/LaunchAgents/com.example.helper.plist");
        assert_eq!(launchd[0].program.as_deref(), Some(Path::new("/bin/sh")));
        assert_eq!(launchd[0].injects, ["DYLD_INSERT_LIBRARIES"]);
        let logins = by(Source::LoginItem);
        let names: Vec<&str> = logins.iter().map(|i| i.location.as_str()).collect();
        assert_eq!(
            names,
            [
                "/Applications/Example App.app/Contents/Library/LaunchAgents/com.example.agent.plist",
                "/Applications/Example App.app/Contents/Library/LoginItems/Helper.app"
            ]
        );
        assert_eq!(
            logins[0].program.as_deref(),
            Some(r.sys("/Applications/Example App.app/Contents/Resources/agent").as_path()),
            "BundleProgram is inside the app"
        );
        assert_eq!(
            logins[1].program.as_deref(),
            Some(r.sys("/Applications/Example App.app/Contents/Library/LoginItems/Helper.app").as_path())
        );
        let cron = by(Source::Cron);
        assert_eq!(cron.len(), 2, "the environment line and the comment run nothing");
        assert_eq!((cron[0].location.as_str(), cron[0].line), ("crontab -l", 2));
        assert_eq!(by(Source::At).len(), 1);
        assert_eq!(by(Source::At)[0].location, "at job 3");
        let shell = by(Source::Shell);
        assert_eq!(shell.len(), 2);
        assert_eq!(shell[1].line, 4);
        assert_eq!(shell[1].injects, ["DYLD_INSERT_LIBRARIES"]);
        assert_eq!(by(Source::AuthPlugin)[0].location, "/Library/Security/SecurityAgentPlugins/Evil.bundle");
        assert_eq!(by(Source::Kext).len(), 1);
        assert_eq!(by(Source::QuickLook)[0].location, "~/Library/QuickLook/Q.qlgenerator");
        assert_eq!(by(Source::Spotlight).len(), 1);
        assert_eq!(by(Source::SystemExtension)[0].location, "com.example.vpn.ext");
        assert_eq!(by(Source::Periodic)[0].location, "/etc/periodic/daily/999.local");
        assert_eq!(by(Source::Emond).len(), 1);
        assert!(inv.unread.is_empty(), "{:?}", inv.unread);
        assert!(programs(&inv).contains(&PathBuf::from("/bin/sh")));
    }

    #[test]
    fn an_unreadable_source_is_unread_not_empty() {
        let d = system::TempDir::new("persist").unwrap();
        let none = |_: &[&str]| String::new();
        let inv = inventory_in(&roots(d.path(), true, &none));
        assert_eq!(inv.unread, [(Source::SystemExtension, "systemextensionsctl list gave no answer".into())]);
        assert!(!inv.read.contains(&Source::SystemExtension));
        assert!(inv.read.contains(&Source::LoginItem), "the app bundles are read from disk");
    }
}
