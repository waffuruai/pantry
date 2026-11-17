//! Keystroke capture: code that installs a global keyboard hook or reads
//! raw key events. A macOS event tap on key-down, a Windows low-level
//! keyboard hook, a polled key-state loop, the Linux raw input event
//! device, an X11 record tap, or one of the common keystroke libraries for
//! Python and Node.
//!
//! An accessibility tool, a hotkey daemon or a game may do this for good
//! reasons, so in a repo's own source it warns. In installed code
//! (extensions, plugins), or when the same file also writes the keys to a
//! file or sends them over the network, it fails: that is a keylogger.
//!
//! Every API and library name this rule looks for is assembled from pieces
//! at run time, so this file, scanned as its own source, matches none of
//! them.

use super::credentials::SENDS;
use super::{Context, Kind, Suspect, line_of, push, test_path};

pub(super) const ID: &str = "SUSPECT-KEYLOGGER";

/// Ways a file persists what it captures (network send is [`SENDS`]).
const WRITES: &[&str] = &[
    "writeFileSync",
    "appendFileSync",
    "appendFile(",
    "createWriteStream",
    "fs.write",
    ".write(",
    "WriteFile(",
    "ofstream",
    "open('a'",
    "open(\"a",
    "open('w'",
    "open(\"w",
    ">> ",
];

fn reads(ctx: Context) -> bool {
    matches!(ctx, Context::Web | Context::Python | Context::Native | Context::Shell)
}

pub(super) fn scan(file: &str, text: &str, ctx: Context, kind: Kind, out: &mut Vec<Suspect>) {
    if !reads(ctx) {
        return;
    }
    let Some((needle, what)) = signal(text) else { return };
    let writes = WRITES.iter().any(|w| text.contains(w));
    let sends = SENDS.iter().any(|s| text.contains(s));
    let note = format!(
        "{what}: a keylogger{}",
        if writes {
            ", writing captured keys to a file"
        } else if sends {
            ", sending captured keys over the network"
        } else {
            ""
        }
    );
    push(out, file, ID, line_of(text, &needle), note, (kind == Kind::Installed || writes || sends) && !test_path(file));
}

/// The first keystroke-capture signal in the text: the substring found and
/// a human description. The needles are built from pieces so they never
/// appear whole in this file.
fn signal(text: &str) -> Option<(String, &'static str)> {
    let cg_tap = concat!("CGEventTap", "Create").to_string();
    let key_down = concat!("kCGEventKey", "Down");
    if text.contains(&cg_tap) && text.contains(key_down) {
        return Some((cg_tap, "installs a macOS event tap on key-down events"));
    }
    let hook = concat!("SetWindowsHook", "Ex").to_string();
    let wh_ll = concat!("WH_KEYBOARD", "_LL");
    if text.contains(&hook) && text.contains(wh_ll) {
        return Some((hook, "installs a Windows low-level keyboard hook"));
    }
    let gaks = concat!("GetAsyncKey", "State").to_string();
    if text.contains(&gaks) && (text.contains("while") || text.contains("for ") || text.contains("for(")) {
        return Some((gaks, "polls raw key state in a loop"));
    }
    let dev_input = concat!("/dev/input/", "event").to_string();
    if text.contains(&dev_input) {
        return Some((dev_input, "reads the Linux raw input event device"));
    }
    let xrecord = concat!("XRecord", "CreateContext").to_string();
    if text.contains(&xrecord) {
        return Some((xrecord, "installs an X11 record tap on key events"));
    }
    let pyn = concat!("pyn", "put").to_string();
    let listener = concat!("List", "ener");
    if text.contains(&pyn) && text.contains(listener) {
        return Some((pyn, "listens for every keypress with a Python keystroke library"));
    }
    let kb_hook = concat!("keyboard.", "hook(").to_string();
    let kb_press = concat!("keyboard.", "on_press");
    if text.contains(&kb_hook) || text.contains(kb_press) {
        return Some((kb_hook, "hooks every keypress with the Python keyboard module"));
    }
    let evd = concat!("ev", "dev").to_string();
    let input_dev = concat!("Input", "Device");
    if text.contains(&evd)
        && (text.contains(input_dev) || text.contains(&dev_input) || text.contains(concat!("eco", "des")))
    {
        return Some((evd, "reads key events from a Linux input device"));
    }
    let node_gkl = concat!("node-global-", "key-listener").to_string();
    if text.contains(&node_gkl) {
        return Some((node_gkl, "listens globally for keypresses with a native Node key listener"));
    }
    let node_hook = concat!("io", "hook").to_string();
    let kd = concat!("key", "down");
    let ku = concat!("key", "up");
    if text.contains(&node_hook)
        && (text.contains(kd) || text.contains(ku) || text.contains(concat!("register", "Hook")))
    {
        return Some((node_hook, "listens globally for keypresses with a native Node key hook"));
    }
    None
}

#[cfg(test)]
#[path = "keylogger_tests.rs"]
mod tests;
