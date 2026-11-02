//! A clipper: code that reads the clipboard, recognises a wallet address
//! in it and writes its own back, so the address a person pastes isn't
//! the one they copied. The shape is the same in every language it is
//! written in (JavaScript, Python, Go, C#, Rust, AppleScript, shell):
//! a clipboard read, a clipboard write, and wallet addresses in hand,
//! either hardcoded (the attacker's) or as the patterns that recognise
//! the victim's. Read and write with addresses fails everywhere but a
//! test; a read with address patterns and no write warns (a form that
//! validates what was pasted); a write alone is a "copy address" button.

use super::{Context, Kind, Suspect, has_any, line_of, push, test_path};
use crate::addresses;

pub(super) const ID: &str = "SUSPECT-CLIPBOARD-SWAP";

/// The ways code reads the clipboard.
const READS: &[&str] = &[
    "navigator.clipboard.readText",
    "clipboard.readText(",
    "clipboard.read(",
    "clipboardData.getData",
    "pbpaste",
    "NSPasteboard",
    "generalPasteboard",
    "UIPasteboard",
    "pyperclip.paste",
    "pyperclip",
    "win32clipboard",
    "GetClipboardData",
    "OpenClipboard",
    "Clipboard.GetText",
    "Clipboard.GetData",
    "Clipboard.ContainsText",
    "clipboard.ReadAll",
    "clipboard.Read(",
    "get_text()",
    "xclip -o",
    "xclip -selection clipboard -o",
    "xclip -sel c -o",
    "xclip -selection c -o",
    "xsel -o",
    "xsel --output",
    "wl-paste",
    "clipboardy",
    "get the clipboard",
    "the clipboard as",
    "QClipboard",
    "clipboard().text()",
    "getPrimaryClip",
    "arboard",
    "ClipboardProvider",
    "clipboard_win",
    "Gtk.Clipboard",
    "gtk.Clipboard",
    "wait_for_text(",
];
/// The ways code writes it.
const WRITES: &[&str] = &[
    "navigator.clipboard.writeText",
    "clipboard.writeText(",
    "clipboard.write(",
    "clipboardData.setData",
    "pbcopy",
    "setString(",
    "setString:",
    "writeObjects:",
    "pyperclip.copy",
    "SetClipboardData",
    "Clipboard.SetText",
    "Clipboard.SetData",
    "clipboard.WriteAll",
    "clipboard.Write(",
    "set_text(",
    "xclip -i",
    "| xclip",
    "|xclip",
    "xsel -i",
    "xsel --input",
    "wl-copy",
    "set the clipboard to",
    "setPrimaryClip(",
    "clipboard()->setText(",
    "clipboard().setText(",
    "execCommand('copy')",
    "execCommand(\"copy\")",
];
/// The regular expressions clippers match addresses with: the quantifier
/// of each shape, as it is spelled in every regex dialect.
pub(crate) const PATTERNS: &[&str] = &[
    "[a-fA-F0-9]{40}",
    "[0-9a-fA-F]{40}",
    "[a-km-zA-HJ-NP-Z1-9]{25,34}",
    "[a-km-zA-HJ-NP-Z1-9]{33}",
    "[1-9A-HJ-NP-Za-km-z]{25,34}",
    "[1-9A-HJ-NP-Za-km-z]{32,44}",
    "[1-9A-HJ-NP-Za-km-z]{33}",
    "[A-Z2-7]{55}",
    "[0-9a-zA-Z]{24,34}",
    "[a-zA-Z0-9]{24,34}",
    "bc1[",
    "bc1q",
    "ltc1[",
    "^T[",
    "^r[",
    "^G[",
    "^0x[",
    "0x[a-f",
    "0x[0-9",
    "0x[A-F",
];

pub(super) fn scan(file: &str, text: &str, ctx: Context, kind: Kind, out: &mut Vec<Suspect>) {
    if !matches!(ctx, Context::Web | Context::Markup | Context::Python | Context::Shell | Context::Native) {
        return;
    }
    let Some(read) = has_any(text, READS) else { return };
    let write = has_any(text, WRITES);
    let chains = addresses::chains_in(text);
    let pattern = has_any(text, PATTERNS);
    if chains.is_empty() && pattern.is_none() {
        return;
    }
    let hardcoded = if chains.is_empty() {
        String::new()
    } else {
        format!(
            ", with {} address{} hardcoded",
            chains.iter().map(|c| c.name()).collect::<Vec<_>>().join(" and "),
            if chains.len() == 1 { "" } else { "es" }
        )
    };
    let recognises = if pattern.is_some() { ", recognises wallet addresses by pattern" } else { "" };
    let (note, hard) = match write {
        Some(w) => (
            format!(
                "reads the clipboard (`{}`) and writes it back (`{}`){recognises}{hardcoded}: a clipper swaps the address you copied",
                read.trim_end_matches('('),
                w.trim_end_matches('(')
            ),
            !test_path(file),
        ),
        None => (
            format!(
                "reads the clipboard (`{}`){recognises}{hardcoded}, without writing it: a form that validates a pasted address, or half of a clipper",
                read.trim_end_matches('(')
            ),
            kind == Kind::Installed && !test_path(file),
        ),
    };
    push(out, file, ID, line_of(text, read), note, hard);
}

#[cfg(test)]
mod tests {
    use super::super::{Kind, ids, scan_text};

    const ATTACKER: &str = "0xD62Eb957610d49f77cFce8bCc9827b5428D790E6";

    #[test]
    fn a_clipper_in_any_language_fails() {
        let js = format!(
            "setInterval(async () => {{ const t = await navigator.clipboard.readText(); if (/^0x[a-fA-F0-9]{{40}}$/.test(t)) navigator.clipboard.writeText('{ATTACKER}'); }}, 500);\n"
        );
        let got = scan_text("src/bg.js", &js, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-CLIPBOARD-SWAP", true)], "{got:?}");
        assert!(got[0].note.contains("a clipper swaps the address you copied"), "{}", got[0].note);
        assert!(got[0].note.contains("EVM (Ethereum, BSC, Tempo)"), "{}", got[0].note);
        assert!(got[0].note.contains("recognises wallet addresses by pattern"), "{}", got[0].note);
        let py = "import pyperclip, re, time\nwhile True:\n    c = pyperclip.paste()\n    if re.match(r'^T[a-km-zA-HJ-NP-Z1-9]{33}$', c): pyperclip.copy('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')\n    time.sleep(0.5)\n";
        assert_eq!(ids(&scan_text("clip.py", py, Kind::Repo)), [("SUSPECT-CLIPBOARD-SWAP", true)]);
        let go = "txt, _ := clipboard.ReadAll()\nif re.MatchString(txt) { clipboard.WriteAll(\"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\") }\n";
        assert_eq!(ids(&scan_text("main.go", go, Kind::Repo)), [("SUSPECT-CLIPBOARD-SWAP", true)]);
        let cs = "var t = Clipboard.GetText(); if (Regex.IsMatch(t, \"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$\")) Clipboard.SetText(mine);";
        assert_eq!(ids(&scan_text("Program.cs", cs, Kind::Repo)), [("SUSPECT-CLIPBOARD-SWAP", true)]);
        let sh = "while true; do c=$(pbpaste); case $c in 0x*) echo 0xD62Eb957610d49f77cFce8bCc9827b5428D790E6 | pbcopy;; esac; sleep 1; done\n";
        assert_eq!(ids(&scan_text("run.sh", sh, Kind::Repo)), [("SUSPECT-CLIPBOARD-SWAP", true)]);
        let applescript = "set the clipboard to \"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t\"\nget the clipboard\n";
        assert_eq!(ids(&scan_text("swap.scpt.sh", applescript, Kind::Repo)), [("SUSPECT-CLIPBOARD-SWAP", true)]);
    }

    #[test]
    fn reads_without_writes_warn_and_writes_alone_are_buttons() {
        let form = "const pasted = await navigator.clipboard.readText(); if (!/^0x[a-fA-F0-9]{40}$/.test(pasted)) setError('not an address');\n";
        let got = scan_text("src/form.ts", form, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-CLIPBOARD-SWAP", false)], "validation only");
        assert!(got[0].note.contains("without writing it"), "{}", got[0].note);
        assert_eq!(
            ids(&scan_text("ext/content.js", form, Kind::Installed)),
            [("SUSPECT-CLIPBOARD-SWAP", true)],
            "installed code fails"
        );
        let button = "onClick={() => navigator.clipboard.writeText('0xdAC17F958D2ee523a2206206994597C13D831ec7')}";
        assert!(scan_text("src/Copy.tsx", button, Kind::Repo).is_empty(), "a copy button reads nothing");
        let manager = "const t = await navigator.clipboard.readText(); history.push(t); navigator.clipboard.writeText(history[0]);\n";
        assert!(scan_text("src/history.js", manager, Kind::Repo).is_empty(), "a clipboard manager has no addresses");
        let test = "test('swaps', () => { navigator.clipboard.readText(); navigator.clipboard.writeText('0xD62Eb957610d49f77cFce8bCc9827b5428D790E6'); });";
        assert_eq!(
            ids(&scan_text("src/__tests__/clip.test.js", test, Kind::Repo)),
            [("SUSPECT-CLIPBOARD-SWAP", false)],
            "tests warn"
        );
        assert!(
            scan_text("notes.md", "pbpaste | pbcopy 0xD62Eb957610d49f77cFce8bCc9827b5428D790E6", Kind::Repo).is_empty(),
            "prose isn't read"
        );
    }
}
