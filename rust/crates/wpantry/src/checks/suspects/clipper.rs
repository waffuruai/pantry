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
use crate::utils::addresses;

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
#[path = "clipper_tests.rs"]
mod tests;
