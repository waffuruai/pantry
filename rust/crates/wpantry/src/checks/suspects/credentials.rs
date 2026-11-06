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
#[path = "credentials_tests.rs"]
mod tests;
