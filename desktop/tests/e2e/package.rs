//! The release downloads: the portable bundle (`PANTRY_E2E_BUNDLE`) and
//! Pantry Setup (`PANTRY_E2E_SETUP`), unpacked as a person would, then
//! Setup's install, lifecycle and refusal paths in throwaway profiles.

use crate::archive;
use crate::harness::Env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const EXE: &str = std::env::consts::EXE_SUFFIX;

/// The app and scanner inside an unpacked bundle or install folder.
pub fn binaries(folder: &Path) -> (PathBuf, PathBuf) {
    if cfg!(target_os = "macos") {
        let macos = folder.join("Pantry.app/Contents/MacOS");
        (macos.join("Pantry"), macos.join("wpantry"))
    } else {
        (
            folder.join(format!("wpantry-desktop{EXE}")),
            folder.join(format!("wpantry{EXE}")),
        )
    }
}

/// The Dock name comes from these keys; LSUIElement keeps Setup out of the
/// Dock. `expected` pairs a key with `<string>` text, or `true`/`false`.
pub fn bundle_plist(app: &Path, expected: &[(&str, &str)]) {
    let plist = app.join("Contents/Info.plist");
    let mut text = std::fs::read_to_string(&plist).unwrap_or_default();
    if !text.starts_with("<?xml") {
        // A binary plist: macOS converts it.
        let out = Command::new("plutil")
            .args(["-convert", "xml1", "-o", "-"])
            .arg(&plist)
            .output()
            .expect("plutil");
        text = String::from_utf8_lossy(&out.stdout).into_owned();
    }
    for (key, value) in expected {
        assert_eq!(
            plist_value(&text, key).as_deref(),
            Some(*value),
            "{}: {key}",
            app.display()
        );
    }
}

/// The value after `<key>key</key>` in an XML plist: a string's text, or
/// `true`/`false`.
fn plist_value(xml: &str, key: &str) -> Option<String> {
    let rest = xml[xml.find(&format!("<key>{key}</key>"))? + key.len() + 11..].trim_start();
    if let Some(string) = rest.strip_prefix("<string>") {
        return Some(string[..string.find("</string>")?].to_string());
    }
    ["true", "false"]
        .into_iter()
        .find(|b| rest.starts_with(&format!("<{b}/>")))
        .map(str::to_string)
}

pub fn plist_rejects_known_bad() {
    let xml = "<?xml?><dict><key>CFBundleName</key>\n\t<string>Pantry</string><key>LSUIElement</key><true/></dict>";
    assert_eq!(plist_value(xml, "CFBundleName").as_deref(), Some("Pantry"));
    assert_eq!(plist_value(xml, "LSUIElement").as_deref(), Some("true"));
    // Known-bad case: a missing key is not read as some other key's value.
    assert_eq!(plist_value(xml, "CFBundleDisplayName"), None);
}

/// Unpack the portable bundle and return its app and scanner.
pub fn extract_bundle(bundle: &Path, temp: &Path) -> (PathBuf, PathBuf) {
    let package = temp.join("Pantry package");
    archive::unzip(bundle, &package);
    if cfg!(target_os = "macos") {
        bundle_plist(
            &package.join("Pantry.app"),
            &[
                ("CFBundleName", "Pantry"),
                ("CFBundleDisplayName", "Pantry"),
            ],
        );
    }
    binaries(&package)
}

/// Unpack a Setup download the way a person would and return its launcher.
pub fn extract_setup(setup: &Path, package: &Path) -> PathBuf {
    std::fs::create_dir(package).expect("create the setup folder");
    let name = setup.to_string_lossy();
    if name.ends_with(".exe") {
        return std::fs::canonicalize(setup).expect("Setup exists");
    }
    if name.ends_with(".zip") {
        archive::unzip(setup, package);
        bundle_plist(
            &package.join("Pantry Setup.app"),
            &[("LSUIElement", "true")],
        );
        return package.join("Pantry Setup.app/Contents/MacOS/Pantry Setup");
    }
    let entries = archive::untar_gz(setup, package);
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["Pantry Setup", "README.txt", "pantry-setup.desktop"]
    );
    for entry in &entries {
        assert!(
            entry.mtime == 0 && entry.uid == 0 && entry.gid == 0,
            "{}",
            entry.name
        );
    }
    let launcher = package.join("Pantry Setup");
    // The double-click launcher must resolve to Setup beside it.
    let entry = package.join("pantry-setup.desktop");
    assert!(executable(&entry) && executable(&launcher));
    let entry_path = entry.display().to_string();
    let argv = desktop_exec(&entry, &[("%k", &entry_path)]);
    assert_eq!(argv[..2], ["sh", "-c"], "{argv:?}");
    let script = argv[2].replacen("exec ", "test -x ", 1);
    let status = Command::new(&argv[0])
        .arg(&argv[1])
        .arg(script)
        .args(&argv[3..])
        .status()
        .expect("run sh");
    assert!(status.success(), "{argv:?}");
    launcher
}

#[cfg(unix)]
pub fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
pub fn executable(path: &Path) -> bool {
    path.is_file()
}

/// Split a Desktop Entry Exec value per the spec: string escapes first,
/// then the quoting rules, then field codes as whole arguments.
pub fn desktop_exec(entry: &Path, codes: &[(&str, &str)]) -> Vec<String> {
    let text =
        std::fs::read_to_string(entry).unwrap_or_else(|e| panic!("{}: {e}", entry.display()));
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("Exec="))
        .expect("an Exec line");
    split_exec(line, codes)
}

fn split_exec(line: &str, codes: &[(&str, &str)]) -> Vec<String> {
    let code = |word: String| {
        codes
            .iter()
            .find(|(c, _)| *c == word)
            .map_or(word, |(_, v)| v.to_string())
    };
    let mut value = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek().copied()) {
            ('\\', Some(next)) => {
                chars.next();
                match next {
                    's' => value.push(' '),
                    'n' => value.push('\n'),
                    't' => value.push('\t'),
                    'r' => value.push('\r'),
                    '\\' => value.push('\\'),
                    other => {
                        value.push('\\');
                        value.push(other);
                    }
                }
            }
            _ => value.push(c),
        }
    }
    let (mut args, mut current, mut quoted, mut started) =
        (Vec::new(), String::new(), false, false);
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted && c == '\\' && chars.peek().is_some_and(|n| "\"`$\\".contains(*n)) {
            current.push(chars.next().unwrap());
            continue;
        }
        if c == '"' {
            (quoted, started) = (!quoted, true);
        } else if c == ' ' && !quoted {
            if started {
                args.push(code(std::mem::take(&mut current)));
            }
            (current, started) = (String::new(), false);
        } else {
            current.push(c);
            started = true;
        }
    }
    assert!(!quoted, "unterminated quote: {value}");
    if started {
        args.push(code(current));
    }
    args
}

pub fn desktop_exec_rejects_known_bad() {
    // The shipped launcher's Exec line, after its string escapes.
    let line = r#"sh -c "exec \\"\\$(dirname \\"\\$0\\")/Pantry Setup\\"" %k"#;
    let argv = split_exec(line, &[("%k", "/x/pantry-setup.desktop")]);
    assert_eq!(
        argv,
        [
            "sh",
            "-c",
            r#"exec "$(dirname "$0")/Pantry Setup""#,
            "/x/pantry-setup.desktop"
        ]
    );
    // Known-bad case: a field code inside a word is not replaced, and an
    // unquoted space splits.
    assert_eq!(split_exec("a%k b", &[("%k", "X")]), ["a%k", "b"]);
}

fn run(launcher: &Path, env: &Env, extra: &[&str]) -> Output {
    let mut command = Command::new(launcher);
    command.args(extra);
    env.apply(&mut command);
    command
        .output()
        .unwrap_or_else(|e| panic!("run {}: {e}", launcher.display()))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Install with Setup into a fresh profile: a folder the person owns is
/// refused, a reinstall works, a newer install is kept. Returns the
/// installed app and scanner, and leaves `WPANTRY_DESKTOP_HOME` set to that
/// profile for the UI checks.
pub fn setup_install(setup: &Path, temp: &Path, env: &mut Env) -> (PathBuf, PathBuf) {
    let launcher = extract_setup(setup, &temp.join("Pantry setup package"));
    #[cfg(unix)]
    crate::lifecycle::setup_lifecycle(&launcher, temp, env);
    #[cfg(windows)]
    crate::lifecycle::setup_shortcut(&launcher, temp, env);
    let profile = temp.join("desktop profile");
    env.set("WPANTRY_DESKTOP_HOME", &profile);
    let destination = profile.join("installed");
    std::fs::create_dir_all(&destination).expect("create the owned folder");
    let sentinel = destination.join("owned by user");
    std::fs::write(&sentinel, "").expect("create the sentinel");
    let refused = run(&launcher, env, &["--install-only"]);
    assert!(
        !refused.status.success() && stderr(&refused).contains("Move or delete that folder"),
        "{refused:?}"
    );
    assert!(sentinel.is_file());
    std::fs::remove_file(&sentinel).expect("remove the sentinel");
    std::fs::remove_dir(&destination).expect("remove the empty folder");
    for _ in 0..2 {
        let output = run(&launcher, env, &["--install-only"]);
        assert!(output.status.success(), "{output:?}");
    }
    let marker = destination.join(".waffuru-pantry-desktop");
    let installed = std::fs::read_to_string(&marker).expect("the install marker");
    std::fs::write(&marker, "999.0.0").expect("mark a newer install");
    let output = run(&launcher, env, &["--install-only"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "999.0.0");
    std::fs::write(&marker, installed).expect("restore the marker");
    if cfg!(target_os = "macos") {
        bundle_plist(
            &destination.join("Pantry.app"),
            &[
                ("CFBundleName", "Pantry"),
                ("CFBundleDisplayName", "Pantry"),
            ],
        );
    }
    binaries(&destination)
}

pub(crate) fn run_setup(launcher: &Path, env: &Env, extra: &[&str]) -> Output {
    run(launcher, env, extra)
}

#[cfg(unix)]
pub(crate) fn setup_stderr(output: &Output) -> String {
    stderr(output)
}
