//! wpantry-release: package, build Setup's download, and sign Pantry Desktop
//! releases. The release workflow and install-local.sh build it from this
//! checkout (`cargo build --release --locked` in desktop/release).
//!
//! Example (what the release workflow runs on macOS):
//!
//! ```text
//! wpantry-release package universal-apple-darwin desktop-one wpantry notices.txt dist/wpantry-desktop.zip
//! wpantry-release sign macos dist/wpantry-desktop.zip
//! wpantry-release setup payload dist/wpantry-desktop.zip setup-payload.zlib
//! wpantry-release setup bundle universal-apple-darwin setup-one setup-payload.zlib dist/wpantry-setup.zip
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use wpantry_release::{package, read, setup, sign, write};

const USAGE: &str = "\
usage:
  wpantry-release package TARGET APP SCANNER NOTICES OUTPUT
  wpantry-release setup payload SOURCE OUTPUT
  wpantry-release setup bundle TARGET SETUP DATA OUTPUT
  wpantry-release sign macos ZIP [--identity NAME] [--keychain PATH] [--notary-profile NAME]
  wpantry-release sign windows FILE [--thumbprint SHA1] [--timestamp-url URL]

TARGET is a Rust target triple, or universal-apple-darwin. Windows signing
takes the thumbprint from WINDOWS_CERT_THUMBPRINT when --thumbprint is not
given; the identity \"-\" (the default) signs macOS bundles ad hoc.";

enum Failure {
    Usage(String),
    Run(String),
}

impl From<String> for Failure {
    fn from(e: String) -> Failure {
        Failure::Run(e)
    }
}

/// Positionals and `--name value` / `--name=value` options, in any order.
fn split(
    args: &[String],
    known: &[&str],
) -> Result<(Vec<String>, BTreeMap<String, String>), Failure> {
    let mut positional = Vec::new();
    let mut options = BTreeMap::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if let Some(flag) = arg.strip_prefix("--") {
            let (name, value) = match flag.split_once('=') {
                Some((n, v)) => (n.to_string(), v.to_string()),
                None => {
                    let v = it
                        .next()
                        .ok_or_else(|| Failure::Usage(format!("--{flag} needs a value")))?;
                    (flag.to_string(), v.clone())
                }
            };
            if !known.contains(&name.as_str()) {
                return Err(Failure::Usage(format!("unknown option --{name}")));
            }
            options.insert(name, value);
        } else {
            positional.push(arg.clone());
        }
    }
    Ok((positional, options))
}

fn exact<const N: usize>(positional: Vec<String>, what: &str) -> Result<[String; N], Failure> {
    positional
        .try_into()
        .map_err(|_| Failure::Usage(format!("{what} takes {N} arguments")))
}

fn run(args: &[String]) -> Result<(), Failure> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["package", rest @ ..] => {
            let (pos, _) = split(&args[args.len() - rest.len()..], &[])?;
            let [target, app, scanner, notices, output] = exact(pos, "package")?;
            let zip = package::package(
                &target,
                &read(Path::new(&app))?,
                &read(Path::new(&scanner))?,
                &read(Path::new(&notices))?,
            )?;
            write(Path::new(&output), &zip)?;
        }
        ["setup", "payload", rest @ ..] => {
            let (pos, _) = split(&args[args.len() - rest.len()..], &[])?;
            let [source, output] = exact(pos, "setup payload")?;
            let data =
                setup::payload(&read(Path::new(&source))?).map_err(|e| format!("{source}: {e}"))?;
            write(Path::new(&output), &data)?;
        }
        ["setup", "bundle", rest @ ..] => {
            let (pos, _) = split(&args[args.len() - rest.len()..], &[])?;
            let [target, setup_bin, data, output] = exact(pos, "setup bundle")?;
            let setup_bytes = read(Path::new(&setup_bin))?;
            let data = if setup::needs_payload(&target) {
                read(Path::new(&data))?
            } else {
                Vec::new()
            };
            write(
                Path::new(&output),
                &setup::bundle(&target, &setup_bytes, &data)?,
            )?;
        }
        ["sign", "macos", rest @ ..] => {
            let (pos, opts) = split(
                &args[args.len() - rest.len()..],
                &["identity", "keychain", "notary-profile"],
            )?;
            let [archive] = exact(pos, "sign macos")?;
            sign::macos(
                &mut sign::System,
                Path::new(&archive),
                opts.get("identity").map_or("-", String::as_str),
                opts.get("keychain").map(String::as_str),
                opts.get("notary-profile").map(String::as_str),
            )?;
        }
        ["sign", "windows", rest @ ..] => {
            let (pos, opts) = split(
                &args[args.len() - rest.len()..],
                &["thumbprint", "timestamp-url"],
            )?;
            let [target] = exact(pos, "sign windows")?;
            let thumbprint = opts
                .get("thumbprint")
                .cloned()
                .or_else(|| std::env::var("WINDOWS_CERT_THUMBPRINT").ok())
                .filter(|t| !t.is_empty())
                .ok_or_else(|| {
                    Failure::Usage(
                        "windows signing needs --thumbprint or WINDOWS_CERT_THUMBPRINT".into(),
                    )
                })?;
            let url = opts
                .get("timestamp-url")
                .map_or(sign::TIMESTAMP_URL, String::as_str);
            let locate = || sign::find_signtool(&PathBuf::from(sign::WINDOWS_KITS_BIN));
            sign::windows(
                &mut sign::System,
                Path::new(&target),
                &thumbprint,
                url,
                &locate,
            )?;
        }
        _ => return Err(Failure::Usage("unknown command".into())),
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return if args.is_empty() {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(e)) => {
            eprintln!("wpantry-release: {e}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Run(e)) => {
            eprintln!("wpantry-release: {e}");
            ExitCode::from(1)
        }
    }
}
