//! `wpantry update`: is there a newer release, and install it after a yes.
//! The download is verified before anything is replaced (see
//! `wpantry::selfinstall`); an install mise, cargo or Homebrew made is
//! updated through that tool; a source build is left alone.

use crate::{EXIT_FAIL, EXIT_OK, EXIT_UPDATE_AVAILABLE, progress, say};
use std::ffi::OsStr;
use std::time::Duration;
use wpantry::VERSION;
use wpantry::db::Cache;
use wpantry::error::{Error, Result};
use wpantry::selfinstall::{self, Kind};
use wpantry::system::{exec, which};

pub struct Update {
    /// Only say whether an update exists (exit 10 when one does).
    pub check: bool,
    /// Install without asking.
    pub yes: bool,
    /// Never ask: report only.
    pub no_input: bool,
    pub offline: bool,
    /// A specific release instead of the latest.
    pub version: Option<String>,
}

pub fn run(u: Update) -> Result<i32> {
    let net = wpantry::net::Http::new();
    let exe = std::env::current_exe()?.canonicalize()?;
    let kind = selfinstall::kind(&exe);
    let latest = match &u.version {
        Some(v) => v.trim_start_matches('v').to_string(),
        None => {
            let cache = Cache::open(None)?;
            let r = selfinstall::latest(&cache, &net, u.offline);
            cache.close()?;
            match r {
                Ok(v) => v,
                Err(e) if e.is_source() => {
                    say(&format!("wpantry {VERSION}: couldn't check for a newer release ({e})"));
                    return Ok(EXIT_OK);
                }
                Err(e) => return Err(e),
            }
        }
    };
    let wanted = u.version.is_some();
    if !wanted && !selfinstall::newer(VERSION, &latest) {
        say(&format!("wpantry {VERSION} is the latest release"));
        return Ok(EXIT_OK);
    }
    if !selfinstall::is_version(&latest) {
        return Err(Error::Invalid(format!("not a release version: {latest:?}")));
    }
    say(&format!("wpantry {VERSION} → {latest} ({})", describe(&kind, &exe)));
    if u.check {
        return Ok(EXIT_UPDATE_AVAILABLE);
    }
    let how = match &kind {
        Kind::Mise => format!("mise use --global packslip:github.com/{}@{latest}", selfinstall::REPO),
        Kind::Cargo => format!("cargo install --locked wpantry-cli@{latest}"),
        Kind::Brew => "brew upgrade wpantry".to_string(),
        Kind::Source => {
            say(
                "  This wpantry was built from a checkout: update the checkout and rebuild it (ops: mise run wpantry).",
            );
            return Ok(EXIT_UPDATE_AVAILABLE);
        }
        Kind::File => format!("download release {latest}, verify it, and replace {}", exe.display()),
    };
    if !u.yes {
        if u.no_input || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            say(&format!("  To update: wpantry update --yes  ({how})"));
            return Ok(EXIT_UPDATE_AVAILABLE);
        }
        let ok = progress::Progress::new(false).ask(&format!("Update now? ({how})"), true).unwrap_or(false);
        if !ok {
            say("  Nothing was changed.");
            return Ok(EXIT_UPDATE_AVAILABLE);
        }
    }
    match kind {
        Kind::Mise => {
            through(&["mise", "use", "--global", &format!("packslip:github.com/{}@{latest}", selfinstall::REPO)])
        }
        Kind::Cargo => through(&["cargo", "install", "--locked", &format!("wpantry-cli@{latest}")]),
        Kind::Brew => through(&["brew", "upgrade", "wpantry"]),
        Kind::Source => unreachable!("handled above"),
        Kind::File => {
            let dir = selfinstall::workdir()?;
            say(&format!("  Downloading and verifying wpantry {latest}…"));
            let (file, verified) = selfinstall::fetch_verified(&net, &latest, dir.path())?;
            say(&format!("  ✓ verified: {}", verified.by));
            selfinstall::replace(&file, &exe)?;
            say(&format!(
                "  ✓ installed wpantry {latest} at {} (the old one is beside it as wpantry.old)",
                exe.display()
            ));
            Ok(EXIT_OK)
        }
    }
}

/// Run the tool that owns this install, with the terminal.
fn through(argv: &[&str]) -> Result<i32> {
    let Some(exe) = which(argv[0]) else {
        say(&format!("  {} isn't on PATH; run the update yourself: {}", argv[0], argv.join(" ")));
        return Ok(EXIT_FAIL);
    };
    say(&format!("  → {}", argv.join(" ")));
    let mut full: Vec<&OsStr> = vec![exe.as_os_str()];
    full.extend(argv[1..].iter().map(OsStr::new));
    let out = exec(&full, &[], Duration::from_secs(30 * 60))?;
    if out.code != Some(0) {
        say(&format!("  ✗ {} failed: {}", argv[0], out.stderr.trim().lines().last().unwrap_or("")));
        return Ok(EXIT_FAIL);
    }
    say(&format!("  ✓ {} updated wpantry; open a new shell if the old version still answers", argv[0]));
    Ok(EXIT_OK)
}

fn describe(kind: &Kind, exe: &std::path::Path) -> String {
    let where_ = wpantry::system::short(&exe.to_string_lossy());
    match kind {
        Kind::Mise => format!("installed by mise at {where_}"),
        Kind::Cargo => format!("installed by cargo at {where_}"),
        Kind::Brew => format!("installed by Homebrew at {where_}"),
        Kind::Source => format!("built from a checkout at {where_}"),
        Kind::File => format!("at {where_}"),
    }
}

/// One line on stderr when a newer release is cached, for `check`; never
/// a network call of its own beyond the daily memo, never under `--json`,
/// `--offline` or `WPANTRY_NO_UPDATE_CHECK`.
pub fn notice(net: &dyn wpantry::net::Net, offline: bool) -> Option<String> {
    if offline || std::env::var_os("WPANTRY_NO_UPDATE_CHECK").is_some() {
        return None;
    }
    let cache = Cache::open(None).ok()?;
    let latest = selfinstall::latest(&cache, net, false).ok()?;
    let _ = cache.close();
    selfinstall::newer(VERSION, &latest)
        .then(|| format!("wpantry {latest} is available (you have {VERSION}): wpantry update"))
}
