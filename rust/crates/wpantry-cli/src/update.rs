//! `wpantry update`: is there a newer release, and install it after a yes.
//! The download is verified before anything is replaced (see
//! `wpantry::selfinstall`); an install mise, cargo or Homebrew made is
//! updated through that tool; a source build is left alone.

use crate::{EXIT_FAIL, EXIT_OK, EXIT_UPDATE_AVAILABLE, progress, say};
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;
use wpantry::VERSION;
use wpantry::db::Cache;
use wpantry::error::{Error, Result};
use wpantry::selfinstall::{self, Kind};
use wpantry::utils::process::exec;
use wpantry::utils::process::which;

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
    let net = wpantry::utils::net::Http::new();
    let exe = std::env::current_exe()?.canonicalize()?;
    run_with(u, &net, &exe, None)
}

/// `run` for the binary at `exe` (its real path), over `net`, with the
/// cache at `db` (None: the usual one).
fn run_with(u: Update, net: &dyn wpantry::utils::net::Net, exe: &Path, db: Option<&Path>) -> Result<i32> {
    let kind = selfinstall::kind(exe);
    let latest = match &u.version {
        Some(v) => v.trim_start_matches('v').to_string(),
        None => {
            let cache = Cache::open(db)?;
            let r = selfinstall::latest(&cache, net, u.offline);
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
    say(&format!("wpantry {VERSION} → {latest} ({})", describe(&kind, exe)));
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
            let (file, verified) = selfinstall::fetch_verified(net, &latest, dir.path())?;
            say(&format!("  ✓ verified: {}", verified.by));
            selfinstall::replace(&file, exe)?;
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

fn describe(kind: &Kind, exe: &Path) -> String {
    let where_ = wpantry::utils::files::short(&exe.to_string_lossy());
    match kind {
        Kind::Mise => format!("installed by mise at {where_}"),
        Kind::Cargo => format!("installed by cargo at {where_}"),
        Kind::Brew => format!("installed by Homebrew at {where_}"),
        Kind::Source => format!("built from a checkout at {where_}"),
        Kind::File => format!("at {where_}"),
    }
}

/// One line on stderr when a newer release is cached, for `scan`; never
/// a network call of its own beyond the daily memo, never under `--json`,
/// `--offline` or `WPANTRY_NO_UPDATE_CHECK`.
pub fn notice(net: &dyn wpantry::utils::net::Net, offline: bool) -> Option<String> {
    if offline || std::env::var_os("WPANTRY_NO_UPDATE_CHECK").is_some() {
        return None;
    }
    notice_in(Cache::open(None).ok()?, net)
}

fn notice_in(cache: Cache, net: &dyn wpantry::utils::net::Net) -> Option<String> {
    let latest = selfinstall::latest(&cache, net, false).ok()?;
    let _ = cache.close();
    selfinstall::newer(VERSION, &latest)
        .then(|| format!("wpantry {latest} is available (you have {VERSION}): wpantry update"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wpantry::utils::net::{Fake, Response};
    use wpantry::utils::temp::TempDir;

    /// A GitHub that names `tag` as the latest release.
    fn github(tag: &'static str) -> Fake {
        Fake::new(move |req| {
            assert!(req.url.ends_with("/releases/latest"), "{}", req.url);
            Ok(Response::ok(format!("{{\"tag_name\": \"{tag}\"}}")))
        })
    }

    fn update(version: Option<&str>) -> Update {
        Update { check: false, yes: false, no_input: true, offline: false, version: version.map(String::from) }
    }

    const SOURCE: &str = "/w/pantry/rust/target/release/wpantry";
    const FILE: &str = "/opt/bin/wpantry";

    #[test]
    fn a_newer_release_is_reported_and_check_exits_10() {
        let d = TempDir::new("update").unwrap();
        let db = d.path().join("w.db");
        let net = github("v99.0.0");
        let u = Update { check: true, ..update(None) };
        assert_eq!(run_with(u, &net, Path::new(SOURCE), Some(&db)).unwrap(), EXIT_UPDATE_AVAILABLE);
        // A checkout is never replaced: the step is to rebuild it.
        assert_eq!(run_with(update(None), &net, Path::new(SOURCE), Some(&db)).unwrap(), EXIT_UPDATE_AVAILABLE);
        assert_eq!(net.requests().len(), 1, "the second run answers from the cache");
    }

    #[test]
    fn the_latest_release_and_an_unreachable_github_are_not_updates() {
        let d = TempDir::new("update").unwrap();
        let db = d.path().join("w.db");
        let net = github(VERSION);
        assert_eq!(run_with(update(None), &net, Path::new(FILE), Some(&db)).unwrap(), EXIT_OK);
        let empty = d.path().join("empty.db");
        assert_eq!(run_with(update(None), &Fake::offline(), Path::new(FILE), Some(&empty)).unwrap(), EXIT_OK);
    }

    #[test]
    fn a_cache_that_cannot_remember_the_release_is_an_internal_error() {
        let d = TempDir::new("update").unwrap();
        let db = d.path().join("w.db");
        let cache = Cache::open(Some(&db)).unwrap();
        cache
            .conn
            .execute_batch("DROP TABLE runs; CREATE VIEW runs AS SELECT '' AS source, '' AS fingerprint, 0.0 AS ran_at, '' AS result WHERE 0")
            .unwrap();
        cache.close().unwrap();
        let err = run_with(update(None), &github("v99.0.0"), Path::new(FILE), Some(&db)).unwrap_err();
        assert!(!err.is_source(), "{err}");
    }

    #[test]
    fn a_wanted_version_must_be_a_release_version() {
        let d = TempDir::new("update").unwrap();
        let db = d.path().join("w.db");
        let err = run_with(update(Some("nope")), &Fake::offline(), Path::new(FILE), Some(&db)).unwrap_err();
        assert!(err.to_string().contains("not a release version"), "{err}");
    }

    #[test]
    fn without_a_yes_each_install_kind_names_its_own_update_step() {
        let d = TempDir::new("update").unwrap();
        let db = d.path().join("w.db");
        for exe in [
            "/h/.local/share/mise/installs/packslip-github-com-waffuruai-pantry/1.0.0/bin/wpantry",
            "/h/.cargo/bin/wpantry",
            "/opt/homebrew/bin/wpantry",
            FILE,
        ] {
            let got = run_with(update(Some("v99.0.0")), &Fake::offline(), Path::new(exe), Some(&db)).unwrap();
            assert_eq!(got, EXIT_UPDATE_AVAILABLE, "{exe}");
        }
    }

    #[test]
    fn a_file_install_downloads_before_it_replaces_anything() {
        let d = TempDir::new("update").unwrap();
        let db = d.path().join("w.db");
        let u = Update { yes: true, ..update(Some("99.0.0")) };
        let err = run_with(u, &Fake::offline(), Path::new(FILE), Some(&db)).unwrap_err();
        assert!(err.is_source(), "{err}");
    }

    #[test]
    fn through_runs_the_owning_tool_when_it_is_here() {
        assert_eq!(through(&["wpantry-no-such-tool", "upgrade", "wpantry"]).unwrap(), EXIT_FAIL);
        assert_eq!(through(&["false"]).unwrap(), EXIT_FAIL);
        assert_eq!(through(&["true"]).unwrap(), EXIT_OK);
    }

    #[test]
    fn describe_names_the_install_kind_and_place() {
        let exe = Path::new("/opt/bin/wpantry");
        assert_eq!(describe(&Kind::Mise, exe), "installed by mise at /opt/bin/wpantry");
        assert_eq!(describe(&Kind::Cargo, exe), "installed by cargo at /opt/bin/wpantry");
        assert_eq!(describe(&Kind::Brew, exe), "installed by Homebrew at /opt/bin/wpantry");
        assert_eq!(describe(&Kind::Source, exe), "built from a checkout at /opt/bin/wpantry");
        assert_eq!(describe(&Kind::File, exe), "at /opt/bin/wpantry");
    }

    #[test]
    fn the_notice_names_a_newer_cached_release_only() {
        assert_eq!(notice(&Fake::offline(), true), None, "offline: no notice");
        let d = TempDir::new("notice").unwrap();
        let db = d.path().join("w.db");
        let open = || Cache::open(Some(&db)).unwrap();
        assert_eq!(notice_in(open(), &Fake::offline()), None, "nothing cached, nothing reachable");
        assert_eq!(notice_in(open(), &github(VERSION)), None, "this is the latest");
        let other = d.path().join("other.db");
        let got = notice_in(Cache::open(Some(&other)).unwrap(), &github("v99.0.0")).unwrap();
        assert_eq!(got, format!("wpantry 99.0.0 is available (you have {VERSION}): wpantry update"));
        assert!(notice_in(Cache::open(Some(&other)).unwrap(), &Fake::offline()).is_some(), "from the day's memo");
    }
}
