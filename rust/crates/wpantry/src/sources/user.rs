//! The user's own sources (`~/.config/wpantry/sources.toml`, or
//! `--sources FILE`; [`crate::sources::file::merged`] says what one may be):
//! each asked about once, fetched into the rules and indicator directories,
//! and used beside the bundled ones. Nothing in the file can make wpantry
//! talk to a host the user wasn't asked about, or send anything but a
//! flagged file's SHA-256 to a lookup the user said yes to.

use crate::db::Cache;
use crate::error::Result;
use crate::sources::fetch;
use crate::sources::file::Source;
use crate::utils::net::{self, Net};
use std::path::Path;

/// Whether the user lets wpantry use `s`: needed when it reaches a host
/// wpantry doesn't already ask, or sends anything. The answer is kept by
/// the source's id and URL, so a changed URL is asked about again. `Err`
/// says why it isn't used.
pub fn consent(
    cache: &Cache,
    ask: Option<crate::checks::email::Ask>,
    s: &Source,
) -> Result<std::result::Result<(), String>> {
    let host = s.host().unwrap_or_default();
    let known = net::HOSTS.contains(&host.as_str());
    if known && s.sends.is_empty() {
        return Ok(Ok(()));
    }
    let key = format!("source_consent:{}", s.id);
    match cache.get(&key)?.as_deref().and_then(|v| v.split_once(' ')) {
        Some(("yes", url)) if url == s.url => return Ok(Ok(())),
        Some(("no", url)) if url == s.url => return Ok(Err("you said no to it".into())),
        _ => {}
    }
    let Some(ask) = ask else {
        return Ok(Err(format!("it reaches {host}, which needs your yes: run `wpantry scan` where it can ask")));
    };
    let sends = if s.sends.is_empty() {
        String::new()
    } else {
        " Each flagged file's SHA-256 is sent to it, never the file.".into()
    };
    let question = format!("Use the {} source {:?} from your sources file ({})?{sends}", s.kind, s.id, s.url);
    let Some(yes) = ask(&question) else {
        return Ok(Err("not answered".into()));
    };
    cache.set(&key, &format!("{} {}", if yes { "yes" } else { "no" }, s.url))?;
    cache.commit()?;
    Ok(if yes { Ok(()) } else { Err("you said no to it".into()) })
}

/// Where a user source of a file kind is kept: YARA rules in the rules
/// directory, lists in the indicator directory beside signature-base's.
fn place(rules: &Path, s: &Source) -> Option<std::path::PathBuf> {
    match s.kind.as_str() {
        "yara" => Some(rules.join(format!("user-{}.yar", s.id))),
        "hashes" | "hosts" | "filenames" => Some(rules.join("iocs").join(format!("user-{}.{}.txt", s.id, s.kind))),
        _ => None,
    }
}

/// Fetch each of `sources` (the user's, in use this run) that is a file
/// into its place, when due; drop the files of user sources no longer in
/// use. Returns what couldn't be
/// fetched, by id.
pub fn fetch_files(
    cache: &Cache,
    net: &dyn Net,
    rules: &Path,
    sources: &[Source],
    offline: bool,
) -> Vec<(String, String)> {
    let mut failed = Vec::new();
    let mut keep = Vec::new();
    for s in sources {
        let Some(path) = place(rules, s) else { continue };
        keep.push(path.clone());
        let key = format!("user:{}", s.id);
        if !path.is_file() {
            let _ = cache.unset(&format!("{key}_at"));
        }
        match fetch::file_of(cache, net, s, &key, offline) {
            Ok(Some(body)) => {
                if let Err(e) =
                    path.parent().map(std::fs::create_dir_all).transpose().and_then(|_| std::fs::write(&path, body))
                {
                    failed.push((s.id.clone(), e.to_string()));
                }
            }
            Ok(None) if !path.is_file() => failed.push((s.id.clone(), "not fetched yet".into())),
            Ok(None) => {}
            Err(e) => failed.push((s.id.clone(), e.to_string())),
        }
    }
    for dir in [rules.to_path_buf(), rules.join("iocs")] {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for p in rd.flatten().map(|e| e.path()) {
            let user = p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("user-"));
            if user && !keep.contains(&p) {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    failed
}

#[cfg(test)]
#[path = "user_tests.rs"]
mod tests;
