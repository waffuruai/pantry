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
mod tests {
    use super::*;
    use crate::sources::file::merged;
    use crate::sources::testing::cache;
    use crate::utils::net::{Fake, Response};

    fn user(body: &str) -> Source {
        let all = merged(&format!("[[source]]\n{body}\n")).unwrap();
        all.into_iter().last().unwrap()
    }

    #[test]
    fn a_new_host_is_used_only_after_a_yes_kept_by_id_and_url() {
        let (_d, c) = cache();
        let s = user(
            "id = \"team-rules\"\nkind = \"yara\"\nformat = \"yara\"\nurl = \"https://rules.example.com/team.yar\"",
        );
        assert!(consent(&c, None, &s).unwrap().unwrap_err().contains("needs your yes"), "--no-input: not used");
        let yes = |_: &str| Some(true);
        assert_eq!(consent(&c, Some(&yes), &s).unwrap(), Ok(()));
        assert_eq!(consent(&c, None, &s).unwrap(), Ok(()), "the yes is kept");
        let moved = Source { url: "https://other.example.com/team.yar".into(), ..s.clone() };
        assert!(consent(&c, None, &moved).unwrap().is_err(), "a new URL is asked about again");
        let no = |_: &str| Some(false);
        assert_eq!(consent(&c, Some(&no), &moved).unwrap(), Err("you said no to it".into()));
        assert!(consent(&c, None, &moved).unwrap().is_err(), "the no is kept");
        let known = user(
            "id = \"mirror\"\nkind = \"hosts\"\nformat = \"lines\"\nurl = \"https://feodotracker.abuse.ch/x.txt\"",
        );
        assert_eq!(consent(&c, None, &known).unwrap(), Ok(()), "a host wpantry already asks needs no yes");
        let lookup = user(
            "id = \"our-lookup\"\nkind = \"hash-lookup\"\nformat = \"circl\"\nurl = \"https://hashlookup.circl.lu/x/\"\nsends = \"sha256\"",
        );
        assert!(consent(&c, None, &lookup).unwrap().is_err(), "sending a hash always needs its own yes");
    }

    #[test]
    fn file_sources_land_in_their_places_and_leave_when_dropped() {
        let (d, c) = cache();
        let rules = d.path().join("rules");
        let mine = vec![
            user("id = \"t-rules\"\nkind = \"yara\"\nformat = \"yara\"\nurl = \"https://api.osv.dev/r.yar\""),
            user("id = \"t-hosts\"\nkind = \"hosts\"\nformat = \"lines\"\nurl = \"https://api.osv.dev/h.txt\""),
        ];
        let net = Fake::new(|r| {
            Ok(Response::ok(if r.url.ends_with(".yar") { "rule t { condition: true }" } else { "bad.example\n" }))
        });
        assert!(fetch_files(&c, &net, &rules, &mine, false).is_empty());
        assert!(rules.join("user-t-rules.yar").is_file() && rules.join("iocs/user-t-hosts.hosts.txt").is_file());
        assert!(fetch_files(&c, &net, &rules, &mine[..1], false).is_empty());
        assert!(!rules.join("iocs/user-t-hosts.hosts.txt").exists(), "a source no longer listed leaves");
        let gone = Fake::offline();
        std::fs::remove_file(rules.join("user-t-rules.yar")).unwrap();
        assert_eq!(fetch_files(&c, &gone, &rules, &mine[..1], false).len(), 1, "unreachable with no copy: said so");
    }
}
