//! The baseline of what persists, and the findings: what is new, and what
//! warns every scan.

use super::{Inventory, Item, Signature, Source, Vetted};
use crate::check::Finding;
use crate::db::Cache;
use crate::error::Result;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// Diff the inventory against the cache's baseline and record it: the
/// indexes of the items new since the last scan, and the sources baselined
/// for the first time.
pub fn diff(cache: &Cache, inv: &Inventory, at: f64) -> Result<(Vec<usize>, Vec<Source>)> {
    let mut new = Vec::new();
    let mut first = Vec::new();
    for &source in &inv.read {
        let mine: Vec<(usize, &Item)> = inv.items.iter().enumerate().filter(|(_, i)| i.source == source).collect();
        match cache.persistence_baseline(source.name())? {
            Some(known) => new.extend(mine.iter().filter(|(_, i)| !known.contains(&i.key())).map(|(n, _)| *n)),
            None => first.push(source),
        }
        let rows: Vec<(String, String, String)> = mine
            .iter()
            .map(|(_, i)| {
                (i.key(), i.location.clone(), i.program.as_ref().map(|p| p.display().to_string()).unwrap_or_default())
            })
            .collect();
        cache.persistence_record(source.name(), &rows, at)?;
    }
    Ok((new, first))
}

const NEW_FIX: &str = "If you didn't add it, find out what it is and who installed it before anything else: read the item and its program, unload it (launchctl bootout, systemctl disable --now, or remove the entry), move the program aside for a look, then change the passwords used on this machine. If you added it yourself, nothing to do: it is in the baseline now";

/// The findings for an inventory: what is new, and what warns every scan.
/// `vetted` holds the program checks by program path.
pub fn findings(
    inv: &Inventory,
    new: &[usize],
    vetted: &BTreeMap<PathBuf, Vetted>,
    show: &dyn Fn(&Path) -> String,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let warn = |component: String, location: String, id: &str, note: String, fix: &str| Finding {
        kind: "persistence".into(),
        component,
        location,
        vuln_id: id.into(),
        status: "warn".into(),
        severity: "MEDIUM".into(),
        note,
        fix_cmd: fix.into(),
        fix_auto: false,
        ..Default::default()
    };
    let runs = |i: &Item| -> (String, String) {
        match &i.program {
            Some(p) => {
                let shown = show(p);
                let v = vetted.get(p).map(Vetted::describe).filter(|d| !d.is_empty());
                let detail = v.map(|d| format!(" ({d})")).unwrap_or_default();
                (shown.clone(), format!(": runs {shown}{detail}"))
            }
            None => (String::new(), String::new()),
        }
    };
    // New items; a startup file's new lines are one finding per file.
    let mut lines: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for &n in new {
        let i = &inv.items[n];
        if i.source == Source::Shell {
            lines.entry(i.location.as_str()).or_default().push(i.line);
            continue;
        }
        let (program, runs) = runs(i);
        let at = if i.line > 0 { format!(" (line {})", i.line) } else { String::new() };
        out.push(warn(
            i.location.clone(),
            program,
            "PERSISTENCE-NEW",
            format!("a {} that wasn't there at the last scan{at}{runs}", i.source.what()),
            NEW_FIX,
        ));
    }
    for (file, nums) in lines {
        let shown: Vec<String> = nums.iter().take(8).map(usize::to_string).collect();
        let more = if nums.len() > 8 { ", …" } else { "" };
        out.push(warn(
            file.to_string(),
            String::new(),
            "PERSISTENCE-NEW",
            format!(
                "{} new line{} since the last scan (line{} {}{more}); every new shell runs {}",
                nums.len(),
                if nums.len() == 1 { "" } else { "s" },
                if nums.len() == 1 { "" } else { "s" },
                shown.join(", "),
                if nums.len() == 1 { "it" } else { "them" }
            ),
            "Read those lines. An installer adding its PATH or completion is normal; a download, a background job or a variable you don't recognise is not: remove it and find what wrote it",
        ));
    }
    // Every scan: injection, broken signatures, hidden places.
    for i in &inv.items {
        if !i.injects.is_empty() {
            let at = if i.line > 0 { format!(" (line {})", i.line) } else { String::new() };
            out.push(warn(
                i.location.clone(),
                i.injects.join(", "),
                "PERSISTENCE-INJECTION",
                format!(
                    "the {} sets {}{at}: every program it starts loads that library first, which is how code is injected into other apps",
                    i.source.what(),
                    i.injects.join(" and ")
                ),
                "Unless you set it for a tool you know, remove the variable (and the library it names) and find what put it there",
            ));
        }
    }
    let mut flagged = HashSet::new();
    for i in &inv.items {
        let Some(p) = &i.program else { continue };
        let Some(v) = vetted.get(p) else { continue };
        if let Signature::Invalid(why) = &v.signature
            && flagged.insert((p.clone(), "sig"))
        {
            out.push(warn(
                i.location.clone(),
                show(p),
                "PERSISTENCE-SIGNATURE",
                format!("the {} runs {}, whose code signature doesn't verify ({why}): it was changed after it was signed", i.source.what(), show(p)),
                "Reinstall the app or tool from its publisher; if you don't know what it is, unload the item and move the program aside for a look",
            ));
        }
        if v.hidden && flagged.insert((p.clone(), "hidden")) {
            out.push(warn(
                i.location.clone(),
                show(p),
                "PERSISTENCE-HIDDEN",
                format!(
                    "the {} runs {} from a temporary or hidden place, where installers don't put programs and malware does",
                    i.source.what(),
                    show(p)
                ),
                NEW_FIX,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system;

    #[test]
    fn the_baseline_is_quiet_first_then_warns_on_new_items() {
        let d = system::TempDir::new("persist").unwrap();
        let cache = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        let item = |loc: &str, ident: &str| Item {
            source: Source::Launchd,
            location: loc.into(),
            ident: ident.into(),
            program: Some(PathBuf::from("/opt/x")),
            injects: Vec::new(),
            line: 0,
        };
        let mut inv =
            Inventory { items: vec![item("a.plist", "/opt/x")], read: vec![Source::Launchd], unread: Vec::new() };
        let (new, first) = diff(&cache, &inv, 1.0).unwrap();
        assert!(new.is_empty());
        assert_eq!(first, [Source::Launchd]);
        // A second scan with the same items: nothing new.
        assert_eq!(diff(&cache, &inv, 2.0).unwrap(), (vec![], vec![]));
        // A new plist, and the old one now runs something else.
        inv.items = vec![item("a.plist", "/opt/y"), item("b.plist", "/opt/x")];
        let (new, _) = diff(&cache, &inv, 3.0).unwrap();
        assert_eq!(new, [0, 1]);
        // Recorded: quiet again. A removed item that comes back is new again.
        assert!(diff(&cache, &inv, 4.0).unwrap().0.is_empty());
        inv.items.pop();
        diff(&cache, &inv, 5.0).unwrap();
        inv.items.push(item("b.plist", "/opt/x"));
        assert_eq!(diff(&cache, &inv, 6.0).unwrap().0, [1]);
        // An unread source keeps its baseline untouched.
        inv.read.clear();
        inv.items.clear();
        diff(&cache, &inv, 7.0).unwrap();
        inv.read.push(Source::Launchd);
        inv.items = vec![item("a.plist", "/opt/y"), item("b.plist", "/opt/x")];
        assert!(diff(&cache, &inv, 8.0).unwrap().0.is_empty());
    }

    #[test]
    fn findings_for_new_items_injection_signatures_and_hidden_programs() {
        let shell = |line: usize, ident: &str| Item {
            source: Source::Shell,
            location: "~/.zshrc".into(),
            ident: ident.into(),
            program: None,
            injects: Vec::new(),
            line,
        };
        let agent = Item {
            source: Source::Launchd,
            location: "~/Library/LaunchAgents/x.plist".into(),
            ident: "/Users/u/.x/agent".into(),
            program: Some(PathBuf::from("/Users/u/.x/agent")),
            injects: vec!["DYLD_INSERT_LIBRARIES".into()],
            line: 0,
        };
        let inv = Inventory { items: vec![shell(3, "a"), shell(9, "b"), agent], read: vec![], unread: vec![] };
        let mut vetted = BTreeMap::new();
        vetted.insert(
            PathBuf::from("/Users/u/.x/agent"),
            Vetted {
                signature: Signature::Invalid("invalid signature".into()),
                quarantined: Some(false),
                hidden: true,
            },
        );
        let show = |p: &Path| p.display().to_string();
        let got = findings(&inv, &[0, 1, 2], &vetted, &show);
        let ids: Vec<(&str, &str)> = got.iter().map(|f| (f.vuln_id.as_str(), f.component.as_str())).collect();
        assert_eq!(
            ids,
            [
                ("PERSISTENCE-NEW", "~/Library/LaunchAgents/x.plist"),
                ("PERSISTENCE-NEW", "~/.zshrc"),
                ("PERSISTENCE-INJECTION", "~/Library/LaunchAgents/x.plist"),
                ("PERSISTENCE-SIGNATURE", "~/Library/LaunchAgents/x.plist"),
                ("PERSISTENCE-HIDDEN", "~/Library/LaunchAgents/x.plist"),
            ]
        );
        assert!(got.iter().all(|f| f.kind == "persistence" && f.status == "warn" && !f.fix_auto));
        assert!(got[0].note.contains("runs /Users/u/.x/agent (its signature doesn't verify"), "{}", got[0].note);
        assert_eq!(got[1].note, "2 new lines since the last scan (lines 3, 9); every new shell runs them");
        // Nothing new: only what warns every scan.
        assert_eq!(findings(&inv, &[], &vetted, &show).len(), 3);
    }
}
