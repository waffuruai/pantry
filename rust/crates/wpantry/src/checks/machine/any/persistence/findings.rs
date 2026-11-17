//! The baseline of what persists, and the findings: what is new, and what
//! warns every scan.

use super::{Inventory, Item, Signature, Source, Vetted};
use crate::checks::Scan;
use crate::db::Cache;
use crate::error::Result;
use crate::finding::Finding;
use crate::utils::files;
use crate::utils::os::now;
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

/// Persistence: every place a program can arrange to run again (listed
/// and checked beside the other probes), diffed against the last scan's
/// list in the cache's `persistence` table. Runs with the machine inventory
/// whatever `--no-posture` says, as the clipper's persistence check does:
/// it is malware's footing, not a setting.
pub fn persistence(scan: &mut Scan, (inv, vetted): crate::checks::machine::any::persistence::Gathered) {
    use crate::checks::machine::any::persistence as p;
    scan.status("Comparing launch agents, login items and the other persistence places with the last scan");
    scan.count("persistence items listed", inv.items.len() as i64);
    for (source, why) in &inv.unread {
        scan.unchecked(&format!("persistence: {}s", source.what()), why);
    }
    let (new, first) = match p::diff(&scan.cache, &inv, now()) {
        Ok(d) => d,
        Err(e) => {
            scan.unchecked("persistence baseline", &e.to_string());
            (Vec::new(), Vec::new())
        }
    };
    let baselined = inv.items.iter().filter(|i| first.contains(&i.source)).count();
    scan.count("persistence items recorded as the baseline (first scan)", baselined as i64);
    for f in p::findings(&inv, &new, &vetted, &|path| files::short(&path.to_string_lossy())) {
        scan.add(f);
    }
}

#[cfg(test)]
#[path = "findings_tests.rs"]
mod tests;
