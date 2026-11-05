//! Editor extensions against the lists VS Code itself uses, OSV and their
//! marketplace's latest, and the npm packages bundled in extensions,
//! harness plugins and desktop extensions.

use crate::checks::supply_chain::repos;
use crate::checks::{Scan, lockfiles};
use crate::component::Component;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::osv;
use crate::sources::osv::Item;
use crate::utils::files::short;
use std::path::{Path, PathBuf};

// Editors and AI harnesses ----------------------------------------------------

/// Malicious or deprecated per the lists VS Code itself uses (and OSV),
/// behind their marketplace's latest, and the npm packages they bundle.
pub fn extensions(scan: &mut Scan) -> Result<Vec<Component>> {
    scan.status("Reading editor extensions");
    extensions_with(scan, crate::checks::machine::editors::extensions())
}

/// As [`extensions`], over the extensions found (`editors::extensions`).
pub fn extensions_with(scan: &mut Scan, mut exts: Vec<Component>) -> Result<Vec<Component>> {
    if exts.is_empty() {
        return Ok(exts);
    }
    scan.count("editor extensions", exts.len() as i64);
    scan.status("Fetching VS Code's malicious-extension list");
    let r = crate::sources::extensions::vscode_lists(&scan.cache, scan.net, scan.opts.offline).map(Some);
    let lists = scan.guard("VS Code's malicious-extension list", r, None)?;
    let items: Vec<Item> = exts.iter().filter_map(|e| e.osv.clone()).collect();
    let answers = scan.lookup(&items, "editor extensions against OSV")?;
    let mut latest: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for market in ["vscode", "openvsx"] {
        let ids: Vec<String> = exts
            .iter()
            .filter(|e| e.extra.get("market").map(String::as_str) == Some(market))
            .map(|e| e.name.clone())
            .collect();
        if !ids.is_empty() {
            scan.status(&format!("Fetching the latest extension versions ({market})"));
            let r = crate::sources::extensions::latest_extensions(
                &scan.cache,
                scan.net,
                &ids,
                market == "openvsx",
                scan.opts.offline,
            );
            latest.extend(scan.guard(&format!("latest extension versions ({market})"), r, Default::default())?);
        }
    }
    for e in &mut exts {
        let id = e.extra.get("id").cloned().unwrap_or_default();
        let editor = e.extra.get("editor").cloned().unwrap_or_default();
        let cli = e.extra.get("cli").cloned().unwrap_or_default();
        let lower = id.to_lowercase();
        e.name = format!("{id} ({editor})"); // how the report names it
        let uninstall = format!("{cli} --uninstall-extension {id}");
        if lists.as_ref().is_some_and(|l| l.malicious.contains(&lower)) {
            scan.add(Finding {
                vuln_id: "MALICIOUS".into(),
                status: "fail".into(),
                kev: true,
                severity: "MALICIOUS".into(),
                fix_cmd: uninstall,
                fix_auto: true,
                note: "known malicious extension (removed from the marketplace)".into(),
                ..Finding::of(e)
            });
            continue;
        }
        (e.fix, e.auto) = (uninstall.clone(), true);
        let recs = e.osv.as_ref().and_then(|o| answers.get(o)).cloned().unwrap_or_default();
        if scan.advisories(e, &recs, None, "fail", None) {
            continue;
        }
        e.fix = format!("{cli} --install-extension {id} --force");
        if let Some(repl) = lists.as_ref().and_then(|l| l.deprecated.get(&lower)) {
            scan.add(Finding {
                vuln_id: "DEPRECATED".into(),
                status: "warn".into(),
                note: if repl.is_empty() { "deprecated".into() } else { format!("deprecated; use {repl}") },
                fix_cmd: uninstall,
                ..Finding::of(e)
            });
        }
        if let Some(newest) = latest.get(&lower)
            && !crate::checks::ecosystems::versions::same_or_newer(&e.version, newest)
        {
            scan.add(Finding {
                vuln_id: "OUTDATED".into(),
                status: "warn".into(),
                fixed: newest.clone(),
                note: format!("latest release is {newest}"),
                fix_cmd: e.fix.clone(),
                fix_auto: true,
                ..Finding::of(e)
            });
        }
    }
    Ok(exts)
}

/// npm packages bundled in editor extensions, harness plugins and desktop
/// extensions, plus lockfiles shipped in those and in skills. A vulnerable
/// bundle warns (only its vendor can fix it); malicious fails.
pub fn bundles(scan: &mut Scan, exts: &[Component]) -> Result<()> {
    scan.status("Reading the packages extensions and plugins bundle");
    let mut dirs: Vec<(String, String, String)> =
        exts.iter().map(|e| (e.name.clone(), e.extra.get("dir").cloned().unwrap_or_default(), e.fix.clone())).collect();
    for (h, d) in crate::checks::machine::harnesses::plugin_dirs() {
        let base = Path::new(&d).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        dirs.push((
            format!("{h} plugin {base}"),
            d.clone(),
            format!("Update or remove the {h} plugin in {}", short(&d)),
        ));
    }
    let pkgs: Vec<Vec<(String, String)>> =
        dirs.iter().map(|(_, d, _)| crate::checks::machine::editors::bundled_npm(Path::new(d))).collect();
    let items: Vec<Item> = pkgs.iter().flatten().map(|(n, v)| ("npm".to_string(), n.clone(), v.clone())).collect();
    let answers = scan.lookup(&items, "bundled npm packages against OSV")?;
    for ((label, d, fix), ps) in dirs.iter().zip(&pkgs) {
        for (n, v) in ps {
            let item = ("npm".to_string(), n.clone(), v.clone());
            let mut c = Component::new("bundled", &format!("{label} › {n}"), v, d);
            c.fix = fix.clone();
            let recs = answers.get(&item).cloned().unwrap_or_default();
            c.osv = Some(item);
            scan.advisories(&c, &recs, None, "warn", None);
        }
    }
    let mut roots: Vec<String> = dirs.iter().map(|(_, d, _)| d.clone()).collect();
    roots.extend(crate::checks::machine::harnesses::skill_dirs().into_iter().map(|(_, d)| d));
    let mut read: Vec<(PathBuf, Vec<lockfiles::Package>)> = Vec::new();
    for root in &roots {
        for f in repos::lockfiles(Path::new(root)) {
            if let Ok(Some(p)) = lockfiles::extract(&f) {
                read.push((f, p));
            }
        }
    }
    scan.count("packages in extension, plugin and skill lockfiles", read.iter().map(|(_, p)| p.len() as i64).sum());
    let items: Vec<Item> = read
        .iter()
        .flat_map(|(_, ps)| ps.iter().map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone())))
        .collect();
    let answers = scan.lookup(&items, "lockfiles inside extensions, plugins and skills")?;
    for (f, ps) in &read {
        let parent = short(&f.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default());
        for p in ps {
            let item = (p.ecosystem.clone(), p.name.clone(), p.version.clone());
            let Some(recs) = answers.get(&item).filter(|r| !r.is_empty()) else { continue };
            let mut c = Component::new("bundled", &format!("{parent} › {}", p.name), &p.version, &f.to_string_lossy());
            c.fix = format!("Update or remove what ships {}", short(&f.to_string_lossy()));
            c.osv = Some(item);
            scan.advisories(&c, &[], None, "warn", Some(osv::group_by_alias(recs)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Options;
    use crate::checks::supply_chain::testing;
    use crate::checks::supply_chain::testing::CARGO_LOCK;
    use crate::utils::files;
    use crate::utils::net::{Fake, Response};
    use crate::utils::temp::TempDir;
    use serde_json::json;

    /// A known malicious extension fails (and nothing else is said of it),
    /// a vulnerable one fails, a deprecated one warns with its replacement,
    /// one behind its marketplace warns with the update.
    #[test]
    fn extensions_against_the_lists_osv_and_the_marketplaces() {
        let d = TempDir::new("extensions").unwrap();
        let net = Fake::new(|r| {
            if r.url == crate::sources::extensions::VSCODE_LISTS {
                return Ok(Response::ok(json!({"malicious": ["Evil.One"], "deprecated": {"Old.Two": {"extension": {"id": "New.Two"}}, "Plain.X": true}}).to_string()));
            }
            if r.url == crate::sources::extensions::MARKETPLACE {
                return Ok(Response::ok(json!({"results": [{"extensions": [
                    {"publisher": {"publisherName": "Old"}, "extensionName": "Two", "versions": [{"version": "2.0.0"}]},
                    {"publisher": {"publisherName": "Vuln"}, "extensionName": "Three", "versions": [{"version": "1.0.0"}]}]}]}).to_string()));
            }
            if r.url == "https://open-vsx.org/api/cur/four/latest" {
                return Ok(Response::ok(json!({"version": "1.0.0"}).to_string()));
            }
            testing::osv(r, &[("VSCode", "Vuln.Three")]).unwrap_or_else(|| panic!("unexpected request to {}", r.url))
        });
        let mut s = testing::scan(&net, &d, Options::default());
        let exts = vec![
            testing::extension("Evil.One", "1.0.0", "vscode", "/e/evil"),
            testing::extension("Old.Two", "1.0.0", "vscode", "/e/old"),
            testing::extension("Vuln.Three", "1.0.0", "vscode", "/e/vuln"),
            testing::extension("Cur.Four", "1.0.0", "openvsx", "/e/cur"),
        ];
        assert!(extensions_with(&mut s, Vec::new()).unwrap().is_empty());
        let out = extensions_with(&mut s, exts).unwrap();
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].name, "Evil.One (VS Code)", "how the report names it");
        assert!(s.counts.contains(&("editor extensions".to_string(), 4)));
        let mal = testing::by_id(&s, "MALICIOUS");
        assert_eq!(mal.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (
                mal[0].component.as_str(),
                mal[0].status.as_str(),
                mal[0].severity.as_str(),
                mal[0].fix_cmd.as_str(),
                mal[0].fix_auto
            ),
            ("Evil.One (VS Code)", "fail", "MALICIOUS", "code --uninstall-extension Evil.One", true)
        );
        assert!(!s.findings.iter().any(|f| f.component.starts_with("Evil.One") && f.vuln_id != "MALICIOUS"));
        let vuln = testing::by_id(&s, "GHSA-Vuln.Three");
        assert_eq!(vuln.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (vuln[0].component.as_str(), vuln[0].status.as_str(), vuln[0].fix_cmd.as_str()),
            ("Vuln.Three (VS Code)", "fail", "code --uninstall-extension Vuln.Three")
        );
        assert!(
            !s.findings.iter().any(|f| f.component.starts_with("Vuln.Three") && f.vuln_id == "OUTDATED"),
            "a vulnerable one is removed, not updated"
        );
        let dep = testing::by_id(&s, "DEPRECATED");
        assert_eq!(dep.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (dep[0].component.as_str(), dep[0].status.as_str(), dep[0].note.as_str()),
            ("Old.Two (VS Code)", "warn", "deprecated; use New.Two")
        );
        let old = testing::by_id(&s, "OUTDATED");
        assert_eq!(old.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (
                old[0].component.as_str(),
                old[0].fixed.as_str(),
                old[0].note.as_str(),
                old[0].fix_cmd.as_str(),
                old[0].fix_auto
            ),
            ("Old.Two (VS Code)", "2.0.0", "latest release is 2.0.0", "code --install-extension Old.Two --force", true)
        );
        assert!(
            !s.findings.iter().any(|f| f.component.starts_with("Cur.Four")),
            "current on Open VSX: {:?}",
            s.findings
        );
        assert!(testing::unchecked(&s).is_empty(), "{:?}", s.findings);
    }

    #[test]
    fn unreachable_extension_lists_are_unchecked_not_clean() {
        let d = TempDir::new("extensions-off").unwrap();
        let net = Fake::offline();
        let mut s = testing::scan(&net, &d, Options::default());
        extensions_with(&mut s, vec![testing::extension("Old.Two", "1.0.0", "vscode", "/e/old")]).unwrap();
        let mut un = testing::unchecked(&s);
        un.sort_unstable();
        assert_eq!(
            un,
            [
                "VS Code's malicious-extension list",
                "editor extensions against OSV",
                "latest extension versions (vscode)"
            ]
        );
        assert_eq!(s.findings.len(), 3, "{:?}", s.findings);
    }

    /// The npm packages bundled in extensions and plugins, and the lockfiles
    /// shipped in those and in skills: a vulnerable one warns (its vendor
    /// fixes it).
    #[test]
    fn bundles_read_node_modules_and_shipped_lockfiles() {
        let _home = crate::utils::files::test_home();
        let home = files::home();
        let d = TempDir::new("bundles").unwrap();
        let net = testing::osv_net(&[("npm", "lodash"), ("crates.io", "serde")]);
        let mut s = testing::scan(&net, &d, Options::default());
        let ext_dir = d.path().join("ext");
        testing::write(&ext_dir, "node_modules/lodash/package.json", r#"{"name": "lodash", "version": "4.17.20"}"#);
        let mut ext = testing::extension("Pub.Ext", "1.0.0", "vscode", ext_dir.to_str().unwrap());
        ext.name = "Pub.Ext (VS Code)".into();
        ext.fix = "code --install-extension Pub.Ext --force".into();
        testing::write(
            &home,
            ".claude/plugins/cache/mk/p1/node_modules/ms/package.json",
            r#"{"name": "ms", "version": "2.1.3"}"#,
        );
        testing::write(&home, ".claude/skills/s1/Cargo.lock", CARGO_LOCK);
        bundles(&mut s, &[ext]).unwrap();
        assert!(
            s.counts.contains(&("packages in extension, plugin and skill lockfiles".to_string(), 2)),
            "{:?}",
            s.counts
        );
        let lodash = testing::by_id(&s, "GHSA-lodash");
        assert_eq!(lodash.len(), 1, "{:?}", s.findings);
        assert_eq!(
            (
                lodash[0].kind.as_str(),
                lodash[0].component.as_str(),
                lodash[0].status.as_str(),
                lodash[0].fix_cmd.as_str()
            ),
            ("bundled", "Pub.Ext (VS Code) › lodash", "warn", "code --install-extension Pub.Ext --force")
        );
        assert_eq!(lodash[0].location, ext_dir.to_string_lossy());
        let serde = testing::by_id(&s, "GHSA-serde");
        assert_eq!(serde.len(), 1, "{:?}", s.findings);
        assert_eq!((serde[0].component.as_str(), serde[0].status.as_str()), ("~/.claude/skills/s1 › serde", "warn"));
        assert_eq!(serde[0].fix_cmd, "Update or remove what ships ~/.claude/skills/s1/Cargo.lock");
        let asked: Vec<String> = net
            .requests()
            .iter()
            .filter(|r| r.url.ends_with("/v1/querybatch"))
            .map(|r| String::from_utf8_lossy(r.body.as_ref().unwrap()).into_owned())
            .collect();
        assert!(asked.iter().any(|b| b.contains("\"ms\"")), "the plugin's bundle is asked too: {asked:?}");
        assert!(!s.findings.iter().any(|f| f.component.contains("ms")), "{:?}", s.findings);
    }
}
