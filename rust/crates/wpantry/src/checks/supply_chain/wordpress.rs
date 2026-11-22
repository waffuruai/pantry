//! WordPress sites in the scanned repos: core, plugins and themes, read as
//! WordPress itself reads them, and checked against Wordfence
//! Intelligence ([`crate::sources::wordfence`]) when the user has a key.
//!
//! What is read, wherever it sits in a repo (Composer's `installer-paths`
//! moves plugins, Bedrock to `web/app/plugins`, so a tree is found by its
//! markers, not by a fixed path):
//!
//! - core: `wp-includes/version.php`'s `$wp_version = '6.5.2';`, a build
//!   suffix (`6.5-RC2-57890`) dropped;
//! - plugins: in a directory named `plugins`, each `*.php` and each
//!   `<slug>/*.php` whose first 8 KB carry a `Plugin Name:` header, as
//!   `get_plugins()` reads them. The version is that file's `Version:`
//!   header, else `readme.txt`'s `Stable tag:` (never `trunk`); the slug is
//!   the directory's name, or the file's stem for a single-file plugin;
//! - themes: in a directory named `themes`, each `<slug>/style.css` with a
//!   `Theme Name:` header, and its `Version:`;
//! - `composer.lock`: `wpackagist-plugin/<slug>`, `wpackagist-theme/<slug>`,
//!   and core as `roots/wordpress`, `roots/wordpress-no-content`,
//!   `johnpbloch/wordpress` or `johnpbloch/wordpress-core`. A plugin the lock
//!   installs under the lock's directory is reported once, at the lock.
//!
//! A version in one of a record's affected ranges fails when the record
//! names a patched version above it, and warns when it names none. Versions
//! compare as PHP's `version_compare` does ([`php_cmp`]), as WordPress and
//! Wordfence compare them. Without `WORDFENCE_API_KEY`, each site is
//! reported not checked, with how to get a free key.

use crate::checks::Scan;
use crate::checks::lockfiles::composer;
use crate::checks::supply_chain::quote;
use crate::checks::supply_chain::repos::Repo;
use crate::finding::Finding;
use crate::sources::wordfence::{self, KIND, Range, Vuln};
use crate::utils::cvss;
use crate::utils::files::{command_path, short};
use crate::utils::walk;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

/// How much of a plugin's or theme's main file is read for its headers, as
/// WordPress's `get_file_data()` reads.
const HEADER_BYTES: usize = 8 << 10;
/// How deep a repo is walked for sites.
const DEPTH: usize = 8;
/// What the count calls what was found.
pub const COUNTED: &str = "WordPress core, plugins and themes";

/// What a piece of WordPress software is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Type {
    Core,
    Plugin,
    Theme,
}

impl Type {
    /// As Wordfence's records name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Type::Core => "core",
            Type::Plugin => "plugin",
            Type::Theme => "theme",
        }
    }
}

/// One piece of WordPress software found in a repo.
#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub kind: Type,
    /// The slug, as Wordfence and wordpress.org name it (`wordpress` for core).
    pub slug: String,
    pub version: String,
    /// Where it was read: the plugin's or theme's directory (a single-file
    /// plugin's file), the site's root for core, or the `composer.lock`.
    pub location: PathBuf,
    /// The site it belongs to: the directory WordPress runs from (the lock's
    /// directory for Composer), so a report can say which site wasn't checked.
    pub site: PathBuf,
    /// Installed by Composer (the lock's entry).
    pub composer: bool,
}

/// Where a version couldn't be read: the file, and why.
pub type Unread = (PathBuf, String);

// Reading headers -------------------------------------------------------------

/// The first [`HEADER_BYTES`] of a file, as text; None when it can't be read.
fn head(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = vec![0u8; HEADER_BYTES];
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return None,
        }
    }
    buf.truncate(n);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// A file header's value (`Plugin Name`, `Version`), as `get_file_data()`
/// reads it: a line holding only comment marks (`*`, `#`, `@`, `/`),
/// spaces and `<?php` before the name, matched without case, the value
/// trimmed of a closing `*/` or `?>`. None when absent or empty.
pub fn header(text: &str, name: &str) -> Option<String> {
    for line in text.split(['\n', '\r']) {
        let mut rest = line.trim_start_matches([' ', '\t']);
        if rest.len() >= 5 && rest[..5].eq_ignore_ascii_case("<?php") {
            rest = &rest[5..];
        }
        let rest = rest.trim_start_matches([' ', '\t', '/', '*', '#', '@']);
        let Some(head) = rest.get(..name.len()) else { continue };
        if !head.eq_ignore_ascii_case(name) {
            continue;
        }
        let Some(value) = rest[name.len()..].strip_prefix(':') else { continue };
        let mut v = value.trim();
        if let Some(i) = v.find("*/") {
            v = &v[..i];
        }
        if let Some(i) = v.find("?>") {
            v = &v[..i];
        }
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

/// `$wp_version`'s value in `wp-includes/version.php`, its build suffix
/// (`-RC2-57890`, `-alpha-…`) dropped.
pub fn core_version(text: &str) -> Option<String> {
    for line in text.lines() {
        let Some(at) = line.find("$wp_version") else { continue };
        let rest = &line[at + "$wp_version".len()..];
        if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let rest = rest.trim_start().strip_prefix('=')?.trim_start();
        let quote = rest.chars().next().filter(|c| *c == '\'' || *c == '"')?;
        let value = rest[1..].split(quote).next()?;
        let version = value.split('-').next().unwrap_or("").trim();
        return plausible(version).then(|| version.to_string());
    }
    None
}

/// A version worth comparing: starts with a digit, one short word.
fn plausible(v: &str) -> bool {
    v.starts_with(|c: char| c.is_ascii_digit())
        && v.len() <= 64
        && v.chars().all(|c| c.is_ascii_alphanumeric() || ".-_+".contains(c))
}

/// A plugin's version: its main file's `Version:`, else its `readme.txt`'s
/// `Stable tag:` (never `trunk`).
fn plugin_version(main: &str, readme: Option<&Path>) -> Option<String> {
    if let Some(v) = header(main, "Version").filter(|v| plausible(v)) {
        return Some(v);
    }
    let text = head(readme?)?;
    header(&text, "Stable tag").filter(|v| !v.eq_ignore_ascii_case("trunk") && plausible(v))
}

// Versions ------------------------------------------------------------------

/// The parts PHP's `version_compare` splits a version into: `_`, `-` and
/// `+` are `.`, and a change between digits and anything else starts a new
/// part.
fn parts(v: &str) -> Vec<String> {
    let v: String = v.chars().map(|c| if "_-+".contains(c) { '.' } else { c }).collect();
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut digits = None;
    for c in v.chars() {
        if c == '.' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            digits = None;
            continue;
        }
        let d = c.is_ascii_digit();
        if digits.is_some_and(|was| was != d) && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        digits = Some(d);
        cur.push(c);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A part's place in PHP's order: any other word < `dev` < `alpha`/`a` <
/// `beta`/`b` < `RC`/`rc` < a number < `pl`/`p`.
fn tier(p: &str) -> u8 {
    if p.bytes().all(|b| b.is_ascii_digit()) {
        return 6;
    }
    match p {
        "dev" => 2,
        "alpha" | "a" => 3,
        "beta" | "b" => 4,
        "RC" | "rc" => 5,
        "pl" | "p" => 7,
        _ => 1,
    }
}

/// PHP's `version_compare`, as Wordfence's scanner implements it: a
/// missing part counts as `0`, so `1.0` equals `1.0.0` and `1.0` is newer
/// than `1.0-rc1`.
pub fn php_cmp(a: &str, b: &str) -> Ordering {
    let (pa, pb) = (parts(a), parts(b));
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).map(String::as_str).unwrap_or("0");
        let y = pb.get(i).map(String::as_str).unwrap_or("0");
        if x == y {
            continue;
        }
        let (tx, ty) = (tier(x), tier(y));
        if tx != ty {
            return tx.cmp(&ty);
        }
        if tx == 6 {
            let o = crate::checks::ecosystems::versions::num_cmp(x, y);
            if o != Ordering::Equal {
                return o;
            }
        }
    }
    Ordering::Equal
}

/// Whether `version` is in `r` (`*` at either end is unbounded).
pub fn in_range(version: &str, r: &Range) -> bool {
    let from_ok = r.from == "*"
        || match php_cmp(&r.from, version) {
            Ordering::Less => true,
            Ordering::Equal => r.from_inclusive,
            Ordering::Greater => false,
        };
    let to_ok = r.to == "*"
        || match php_cmp(&r.to, version) {
            Ordering::Greater => true,
            Ordering::Equal => r.to_inclusive,
            Ordering::Less => false,
        };
    from_ok && to_ok
}

/// A range as the contract's `affected_range` writes it: `>=A, <=B`.
pub fn range_text(r: &Range) -> String {
    let mut out = Vec::new();
    if r.from != "*" {
        out.push(format!("{}{}", if r.from_inclusive { ">=" } else { ">" }, r.from));
    }
    if r.to != "*" {
        out.push(format!("{}{}", if r.to_inclusive { "<=" } else { "<" }, r.to));
    }
    if out.is_empty() { "*".into() } else { out.join(", ") }
}

// Finding sites -------------------------------------------------------------

/// Every piece of WordPress software in `root`, and the ones whose version
/// couldn't be read.
pub fn inventory(root: &Path) -> (Vec<Item>, Vec<Unread>) {
    let dirs = walk::walk(root, DEPTH);
    let mut children: HashMap<&Path, Vec<&(PathBuf, Vec<String>)>> = HashMap::new();
    for d in &dirs {
        if let Some(p) = d.0.parent() {
            children.entry(p).or_default().push(d);
        }
    }
    let (mut items, mut unread) = (Vec::new(), Vec::new());
    for (dir, files) in &dirs {
        let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // A site's root: two up from `plugins` or `themes` (`wp-content`, Bedrock's `app`).
        let site = || dir.parent().and_then(Path::parent).unwrap_or(dir).to_path_buf();
        match name {
            "wp-includes" if files.iter().any(|f| f == "version.php") => {
                let file = dir.join("version.php");
                let at = dir.parent().unwrap_or(dir).to_path_buf();
                match head_all(&file).as_deref().and_then(core_version) {
                    Some(v) => items.push(Item {
                        kind: Type::Core,
                        slug: "wordpress".into(),
                        version: v,
                        location: at.clone(),
                        site: at,
                        composer: false,
                    }),
                    None => unread.push((file, "no $wp_version".into())),
                }
            }
            "plugins" => {
                for f in files.iter().filter(|f| f.ends_with(".php")) {
                    let file = dir.join(f);
                    let Some(text) = head(&file) else { continue };
                    if header(&text, "Plugin Name").is_none() {
                        continue;
                    }
                    let slug = f.trim_end_matches(".php").to_ascii_lowercase();
                    match plugin_version(&text, None) {
                        Some(v) => items.push(item(Type::Plugin, &slug, v, file, site())),
                        None => unread.push((file, "no Version header".into())),
                    }
                }
                for (sub, sub_files) in children.get(dir.as_path()).into_iter().flatten().map(|d| (&d.0, &d.1)) {
                    let slug = sub.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
                    let readme = sub_files.iter().any(|f| f.eq_ignore_ascii_case("readme.txt")).then(|| {
                        sub.join(sub_files.iter().find(|f| f.eq_ignore_ascii_case("readme.txt")).expect("found"))
                    });
                    // The first file with a Plugin Name header is the plugin, as get_plugins() keeps one per folder.
                    let main = sub_files
                        .iter()
                        .filter(|f| f.ends_with(".php"))
                        .filter_map(|f| head(&sub.join(f)).map(|t| (f, t)))
                        .find(|(_, t)| header(t, "Plugin Name").is_some());
                    let Some((_, text)) = main else { continue };
                    match plugin_version(&text, readme.as_deref()) {
                        Some(v) => items.push(item(Type::Plugin, &slug, v, sub.clone(), site())),
                        None => unread.push((sub.clone(), "no Version header or Stable tag".into())),
                    }
                }
            }
            "themes" => {
                for (sub, sub_files) in children.get(dir.as_path()).into_iter().flatten().map(|d| (&d.0, &d.1)) {
                    if !sub_files.iter().any(|f| f == "style.css") {
                        continue;
                    }
                    let Some(text) = head(&sub.join("style.css")) else { continue };
                    if header(&text, "Theme Name").is_none() {
                        continue;
                    }
                    let slug = sub.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
                    match header(&text, "Version").filter(|v| plausible(v)) {
                        Some(v) => items.push(item(Type::Theme, &slug, v, sub.clone(), site())),
                        None => unread.push((sub.join("style.css"), "no Version header".into())),
                    }
                }
            }
            _ => {}
        }
        if files.iter().any(|f| f == "composer.lock") {
            let lock = dir.join("composer.lock");
            match composer_items(&lock) {
                Ok(found) => items.extend(found),
                Err(e) => unread.push((lock, e)),
            }
        }
    }
    // What a lock installs below its own directory is the lock's.
    let locked: Vec<(Type, String, String, PathBuf)> = items
        .iter()
        .filter(|i| i.composer)
        .map(|i| (i.kind, i.slug.clone(), i.version.clone(), i.site.clone()))
        .collect();
    items.retain(|i| {
        i.composer
            || !locked.iter().any(|(k, s, v, at)| {
                *k == i.kind && *s == i.slug && php_cmp(v, &i.version) == Ordering::Equal && i.location.starts_with(at)
            })
    });
    items.sort_by(|a, b| (&a.site, a.kind, &a.slug, &a.location).cmp(&(&b.site, b.kind, &b.slug, &b.location)));
    (items, unread)
}

fn item(kind: Type, slug: &str, version: String, location: PathBuf, site: PathBuf) -> Item {
    Item { kind, slug: slug.to_string(), version, location, site, composer: false }
}

/// `version.php` is short; read it whole (capped).
fn head_all(path: &Path) -> Option<String> {
    crate::utils::files::read_capped(path, 1 << 20).ok()
}

/// Composer's names for WordPress core.
const CORE_PACKAGES: &[&str] =
    &["roots/wordpress", "roots/wordpress-no-content", "johnpbloch/wordpress", "johnpbloch/wordpress-core"];

/// The WordPress software a `composer.lock` installs.
pub fn composer_items(lock: &Path) -> std::result::Result<Vec<Item>, String> {
    let text = crate::utils::files::read_capped(lock, crate::checks::lockfiles::MAX_FILE).map_err(|e| e.to_string())?;
    let packages = composer::parse(&text).map_err(|e| e.to_string())?;
    let site = lock.parent().unwrap_or(lock).to_path_buf();
    Ok(packages
        .into_iter()
        .filter_map(|p| {
            let version = p.version.strip_prefix(['v', 'V']).unwrap_or(&p.version).to_string();
            let (kind, slug) = if let Some(s) = p.name.strip_prefix("wpackagist-plugin/") {
                (Type::Plugin, s.to_string())
            } else if let Some(s) = p.name.strip_prefix("wpackagist-theme/") {
                (Type::Theme, s.to_string())
            } else if CORE_PACKAGES.contains(&p.name.as_str()) {
                (Type::Core, "wordpress".to_string())
            } else {
                return None;
            };
            Some(Item {
                kind,
                slug: slug.to_ascii_lowercase(),
                version,
                location: lock.to_path_buf(),
                site: site.clone(),
                composer: true,
            })
        })
        .collect())
}

// Judging -------------------------------------------------------------------

/// How to update `it` to `safe`, or past it: wp-cli for a site's own
/// copy, Composer for a locked one.
pub fn fix(it: &Item, safe: &str) -> String {
    let site = quote(&command_path(&it.site));
    let at_least = if safe.is_empty() { String::new() } else { format!(":^{safe}") };
    match (it.composer, it.kind) {
        (true, Type::Core) => {
            let lock = std::fs::read_to_string(&it.location).unwrap_or_default();
            let name = CORE_PACKAGES.iter().find(|p| lock.contains(&format!("\"{p}\""))).unwrap_or(&"roots/wordpress");
            format!("cd {site} && composer require {}", quote(&format!("{name}{at_least}")))
        }
        (true, k) => {
            format!(
                "cd {site} && composer require {}",
                quote(&format!("wpackagist-{}/{}{at_least}", k.as_str(), it.slug))
            )
        }
        (false, Type::Core) => format!("wp core update --path={site}"),
        (false, k) => format!("wp {} update {} --path={site}", k.as_str(), quote(&it.slug)),
    }
}

/// The findings for `it` from its records.
pub fn judge(it: &Item, vulns: &[Vuln], kev: &std::collections::HashSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    for v in vulns {
        let Some(r) = v.ranges.iter().find(|r| in_range(&it.version, r)) else { continue };
        let safe = crate::checks::ecosystems::versions::pick_safe_by(&it.version, &v.patched, php_cmp)
            .filter(|s| crate::checks::ecosystems::versions::is_safe_token(s))
            .unwrap_or_default();
        let what = match it.kind {
            Type::Core => "WordPress".to_string(),
            k => format!("{} {}", k.as_str(), it.slug),
        };
        let fix_cmd = if safe.is_empty() {
            let advice = if v.remediation.is_empty() {
                "No patched version yet".to_string()
            } else {
                v.remediation.chars().take(200).collect()
            };
            format!("{advice} ({what}; {})", v.url())
        } else {
            fix(it, &safe)
        };
        let score =
            v.score.map(|s| (s, v.vector.split('/').next().and_then(|p| p.strip_prefix("CVSS:")).unwrap_or("3.x")));
        let severity = match cvss::word(&v.rating) {
            "" => score.map(|(s, _)| cvss::label(s).to_string()).unwrap_or_default(),
            w => w.to_string(),
        };
        let id = if v.cve.is_empty() { v.id.clone() } else { v.cve.clone() };
        out.push(Finding {
            kind: KIND.into(),
            component: it.slug.clone(),
            version: it.version.clone(),
            location: command_path(&it.location),
            kev: kev.contains(&id),
            status: if safe.is_empty() { "warn" } else { "fail" }.into(),
            fixed: safe,
            severity,
            note: format!("{} (Wordfence: {})", v.title, v.url()),
            fix_cmd,
            affected_range: range_text(r),
            cvss: score.map(|(s, _)| s),
            cvss_version: score.map(|(_, ver)| ver.to_string()).unwrap_or_default(),
            vuln_id: id,
            ..Default::default()
        });
    }
    // One finding per advisory: two records can share a CVE.
    let mut seen = std::collections::HashSet::new();
    out.retain(|f| seen.insert(f.vuln_id.clone()));
    out
}

// The check -----------------------------------------------------------------

/// Every repo's WordPress software against Wordfence Intelligence, with
/// the user's key (`WORDFENCE_API_KEY`).
pub fn wordpress(scan: &mut Scan, repos: &[Repo]) -> crate::error::Result<()> {
    wordpress_with(scan, repos, wordfence::key())
}

/// [`wordpress`] with the key given (None: not set).
pub fn wordpress_with(scan: &mut Scan, repos: &[Repo], key: Option<String>) -> crate::error::Result<()> {
    let mut items = Vec::new();
    for (name, root) in repos {
        scan.status(&format!("Finding WordPress sites in {name}"));
        let (found, unread) = inventory(root);
        items.extend(found);
        for (file, why) in unread {
            scan.unchecked(&format!("WordPress version in {}", short(&command_path(&file))), why.as_str());
        }
    }
    if items.is_empty() {
        return Ok(());
    }
    scan.count(COUNTED, items.len() as i64);
    let Some(key) = key else {
        let mut sites: BTreeMap<&Path, usize> = BTreeMap::new();
        for it in &items {
            *sites.entry(it.site.as_path()).or_default() += 1;
        }
        for (site, n) in sites {
            scan.unchecked(
                &format!("WordPress core, plugins and themes in {} ({n})", short(&command_path(site))),
                wordfence::GET_A_KEY,
            );
        }
        return Ok(());
    };
    scan.status("Fetching Wordfence Intelligence's WordPress vulnerabilities");
    let held = wordfence::refresh(&scan.cache, scan.net, &key, scan.opts.offline);
    if scan.guard("WordPress core, plugins and themes against Wordfence Intelligence", held, 0)? == 0 {
        return Ok(());
    }
    for it in &items {
        let vulns = wordfence::for_software(&scan.cache, it.kind.as_str(), &it.slug)?;
        for f in judge(it, &vulns, &scan.kev) {
            if f.status == "warn" {
                scan.unfixed += 1;
            }
            scan.add(f);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "wordpress_tests.rs"]
mod tests;
