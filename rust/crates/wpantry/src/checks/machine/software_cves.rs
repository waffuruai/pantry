//! Installed software against the CVE records its publishers filed
//! ([`crate::sources::cve_records`]): desktop, server and industrial
//! software no package ecosystem covers, so OSV has no advisory for it.
//! What is judged is a [`Subject`]: a Windows program (its Publisher and
//! DisplayName), or a catalog tool OSV can't map, named in [`TOOLS`].
//!
//! Matching is deliberately narrow. A record applies only when both its
//! vendor and its product equal the subject's after [`vendor_key`] and
//! [`product_key`] (case, punctuation, a company suffix, a version and an
//! architecture in the name are ignored; nothing is fuzzy). A publisher
//! whose records are filed under another name is in [`VENDOR_ALIASES`].
//! The installed version is then judged by the record's own `versions[]`
//! ([`judge`]), numerically; a record whose versions aren't dotted numbers
//! (`25H2`, `5.x.x`, a URL) can't be judged, and the subject is reported
//! not checked rather than clean.
//!
//! How `versions[]` is read (CVE JSON 5): `version` with `lessThan` or
//! `lessThanOrEqual` is a range (`0` or `*` as its start means from the
//! first release, `*` as its end means every later one); `version` alone
//! is that one version, and `a-b` alone (as Oracle writes MySQL's) the
//! inclusive range from `a` to `b`. An `unaffected` match wins over an
//! `affected` one. Products in [`TRAINS`] are the exception: their vendor
//! lists, per release train, the last affected version alone, so a bare
//! version there means that version or any earlier one of its train.
//!
//! Example: a program `PowerStudio SCADA Wave 24.10.3.0` published by
//! `CIRCUTOR, SA` matches records for vendor `Circutor`, product
//! `PowerStudio SCADA Wave`; one with `version 24.8.0, lessThan 24.11.17.0`
//! fails it, fixed in 24.11.17.0.

use crate::checks::Scan;
use crate::checks::ecosystems::versions::num_cmp;
use crate::component::Component;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::cve_records::{self, Record};
use crate::sources::fetch;
use crate::utils::cvss;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// What the tool check's not-checked lines are called.
pub const TOOLS_WHAT: &str = "tools against CVE records";

/// The not-checked lines a check called `what` reports: the source
/// unreachable with nothing cached, records whose versions can't be
/// compared, and products with more records than are read.
pub fn unreached(what: &str) -> String {
    format!("{what} (unreachable, not cached)")
}

pub fn unjudged(what: &str) -> String {
    format!("{what} (versions not comparable)")
}

pub fn partial(what: &str) -> String {
    format!("{what} (too many records, read in part)")
}

/// Catalog tools whose advisories are CVE records rather than OSV
/// entries: (catalog name, vendor, product) as the records name them.
/// OpenJDK builds are matched to Oracle Java SE: the same code, and
/// Oracle's records are the CVEs for it.
pub const TOOLS: &[(&str, &str, &str)] =
    &[("java", "Oracle Corporation", "Oracle Java SE"), ("mysql", "Oracle Corporation", "MySQL Server")];

/// Products whose records list the last affected version of each release
/// train alone (by [`vendor_key`], [`product_key`]): Oracle's Java SE
/// (`8u511b33-perf`, `17.0.21.0.3`, `21.0.13.0.3`).
pub const TRAINS: &[(&str, &str)] = &[("oracle", "java se")];

/// What is judged: an installed program or tool, as its findings name it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Subject {
    /// The finding's kind: `app` for a program, the tool's kind otherwise.
    pub kind: String,
    pub name: String,
    pub version: String,
    pub location: String,
    /// The vendor names to ask the index for ([`vendors_for`]).
    pub vendors: Vec<String>,
    /// The product to match, when it isn't the name ("Oracle Java SE" for
    /// `java`).
    pub product: Option<String>,
}

impl Subject {
    fn product_name(&self) -> &str {
        self.product.as_deref().unwrap_or(&self.name)
    }
}

/// Publishers whose records are filed under another vendor name, by
/// [`vendor_key`]: the vendor names to ask for instead. Explicit, short and
/// reviewed; a publisher not here is asked for under its own name.
///
/// TODO: grow from real misses (reported as issues), never by fuzzy matching.
pub const VENDOR_ALIASES: &[(&str, &[&str])] = &[
    ("adobe systems", &["adobe"]),
    ("broadcom", &["vmware", "broadcom"]),
    ("circutor", &["circutor"]),
    ("vmware", &["vmware"]),
];

/// Words a company name ends with that a CVE record's vendor usually drops.
const COMPANY_SUFFIXES: &[&str] = &[
    "inc",
    "incorporated",
    "corp",
    "corporation",
    "co",
    "company",
    "ltd",
    "limited",
    "llc",
    "gmbh",
    "sa",
    "ag",
    "bv",
    "nv",
    "plc",
    "srl",
    "sl",
    "spa",
    "sas",
    "sarl",
    "pty",
    "oy",
    "ab",
    "kk",
];

/// Words in a program's name that say how it was built, not what it is.
const BUILD_WORDS: &[&str] = &["x64", "x86", "amd64", "arm64", "win64", "win32", "64bit", "32bit"];

/// Lower case, letters and digits (and `+`, `#`) in words, everything else
/// a space.
fn words(s: &str) -> Vec<String> {
    let mapped: String = s
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '+' || c == '#' { c.to_ascii_lowercase() } else { ' ' })
        .collect();
    mapped.split_whitespace().map(str::to_string).collect()
}

/// A publisher or a record's vendor, compared: its words, a company
/// suffix (and a one-letter word, as in "S.A.") dropped from the end.
/// `CIRCUTOR, SA` and `Circutor` are both `circutor`.
pub fn vendor_key(vendor: &str) -> String {
    let mut w = words(vendor);
    while w.len() > 1 && w.last().is_some_and(|l| l.len() == 1 || COMPANY_SUFFIXES.contains(&l.as_str())) {
        w.pop();
    }
    w.join(" ")
}

/// The vendor names to ask the index for, for a publisher: its alias's,
/// or its [`vendor_key`]; and its whole name in words, since the index
/// keeps a record's vendor as written (`oracle corporation`).
pub fn vendors_for(publisher: &str) -> Vec<String> {
    let key = vendor_key(publisher);
    if key.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = match VENDOR_ALIASES.iter().find(|(k, _)| *k == key) {
        Some((_, names)) => names.iter().map(|n| n.to_string()).collect(),
        None => vec![key],
    };
    let whole = words(publisher).join(" ");
    if !out.contains(&whole) {
        out.push(whole);
    }
    out
}

/// Whether a word of a name is a version: starts with a digit (or `v` and
/// a digit) and has a dot in it, or is the program's own version.
fn is_version_word(w: &str, version: &str) -> bool {
    let w = w.trim_matches(|c: char| "()[],".contains(c));
    let digits = w.strip_prefix(['v', 'V']).unwrap_or(w);
    (!version.is_empty() && w == version) || (digits.starts_with(|c: char| c.is_ascii_digit()) && digits.contains('.'))
}

/// A program's name or a record's product, compared: its words without a
/// version, a build word (`x64`, `64-bit`) and the vendor's words in front.
/// `PowerStudio SCADA Wave 24.11.17.0 (x64)` by Circutor is
/// `powerstudio scada wave`.
pub fn product_key(name: &str, vendor: &str, version: &str) -> String {
    let kept: Vec<&str> = name.split_whitespace().filter(|w| !is_version_word(w, version)).collect();
    let mut w = words(&kept.join(" "));
    let mut i = 0;
    while i < w.len() {
        let pair = w.get(i + 1).is_some_and(|n| n == "bit") && (w[i] == "64" || w[i] == "32");
        if pair {
            w.drain(i..i + 2);
        } else if BUILD_WORDS.contains(&w[i].as_str()) {
            w.remove(i);
        } else {
            i += 1;
        }
    }
    let v = words(vendor);
    if !v.is_empty() && w.len() > v.len() && w[..v.len()] == v[..] {
        w.drain(..v.len());
    }
    w.join(" ")
}

/// A dotted number (`24.11.17.0`, `v2.4`) as its parts; None for anything
/// else. A trailing `.x` (`17.x`) is dropped when `wild` allows it.
fn dotted(v: &str, wild: bool) -> Option<Vec<String>> {
    let mut v = v.trim();
    v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    if wild {
        while let Some(rest) = v.strip_suffix(".x").or_else(|| v.strip_suffix(".X")).or_else(|| v.strip_suffix(".*")) {
            v = rest;
        }
    }
    let parts: Vec<String> = v.split('.').map(str::to_string).collect();
    (!v.is_empty() && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))).then_some(parts)
}

/// Two dotted numbers compared part by part, a missing part 0.
fn cmp_parts(a: &[String], b: &[String]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).map(String::as_str).unwrap_or("0");
        let y = b.get(i).map(String::as_str).unwrap_or("0");
        match num_cmp(x, y) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    Ordering::Equal
}

/// What one `affected[]` entry says about an installed version.
#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    /// In an affected range: the range as shown, and the first fixed
    /// version when the entry names one ("" otherwise).
    Affected {
        range: String,
        fixed: String,
    },
    Unaffected,
    /// The entry's versions aren't comparable with the installed one.
    Unknown,
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Judge `installed` (dotted) by one `affected[]` entry's `versions[]`:
/// an unaffected match wins over an affected one; with no match, an entry
/// that couldn't be read, or a default of "affected", is Unknown.
pub fn judge(installed: &[String], entry: &Value) -> Verdict {
    let versions = crate::utils::json::arr_at(entry, "versions");
    let mut unknown = s(entry, "defaultStatus") == "affected";
    let mut affected: Option<Verdict> = None;
    for v in versions {
        let status = s(v, "status");
        let start = s(v, "version");
        let (bound, inclusive) = match (s(v, "lessThan"), s(v, "lessThanOrEqual")) {
            ("", "") => ("", false),
            (lt, "") => (lt, false),
            (_, le) => (le, true),
        };
        let span = if bound.is_empty() { inclusive_span(start) } else { None };
        let hit = if let Some((from, to)) = &span {
            // `a-b`: from a to b, both included.
            cmp_parts(installed, from) != Ordering::Less && cmp_parts(installed, to) != Ordering::Greater
        } else if bound.is_empty() {
            // One version.
            match dotted(start, false) {
                Some(p) => cmp_parts(installed, &p) == Ordering::Equal,
                None => {
                    unknown = true;
                    continue;
                }
            }
        } else {
            let from = if matches!(start, "" | "0" | "*") { Some(Vec::new()) } else { dotted(start, true) };
            let to = if bound == "*" { Some(Vec::new()) } else { dotted(bound, false) };
            let (Some(from), Some(to)) = (from, to) else {
                unknown = true;
                continue;
            };
            let above = from.is_empty() || cmp_parts(installed, &from) != Ordering::Less;
            let below = to.is_empty()
                || match cmp_parts(installed, &to) {
                    Ordering::Less => true,
                    Ordering::Equal => inclusive,
                    Ordering::Greater => false,
                };
            above && below
        };
        if !hit {
            continue;
        }
        match status {
            "unaffected" => return Verdict::Unaffected,
            "affected" if affected.is_none() => {
                let lower = if matches!(start, "" | "0" | "*") { String::new() } else { format!(">={start}, ") };
                let range = match (bound, inclusive) {
                    ("", _) if span.is_some() => {
                        let (a, b) = start.split_once('-').unwrap_or_default();
                        format!(">={a}, <={b}")
                    }
                    ("", _) => format!("={start}"),
                    ("*", _) => format!(">={start}"),
                    (b, true) => format!("{lower}<={b}"),
                    (b, false) => format!("{lower}<{b}"),
                };
                let fixed = match (bound, inclusive) {
                    ("" | "*", _) => String::new(),
                    (b, false) => b.to_string(),
                    // Past an inclusive bound: the entry's first unaffected
                    // version above it, when it names one.
                    (b, true) => first_unaffected_above(versions, b),
                };
                affected = Some(Verdict::Affected { range, fixed });
            }
            _ => {}
        }
    }
    match affected {
        Some(a) => a,
        None if unknown => Verdict::Unknown,
        None => Verdict::Unaffected,
    }
}

/// `a-b` with both ends dotted numbers, as its two ends.
fn inclusive_span(v: &str) -> Option<(Vec<String>, Vec<String>)> {
    let (a, b) = v.split_once('-')?;
    let (a, b) = (dotted(a, false)?, dotted(b, false)?);
    (cmp_parts(&a, &b) != Ordering::Greater).then_some((a, b))
}

/// A Java version as its train and parts: `17.0.21.0.3` is train 17;
/// `8u511b33-perf` (Oracle's records) and `1.8.0_511` (what `java
/// -version` reports for Java 8, a build suffix such as `-b08` ignored) are
/// train 8, update 511 (`8.0.511`). None for a Java 8 without its update
/// (`1.8.0`): it can't be placed in its train. None for anything else.
pub fn java_parts(v: &str) -> Option<Vec<String>> {
    let v = v.trim();
    let eight = |update: &str| {
        let digits: String = update.chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty()).then(|| vec!["8".to_string(), "0".to_string(), digits])
    };
    if let Some(update) = v.strip_prefix("8u") {
        return eight(update);
    }
    if let Some(rest) = v.strip_prefix("1.8.0") {
        return rest.strip_prefix('_').and_then(eight);
    }
    dotted(v, false).filter(|p| p[0] != "1")
}

/// [`judge`] for a product in [`TRAINS`]: each bare `affected` version is
/// the last affected one of its train (its first number).
pub fn judge_trains(installed: &[String], entry: &Value) -> Verdict {
    for v in crate::utils::json::arr_at(entry, "versions") {
        if s(v, "status") != "affected" {
            continue;
        }
        let Some(last) = java_parts(s(v, "version")) else { continue };
        if last[0] != installed[0] {
            continue;
        }
        return if cmp_parts(installed, &last) == Ordering::Greater {
            Verdict::Unaffected
        } else {
            Verdict::Affected { range: format!("<={} (the {} train)", s(v, "version"), last[0]), fixed: String::new() }
        };
    }
    // A train the record doesn't list (or lists in a form not read): it
    // may be out of public support rather than fixed; it can't be judged.
    Verdict::Unknown
}

fn first_unaffected_above(versions: &[Value], bound: &str) -> String {
    let Some(b) = dotted(bound, false) else { return String::new() };
    versions
        .iter()
        .filter(|v| s(v, "status") == "unaffected" && s(v, "lessThan").is_empty() && s(v, "lessThanOrEqual").is_empty())
        .filter_map(|v| dotted(s(v, "version"), false).map(|p| (p, s(v, "version"))))
        .filter(|(p, _)| cmp_parts(p, &b) == Ordering::Greater)
        .min_by(|a, b| cmp_parts(&a.0, &b.0))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default()
}

/// What the records say about one subject, asked for under `vendor`: its
/// findings, and whether any record for it couldn't be judged.
pub fn assess(x: &Subject, vendor: &str, records: &[Record], kev: &dyn Fn(&str) -> bool) -> (Vec<Finding>, bool) {
    let vkey = vendor_key(vendor);
    let pkey = product_key(x.product_name(), &vkey, &x.version);
    let trains = TRAINS.contains(&(vkey.as_str(), pkey.as_str()));
    let installed = if trains { java_parts(&x.version) } else { dotted(&x.version, false) };
    let Some(installed) = installed else {
        // Records exist for it, but its version can't be compared.
        return (Vec::new(), !records.is_empty());
    };
    let mut out: Vec<Finding> = Vec::new();
    let mut unjudged = false;
    let mut seen = BTreeSet::new();
    for r in records {
        let entries: Vec<&Value> = r
            .affected
            .iter()
            .filter(|a| vendor_key(s(a, "vendor")) == vkey && product_key(s(a, "product"), &vkey, "") == pkey)
            .collect();
        let verdicts: Vec<Verdict> =
            entries.iter().map(|e| if trains { judge_trains(&installed, e) } else { judge(&installed, e) }).collect();
        let Some(Verdict::Affected { range, fixed }) = verdicts.iter().find(|v| matches!(v, Verdict::Affected { .. }))
        else {
            unjudged |= verdicts.contains(&Verdict::Unknown);
            continue;
        };
        if !seen.insert(r.id.clone()) {
            continue;
        }
        let shown = entries.first().map(|e| (s(e, "vendor"), s(e, "product"))).unwrap_or_default();
        let severity = r.score.as_ref().map(|(v, _)| cvss::label(*v).to_string()).unwrap_or_default();
        let fix_cmd = if fixed.is_empty() {
            format!(
                "No fixed version named in the CVE record: check {}'s advisory and update {} from its vendor",
                shown.0, x.name
            )
        } else {
            format!("Update {} to {fixed} or later from its vendor", x.name)
        };
        out.push(Finding {
            kind: x.kind.clone(),
            component: x.name.clone(),
            version: x.version.clone(),
            location: x.location.clone(),
            vuln_id: r.id.clone(),
            status: if fixed.is_empty() { "warn" } else { "fail" }.into(),
            fixed: fixed.clone(),
            kev: kev(&r.id),
            severity,
            note: format!("{} (CVE record for vendor {:?}, product {:?})", r.title, shown.0, shown.1),
            fix_cmd,
            affected_range: range.clone(),
            cvss: r.score.as_ref().map(|(v, _)| *v),
            cvss_version: r.score.as_ref().map(|(_, v)| v.clone()).unwrap_or_default(),
            ..Default::default()
        });
    }
    (out, unjudged)
}

/// The index's product names of `vendor` that are the subject's product.
pub fn matching_products(x: &Subject, vendor: &str, products: &[String]) -> Vec<String> {
    let vkey = vendor_key(vendor);
    let pkey = product_key(x.product_name(), &vkey, &x.version);
    if pkey.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = products.iter().filter(|q| product_key(q, &vkey, "") == pkey).cloned().collect();
    out.sort();
    out.dedup();
    out
}

/// The catalog tools found that [`TOOLS`] names, as subjects.
pub fn tool_subjects(found: &[Component]) -> Vec<Subject> {
    found
        .iter()
        .filter_map(|c| {
            let (_, vendor, product) = TOOLS.iter().find(|(name, _, _)| *name == c.name)?;
            Some(Subject {
                kind: c.kind.clone(),
                name: c.name.clone(),
                version: c.version.clone(),
                location: c.path.clone(),
                vendors: vendors_for(vendor),
                product: Some(product.to_string()),
            })
        })
        .collect()
}

/// The catalog tools [`TOOLS`] names, against CVE records.
pub fn tools(scan: &mut Scan, found: &[Component]) -> Result<()> {
    check(scan, &tool_subjects(found), TOOLS_WHAT)
}

/// The check over `subjects`: every record that applies is a finding;
/// what couldn't be asked or judged is a not-checked line, named after
/// `what`.
pub fn check(scan: &mut Scan, subjects: &[Subject], what: &str) -> Result<()> {
    if subjects.is_empty() {
        return Ok(());
    }
    if let Err(e) = fetch::on(cve_records::ID) {
        scan.unchecked(what, &e.to_string());
        return Ok(());
    }
    let programs = subjects;
    let offline = scan.opts.offline;
    let mut vendors: Vec<String> = programs.iter().flat_map(|p| p.vendors.clone()).collect();
    vendors.sort();
    vendors.dedup();
    scan.status(&format!("Asking CVE records about {} software vendors", vendors.len()));
    cve_records::prefetch_products(&scan.cache, scan.net, &vendors, offline)?;
    // Each program's (vendor, product) pairs the index knows.
    let mut unreached_names: BTreeSet<String> = BTreeSet::new();
    let mut wanted: Vec<(usize, String, String)> = Vec::new();
    for (i, p) in programs.iter().enumerate() {
        for v in p.vendors.clone() {
            match cve_records::products(&scan.cache, &v)? {
                None => {
                    unreached_names.insert(p.name.clone());
                }
                Some(products) => {
                    for q in matching_products(p, &v, &products) {
                        wanted.push((i, v.clone(), q));
                    }
                }
            }
        }
    }
    let mut pairs: Vec<(String, String)> = wanted.iter().map(|(_, v, q)| (v.clone(), q.clone())).collect();
    pairs.sort();
    pairs.dedup();
    if !pairs.is_empty() {
        scan.status(&format!("Fetching CVE records for {} installed products", pairs.len()));
    }
    cve_records::prefetch_records(&scan.cache, scan.net, &pairs, offline)?;
    let mut unjudged_names: BTreeSet<String> = BTreeSet::new();
    let mut partial_names: BTreeSet<String> = BTreeSet::new();
    let kev = scan.kev.clone();
    let mut found: Vec<Finding> = Vec::new();
    for (i, p) in programs.iter().enumerate() {
        // Records by the vendor they were asked under: each judged with its own vendor's name.
        let mut by_vendor: Vec<(String, Vec<Record>)> = Vec::new();
        for (_, v, q) in wanted.iter().filter(|(j, _, _)| *j == i) {
            let Some(r) = cve_records::records(&scan.cache, v, q)? else {
                unreached_names.insert(p.name.clone());
                continue;
            };
            if !r.complete {
                partial_names.insert(p.name.clone());
            }
            match by_vendor.iter_mut().find(|(w, _)| w == v) {
                Some((_, recs)) => recs.extend(r.records),
                None => by_vendor.push((v.clone(), r.records)),
            }
        }
        for (vendor, recs) in by_vendor.iter().filter(|(_, r)| !r.is_empty()) {
            let (findings, unknown) = assess(p, vendor, recs, &|id| kev.contains(id));
            if unknown {
                unjudged_names.insert(p.name.clone());
            }
            for f in findings {
                if !found.iter().any(|g| g.component == f.component && g.version == f.version && g.vuln_id == f.vuln_id)
                {
                    found.push(f);
                }
            }
        }
    }
    for f in found {
        scan.add(f);
    }
    for (set, label) in
        [(&unreached_names, unreached(what)), (&unjudged_names, unjudged(what)), (&partial_names, partial(what))]
    {
        if !set.is_empty() {
            let shown: Vec<&str> = set.iter().take(4).map(String::as_str).collect();
            let more = if set.len() > 4 { format!(" and {} more", set.len() - 4) } else { String::new() };
            scan.unchecked(&label, &format!("{}{more}", shown.join(", ")));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "software_cves_tests.rs"]
mod tests;
