//! Installed software against the CVE records its publishers filed
//! ([`crate::sources::cve_records`]): desktop, server and industrial
//! software no package ecosystem covers, so OSV has no advisory for it.
//! What is judged is a [`Subject`]: a Windows program named in
//! [`crate::checks::machine::programs::PROGRAMS`] (by its Publisher and
//! DisplayName), or a catalog tool OSV can't map, named in [`TOOLS`] (PHP
//! and Rust only when OSV answered no CVE for them, [`OSV_FIRST`]).
//!
//! Matching is deliberately narrow. A record applies only when both its
//! vendor and its product equal the subject's after [`vendor_key`] and
//! [`product_key`] (case, punctuation, a company suffix, a version and an
//! architecture in the name are ignored; nothing is fuzzy). A publisher
//! whose records are filed under another name is in [`VENDOR_ALIASES`].
//! The installed version is then judged by the record's own `versions[]`
//! ([`judge`]), numerically; a record whose versions aren't dotted numbers
//! (`25H2`, `5.x.x`, a URL), or whose numbers follow another scheme than
//! the installed version ([`same_scheme`]: a build number against release
//! numbers), can't be judged, and the subject is reported not checked
//! rather than clean or failed.
//!
//! How `versions[]` is read (CVE JSON 5): `version` with `lessThan` or
//! `lessThanOrEqual` is a range (`0` or `*` as its start means from the
//! first release, `*` as its end means every later one); `version` alone
//! is that one version, and `a-b` alone (as Oracle writes MySQL's) the
//! inclusive range from `a` to `b`. A `version` alone may also be spelled
//! out ([`spelled`]): comparisons (`< 1.77.2`, `>= 1.60.0, < 1.72`) or a
//! train with its fix in words (`7.2.x below 7.2.30`, `5.6.x before 5.6.1`).
//! An `unaffected` match wins over an `affected` one. A record whose
//! `defaultStatus` is `affected` leaves every version it doesn't list
//! affected, so a miss there is unknown, unless the installed version's own
//! train is listed and it is at or past that train's fix ([`train_of`]), or
//! its train is newer than every train the record lists and was first
//! released after the record was published ([`unlisted_later_train`]): the
//! record couldn't have meant it.
//! Products in [`TRAINS`] are the exception: their vendor lists, per
//! release train, the last affected version alone, so a bare version there
//! means that version or any earlier one of its train.
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
use crate::sources::osv::Item;
use crate::utils::cvss;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

/// What the tool check's not-checked lines are called.
pub const TOOLS_WHAT: &str = "tools against CVE records";

/// The not-checked lines a check called `what` reports: the source
/// unreachable with nothing cached, records whose versions can't be
/// compared, and products with more records than are read.
pub fn unreached(what: &str) -> String {
    format!("{what} (unreachable, not cached)")
}

pub fn unjudged_label(what: &str) -> String {
    format!("{what} (versions not comparable)")
}

pub fn partial(what: &str) -> String {
    format!("{what} (too many records, read in part)")
}

/// Catalog tools whose advisories are CVE records rather than OSV
/// entries: (catalog name, vendor, product) as the records name them, one
/// row per spelling the records use. OpenJDK builds are matched to Oracle
/// Java SE: the same code, and Oracle's records are the CVEs for it.
///
/// PHP's records are filed as `PHP Group` / `PHP` (most), `PHP` / `PHP`
/// (CVE-2019-11043) and `php` / `php` (CVE-2026-14355); the last two compare
/// the same. Rust's as `rust-lang` / `rust` (CVE-2024-24576) and, for the
/// standard library that ships with each `rustc`, `Rust Project` / `std`
/// (CVE-2025-11233).
///
/// TODO: `The Rust Programming Language` / `Standard Library` has one record
/// (CVE-2019-1010299, fixed in 1.30.0) whose version is free text; mapped,
/// it would leave every Rust "not checked", so it is left out.
pub const TOOLS: &[(&str, &str, &str)] = &[
    ("java", "Oracle Corporation", "Oracle Java SE"),
    ("mysql", "Oracle Corporation", "MySQL Server"),
    ("php", "PHP Group", "PHP"),
    ("php", "PHP", "PHP"),
    ("rust", "rust-lang", "rust"),
    ("rust", "Rust Project", "std"),
];

/// Catalog tools in [`TOOLS`] that keep an OSV mapping (php-src's and
/// rust-lang/rust's release tags) which often answers nothing for versions
/// their CVE records name. OSV goes first; when its answer for the
/// installed version names no CVE (or OSV couldn't be asked), the CVE
/// records decide, so an empty answer is never read as clean. An answer
/// with no CVE isn't coverage: for PHP 8.1 and 8.2 it is often one
/// OSS-Fuzz crash record (`OSV-2021-1199`) and none of PHP's CVEs.
pub const OSV_FIRST: &[&str] = &["php", "rust"];

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
    /// When the installed version's release train was first released
    /// (endoflife.date's `releaseDate` for its cycle), when known.
    pub released: Option<String>,
    /// When support for that train ends or ended
    /// ([`crate::sources::endoflife::support_end`]), when known.
    pub support_end: Option<String>,
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
    // The index keeps the hyphen: `browse/rust-lang`.
    ("rust lang", &["rust-lang"]),
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
pub(crate) fn dotted(v: &str, wild: bool) -> Option<Vec<String>> {
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
pub(crate) fn cmp_parts(a: &[String], b: &[String]) -> Ordering {
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
    let versions: Vec<Value> = crate::utils::json::arr_at(entry, "versions")
        .iter()
        .flat_map(|v| spelled(v).unwrap_or_else(|| vec![v.clone()]))
        .collect();
    let versions = versions.as_slice();
    let default_affected = s(entry, "defaultStatus") == "affected";
    // A version entry that couldn't be read; the installed version's train
    // listed with a fix it is at or past.
    let mut unknown = false;
    let mut fixed_in_train = false;
    let mut affected: Option<Verdict> = None;
    for v in versions {
        let status = s(v, "status");
        let raw = s(v, "version");
        // `8.0.30 and prior` (also `and earlier`), as Oracle writes some
        // MySQL entries: everything up to that version, included.
        let prior = [" and prior", " and earlier"].iter().find_map(|w| raw.strip_suffix(w)).map(str::trim);
        let start = if prior.is_some() { "" } else { raw };
        let (bound, inclusive) = match (prior, s(v, "lessThan"), s(v, "lessThanOrEqual")) {
            (Some(top), "", "") => (top, true),
            (_, "", "") => ("", false),
            (_, lt, "") => (lt, false),
            (_, _, le) => (le, true),
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
            if !below
                && status == "affected"
                && let Some(train) = train_of(start, bound)
            {
                let head: Vec<String> =
                    (0..train.len()).map(|i| installed.get(i).cloned().unwrap_or_else(|| "0".into())).collect();
                fixed_in_train |= cmp_parts(&head, &train) == Ordering::Equal;
            }
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
        None if unknown || (default_affected && !fixed_in_train) => Verdict::Unknown,
        None => Verdict::Unaffected,
    }
}

/// The release train a range covers, when it covers one: a wildcard start
/// (`8.3.*`, `7.4.X`) names it, or a start and fix that differ only in
/// their last part (`8.4.0` to `8.4.23` is the 8.4 train). None otherwise
/// (`1.87.0` to `1.89.0` spans trains).
pub fn train_of(start: &str, bound: &str) -> Option<Vec<String>> {
    if dotted(start, false).is_none() {
        return dotted(start, true);
    }
    let (a, b) = (dotted(start, false)?, dotted(bound, false)?);
    let n = a.len();
    (n >= 2 && b.len() == n && a[..n - 1] == b[..n - 1]).then(|| a[..n - 1].to_vec())
}

/// A `version` given alone in words or comparisons, as the `version` plus
/// `lessThan` / `lessThanOrEqual` entries it stands for; None for any other
/// `version` (one version, `a-b`, something unread). Each shape is from
/// real records:
///
/// - comparisons, as GitHub's records write them: `< 1.77.2`
///   (CVE-2024-24576), `>= 1.60.0, < 1.72` (CVE-2023-40030), `<= 3.0`,
///   `>= 5.0`;
/// - a train and its fix in words, as PHP's older records do: `7.1.x <
///   7.1.30` (CVE-2019-11038), `7.2.x below 7.2.30` and `7.3.x below 7.3.17
///   and 7.4.x below 7.4.5` (CVE-2020-7067), `5.6.x before 5.6.1`
///   (CVE-2014-3622).
///
/// Example: `{"status": "affected", "version": "< 1.77.2"}` reads as
/// `{"status": "affected", "version": "0", "lessThan": "1.77.2"}`.
pub fn spelled(v: &Value) -> Option<Vec<Value>> {
    if !s(v, "lessThan").is_empty() || !s(v, "lessThanOrEqual").is_empty() {
        return None;
    }
    let status = s(v, "status");
    s(v, "version").split(" and ").map(|c| spelled_clause(c.trim(), status)).collect()
}

fn spelled_clause(c: &str, status: &str) -> Option<Value> {
    if c.starts_with(['<', '>']) {
        let (mut from, mut to): (Option<&str>, Option<(&str, bool)>) = (None, None);
        for part in c.split(',').map(str::trim) {
            let (op, ver) = [">=", "<=", "<"].iter().find_map(|op| part.strip_prefix(op).map(|r| (*op, r.trim())))?;
            dotted(ver, false)?;
            match op {
                ">=" if from.is_none() => from = Some(ver),
                "<" | "<=" if to.is_none() => to = Some((ver, op == "<=")),
                _ => return None,
            }
        }
        let mut item = serde_json::json!({"status": status, "version": from.unwrap_or("0")});
        match to {
            Some((bound, true)) => item["lessThanOrEqual"] = bound.into(),
            Some((bound, false)) => item["lessThan"] = bound.into(),
            None => item["lessThan"] = "*".into(),
        }
        return Some(item);
    }
    let (train, bound) = [" below ", " before ", " < "].iter().find_map(|sep| c.split_once(sep))?;
    let (train, bound) = (train.trim(), bound.trim());
    // The start must be a train (`7.2.x`), the fix a version.
    (dotted(train, false).is_none() && dotted(train, true).is_some() && dotted(bound, false).is_some())
        .then(|| serde_json::json!({"status": status, "version": train, "lessThan": bound}))
}

/// Whether `installed` sits in a train newer than every train `entry`
/// lists, under a default of affected: every `affected` range of the entry
/// names a train ([`train_of`]) below the installed one. Such a version is
/// judged by dates ([`assess`]): the record says nothing about a train
/// released after it was published.
///
/// Example: CVE-2024-4577 lists 8.1.*, 8.2.* and 8.3.* with a default of
/// affected and was published 2024-06-09; PHP 8.4 was first released
/// 2024-11-21, so 8.4.27 is not what it calls affected.
pub fn unlisted_later_train(installed: &[String], entry: &Value) -> bool {
    if s(entry, "defaultStatus") != "affected" {
        return false;
    }
    let versions: Vec<Value> = crate::utils::json::arr_at(entry, "versions")
        .iter()
        .flat_map(|v| spelled(v).unwrap_or_else(|| vec![v.clone()]))
        .collect();
    let mut trains = 0;
    for v in versions.iter().filter(|v| s(v, "status") == "affected") {
        let bound = if s(v, "lessThan").is_empty() { s(v, "lessThanOrEqual") } else { s(v, "lessThan") };
        let Some(train) = train_of(s(v, "version"), bound).filter(|_| !bound.is_empty()) else { return false };
        let head: Vec<String> =
            (0..train.len()).map(|i| installed.get(i).cloned().unwrap_or_else(|| "0".into())).collect();
        if cmp_parts(&head, &train) != Ordering::Greater {
            return false;
        }
        trains += 1;
    }
    trains > 0
}

/// Whether a version's first number is written the way a record's is: both
/// a year (four digits, 1990 to 2100) or neither, and no more than one
/// digit apart in length (`9` and `10` are one scheme, `262` and `9` aren't).
fn same_major(a: &str, b: &str) -> bool {
    let len = |x: &str| x.trim_start_matches('0').len().max(1);
    let year = |x: &str| x.len() == 4 && x.parse::<u32>().is_ok_and(|y| (1990..=2100).contains(&y));
    year(a) == year(b) && len(a).abs_diff(len(b)) <= 1
}

/// Whether `installed` uses the same version scheme as `entry`'s
/// versions: its first number fits ([`same_major`]) the first number of
/// at least one dotted start or bound the entry names (`0` and `*` name
/// none). An entry naming none is taken as fitting; [`judge`] decides it.
///
/// Example: JetBrains' Windows installers write IntelliJ IDEA's build
/// (`262.8665.42`) as its DisplayVersion, while its records name releases
/// (`lessThan 2026.3`). Compared as numbers, 262 is below 2026 and a current
/// IntelliJ would fail; by scheme, it is not comparable.
pub fn same_scheme(installed: &[String], entry: &Value) -> bool {
    let Some(mine) = installed.first() else { return true };
    let mut firsts: Vec<String> = Vec::new();
    for v in
        crate::utils::json::arr_at(entry, "versions").iter().flat_map(|v| spelled(v).unwrap_or_else(|| vec![v.clone()]))
    {
        let raw = s(&v, "version");
        let raw = [" and prior", " and earlier"].iter().find_map(|w| raw.strip_suffix(w)).map_or(raw, str::trim);
        let mut ends: Vec<&str> = match inclusive_span(raw) {
            Some(_) => raw.split('-').collect(),
            None if matches!(raw, "" | "0" | "*") => Vec::new(),
            None => vec![raw],
        };
        ends.extend([s(&v, "lessThan"), s(&v, "lessThanOrEqual")].into_iter().filter(|b| !matches!(*b, "" | "*")));
        firsts.extend(ends.iter().filter_map(|e| dotted(e, true)).filter_map(|p| p.first().cloned()));
    }
    firsts.is_empty() || firsts.iter().any(|f| same_major(mine, f))
}

/// Whether day `a` (`YYYY-MM-DD`) is strictly before day `b`; false when
/// either can't be read.
fn before(a: &str, b: &str) -> bool {
    match (crate::utils::dates::parse_date(a.get(..10).unwrap_or(a)), crate::utils::dates::parse_date(b)) {
        (Some(x), Some(y)) => x < y,
        _ => false,
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
///
/// Oracle also lists its Java SE Performance Pack (`8u511b33-perf`), a
/// separate build; a Java 8 is judged only by the plain 8 entries, and a
/// record naming Java 8 only as Performance Pack doesn't affect it.
pub fn judge_trains(installed: &[String], entry: &Value) -> Verdict {
    let mut perf_only = false;
    for v in crate::utils::json::arr_at(entry, "versions") {
        if s(v, "status") != "affected" {
            continue;
        }
        // Some entries carry the product first: `Oracle Java SE:17.0.13`.
        let raw = s(v, "version");
        let shown =
            raw.rsplit_once(':').filter(|(p, _)| p.chars().any(char::is_alphabetic)).map_or(raw, |(_, b)| b.trim());
        let Some(last) = java_parts(shown) else { continue };
        if last[0] != installed[0] {
            continue;
        }
        if shown.contains("perf") {
            perf_only = true;
            continue;
        }
        return if java_cmp(installed, &last) == Ordering::Greater {
            Verdict::Unaffected
        } else {
            Verdict::Affected { range: format!("<={shown} (the {} train)", last[0]), fixed: String::new() }
        };
    }
    if perf_only {
        return Verdict::Unaffected;
    }
    // A train the record doesn't list (or lists in a form not read): it
    // may be out of public support rather than fixed; it can't be judged.
    Verdict::Unknown
}

/// Two versions of one Java train. Java 8 is compared by quarterly update:
/// OpenJDK numbers each one above Oracle's (OpenJDK 8u412 is Oracle's 8u411,
/// April 2024), so `8u411` as the last affected covers OpenJDK's 8u412 too.
fn java_cmp(a: &[String], b: &[String]) -> Ordering {
    let quarter = |p: &[String]| p.get(2).and_then(|u| u.parse::<u64>().ok()).map(|u| u / 10);
    match (a.first().map(String::as_str), quarter(a), quarter(b)) {
        (Some("8"), Some(x), Some(y)) => x.cmp(&y),
        _ => cmp_parts(a, b),
    }
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
/// findings, and why the records that couldn't be judged couldn't be
/// (None when every one was).
pub fn assess(
    x: &Subject,
    vendor: &str,
    records: &[Record],
    kev: &dyn Fn(&str) -> bool,
) -> (Vec<Finding>, Option<String>) {
    let vkey = vendor_key(vendor);
    let pkey = product_key(x.product_name(), &vkey, &x.version);
    let trains = TRAINS.contains(&(vkey.as_str(), pkey.as_str()));
    let installed = if trains { java_parts(&x.version) } else { dotted(&x.version, false) };
    let Some(installed) = installed else {
        // Records exist for it, but its version can't be compared.
        let why = format!("{:?} can't be read as a version to compare with its records", x.version);
        return (Vec::new(), (!records.is_empty()).then_some(why));
    };
    let mut out: Vec<Finding> = Vec::new();
    // What made records unjudgeable, each with their ids.
    let mut unjudged: Vec<(String, Vec<String>)> = Vec::new();
    let mut seen = BTreeSet::new();
    for r in records {
        let entries: Vec<&Value> = r
            .affected
            .iter()
            .filter(|a| vendor_key(s(a, "vendor")) == vkey && product_key(s(a, "product"), &vkey, "") == pkey)
            .collect();
        // A train released after the record was published, newer than every
        // train it lists: not what the record calls affected.
        let later = |e: &Value| {
            x.released.as_deref().is_some_and(|day| before(&r.published, day)) && unlisted_later_train(&installed, e)
        };
        let verdicts: Vec<(Verdict, String)> = entries
            .iter()
            .map(|e| {
                // Numbered another way than the record (a build number
                // against release numbers): the ranges can't place it.
                if !trains && !same_scheme(&installed, e) {
                    let like = example_bound(e).map(|b| format!(" (like `{b}`)")).unwrap_or_default();
                    return (Verdict::Unknown, format!("number versions another way than {}{like}", x.version));
                }
                if trains {
                    return match judge_trains(&installed, e) {
                        Verdict::Unknown => unlisted_train(x, &installed, e, &r.published),
                        v => (v, String::new()),
                    };
                }
                match judge(&installed, e) {
                    Verdict::Unknown if later(e) => (Verdict::Unaffected, String::new()),
                    Verdict::Unknown => (Verdict::Unknown, unjudged_why(&installed, e)),
                    v => (v, String::new()),
                }
            })
            .collect();
        let Some((Verdict::Affected { range, fixed }, _)) =
            verdicts.iter().find(|(v, _)| matches!(v, Verdict::Affected { .. }))
        else {
            for (_, why) in verdicts.iter().filter(|(v, _)| *v == Verdict::Unknown) {
                match unjudged.iter_mut().find(|(w, _)| w == why) {
                    Some((_, ids)) if ids.contains(&r.id) => {}
                    Some((_, ids)) => ids.push(r.id.clone()),
                    None => unjudged.push((why.clone(), vec![r.id.clone()])),
                }
            }
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
    let why: Vec<String> = unjudged
        .iter()
        .map(|(why, ids)| {
            // The verb agrees with the ids: "CVE-1 names", "CVE-1 and 2 more name".
            let (verb, rest) = why.split_once(' ').unwrap_or((why, ""));
            let verb = if ids.len() == 1 { format!("{verb}s") } else { verb.to_string() };
            let shown = match ids.len() {
                1 => ids[0].clone(),
                2 => format!("{} and {}", ids[0], ids[1]),
                n => format!("{} and {} more", ids[0], n - 1),
            };
            format!("{shown} {verb} {rest}")
        })
        .collect();
    (out, (!why.is_empty()).then(|| why.join("; ")))
}

/// Why [`judge`] couldn't place `installed` by `entry`, as a predicate of
/// the records: a version it couldn't read, or no range for the installed
/// line while versions not listed count as affected.
fn unjudged_why(installed: &[String], entry: &Value) -> String {
    let unreadable = crate::utils::json::arr_at(entry, "versions")
        .iter()
        .flat_map(|v| spelled(v).unwrap_or_else(|| vec![v.clone()]))
        .any(|v| {
            let raw = s(&v, "version");
            let bound = [s(&v, "lessThan"), s(&v, "lessThanOrEqual")].into_iter().find(|b| !b.is_empty());
            let prior = [" and prior", " and earlier"].iter().any(|w| raw.ends_with(w));
            match bound {
                _ if prior => false,
                None => inclusive_span(raw).is_none() && dotted(raw, false).is_none(),
                Some(b) => {
                    (!matches!(raw, "" | "0" | "*") && dotted(raw, true).is_none())
                        || (b != "*" && dotted(b, false).is_none())
                }
            }
        });
    if unreadable {
        return "write some versions in a form Pantry can't read".into();
    }
    let line = installed.iter().take(2).cloned().collect::<Vec<_>>().join(".");
    format!("list no range for the {line} line (versions not listed count as affected)")
}

/// A train a record doesn't list (or lists in a form not read). Oracle
/// lists the supported versions a flaw affects, so a train it supported
/// on the day the record was published and left out isn't affected;
/// otherwise it can't be judged, and the reason says why, as a predicate
/// of the records ("name the 8 and 11 trains but not 26, …").
fn unlisted_train(x: &Subject, installed: &[String], entry: &Value, published: &str) -> (Verdict, String) {
    let mine = &installed[0];
    let listed = listed_trains(entry);
    if listed.contains(mine) {
        return (Verdict::Unknown, format!("list the {mine} train in a form Pantry can't compare"));
    }
    let names = match listed.as_slice() {
        [] => format!("name no train, so not {mine}"),
        [one] => format!("name the {one} train but not {mine}"),
        [rest @ .., last] => format!("name the {} and {last} trains but not {mine}", rest.join(", ")),
    };
    match (x.released.as_deref(), x.support_end.as_deref()) {
        (Some(out), Some(end)) if !before(published, out) && (end.is_empty() || before(published, end)) => {
            (Verdict::Unaffected, String::new())
        }
        (Some(out), _) if before(published, out) => {
            (Verdict::Unknown, format!("{names}, which came out after publication"))
        }
        (Some(_), Some(_)) => (Verdict::Unknown, format!("{names}, which was out of support at publication")),
        _ => (
            Verdict::Unknown,
            format!(
                "{names}, and Pantry has no release and support dates for {mine} to tell whether that means unaffected"
            ),
        ),
    }
}

/// The trains an entry names as affected (each one's first number), in
/// order; the Performance Pack's aren't plain trains.
fn listed_trains(entry: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in crate::utils::json::arr_at(entry, "versions") {
        let raw = s(v, "version");
        let shown =
            raw.rsplit_once(':').filter(|(p, _)| p.chars().any(char::is_alphabetic)).map_or(raw, |(_, b)| b.trim());
        if s(v, "status") != "affected" || shown.contains("perf") {
            continue;
        }
        if let Some(p) = java_parts(shown).and_then(|p| p.first().cloned())
            && !out.contains(&p)
        {
            out.push(p);
        }
    }
    out.sort_by(|a, b| num_cmp(a, b));
    out
}

/// A bound or version an entry names, to show how its versions are written.
fn example_bound(entry: &Value) -> Option<String> {
    crate::utils::json::arr_at(entry, "versions").iter().find_map(|v| {
        [s(v, "lessThan"), s(v, "lessThanOrEqual"), s(v, "version")]
            .into_iter()
            .find(|b| !matches!(*b, "" | "0" | "*"))
            .map(str::to_string)
    })
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

/// The catalog tools found that [`TOOLS`] names, as subjects: one per
/// spelling of the tool's records. A tool in [`OSV_FIRST`] only when
/// `osv_answered` says OSV had no CVE for it.
pub fn tool_subjects(found: &[Component], osv_answered: &dyn Fn(&Component) -> bool) -> Vec<Subject> {
    found
        .iter()
        .filter(|c| !(OSV_FIRST.contains(&c.name.as_str()) && osv_answered(c)))
        .flat_map(|c| {
            TOOLS.iter().filter(|(name, _, _)| *name == c.name).map(|(_, vendor, product)| Subject {
                kind: c.kind.clone(),
                name: c.name.clone(),
                version: c.version.clone(),
                location: c.path.clone(),
                vendors: vendors_for(vendor),
                product: Some(product.to_string()),
                released: None,
                support_end: None,
            })
        })
        .collect()
}

/// The catalog tools [`TOOLS`] names, against CVE records. `osv` is what
/// OSV answered for the inventory ([`crate::checks::machine::components`]):
/// a tool in [`OSV_FIRST`] with records there is OSV's to judge.
pub fn tools(scan: &mut Scan, found: &[Component], osv: &HashMap<Item, Vec<Value>>) -> Result<()> {
    let answered = |c: &Component| {
        c.osv.as_ref().and_then(|o| osv.get(o)).is_some_and(|recs| {
            recs.iter().any(|r| crate::sources::osv::ids_of(r).iter().any(|id| id.starts_with("CVE-")))
        })
    };
    let mut subjects = tool_subjects(found, &answered);
    // Each one's train release date, from endoflife.date's copy the
    // inventory check already fetched (nothing is asked here).
    for x in &mut subjects {
        let cycle = found.iter().find(|c| c.name == x.name && c.version == x.version && c.path == x.location);
        if let Some((product, cycle)) = cycle.and_then(|c| c.eol.as_ref()) {
            x.released = crate::sources::endoflife::released(&scan.cache, product, cycle)?;
            x.support_end = crate::sources::endoflife::support_end(&scan.cache, product, cycle)?;
        }
    }
    check(scan, &subjects, TOOLS_WHAT)
}

/// The check over `subjects`: every record that applies is a finding;
/// what couldn't be asked or judged is a not-checked line, named after
/// `what`.
pub fn check(scan: &mut Scan, subjects: &[Subject], what: &str) -> Result<()> {
    if subjects.is_empty() {
        return Ok(());
    }
    if let Err(e) = fetch::on(cve_records::ID) {
        scan.missed(what, &e);
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
    // Each install's reasons its records couldn't be judged.
    let mut unjudged: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
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
            let (findings, why) = assess(p, vendor, recs, &|id| kev.contains(id));
            if let Some(why) = why {
                let mine = unjudged.entry(format!("{} {}", p.name, p.version)).or_default();
                if !mine.contains(&why) {
                    mine.push(why);
                }
            }
            for f in findings {
                // One finding per install and CVE: a second install at
                // another path is its own, and a CVE OSV already reported
                // for this install (MySQL has both; OSV findings show the
                // CVE id) isn't repeated.
                let same = |g: &Finding| {
                    g.component == f.component
                        && g.version == f.version
                        && g.location == f.location
                        && g.vuln_id == f.vuln_id
                };
                if !found.iter().any(same) && !scan.findings.iter().any(same) {
                    found.push(f);
                }
            }
        }
    }
    for f in found {
        scan.add(f);
    }
    if !unjudged.is_empty() {
        // Installs with the same reasons share a line.
        let mut by_why: Vec<(String, Vec<String>)> = Vec::new();
        for (who, why) in &unjudged {
            let why = why.join("; ");
            match by_why.iter_mut().find(|(w, _)| *w == why) {
                Some((_, whos)) => whos.push(who.clone()),
                None => by_why.push((why, vec![who.clone()])),
            }
        }
        let shown: Vec<String> = by_why
            .iter()
            .map(|(why, whos)| {
                let more = if whos.len() > 3 { format!(" and {} more", whos.len() - 3) } else { String::new() };
                format!("{}{more}: {why}.", whos[..whos.len().min(3)].join(", "))
            })
            .collect();
        scan.unchecked(&unjudged_label(what), &shown.join(" "));
    }
    for (set, label) in [(&unreached_names, unreached(what)), (&partial_names, partial(what))] {
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
