//! Wordfence Intelligence's vulnerability feed (v3, `production`): every
//! known vulnerability in WordPress core, plugins and themes, keyed by
//! slug, with the affected ranges and patched versions. OSV has no
//! WordPress ecosystem, so this is the only source for them.
//!
//! The feed needs the user's own key (`WORDFENCE_API_KEY`, free from a
//! wordfence.com account; Wordfence's terms forbid sharing one, so none
//! ships). Only the key is sent, as `Authorization: Bearer`. The whole feed
//! (over 100 MB of JSON) is downloaded at most daily, gzip asked for, with
//! its ETag, and read record by record into the cache's `wordfence` table:
//! one row per (record, software), only what the judgement needs.
//!
//! A record looks like this (trimmed):
//!
//! ```text
//! "61c39f5f-…": {"id": "61c39f5f-…", "title": "Contact Form Builder by vcita <= 4.9.1 - CSRF",
//!   "software": [{"type": "plugin", "slug": "contact-form-with-a-meeting-scheduler-by-vcita",
//!     "affected_versions": {"* - 4.9.1": {"from_version": "*", "from_inclusive": true,
//!                                         "to_version": "4.9.1", "to_inclusive": true}},
//!     "patched": false, "patched_versions": [], "remediation": "No known patch available. …"}],
//!   "cve": "CVE-2023-2301", "cvss": {"vector": "CVSS:3.1/…", "score": 6.1, "rating": "Medium"},
//!   "copyrights": {"message": "…", "defiant": {"notice": "Copyright 2012-2023 Defiant Inc.", …}}}
//! ```
//!
//! Informational records (`"informational": true`) aren't vulnerabilities
//! and aren't kept. A copy that isn't the feed's shape, or holds no
//! records, is refused: the last good one stays.
//!
//! The licence asks every copy to link the record and reproduce Defiant's
//! copyright and licence ([`notices`]), and MITRE's for the CVE ids.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::sources::fetch;
use crate::utils::archive::gzip;
use rusqlite::params;
use serde::de::{DeserializeSeed, MapAccess, Visitor};
use serde_json::Value;
use std::fmt;

/// The source's id in `sources.toml`.
pub const ID: &str = "wordfence";
/// The environment variable that holds the user's key.
pub const KEY_VAR: &str = "WORDFENCE_API_KEY";
/// How to get a key, for a report that couldn't check without one.
pub const GET_A_KEY: &str =
    "set WORDFENCE_API_KEY to check them: a free key from a wordfence.com account (Wordfence Intelligence, API key)";
/// The most the feed may be once inflated.
const MAX_TEXT: usize = 512 << 20;
/// What a finding's `kind` is: WordPress core, a plugin or a theme.
pub const KIND: &str = "wordpress";

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS wordfence (
  id TEXT, type TEXT, slug TEXT, title TEXT, cve TEXT, score REAL, vector TEXT, rating TEXT,
  ranges TEXT, patched TEXT, remediation TEXT,
  PRIMARY KEY (id, type, slug));
CREATE INDEX IF NOT EXISTS wordfence_software ON wordfence (type, slug);
";

/// The user's key, when set and not empty.
pub fn key() -> Option<String> {
    std::env::var(KEY_VAR).ok().map(|k| k.trim().to_string()).filter(|k| !k.is_empty())
}

/// One affected range: `*` as either end means unbounded.
#[derive(Clone, Debug, PartialEq)]
pub struct Range {
    pub from: String,
    pub from_inclusive: bool,
    pub to: String,
    pub to_inclusive: bool,
}

/// One record's entry for one piece of software.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Vuln {
    /// The record's UUID.
    pub id: String,
    pub title: String,
    /// `core`, `plugin` or `theme`.
    pub kind: String,
    pub slug: String,
    /// The CVE id, "" without one.
    pub cve: String,
    pub score: Option<f64>,
    pub vector: String,
    pub rating: String,
    pub ranges: Vec<Range>,
    pub patched: Vec<String>,
    pub remediation: String,
}

impl Vuln {
    /// The record's page, which every finding from it links.
    pub fn url(&self) -> String {
        record_url(&self.id)
    }
}

/// Wordfence's page for record `id`.
pub fn record_url(id: &str) -> String {
    format!("https://www.wordfence.com/threat-intel/vulnerabilities/id/{id}")
}

/// The Wordfence record a finding's note links, if any.
pub fn link_in(note: &str) -> Option<&str> {
    let at = note.find("https://www.wordfence.com/threat-intel/vulnerabilities/id/")?;
    let rest = &note[at..];
    Some(&rest[..rest.find(|c: char| c == ')' || c.is_whitespace()).unwrap_or(rest.len())])
}

/// Whether `id` is a record id as Wordfence writes them (a UUID): only
/// those are put in a link.
fn is_record_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// The rows one record gives: one per software it names, none for an
/// informational record or one without a usable id.
pub fn rows_of(rec: &Value) -> Vec<Vuln> {
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string();
    let id = s(rec, "id");
    if !is_record_id(&id) || rec.get("informational").and_then(Value::as_bool) == Some(true) {
        return Vec::new();
    }
    let cvss = rec.get("cvss").filter(|c| c.is_object());
    let score = cvss.and_then(|c| c.get("score")).and_then(Value::as_f64).filter(|x| (0.0..=10.0).contains(x));
    let mut out = Vec::new();
    for sw in rec.get("software").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        let kind = s(sw, "type");
        let slug = s(sw, "slug").to_ascii_lowercase();
        if !matches!(kind.as_str(), "core" | "plugin" | "theme") || slug.is_empty() {
            continue;
        }
        let ranges: Vec<Range> = sw
            .get("affected_versions")
            .and_then(Value::as_object)
            .map(|m| {
                m.values()
                    .map(|r| Range {
                        from: s(r, "from_version"),
                        from_inclusive: r.get("from_inclusive").and_then(Value::as_bool).unwrap_or(true),
                        to: s(r, "to_version"),
                        to_inclusive: r.get("to_inclusive").and_then(Value::as_bool).unwrap_or(true),
                    })
                    .filter(|r| !r.from.is_empty() && !r.to.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if ranges.is_empty() {
            continue;
        }
        let patched = sw
            .get("patched_versions")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter().filter_map(Value::as_str).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect()
            })
            .unwrap_or_default();
        out.push(Vuln {
            id: id.clone(),
            title: s(rec, "title"),
            kind,
            slug,
            cve: Some(s(rec, "cve")).filter(|c| c.starts_with("CVE-")).unwrap_or_default(),
            score,
            vector: cvss.map(|c| s(c, "vector")).unwrap_or_default(),
            rating: cvss.map(|c| s(c, "rating")).unwrap_or_default(),
            ranges,
            patched,
            remediation: s(sw, "remediation"),
        });
    }
    out
}

/// Reads the feed's top-level object one record at a time, so the whole
/// feed is never held as one parsed value.
struct Records<'a>(&'a mut Vec<Vuln>, &'a mut usize);

impl<'de> DeserializeSeed<'de> for Records<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Records<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an object of Wordfence records")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        while let Some((_, rec)) = map.next_entry::<String, Value>()? {
            if rec.is_object() {
                *self.1 += 1;
                self.0.extend(rows_of(&rec));
            }
        }
        Ok(())
    }
}

/// The rows of a whole feed (gzip or not), and how many records it held;
/// an error when it isn't the feed's shape.
pub fn parse(body: &[u8]) -> Result<(Vec<Vuln>, usize)> {
    let inflated;
    let text = if gzip::is_gzip(body) {
        inflated = gzip::gunzip(body, MAX_TEXT).ok_or_else(|| Error::Invalid("not gzip, or over its cap".into()))?;
        &inflated[..]
    } else {
        body
    };
    let (mut rows, mut records) = (Vec::new(), 0);
    let mut de = serde_json::Deserializer::from_slice(text);
    Records(&mut rows, &mut records)
        .deserialize(&mut de)
        .map_err(|e| Error::Invalid(format!("malformed feed: {e}")))?;
    de.end().map_err(|e| Error::Invalid(format!("malformed feed: {e}")))?;
    Ok((rows, records))
}

/// Refresh the feed when due (unless `offline`), sending only `key`; the
/// number of rows kept. Unreachable with nothing kept is `Offline`, with
/// what went wrong.
pub fn refresh(cache: &Cache, net: &dyn crate::utils::net::Net, key: &str, offline: bool) -> Result<usize> {
    let auth = format!("Bearer {key}");
    let headers = [("Authorization", auth.as_str()), ("Accept-Encoding", "gzip")];
    if let Some(body) = fetch::file_with_headers(cache, net, ID, ID, offline, &headers)? {
        match parse(&body) {
            Ok((_, 0)) => fetch::rejected(ID, "no records in the feed"),
            Ok((rows, _)) => store(cache, &rows)?,
            Err(e) => fetch::rejected(ID, &e.to_string()),
        }
    }
    let n: i64 = cache.conn.query_row("SELECT COUNT(*) FROM wordfence", [], |r| r.get(0))?;
    if n == 0 {
        let why = fetch::last_error(ID).unwrap_or_else(|| "nothing cached".into());
        return Err(Error::Offline(format!("Wordfence Intelligence unreachable and not cached: {why}")));
    }
    Ok(n as usize)
}

fn store(cache: &Cache, rows: &[Vuln]) -> Result<()> {
    cache.conn.execute("DELETE FROM wordfence", [])?;
    let mut stmt = cache.conn.prepare("INSERT OR REPLACE INTO wordfence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")?;
    for v in rows {
        let ranges: Vec<Value> =
            v.ranges.iter().map(|r| serde_json::json!([r.from, r.from_inclusive, r.to, r.to_inclusive])).collect();
        stmt.execute(params![
            v.id,
            v.kind,
            v.slug,
            v.title,
            v.cve,
            v.score,
            v.vector,
            v.rating,
            Value::Array(ranges).to_string(),
            serde_json::json!(v.patched).to_string(),
            v.remediation,
        ])?;
    }
    drop(stmt);
    cache.commit()
}

/// Every kept row for (`kind`, `slug`).
pub fn for_software(cache: &Cache, kind: &str, slug: &str) -> Result<Vec<Vuln>> {
    let mut stmt = cache.conn.prepare(
        "SELECT id, title, cve, score, vector, rating, ranges, patched, remediation FROM wordfence \
         WHERE type = ? AND slug = ? ORDER BY id",
    )?;
    let rows = stmt.query_map(params![kind, slug.to_ascii_lowercase()], |r| {
        let text = |i: usize| r.get::<_, Option<String>>(i).map(Option::unwrap_or_default);
        let ranges: Vec<Range> = serde_json::from_str::<Vec<Value>>(&text(6)?)
            .unwrap_or_default()
            .iter()
            .filter_map(|x| {
                Some(Range {
                    from: x.get(0)?.as_str()?.to_string(),
                    from_inclusive: x.get(1)?.as_bool()?,
                    to: x.get(2)?.as_str()?.to_string(),
                    to_inclusive: x.get(3)?.as_bool()?,
                })
            })
            .collect();
        Ok(Vuln {
            id: text(0)?,
            title: text(1)?,
            kind: kind.to_string(),
            slug: slug.to_ascii_lowercase(),
            cve: text(2)?,
            score: r.get(3)?,
            vector: text(4)?,
            rating: text(5)?,
            ranges,
            patched: serde_json::from_str(&text(7)?).unwrap_or_default(),
            remediation: text(8)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Defiant's licence, as each record carries it.
pub const DEFIANT_LICENSE: &str = "Defiant hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute this software vulnerability information. Any copy of the software vulnerability information you make for such purposes is authorized provided that you include a hyperlink to this vulnerability record and reproduce Defiant's copyright designation and this license in any such copy.";
pub const DEFIANT_LICENSE_URL: &str = "https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/";
/// MITRE's licence for the CVE ids, as each record carries it.
pub const MITRE_LICENSE: &str = "CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE®). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.";
pub const MITRE_LICENSE_URL: &str = "https://www.cve.org/Legal/TermsOfUse";

/// Whether `f` came from Wordfence's feed (not a not-checked line).
pub fn from_feed(f: &Finding) -> bool {
    f.kind == KIND && f.vuln_id != "UNCHECKED" && link_in(&f.note).is_some()
}

/// The notices a report with Wordfence findings carries, one paragraph
/// each: Defiant's copyright and licence, then MITRE's when one of them
/// names a CVE. Empty without any.
pub fn notices(findings: &[Finding]) -> Vec<String> {
    let ours: Vec<&Finding> = findings.iter().filter(|f| from_feed(f)).collect();
    if ours.is_empty() {
        return Vec::new();
    }
    let year = crate::utils::dates::civil_from_days(crate::utils::dates::today()).0;
    let mut out = vec![format!(
        "WordPress vulnerability data: Wordfence Intelligence. Copyright 2012-{year} Defiant Inc. License: {DEFIANT_LICENSE} {DEFIANT_LICENSE_URL}"
    )];
    if ours.iter().any(|f| f.vuln_id.starts_with("CVE-")) {
        out.push(format!("Copyright 1999-{year} The MITRE Corporation. License: {MITRE_LICENSE} {MITRE_LICENSE_URL}"));
    }
    out
}

#[cfg(test)]
#[path = "wordfence_tests.rs"]
pub(crate) mod tests;
