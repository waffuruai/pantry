//! Side feeds: CISA KEV, endoflife.date, the Homebrew cask catalog, the
//! Chrome and Firefox release feeds, PostgreSQL's security table, the Arch
//! tracker, VS Code's extension lists and marketplaces, and GitHub's latest
//! releases. Each is cached and refetched only when stale (with an ETag
//! where the server supports one). A feed that can't be reached and has
//! nothing cached is `Offline`, so the caller reports it unchecked instead
//! of clean.

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::json::{self, str_at};
use crate::net::{self, Net};
use rusqlite::params;
use serde_json::Value;
use std::collections::HashSet;

pub const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const ARCH_URL: &str = "https://security.archlinux.org/issues/all.json";
pub const CASKS_URL: &str = "https://formulae.brew.sh/api/cask.json";
pub const CHROME_URL: &str = "https://versionhistory.googleapis.com/v1/chrome/platforms/{}/channels/stable/versions/all/releases?filter=endtime=none";
pub const FIREFOX: &str = "https://product-details.mozilla.org/1.0/";
pub const POSTGRES_URL: &str = "https://www.postgresql.org/support/security/";
pub const VSCODE_LISTS: &str = "https://main.vscode-cdn.net/extensions/marketplace.json";
pub const MARKETPLACE: &str = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery";
pub const OPENVSX: &str = "https://open-vsx.org/api/{}/{}/latest";
pub const GITHUB_LATEST: &str = "https://api.github.com/repos/{}/releases/latest";

/// Body bytes when a refetch returned new data, else None.
fn etag_fetch(
    cache: &Cache,
    net: &dyn Net,
    url: &str,
    key: &str,
    max_age: f64,
    offline: bool,
) -> Result<Option<Vec<u8>>> {
    if offline || cache.fresh(&format!("{key}_at"), max_age)? {
        return Ok(None);
    }
    let etag = cache.get(&format!("{key}_etag"))?;
    let resp = match net::request(net, url, None, &[], etag.as_deref()) {
        Ok(r) => r,
        Err(e) if e.is_source() => return Ok(None),
        Err(e) => return Err(e),
    };
    cache.touch(&format!("{key}_at"))?;
    if resp.status != 200 {
        return Ok(None);
    }
    if let Some(e) = &resp.etag {
        cache.set(&format!("{key}_etag"), e)?;
    }
    Ok(Some(resp.body))
}

/// The CVE ids in CISA's Known Exploited Vulnerabilities list.
pub fn kev(cache: &Cache, net: &dyn Net, offline: bool) -> Result<HashSet<String>> {
    if let Some(body) = etag_fetch(cache, net, KEV_URL, "kev", DAY, offline)? {
        let data = json::parse(&body, json::MAX_DOCUMENT)?;
        cache.conn.execute("DELETE FROM kev", [])?;
        let mut stmt = cache.conn.prepare("INSERT OR REPLACE INTO kev VALUES (?, ?, ?)")?;
        for v in json::arr_at(&data, "vulnerabilities") {
            let id = str_at(v, "cveID");
            if !id.is_empty() {
                stmt.execute(params![id, str_at(v, "dateAdded"), str_at(v, "vulnerabilityName")])?;
            }
        }
        drop(stmt);
        cache.commit()?;
    }
    let ids = cache.kev_ids()?;
    if ids.is_empty() {
        return Err(Error::Offline("CISA KEV list unreachable and not cached".into()));
    }
    Ok(ids)
}

/// What endoflife.date says about one release cycle.
#[derive(Debug, PartialEq)]
pub struct Eol {
    pub cycle: String,
    /// The end-of-life date when it has passed ("True" for a bare `true`).
    pub ended: Option<String>,
    pub latest: String,
    /// Cycles still supported.
    pub supported: Vec<String>,
}

/// endoflife.date's view of `cycle` of `product`, or None when it doesn't
/// know the cycle.
pub fn eol(cache: &Cache, net: &dyn Net, product: &str, cycle: &str, offline: bool) -> Result<Option<Eol>> {
    if !(offline || cache.fresh(&format!("eol_at:{product}"), 7.0 * DAY)?) {
        match net::get_json(net, &format!("https://endoflife.date/api/{product}.json"), &[]) {
            Ok(data) => {
                cache.conn.execute("DELETE FROM eol WHERE product = ?", [product])?;
                let rows = data.as_ref().and_then(Value::as_array).cloned().unwrap_or_default();
                for c in rows {
                    let cyc = match &c["cycle"] {
                        Value::String(s) => s.clone(),
                        Value::Null => continue,
                        other => other.to_string(),
                    };
                    let latest = match c.get("latest") {
                        Some(Value::String(s)) => s.clone(),
                        Some(Value::Null) | None => String::new(),
                        Some(other) => other.to_string(),
                    };
                    let end = c.get("eol").cloned().unwrap_or(Value::Null).to_string();
                    cache.conn.execute(
                        "INSERT OR REPLACE INTO eol VALUES (?, ?, ?, ?)",
                        params![product, cyc, end, latest],
                    )?;
                }
                cache.touch(&format!("eol_at:{product}"))?;
            }
            Err(e) if e.is_source() => {}
            Err(e) => return Err(e),
        }
    }
    let mut stmt = cache.conn.prepare("SELECT cycle, eol, latest FROM eol WHERE product = ?")?;
    let rows: Vec<(String, String, String)> = stmt
        .query_map([product], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    if rows.is_empty() {
        return Err(Error::Offline(format!("endoflife.date ({product}) unreachable and not cached")));
    }
    let end_of = |e: &str| serde_json::from_str::<Value>(e).unwrap_or(Value::Null);
    let supported: Vec<String> = rows.iter().filter(|(_, e, _)| !past(&end_of(e))).map(|(c, _, _)| c.clone()).collect();
    for (c, e, latest) in &rows {
        if c == cycle {
            let end = end_of(e);
            let ended = past(&end).then(|| match &end {
                Value::String(s) => s.clone(),
                _ => "True".to_string(), // as Python prints it
            });
            return Ok(Some(Eol { cycle: c.clone(), ended, latest: latest.clone(), supported }));
        }
    }
    Ok(None)
}

/// Whether an endoflife.date `eol` value (a date, or true/false) has passed.
pub fn past(end: &Value) -> bool {
    match end {
        Value::Bool(b) => *b,
        Value::String(s) => parse_date(s).is_some_and(|d| d <= today()),
        _ => false,
    }
}

/// Days since 1970-01-01 for an ISO date (YYYY-MM-DD).
pub fn parse_date(s: &str) -> Option<i64> {
    let mut it = s.splitn(3, '-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Howard Hinnant's days_from_civil.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Today (UTC), in days since 1970-01-01.
pub fn today() -> i64 {
    (crate::system::now() / 86400.0).floor() as i64
}

/// The Arch Linux security tracker's advisory groups.
pub fn arch(cache: &Cache, net: &dyn Net, offline: bool) -> Result<Value> {
    let fetch = || match net::get_json(net, ARCH_URL, &[])? {
        Some(Value::Array(groups)) if !groups.is_empty() => Ok(Value::Array(groups)),
        _ => Err(Error::Offline("the Arch security tracker returned nothing".into())),
    };
    cache.memo("arch-tracker", fetch, DAY, "", false, offline)
}

/// {app bundle name: (cask token, latest version)} from the public cask
/// catalog, refreshed weekly.
pub fn casks(
    cache: &Cache,
    net: &dyn Net,
    offline: bool,
) -> Result<std::collections::BTreeMap<String, (String, String)>> {
    if let Some(body) = etag_fetch(cache, net, CASKS_URL, "casks", 7.0 * DAY, offline)? {
        let data = json::parse(&body, json::MAX_DOCUMENT)?;
        let mut rows: Vec<(String, String, String)> = Vec::new();
        for c in data.as_array().map(Vec::as_slice).unwrap_or(&[]) {
            let version = match c.get("version") {
                Some(Value::String(v)) => v.clone(),
                Some(Value::Null) | None => String::new(),
                Some(o) => o.to_string(),
            };
            if version.is_empty() || version == "latest" {
                continue;
            }
            for art in json::arr_at(c, "artifacts") {
                for app in json::arr_at(art, "app") {
                    if let Some(a) = app.as_str().filter(|a| a.ends_with(".app"))
                        && !rows.iter().any(|(x, _, _)| x == a)
                    {
                        rows.push((
                            a.to_string(),
                            str_at(c, "token").to_string(),
                            version.split(',').next().unwrap_or("").to_string(),
                        ));
                    }
                }
            }
        }
        cache.conn.execute("DELETE FROM casks", [])?;
        let mut stmt = cache.conn.prepare("INSERT INTO casks VALUES (?, ?, ?)")?;
        for (a, t, v) in &rows {
            stmt.execute(params![a, t, v])?;
        }
        drop(stmt);
        cache.commit()?;
    }
    let mut stmt = cache.conn.prepare("SELECT app, token, version FROM casks")?;
    let out: std::collections::BTreeMap<String, (String, String)> = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                (
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                ),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    if out.is_empty() {
        return Err(Error::Offline("the Homebrew cask catalog is unreachable and not cached".into()));
    }
    Ok(out)
}

/// Day precision is enough: the grace period is counted in days.
pub fn epoch(stamp: &str) -> f64 {
    stamp.get(..10).and_then(parse_date).map(|d| d as f64 * 86400.0).unwrap_or(0.0)
}

/// [(version, serving since epoch)] currently served on Chrome's stable channel.
pub fn chrome(cache: &Cache, net: &dyn Net, platform: &str, offline: bool) -> Result<Vec<(String, f64)>> {
    let fetch = || -> Result<Value> {
        let data = net::get_json(net, &CHROME_URL.replace("{}", platform), &[])?.unwrap_or(Value::Null);
        let rows: Vec<Value> = json::arr_at(&data, "releases")
            .iter()
            .map(|r| {
                let start = r.get("serving").map(|s| str_at(s, "startTime")).unwrap_or("");
                serde_json::json!([str_at(r, "version"), epoch(start)])
            })
            .collect();
        Ok(Value::Array(rows))
    };
    let v = cache.memo(&format!("chrome:{platform}"), fetch, DAY, "", false, offline)?;
    Ok(v.as_array()
        .map(|a| a.iter().map(|r| (r[0].as_str().unwrap_or("").to_string(), r[1].as_f64().unwrap_or(0.0))).collect())
        .unwrap_or_default())
}

/// Firefox: (latest, ESR versions, {version: release epoch}).
pub struct Firefox {
    pub latest: String,
    pub esr: Vec<String>,
    pub dates: std::collections::BTreeMap<String, f64>,
}

pub fn firefox(cache: &Cache, net: &dyn Net, offline: bool) -> Result<Firefox> {
    let fetch = || -> Result<Value> {
        let v = net::get_json(net, &format!("{FIREFOX}firefox_versions.json"), &[])?.unwrap_or(Value::Null);
        let mut dates = serde_json::Map::new();
        for name in ["firefox_history_major_releases.json", "firefox_history_stability_releases.json"] {
            if let Some(Value::Object(m)) = net::get_json(net, &format!("{FIREFOX}{name}"), &[])? {
                for (ver, day) in m {
                    dates.insert(ver, serde_json::json!(epoch(day.as_str().unwrap_or(""))));
                }
            }
        }
        let esr: Vec<Value> = v
            .as_object()
            .map(|o| {
                o.iter()
                    .filter(|(k, val)| k.starts_with("FIREFOX_ESR") && val.as_str().is_some_and(|s| !s.is_empty()))
                    .map(|(_, val)| Value::String(val.as_str().unwrap_or("").replace("esr", "")))
                    .collect()
            })
            .unwrap_or_default();
        Ok(serde_json::json!({"latest": str_at(&v, "LATEST_FIREFOX_VERSION"), "esr": esr, "dates": dates}))
    };
    let v = cache.memo("firefox", fetch, DAY, "", false, offline)?;
    Ok(Firefox {
        latest: str_at(&v, "latest").to_string(),
        esr: json::strs_at(&v, "esr"),
        dates: v
            .get("dates")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, d)| (k.clone(), d.as_f64().unwrap_or(0.0))).collect())
            .unwrap_or_default(),
    })
}

/// The version of `repo`'s latest GitHub release (its tag without a leading
/// v), refreshed daily.
pub fn github_latest(cache: &Cache, net: &dyn Net, repo: &str, offline: bool) -> Result<String> {
    let fetch = || -> Result<Value> {
        let headers = net::github_headers();
        let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let data = net::get_json(net, &GITHUB_LATEST.replace("{}", repo), &h)?.unwrap_or(Value::Null);
        let tag = str_at(&data, "tag_name");
        if tag.is_empty() {
            return Err(Error::Offline(format!("{repo} has no latest release")));
        }
        let v =
            if tag.len() > 1 && tag.starts_with('v') && tag.as_bytes()[1].is_ascii_digit() { &tag[1..] } else { tag };
        Ok(Value::String(v.to_string()))
    };
    Ok(cache.memo(&format!("github-latest:{repo}"), fetch, DAY, "", false, offline)?.as_str().unwrap_or("").to_string())
}

/// One row of PostgreSQL's security table.
#[derive(Clone, Debug, PartialEq)]
pub struct PgAdvisory {
    pub cve: String,
    pub majors: Vec<String>,
    pub fixed: Vec<String>,
    pub component: String,
    pub score: f64,
    pub vector: String,
    pub summary: String,
}

/// HTML entities as `html.unescape` reads the common ones.
pub fn unescape_html(s: &str) -> String {
    let re = crate::re::Regex::new(r"&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z]+);");
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut last = 0;
    for m in re.find_all(s) {
        out.extend(&chars[last..m.start]);
        let e = m.get(1);
        let c = if let Some(hex) = e.strip_prefix("#x").or_else(|| e.strip_prefix("#X")) {
            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
        } else if let Some(dec) = e.strip_prefix('#') {
            dec.parse().ok().and_then(char::from_u32)
        } else {
            match e {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                _ => None,
            }
        };
        match c {
            Some(c) => out.push(c),
            None => out.extend(&chars[m.start..m.end]),
        }
        last = m.end;
    }
    out.extend(&chars[last..]);
    out
}

/// The rows of the table at postgresql.org/support/security/.
pub fn parse_postgres(page: &str) -> Vec<PgAdvisory> {
    use crate::re::Regex;
    let (row_re, cell_re) = (Regex::with_flags("<tr>(.*?)</tr>", "s"), Regex::with_flags("<td[^>]*>(.*?)</td>", "s"));
    let (tags, spaces) = (Regex::new("<[^>]+>"), Regex::new(r"\s+"));
    let (cve, meta, more) =
        (Regex::new(r"CVE-\d{4}-\d+"), Regex::new(r"(.*?)\s+([\d.]+)\s+(AV:\S+)?"), Regex::new(r"\s*more details$"));
    let mut out = Vec::new();
    for row in row_re.find_all(page) {
        let cells: Vec<String> = cell_re
            .find_all(row.get(1))
            .iter()
            .map(|c| unescape_html(&spaces.replace_all(&tags.replace_all(c.get(1), " "), " ")).trim().to_string())
            .collect();
        if cells.len() < 5 || cve.match_start(&cells[0]).is_none() {
            continue;
        }
        let m = meta.match_start(&cells[3]);
        let split =
            |s: &str| s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect::<Vec<_>>();
        out.push(PgAdvisory {
            cve: cells[0].split_whitespace().next().unwrap_or("").to_string(),
            majors: split(&cells[1]),
            fixed: split(&cells[2]),
            component: m.as_ref().map(|m| m.get(1).to_string()).unwrap_or_else(|| cells[3].clone()),
            score: m.as_ref().and_then(|m| m.get(2).parse().ok()).unwrap_or(0.0),
            vector: m.as_ref().map(|m| m.get(3).to_string()).unwrap_or_default(),
            summary: more.replace_all(&cells[4], ""),
        });
    }
    out
}

/// The PostgreSQL project's own security table (OSV has no PostgreSQL
/// release data) for every supported major.
pub fn postgres(cache: &Cache, net: &dyn Net, offline: bool) -> Result<Vec<PgAdvisory>> {
    let fetch = || -> Result<Value> {
        let resp = net::request(net, POSTGRES_URL, None, &[("Accept", "text/html")], None)?;
        let rows: Vec<Value> = parse_postgres(&String::from_utf8_lossy(&resp.body))
            .into_iter()
            .map(|a| serde_json::json!({"cve": a.cve, "majors": a.majors, "fixed": a.fixed, "component": a.component, "score": a.score, "vector": a.vector, "summary": a.summary}))
            .collect();
        Ok(Value::Array(rows))
    };
    let v = cache.memo("postgres", fetch, DAY, "", false, offline)?;
    Ok(v.as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .map(|a| PgAdvisory {
            cve: str_at(a, "cve").into(),
            majors: json::strs_at(a, "majors"),
            fixed: json::strs_at(a, "fixed"),
            component: str_at(a, "component").into(),
            score: a.get("score").and_then(Value::as_f64).unwrap_or(0.0),
            vector: str_at(a, "vector").into(),
            summary: str_at(a, "summary").into(),
        })
        .collect())
}

/// The label for a CVSS score.
pub fn severity_from_score(score: f64) -> &'static str {
    if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MODERATE"
    } else if score > 0.0 {
        "LOW"
    } else {
        ""
    }
}

/// The lists VS Code itself downloads: malicious extension ids and
/// deprecated ones (id → replacement or ""), lowercased.
pub struct VscodeLists {
    pub malicious: std::collections::HashSet<String>,
    pub deprecated: std::collections::HashMap<String, String>,
}

pub fn vscode_lists(cache: &Cache, net: &dyn Net, offline: bool) -> Result<VscodeLists> {
    let fetch = || Ok(net::get_json(net, VSCODE_LISTS, &[])?.unwrap_or(Value::Object(serde_json::Map::new())));
    let data = cache.memo("vscode-lists", fetch, DAY, "", false, offline)?;
    let mut deprecated = std::collections::HashMap::new();
    if let Some(m) = data.get("deprecated").and_then(Value::as_object) {
        for (ext, info) in m {
            let repl = match info {
                Value::Object(o) if !o.is_empty() => {
                    let id = info.get("extension").map(|e| str_at(e, "id")).unwrap_or("");
                    if id.is_empty() { str_at(info, "additionalInfo").to_string() } else { id.to_string() }
                }
                _ => String::new(),
            };
            deprecated.insert(ext.to_lowercase(), repl);
        }
    }
    let malicious = json::arr_at(&data, "malicious").iter().filter_map(Value::as_str).map(str::to_lowercase).collect();
    Ok(VscodeLists { malicious, deprecated })
}

/// {id: latest version} from Microsoft's marketplace, or Open VSX (which
/// Cursor, Windsurf and VSCodium install from). Unknown ids are left out.
pub fn latest_extensions(
    cache: &Cache,
    net: &dyn Net,
    ids: &[String],
    openvsx: bool,
    offline: bool,
) -> Result<std::collections::HashMap<String, String>> {
    let mut ids: Vec<String> = ids.to_vec();
    ids.sort();
    ids.dedup();
    let key = format!("{}:{}", if openvsx { "openvsx" } else { "marketplace" }, ids.join(","));
    let fetch = || -> Result<Value> {
        let mut out = serde_json::Map::new();
        if openvsx {
            for i in &ids {
                let (ns, name) = i.split_once('.').unwrap_or((i, ""));
                if let Some(d) = net::get_json(net, &OPENVSX.replacen("{}", ns, 1).replacen("{}", name, 1), &[])? {
                    let v = str_at(&d, "version");
                    if !v.is_empty() {
                        out.insert(i.clone(), Value::String(v.into()));
                    }
                }
            }
            return Ok(Value::Object(out));
        }
        for chunk in ids.chunks(100) {
            let criteria: Vec<Value> = chunk.iter().map(|i| serde_json::json!({"filterType": 7, "value": i})).collect();
            let body = serde_json::json!({"filters": [{"criteria": criteria, "pageSize": 100}], "flags": 1 | 16});
            let resp = net::request(
                net,
                MARKETPLACE,
                Some(&body),
                &[("Accept", "application/json;api-version=7.2-preview.1")],
                None,
            )?;
            let data = json::parse(&resp.body, json::MAX_DOCUMENT)?;
            let results = json::arr_at(&data, "results");
            for e in results.first().map(|r| json::arr_at(r, "extensions")).unwrap_or(&[]) {
                let ext = format!(
                    "{}.{}",
                    e.get("publisher").map(|p| str_at(p, "publisherName")).unwrap_or(""),
                    str_at(e, "extensionName")
                )
                .to_lowercase();
                let versions = json::arr_at(e, "versions");
                let pre = |v: &Value| {
                    json::arr_at(v, "properties")
                        .iter()
                        .any(|p| str_at(p, "key") == "Microsoft.VisualStudio.Code.PreRelease")
                };
                let stable: Vec<&str> = versions.iter().filter(|v| !pre(v)).map(|v| str_at(v, "version")).collect();
                let pick = stable.first().copied().or_else(|| versions.first().map(|v| str_at(v, "version")));
                if let Some(v) = pick {
                    out.insert(ext, Value::String(v.into()));
                }
            }
        }
        Ok(Value::Object(out))
    };
    let v = cache.memo(&key, fetch, DAY, "", false, offline)?;
    Ok(v.as_object()
        .map(|m| m.iter().map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string())).collect())
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Fake, Response};
    use serde_json::json;

    fn cache() -> (crate::system::TempDir, Cache) {
        let d = crate::system::TempDir::new("feeds").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        (d, c)
    }

    // The Python test vector (python/test_wscanner.py `Parsers.test_postgres_table`).
    #[test]
    fn postgres_table() {
        let page = "<table><tr><th>Reference</th></tr><tr><td><a>CVE-2026-19385</a> <a>Announcement</a></td><td>18, 17, 16</td><td>18.6, 17.11, 16.15</td><td>core server<br>8.8<br>AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td><td>Heap overflow <a>more details</a></td></tr><tr><td>client</td><td>legend row</td></tr></table>";
        let got = parse_postgres(page);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].majors, ["18", "17", "16"]);
        assert_eq!(got[0].fixed, ["18.6", "17.11", "16.15"]);
        assert_eq!((got[0].component.as_str(), got[0].score), ("core server", 8.8));
        assert_eq!(got[0].summary, "Heap overflow");
        assert_eq!(severity_from_score(8.8), "HIGH");
        assert_eq!(unescape_html("a &amp; b &#39;c&#x27; &bogus;"), "a & b 'c' &bogus;");
    }

    #[test]
    fn unreachable_postgres_is_offline_but_stale_beats_nothing() {
        let (_d, c) = cache();
        assert!(matches!(postgres(&c, &Fake::offline(), true), Err(Error::Offline(_))));
        c.put_run("postgres", "", &serde_json::json!([{"cve": "CVE-1"}])).unwrap();
        assert_eq!(postgres(&c, &Fake::offline(), true).unwrap()[0].cve, "CVE-1");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(parse_date("2000-03-01"), Some(11017));
        assert_eq!(parse_date("2026-10-27"), Some(20753));
        assert_eq!(parse_date("2026-13-01"), None);
        assert!(
            past(&json!(true)) && !past(&json!(false)) && past(&json!("2000-01-01")) && !past(&json!("2999-01-01"))
        );
    }

    #[test]
    fn unreachable_feed_raises_instead_of_reporting_clean() {
        let (_d, c) = cache();
        assert!(matches!(kev(&c, &Fake::offline(), true), Err(Error::Offline(_))));
        assert!(matches!(eol(&c, &Fake::offline(), "nodejs", "24", true), Err(Error::Offline(_))));
        assert!(matches!(kev(&c, &Fake::offline(), false), Err(Error::Offline(_))));
    }

    #[test]
    fn kev_fetch_with_etag() {
        let (_d, c) = cache();
        let net = Fake::new(|r| {
            assert!(r.header("If-None-Match").is_none());
            Ok(Response {
                status: 200,
                body: json!({"vulnerabilities": [{"cveID": "CVE-2026-1", "dateAdded": "2026-01-01"}]})
                    .to_string()
                    .into_bytes(),
                etag: Some("\"k1\"".into()),
            })
        });
        assert_eq!(kev(&c, &net, false).unwrap(), HashSet::from(["CVE-2026-1".to_string()]));
        assert_eq!(c.get("kev_etag").unwrap().as_deref(), Some("\"k1\""));
        // Fresh: no request at all.
        assert!(kev(&c, &Fake::new(|_| panic!("fresh")), false).is_ok());
    }

    #[test]
    fn eol_cycles() {
        let (_d, c) = cache();
        let net = Fake::new(|_| {
            Ok(Response::ok(
                json!([{"cycle": "24", "eol": "2999-04-30", "latest": "24.11.0"},
                                   {"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8"},
                                   {"cycle": 16, "eol": true, "latest": "16.20.2"}])
                .to_string(),
            ))
        });
        let e = eol(&c, &net, "nodejs", "18", false).unwrap().unwrap();
        assert_eq!(
            (e.ended.as_deref(), e.latest.as_str(), e.supported.clone()),
            (Some("2025-04-30"), "18.20.8", vec!["24".to_string()])
        );
        assert_eq!(eol(&c, &net, "nodejs", "16", true).unwrap().unwrap().ended.as_deref(), Some("True"));
        assert_eq!(eol(&c, &net, "nodejs", "24", true).unwrap().unwrap().ended, None);
        assert_eq!(eol(&c, &net, "nodejs", "99", true).unwrap(), None);
    }
}
