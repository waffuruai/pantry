//! Release feeds: the Homebrew cask catalog, Chrome's and Firefox's
//! release histories, PostgreSQL's security table and GitHub's latest
//! releases. Each is cached and refetched only when stale; one that can't be
//! reached with nothing cached is `Offline`, so the caller reports it
//! unchecked instead of clean.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::fetch;
use crate::sources::file::url;
use crate::utils::dates::epoch;
use crate::utils::json::{self, str_at};
use crate::utils::net::{self, Net};
use rusqlite::params;
use serde_json::Value;

/// {app bundle name: (cask token, latest version)} from the public cask
/// catalog, refreshed weekly.
pub fn casks(
    cache: &Cache,
    net: &dyn Net,
    offline: bool,
) -> Result<std::collections::BTreeMap<String, (String, String)>> {
    if let Some(body) = fetch::file(cache, net, "homebrew-casks", "casks", offline)? {
        let data = json::parse(&body, json::MAX_DOCUMENT).unwrap_or_else(|e| {
            fetch::rejected("homebrew-casks", &e.to_string());
            Value::Null
        });
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
        // A catalog with no apps in it is refused: the last good one stays.
        if rows.is_empty() {
            fetch::rejected("homebrew-casks", "no apps in the catalog");
        } else {
            cache.conn.execute("DELETE FROM casks", [])?;
            let mut stmt = cache.conn.prepare("INSERT INTO casks VALUES (?, ?, ?)")?;
            for (a, t, v) in &rows {
                stmt.execute(params![a, t, v])?;
            }
            drop(stmt);
            cache.commit()?;
        }
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

/// [(version, serving since epoch)] currently served on Chrome's stable channel.
pub fn chrome(cache: &Cache, net: &dyn Net, platform: &str, offline: bool) -> Result<Vec<(String, f64)>> {
    let fetch = || -> Result<Value> {
        let data = fetch::get_json(net, "chrome-releases", &url("chrome-releases").replace("{}", platform), &[])?
            .unwrap_or(Value::Null);
        let rows: Vec<Value> = json::arr_at(&data, "releases")
            .iter()
            .map(|r| {
                let start = r.get("serving").map(|s| str_at(s, "startTime")).unwrap_or("");
                serde_json::json!([str_at(r, "version"), epoch(start)])
            })
            .filter(|r| r[0].as_str().is_some_and(|v| !v.is_empty()))
            .collect();
        if rows.is_empty() {
            return Err(fetch::invalid("chrome-releases", "no releases"));
        }
        Ok(Value::Array(rows))
    };
    let v = fetch::memo(cache, "chrome-releases", &format!("chrome:{platform}"), fetch, "", false, offline)?;
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
        let v = fetch::get_json(
            net,
            "firefox-releases",
            &format!("{}firefox_versions.json", url("firefox-releases")),
            &[],
        )?
        .unwrap_or(Value::Null);
        let mut dates = serde_json::Map::new();
        for name in ["firefox_history_major_releases.json", "firefox_history_stability_releases.json"] {
            if let Some(Value::Object(m)) =
                fetch::get_json(net, "firefox-releases", &format!("{}{name}", url("firefox-releases")), &[])?
            {
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
        if str_at(&v, "LATEST_FIREFOX_VERSION").is_empty() {
            return Err(fetch::invalid("firefox-releases", "no latest version"));
        }
        Ok(serde_json::json!({"latest": str_at(&v, "LATEST_FIREFOX_VERSION"), "esr": esr, "dates": dates}))
    };
    let v = fetch::memo(cache, "firefox-releases", "firefox", fetch, "", false, offline)?;
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
        let data = fetch::get_json(net, "github-releases", &url("github-releases").replace("{}", repo), &h)?
            .unwrap_or(Value::Null);
        let tag = str_at(&data, "tag_name");
        if tag.is_empty() {
            return Err(Error::Offline(format!("{repo} has no latest release")));
        }
        let v =
            if tag.len() > 1 && tag.starts_with('v') && tag.as_bytes()[1].is_ascii_digit() { &tag[1..] } else { tag };
        Ok(Value::String(v.to_string()))
    };
    Ok(fetch::memo(cache, "github-releases", &format!("github-latest:{repo}"), fetch, "", false, offline)?
        .as_str()
        .unwrap_or("")
        .to_string())
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
    let re = crate::utils::re::Regex::new(r"&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z]+);");
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
    use crate::utils::re::Regex;
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
        let resp = fetch::request(
            net,
            "postgresql-security",
            url("postgresql-security"),
            None,
            &[("Accept", "text/html")],
            None,
        )?;
        let rows: Vec<Value> = parse_postgres(&String::from_utf8_lossy(&resp.body))
            .into_iter()
            .map(|a| serde_json::json!({"cve": a.cve, "majors": a.majors, "fixed": a.fixed, "component": a.component, "score": a.score, "vector": a.vector, "summary": a.summary}))
            .collect();
        if rows.is_empty() {
            return Err(fetch::invalid("postgresql-security", "no advisories in the page"));
        }
        Ok(Value::Array(rows))
    };
    let v = fetch::memo(cache, "postgresql-security", "postgres", fetch, "", false, offline)?;
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

#[cfg(test)]
#[path = "releases_tests.rs"]
mod tests;
