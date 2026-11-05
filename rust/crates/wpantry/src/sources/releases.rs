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
mod tests {
    use super::*;
    use crate::sources::testing::cache;
    use crate::utils::dates::epoch;
    use crate::utils::net::{Fake, Response};
    use serde_json::json;

    // The test vector the Python implementation had (`Parsers.test_postgres_table`).
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
    fn cask_catalog_maps_app_bundles_to_tokens() {
        let (_d, c) = cache();
        assert!(matches!(casks(&c, &Fake::offline(), true), Err(Error::Offline(_))));
        assert!(matches!(casks(&c, &Fake::new(|_| Ok(Response::ok("{}"))), false), Err(Error::Offline(_))));
        let body = json!([
            {"token": "firefox", "version": "145.0", "artifacts": [{"app": ["Firefox.app"]}, {"zap": []}]},
            {"token": "dup", "version": "1", "artifacts": [{"app": ["Firefox.app"]}]},
            {"token": "nover", "artifacts": [{"app": ["X.app"]}]},
            {"token": "rolling", "version": "latest", "artifacts": [{"app": ["Y.app"]}]},
            {"token": "num", "version": 7, "artifacts": [{"app": ["Num.app"]}]},
            {"token": "nul", "version": null},
            {"token": "comma", "version": "1.2,345", "artifacts": [{"app": ["Comma.app", "not-an-app"]}]}
        ]);
        c.set("casks_at", "0").unwrap();
        let net = Fake::new(move |_| Ok(Response::ok(body.to_string())));
        let got = casks(&c, &net, false).unwrap();
        let rows: Vec<(&str, &str, &str)> =
            got.iter().map(|(a, (t, v))| (a.as_str(), t.as_str(), v.as_str())).collect();
        assert_eq!(rows, [("Comma.app", "comma", "1.2"), ("Firefox.app", "firefox", "145.0"), ("Num.app", "num", "7")]);
        assert_eq!(casks(&c, &Fake::new(|_| panic!("fresh")), false).unwrap().len(), 3);
    }

    #[test]
    fn chrome_releases_carry_their_serving_date() {
        let (_d, c) = cache();
        let net = Fake::new(|r| {
            assert!(r.url.contains("/platforms/mac/"), "{}", r.url);
            Ok(Response::ok(
                json!({"releases": [{"version": "142.0.1", "serving": {"startTime": "2026-10-01T00:00:00Z"}}, {"version": "141.0.0"}]})
                    .to_string(),
            ))
        });
        let got = chrome(&c, &net, "mac", false).unwrap();
        assert_eq!(got, [("142.0.1".to_string(), epoch("2026-10-01")), ("141.0.0".to_string(), 0.0)]);
        assert!(epoch("2026-10-01") > 0.0 && epoch("soon") == 0.0);
        let gone = Fake::new(|_| Ok(Response { status: 404, body: Vec::new(), etag: None }));
        assert!(chrome(&c, &gone, "linux", false).is_err(), "a feed that is gone is unchecked, not empty");
    }

    #[test]
    fn firefox_feed_joins_versions_and_release_dates() {
        let (_d, c) = cache();
        let net = Fake::new(|r| {
            Ok(Response::ok(
                match r.url.rsplit('/').next().unwrap_or("") {
                    "firefox_versions.json" => json!({"LATEST_FIREFOX_VERSION": "145.0", "FIREFOX_ESR": "140.4.0esr",
                    "FIREFOX_ESR_NEXT": "", "FIREFOX_ESR115": "115.30.0esr", "FIREFOX_NIGHTLY": "147.0a1"}),
                    "firefox_history_major_releases.json" => json!({"145.0": "2026-10-14"}),
                    _ => json!({"145.0.1": "2026-10-21", "odd": 3}),
                }
                .to_string(),
            ))
        });
        let f = firefox(&c, &net, false).unwrap();
        let mut esr = f.esr.clone();
        esr.sort();
        assert_eq!((f.latest.as_str(), esr), ("145.0", vec!["115.30.0".to_string(), "140.4.0".into()]));
        assert_eq!(f.dates.get("145.0.1"), Some(&epoch("2026-10-21")));
        assert_eq!(f.dates.get("odd"), Some(&0.0));
        assert_eq!(net.requests().len(), 3);
        let gone = Fake::new(|_| Ok(Response { status: 404, body: Vec::new(), etag: None }));
        let (_d2, c2) = cache();
        assert!(firefox(&c2, &gone, false).is_err(), "a feed that is gone is unchecked, not empty");
    }

    #[test]
    fn latest_release_drops_the_v_and_needs_a_tag() {
        let (_d, c) = cache();
        let net = Fake::new(|r| {
            assert_eq!(r.header("Accept"), Some("application/vnd.github+json"));
            Ok(Response::ok(
                match r.url.as_str() {
                    "https://api.github.com/repos/a/v/releases/latest" => json!({"tag_name": "v1.2.3"}),
                    "https://api.github.com/repos/a/plain/releases/latest" => json!({"tag_name": "release-1"}),
                    "https://api.github.com/repos/a/bare/releases/latest" => json!({"tag_name": "v"}),
                    _ => json!({}),
                }
                .to_string(),
            ))
        });
        assert_eq!(github_latest(&c, &net, "a/v", false).unwrap(), "1.2.3");
        assert_eq!(github_latest(&c, &net, "a/plain", false).unwrap(), "release-1");
        assert_eq!(github_latest(&c, &net, "a/bare", false).unwrap(), "v");
        assert!(matches!(github_latest(&c, &net, "a/none", false), Err(Error::Offline(_))));
    }

    #[test]
    fn postgres_table_is_fetched_as_html() {
        let (_d, c) = cache();
        let net = Fake::new(|r| {
            assert_eq!(r.header("Accept"), Some("text/html"));
            Ok(Response::ok("<tr><td>CVE-2026-1</td><td>18</td><td>18.1</td><td>core 7.5 AV:N</td><td>Oops</td></tr>"))
        });
        let got = postgres(&c, &net, false).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].cve.as_str(), got[0].score, got[0].vector.as_str()), ("CVE-2026-1", 7.5, "AV:N"));
        assert_eq!(severity_from_score(9.5), "CRITICAL");
        assert_eq!(severity_from_score(5.0), "MODERATE");
        assert_eq!(severity_from_score(0.5), "LOW");
        assert_eq!(severity_from_score(0.0), "");
    }
}
