//! The sources file (`specs/design/sources-file.md`): every outside source
//! wpantry reads, declared once in `assets/defaults/sources.toml` and
//! compiled in. Where a source lives, how fresh it must be and how much of
//! it is read come from here, not from the code that reads it; `net::HOSTS`
//! is these sources' hosts, and a test fails when the two disagree.

use crate::error::{Error, Result};
use crate::utils::toml::{self, Table, Val};
use std::sync::LazyLock;

/// When a source is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// Every scan.
    Default,
    /// Only with `--deep`.
    Deep,
    /// Never.
    Off,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Default => "default",
            Tier::Deep => "deep",
            Tier::Off => "off",
        }
    }
}

/// How a source is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Through [`crate::utils::net`], to an allowed host only.
    Https,
    /// Cloned or listed by `git`.
    Git,
}

/// One source.
#[derive(Clone, Debug, PartialEq)]
pub struct Source {
    pub id: String,
    pub kind: String,
    pub format: String,
    /// The file, or the API's base; `{}` marks where a request puts its part.
    pub url: String,
    pub transport: Transport,
    /// Other hosts the source sends its downloads to.
    pub redirects: Vec<String>,
    pub tier: Tier,
    /// How stale a copy may be before it is fetched again, in seconds.
    pub refresh: f64,
    pub license: String,
    pub redistribute: bool,
    /// The most of one answer read; 0 when the transport sets its own.
    pub max_bytes: u64,
    /// What a request sends about this machine, "" for nothing.
    pub sends: String,
    /// The consent it is asked under, "" when none is needed.
    pub consent: String,
}

impl Source {
    /// The host a request goes to, for an https source.
    pub fn host(&self) -> Option<String> {
        if self.transport != Transport::Https {
            return None;
        }
        crate::utils::net::host_of(&self.url)
    }
}

/// A duration as the file writes one: `30m`, `12h`, `1d`, `7d`.
pub fn duration(s: &str) -> Option<f64> {
    let s = s.trim();
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: f64 = n.parse().ok()?;
    Some(
        n * match unit {
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86_400.0,
            _ => return None,
        },
    )
}

fn raw(t: &Table, key: &str) -> Option<String> {
    match t.get(key)? {
        Val::Raw(r) => Some(r.split('#').next().unwrap_or("").trim().to_string()),
        Val::Str(_) => None,
    }
}

/// The sources in a file's text: every `[[source]]` table, checked.
pub fn parse(text: &str) -> Result<Vec<Source>> {
    let mut out: Vec<Source> = Vec::new();
    for t in toml::parse(text)?.into_iter().filter(|t| t.array && t.name == "source") {
        let id = t.str("id").to_string();
        let bad = |why: &str| Error::Invalid(format!("source {:?}: {why}", id));
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(bad("an id is kebab-case"));
        }
        if out.iter().any(|s| s.id == id) {
            return Err(bad("listed twice"));
        }
        let transport = match t.str("transport") {
            "" | "https" => Transport::Https,
            "git" => Transport::Git,
            other => return Err(bad(&format!("unknown transport {other:?}"))),
        };
        let tier = match t.str("tier") {
            "" | "default" => Tier::Default,
            "deep" => Tier::Deep,
            "off" => Tier::Off,
            other => return Err(bad(&format!("unknown tier {other:?}"))),
        };
        let url = t.str("url").to_string();
        if transport == Transport::Https && crate::utils::net::host_of(&url).is_none() {
            return Err(bad("an https source needs an https URL"));
        }
        let refresh = match t.str("refresh") {
            "" => 86_400.0,
            r => duration(r).ok_or_else(|| bad(&format!("unreadable refresh {r:?}")))?,
        };
        let max_bytes = match raw(&t, "max_bytes") {
            None => 0,
            Some(n) => n.parse().map_err(|_| bad(&format!("unreadable max_bytes {n:?}")))?,
        };
        let redistribute = match raw(&t, "redistribute").as_deref() {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => return Err(bad(&format!("redistribute is true or false, not {other:?}"))),
        };
        let redirects = match t.get("redirects") {
            Some(Val::Raw(r)) => toml::strings(r),
            _ => Vec::new(),
        };
        out.push(Source {
            id: id.clone(),
            kind: t.str("kind").to_string(),
            format: t.str("format").to_string(),
            url,
            transport,
            redirects,
            tier,
            refresh,
            license: t.str("license").to_string(),
            redistribute,
            max_bytes,
            sends: t.str("sends").to_string(),
            consent: t.str("consent").to_string(),
        });
    }
    Ok(out)
}

static BUNDLED: LazyLock<Vec<Source>> =
    LazyLock::new(|| parse(crate::defaults::SOURCES).expect("the bundled sources file reads (tested)"));

/// The sources wpantry ships with.
pub fn bundled() -> &'static [Source] {
    &BUNDLED
}

/// A bundled source by its id. The ids the code names are tested to exist.
pub fn source(id: &str) -> &'static Source {
    bundled().iter().find(|s| s.id == id).unwrap_or_else(|| panic!("no bundled source {id:?}"))
}

/// A bundled source's URL.
pub fn url(id: &str) -> &'static str {
    &source(id).url
}

/// Every host the bundled https sources reach, their redirects' included.
pub fn hosts() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in bundled().iter().filter(|s| s.transport == Transport::Https) {
        for h in s.host().into_iter().chain(s.redirects.iter().cloned()) {
            if !out.contains(&h) {
                out.push(h);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_file_reads_and_its_hosts_are_the_allowlist() {
        let all = bundled();
        assert!(all.len() >= 20);
        let mut hosts = hosts();
        hosts.sort();
        let mut allowed: Vec<String> = crate::utils::net::HOSTS.iter().map(|h| h.to_string()).collect();
        allowed.sort();
        assert_eq!(hosts, allowed, "net::HOSTS is the bundled sources' hosts, no more and no fewer");
        for s in all {
            assert!(!s.kind.is_empty() && !s.format.is_empty() && !s.license.is_empty(), "{}", s.id);
            assert!(s.transport == Transport::Git || s.max_bytes > 0, "{}: an https source caps what it reads", s.id);
            assert!(s.sends.is_empty() || !s.sends.contains(' '), "{}", s.id);
        }
    }

    #[test]
    fn every_id_the_code_names_is_bundled() {
        let src = [
            include_str!("osv.rs"),
            include_str!("kev.rs"),
            include_str!("endoflife.rs"),
            include_str!("releases.rs"),
            include_str!("distros.rs"),
            include_str!("extensions.rs"),
            include_str!("package_licenses.rs"),
            include_str!("malicious_packages.rs"),
            include_str!("breaches.rs"),
            include_str!("indicator_lists.rs"),
            include_str!("hash_lookups.rs"),
            include_str!("../checks/malware/yara.rs"),
            include_str!("../checks/supply_chain/malicious.rs"),
        ]
        .concat();
        let mut named = 0;
        for part in src.split("url(\"").skip(1) {
            let id = part.split('"').next().unwrap();
            assert!(bundled().iter().any(|s| s.id == id), "{id} is named in the code but not bundled");
            named += 1;
        }
        assert!(named >= 20, "{named}");
    }

    #[test]
    fn a_broken_file_says_what_is_wrong() {
        let one = |body: &str| parse(&format!("[[source]]\n{body}\n"));
        assert!(one("id = \"Bad Id\"\nurl = \"https://a.b/\"").unwrap_err().to_string().contains("kebab-case"));
        assert!(one("id = \"a\"\nurl = \"http://a.b/\"").unwrap_err().to_string().contains("https"));
        assert!(
            one("id = \"a\"\nurl = \"https://a.b/\"\ntier = \"sometimes\"").unwrap_err().to_string().contains("tier")
        );
        assert!(
            one("id = \"a\"\nurl = \"https://a.b/\"\nrefresh = \"soon\"").unwrap_err().to_string().contains("refresh")
        );
        assert!(
            one("id = \"a\"\nurl = \"https://a.b/\"\nmax_bytes = lots").unwrap_err().to_string().contains("max_bytes")
        );
        assert!(
            one("id = \"a\"\nurl = \"https://a.b/\"\nredistribute = maybe")
                .unwrap_err()
                .to_string()
                .contains("redistribute")
        );
        assert!(one("id = \"a\"\nurl = \"\"\ntransport = \"ftp\"").unwrap_err().to_string().contains("transport"));
        let twice = "[[source]]\nid = \"a\"\nurl = \"https://a.b/\"\n[[source]]\nid = \"a\"\nurl = \"https://a.b/\"\n";
        assert!(parse(twice).unwrap_err().to_string().contains("twice"));
        let ok =
            one("id = \"a\"\nurl = \"https://a.b/x\"\nmax_bytes = 10 # ten\nredistribute = true\nrefresh = \"12h\"")
                .unwrap();
        assert_eq!(
            (ok[0].max_bytes, ok[0].redistribute, ok[0].refresh, ok[0].tier),
            (10, true, 43_200.0, Tier::Default)
        );
        assert_eq!(
            (duration("30m"), duration("2s"), duration("1w"), duration("d")),
            (Some(1800.0), Some(2.0), None, None)
        );
    }
}
