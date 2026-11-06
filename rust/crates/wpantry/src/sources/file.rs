//! The sources file (`specs/design/sources-file.md`): every outside source
//! wpantry reads, declared once in `assets/defaults/sources.toml` and
//! compiled in. Where a source lives, how fresh it must be and how much of
//! it is read come from here, not from the code that reads it; `net::HOSTS`
//! is these sources' hosts, and a test fails when the two disagree.

use crate::error::{Error, Result};
use crate::utils::toml::{self, Table, Val};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, RwLock};

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
    /// A pin: the SHA-256 a fixed file must have, "" for none.
    pub sha256: String,
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
    Ok(entries(text)?.into_iter().map(|(s, _)| s).collect())
}

/// Each source in a file's text, with the keys its entry set.
fn entries(text: &str) -> Result<Vec<(Source, Vec<String>)>> {
    let mut out: Vec<(Source, Vec<String>)> = Vec::new();
    for t in toml::parse(text)?.into_iter().filter(|t| t.array && t.name == "source") {
        let id = t.str("id").to_string();
        let bad = |why: &str| Error::Invalid(format!("source {:?}: {why}", id));
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(bad("an id is kebab-case"));
        }
        if out.iter().any(|(s, _)| s.id == id) {
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
        let keys: Vec<String> = t.entries.iter().map(|(k, _)| k.clone()).collect();
        if transport == Transport::Https
            && (keys.contains(&"url".to_string()) || !url.is_empty())
            && crate::utils::net::host_of(&url).is_none()
        {
            return Err(bad("an https source needs an https URL"));
        }
        let pin = t.str("sha256");
        if !pin.is_empty() && !(pin.len() == 64 && pin.chars().all(|c| c.is_ascii_hexdigit())) {
            return Err(bad("a sha256 pin is 64 hex digits"));
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
        out.push((
            Source {
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
                sha256: t.str("sha256").to_ascii_lowercase(),
            },
            keys,
        ));
    }
    Ok(out)
}

static BUNDLED: LazyLock<Vec<Source>> =
    LazyLock::new(|| parse(crate::defaults::SOURCES).expect("the bundled sources file reads (tested)"));

/// Where the user's own Pantry files live: `$XDG_CONFIG_HOME/wpantry`, or
/// `~/.config/wpantry`.
pub fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::utils::files::home().join(".config"))
        .join("wpantry")
}

/// The user's sources file: `sources.toml` in [`config_dir`].
pub fn user_file() -> PathBuf {
    config_dir().join("sources.toml")
}

/// The kinds and formats a user's source may have: what wpantry can read
/// and use with no code of the user's own.
const USER_FORMATS: &[(&str, &[&str])] = &[
    ("yara", &["yara"]),
    ("hashes", &["lines"]),
    ("hosts", &["lines"]),
    ("filenames", &["lines"]),
    ("indicators", &["maltrail-csv"]),
    ("advisories", &["osv-api"]),
    ("hash-lookup", &["circl", "yaraify"]),
];

/// The sources in effect: the bundled ones with the user's tiers, then the
/// user's own, checked against what a user's source may be and do.
pub fn merged(user_text: &str) -> Result<Vec<Source>> {
    let mut all: Vec<Source> = bundled().to_vec();
    for (mut s, keys) in entries(user_text)? {
        let bad = |why: &str| Error::Invalid(format!("your sources file, source {:?}: {why}", s.id));
        if let Some(b) = all.iter_mut().find(|b| b.id == s.id) {
            if keys.iter().any(|k| k != "id" && k != "tier") {
                return Err(bad(
                    "a bundled source's only setting is its tier; a different URL is a different source, with its own id",
                ));
            }
            b.tier = s.tier;
            continue;
        }
        let formats = USER_FORMATS.iter().find(|(k, _)| *k == s.kind).map(|(_, f)| *f);
        match formats {
            None => {
                return Err(bad(&format!(
                    "kind {:?} can't be a source of yours (yara, hashes, hosts, filenames, indicators, advisories, hash-lookup)",
                    s.kind
                )));
            }
            Some(f) if !f.contains(&s.format.as_str()) => {
                return Err(bad(&format!("a {} source's format is {}", s.kind, f.join(" or "))));
            }
            _ => {}
        }
        if s.transport != Transport::Https || s.host().is_none() {
            return Err(bad("a source of yours is fetched over https"));
        }
        match (s.kind.as_str(), s.sends.as_str()) {
            ("hash-lookup", "sha256") => s.consent = format!("source:{}", s.id),
            ("hash-lookup", _) => {
                return Err(bad("a hash lookup of yours sends a SHA-256 and nothing else: sends = \"sha256\""));
            }
            (_, "") => {}
            _ => return Err(bad("only a hash lookup sends anything, and only a SHA-256")),
        }
        if s.max_bytes == 0 || s.max_bytes > crate::utils::net::MAX_BODY {
            s.max_bytes = crate::utils::net::MAX_BODY;
        }
        s.redistribute = false;
        s.redirects.clear();
        all.push(s);
    }
    Ok(all)
}

/// The sources in effect for this run, and the ids of the user's own.
#[derive(Clone, Debug, Default)]
pub struct Effective {
    pub sources: Vec<Source>,
    pub user: Vec<String>,
    pub deep: bool,
}

static EFFECTIVE: LazyLock<RwLock<Arc<Effective>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Effective { sources: bundled().to_vec(), user: Vec::new(), deep: false })));

/// Use the user's sources (`user_text`, the file's text) and `deep` for
/// this run. A file that can't be used leaves the bundled sources in effect
/// and says why.
pub fn configure(user_text: Option<&str>, deep: bool) -> Result<()> {
    let merged = match user_text {
        Some(t) => merged(t),
        None => Ok(bundled().to_vec()),
    };
    let (sources, err) = match merged {
        Ok(s) => (s, None),
        Err(e) => (bundled().to_vec(), Some(e)),
    };
    let user = sources.iter().filter(|s| !bundled().iter().any(|b| b.id == s.id)).map(|s| s.id.clone()).collect();
    *EFFECTIVE.write().expect("lock") = Arc::new(Effective { sources, user, deep });
    err.map_or(Ok(()), Err)
}

/// Turn `id` off for the rest of this run (a source of the user's that
/// wasn't said yes to).
pub fn turn_off(id: &str) {
    let mut e = EFFECTIVE.write().expect("lock");
    let mut next = (**e).clone();
    if let Some(s) = next.sources.iter_mut().find(|s| s.id == id) {
        s.tier = Tier::Off;
    }
    *e = Arc::new(next);
}

/// The sources in effect.
pub fn effective() -> Arc<Effective> {
    EFFECTIVE.read().expect("lock").clone()
}

/// A source in effect by id.
pub fn find(id: &str) -> Option<Source> {
    effective().sources.iter().find(|s| s.id == id).cloned()
}

/// Whether a source is used this run: its tier is default, or deep with `--deep`.
pub fn active(id: &str) -> bool {
    let e = effective();
    e.sources.iter().find(|s| s.id == id).is_some_and(|s| match s.tier {
        Tier::Default => true,
        Tier::Deep => e.deep,
        Tier::Off => false,
    })
}

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
#[path = "file_tests.rs"]
mod tests;
