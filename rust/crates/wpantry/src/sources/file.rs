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

    /// How much checking a tier gives, the order the variants are declared
    /// in read the other way round: `Default` (every scan) is the most,
    /// `Deep` (only with `--deep`) less, `Off` (never) none.
    fn checking(self) -> u8 {
        match self {
            Tier::Default => 2,
            Tier::Deep => 1,
            Tier::Off => 0,
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
    /// Read from a file or folder on this machine (`path = "..."`, a source
    /// of the user's own only): it contacts nobody.
    Local,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Https => "https",
            Transport::Git => "git",
            Transport::Local => "local",
        }
    }
}

/// One source.
#[derive(Clone, Debug, PartialEq)]
pub struct Source {
    pub id: String,
    pub kind: String,
    pub format: String,
    /// The file, or the API's base; `{}` marks where a request puts its part.
    /// For a [`Transport::Local`] source, its `path` as written
    /// ([`local_path`] resolves it).
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

/// Whether a local source's `path` is one wpantry reads: absolute (`/…`,
/// `C:\…`, `\\server\…`) or under the home folder (`~/…`), with no `..`
/// part. Checked as text, so a file written for one system reads on any;
/// [`local_path`] then refuses a path that isn't absolute where it runs.
fn path_shape(p: &str) -> std::result::Result<(), &'static str> {
    if p.is_empty() {
        return Err("a path is not empty");
    }
    if p.split(['/', '\\']).any(|part| part == "..") {
        return Err("a path has no .. part");
    }
    let b = p.as_bytes();
    let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/');
    if p.starts_with('/') || p.starts_with("~/") || p.starts_with(r"\\") || drive {
        Ok(())
    } else {
        Err("a path is absolute, or starts with ~/ for your home folder")
    }
}

/// Where a local source is read: its path with `~/` taken as the home
/// folder. A path that isn't absolute on this system (`C:\…` on macOS) is
/// refused rather than read from the current folder.
///
/// ```ignore
/// // path = "~/rules/team" reads $HOME/rules/team
/// ```
pub fn local_path(s: &Source) -> Result<PathBuf> {
    let p = match s.url.strip_prefix("~/") {
        Some(rest) => crate::utils::files::home().join(rest),
        None => PathBuf::from(&s.url),
    };
    if !p.is_absolute() {
        return Err(Error::Invalid(format!("source {:?}: {} is not an absolute path on this system", s.id, s.url)));
    }
    Ok(p)
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
        let has = |k: &str| t.entries.iter().any(|(n, _)| n == k);
        let transport = match (t.str("transport"), has("path")) {
            ("" | "local", true) => Transport::Local,
            (_, true) => return Err(bad("a source with a path is read on this machine: its transport is local")),
            ("local", false) => return Err(bad("a local source gives its path")),
            ("" | "https", false) => Transport::Https,
            ("git", false) => Transport::Git,
            (other, false) => return Err(bad(&format!("unknown transport {other:?}"))),
        };
        if transport == Transport::Local {
            if has("url") {
                return Err(bad("a source gives a url or a path, not both"));
            }
            path_shape(t.str("path")).map_err(&bad)?;
        }
        let tier = match t.str("tier") {
            "" | "default" => Tier::Default,
            "deep" => Tier::Deep,
            "off" => Tier::Off,
            other => return Err(bad(&format!("unknown tier {other:?}"))),
        };
        let url = if transport == Transport::Local { t.str("path") } else { t.str("url") }.to_string();
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

/// The sources files of a run, as `(name, text)`: the user's own (`main`,
/// else [`user_file`] when it exists), then each of `added`
/// (`--add-sources FILE`) in order. A file named on the command line that
/// can't be read is an error, `(name, why)`; only the default file may be
/// missing.
pub fn read_files(
    main: Option<&std::path::Path>,
    added: &[PathBuf],
) -> std::result::Result<Vec<(String, String)>, (String, String)> {
    let mut out = Vec::new();
    let path = main.map(std::path::Path::to_path_buf).unwrap_or_else(user_file);
    match std::fs::read_to_string(&path) {
        Ok(t) => out.push((USER_FILE_NAME.to_string(), t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && main.is_none() => {}
        Err(e) => return Err((USER_FILE_NAME.to_string(), format!("{}: {e}", path.display()))),
    }
    for p in added {
        let name = added_name(p);
        match std::fs::read_to_string(p) {
            Ok(t) => out.push((name, t)),
            Err(e) => return Err((name, format!("{}: {e}", p.display()))),
        }
    }
    Ok(out)
}

/// What an added sources file is called in messages.
pub fn added_name(p: &std::path::Path) -> String {
    format!("the added sources file {}", p.display())
}

/// The kinds and formats a user's source may have: what wpantry can read
/// and use with no code of the user's own.
const USER_FORMATS: &[(&str, &[&str])] = &[
    ("yara", &["yara"]),
    ("hashes", &["lines"]),
    ("hosts", &["lines"]),
    ("filenames", &["lines"]),
    ("indicators", &["maltrail-csv"]),
    ("advisories", &["osv-api", "osv-dir"]),
    ("hash-lookup", &["circl", "yaraify"]),
];

/// The kinds a local source (`path = …`) may have: the ones kept as a file
/// ([`crate::sources::user`]), read into that file instead of fetched, and
/// advisories as a folder of OSV records (`format = "osv-dir"`,
/// [`crate::sources::osv_dir`]).
const LOCAL_KINDS: &[&str] = &["yara", "hashes", "hosts", "filenames", "indicators", "advisories"];

/// The format of a folder of OSV records on this machine.
pub const OSV_DIR: &str = "osv-dir";

/// What the user's sources file is called in messages.
pub const USER_FILE_NAME: &str = "your sources file";

/// The sources in effect: the bundled ones with the user's tiers, then the
/// user's own, checked against what a user's source may be and do.
pub fn merged(user_text: &str) -> Result<Vec<Source>> {
    merged_files(&[(USER_FILE_NAME.to_string(), user_text.to_string())])
}

/// [`merged`] over several sources files, as `(name, text)` in order: the
/// user's own, then each `--add-sources FILE`. An id one file defines can't
/// be defined again by a later one. The user's own file (named
/// [`USER_FILE_NAME`]) may set any bundled source's tier, the last file to
/// set it winning; an added file may only turn one up (more checking:
/// `off` to `deep` or `default`, `deep` to `default`), because a flag that
/// adds sources must not make a run check less. An entry in an added file
/// that would lower or disable a bundled source refuses the whole file.
pub fn merged_files(files: &[(String, String)]) -> Result<Vec<Source>> {
    let mut all: Vec<Source> = bundled().to_vec();
    // The file each of the user's own ids came from.
    let mut defined: Vec<(String, String)> = Vec::new();
    for (name, text) in files {
        // A file is applied whole or not at all: work on copies and keep
        // them only when every entry of the file was accepted.
        let (mut next, mut next_defined) = (all.clone(), defined.clone());
        merge_one(&mut next, &mut next_defined, name, text)?;
        (all, defined) = (next, next_defined);
    }
    Ok(all)
}

fn merge_one(all: &mut Vec<Source>, defined: &mut Vec<(String, String)>, name: &str, text: &str) -> Result<()> {
    let parsed = entries(text).map_err(|e| Error::Invalid(format!("{name}: {e}")))?;
    let added = name != USER_FILE_NAME;
    for (mut s, keys) in parsed {
        let bad = |why: &str| Error::Invalid(format!("{name}, source {:?}: {why}", s.id));
        if let Some(b) = all.iter_mut().find(|b| b.id == s.id && bundled().iter().any(|x| x.id == s.id)) {
            if keys.iter().any(|k| k != "id" && k != "tier") {
                return Err(bad(
                    "a bundled source's only setting is its tier; a different URL is a different source, with its own id",
                ));
            }
            if added && s.tier.checking() < b.tier.checking() {
                return Err(bad(&format!(
                    "--add-sources adds sources and may only turn a bundled source up, never down or off \
                     (it is {} and this file sets {}); set it in your own sources file instead",
                    b.tier.as_str(),
                    s.tier.as_str()
                )));
            }
            b.tier = s.tier;
            continue;
        }
        if let Some((_, first)) = defined.iter().find(|(id, _)| *id == s.id) {
            return Err(Error::Invalid(format!(
                "source {:?} is defined in {first} and again in {name}: an id names one source",
                s.id
            )));
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
        // A folder of OSV records is read on this machine, and advisories on
        // this machine come only as such a folder.
        if s.format == OSV_DIR && s.transport != Transport::Local {
            return Err(bad("an osv-dir source is a folder on this machine: it gives a path, not a url"));
        }
        if s.kind == "advisories" && s.transport == Transport::Local && s.format != OSV_DIR {
            return Err(bad("an advisories source with a path is a folder of OSV records: format = \"osv-dir\""));
        }
        if s.transport == Transport::Local {
            if !LOCAL_KINDS.contains(&s.kind.as_str()) {
                return Err(bad(&format!(
                    "a {} source is fetched over https; a path is for {}",
                    s.kind,
                    LOCAL_KINDS.join(", ")
                )));
            }
        } else if s.transport == Transport::Https && s.url.is_empty() && !keys.iter().any(|k| k == "url") {
            return Err(bad("a source of yours gives a url (https) or a path on this machine"));
        } else if s.transport != Transport::Https || s.host().is_none() {
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
        defined.push((s.id.clone(), name.to_string()));
        all.push(s);
    }
    Ok(())
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
    let files: Vec<(String, String)> =
        user_text.map(|t| (USER_FILE_NAME.to_string(), t.to_string())).into_iter().collect();
    configure_files(&files, deep)
}

/// [`configure`] with several sources files, as `(name, text)`
/// ([`merged_files`], [`read_files`]).
pub fn configure_files(files: &[(String, String)], deep: bool) -> Result<()> {
    let merged = merged_files(files);
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
    used(id, effective().deep)
}

/// Whether a source is used by a `--deep` scan, whatever this run is: its
/// tier is default or deep. For a read that reports what `--deep` would
/// use (`wpantry rules` counts every rule), so it reads what a deep scan
/// does and the two share one compiled copy.
pub fn active_when_deep(id: &str) -> bool {
    used(id, true)
}

fn used(id: &str, deep: bool) -> bool {
    #[cfg(test)]
    if TEST_ON.with(|on| on.borrow().iter().any(|x| x == id)) {
        return true;
    }
    let e = effective();
    e.sources.iter().find(|s| s.id == id).is_some_and(|s| match s.tier {
        Tier::Default => true,
        Tier::Deep => deep,
        Tier::Off => false,
    })
}

#[cfg(test)]
thread_local! {
    static TEST_ON: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Turn the sources `ids` on for this test's thread only (the sources in
/// effect are the process's, shared by every test); empty turns them back.
#[cfg(test)]
pub fn set_test_on(ids: &[&str]) {
    TEST_ON.with(|on| *on.borrow_mut() = ids.iter().map(|s| s.to_string()).collect());
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
