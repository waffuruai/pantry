//! Fetching a source (`specs/design/sources-file.md`). Every request a
//! source makes goes through here: it reads at most the source's
//! `max_bytes`, a whole-file source is refetched once its copy is older
//! than its `refresh` (with the copy's ETag, so an unchanged file costs a
//! 304) and checked against its `sha256` pin, and every attempt's outcome
//! is kept for `wpantry sources`. A copy that fails its pin, or that its
//! reader refuses ([`rejected`]), is never stored: the last good one stays,
//! and the source is reported unchecked.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::file::{Source, source};
use crate::utils::json;
use crate::utils::net::{self, Net, Response};
use rusqlite::params;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS source_state (
  id TEXT PRIMARY KEY, attempt REAL, success REAL, error TEXT, bytes INTEGER);
";

/// What became of a source's requests: when it was last asked, last
/// answered, what last went wrong ("" when the last attempt worked), and
/// how many bytes its last answer was.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct State {
    pub attempt: f64,
    pub success: f64,
    pub error: String,
    pub bytes: u64,
}

/// This process's outcomes, written by [`save`].
static SEEN: LazyLock<Mutex<HashMap<String, State>>> = LazyLock::new(Default::default);

/// Keep one outcome: the bytes an answer had, or why there was none.
pub fn record(id: &str, outcome: std::result::Result<u64, String>) {
    let now = crate::utils::os::now();
    let mut seen = SEEN.lock().expect("lock");
    let s = seen.entry(id.to_string()).or_default();
    s.attempt = now;
    match outcome {
        Ok(bytes) => {
            s.success = now;
            s.error.clear();
            s.bytes = bytes;
        }
        Err(why) => s.error = why,
    }
}

/// A source's reader refused what came (a parse error): the last good copy
/// stays, and `wpantry sources` says why.
pub fn rejected(id: &str, why: &str) {
    record(id, Err(format!("rejected: {why}")));
}

/// The error for a copy `id`'s reader refused, the refusal kept: a
/// memoised source then falls back to its last good copy.
pub fn invalid(id: &str, why: &str) -> Error {
    rejected(id, why);
    Error::Invalid(format!("{id}: {why}"))
}

/// Keep `result`'s outcome for `id`, for sources fetched by other means (git).
pub fn note<T>(id: &str, result: &Result<T>) {
    match result {
        Ok(_) => record(id, Ok(0)),
        Err(e) if e.is_source() => record(id, Err(e.to_string())),
        Err(_) => {}
    }
}

fn kept<T>(id: &str, result: Result<T>, bytes: impl Fn(&T) -> u64) -> Result<T> {
    match &result {
        Ok(r) => record(id, Ok(bytes(r))),
        Err(e) if e.is_source() => record(id, Err(e.to_string())),
        Err(_) => {}
    }
    result
}

/// [`net::request`] for source `id`: its cap, its outcome kept.
pub fn request(
    net: &dyn Net,
    id: &str,
    url: &str,
    data: Option<&Value>,
    headers: &[(&str, &str)],
    etag: Option<&str>,
) -> Result<Response> {
    let s = source(id);
    kept(id, net::request_capped(net, url, data, headers, etag, s.max_bytes), |r| r.body.len() as u64)
}

/// [`net::get_json`] for source `id`.
pub fn get_json(net: &dyn Net, id: &str, url: &str, headers: &[(&str, &str)]) -> Result<Option<Value>> {
    let resp = request(net, id, url, None, headers, None)?;
    if resp.status == 404 {
        return Ok(None);
    }
    let parsed = json::parse(&resp.body, json::MAX_DOCUMENT);
    if let Err(e) = &parsed {
        rejected(id, &e.to_string());
    }
    parsed.map(Some)
}

/// [`net::post_json`] for source `id`.
pub fn post_json(net: &dyn Net, id: &str, url: &str, data: &Value) -> Result<Value> {
    let resp = request(net, id, url, Some(data), &[], None)?;
    let parsed = json::parse(&resp.body, json::MAX_DOCUMENT);
    if let Err(e) = &parsed {
        rejected(id, &e.to_string());
    }
    parsed
}

/// A whole-file source's new copy, when it is due (older than its
/// `refresh`) and changed (not a 304) and passes its pin; None otherwise,
/// and when the source can't be reached (the last copy stays). `key` names
/// the copy's freshness in the cache.
pub fn file(cache: &Cache, net: &dyn Net, id: &str, key: &str, offline: bool) -> Result<Option<Vec<u8>>> {
    file_of(cache, net, source(id), key, offline)
}

pub(crate) fn file_of(cache: &Cache, net: &dyn Net, s: &Source, key: &str, offline: bool) -> Result<Option<Vec<u8>>> {
    if offline || cache.fresh(&format!("{key}_at"), s.refresh)? {
        return Ok(None);
    }
    let etag = cache.get(&format!("{key}_etag"))?;
    let resp = match net::request_capped(net, &s.url, None, &[], etag.as_deref(), s.max_bytes) {
        Ok(r) => r,
        Err(e) if e.is_source() => {
            record(&s.id, Err(e.to_string()));
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    cache.touch(&format!("{key}_at"))?;
    if resp.status != 200 {
        record(&s.id, Ok(0));
        return Ok(None);
    }
    if !s.sha256.is_empty() && crate::utils::sha256::hex(&resp.body) != s.sha256 {
        record(&s.id, Err(format!("rejected: {} doesn't match its sha256 pin", s.url)));
        return Ok(None);
    }
    record(&s.id, Ok(resp.body.len() as u64));
    if let Some(e) = &resp.etag {
        cache.set(&format!("{key}_etag"), e)?;
    }
    Ok(Some(resp.body))
}

/// [`Cache::memo`] for source `id`, fresh for its `refresh`.
pub fn memo(
    cache: &Cache,
    id: &str,
    key: &str,
    compute: impl FnOnce() -> Result<Value>,
    fingerprint: &str,
    refresh: bool,
    offline: bool,
) -> Result<Value> {
    cache.memo(key, compute, source(id).refresh, fingerprint, refresh, offline)
}

/// Write this process's outcomes for the sources the file declares into the
/// cache: an attempt that failed keeps the last success it had.
pub fn save(cache: &Cache) -> Result<()> {
    save_matching(cache, |id| crate::sources::file::bundled().iter().any(|s| s.id == id))
}

/// [`save`], for the ids `keep` picks.
pub(crate) fn save_matching(cache: &Cache, keep: impl Fn(&str) -> bool) -> Result<()> {
    let seen: Vec<(String, State)> = {
        let mut all = SEEN.lock().expect("lock");
        let ids: Vec<String> = all.keys().filter(|id| keep(id)).cloned().collect();
        ids.into_iter().filter_map(|id| all.remove_entry(&id)).collect()
    };
    for (id, s) in seen {
        cache.conn.execute(
            "INSERT INTO source_state VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET \
             attempt = excluded.attempt, error = excluded.error, \
             success = CASE WHEN excluded.success > 0 THEN excluded.success ELSE source_state.success END, \
             bytes = CASE WHEN excluded.success > 0 THEN excluded.bytes ELSE source_state.bytes END",
            params![id, s.attempt, s.success, s.error, s.bytes as i64],
        )?;
    }
    cache.commit()
}

/// One source as `wpantry sources` lists it: what the file says, and what
/// its fetches came to.
#[derive(Clone, Debug, PartialEq)]
pub struct Listed {
    pub source: Source,
    pub state: State,
    /// Fetched within its `refresh`.
    pub fresh: bool,
}

/// Every source, in the file's order, with its kept state.
pub fn listing(cache: &Cache) -> Result<Vec<Listed>> {
    listing_of(cache, crate::sources::file::bundled())
}

pub(crate) fn listing_of(cache: &Cache, sources: &[Source]) -> Result<Vec<Listed>> {
    let states = states(cache)?;
    let now = crate::utils::os::now();
    Ok(sources
        .iter()
        .map(|s| {
            let state = states.get(&s.id).cloned().unwrap_or_default();
            let fresh = state.success > 0.0 && now - state.success < s.refresh;
            Listed { source: s.clone(), state, fresh }
        })
        .collect())
}

/// Every source's kept state, by id.
pub fn states(cache: &Cache) -> Result<HashMap<String, State>> {
    let mut stmt = cache.conn.prepare("SELECT id, attempt, success, error, bytes FROM source_state")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            State {
                attempt: r.get::<_, Option<f64>>(1)?.unwrap_or(0.0),
                success: r.get::<_, Option<f64>>(2)?.unwrap_or(0.0),
                error: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                bytes: r.get::<_, Option<i64>>(4)?.unwrap_or(0) as u64,
            },
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::file::parse;
    use crate::sources::testing::cache;
    use crate::utils::net::Fake;

    fn one(body: &str) -> Source {
        parse(&format!("[[source]]\nid = \"t\"\nurl = \"https://api.osv.dev/x\"\n{body}\n")).unwrap().remove(0)
    }

    #[test]
    fn a_file_is_refetched_when_due_and_pinned_and_capped() {
        let (_d, c) = cache();
        let net = Fake::new(|_| Ok(Response::ok("hello")));
        let s = one("max_bytes = 100\nrefresh = \"1d\"");
        assert_eq!(file_of(&c, &net, &s, "t", false).unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(file_of(&c, &net, &s, "t", false).unwrap(), None, "fresh: not asked again");
        assert_eq!(net.requests().len(), 1);
        let pinned = one(&format!("max_bytes = 100\nsha256 = \"{}\"", "0".repeat(64)));
        c.unset("p_at").unwrap();
        assert_eq!(file_of(&c, &net, &pinned, "p", false).unwrap(), None, "a copy that fails its pin isn't kept");
        let good = one(&format!("max_bytes = 100\nsha256 = \"{}\"", crate::utils::sha256::hex(b"hello")));
        assert!(file_of(&c, &net, &good, "g", false).unwrap().is_some());
        let small = one("max_bytes = 3");
        assert_eq!(
            file_of(&c, &net, &small, "s", false).unwrap(),
            None,
            "over its cap: unreachable, the last copy stays"
        );
        assert_eq!(file_of(&c, &net, &s, "o", true).unwrap(), None, "offline asks nothing");
    }

    #[test]
    fn the_listing_is_every_source_with_its_state() {
        let (_d, c) = cache();
        record("t-listed", Ok(10));
        save_matching(&c, |id| id == "t-listed").unwrap();
        let sources = parse(
            "[[source]]\nid = \"t-listed\"\nurl = \"https://a.b/\"\n[[source]]\nid = \"t-never\"\nurl = \"https://a.b/\"\n",
        )
        .unwrap();
        let all = listing_of(&c, &sources).unwrap();
        assert_eq!(
            all.iter().map(|l| (l.source.id.as_str(), l.fresh, l.state.bytes)).collect::<Vec<_>>(),
            [("t-listed", true, 10), ("t-never", false, 0)]
        );
        assert_eq!(listing(&c).unwrap().len(), crate::sources::file::bundled().len());
    }

    #[test]
    fn outcomes_are_kept_and_a_failure_keeps_the_last_success() {
        let (_d, c) = cache();
        record("t-ok", Ok(5));
        save_matching(&c, |id| id.starts_with("t-")).unwrap();
        let first = states(&c).unwrap()["t-ok"].clone();
        assert!(first.success > 0.0 && first.error.is_empty() && first.bytes == 5);
        rejected("t-ok", "garbage");
        save_matching(&c, |id| id.starts_with("t-")).unwrap();
        let after = states(&c).unwrap()["t-ok"].clone();
        assert_eq!((after.success, after.bytes), (first.success, 5), "the last success stays");
        assert_eq!(after.error, "rejected: garbage");
        note::<()>("t-git", &Err(Error::Offline("no network".into())));
        let e = invalid("t-bad", "no rows");
        assert!(matches!(e, Error::Invalid(m) if m == "t-bad: no rows"));
        save_matching(&c, |id| id.starts_with("t-")).unwrap();
        let all = states(&c).unwrap();
        assert_eq!((all["t-git"].success, all["t-git"].error.as_str()), (0.0, "no network"));
        assert_eq!(all["t-bad"].error, "rejected: no rows");
    }
}
