//! Fetching a source: a refetch with the copy's ETag, so an unchanged
//! list costs a 304.

use crate::db::Cache;
use crate::error::Result;
use crate::utils::net::{self, Net};

/// Body bytes when a refetch returned new data, else None.
pub(crate) fn etag_fetch(
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
