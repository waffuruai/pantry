//! Self-hosted servers that run as a container, read from the images behind
//! running containers ([`catalog::IMAGES`]): `metabase/metabase:v0.50.3`
//! is Metabase 0.50.3. The image's tag is the only thing read; nothing is
//! pulled, started or exported. Servers with a binary (FreeSWITCH,
//! UnrealIRCd) are catalog tools.
//!
//! Example: a running `docker.io/metabase/metabase:v0.64.2` becomes the
//! `metabase` component, version 0.64.2, which endoflife.date's `metabase`
//! 0.64 line then judges like any catalog tool.
//!
//! TODO: Metabase Enterprise (`metabase/metabase-enterprise`, `v1.x` tags)
//! once a source numbers its releases that way; endoflife.date uses 0.x.

use crate::checks::machine::apps::running_images;
use crate::checks::machine::catalog::IMAGES;
use crate::component::Component;
use crate::utils::re::Regex;

/// Registry hosts that name Docker Hub, so `docker.io/metabase/metabase`
/// is `metabase/metabase`.
const HUB: &[&str] = &["docker.io/", "index.docker.io/", "registry-1.docker.io/"];

/// (repository, tag) of an image reference, the tag "" when it has none;
/// a digest (`@sha256:…`) is dropped.
pub fn split(r: &str) -> (String, String) {
    let r = r.split('@').next().unwrap_or("");
    let r = HUB.iter().find_map(|h| r.strip_prefix(h)).unwrap_or(r);
    let slash = r.rfind('/').map_or(0, |i| i + 1);
    match r[slash..].rfind(':') {
        Some(i) => (r[..slash + i].to_string(), r[slash + i + 1..].to_string()),
        None => (r.to_string(), String::new()),
    }
}

/// The catalog servers among image references.
pub fn from_images(refs: &[String]) -> Vec<Component> {
    let mut out: Vec<Component> = Vec::new();
    for r in refs {
        let (repo, tag) = split(r);
        let Some((image, name, pattern, (product, cycle))) = IMAGES.iter().find(|(i, ..)| *i == repo) else {
            continue;
        };
        let Some(m) = Regex::new(pattern).search(&tag) else { continue };
        let v = m.get(1).to_string();
        if out.iter().any(|c| c.name == *name && c.version == v) {
            continue;
        }
        let mut c = Component::new("tool", name, &v, r);
        c.eol = Some((product.to_string(), cycle.of(&v)));
        c.fix = format!("docker pull {image}:v{{safe}}, then recreate its containers");
        out.push(c);
    }
    out
}

/// The catalog servers running in containers here (nothing without Docker).
pub fn servers() -> Vec<Component> {
    from_images(&running_images())
}

#[cfg(test)]
#[path = "servers_tests.rs"]
mod tests;
