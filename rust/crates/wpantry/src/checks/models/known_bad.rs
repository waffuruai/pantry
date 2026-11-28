//! The known-bad model list: hub repo ids and file SHA-256s, bundled in
//! `assets/defaults/known-bad-models.toml` and matched with no network. A
//! row added there is matched without a code change. The user's own
//! indicator lists are consulted for the hashes too, when the malware scan
//! loaded them ([`crate::sources::indicator_store`]).
//!
//! ```
//! use wpantry::checks::models::known_bad::List;
//! let list = List::parse("source = \"test\"\nrepos = [\"Org/Bad\"]\nsha256 = []\n");
//! assert!(list.repo("org/bad").is_some());
//! assert!(list.repo("org/good").is_none());
//! ```

use crate::sources::indicator_store::{Kind, Store, key};

/// The list, parsed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct List {
    pub source: String,
    repos: Vec<String>,
    hashes: Vec<String>,
}

impl List {
    /// The list in `text` (TOML); an unreadable one is empty.
    pub fn parse(text: &str) -> List {
        let get = |k| crate::utils::toml::list(text, "", k).unwrap_or_default();
        List {
            source: get("source").into_iter().next().unwrap_or_else(|| "the known-bad model list".into()),
            repos: get("repos").iter().map(|r| r.trim().to_ascii_lowercase()).collect(),
            hashes: get("sha256").iter().map(|h| h.trim().to_ascii_lowercase()).collect(),
        }
    }

    /// The bundled list.
    pub fn bundled() -> List {
        List::parse(crate::defaults::KNOWN_BAD_MODELS)
    }

    /// The entry naming hub repo `id`, matched without regard to case.
    pub fn repo(&self, id: &str) -> Option<String> {
        let id = id.trim().to_ascii_lowercase();
        self.repos.iter().find(|r| **r == id).map(|r| format!("repo {r} on {}", self.source))
    }

    /// The entry naming this SHA-256.
    pub fn hash(&self, sha256: &str) -> Option<String> {
        let h = sha256.to_ascii_lowercase();
        self.hashes.iter().find(|x| **x == h).map(|x| format!("SHA-256 {x} on {}", self.source))
    }

    pub fn len(&self) -> usize {
        self.repos.len() + self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What the user's indicator lists say of this SHA-256, if anything.
pub fn in_store(store: &Store, sha256: &str) -> Option<String> {
    if store.is_empty() {
        return None;
    }
    let f = store.get(key(Kind::Hash, &sha256.to_ascii_lowercase()))?;
    let what = if f.what.is_empty() { "a known-bad file" } else { f.what };
    Some(format!("SHA-256 {} on {} ({what})", f.value, f.origin.source))
}

#[cfg(test)]
#[path = "known_bad_tests.rs"]
mod tests;
