//! The known-bad model list, bundled in
//! `assets/defaults/known-bad-models.toml` and matched with no network. A
//! row added there is matched without a code change. Each list has its
//! level:
//!
//! - `repos` (fail): Hugging Face repo ids that published a malicious model,
//!   file or chat template, matched without regard to case;
//! - `sha256` (fail): model files' SHA-256s, where the store's layout gives
//!   them;
//! - `ollama` (fail): Ollama models (`namespace/model`), any tag;
//! - `owners` (warn): accounts behind confirmed malicious models; any other
//!   repo of theirs is worth a look, but isn't known to be bad;
//! - `demos` (warn): public proofs of concept and deliberately backdoored
//!   models.
//!
//! The user's own indicator lists are consulted for the hashes too, when
//! the malware scan loaded them ([`crate::sources::indicator_store`]).
//!
//! ```
//! use wpantry::checks::models::known_bad::List;
//! let list = List::parse("source = \"test\"\nrepos = [\"Org/Bad\"]\nowners = [\"Org\"]\n");
//! assert!(list.repo("org/bad").is_some());
//! assert!(list.repo("org/good").is_none());
//! assert!(list.owner("Org/good").is_some());
//! ```

use crate::sources::indicator_store::{Kind, Store, key};

/// The list, parsed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct List {
    pub source: String,
    pub repos: Vec<String>,
    pub hashes: Vec<String>,
    pub ollama: Vec<String>,
    pub owners: Vec<String>,
    pub demos: Vec<String>,
}

impl List {
    /// The list in `text` (TOML); an unreadable one is empty.
    pub fn parse(text: &str) -> List {
        let get = |k| -> Vec<String> {
            crate::utils::toml::list(text, "", k)
                .unwrap_or_default()
                .iter()
                .map(|r| r.trim().to_ascii_lowercase())
                .filter(|r| !r.is_empty())
                .collect()
        };
        List {
            source: crate::utils::toml::list(text, "", "source")
                .unwrap_or_default()
                .into_iter()
                .next()
                .unwrap_or_else(|| "the known-bad model list".into()),
            repos: get("repos"),
            hashes: get("sha256"),
            ollama: get("ollama"),
            owners: get("owners"),
            demos: get("demos"),
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

    /// The entry naming an Ollama model (`namespace/model[:tag]`; the tag
    /// doesn't matter).
    pub fn ollama(&self, name: &str) -> Option<String> {
        let n = name.trim().to_ascii_lowercase();
        let n = n.rsplit_once(':').map_or(n.as_str(), |(m, _)| m);
        self.ollama.iter().find(|x| *x == n).map(|x| format!("Ollama model {x} on {}", self.source))
    }

    /// The account of hub repo `id`, when it published confirmed malicious
    /// models.
    pub fn owner(&self, id: &str) -> Option<String> {
        let id = id.trim().to_ascii_lowercase();
        let (owner, _) = id.split_once('/')?;
        self.owners.iter().find(|o| *o == owner).cloned()
    }

    /// The entry naming hub repo `id` as a published attack demonstration.
    pub fn demo(&self, id: &str) -> Option<String> {
        let id = id.trim().to_ascii_lowercase();
        self.demos.iter().find(|r| **r == id).cloned()
    }

    pub fn len(&self) -> usize {
        self.repos.len() + self.hashes.len() + self.ollama.len() + self.owners.len() + self.demos.len()
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
