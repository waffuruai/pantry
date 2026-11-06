//! Identifiers written to bait a model into calling them. The terms are
//! data: `assets/defaults/bait.toml`.

use crate::utils::toml;
use std::sync::LazyLock;

/// The bait list ([`crate::defaults::BAIT`]): the terms, and the strong
/// ones of which one is enough.
static TERMS: LazyLock<Terms> = LazyLock::new(|| Terms::parse(crate::defaults::BAIT));

#[derive(Debug, Default, PartialEq)]
struct Terms {
    terms: Vec<String>,
    strong: Vec<String>,
}

impl Terms {
    /// `terms` and `strong` from the list's TOML, lowercased, compound
    /// terms joined ("chemical weapon" is read as one word).
    fn parse(text: &str) -> Terms {
        let tables = toml::parse(text).unwrap_or_default();
        let list = |key: &str| -> Vec<String> {
            tables
                .iter()
                .filter_map(|t| t.get(key))
                .flat_map(|v| match v {
                    toml::Val::Raw(r) => toml::strings(r),
                    toml::Val::Str(s) => vec![s.clone()],
                })
                .map(|s| s.replace(' ', "").to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };
        Terms { terms: list("terms"), strong: list("strong") }
    }
}

/// Identifiers (camelCase or snake_case words) carrying two or more bait
/// terms, or one of the unmistakable ones.
pub fn bait_identifiers(text: &str) -> Vec<String> {
    let Terms { terms, strong } = &*TERMS;
    let mut out: Vec<String> = Vec::new();
    for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if word.len() < 12 || !word.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let lower = word.to_ascii_lowercase().replace('_', "");
        let hits = terms.iter().filter(|b| lower.contains(b.as_str())).count();
        if (hits >= 2 || strong.iter().any(|s| lower.contains(s.as_str()))) && !out.contains(&word.to_string()) {
            out.push(word.to_string());
        }
    }
    out
}

#[cfg(test)]
#[path = "bait_tests.rs"]
mod tests;
