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
mod tests {
    use super::*;

    #[test]
    fn the_bundled_list_reads_and_joins_compound_terms() {
        let t = &*TERMS;
        assert_eq!(t.terms.len(), 30);
        assert_eq!(t.strong.len(), 9);
        assert!(t.strong.iter().all(|s| t.terms.contains(s)), "a strong term is a term");
        assert!(t.terms.contains(&["nerve", "agent"].concat()));
        assert!(t.terms.iter().all(|s| !s.contains(' ')));
    }

    #[test]
    fn the_list_does_not_flag_itself() {
        assert!(bait_identifiers(crate::defaults::BAIT).is_empty());
        assert!(crate::checks::hidden::scan_text("bait.toml", crate::defaults::BAIT).is_empty());
    }

    #[test]
    fn odd_lists_read_what_they_can() {
        assert_eq!(Terms::parse("not toml at all"), Terms::default());
        let t = Terms::parse("terms = [\"A b\", # note\n  \"\", \"c\"]\nstrong = \"Single Term\"\n");
        assert_eq!(t.terms, ["ab", "c"]);
        assert_eq!(t.strong, ["singleterm"]);
    }
}
