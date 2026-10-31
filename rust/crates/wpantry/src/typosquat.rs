//! Dependency names one keystroke from a popular package: `lodahs`,
//! `reqeusts`, `node-fetch` written `nodefetch`, `@babe1/core`. A squat
//! registers the name people mistype and ships something extra; a lockfile
//! that holds one is a repo that typed it. The popular names are bundled
//! (`assets/defaults/popular.txt`, `ecosystem<TAB>name`, or `@scope` for
//! an npm scope) so the check works offline and never asks a registry.

use crate::lockfiles::Package;

/// A dependency that looks like a typo of a popular one.
#[derive(Clone, Debug, PartialEq)]
pub struct Squat {
    pub ecosystem: String,
    pub name: String,
    /// The popular name it is one keystroke from.
    pub near: String,
    /// The popular name is in the same lockfile too: a typo that pulled in a
    /// stranger's package beside the one meant.
    pub both: bool,
}

fn popular(ecosystem: &str) -> Vec<&'static str> {
    let key = ecosystem.to_ascii_lowercase();
    crate::defaults::POPULAR
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t'))
        .filter(|(eco, _)| eco.eq_ignore_ascii_case(&key))
        .map(|(_, name)| name.trim())
        .collect()
}

/// Lowercase without separators: `node-fetch` and `nodefetch` are one word.
fn fold(name: &str) -> String {
    name.to_ascii_lowercase().chars().filter(|c| !matches!(c, '-' | '_' | '.')).collect()
}

/// Optimal string alignment distance, capped at 2: substitutions,
/// insertions, deletions and adjacent transpositions.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > 2 {
        return 3;
    }
    let mut prev2: Vec<usize> = Vec::new();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut d = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d = d.min(prev2[j - 2] + 1);
            }
            cur[j] = d;
        }
        prev2 = prev;
        prev = cur;
    }
    prev[b.len()].min(3)
}

/// How one name differs from another by a single keystroke, if it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edit {
    /// Two adjacent letters swapped: `lodahs`.
    Transposition,
    /// A letter typed twice or a double letter typed once: `lodaash`, `expres`.
    Duplication,
    /// A letter swapped for one that looks like it: `@babe1`, `0penai`.
    Confusable,
    /// One letter missing or extra: `lodas`, `lodashs`.
    Omission,
    /// One letter replaced: `lodesh`.
    Substitution,
}

fn confusable_pair(a: char, b: char) -> bool {
    [('1', 'l'), ('1', 'i'), ('0', 'o'), ('5', 's'), ('i', 'l'), ('u', 'v'), ('m', 'n'), ('3', 'e')]
        .iter()
        .any(|(x, y)| (a, b) == (*x, *y) || (a, b) == (*y, *x))
}

/// The single edit that turns `typed` into `meant`, when there is one.
pub fn edit(typed: &str, meant: &str) -> Option<Edit> {
    let a: Vec<char> = typed.chars().collect();
    let b: Vec<char> = meant.chars().collect();
    if a == b {
        return None;
    }
    if a.len() == b.len() {
        let diffs: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        return match diffs.as_slice() {
            [i] => Some(if confusable_pair(a[*i], b[*i]) { Edit::Confusable } else { Edit::Substitution }),
            [i, j] if *j == i + 1 && a[*i] == b[*j] && a[*j] == b[*i] => Some(Edit::Transposition),
            _ => None,
        };
    }
    let (longer, shorter) = if a.len() == b.len() + 1 {
        (&a, &b)
    } else if b.len() == a.len() + 1 {
        (&b, &a)
    } else {
        return None;
    };
    let i = (0..shorter.len()).find(|&i| longer[i] != shorter[i]).unwrap_or(shorter.len());
    if longer[i + 1..] != shorter[i..] {
        return None;
    }
    let extra = longer[i];
    let doubled = (i > 0 && longer[i - 1] == extra) || longer.get(i + 1) == Some(&extra);
    Some(if doubled { Edit::Duplication } else { Edit::Omission })
}

/// Whether a name this far from a popular one reads as a typo of it rather
/// than a word of its own: swaps, doubled letters and look-alikes at four
/// letters or more, a missing, extra or replaced letter at six or more
/// (`libm`/`libc`, `glow`/`glob`, `mime`/`time` are different crates).
fn is_typo(e: Edit, len: usize) -> bool {
    match e {
        Edit::Transposition | Edit::Duplication | Edit::Confusable => len >= 4,
        Edit::Omission | Edit::Substitution => len >= 6,
    }
}

/// The squats among these packages.
pub fn find(packages: &[Package]) -> Vec<Squat> {
    let mut out = Vec::new();
    let names: Vec<(String, String)> =
        packages.iter().map(|p| (p.ecosystem.to_ascii_lowercase(), p.name.to_ascii_lowercase())).collect();
    for p in packages {
        let eco = p.ecosystem.to_ascii_lowercase();
        let name = p.name.to_ascii_lowercase();
        let pop = popular(&eco);
        if pop.is_empty() {
            continue;
        }
        let pypi = eco == "pypi";
        let (scope, bare) = match name.strip_prefix('@').and_then(|_| name.split_once('/')) {
            Some((s, b)) => (Some(s.to_string()), b.to_string()),
            None => (None, name.clone()),
        };
        if let Some(scope) = scope {
            // Scopes are owned by organizations and often legitimately a letter
            // apart (@next, @nuxt): only a swap, a double letter or a look-alike counts.
            if pop.contains(&scope.as_str()) || pop.contains(&name.as_str()) {
                continue;
            }
            let near = pop.iter().filter(|c| c.starts_with('@')).find(|c| {
                scope.chars().count() >= 5
                    && matches!(edit(&scope, c), Some(Edit::Transposition | Edit::Duplication | Edit::Confusable))
            });
            if let Some(near) = near {
                out.push(Squat {
                    ecosystem: p.ecosystem.clone(),
                    name: p.name.clone(),
                    near: format!("{near}/{bare}"),
                    both: false,
                });
            }
            continue;
        }
        if bare.chars().count() < 4 || pop.contains(&bare.as_str()) {
            continue;
        }
        let fb = fold(&bare);
        let near = pop.iter().filter(|c| !c.starts_with('@')).find(|c| {
            let fc = fold(c);
            let len = c.chars().count();
            if pypi {
                // Separators and case are the same package there: compare the folded names.
                fb != fc && edit(&fb, &fc).is_some_and(|e| is_typo(e, len))
            } else {
                (fb == fc && bare != **c)
                    || edit(&bare, c).is_some_and(|e| is_typo(e, len))
                    || (fb != fc && edit(&fb, &fc).is_some_and(|e| is_typo(e, len)))
            }
        });
        if let Some(near) = near {
            let both = names.iter().any(|(e, n)| *e == eco && (n == near || (pypi && fold(n) == fold(near))));
            out.push(Squat { ecosystem: p.ecosystem.clone(), name: p.name.clone(), near: near.to_string(), both });
        }
    }
    out.sort_by(|a, b| (&a.ecosystem, &a.name).cmp(&(&b.ecosystem, &b.name)));
    out.dedup_by(|a, b| a.ecosystem == b.ecosystem && a.name == b.name);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(eco: &str, name: &str) -> Package {
        Package::new(eco, name, "1.0.0")
    }

    #[test]
    fn edits() {
        assert_eq!(edit("lodahs", "lodash"), Some(Edit::Transposition));
        assert_eq!(edit("lodas", "lodash"), Some(Edit::Omission));
        assert_eq!(edit("lodashs", "lodash"), Some(Edit::Omission));
        assert_eq!(edit("lodaash", "lodash"), Some(Edit::Duplication));
        assert_eq!(edit("expres", "express"), Some(Edit::Duplication));
        assert_eq!(edit("lodesh", "lodash"), Some(Edit::Substitution));
        assert_eq!(edit("@babe1", "@babel"), Some(Edit::Confusable));
        assert_eq!(edit("lodash", "underscore"), None);
        assert_eq!(edit("preact", "react"), Some(Edit::Omission));
        assert_eq!(distance("lodash", "lodahs"), 1);
        assert!(!is_typo(Edit::Substitution, 4), "mime is not a typo of time");
        assert!(is_typo(Edit::Transposition, 4));
    }

    #[test]
    fn squats_warn_and_a_typo_beside_the_real_one_is_both() {
        let s = find(&[pkg("npm", "lodahs"), pkg("npm", "react"), pkg("npm", "express")]);
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!((s[0].name.as_str(), s[0].near.as_str(), s[0].both), ("lodahs", "lodash", false));
        let s = find(&[pkg("npm", "lodahs"), pkg("npm", "lodash")]);
        assert!(s[0].both);
        assert!(find(&[pkg("npm", "preact"), pkg("npm", "react")]).is_empty(), "both popular");
        assert!(find(&[pkg("npm", "colors"), pkg("npm", "color")]).is_empty(), "both popular");
        let s = find(&[pkg("npm", "nodefetch")]);
        assert_eq!(s[0].near, "node-fetch", "a dropped separator is a different npm package");
        assert!(find(&[pkg("npm", "ms"), pkg("npm", "qs")]).is_empty(), "short names are skipped");
        let s = find(&[pkg("npm", "@babe1/core")]);
        assert_eq!(s[0].near, "@babel/core");
        assert!(find(&[pkg("npm", "@babel/core"), pkg("npm", "@mycompany/react")]).is_empty());
        assert!(
            find(&[pkg("npm", "@next/env"), pkg("npm", "@clack/core")]).is_empty(),
            "a scope a letter apart is a scope"
        );
        assert_eq!(find(&[pkg("npm", "lodesh")])[0].near, "lodash");
        assert!(
            find(&[
                pkg("crates.io", "libm"),
                pkg("crates.io", "libc"),
                pkg("crates.io", "mime"),
                pkg("crates.io", "time")
            ])
            .is_empty(),
            "short names a letter apart are words of their own"
        );
        assert!(find(&[pkg("npm", "ntapi")]).is_empty(), "five letters, one extra: a word of its own");
    }

    #[test]
    fn pypi_separators_are_the_same_package() {
        assert!(find(&[pkg("PyPI", "python_dateutil")]).is_empty(), "PEP 503: one package");
        assert!(find(&[pkg("PyPI", "Scikit-Learn")]).is_empty());
        let s = find(&[pkg("PyPI", "reqeusts")]);
        assert_eq!(s[0].near, "requests");
        let s = find(&[pkg("PyPI", "sklearn")]);
        assert!(s.is_empty(), "too far from scikit-learn; the squat is in the malicious index instead");
        assert!(find(&[pkg("crates.io", "serde"), pkg("crates.io", "serde_json")]).is_empty());
        let s = find(&[pkg("crates.io", "serde_jsn")]);
        assert_eq!(s[0].near, "serde_json");
        assert!(find(&[pkg("Go", "github.com/x/y")]).is_empty(), "no list for the ecosystem");
    }
}
