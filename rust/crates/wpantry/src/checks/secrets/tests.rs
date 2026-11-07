use super::*;
use crate::utils::toml;
use std::sync::OnceLock;

/// The bundled rules, compiled once for every test here.
pub(crate) fn scanner() -> &'static Scanner {
    static S: OnceLock<Scanner> = OnceLock::new();
    S.get_or_init(|| Scanner::new(RuleSet::load(&[]).expect("bundled rules compile")))
}

/// The rules (YARA names) the scanner reports for `text`.
fn reported(text: &[u8]) -> Vec<String> {
    let s = scanner();
    let mut names: Vec<String> = s
        .scan(text, "", None)
        .into_iter()
        .map(|f| s.rules.rules[s.rules.by_id(&f.rule).expect("known rule")].name.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

const CASES: &str = include_str!("../../../tests/secret-cases.toml");

/// The secret rule `r`'s regex finds first in `text`.
fn sample_secret(r: &SecretRule, text: &[u8]) -> Option<Vec<u8>> {
    let (_, tree, groups) = r.regex.as_ref()?;
    let caps = matcher::search_captures(tree, text, *groups)?;
    let (a, b) = caps[0]?;
    secret_of(r, trim_newlines(&text[a..b]))
}

#[test]
fn every_bundled_rule_and_filter_program_compiles() {
    let s = scanner();
    assert!(s.rules.rules.len() > 450, "{} rules", s.rules.rules.len());
    assert_eq!(s.rules.rules.iter().filter(|r| r.program.is_some()).count(), 5);
    assert!(!s.rules.prefilter.is_empty());
    assert!(s.rules.filters.len() >= 4, "betterleaks' filter and Pantry's three");
}

#[test]
fn every_case_betterleaks_confirmed_reports_exactly_its_rules() {
    let s = scanner();
    let mut failed = Vec::new();
    let mut read_as_text = Vec::new();
    let mut n = 0;
    for t in toml::parse(CASES).expect("cases parse").iter().filter(|t| t.name == "case") {
        n += 1;
        // Stored reversed, so the file holds nothing a scanner takes for a key.
        let text: String = t.str("reversed_text").chars().rev().collect();
        let want: Vec<String> = match t.get("rules") {
            Some(toml::Val::Raw(raw)) => toml::strings(raw),
            _ => Vec::new(),
        };
        let got = reported(text.as_bytes());
        if got != want {
            // A random sample can hold a word by chance: Pantry's readable-text
            // check then skips what betterleaks' tokenizer kept.
            let reads_as_text = want.iter().all(|name| {
                let r = s.rules.rules.iter().find(|r| r.name == *name).expect("a rule");
                let token_checked = r.skips.token_ratio_ge.is_some() || r.skips.token_efficiency;
                token_checked && sample_secret(r, text.as_bytes()).is_some_and(|sec| readable::readable(&sec))
            });
            if got.is_empty() && reads_as_text {
                read_as_text.push(t.str("name").to_string());
            } else {
                failed.push(format!("{}: want {want:?}, got {got:?}", t.str("name")));
            }
        }
    }
    assert!(read_as_text.len() <= 2, "samples read as text: {read_as_text:?}");
    assert!(n > 700, "{n} cases");
    assert!(failed.is_empty(), "{} of {n} cases differ:\n{}", failed.len(), failed.join("\n"));
}

fn hit(rule: usize, line_no: usize, secret: &str, parts: Vec<Hit>) -> Hit {
    Hit {
        rule,
        secret: secret.as_bytes().to_vec(),
        start: 0,
        end: 0,
        orig: (line_no, line_no + 1),
        line_no,
        tags: Vec::new(),
        confidence: None,
        parts,
    }
}

#[test]
fn ties_go_to_higher_specificity_and_a_multipart_findings_parts_only_outrank_other_rules() {
    let s = scanner();
    let password = s.rules.by_id("generic-password").unwrap();
    let username = s.rules.by_id("generic-username").unwrap();
    let generic = s.rules.by_id("generic-api-key").unwrap();
    let rules = &s.rules.rules;
    assert!(rules[username].specificity > rules[password].specificity);
    assert!(rules[password].specificity > rules[generic].specificity);
    let part = hit(username, 7, "svc\nPASSWORD=foo-beta", Vec::new());
    let first = hit(password, 7, "foo-alpha", vec![part]);
    let second = hit(password, 7, "foo-beta", Vec::new());
    // The second password isn't outranked by a part of the first: same rule.
    assert!(!suppressed_by(rules, &second, [&first].into_iter()));
    // A generic key whose secret is in that part is.
    let key = hit(generic, 7, "foo-beta", Vec::new());
    assert!(suppressed_by(rules, &key, [&first].into_iter()));
    // On another line it isn't.
    assert!(!suppressed_by(rules, &hit(generic, 8, "foo-beta", Vec::new()), [&first].into_iter()));
    // The final pass doesn't hold a finding against itself, nor its own parts.
    let mut hits = vec![first.clone(), second.clone()];
    suppress(rules, &mut hits);
    assert_eq!(hits.len(), 2);
    // A finding that is also a part of another is dropped as a duplicate.
    let mut hits = vec![first.clone(), hit(username, 7, "svc\nPASSWORD=foo-beta", Vec::new())];
    suppress(rules, &mut hits);
    assert_eq!(hits.len(), 1);
}
