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

#[test]
fn a_scan_past_its_deadline_gives_up_instead_of_reading_on() {
    let s = scanner();
    let text = format!("token = \"gh{}_{}\"\n", "p", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5");
    let past = Some(Instant::now() - std::time::Duration::from_secs(1));
    assert_eq!(s.scan_until(text.as_bytes(), "a.env", None, None).map(|f| f.len()), Some(1));
    assert!(s.scan_until(text.as_bytes(), "a.env", None, past).is_none(), "not read: not checked");
    // A binary file needs no reading, late or not.
    assert_eq!(s.scan_until(b"\x00\x01 token", "a.bin", None, past).map(|f| f.len()), Some(0));
}

#[test]
fn generic_rules_skip_translations_docs_and_test_passwords_but_not_real_secrets() {
    let s = scanner();
    let rules = |text: &str, path: &str| -> Vec<String> {
        let mut r: Vec<String> = s.scan(text.as_bytes(), path, None).into_iter().map(|f| f.rule).collect();
        r.dedup();
        r
    };
    let password = "db:\n  host: db.internal\n  username: svc_app\n  password: \"Tr0ub4dor&3xq\"\n";
    let key = format!("api_key = \"{}\"\n", "q8Zr2Lx0Vb7Nc4Mw1Ks9Jd6Hf3Gt5Py");
    let github = format!("token = \"gh{}_{}\"\n", "p", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5");
    // True positives: config and code still report.
    assert_eq!(rules(password, "config/database.yml"), ["generic-password"]);
    assert_eq!(rules(&key, "src/client.py"), ["generic-api-key"]);
    assert_eq!(rules(&key, "backend/tests/unit/test_client.py"), ["generic-api-key"], "keys in tests are read");
    // A provider's key is reported wherever it is.
    for path in ["app/src/lang/en.yaml", "README.md", "spec/x_spec.rb", "public/js/app.6fb2ab18.js"] {
        assert_eq!(rules(&github, path), ["github-pat"], "{path}");
    }
    // False positives: translations, bundles, docs and test passwords.
    assert_eq!(rules(password, "config/database.yml.md"), Vec::<String>::new());
    for (text, path) in [
        ("password: Jelszó\nforgot_password: Elfelejtett jelszó\n", "app/src/lang/translations/hu-HU.yaml"),
        ("{\"enterWifiPassword\": \"Insira a senha do WiFi\"}\n", "app/lib/l10n/app_pt.arb"),
        (password, "documentation/modules/exploit/demo.md"),
        (password, "spec/lib/client_spec.rb"),
        (key.as_str(), "docs/setup.txt"),
        (key.as_str(), "public/admin/js/chunk-2d0b219a.92a44bfd.js"),
    ] {
        assert_eq!(rules(text, path), Vec::<String>::new(), "{path}");
    }
    // As betterleaks, with the skips off.
    let mut bl = Scanner::new(RuleSet::load(&[]).unwrap());
    bl.skip_noise = false;
    assert_eq!(bl.scan(password.as_bytes(), "spec/lib/client_spec.rb", None).len(), 1);
}
