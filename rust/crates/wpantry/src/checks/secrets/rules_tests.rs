use super::*;

const RULE: &str = r#"
rule Any_Secret_Acme {
    meta:
        id = "acme-key"
        category = "secret"
        keyword = "ACME_"
        confidence = "medium"
        skip_entropy_le = "3.0"
        skip_regex_secret = "(?i)^test"
        skip_word_line = "Example"
        require_secret = "[0-9]"
        component1 = "acme-id"
        component1_within = "-2L,+4C"
        component2 = "acme-region"
        component2_optional = true
        specificity = 120
    strings:
        $secret = /acme_([a-z0-9]{8})/
    condition:
        $secret
}
private rule Any_Secret_AcmeId {
    meta:
        id = "acme-id"
        category = "secret"
    strings:
        $secret = /id_[0-9]{4}/
    condition:
        $secret
}
private rule Any_Secret_Filter {
    meta:
        category = "secret"
        applies_to = "acme-key"
        skip_regex_secret = "^x+$"
    condition:
        false
}
"#;

#[test]
fn meta_becomes_a_secret_rule() {
    let set = RuleSet::from_sources(&[("t", RULE)]).unwrap();
    let r = &set.rules[set.by_id("acme-key").unwrap()];
    assert_eq!(r.keywords, vec![b"acme_".to_vec()]);
    assert_eq!(r.confidence, Some(Confidence::Medium));
    assert_eq!(r.specificity, 120);
    assert_eq!(r.skips.entropy_le, Some(3.0));
    assert_eq!((r.skips.regex.len(), r.skips.words.len(), r.skips.require.len()), (1, 1, 1));
    assert_eq!(r.skips.words[0], (Target::Line, b"example".to_vec()));
    assert_eq!(r.components.len(), 2);
    assert_eq!(
        r.components[0].within,
        Window { lines_before: Some(1), lines_after: None, cols_before: None, cols_after: Some(4) }
    );
    assert!(r.components[1].optional && r.components[1].within.is_fragment());
    assert_eq!(r.regex.as_ref().map(|(_, _, g)| *g), Some(1));
    assert!(set.rules[set.by_id("acme-id").unwrap()].private);
    assert_eq!(set.filters.len(), 1);
    assert_eq!(set.filters[0].applies_to, vec!["acme-key".to_string()]);
}

#[test]
fn windows_read_betterleaks_grammar() {
    assert_eq!(
        Window::parse("5L").unwrap(),
        Window { lines_before: Some(4), lines_after: Some(4), ..Default::default() }
    );
    assert_eq!(
        Window::parse("100").unwrap(),
        Window { cols_before: Some(100), cols_after: Some(100), ..Default::default() }
    );
    assert!(Window::parse("0").unwrap().is_fragment());
    assert!(Window::parse("x").is_none());
}

#[test]
fn a_rule_that_doesnt_compile_is_an_error_naming_it() {
    let bad =
        r#"rule Any_Secret_Bad { meta: id = "bad" category = "secret" strings: $secret = /(/ condition: $secret }"#;
    let err = RuleSet::from_sources(&[("t", bad)]).err().expect("rejected");
    assert!(format!("{err:?}").contains("Any_Secret_Bad"), "{err:?}");
}

#[test]
fn rules_split_at_each_top_level_rule() {
    let parts = split_rules("// a\nrule A { condition: true }\nprivate rule B { condition: true }\n");
    // A leading comment is a chunk of its own, with no rule in it.
    assert_eq!(parts.len(), 3);
    assert_eq!(rule_name(parts[0]), None);
    assert_eq!(rule_name(parts[1]), Some("A"));
    assert_eq!(rule_name(parts[2]), Some("B"));
}
