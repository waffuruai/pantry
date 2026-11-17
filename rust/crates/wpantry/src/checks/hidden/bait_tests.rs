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
