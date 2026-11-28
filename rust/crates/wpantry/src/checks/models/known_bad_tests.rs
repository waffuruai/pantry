use super::*;

/// The bundled list carries the seed rows, and matches them; a near miss
/// doesn't.
#[test]
fn the_bundled_list_matches_its_seeds() {
    let l = List::bundled();
    assert_eq!(l.len(), 12);
    assert!(l.repo("mir2k/huihui-qwen3.5-9b-abliterated-gguf").is_some(), "case does not matter");
    assert!(l.repo("timdedid/qwen3-cyber-UNCENSORED").is_some());
    assert!(l.repo("timdedid/qwen3-cyber").is_none());
    let h = "6037244a718f2afc2e9eabf6ab253f53fe7b9552792b3533956d63e43e4ac058";
    assert!(l.hash(&h.to_uppercase()).unwrap().contains(h));
    assert!(l.hash(&h.replace('6', "7")).is_none());
    assert!(l.source.contains("known-bad"));
    assert!(crate::defaults::KNOWN_BAD_MODELS.contains("https://malspark.com/blog/malicious-gguf-models-hugging-face"));
    assert!(List::parse("not toml [").is_empty());
}

/// The user's indicator lists are asked about a hash too.
#[test]
fn the_indicator_store_is_consulted() {
    let mut s = Store::new();
    let o = s.origin("rule", "your list");
    let h = "ab".repeat(32);
    assert!(s.add(&h, "a bad model", o));
    s.seal();
    assert!(in_store(&s, &h).unwrap().contains("your list"));
    assert!(in_store(&s, &"cd".repeat(32)).is_none());
    assert!(in_store(&Store::new(), &h).is_none());
}
