use super::*;

/// The bundled list carries the seed rows, and matches them; a near miss
/// doesn't.
#[test]
fn the_bundled_list_matches_its_seeds() {
    let l = List::bundled();
    // At least the rows the list began with: rows are added without a code change.
    assert!(l.repos.len() >= 71 && l.hashes.len() >= 34 && l.demos.len() >= 129, "rows went missing");
    assert!(!l.ollama.is_empty() && l.owners.len() >= 2);
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

/// Every row parses: each list holds what the file holds, every hash is 64
/// lowercase hex, every repo is `owner/name`, and no id is in two lists.
#[test]
fn every_row_of_the_bundled_list_is_well_formed() {
    let text = crate::defaults::KNOWN_BAD_MODELS;
    let l = List::bundled();
    // Rows as written: a quoted string on its own line.
    let rows = text.lines().filter(|line| line.trim_start().starts_with('"')).count();
    assert_eq!(rows, l.len(), "every row parsed");
    // The hashes as written, before parsing lowercases them.
    let block = text.split("\nsha256 = [").nth(1).and_then(|b| b.split("\n]").next()).expect("a sha256 list");
    let written: Vec<&str> = block.lines().map(str::trim).filter(|x| x.starts_with('"')).collect();
    assert_eq!(written.len(), l.hashes.len());
    for h in written {
        let h = h.trim_end_matches(',').trim_matches('"');
        assert!(h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{h}");
    }
    for r in l.repos.iter().chain(&l.ollama).chain(&l.demos) {
        let (o, n) = r.split_once('/').unwrap_or_else(|| panic!("{r} is owner/name"));
        assert!(!o.is_empty() && !n.is_empty() && !n.contains('/'), "{r}");
    }
    let mut seen = std::collections::HashSet::new();
    for id in l.repos.iter().chain(&l.hashes).chain(&l.ollama).chain(&l.owners).chain(&l.demos) {
        assert!(seen.insert(id.clone()), "{id} is in two lists, or twice");
    }
    for o in &l.owners {
        assert!(l.repos.iter().any(|r| r.starts_with(&format!("{o}/"))), "{o} published a listed repo");
    }
}
