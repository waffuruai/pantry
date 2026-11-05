use super::*;

#[test]
fn the_bundled_file_reads_and_its_hosts_are_the_allowlist() {
    let all = bundled();
    assert!(all.len() >= 20);
    let mut hosts = hosts();
    hosts.sort();
    let mut allowed: Vec<String> = crate::utils::net::HOSTS.iter().map(|h| h.to_string()).collect();
    allowed.sort();
    assert_eq!(hosts, allowed, "net::HOSTS is the bundled sources' hosts, no more and no fewer");
    for s in all {
        assert!(!s.kind.is_empty() && !s.format.is_empty() && !s.license.is_empty(), "{}", s.id);
        assert!(s.transport == Transport::Git || s.max_bytes > 0, "{}: an https source caps what it reads", s.id);
        assert!(s.sends.is_empty() || !s.sends.contains(' '), "{}", s.id);
    }
}

#[test]
fn every_id_the_code_names_is_bundled() {
    let src = [
        include_str!("osv.rs"),
        include_str!("kev.rs"),
        include_str!("endoflife.rs"),
        include_str!("releases.rs"),
        include_str!("distros.rs"),
        include_str!("extensions.rs"),
        include_str!("package_licenses.rs"),
        include_str!("malicious_packages.rs"),
        include_str!("breaches.rs"),
        include_str!("indicator_lists.rs"),
        include_str!("hash_lookups.rs"),
        include_str!("../checks/malware/yara.rs"),
        include_str!("../checks/supply_chain/malicious.rs"),
    ]
    .concat();
    let mut named = 0;
    for part in src.split("url(\"").skip(1) {
        let id = part.split('"').next().unwrap();
        assert!(bundled().iter().any(|s| s.id == id), "{id} is named in the code but not bundled");
        named += 1;
    }
    assert!(named >= 20, "{named}");
}

#[test]
fn a_users_file_sets_tiers_and_adds_what_a_user_may_add() {
    let one = |body: &str| merged(&format!("[[source]]\n{body}\n"));
    let off = one("id = \"cisa-kev\"\ntier = \"off\"").unwrap();
    assert_eq!(off.iter().find(|s| s.id == "cisa-kev").unwrap().tier, Tier::Off);
    assert_eq!(off.len(), bundled().len());
    let moved = one("id = \"cisa-kev\"\nurl = \"https://evil.example/kev.json\"").unwrap_err().to_string();
    assert!(moved.contains("only setting is its tier"), "{moved}");
    let rules = one(
        "id = \"team\"\nkind = \"yara\"\nformat = \"yara\"\nurl = \"https://rules.example/t.yar\"\nredistribute = true",
    )
    .unwrap();
    let team = rules.last().unwrap();
    assert_eq!((team.id.as_str(), team.redistribute, team.max_bytes), ("team", false, crate::utils::net::MAX_BODY));
    assert!(
        one("id = \"x\"\nkind = \"kev\"\nformat = \"kev\"\nurl = \"https://a.b/\"")
            .unwrap_err()
            .to_string()
            .contains("can't be a source of yours")
    );
    assert!(
        one("id = \"x\"\nkind = \"yara\"\nformat = \"zip\"\nurl = \"https://a.b/\"")
            .unwrap_err()
            .to_string()
            .contains("format is yara")
    );
    assert!(
        one("id = \"x\"\nkind = \"yara\"\nformat = \"yara\"\nurl = \"\"").unwrap_err().to_string().contains("https")
    );
    assert!(
        one("id = \"x\"\nkind = \"hosts\"\nformat = \"lines\"\nurl = \"https://a.b/\"\nsends = \"email\"")
            .unwrap_err()
            .to_string()
            .contains("only a hash lookup sends")
    );
    assert!(
        one("id = \"x\"\nkind = \"hash-lookup\"\nformat = \"circl\"\nurl = \"https://a.b/\"\nsends = \"path\"")
            .unwrap_err()
            .to_string()
            .contains("SHA-256 and nothing else")
    );
    let lookup =
        one("id = \"x\"\nkind = \"hash-lookup\"\nformat = \"circl\"\nurl = \"https://a.b/\"\nsends = \"sha256\"")
            .unwrap();
    assert_eq!(lookup.last().unwrap().consent, "source:x", "its own consent");
    assert!(
        merged("[[source]]\nid = \"osv\"\ntier = \"deep\"\n[[source]]\nid = \"osv\"\ntier = \"off\"\n").is_err(),
        "twice"
    );
    assert!(user_file().ends_with("wpantry/sources.toml"));
}

#[test]
fn a_broken_file_says_what_is_wrong() {
    let one = |body: &str| parse(&format!("[[source]]\n{body}\n"));
    assert!(one("id = \"Bad Id\"\nurl = \"https://a.b/\"").unwrap_err().to_string().contains("kebab-case"));
    assert!(one("id = \"a\"\nurl = \"http://a.b/\"").unwrap_err().to_string().contains("https"));
    assert!(one("id = \"a\"\nurl = \"https://a.b/\"\ntier = \"sometimes\"").unwrap_err().to_string().contains("tier"));
    assert!(one("id = \"a\"\nurl = \"https://a.b/\"\nrefresh = \"soon\"").unwrap_err().to_string().contains("refresh"));
    assert!(one("id = \"a\"\nurl = \"https://a.b/\"\nmax_bytes = lots").unwrap_err().to_string().contains("max_bytes"));
    assert!(
        one("id = \"a\"\nurl = \"https://a.b/\"\nredistribute = maybe")
            .unwrap_err()
            .to_string()
            .contains("redistribute")
    );
    assert!(one("id = \"a\"\nurl = \"\"\ntransport = \"ftp\"").unwrap_err().to_string().contains("transport"));
    let twice = "[[source]]\nid = \"a\"\nurl = \"https://a.b/\"\n[[source]]\nid = \"a\"\nurl = \"https://a.b/\"\n";
    assert!(parse(twice).unwrap_err().to_string().contains("twice"));
    let ok = one("id = \"a\"\nurl = \"https://a.b/x\"\nmax_bytes = 10 # ten\nredistribute = true\nrefresh = \"12h\"")
        .unwrap();
    assert_eq!((ok[0].max_bytes, ok[0].redistribute, ok[0].refresh, ok[0].tier), (10, true, 43_200.0, Tier::Default));
    assert_eq!((duration("30m"), duration("2s"), duration("1w"), duration("d")), (Some(1800.0), Some(2.0), None, None));
}
