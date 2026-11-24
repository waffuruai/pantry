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
        include_str!("cve_records.rs"),
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

/// Risk: a `path` reads something the person didn't mean (a path relative
/// to wherever wpantry runs, one that climbs out with `..`), or a source
/// that must stay remote, or a bundled source, is pointed at a file.
/// Oracle: the sources file rules in `specs/design/sources-file.md`; each
/// refusal names the source.
#[test]
fn a_local_path_is_absolute_or_under_home_and_only_for_a_file_kind() {
    let one = |body: &str| merged(&format!("[[source]]\n{body}\n"));
    let local = |kind: &str, format: &str, path: &str| {
        one(&format!("id = \"mine\"\nkind = \"{kind}\"\nformat = \"{format}\"\npath = {path}"))
    };
    for path in ["\"/srv/rules\"", "\"~/rules/team.yar\"", r"'C:\Users\me\rules'", r"'\\server\share\rules'"] {
        let all = local("yara", "yara", path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let s = all.last().unwrap();
        assert_eq!((s.id.as_str(), s.transport, s.host()), ("mine", Transport::Local, None), "{path}");
        assert_eq!(s.url, path.trim_matches(['"', '\'']), "the path as written");
        assert_eq!(s.max_bytes, crate::utils::net::MAX_BODY, "capped like a download");
    }
    for (kind, format) in
        [("hashes", "lines"), ("hosts", "lines"), ("filenames", "lines"), ("indicators", "maltrail-csv")]
    {
        assert!(local(kind, format, "\"/srv/list.txt\"").is_ok(), "{kind}");
    }
    let refused = |body: &str, why: &str| {
        let e = one(body).unwrap_err().to_string();
        assert!(e.contains("\"mine\"") && e.contains(why), "{body}: {e}");
    };
    let yara = "id = \"mine\"\nkind = \"yara\"\nformat = \"yara\"\n";
    refused(&format!("{yara}path = \"rules/team.yar\""), "absolute");
    refused(&format!("{yara}path = \"./team.yar\""), "absolute");
    refused(&format!("{yara}path = \"~other/team.yar\""), "absolute");
    refused(&format!("{yara}path = \"/srv/../etc/rules\""), "..");
    refused(&format!("{yara}path = '..\\rules'"), "..");
    refused(&format!("{yara}path = \"~/../x\""), "..");
    refused(&format!("{yara}path = \"\""), "not empty");
    refused(&format!("{yara}path = \"/srv/r.yar\"\nurl = \"https://a.b/r.yar\""), "not both");
    refused(yara, "a url (https) or a path");
    refused(&format!("{yara}path = \"/srv/r.yar\"\ntransport = \"https\""), "transport is local");
    refused(&format!("{yara}transport = \"local\""), "gives its path");
    // Advisories on this machine are a folder of OSV records, and such a
    // folder is never fetched.
    refused("id = \"mine\"\nkind = \"advisories\"\nformat = \"osv-api\"\npath = \"/srv/osv\"", "format = \"osv-dir\"");
    refused("id = \"mine\"\nkind = \"advisories\"\nformat = \"osv-dir\"\nurl = \"https://a.b/osv\"", "gives a path");
    refused("id = \"mine\"\nkind = \"advisories\"\nformat = \"osv-dir\"", "gives a path");
    refused("id = \"mine\"\nkind = \"advisories\"\nformat = \"osv-dir\"\npath = \"advisories\"", "absolute");
    let osv = local("advisories", "osv-dir", "\"~/advisories\"").unwrap();
    let s = osv.last().unwrap();
    assert_eq!((s.transport, s.host(), s.url.as_str()), (Transport::Local, None, "~/advisories"));
    assert!(local("advisories", "osv-api", "\"/srv/osv\"").is_err());
    refused(
        "id = \"mine\"\nkind = \"hash-lookup\"\nformat = \"circl\"\npath = \"/srv/h\"\nsends = \"sha256\"",
        "fetched over https",
    );
    let moved = one("id = \"cisa-kev\"\npath = \"/srv/kev.json\"").unwrap_err().to_string();
    assert!(moved.contains("\"cisa-kev\"") && moved.contains("only setting is its tier"), "{moved}");
    assert!(
        parse("[[source]]\nid = \"a\"\nkind = \"yara\"\nformat = \"yara\"\nurl = \"http://a.b/r.yar\"\n").is_err(),
        "http:// stays refused"
    );
    assert!(bundled().iter().all(|s| s.transport != Transport::Local), "no bundled source reads this machine");
}

/// Risk: `~/` is taken from somewhere other than the home folder, or a path
/// that is only absolute on another system (`C:\…` on macOS) is read from
/// the current folder. Oracle: the home folder wpantry uses everywhere
/// ([`crate::utils::files::home`]) and `Path::is_absolute` where it runs.
#[test]
fn a_local_path_resolves_under_home_and_never_relative() {
    let _home = crate::utils::files::test_home();
    let home = crate::utils::files::home();
    let s = |path: &str| Source {
        id: "mine".into(),
        url: path.into(),
        transport: Transport::Local,
        ..bundled()[0].clone()
    };
    assert_eq!(local_path(&s("~/rules/t.yar")).unwrap(), home.join("rules/t.yar"));
    // `/srv/t.yar` has no drive, so it is an absolute path only off Windows.
    let rooted = local_path(&s("/srv/t.yar"));
    if cfg!(windows) {
        assert!(rooted.is_err(), "{rooted:?}");
    } else {
        assert_eq!(rooted.unwrap(), std::path::PathBuf::from("/srv/t.yar"));
    }
    let windows = local_path(&s(r"C:\rules\t.yar"));
    assert_eq!(windows.is_ok(), cfg!(windows), "{windows:?}");
}

/// Risk: an added sources file replaces the person's own instead of adding
/// to it, or two files quietly define one id (the later one winning).
/// Oracle: `--add-sources` in `specs/cli-contract.md`: every file's sources
/// are used; an id defined twice is an error naming it and both files; any
/// file may still set a bundled source's tier.
#[test]
fn added_files_add_sources_and_an_id_is_defined_once() {
    let src = |id: &str| {
        format!("[[source]]\nid = \"{id}\"\nkind = \"hashes\"\nformat = \"lines\"\npath = \"/srv/{id}.txt\"\n")
    };
    let f = |name: &str, text: String| (name.to_string(), text);
    let all = merged_files(&[
        f(USER_FILE_NAME, src("own")),
        f("the added sources file /a.toml", format!("{}[[source]]\nid = \"elastic\"\ntier = \"deep\"\n", src("added"))),
    ])
    .unwrap();
    let ids: Vec<&str> = all.iter().skip(bundled().len()).map(|s| s.id.as_str()).collect();
    assert_eq!(ids, ["own", "added"], "both files' sources, the user's first");
    assert_eq!(all.iter().find(|s| s.id == "elastic").unwrap().tier, Tier::Deep, "a tier raised by an added file");
    let twice = merged_files(&[f(USER_FILE_NAME, src("team")), f("the added sources file /a.toml", src("team"))])
        .unwrap_err()
        .to_string();
    assert!(twice.contains("\"team\"") && twice.contains(USER_FILE_NAME) && twice.contains("/a.toml"), "{twice}");
    let later = merged_files(&[
        f("the added sources file /a.toml", src("team")),
        f("the added sources file /b.toml", src("team")),
    ])
    .unwrap_err()
    .to_string();
    assert!(later.contains("/a.toml") && later.contains("/b.toml"), "{later}");
    let broken = merged_files(&[f("the added sources file /a.toml", "[[source]]\nid = \"Bad\"\n".into())])
        .unwrap_err()
        .to_string();
    assert!(broken.contains("/a.toml") && broken.contains("kebab-case"), "{broken}");
}

/// Risk: a named file that can't be read is passed over, so a run uses
/// fewer sources than asked with no word of it. Oracle: only the default
/// sources file may be missing.
#[test]
fn read_files_needs_every_file_named_and_not_the_default() {
    let d = crate::utils::temp::TempDir::new("srcfiles").unwrap();
    let added = d.path().join("added.toml");
    std::fs::write(&added, "# none\n").unwrap();
    let main = d.path().join("main.toml");
    std::fs::write(&main, "# mine\n").unwrap();
    let got = read_files(Some(&main), std::slice::from_ref(&added)).unwrap();
    assert_eq!(
        got.iter().map(|(n, t)| (n.as_str(), t.as_str())).collect::<Vec<_>>(),
        [(USER_FILE_NAME, "# mine\n"), (added_name(&added).as_str(), "# none\n")]
    );
    let missing = d.path().join("missing.toml");
    let (name, why) = read_files(Some(&main), std::slice::from_ref(&missing)).unwrap_err();
    assert!(name.contains("missing.toml") && why.contains("missing.toml"), "{name}: {why}");
    assert_eq!(read_files(Some(&missing), &[]).unwrap_err().0, USER_FILE_NAME, "a --sources FILE named must exist");
}

/// A sources file as `merged_files` is given one: the user's own, or an added one.
fn added(path: &str) -> String {
    format!("the added sources file {path}")
}

fn tier_of(all: &[Source], id: &str) -> Tier {
    all.iter().find(|s| s.id == id).unwrap().tier
}

/// Risk: `--add-sources`, a flag described as adding sources, makes a run
/// check LESS: a repo's `sources.toml` turning a bundled source off or down.
/// Oracle: `specs/cli-contract.md`, `--add-sources`: an added file may add
/// sources and may turn a bundled source up, never down or off; an entry
/// that would is refused with an error naming the file, the id and the rule.
#[test]
fn an_added_file_may_not_turn_a_bundled_source_off_or_down() {
    let tier = |id: &str, t: &str| format!("[[source]]\nid = \"{id}\"\ntier = \"{t}\"\n");
    // Off: the case the review named.
    let e = merged_files(&[(added("/repo/sources.toml"), tier("yara-forge-full", "off"))]).unwrap_err().to_string();
    assert!(
        e.contains("/repo/sources.toml") && e.contains("\"yara-forge-full\"") && e.contains("--add-sources"),
        "the error names the file, the id and the rule: {e}"
    );
    // Down: default to deep checks less than every scan.
    let e = merged_files(&[(added("/repo/sources.toml"), tier("cisa-kev", "deep"))]).unwrap_err().to_string();
    assert!(e.contains("\"cisa-kev\"") && e.contains("--add-sources"), "{e}");
    // Not changing a tier is not lowering it.
    let same = merged_files(&[(added("/a.toml"), tier("cisa-kev", "default"))]).unwrap();
    assert_eq!(tier_of(&same, "cisa-kev"), Tier::Default);
}

/// Oracle: the same rule: up (more checking) is allowed from an added file;
/// so is a new id; one added file can't undo what an earlier one raised.
#[test]
fn an_added_file_may_turn_a_bundled_source_up_and_add_a_new_id() {
    let tier = |id: &str, t: &str| format!("[[source]]\nid = \"{id}\"\ntier = \"{t}\"\n");
    assert_eq!(tier_of(bundled(), "elastic"), Tier::Off, "the fixture: a bundled source that is off");
    let up = merged_files(&[(added("/a.toml"), tier("elastic", "deep"))]).unwrap();
    assert_eq!(tier_of(&up, "elastic"), Tier::Deep, "off to deep is up");
    let top = merged_files(&[(added("/a.toml"), tier("elastic", "default"))]).unwrap();
    assert_eq!(tier_of(&top, "elastic"), Tier::Default, "off to default is up");
    let new =
        "[[source]]\nid = \"added\"\nkind = \"hashes\"\nformat = \"lines\"\npath = \"/srv/h.txt\"\ntier = \"off\"\n";
    let with_new = merged_files(&[(added("/a.toml"), new.into())]).unwrap();
    assert_eq!(tier_of(&with_new, "added"), Tier::Off, "a source of its own may have any tier");
    // Later than a raise: the second file may not lower what the first raised.
    let e = merged_files(&[(added("/a.toml"), tier("elastic", "default")), (added("/b.toml"), tier("elastic", "off"))])
        .unwrap_err()
        .to_string();
    assert!(e.contains("/b.toml") && e.contains("\"elastic\""), "{e}");
}

/// Risk: a refused entry leaves the rest of its file half applied.
/// Oracle: the rule is all or nothing: a mixed file (a new source, a raise,
/// and one lowering) is refused as a whole, and the error names the file.
#[test]
fn a_mixed_added_file_is_refused_as_a_whole() {
    let mixed = "[[source]]\nid = \"added\"\nkind = \"hashes\"\nformat = \"lines\"\npath = \"/srv/h.txt\"\n\n\
                 [[source]]\nid = \"elastic\"\ntier = \"default\"\n\n\
                 [[source]]\nid = \"cisa-kev\"\ntier = \"off\"\n";
    let e = merged_files(&[(added("/repo/mixed.toml"), mixed.into())]).unwrap_err().to_string();
    assert!(e.contains("/repo/mixed.toml") && e.contains("\"cisa-kev\""), "{e}");
    // Nothing comes back, so nothing of the file (its new source, its
    // raise) is applied; the same file without the lowering entry is fine.
    let without = mixed.split("[[source]]\nid = \"cisa-kev\"").next().unwrap();
    let ok = merged_files(&[(added("/repo/mixed.toml"), without.into())]).unwrap();
    assert!(ok.iter().any(|s| s.id == "added") && tier_of(&ok, "elastic") == Tier::Default, "the control applies");
}

/// Oracle: the user's own file keeps its full power: it may turn a bundled
/// source off, and an added file after it may raise that source again.
#[test]
fn the_users_own_file_may_still_turn_a_source_off() {
    let off = "[[source]]\nid = \"cisa-kev\"\ntier = \"off\"\n";
    let all = merged_files(&[(USER_FILE_NAME.to_string(), off.into())]).unwrap();
    assert_eq!(tier_of(&all, "cisa-kev"), Tier::Off);
    let deep = merged("[[source]]\nid = \"cisa-kev\"\ntier = \"deep\"\n").unwrap();
    assert_eq!(tier_of(&deep, "cisa-kev"), Tier::Deep, "and down to deep");
}
