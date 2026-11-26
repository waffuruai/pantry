use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing::{repo, scan, write};
use crate::sources::wordfence::tests::{feed, one_at_a_time, record};
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;
use std::collections::HashSet;

const PLUGIN: &str = "<?php\n/**\n * Plugin Name: Akismet Anti-spam\n * Plugin URI: https://akismet.com/\n * Version: 5.3.1\n * Author: Automattic\n */\n";

#[test]
fn headers_are_read_as_get_file_data_reads_them() {
    assert_eq!(header(PLUGIN, "Plugin Name").as_deref(), Some("Akismet Anti-spam"));
    assert_eq!(header(PLUGIN, "Version").as_deref(), Some("5.3.1"));
    assert_eq!(header("<?php /* plugin name: Tiny */ ?>", "Plugin Name").as_deref(), Some("Tiny"));
    assert_eq!(header("# Version: 2.0 ?>\n", "Version").as_deref(), Some("2.0"));
    assert_eq!(header("@Version:\t1.0\r\n", "version").as_deref(), Some("1.0"));
    assert_eq!(header("$x = 'Version: 9';", "Version"), None, "not a header line");
    assert_eq!(header(" * Version:   \n", "Version"), None, "empty");
    assert_eq!(header("Requires at least: 6.0", "Version"), None);
    assert_eq!(header("Stable tag: 4.1\n", "Stable tag").as_deref(), Some("4.1"));
}

#[test]
fn core_version_drops_its_build_suffix() {
    assert_eq!(core_version("<?php\n$wp_version = '6.5.2';\n").as_deref(), Some("6.5.2"));
    assert_eq!(core_version("$wp_version = \"6.6-RC2-58402\";").as_deref(), Some("6.6"));
    assert_eq!(core_version("$wp_db_version = 57155;\n$wp_version = '6.4-alpha-56000-src';").as_deref(), Some("6.4"));
    assert_eq!(core_version("$wp_version = get_it();"), None);
    assert_eq!(core_version("no version here"), None);
    assert_eq!(core_version("<?php $wp_version = '6.5.2';").as_deref(), Some("6.5.2"));
    assert_eq!(core_version("$wp_version_x = '1';"), None);
}

#[test]
fn versions_compare_as_php_version_compare() {
    use Ordering::*;
    for (a, b, want) in [
        ("1.0", "1.0.0", Equal),
        ("1.0-rc1", "1.0", Less),
        ("1.0.0-beta", "1.0.0-RC1", Less),
        ("1.0-dev", "1.0-alpha", Less),
        ("1.0a", "1.0b", Less),
        ("1.10", "1.9", Greater),
        ("5.0pl1", "5.0", Greater),
        ("2.1.0", "2.1", Equal),
        ("6.4.3", "6.4.10", Less),
        ("1.0-foo", "1.0-dev", Less),
        ("1_2", "1.2", Equal),
    ] {
        assert_eq!(php_cmp(a, b), want, "{a} vs {b}");
        assert_eq!(php_cmp(b, a), want.reverse(), "{b} vs {a}");
    }
}

#[test]
fn ranges_include_their_ends_only_when_inclusive() {
    let r =
        |from: &str, fi, to: &str, ti| Range { from: from.into(), from_inclusive: fi, to: to.into(), to_inclusive: ti };
    assert!(in_range("1.2.3", &r("*", true, "1.2.3", true)));
    assert!(!in_range("1.2.3", &r("*", true, "1.2.3", false)));
    assert!(in_range("0.1", &r("*", true, "1.2.3", false)));
    assert!(!in_range("1.2.4", &r("*", true, "1.2.3", true)));
    assert!(in_range("2.0", &r("2.0", true, "*", true)));
    assert!(!in_range("2.0", &r("2.0", false, "*", true)));
    assert!(in_range("9.9", &r("*", true, "*", true)));
    assert_eq!(range_text(&r("*", true, "1.2.3", true)), "<=1.2.3");
    assert_eq!(range_text(&r("2.0", true, "2.1", false)), ">=2.0, <2.1");
    assert_eq!(range_text(&r("2.0", false, "*", true)), ">2.0");
    assert_eq!(range_text(&r("*", true, "*", true)), "*");
}

/// A classic site committed whole, and a Bedrock site whose plugins Composer installs.
fn sites(root: &Path) {
    write(root, "site/wp-includes/version.php", "<?php\n$wp_version = '6.4.2';\n");
    write(root, "site/wp-content/plugins/akismet/akismet.php", PLUGIN);
    write(root, "site/wp-content/plugins/akismet/class.akismet.php", "<?php class Akismet {}");
    write(root, "site/wp-content/plugins/hello.php", "<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/");
    write(root, "site/wp-content/plugins/index.php", "<?php // Silence is golden.");
    write(root, "site/wp-content/plugins/tagged/tagged.php", "<?php\n/* Plugin Name: Tagged */");
    write(root, "site/wp-content/plugins/tagged/readme.txt", "=== Tagged ===\nStable tag: 2.0.1\n");
    write(root, "site/wp-content/plugins/trunk/trunk.php", "<?php\n/* Plugin Name: Trunk */");
    write(root, "site/wp-content/plugins/trunk/readme.txt", "Stable tag: trunk\n");
    write(root, "site/wp-content/plugins/not-a-plugin/lib.php", "<?php function f() {}");
    write(root, "site/wp-content/themes/astra/style.css", "/*\nTheme Name: Astra\nVersion: 4.6.0\n*/");
    write(root, "site/wp-content/themes/notes/style.css", "body { color: red }");
    write(root, "bedrock/web/wp/wp-includes/version.php", "<?php $wp_version = '6.5-RC2-57890';");
    write(
        root,
        "bedrock/web/app/plugins/wordfence/wordfence.php",
        "<?php\n/* Plugin Name: Wordfence\n Version: 7.11.0 */",
    );
    write(
        root,
        "bedrock/composer.lock",
        serde_json::json!({"packages": [
            {"name": "wpackagist-plugin/wordfence", "version": "7.11.0", "type": "wordpress-plugin"},
            {"name": "wpackagist-theme/twentytwentyfour", "version": "1.0", "type": "wordpress-theme"},
            {"name": "roots/wordpress-no-content", "version": "6.5.0", "type": "wordpress-core"},
            {"name": "monolog/monolog", "version": "3.5.0"}
        ]})
        .to_string(),
    );
}

#[test]
fn every_site_is_found_by_its_markers_wherever_it_is() {
    let d = TempDir::new("wp").unwrap();
    sites(d.path());
    let (items, unread) = inventory(d.path());
    let got: Vec<(Type, &str, &str, bool)> =
        items.iter().map(|i| (i.kind, i.slug.as_str(), i.version.as_str(), i.composer)).collect();
    assert_eq!(
        got,
        vec![
            (Type::Core, "wordpress", "6.5.0", true),
            (Type::Plugin, "wordfence", "7.11.0", true),
            (Type::Theme, "twentytwentyfour", "1.0", true),
            (Type::Core, "wordpress", "6.4.2", false),
            (Type::Plugin, "akismet", "5.3.1", false),
            (Type::Plugin, "hello", "1.7.2", false),
            (Type::Plugin, "tagged", "2.0.1", false),
            (Type::Theme, "astra", "4.6.0", false),
        ],
        "the Bedrock core and plugin are its lock's; a Stable tag is the fallback"
    );
    let akismet = items.iter().find(|i| i.slug == "akismet").unwrap();
    assert_eq!(akismet.location, d.path().join("site/wp-content/plugins/akismet"));
    assert_eq!(akismet.site, d.path().join("site"));
    assert_eq!(
        items.iter().find(|i| i.slug == "hello").unwrap().location,
        d.path().join("site/wp-content/plugins/hello.php")
    );
    assert_eq!(unread.len(), 1, "{unread:?}");
    assert!(unread[0].0.ends_with("plugins/trunk"), "trunk is never a version");
}

#[test]
fn a_fix_updates_with_wp_cli_or_composer() {
    let d = TempDir::new("wp").unwrap();
    sites(d.path());
    let (items, _) = inventory(d.path());
    let by = |slug: &str, composer: bool| items.iter().find(|i| i.slug == slug && i.composer == composer).unwrap();
    let site = command_path(&d.path().join("site"));
    let bedrock = command_path(&d.path().join("bedrock"));
    assert_eq!(fix(by("akismet", false), "5.3.2"), format!("wp plugin update akismet --path={}", quote(&site)));
    assert_eq!(fix(by("astra", false), "4.6.1"), format!("wp theme update astra --path={}", quote(&site)));
    assert_eq!(
        fix(by("wordfence", true), "7.11.1"),
        format!("cd {} && composer require {}", quote(&bedrock), quote("wpackagist-plugin/wordfence:^7.11.1"))
    );
    assert_eq!(
        fix(by("wordpress", true), "6.5.2"),
        format!("cd {} && composer require {}", quote(&bedrock), quote("roots/wordpress-no-content:^6.5.2"))
    );
    let core = items.iter().find(|i| i.kind == Type::Core && i.version == "6.4.2").unwrap();
    assert_eq!(fix(core, "6.4.3"), format!("wp core update --path={}", quote(&site)));
}

fn vuln(ranges: &[(&str, bool, &str, bool)], patched: &[&str], cve: &str) -> Vuln {
    let mut rec = record("61c39f5f-3b17-4e4d-824e-241159a73400", "plugin", "akismet", ranges, patched);
    rec["cve"] = serde_json::json!(cve);
    crate::sources::wordfence::rows_of(&rec).remove(0)
}

#[test]
fn a_patched_version_fails_and_none_warns() {
    let it = Item {
        kind: Type::Plugin,
        slug: "akismet".into(),
        version: "5.3.1".into(),
        location: PathBuf::from("/w/site/wp-content/plugins/akismet"),
        site: PathBuf::from("/w/site"),
        composer: false,
    };
    let kev = HashSet::from(["CVE-2026-1001".to_string()]);
    let f = judge(&it, &[vuln(&[("*", true, "5.3.1", true)], &["5.3.2", "4.0.4"], "CVE-2026-1001")], &kev);
    assert_eq!(f.len(), 1);
    let f = &f[0];
    assert_eq!((f.kind.as_str(), f.status.as_str(), f.fixed.as_str()), ("wordpress", "fail", "5.3.2"));
    assert_eq!(
        (f.vuln_id.as_str(), f.severity.as_str(), f.cvss, f.cvss_version.as_str()),
        ("CVE-2026-1001", "MEDIUM", Some(6.1), "3.1")
    );
    assert!(f.kev);
    assert_eq!(f.affected_range, "<=5.3.1");
    assert_eq!(f.fix_cmd, "wp plugin update akismet --path=/w/site");
    assert!(f.note.ends_with(
        "(Wordfence: https://www.wordfence.com/threat-intel/vulnerabilities/id/61c39f5f-3b17-4e4d-824e-241159a73400)"
    ));
    assert!(!f.fix_auto);

    let w = judge(&it, &[vuln(&[("*", true, "*", true)], &[], "")], &kev);
    assert_eq!((w[0].status.as_str(), w[0].fixed.as_str()), ("warn", ""));
    assert_eq!(w[0].vuln_id, "61c39f5f-3b17-4e4d-824e-241159a73400", "no CVE: the record's id");
    assert!(w[0].fix_cmd.starts_with("Update to version 1.2.4") && w[0].fix_cmd.contains("wordfence.com"));

    let old = judge(&it, &[vuln(&[("5.0", true, "5.3.1", true)], &["5.2"], "")], &kev);
    assert_eq!(old[0].status, "warn", "only an older patch: no fix above what is installed");
    assert!(judge(&it, &[vuln(&[("*", true, "5.3.1", false)], &["5.3.1"], "")], &kev).is_empty(), "past the range");
}

fn wordfence_net(body: String) -> Fake {
    Fake::new(move |r| {
        assert!(r.url.starts_with("https://www.wordfence.com/"), "{}", r.url);
        assert_eq!(r.header("Authorization"), Some("Bearer test-key"));
        Ok(Response::ok(body.clone()))
    })
}

#[test]
fn without_a_key_each_site_is_not_checked_with_how_to_get_one() {
    let _turn = one_at_a_time();
    let d = TempDir::new("wp").unwrap();
    let (name, root) = repo(&d, "app");
    sites(&root);
    let net = Fake::new(|r| panic!("nothing is asked without a key: {}", r.url));
    let mut s = scan(&net, &d, Options::default());
    wordpress_with(&mut s, &[(name, root)], None).unwrap();
    let gaps: Vec<&Finding> = s.findings.iter().filter(|f| f.kind == "unchecked").collect();
    let sites: Vec<&str> =
        gaps.iter().filter(|f| f.note == wordfence::GET_A_KEY).map(|f| f.component.as_str()).collect();
    assert_eq!(sites.len(), 2, "{sites:?}");
    assert!(sites.iter().any(|c| c.ends_with("app/site (5)")), "{sites:?}");
    assert!(gaps.iter().any(|f| f.component.contains("plugins/trunk")), "a version that couldn't be read is a gap too");
    assert!(s.findings.iter().all(|f| f.kind != KIND));
    assert_eq!(s.counts, vec![(COUNTED.to_string(), 8)]);
}

#[test]
fn with_a_key_the_sites_are_judged_and_the_report_carries_the_notices() {
    let _turn = one_at_a_time();
    let d = TempDir::new("wp").unwrap();
    let (name, root) = repo(&d, "app");
    sites(&root);
    let body = feed(&[
        record("00000000-0000-0000-0000-00000000000a", "plugin", "akismet", &[("*", true, "5.3.1", true)], &["5.3.2"]),
        record("00000000-0000-0000-0000-00000000000b", "plugin", "wordfence", &[("7.0", true, "7.11.0", true)], &[]),
        record(
            "00000000-0000-0000-0000-00000000000c",
            "core",
            "wordpress",
            &[("6.4", true, "6.4.3", false)],
            &["6.4.3"],
        ),
        record("00000000-0000-0000-0000-00000000000d", "theme", "astra", &[("*", true, "4.5.9", true)], &["4.6.0"]),
    ]);
    let net = wordfence_net(body);
    let mut s = scan(&net, &d, Options::default());
    wordpress_with(&mut s, &[(name, root.clone())], Some("test-key".into())).unwrap();
    let mut got: Vec<(&str, &str, &str, &str)> = s
        .findings
        .iter()
        .filter(|f| f.kind == KIND)
        .map(|f| (f.component.as_str(), f.version.as_str(), f.status.as_str(), f.fixed.as_str()))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("akismet", "5.3.1", "fail", "5.3.2"),
            ("wordfence", "7.11.0", "warn", ""),
            ("wordpress", "6.4.2", "fail", "6.4.3")
        ]
    );
    assert_eq!(s.unfixed, 1);
    let core = s.findings.iter().find(|f| f.component == "wordpress").unwrap();
    assert_eq!(core.location, command_path(&root.join("site")));
    let wf = s.findings.iter().find(|f| f.component == "wordfence").unwrap();
    assert_eq!(wf.location, command_path(&root.join("bedrock/composer.lock")));
    assert_eq!(crate::sources::wordfence::notices(&s.findings).len(), 2);
    assert_eq!(net.requests().len(), 1);
}

#[test]
fn a_feed_that_cant_be_had_is_not_checked() {
    let _turn = one_at_a_time();
    let d = TempDir::new("wp").unwrap();
    let (name, root) = repo(&d, "app");
    sites(&root);
    let net = Fake::new(|_| Ok(Response { status: 401, body: Vec::new(), etag: None }));
    let mut s = scan(&net, &d, Options::default());
    wordpress_with(&mut s, &[(name, root)], Some("test-key".into())).unwrap();
    let gap = s.findings.iter().find(|f| f.component.contains("against Wordfence Intelligence")).unwrap();
    assert!(gap.note.contains("HTTP 401"), "{}", gap.note);
    assert!(s.findings.iter().all(|f| f.kind != KIND));
}

#[test]
fn a_repo_without_wordpress_asks_nothing() {
    let _turn = one_at_a_time();
    let d = TempDir::new("wp").unwrap();
    let (name, root) = repo(&d, "app");
    write(&root, "composer.lock", r#"{"packages": [{"name": "monolog/monolog", "version": "3.5.0"}]}"#);
    write(&root, "plugins/readme.md", "not WordPress");
    let net = Fake::new(|r| panic!("asked {}", r.url));
    let mut s = scan(&net, &d, Options::default());
    wordpress_with(&mut s, &[(name, root)], Some("test-key".into())).unwrap();
    assert!(s.findings.is_empty() && s.counts.is_empty());
}
