use super::*;
use crate::checks::machine::testing::scan;
use crate::utils::net::{Fake, Response};
use serde_json::{Value, json};

/// The findings that aren't not-checked lines, and whether there are any of those.
fn found(s: &crate::checks::Scan) -> (Vec<crate::finding::Finding>, bool) {
    let (gaps, real): (Vec<_>, Vec<_>) = s.findings.iter().cloned().partition(|f| f.kind == "unchecked");
    (real, !gaps.is_empty())
}

fn app(id: &str, name: &str, version: &str) -> App {
    App { id: id.into(), name: name.into(), version: version.into(), location: format!("/Applications/{name}.app") }
}

#[test]
fn only_the_table_names_an_app_and_its_version_is_its_first_word() {
    let found = [
        app("us.zoom.xos", "zoom.us", "7.1.9 (88375)"),
        app("org.gimp.gimp-3.2", "GIMP", "3.2.2"),
        app("org.gimp.gimpish", "Gimpish", "1.0"),
        app("com.tinyspeck.slackmacgap", "Slack", "4.53.287"),
    ];
    let got: Vec<(String, String, Option<String>, bool)> =
        subjects(&found).into_iter().map(|x| (x.name, x.version, x.product, x.nvd)).collect();
    let want = |n: &str, v: &str, p: &str| (n.to_string(), v.to_string(), Some(p.to_string()), true);
    assert_eq!(
        got,
        vec![
            want("zoom.us", "7.1.9", "Zoom Workplace"),
            want("zoom.us", "7.1.9", "Zoom"),
            want("GIMP", "3.2.2", "GIMP")
        ]
    );
    let zoom = &subjects(&found[..1])[0];
    assert!(zoom.vendors.contains(&"zoom communications".to_string()), "{:?}", zoom.vendors);
    assert_eq!(zoom.system, software_cves::this_system());
}

#[test]
fn the_flatpaks_and_snaps_the_table_names_are_read() {
    let flatpaks = "org.videolan.VLC\t3.0.21\norg.example.Thing\t1.0\norg.signal.Signal\t\n";
    let snaps = "Name  Version  Rev  Tracking  Publisher  Notes\n\
                 signal-desktop  7.40.0  700  latest/stable  snapcrafters✪  -\n\
                 core22  20240111  1122  latest/stable  canonical✓  base\n";
    assert_eq!(
        linux_apps(flatpaks, snaps),
        vec![
            App {
                id: "org.videolan.VLC".into(),
                name: "org.videolan.VLC".into(),
                version: "3.0.21".into(),
                location: "flatpak:org.videolan.VLC".into()
            },
            App {
                id: "snap:signal-desktop".into(),
                name: "signal-desktop".into(),
                version: "7.40.0".into(),
                location: "/snap/bin/signal-desktop".into()
            },
        ]
    );
}

/// A CVE JSON 5 record: `affected` as given.
fn cna(id: &str, affected: Value) -> Value {
    json!({"cveMetadata": {"cveId": id, "state": "PUBLISHED", "datePublished": "2026-01-10T00:00:00"},
           "containers": {"cna": {"title": format!("{id} issue"), "affected": affected}}})
}

/// NVD's copy (FKIE's shape): one configuration of `matches`.
fn nvd(id: &str, matches: Value) -> Value {
    json!({"id": id, "published": "2026-01-11T00:00:00", "vulnStatus": "Analyzed",
           "descriptions": [{"lang": "en", "value": format!("{id} from NVD")}],
           "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.5}}]},
           "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": matches}]}]})
}

/// The index, answering `browse` and `search` for each (vendor, products,
/// records) given; NVD's copies listed beside the CVE list's.
fn index(vendors: Vec<(&'static str, &'static str, Vec<Value>, Vec<Value>)>) -> Fake {
    Fake::new(move |r| {
        for (vendor, product, list, copies) in &vendors {
            if r.url.ends_with(&format!("/browse/{vendor}")) {
                return Ok(Response::ok(json!([product]).to_string()));
            }
            if r.url.contains(&format!("search/{vendor}/{}", crate::sources::cve_records::segment(product))) {
                let pair = |id_of: &dyn Fn(&Value) -> Value, r: &Value| json!([id_of(r), r]);
                let lists = json!({
                    "cvelistv5": list.iter().map(|r| pair(&|r: &Value| r["cveMetadata"]["cveId"].clone(), r)).collect::<Vec<_>>(),
                    "fkie_nvd": copies.iter().map(|r| pair(&|r: &Value| r["id"].clone(), r)).collect::<Vec<_>>(),
                });
                let total = list.len() + copies.len();
                return Ok(Response::ok(json!({"total_count": total, "page_size": 100, "results": lists}).to_string()));
            }
        }
        Ok(if r.url.contains("/browse/") { Response::ok("[]") } else { Response::not_found() })
    })
}

/// Signal's records name no product (`n/a`): NVD's configuration is what
/// places the install.
#[test]
fn a_record_naming_no_product_is_judged_by_nvds_configuration() {
    let d = crate::utils::temp::TempDir::new("apps-signal").unwrap();
    let id = "CVE-2023-24069";
    let net = index(vec![(
        "signal",
        "signal-desktop",
        vec![cna(
            id,
            json!([{"vendor": "n/a", "product": "n/a", "versions": [{"version": "n/a", "status": "affected"}]}]),
        )],
        vec![nvd(
            id,
            json!([{"vulnerable": true, "criteria": "cpe:2.3:a:signal:signal-desktop:*:*:*:*:*:*:*:*",
                    "versionEndIncluding": "6.2.0"}]),
        )],
    )]);
    let mut s = scan(&net, &d);
    check_found(&mut s, &[app("org.whispersystems.signal-desktop", "Signal", "6.1.0")]).unwrap();
    let (real, gaps) = found(&s);
    let got: Vec<(&str, &str, &str, &str)> = real
        .iter()
        .map(|f| (f.component.as_str(), f.vuln_id.as_str(), f.status.as_str(), f.affected_range.as_str()))
        .collect();
    assert_eq!(got, [("Signal", id, "warn", "<=6.2.0")], "no fixed version named: a warning");
    assert_eq!(real[0].cvss, Some(7.5), "NVD's score, the record having none");
    assert!(!gaps, "{:?}", s.findings);
    let mut s = scan(&net, &d);
    check_found(&mut s, &[app("org.whispersystems.signal-desktop", "Signal", "7.40.0")]).unwrap();
    assert!(s.findings.is_empty(), "judged clean, not left unchecked: {:?}", s.findings);
}

/// VLC: the publisher's entry can't be read; NVD's range judges it, fix
/// and all.
#[test]
fn nvd_settles_what_the_publishers_entry_cant() {
    let d = crate::utils::temp::TempDir::new("apps-vlc").unwrap();
    let id = "CVE-2026-0001";
    let entry = json!([{"vendor": "VideoLAN", "product": "VLC media player",
                        "versions": [{"version": "3.0.x and earlier", "status": "affected"}]}]);
    let copy = nvd(
        id,
        json!([{"vulnerable": true, "criteria": "cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "3.0.21"}]),
    );
    let net = index(vec![("videolan", "vlc media player", vec![cna(id, entry)], vec![copy])]);
    let mut s = scan(&net, &d);
    check_found(&mut s, &[app("org.videolan.vlc", "VLC", "3.0.20")]).unwrap();
    let (real, gaps) = found(&s);
    let got: Vec<(&str, &str, &str)> =
        real.iter().map(|f| (f.vuln_id.as_str(), f.status.as_str(), f.fixed.as_str())).collect();
    assert_eq!(got, [(id, "fail", "3.0.21")]);
    assert!(!gaps, "{:?}", s.findings);
    let mut s = scan(&net, &d);
    check_found(&mut s, &[app("org.videolan.vlc", "VLC", "3.0.21")]).unwrap();
    assert!(s.findings.is_empty(), "{:?}", s.findings);
}
