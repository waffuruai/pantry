//! Hostile-input tests for every source's reader (S3): each is served
//! seeded corruptions of a good answer (bits flipped, cut short, bytes
//! inserted, deleted and repeated, other JSON, deep nesting, huge numbers)
//! and must return, never panic, and never lose the last good copy it had.

use crate::db::Cache;
use crate::utils::net::{Fake, Response};
use serde_json::json;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// How many corruptions each reader is served.
const ROUNDS: usize = 96;

/// A small, seeded generator (xorshift64*): the same corruptions every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

/// `good`, corrupted `ROUNDS` ways, after the shapes a hostile server sends.
pub(crate) fn mutations(good: &[u8], seed: u64) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"{}".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        b"\"text\"".to_vec(),
        b"1e999999".to_vec(),
        b"<html><body>Service unavailable</body></html>".to_vec(),
        "[".repeat(10_000).into_bytes(),
        vec![0xff; 4096],
        [good, good].concat(),
    ];
    let mut rng = Rng(seed | 1);
    while out.len() < ROUNDS {
        let mut b = good.to_vec();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(b.len().max(1));
            match rng.below(6) {
                0 if !b.is_empty() => b[at] ^= 1 << rng.below(8),
                1 => b.truncate(at),
                2 => b.insert(at.min(b.len()), (rng.next() & 0xff) as u8),
                3 if !b.is_empty() => {
                    b.remove(at);
                }
                4 => {
                    let end = (at + 1 + rng.below(64)).min(b.len());
                    let chunk = b[at.min(end)..end].to_vec();
                    for _ in 0..1 + rng.below(8) {
                        b.splice(at.min(b.len())..at.min(b.len()), chunk.iter().copied());
                    }
                }
                _ => {
                    let junk: &[u8] =
                        [&b"\"\\u0000\""[..], b"99999999999999999999999", b"{\"a\":", b"]]]", b"\xc3("][rng.below(5)];
                    b.splice(at.min(b.len())..at.min(b.len()), junk.iter().copied());
                }
            }
        }
        out.push(b);
    }
    out
}

/// Run `f` on each corruption of `good`, naming the one that panicked.
fn each(name: &str, good: &[u8], seed: u64, mut f: impl FnMut(&[u8])) {
    for (i, m) in mutations(good, seed).iter().enumerate() {
        if catch_unwind(AssertUnwindSafe(|| f(m))).is_err() {
            panic!("{name}: corruption {i} panicked: {:?}", String::from_utf8_lossy(&m[..m.len().min(200)]));
        }
    }
}

/// A zip that stores `name` uncompressed.
fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
    let mut local = b"PK\x03\x04".to_vec();
    local.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    local.extend((data.len() as u32).to_le_bytes());
    local.extend((data.len() as u32).to_le_bytes());
    local.extend((name.len() as u16).to_le_bytes());
    local.extend([0, 0]);
    local.extend(name.as_bytes());
    local.extend(data);
    let mut central = b"PK\x01\x02".to_vec();
    central.extend([20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    central.extend((data.len() as u32).to_le_bytes());
    central.extend((data.len() as u32).to_le_bytes());
    central.extend((name.len() as u16).to_le_bytes());
    central.extend([0; 12]);
    central.extend(0u32.to_le_bytes());
    central.extend(name.as_bytes());
    let mut z = local.clone();
    let cd_offset = z.len() as u32;
    z.extend(&central);
    z.extend(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    z.extend((central.len() as u32).to_le_bytes());
    z.extend(cd_offset.to_le_bytes());
    z.extend([0, 0]);
    z
}

fn answer(body: &[u8]) -> Fake {
    let body = body.to_vec();
    Fake::new(move |_| Ok(Response::ok(body.clone())))
}

/// Make every memoised answer stale, so the next call asks again.
fn stale(cache: &Cache) {
    cache.conn.execute("UPDATE runs SET ran_at = 0", []).unwrap();
    cache.conn.execute("DELETE FROM meta WHERE key LIKE '%_at' OR key LIKE '%_at:%'", []).unwrap();
}

fn cache() -> (crate::utils::temp::TempDir, Cache) {
    crate::sources::testing::cache()
}

#[test]
fn the_generator_is_seeded_and_varied() {
    let a = mutations(b"{\"a\": [1, 2, 3]}", 7);
    assert_eq!(a, mutations(b"{\"a\": [1, 2, 3]}", 7));
    assert_eq!(a.len(), ROUNDS);
    let distinct: std::collections::HashSet<&Vec<u8>> = a.iter().collect();
    assert!(distinct.len() > ROUNDS / 2);
}

#[test]
fn kev_keeps_its_last_good_list() {
    let (_d, c) = cache();
    let good =
        json!({"vulnerabilities": [{"cveID": "CVE-2026-1", "dateAdded": "2026-01-01", "vulnerabilityName": "x"}]})
            .to_string();
    crate::sources::kev::kev(&c, &answer(good.as_bytes()), false).unwrap();
    each("kev", good.as_bytes(), 1, |m| {
        stale(&c);
        let got = crate::sources::kev::kev(&c, &answer(m), false);
        assert!(got.is_ok_and(|ids| !ids.is_empty()), "the last good list is kept");
    });
}

#[test]
fn casks_keep_their_last_good_catalog() {
    let (_d, c) = cache();
    let good = json!([{"token": "firefox", "version": "145.0", "artifacts": [{"app": ["Firefox.app"]}]}]).to_string();
    crate::sources::releases::casks(&c, &answer(good.as_bytes()), false).unwrap();
    each("casks", good.as_bytes(), 2, |m| {
        stale(&c);
        let got = crate::sources::releases::casks(&c, &answer(m), false);
        assert!(got.is_ok_and(|v| !v.is_empty()), "the last good catalog is kept");
    });
}

#[test]
fn chrome_firefox_postgres_and_github_keep_their_last_good_answer() {
    use crate::sources::releases::{chrome, firefox, github_latest, postgres};
    let (_d, c) = cache();
    let chrome_good =
        json!({"releases": [{"version": "142.0.1", "serving": {"startTime": "2026-10-01T00:00:00Z"}}]}).to_string();
    chrome(&c, &answer(chrome_good.as_bytes()), "mac", false).unwrap();
    each("chrome", chrome_good.as_bytes(), 3, |m| {
        stale(&c);
        assert!(chrome(&c, &answer(m), "mac", false).is_ok_and(|v| !v.is_empty()));
    });
    let ff = json!({"LATEST_FIREFOX_VERSION": "145.0", "FIREFOX_ESR": "140.4.0esr"}).to_string();
    firefox(&c, &answer(ff.as_bytes()), false).unwrap();
    each("firefox", ff.as_bytes(), 4, |m| {
        stale(&c);
        assert!(firefox(&c, &answer(m), false).is_ok_and(|f| !f.latest.is_empty()));
    });
    let page = "<table><tr><td>CVE-2026-1 <a>x</a></td><td>17, 16</td><td>17.2, 16.6</td><td>server <a>8.8</a> \
                <a>AV:N</a></td><td>A flaw <a>more</a></td></tr></table>";
    let got = postgres(&c, &answer(page.as_bytes()), false).unwrap();
    each("postgres", page.as_bytes(), 5, |m| {
        stale(&c);
        assert!(postgres(&c, &answer(m), false).is_ok_and(|v| v.len() >= got.len().min(1)));
    });
    let gh = json!({"tag_name": "v1.2.3"}).to_string();
    github_latest(&c, &answer(gh.as_bytes()), "jdx/mise", false).unwrap();
    each("github", gh.as_bytes(), 6, |m| {
        stale(&c);
        assert!(github_latest(&c, &answer(m), "jdx/mise", false).is_ok_and(|v| !v.is_empty()));
    });
}

#[test]
fn arch_and_the_vscode_lists_keep_their_last_good_answer() {
    let (_d, c) = cache();
    let arch = json!([{"name": "AVG-1", "packages": ["openssl"], "status": "Fixed", "fixed": "3.0.1-1",
                       "issues": ["CVE-2026-1"], "severity": "High"}])
    .to_string();
    crate::sources::distros::arch(&c, &answer(arch.as_bytes()), false).unwrap();
    each("arch", arch.as_bytes(), 7, |m| {
        stale(&c);
        assert!(
            crate::sources::distros::arch(&c, &answer(m), false)
                .is_ok_and(|v| v.as_array().is_some_and(|a| !a.is_empty()))
        );
    });
    let lists =
        json!({"malicious": ["evil.ext"], "deprecated": {"old.ext": {"extension": {"id": "new.ext"}}}}).to_string();
    crate::sources::extensions::vscode_lists(&c, &answer(lists.as_bytes()), false).unwrap();
    each("vscode lists", lists.as_bytes(), 8, |m| {
        stale(&c);
        let got = crate::sources::extensions::vscode_lists(&c, &answer(m), false);
        assert!(got.is_ok_and(|l| !l.malicious.is_empty() || !l.deprecated.is_empty()));
    });
}

#[test]
fn per_item_lookups_never_panic() {
    let (_d, c) = cache();
    let item = || [("npm".to_string(), "lodash".to_string(), "4.17.20".to_string())];
    let eol = json!([{"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8"}]).to_string();
    each("endoflife", eol.as_bytes(), 9, |m| {
        stale(&c);
        let _ = crate::sources::endoflife::eol(&c, &answer(m), "nodejs", "18", false);
    });
    let deps = json!({"licenses": ["MIT"]}).to_string();
    each("deps.dev", deps.as_bytes(), 10, |m| {
        c.conn.execute("DELETE FROM runs", []).unwrap();
        let _ = crate::sources::package_licenses::lookup(&c, &answer(m), &item(), false, &crate::component::quiet);
    });
    let osv = json!({"results": [{"vulns": [{"id": "GHSA-1", "modified": "2026-01-01T00:00:00Z"}]}]}).to_string();
    each("osv", osv.as_bytes(), 11, |m| {
        c.conn.execute("DELETE FROM queries", []).unwrap();
        let _ = crate::sources::osv::lookup(&c, &answer(m), &item(), true, false, &|_| {}, &crate::component::quiet);
    });
    let breach = json!({"breaches": [["Adobe"]]}).to_string();
    each("breaches", breach.as_bytes(), 12, |m| {
        c.conn.execute("DELETE FROM runs", []).unwrap();
        let _ = crate::sources::breaches::check_emails(&c, &answer(m), false, vec!["a@example.com".into()]);
    });
    let verdict =
        json!({"query_status": "ok", "data": {"tasks": [{"clamav_results": ["Unix.Trojan.X-1"]}]}}).to_string();
    each("hash lookups", verdict.as_bytes(), 13, |m| {
        c.conn.execute("DELETE FROM hash_verdict", []).ok();
        let _ = crate::sources::hash_lookups::verify(&c, &answer(m), &"ab".repeat(32));
    });
}

#[test]
fn the_indicator_lists_and_the_rules_package_never_panic() {
    let (d, c) = cache();
    let dir = d.path().join("iocs");
    let lists = "# hashes\n0123456789abcdef0123456789abcdef;Test Kit\n(?i)\\\\evil\\.exe;90\nbad-c2.example\n";
    each("indicator lists", lists.as_bytes(), 14, |m| {
        stale(&c);
        let _ = crate::sources::indicator_lists::update(&c, &answer(m), &dir, true);
        let _ = crate::sources::indicator_lists::load(&dir);
    });
    let feodo = json!([{"ip_address": "198.51.100.7", "malware": "Emotet"}]).to_string();
    each("feodo", feodo.as_bytes(), 15, |m| {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("feodo-ipblocklist.json"), m).unwrap();
        let _ = crate::sources::indicator_lists::load(&dir);
    });
    let zip = stored_zip("yara-rules-full.yar", b"rule a { condition: true }");
    each("rules package", &zip, 16, |m| {
        let _ = crate::checks::documents::zip_members(m, "yara-rules-full.yar", 1 << 20);
    });
}

#[test]
fn a_sources_file_never_panics() {
    let good = crate::defaults::SOURCES.as_bytes();
    each("sources file", &good[..good.len().min(2048)], 17, |m| {
        let _ = crate::sources::file::parse(&String::from_utf8_lossy(m));
    });
}
