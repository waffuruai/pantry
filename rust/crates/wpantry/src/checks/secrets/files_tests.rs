use super::*;
use crate::checks::Options;
use crate::checks::files::roots::set_test_system;
use crate::checks::files::view::opens;
use crate::db::Cache;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;

/// A GitHub token the bundled rules find (stored reversed, so this file
/// holds none).
fn token() -> String {
    "gvrMOVt7kvW7QXR9RsHxWt65VWBByL5t718Z_phg".chars().rev().collect()
}

fn write(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// A deep scan of this test's home and its one other folder, the
/// malware scan off; `history` the secrets the history scan found.
fn deep_scan<'a>(net: &'a Fake, db: &Path, deep: bool, history: &[(PathBuf, &str, usize)]) -> Scan<'a> {
    crate::utils::walk::forget_walks();
    let opts = Options { deep, machine: true, no_malware: true, ..Default::default() };
    let mut s = Scan::new(opts, Cache::open(Some(db)).unwrap(), net, &|_| {}, &|_| {});
    for (p, rule, line) in history {
        s.history_secrets.insert((p.clone(), rule.to_string(), *line));
    }
    if deep {
        report(&mut s);
    }
    s
}

fn secrets(s: &Scan) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = s
        .findings
        .iter()
        .filter(|f| f.kind == "secret")
        .map(|f| (f.component.replace('\\', "/"), f.location.clone()))
        .collect();
    v.sort();
    v
}

/// `--deep` finds a secret in an uncommitted file, in `~/.config` and in
/// another folder of the computer, not the one history already reported;
/// a second deep scan reads none of them again; a folder it can't read is
/// not checked.
#[test]
fn deep_reads_every_file_once_and_names_what_it_cant_read() {
    let _home = crate::utils::files::test_home();
    let home = crate::utils::files::home();
    let d = TempDir::new("deep-secrets").unwrap();
    let other = d.path().join("disk/opt");
    set_test_system(vec![d.path().join("disk")], Vec::new());
    let t = token();
    let committed = home.join("code/app/committed.env");
    let files = [
        home.join("code/app/.env"),
        home.join(".config/tool/credentials"),
        other.join("deploy/token.txt"),
        committed.clone(),
    ];
    for f in &files {
        write(f, &format!("export GITHUB_TOKEN={t}\n"));
    }
    write(&home.join("code/app/README.md"), "nothing secret\n");
    let net = Fake::offline();
    let db = d.path().join("w.db");
    let history = [(committed.clone(), "github-pat", 1)];
    let s = deep_scan(&net, &db, true, &history);
    // One separator, so Windows' paths compare.
    let short = |p: &Path| crate::utils::files::short(&p.to_string_lossy()).replace('\\', "/");
    let want: Vec<(String, String)> = {
        let mut w: Vec<(String, String)> = files[..3].iter().map(|f| (short(f), "line 1".to_string())).collect();
        w.sort();
        w
    };
    assert_eq!(secrets(&s), want, "the committed one only once, from history");
    let gh = s.findings.iter().find(|f| f.kind == "secret").unwrap();
    assert_eq!((gh.vuln_id.as_str(), gh.status.as_str()), ("github-pat", "fail"));
    assert!(gh.note.contains("in a file on this machine") && gh.fix_cmd.contains("Rotate it"), "{gh:?}");
    let read: Vec<usize> = files.iter().map(|f| opens(f)).collect();
    assert!(read.iter().all(|n| *n >= 1), "{read:?}");
    // Again, nothing changed: nothing read again, the same findings.
    let again = deep_scan(&net, &db, true, &history);
    assert_eq!(files.iter().map(|f| opens(f)).collect::<Vec<_>>(), read, "a second deep scan reads no file again");
    assert_eq!(secrets(&again), want);
    // Without --deep, no file is read for secrets: only history's.
    let plain = deep_scan(&net, &db, false, &history);
    assert!(plain.secret_file_jobs().is_empty() && secrets(&plain).is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = home.join("Library/Mail");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads anything: nothing to report then.
        if std::fs::read_dir(&locked).is_err() {
            let s = deep_scan(&net, &db, true, &history);
            let gap = s
                .findings
                .iter()
                .find(|f| f.kind == "unchecked" && f.component.contains("this user can't read"))
                .unwrap_or_else(|| panic!("{:?}", s.findings));
            assert!(gap.component.starts_with("1 folder under ~"), "{gap:?}");
            assert!(gap.note.contains("~/Library/Mail"), "by place: {gap:?}");
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    set_test_system(Vec::new(), Vec::new());
}

#[test]
fn a_file_too_big_or_prefiltered_isnt_read() {
    let d = TempDir::new("secret-plan").unwrap();
    let root = d.path();
    write(&root.join("a.env"), "x");
    write(&root.join("logo.png"), "x");
    let big = root.join("big.log");
    std::fs::write(&big, vec![b'a'; (MAX_FILE + 1) as usize]).unwrap();
    let engine = Engine {
        scanner: crate::checks::supply_chain::leaks::Rules::new(None).scanner().unwrap(),
        fingerprint: String::new(),
    };
    let walk = crate::utils::walk::walk(root, 1);
    let stat = |p: &Path| crate::checks::files::FileView::new(p.to_path_buf()).stat();
    let p = plan(Some(&engine), root, &walk, &stat);
    let reads: Vec<&str> = p.reads.iter().map(|r| r.rel.as_str()).collect();
    assert_eq!(reads, ["a.env"], "images are prefiltered, a big file isn't read");
    assert_eq!(p.too_big, [big]);
    assert!(plan(None, root, &walk, &stat).reads.is_empty(), "no engine: not deep, nothing read");
}
