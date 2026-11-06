//! What the contract and advisories suites share: the built binary run with
//! a temp HOME and cache per test, offline, stdin closed; only its stdout,
//! stderr, exit codes and cache file are checked (specs/cli-contract.md).
//! `cargo test` runs the debug binary, `cargo test --release` the release
//! one; under `cargo llvm-cov` it is the instrumented build, and the
//! profile it writes counts toward the coverage gate.

#![allow(dead_code)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wpantry::utils::temp::TempDir;

/// The binary under test.
pub const BIN: &str = env!("CARGO_BIN_EXE_wpantry");

/// How long one run may take before the test fails (and the run is killed).
const TIMEOUT: Duration = Duration::from_secs(300);

/// The name the binary goes by, which its skill and errors carry.
pub fn name() -> String {
    Path::new(BIN).file_stem().unwrap().to_string_lossy().into_owned()
}

/// A path as an argument.
pub fn s(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 temp path")
}

/// Seconds since the epoch, as `time.time()`.
pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

/// One run: (exit code, stdout, stderr). A signal is exit code -1.
#[derive(Clone, Debug, PartialEq)]
pub struct Out {
    pub code: i32,
    pub out: String,
    pub err: String,
}

impl Out {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.out).unwrap_or_else(|e| panic!("{e}: {:?} {:?}", self.out, self.err))
    }
}

/// A temp HOME and cache; nothing reads the real home directory or writes
/// its cache.
pub struct Ctx {
    _tmp: TempDir,
    pub tmp: PathBuf,
    pub home: PathBuf,
    pub db: PathBuf,
    /// Variables removed from the inherited environment.
    unset: &'static [&'static str],
}

impl Ctx {
    /// The contract suite's: the user's own sources file stays out too.
    pub fn new() -> Ctx {
        Ctx::with_unset(&["XDG_CONFIG_HOME", "XDG_CACHE_HOME"])
    }

    pub fn with_unset(unset: &'static [&'static str]) -> Ctx {
        let tmp = TempDir::new("contract").unwrap();
        let root = tmp.path().to_path_buf();
        let home = root.join("home");
        std::fs::create_dir(&home).unwrap();
        let db = root.join("cache").join("w.db");
        Ctx { _tmp: tmp, tmp: root, home, db, unset }
    }

    pub fn run(&self, argv: &[&str]) -> Out {
        self.run_env(argv, &[])
    }

    /// A run with these variables set over the test's environment.
    pub fn run_env(&self, argv: &[&str], env: &[(&str, &str)]) -> Out {
        let mut cmd = Command::new(BIN);
        cmd.args(argv)
            .env("HOME", &self.home)
            .env("WPANTRY_DB", &self.db)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for k in self.unset {
            cmd.env_remove(k);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        run_with_timeout(cmd, argv)
    }

    /// `cmd --no-machine --path HOME --offline --no-input` and more.
    pub fn project_run(&self, cmd: &str, extra: &[&str]) -> Out {
        let mut argv = vec![cmd, "--no-machine", "--path", s(&self.home), "--offline", "--no-input"];
        argv.extend_from_slice(extra);
        self.run(&argv)
    }

    pub fn conn(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.db).unwrap()
    }
}

fn run_with_timeout(mut cmd: Command, argv: &[&str]) -> Out {
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("{BIN}: {e}"));
    let pipe = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                r.read_to_end(&mut buf).unwrap();
            }
            buf
        })
    };
    let out = pipe(child.stdout.take().map(|r| Box::new(r) as Box<dyn Read + Send>));
    let err = pipe(child.stderr.take().map(|r| Box::new(r) as Box<dyn Read + Send>));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{argv:?} took longer than {TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let text = |b: Vec<u8>| String::from_utf8(b).expect("UTF-8 output");
    Out { code: status.code().unwrap_or(-1), out: text(out.join().unwrap()), err: text(err.join().unwrap()) }
}

/// A directory that looks like a checkout (a .git dir, or a worktree's .git file).
pub fn git_repo(path: &Path, worktree: bool) -> PathBuf {
    std::fs::create_dir_all(path).unwrap();
    if worktree {
        std::fs::write(path.join(".git"), "gitdir: /elsewhere\n").unwrap();
    } else {
        std::fs::create_dir(path.join(".git")).unwrap();
    }
    path.to_path_buf()
}

pub fn write(path: &Path, text: impl AsRef<[u8]>) {
    std::fs::write(path, text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

pub fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn mkdir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
}

/// Copies a directory tree.
pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

/// The names of the entries in a directory.
pub fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> =
        std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

// JSON ---------------------------------------------------------------------

pub const ENVELOPE: &[&str] = &["schema", "impl", "version", "checked", "unfixed", "unknown_licenses", "findings"];

/// A finding field's JSON type, as the contract has it.
#[derive(Clone, Copy)]
pub enum Ty {
    Str,
    Bool,
    BoolOrNull,
    NumOrNull,
}

impl Ty {
    pub fn matches(self, v: &Value) -> bool {
        match self {
            Ty::Str => v.is_string(),
            Ty::Bool => v.is_boolean(),
            Ty::BoolOrNull => v.is_boolean() || v.is_null(),
            Ty::NumOrNull => v.is_number() || v.is_null(),
        }
    }
}

pub const FINDING: &[(&str, Ty)] = &[
    ("kind", Ty::Str),
    ("component", Ty::Str),
    ("version", Ty::Str),
    ("location", Ty::Str),
    ("vuln_id", Ty::Str),
    ("status", Ty::Str),
    ("fixed", Ty::Str),
    ("kev", Ty::Bool),
    ("severity", Ty::Str),
    ("note", Ty::Str),
    ("fix_cmd", Ty::Str),
    ("fix_auto", Ty::Bool),
    ("dep_scope", Ty::Str),
    ("dep_direct", Ty::BoolOrNull),
    ("affected_range", Ty::Str),
    ("cvss", Ty::NumOrNull),
    ("cvss_version", Ty::Str),
    ("epss", Ty::NumOrNull),
    ("epss_percentile", Ty::NumOrNull),
];

pub const SCOPES: &[&str] = &["runtime", "dev", "optional", "unknown"];

/// The keys of a JSON object.
pub fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().unwrap_or_else(|| panic!("not an object: {v}")).keys().cloned().collect()
}

pub fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

pub fn finding_keys() -> BTreeSet<String> {
    FINDING.iter().map(|(k, _)| k.to_string()).collect()
}

/// The `scan --json` envelope, checked field by field.
pub fn envelope(out: &str) -> Value {
    let env: Value = serde_json::from_str(out).unwrap_or_else(|e| panic!("{e}: {out:?}"));
    assert_eq!(keys(&env), set(ENVELOPE));
    assert_eq!(env["schema"], 1);
    for f in arr(&env["findings"]) {
        assert_eq!(keys(f), finding_keys(), "{f}");
        for (k, ty) in FINDING {
            assert!(ty.matches(&f[*k]), "{k}: {f}");
        }
        assert!(["fail", "warn"].contains(&str_(&f["status"])), "{f}");
        assert!(SCOPES.contains(&str_(&f["dep_scope"])), "{f}");
    }
    env
}

pub fn arr(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap_or_else(|| panic!("not an array: {v}"))
}

pub fn str_(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

/// The findings of an envelope with this `kind`.
pub fn of_kind<'a>(env: &'a Value, kind: &str) -> Vec<&'a Value> {
    arr(&env["findings"]).iter().filter(|f| f["kind"] == kind).collect()
}

// CSV ----------------------------------------------------------------------

/// The rows of a CSV text, as Python's csv.reader reads them: quoted
/// fields with doubled quotes, CRLF or LF line ends, an empty line an empty row.
pub fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let (mut quoted, mut started) = (false, false);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => (quoted, started) = (true, true),
            ',' => {
                row.push(std::mem::take(&mut field));
                started = true;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\r' => {
                if started || !field.is_empty() {
                    row.push(std::mem::take(&mut field));
                }
                rows.push(std::mem::take(&mut row));
                started = false;
            }
            _ => {
                field.push(c);
                started = true;
            }
        }
    }
    if started || !field.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// The rows after the header, keyed by it, as csv.DictReader reads them.
pub fn csv_dicts(text: &str) -> Vec<BTreeMap<String, String>> {
    let rows = csv_rows(text);
    let Some((header, rest)) = rows.split_first() else { return Vec::new() };
    rest.iter()
        .filter(|r| !r.is_empty())
        .map(|r| header.iter().cloned().zip(r.iter().cloned().chain(std::iter::repeat(String::new()))).collect())
        .collect()
}

// The cache ----------------------------------------------------------------

pub const CACHE: &[(&str, &[&str])] = &[
    ("meta", &["key", "value"]),
    ("vulns", &["id", "aliases", "summary", "details", "severity", "published", "modified", "url", "record"]),
    ("queries", &["ecosystem", "package", "version", "checked_at", "vuln_ids"]),
    (
        "findings",
        &[
            "kind",
            "component",
            "version",
            "location",
            "vuln_id",
            "status",
            "fixed",
            "kev",
            "severity",
            "note",
            "fix_cmd",
            "fix_auto",
            "dep_scope",
            "dep_direct",
            "affected_range",
            "cvss",
            "cvss_version",
            "epss",
            "epss_percentile",
        ],
    ),
    ("kev", &["cve", "added", "name"]),
    ("eol", &["product", "cycle", "eol", "latest"]),
    ("casks", &["app", "token", "version"]),
    ("runs", &["source", "fingerprint", "ran_at", "result"]),
    ("malicious", &["ecosystem", "name", "id"]),
];

/// A finding row as the tests write it: the columns before the scores.
pub fn insert_finding_sql() -> String {
    let cols = &CACHE.iter().find(|(t, _)| *t == "findings").unwrap().1[..15];
    format!("INSERT INTO findings ({}) VALUES ({})", cols.join(", "), vec!["?"; 15].join(", "))
}

/// `INSERT INTO table VALUES (?, ...)` with n placeholders.
pub fn insert_sql(verb: &str, table: &str, n: usize) -> String {
    format!("{verb} INTO {table} VALUES ({})", vec!["?"; n].join(", "))
}

/// A finding row: kind, component, version, location, vuln_id, status,
/// fixed, kev, severity, note, fix_cmd, fix_auto, dep_scope, dep_direct,
/// affected_range.
pub type FindingRow<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    i64,
    &'a str,
    &'a str,
    &'a str,
    i64,
    &'a str,
    Option<i64>,
    &'a str,
);

pub fn insert_finding(conn: &rusqlite::Connection, r: FindingRow) {
    conn.execute(
        &insert_finding_sql(),
        rusqlite::params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.8, r.9, r.10, r.11, r.12, r.13, r.14],
    )
    .unwrap();
}

/// A `vulns` row: id, aliases, summary, details, severity, published, modified, url, record.
pub fn insert_vuln(conn: &rusqlite::Connection, verb: &str, row: [&str; 9]) {
    conn.execute(&insert_sql(verb, "vulns", 9), rusqlite::params_from_iter(row)).unwrap();
}

/// A `queries` row: ecosystem, package, version, checked_at (a float, or
/// an integer as some tests write it), vuln_ids.
pub fn insert_query(
    conn: &rusqlite::Connection,
    verb: &str,
    eco: &str,
    name: &str,
    version: &str,
    at: impl rusqlite::ToSql,
    ids: &str,
) {
    conn.execute(&insert_sql(verb, "queries", 5), rusqlite::params![eco, name, version, at, ids]).unwrap();
}

// A deflated zip, as Python's zipfile writes one --------------------------------

/// CRC-32 (IEEE), the zip member checksum.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Raw DEFLATE (RFC 1951): one fixed-Huffman block, greedy LZ77 matches
/// within a 32 KiB window. Small and slow, enough for test documents.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    const LEN_BASE: [usize; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227,
        258,
    ];
    const LEN_EXTRA: [u32; 29] =
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    const DIST_BASE: [usize; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
        6145, 8193, 12289, 16385, 24577,
    ];
    const DIST_EXTRA: [u32; 30] =
        [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

    struct Bits {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }
    impl Bits {
        /// Header fields and extra bits, LSB first.
        fn put(&mut self, v: u32, count: u32) {
            self.acc |= (v as u64) << self.n;
            self.n += count;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }
        /// Huffman codes, MSB first.
        fn code(&mut self, code: u32, len: u32) {
            for i in (0..len).rev() {
                self.put((code >> i) & 1, 1);
            }
        }
        /// A literal/length symbol in the fixed code.
        fn sym(&mut self, sym: u32) {
            match sym {
                0..=143 => self.code(0x30 + sym, 8),
                144..=255 => self.code(0x190 + sym - 144, 9),
                256..=279 => self.code(sym - 256, 7),
                _ => self.code(0xC0 + sym - 280, 8),
            }
        }
    }
    let slot = |base: &[usize], v: usize| base.iter().rposition(|&b| b <= v).unwrap();

    let mut w = Bits { out: Vec::new(), acc: 0, n: 0 };
    w.put(1, 1); // the last block
    w.put(1, 2); // fixed Huffman
    let mut i = 0;
    while i < data.len() {
        let (mut best, mut dist) = (0, 0);
        let max = (data.len() - i).min(258);
        for d in 1..=i.min(32768) {
            let len = (0..max).take_while(|&k| data[i + k] == data[i + k - d]).count();
            if len > best {
                (best, dist) = (len, d);
                if len == max {
                    break;
                }
            }
        }
        if best >= 3 {
            let l = slot(&LEN_BASE, best);
            w.sym(257 + l as u32);
            w.put((best - LEN_BASE[l]) as u32, LEN_EXTRA[l]);
            let d = slot(&DIST_BASE, dist);
            w.code(d as u32, 5);
            w.put((dist - DIST_BASE[d]) as u32, DIST_EXTRA[d]);
            i += best;
        } else {
            w.sym(data[i] as u32);
            i += 1;
        }
    }
    w.sym(256);
    if w.n > 0 {
        w.put(0, 8 - w.n);
    }
    w.out
}

/// A zip whose members are all deflated.
pub fn zip_deflated(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in members {
        let packed = deflate(data);
        let crc = crc32(data);
        let offset = out.len() as u32;
        let common = |v: &mut Vec<u8>| {
            v.extend_from_slice(&20u16.to_le_bytes()); // version needed
            v.extend_from_slice(&0u16.to_le_bytes()); // flags
            v.extend_from_slice(&8u16.to_le_bytes()); // deflated
            v.extend_from_slice(&[0, 0, 0x21, 0]); // time, date (1980-01-01)
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes()); // extra
        };
        out.extend_from_slice(b"PK\x03\x04");
        common(&mut out);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&packed);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        common(&mut central);
        central.extend_from_slice(&[0; 10]); // comment, disk, internal and external attributes
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0, 0, 0, 0]); // disks
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&[0, 0]); // comment
    out
}
