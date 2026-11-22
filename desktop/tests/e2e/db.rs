//! Rows the suite writes straight into the scanner's SQLite cache, after a
//! real scan has created its tables. Each helper runs in one transaction and
//! closes the connection, since Windows can't replace an open database.

use crate::tools::touch_command;
use rusqlite::{Connection, Transaction, params};
use std::path::Path;

pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// Run `body` in one transaction on the cache at `db`, then close it.
pub fn with_db<T>(db: &Path, body: impl FnOnce(&Transaction) -> rusqlite::Result<T>) -> T {
    let mut connection = Connection::open(db).expect("open the cache");
    let tx = connection.transaction().expect("begin");
    let value = body(&tx).expect("write the cache");
    tx.commit().expect("commit");
    connection
        .close()
        .map_err(|(_, e)| e)
        .expect("close the cache");
    value
}

pub fn clear(tx: &Transaction) -> rusqlite::Result<()> {
    for table in ["scans", "exposures", "findings"] {
        tx.execute(&format!("DELETE FROM {table}"), [])?;
    }
    Ok(())
}

#[derive(Default)]
pub struct Counts {
    pub fails: i64,
    pub warns: i64,
    pub unchecked: i64,
    pub unfixed: i64,
}

pub fn insert_scan(tx: &Transaction, at: f64, scope: &str, c: Counts) -> rusqlite::Result<i64> {
    tx.execute(
        "INSERT INTO scans (started_at, finished_at, version, scope, counts, fails, warns,
                            unchecked, checked, unfixed, unknown_licenses)
         VALUES (?, ?, '0.6.0', ?, '{}', ?, ?, ?, '[[\"lockfiles\", 1]]', ?, 0)",
        params![
            at - 2.0,
            at,
            scope,
            c.fails,
            c.warns,
            c.unchecked,
            c.unfixed
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// An open or resolved exposure from an earlier machine scan.
struct Earlier<'a> {
    name: &'a str,
    status: &'a str,
    severity: &'a str,
    resolved: Option<f64>,
    instructions: &'a str,
}

fn add_exposure(tx: &Transaction, scan: i64, at: f64, e: Earlier) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id,
                                status, severity, note, first_scan, first_at, last_scan,
                                last_at, resolved_at, fix_cmd)
         VALUES (?, 'machine:~', 'osv', ?, '1.0', '/test/another-project', 'TEST-2026-OLDER',
                 ?, ?, 'Evidence from an earlier scan.', ?, ?, ?, ?, ?, ?)",
        params![
            e.name,
            e.name,
            e.status,
            e.severity,
            scan,
            at,
            scan,
            at,
            e.resolved,
            e.instructions
        ],
    )?;
    Ok(())
}

type Row<'a> = (
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
);

fn insert_findings(tx: &Transaction, rows: &[Row]) -> rusqlite::Result<()> {
    for r in rows {
        tx.execute(
            "INSERT INTO findings (kind, component, version, location, vuln_id, status, fixed,
                                   kev, severity, note, fix_cmd, fix_auto)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.8, r.9, r.10, r.11],
        )?;
    }
    Ok(())
}

fn open_exposure(
    tx: &Transaction,
    project: &str,
    (component, version, id): (&str, &str, &str),
    scan: i64,
    at: f64,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id,
                                status, severity, first_scan, first_at, last_scan, last_at)
         VALUES (?, ?, 'osv', ?, ?, ?, ?, 'fail', 'high', ?, ?, ?, ?)",
        params![
            format!("osv|{component}|{project}|{id}"),
            format!("repos:{project}"),
            component,
            version,
            project,
            id,
            scan,
            at,
            scan,
            at
        ],
    )?;
    Ok(())
}

/// The main suite's data: an earlier machine scan with one open and one
/// resolved exposure, then a scan of `project` with an automatic fix (it
/// creates `applied`), a manual one and an unchecked source. Returns the
/// scan id and the fix command.
pub fn seed(tx: &Transaction, project: &Path, applied: &Path) -> rusqlite::Result<(i64, String)> {
    let now = now();
    let patch = touch_command(applied);
    let earlier = insert_scan(
        tx,
        now - 60.0,
        "machine:~",
        Counts {
            fails: 1,
            ..Counts::default()
        },
    )?;
    let open = Earlier {
        name: "older-open",
        status: "fail",
        severity: "medium",
        resolved: None,
        instructions: "Update the installed tool.",
    };
    add_exposure(tx, earlier, now - 60.0, open)?;
    let resolved = Earlier {
        name: "older-resolved",
        status: "warn",
        severity: "low",
        resolved: Some(now - 10.0),
        instructions: "",
    };
    add_exposure(tx, earlier, now - 60.0, resolved)?;
    let p = project.display().to_string();
    let scan = insert_scan(
        tx,
        now,
        &format!("repos:{p}"),
        Counts {
            fails: 2,
            warns: 1,
            unchecked: 1,
            unfixed: 1,
        },
    )?;
    insert_findings(
        tx,
        &[
            (
                "osv",
                "auto-fixture",
                "1.0",
                &p,
                "TEST-2026-AUTO",
                "fail",
                "2.0",
                0,
                "high",
                "Automatic test update.",
                &patch,
                1,
            ),
            (
                "osv",
                "manual-fixture",
                "1.0",
                &p,
                "TEST-2026-MANUAL",
                "fail",
                "",
                0,
                "medium",
                "Manual update.",
                "Install the vendor update.",
                0,
            ),
            (
                "unchecked",
                "Feed unavailable",
                "",
                "",
                "source",
                "warn",
                "",
                0,
                "",
                "This feed did not answer.",
                "",
                0,
            ),
        ],
    )?;
    // What the advisory is: aliases with public-database shapes (links), a
    // summary and a weakness type, as the scanner saves them.
    tx.execute(
        "UPDATE findings SET summary = 'Out-of-bounds write in the test decoder',
                             aliases = 'GHSA-test-aaaa-bbbb CVE-2099-0001', cwe = 'CWE-787'
         WHERE vuln_id = 'TEST-2026-AUTO'",
        [],
    )?;
    open_exposure(tx, &p, ("auto-fixture", "1.0", "TEST-2026-AUTO"), scan, now)?;
    Ok((scan, patch))
}

/// Synthetic data for the documentation screenshots: invented package names
/// marked "demo" and DEMO-* ids, so no real advisory is misquoted.
pub fn demo_seed(tx: &Transaction, project: &Path, applied: &Path) -> rusqlite::Result<i64> {
    let now = now();
    let patch = touch_command(applied);
    let p = project.display().to_string();
    let earlier = insert_scan(
        tx,
        now - 86_400.0,
        "machine:~",
        Counts {
            fails: 1,
            ..Counts::default()
        },
    )?;
    for (name, status, severity, resolved) in [
        ("demo-http-client", "fail", "medium", None),
        ("demo-json-parser", "warn", "low", Some(now - 3600.0)),
    ] {
        tx.execute(
            "INSERT INTO exposures (key, scope, kind, component, version, location, vuln_id,
                                    status, severity, note, first_scan, first_at, last_scan,
                                    last_at, resolved_at, fix_cmd)
             VALUES (?, 'machine:~', 'osv', ?, '3.1.0', ?, 'DEMO-2026-0003', ?, ?, 'Demo data.',
                     ?, ?, ?, ?, ?, 'Update the installed tool.')",
            params![
                name,
                name,
                p,
                status,
                severity,
                earlier,
                now - 86_400.0,
                earlier,
                now - 86_400.0,
                resolved
            ],
        )?;
    }
    let scan = insert_scan(
        tx,
        now,
        &format!("repos:{p}"),
        Counts {
            fails: 2,
            warns: 1,
            unchecked: 1,
            unfixed: 1,
        },
    )?;
    insert_findings(
        tx,
        &[
            (
                "osv",
                "demo-image-tools",
                "1.4.2",
                &p,
                "DEMO-2026-0001",
                "fail",
                "1.4.9",
                0,
                "high",
                "Demo data: a crafted image can run code.",
                &patch,
                1,
            ),
            (
                "osv",
                "demo-markdown",
                "2.0.1",
                &p,
                "DEMO-2026-0002",
                "fail",
                "",
                0,
                "medium",
                "Demo data: a crafted link can slow the page.",
                "Install the maker's update when it is out.",
                0,
            ),
            (
                "unchecked",
                "Advisory feed",
                "",
                "",
                "source",
                "warn",
                "",
                0,
                "",
                "This source did not answer.",
                "",
                0,
            ),
        ],
    )?;
    // Demo advisory text: DEMO ids only, so no real notice is misquoted.
    tx.execute(
        "UPDATE findings SET summary = 'Demo data: heap overflow when decoding a crafted image',
                             aliases = 'DEMO-GHSA-0001 DEMO-OSV-0001', cwe = 'CWE-787',
                             affected_range = '>=1.0.0, <1.4.9', cvss = 8.8, cvss_version = '3.1',
                             epss = 0.03, dep_scope = 'runtime', dep_direct = 1
         WHERE vuln_id = 'DEMO-2026-0001'",
        [],
    )?;
    tx.execute(
        "UPDATE findings SET summary = 'Demo data: slow parsing of crafted links', cwe = 'CWE-1333'
         WHERE vuln_id = 'DEMO-2026-0002'",
        [],
    )?;
    open_exposure(
        tx,
        &p,
        ("demo-image-tools", "1.4.2", "DEMO-2026-0001"),
        scan,
        now,
    )?;
    Ok(scan)
}

/// A newer scan with one automatic fix per file; each fix creates its file.
pub fn seed_fixable(tx: &Transaction, project: &Path, files: &[&Path]) -> rusqlite::Result<i64> {
    let now = now();
    let p = project.display().to_string();
    let scan = insert_scan(
        tx,
        now,
        &format!("repos:{p}"),
        Counts {
            fails: files.len() as i64,
            ..Counts::default()
        },
    )?;
    tx.execute("DELETE FROM findings", [])?;
    for (n, path) in files.iter().enumerate() {
        let patch = touch_command(path);
        let name = format!("batch-fixture-{n}");
        let id = format!("TEST-BATCH-{n}");
        tx.execute(
            "INSERT INTO findings (kind, component, version, location, vuln_id, status, fixed,
                                   kev, severity, note, fix_cmd, fix_auto)
             VALUES ('osv', ?, '1.0', ?, ?, 'fail', '2.0', 0, 'high', 'Batch test update.', ?, 1)",
            params![name, p, id, patch],
        )?;
        open_exposure(tx, &p, (&name, "1.0", &id), scan, now)?;
    }
    Ok(scan)
}
