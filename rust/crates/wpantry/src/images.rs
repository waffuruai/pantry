//! Container images (F12): `docker|podman create` then `export` to a temp
//! directory, read by the same extractors as the machine and the repos (the
//! OS package database, and the lockfiles shipped in the image). There is
//! no layer attribution: export flattens the image. The container and the
//! temp directory are removed even on error.
//!
//! The export is read as a tar stream by a reader written here: only the
//! files the extractors read are kept, each under a size cap, and an entry
//! naming a path outside the image root (`..`, absolute links) is ignored,
//! since an image's contents are untrusted.

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::json::{self, str_at};
use crate::lockfiles::{self, Package};
use crate::osdb;
use crate::system::{TempDir, exec, parse_os_release, which};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// The largest single file kept from an image.
pub const MAX_FILE: u64 = 64 << 20;

/// One package found in an image, with the file it was read from.
#[derive(Clone, Debug, PartialEq)]
pub struct ImagePackage {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub source: String,
}

/// The kernel's source package, which an image carries only as headers
/// (linux-libc-dev): a container runs on the host's kernel, so the kernel's
/// advisories are the host's, not the image's (osv-scanner skips it too).
pub fn host_kernel(p: &ImagePackage) -> bool {
    p.source == "/var/lib/dpkg/status" && p.name == "linux"
}

/// docker, else podman.
pub fn engine() -> Option<PathBuf> {
    which("docker").or_else(|| which("podman"))
}

/// The local image id for `r`, or "" when it isn't pulled or built here.
pub fn image_id(engine: &Path, r: &str) -> String {
    let argv = [
        engine.as_os_str(),
        OsStr::new("image"),
        OsStr::new("inspect"),
        OsStr::new("--format"),
        OsStr::new("{{.Id}}"),
        OsStr::new(r),
    ];
    let out = exec(&argv, &[], Duration::from_secs(20))
        .map(|o| if o.code == Some(0) { o.stdout } else { String::new() })
        .unwrap_or_default();
    let id = out.trim().lines().last().unwrap_or("").trim();
    let hex = id.strip_prefix("sha256:").unwrap_or(id);
    if hex.len() >= 12 && hex.bytes().all(|b| b.is_ascii_hexdigit()) { id.to_string() } else { String::new() }
}

/// Removes the created container when dropped.
struct Container<'a> {
    engine: &'a Path,
    id: String,
}

impl Drop for Container<'_> {
    fn drop(&mut self) {
        let _ = exec(
            &[self.engine.as_os_str(), OsStr::new("rm"), OsStr::new("-f"), OsStr::new(&self.id)],
            &[],
            Duration::from_secs(60),
        );
    }
}

fn wanted(path: &str) -> bool {
    if matches!(path, "etc/os-release" | "usr/lib/os-release" | "var/lib/dpkg/status" | "lib/apk/db/installed") {
        return true;
    }
    let mut parts = path.split('/');
    let name = parts.next_back().unwrap_or("");
    // The same pruning as a repo walk: dependency and build directories.
    let pruned = path.split('/').any(|p| crate::repos::PRUNE.contains(&p));
    !pruned && (lockfiles::supported(name) || (name.starts_with("requirements") && name.ends_with(".txt")))
}

/// A relative path inside the image root, or None when it would escape it.
fn inside(name: &str) -> Option<PathBuf> {
    let p = Path::new(name.trim_start_matches("./").trim_start_matches('/'));
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

fn octal(field: &[u8]) -> u64 {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        // base-256, for sizes over 8 GiB
        return field[1..].iter().fold(0u64, |acc, b| acc.saturating_mul(256).saturating_add(u64::from(*b)));
    }
    let s: String = field.iter().take_while(|b| **b != 0).map(|b| *b as char).collect();
    u64::from_str_radix(s.trim(), 8).unwrap_or(0)
}

fn cstr(field: &[u8]) -> String {
    String::from_utf8_lossy(&field[..field.iter().position(|b| *b == 0).unwrap_or(field.len())]).into_owned()
}

/// pax extended header records ("len key=value\n").
fn pax(data: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let text = String::from_utf8_lossy(data);
    let mut rest: &str = &text;
    while let Some((len, _)) = rest.split_once(' ') {
        let Ok(n) = len.parse::<usize>() else { break };
        if n == 0 || n > rest.len() {
            break;
        }
        let record = &rest[len.len() + 1..n];
        if let Some((k, v)) = record.trim_end_matches('\n').split_once('=') {
            out.insert(k.to_string(), v.to_string());
        }
        rest = &rest[n..];
    }
    out
}

/// Extract the wanted files of a tar into `root`. Symlinks and hard links
/// to wanted files are followed when they stay inside the image.
pub fn untar(tar: &Path, root: &Path) -> Result<()> {
    let mut r = BufReader::new(std::fs::File::open(tar)?);
    let mut header = [0u8; 512];
    let (mut long_name, mut pax_path, mut pax_link): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let mut links: Vec<(PathBuf, PathBuf)> = Vec::new();
    let truncated = || Error::Invalid("the image export is truncated".into());
    loop {
        // Only the end-of-archive block ends the walk: an export cut short
        // (a partial header, or no end marker) is an error, never an image
        // with fewer files.
        if fill(&mut r, &mut header)? < header.len() {
            return Err(truncated());
        }
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let size = octal(&header[124..136]);
        let padded = size.div_ceil(512) * 512;
        let kind = header[156];
        let mut name = cstr(&header[0..100]);
        if &header[257..262] == b"ustar" {
            let prefix = cstr(&header[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        if let Some(n) = pax_path.take().or(long_name.take()) {
            name = n;
        }
        let link = pax_link.take().unwrap_or_else(|| cstr(&header[157..257]));
        match kind {
            b'x' | b'L' | b'K' => {
                if size > 1 << 20 {
                    return Err(Error::Invalid("an oversized tar extension header".into()));
                }
                let mut data = vec![0u8; padded as usize];
                r.read_exact(&mut data).map_err(|_| truncated())?;
                data.truncate(size as usize);
                match kind {
                    b'x' => {
                        let rec = pax(&data);
                        pax_path = rec.get("path").cloned();
                        pax_link = rec.get("linkpath").cloned();
                    }
                    b'L' => long_name = Some(cstr(&data)),
                    _ => pax_link = Some(cstr(&data)),
                }
                continue;
            }
            b'0' | 0 | b'7' => {
                if let Some(rel) = inside(&name).filter(|p| wanted(&p.to_string_lossy())).filter(|_| size <= MAX_FILE) {
                    let mut data = vec![0u8; size as usize];
                    r.read_exact(&mut data).map_err(|_| truncated())?;
                    r.seek_relative((padded - size) as i64)?;
                    let dest = root.join(&rel);
                    if let Some(dir) = dest.parent() {
                        std::fs::create_dir_all(dir)?;
                    }
                    std::fs::write(dest, data)?;
                    continue;
                }
            }
            b'1' | b'2' => {
                if let Some(rel) = inside(&name).filter(|p| wanted(&p.to_string_lossy())) {
                    // A symlink is relative to its directory, unless absolute (then the image root).
                    let target = if kind == b'2' && !link.starts_with('/') {
                        rel.parent().map(|d| d.join(&link).to_string_lossy().into_owned()).unwrap_or(link.clone())
                    } else {
                        link.clone()
                    };
                    if let Some(t) = normalize(&target) {
                        links.push((rel, t));
                    }
                }
            }
            _ => {}
        }
        r.seek_relative(padded as i64)?;
    }
    for (rel, target) in links {
        let (src, dest) = (root.join(&target), root.join(&rel));
        if src.is_file() && !dest.exists() {
            if let Some(dir) = dest.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::copy(src, dest)?;
        }
    }
    Ok(())
}

/// Read until `buf` is full or the stream ends; how many bytes were read.
fn fill(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// A link target resolved lexically inside the image root.
fn normalize(target: &str) -> Option<PathBuf> {
    let mut out: Vec<String> = Vec::new();
    for part in target.trim_start_matches('/').split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            p => out.push(p.to_string()),
        }
    }
    (!out.is_empty()).then(|| out.iter().collect())
}

/// What an exported image root holds: packages, and what couldn't be read.
pub fn read_root(root: &Path) -> (Vec<ImagePackage>, Vec<String>) {
    let mut pkgs = Vec::new();
    let mut gaps = Vec::new();
    let rel = ["etc/os-release", "usr/lib/os-release"]
        .iter()
        .find_map(|f| std::fs::read_to_string(root.join(f)).ok())
        .map(|t| parse_os_release(&t))
        .unwrap_or_default();
    let dbs = [("var/lib/dpkg/status", "/var/lib/dpkg/status"), ("lib/apk/db/installed", "/lib/apk/db/installed")];
    let present: Vec<&(&str, &str)> = dbs.iter().filter(|(f, _)| root.join(f).is_file()).collect();
    match (present.first(), osdb::ecosystem(&rel)) {
        (Some((file, shown)), Ok(eco)) => {
            let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
            let found = if file.contains("dpkg") { osdb::dpkg(&text) } else { osdb::apk(&text) };
            pkgs.extend(found.into_iter().map(|p| ImagePackage {
                ecosystem: eco.clone(),
                name: p.name,
                version: p.version,
                source: shown.to_string(),
            }));
        }
        (Some(_), Err(why)) => gaps.push(format!("OS packages: {why}")),
        (None, _) if !rel.is_empty() => gaps.push(format!(
            "OS packages: no dpkg or apk database ({} images are read through their own tools, not yet supported)",
            rel.get("ID").map(String::as_str).unwrap_or("this distro")
        )),
        (None, _) => {}
    }
    let files = crate::repos::lockfiles(root);
    for f in files {
        let shown = format!("/{}", f.strip_prefix(root).unwrap_or(&f).display());
        match lockfiles::extract(&f) {
            Ok(Some(found)) => pkgs.extend(found.into_iter().map(|p: Package| ImagePackage {
                ecosystem: p.ecosystem,
                name: p.name,
                version: p.version,
                source: shown.clone(),
            })),
            Ok(None) => gaps.push(format!("{shown}: a lockfile kind not read yet")),
            Err(e) => gaps.push(format!("{shown}: {e}")),
        }
    }
    (pkgs, gaps)
}

fn export(engine: &Path, r: &str, dir: &Path) -> Result<PathBuf> {
    let create = exec(
        &[engine.as_os_str(), OsStr::new("create"), OsStr::new(r), OsStr::new("wpantry-export")],
        &[],
        Duration::from_secs(120),
    )?;
    let id = create.stdout.trim().lines().last().unwrap_or("").trim().to_string();
    if create.code != Some(0) || id.is_empty() {
        return Err(Error::Failed(format!(
            "{} create {r} failed: {}",
            engine.display(),
            create.stderr.trim().lines().last().unwrap_or("")
        )));
    }
    let _container = Container { engine, id: id.clone() };
    let tar = dir.join("rootfs.tar");
    let out = exec(
        &[engine.as_os_str(), OsStr::new("export"), OsStr::new("-o"), tar.as_os_str(), OsStr::new(&id)],
        &[],
        Duration::from_secs(1800),
    )?;
    if out.code != Some(0) {
        return Err(Error::Failed(format!(
            "{} export failed: {}",
            engine.display(),
            out.stderr.trim().lines().last().unwrap_or("")
        )));
    }
    Ok(tar)
}

/// The packages in one local image, cached by image id (an id never changes
/// content; advisories are asked fresh through OSV's own cache).
pub fn packages(
    cache: &Cache,
    engine: &Path,
    r: &str,
    id: &str,
    refresh: bool,
    offline: bool,
) -> Result<(Vec<ImagePackage>, Vec<String>)> {
    let read = || -> Result<Value> {
        let dir = TempDir::new("image")?;
        let tar = export(engine, r, dir.path())?;
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root)?;
        untar(&tar, &root)?;
        let _ = std::fs::remove_file(&tar);
        let (pkgs, gaps) = read_root(&root);
        let rows: Vec<Value> = pkgs
            .iter()
            .map(|p| json!({"ecosystem": p.ecosystem, "name": p.name, "version": p.version, "source": p.source}))
            .collect();
        Ok(json!({"packages": rows, "gaps": gaps}))
    };
    // Not Python's `image:<id>`: that holds osv-scanner's result for the
    // image, in another shape, under the same cache file.
    let key = format!("image-packages:{id}");
    let ours = |v: &Value| v.get("packages").is_some_and(Value::is_array) && v.get("gaps").is_some_and(Value::is_array);
    let mut v = cache.memo(&key, read, 30.0 * DAY, id, refresh, offline)?;
    if !ours(&v) && !offline {
        v = cache.memo(&key, read, 30.0 * DAY, id, true, false)?;
    }
    if !ours(&v) {
        return Err(Error::Offline(format!("{key}: the cached entry is unreadable")));
    }
    let pkgs = json::arr_at(&v, "packages")
        .iter()
        .map(|p| ImagePackage {
            ecosystem: str_at(p, "ecosystem").into(),
            name: str_at(p, "name").into(),
            version: str_at(p, "version").into(),
            source: str_at(p, "source").into(),
        })
        .collect();
    Ok((pkgs, json::strs_at(&v, "gaps")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ustar archive from (name, kind, link, data) entries.
    fn tar(entries: &[(&str, u8, &str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, kind, link, data) in entries {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..107].copy_from_slice(b"0000644");
            let size = format!("{:011o}", data.len());
            h[124..135].copy_from_slice(size.as_bytes());
            h[156] = *kind;
            h[157..157 + link.len()].copy_from_slice(link.as_bytes());
            h[257..263].copy_from_slice(b"ustar\0");
            h[148..156].copy_from_slice(b"        ");
            let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
            h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
            out.extend(h);
            out.extend(*data);
            out.extend(vec![0u8; (512 - data.len() % 512) % 512]);
        }
        out.extend([0u8; 1024]);
        out
    }

    #[test]
    fn reads_an_exported_debian_image() {
        let d = TempDir::new("untar").unwrap();
        let pax_name = "app/node_modules/x/package-lock.json";
        let pax_rec = format!("{} path={pax_name}\n", pax_name.len() + 9);
        let archive = tar(&[
            ("usr/lib/os-release", b'0', "", b"ID=debian\nVERSION_ID=\"12\"\n"),
            ("etc/os-release", b'2', "../usr/lib/os-release", b""),
            ("var/lib/dpkg/status", b'0', "", b"Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n"),
            ("srv/app/Cargo.lock", b'0', "", b"version = 4\n[[package]]\nname = \"itoa\"\nversion = \"1.0.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"),
            ("../escape/Cargo.lock", b'0', "", b"x"),
            ("etc/evil", b'2', "/../../outside", b""),
            ("pax", b'x', "", pax_rec.as_bytes()),
            ("ignored", b'0', "", b"{}"),
            ("usr/bin/tool", b'0', "", &[1, 2, 3]),
        ]);
        let t = d.path().join("rootfs.tar");
        std::fs::write(&t, archive).unwrap();
        let root = d.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        untar(&t, &root).unwrap();
        assert!(!d.path().join("escape").exists(), "paths outside the root are ignored");
        assert!(!root.join("app/node_modules").exists(), "dependency directories are pruned, as in a repo walk");
        assert!(!root.join("usr/bin/tool").exists(), "only the files the extractors read are kept");
        let (pkgs, gaps) = read_root(&root);
        let got: Vec<(String, String, String, String)> =
            pkgs.into_iter().map(|p| (p.ecosystem, p.name, p.version, p.source)).collect();
        assert_eq!(
            got,
            [
                ("Debian:12".into(), "openssl".into(), "3.0.11-1~deb12u2".into(), "/var/lib/dpkg/status".into()),
                ("crates.io".into(), "itoa".into(), "1.0.9".into(), "/srv/app/Cargo.lock".into()),
            ]
        );
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn the_kernel_in_an_image_is_the_hosts() {
        let pkg = |name: &str, source: &str| ImagePackage {
            ecosystem: "Debian:12".into(),
            name: name.into(),
            version: "6.1.176-1".into(),
            source: source.into(),
        };
        assert!(host_kernel(&pkg("linux", "/var/lib/dpkg/status")));
        assert!(!host_kernel(&pkg("libssh2", "/var/lib/dpkg/status")));
        assert!(
            !host_kernel(&pkg("linux", "/srv/app/package-lock.json")),
            "an npm package named linux is not the kernel"
        );
    }

    #[test]
    fn a_cut_short_export_is_an_error_not_an_empty_image() {
        let d = TempDir::new("untar").unwrap();
        let whole =
            tar(&[("var/lib/dpkg/status", b'0', "", b"Package: x\nStatus: install ok installed\nVersion: 1\n")]);
        for cut in [vec![65u8; 23], whole[..512].to_vec(), whole[..whole.len() - 1024].to_vec(), Vec::new()] {
            let t = d.path().join("cut.tar");
            std::fs::write(&t, &cut).unwrap();
            let root = d.path().join(format!("root{}", cut.len()));
            std::fs::create_dir_all(&root).unwrap();
            assert!(matches!(untar(&t, &root), Err(Error::Invalid(_))), "{} bytes", cut.len());
        }
    }

    /// Python keeps osv-scanner's result at `image:<id>` (`packages` is a
    /// count there); Rust neither reads it nor trusts an entry of the wrong
    /// shape under its own key.
    #[test]
    fn python_and_malformed_cache_entries_are_not_read_as_an_empty_image() {
        let d = TempDir::new("imgcache").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        c.put_run("image:sha256:1", "sha256:1", &json!({"packages": 1, "vulnerable": []})).unwrap();
        let no_engine = Path::new("/nonexistent/docker");
        assert!(packages(&c, no_engine, "x", "sha256:1", false, true).is_err(), "offline, nothing of ours cached");
        c.put_run("image-packages:sha256:1", "sha256:1", &json!({"packages": 1})).unwrap();
        assert!(packages(&c, no_engine, "x", "sha256:1", false, true).is_err());
        assert!(packages(&c, no_engine, "x", "sha256:1", false, false).is_err(), "rereads, and can't");
    }

    #[test]
    fn paths_and_headers() {
        assert_eq!(inside("./etc/os-release"), Some(PathBuf::from("etc/os-release")));
        assert_eq!(inside("/a/../../b"), None);
        assert_eq!(normalize("etc/../usr/lib/os-release"), Some(PathBuf::from("usr/lib/os-release")));
        assert_eq!(normalize("../../x"), None);
        assert_eq!(octal(b"00000000017\0"), 15);
        assert_eq!(pax(b"29 path=a/very/long/name.txt\n")["path"], "a/very/long/name.txt");
    }
}
