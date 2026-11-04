//! What the posture tests share: a machine that answers commands from a
//! table, and files written into a temporary directory.

use crate::posture::Runner;
use crate::posture::any::persistence::Roots;
use crate::utils::temp::TempDir;
use std::path::Path;

/// A machine's answers, keyed by the command's words: the first key the
/// command line contains wins.
pub fn machine(answers: &'static [(&'static str, &'static str)]) -> impl Fn(&[&str]) -> String {
    move |argv: &[&str]| {
        let joined = argv.join(" ");
        answers.iter().find(|(k, _)| joined.contains(k)).map(|(_, v)| v.to_string()).unwrap_or_default()
    }
}

/// Write `text` to `p`, making its directories.
pub fn write(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// A copy of /etc with the given files.
pub fn etc(files: &[(&str, &str)]) -> TempDir {
    let d = TempDir::new("etc").unwrap();
    for (rel, body) in files {
        write(&d.path().join(rel), body);
    }
    d
}

/// The persistence inventory's view of `dir`: `home` and `root` inside it.
pub fn roots<'a>(dir: &Path, macos: bool, runner: Runner<'a>) -> Roots<'a> {
    Roots { home: dir.join("home"), root: dir.join("root"), macos, runner }
}
