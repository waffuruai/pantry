//! `gradle.lockfile` → `Maven`: one `group:artifact:version=configurations`
//! line per module; comments and the `empty=` line are skipped. The
//! package is `group:artifact`, as OSV names Maven packages.

use super::{Package, lines, plausible};
use crate::error::Result;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut out = Vec::new();
    for line in lines(text)? {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        let Some((coords, _configurations)) = line.split_once('=') else { continue };
        let mut parts = coords.splitn(3, ':');
        let (Some(group), Some(artifact), Some(version)) = (parts.next(), parts.next(), parts.next()) else { continue };
        if !group.is_empty() && !artifact.is_empty() && plausible(version) {
            out.push(Package::new("Maven", &format!("{group}:{artifact}"), version));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_of_coordinates() {
        let text = "# This is a Gradle generated file for dependency locking.\ncom.google.guava:guava:32.1.2-jre=compileClasspath,runtimeClasspath\njunit:junit:4.13.2=testCompileClasspath\nbad-line\nempty=annotationProcessor\n";
        assert_eq!(
            parse(text).unwrap(),
            [
                Package::new("Maven", "com.google.guava:guava", "32.1.2-jre"),
                Package::new("Maven", "junit:junit", "4.13.2")
            ]
        );
    }
}
