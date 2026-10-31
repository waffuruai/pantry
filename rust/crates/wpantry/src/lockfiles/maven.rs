//! `pom.xml` → `Maven`: the project's own `<dependencies>`, without
//! resolving anything. A version is taken literally, through `${…}`
//! properties defined in the same file (`<properties>`, `project.version`
//! and friends), or from the same file's `<dependencyManagement>`; an
//! exact range `[1.2.3]` is its version. Ranges, unresolved properties,
//! `system` scope (a local jar), plugin dependencies and profiles are
//! skipped; there is no parent or remote POM resolution, so a version
//! inherited from a parent or a BOM isn't reported.

use super::{Package, plausible};
use crate::error::{Error, Result};
use std::collections::BTreeMap;

const MAX_DEPTH: usize = 256;

/// One leaf element's text, with the path of element names leading to it.
struct Leaf {
    path: Vec<String>,
    /// Which element under the parent it is (to group a dependency's fields).
    owner: usize,
    text: String,
}

fn decode(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';') else { break };
        let entity = &rest[1..end];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The text of every element that holds only text, in document order.
fn leaves(xml: &str) -> Result<Vec<Leaf>> {
    let bad = |m: &str| Error::Invalid(format!("pom.xml: {m}"));
    let mut out = Vec::new();
    let mut stack: Vec<(String, usize)> = Vec::new(); // (name, element number)
    let mut text = String::new();
    let mut count = 0usize;
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        text.push_str(&rest[..lt]);
        rest = &rest[lt..];
        if let Some(r) = rest.strip_prefix("<!--") {
            rest = &r[r.find("-->").ok_or_else(|| bad("a comment never closes"))? + 3..];
        } else if let Some(r) = rest.strip_prefix("<![CDATA[") {
            let end = r.find("]]>").ok_or_else(|| bad("a CDATA section never closes"))?;
            text.push_str(&r[..end]);
            rest = &r[end + 3..];
            continue;
        } else if rest.starts_with("<?") || rest.starts_with("<!") {
            rest = &rest[rest.find('>').ok_or_else(|| bad("a declaration never closes"))? + 1..];
        } else if let Some(r) = rest.strip_prefix("</") {
            let end = r.find('>').ok_or_else(|| bad("a tag never closes"))?;
            let name = r[..end].trim();
            let name = name.rsplit(':').next().unwrap_or(name);
            let (open, n) = stack.pop().ok_or_else(|| bad("a closing tag without an opening one"))?;
            if open != name {
                return Err(bad(&format!("</{name}> closes <{open}>")));
            }
            if n == count {
                // Nothing opened since: a leaf.
                out.push(Leaf {
                    path: stack.iter().map(|(s, _)| s.clone()).chain([open]).collect(),
                    owner: stack.last().map_or(0, |(_, n)| *n),
                    text: decode(text.trim()),
                });
            }
            rest = &r[end + 1..];
        } else {
            let end = rest.find('>').ok_or_else(|| bad("a tag never closes"))?;
            let tag = &rest[1..end];
            let self_closing = tag.ends_with('/');
            let name = tag.trim_end_matches('/').split_whitespace().next().unwrap_or("");
            let name = name.rsplit(':').next().unwrap_or(name).to_string();
            count += 1;
            if !self_closing {
                if stack.len() >= MAX_DEPTH {
                    return Err(bad("nested too deeply"));
                }
                stack.push((name, count));
            }
            rest = &rest[end + 1..];
        }
        text.clear();
    }
    if !stack.is_empty() {
        return Err(bad("an element never closes"));
    }
    Ok(out)
}

/// The longest a property may expand to: a version or a group id, not a document.
const MAX_EXPANSION: usize = 4096;

/// `${name}` references replaced from `props`, recursively; None if one
/// is undefined or the references loop.
fn interpolate(s: &str, props: &BTreeMap<String, String>, depth: usize) -> Option<String> {
    if !s.contains("${") {
        return Some(s.to_string());
    }
    if depth > 8 {
        return None;
    }
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let end = rest[i..].find('}')? + i;
        out.push_str(&interpolate(props.get(&rest[i + 2..end])?, props, depth + 1)?);
        if out.len() > MAX_EXPANSION {
            return None; // properties that multiply (a billion laughs)
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

#[derive(Default)]
struct Dep {
    group: String,
    artifact: String,
    version: String,
    scope: String,
}

/// The `<dependency>` fields under `prefix` (a path of element names), in order.
fn deps(leaves: &[Leaf], prefix: &[&str]) -> Vec<Dep> {
    let mut by_owner: BTreeMap<usize, Dep> = BTreeMap::new();
    for l in leaves {
        if l.path.len() != prefix.len() + 2 || !l.path.iter().zip(prefix).all(|(a, b)| a == b) {
            continue;
        }
        if l.path[prefix.len()] != "dependency" {
            continue;
        }
        let d = by_owner.entry(l.owner).or_default();
        match l.path[prefix.len() + 1].as_str() {
            "groupId" => d.group = l.text.clone(),
            "artifactId" => d.artifact = l.text.clone(),
            "version" => d.version = l.text.clone(),
            "scope" => d.scope = l.text.clone(),
            _ => {}
        }
    }
    by_owner.into_values().collect()
}

/// A literal version: as written, or the one version of an exact range.
fn literal(v: &str) -> Option<&str> {
    let v = v.trim();
    let v = match v.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        Some(exact) if !exact.contains(',') => exact.trim(),
        Some(_) => return None,
        None => v,
    };
    (plausible(v) && !v.contains(['(', ')', '[', ']', ','])).then_some(v)
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let leaves = leaves(text)?;
    let mut props: BTreeMap<String, String> = BTreeMap::new();
    for l in &leaves {
        let p: Vec<&str> = l.path.iter().map(String::as_str).collect();
        match p.as_slice() {
            ["project", "properties", name] => {
                props.insert(name.to_string(), l.text.clone());
            }
            ["project", field @ ("groupId" | "artifactId" | "version")] => {
                props.insert(format!("project.{field}"), l.text.clone());
                props.insert(format!("pom.{field}"), l.text.clone());
                if *field == "version" {
                    props.insert("version".into(), l.text.clone());
                }
            }
            ["project", "parent", field @ ("groupId" | "artifactId" | "version")] => {
                props.insert(format!("project.parent.{field}"), l.text.clone());
                // A project without its own groupId or version inherits the parent's.
                props.entry(format!("project.{field}")).or_insert_with(|| l.text.clone());
            }
            _ => {}
        }
    }
    let resolve = |s: &str| interpolate(s, &props, 0);
    let mut managed: BTreeMap<(String, String), String> = BTreeMap::new();
    for d in deps(&leaves, &["project", "dependencyManagement", "dependencies"]) {
        if let (Some(g), Some(a), Some(v)) = (resolve(&d.group), resolve(&d.artifact), resolve(&d.version)) {
            managed.insert((g, a), v);
        }
    }
    let mut out = Vec::new();
    for d in deps(&leaves, &["project", "dependencies"]) {
        if d.scope.trim() == "system" {
            continue;
        }
        let (Some(group), Some(artifact)) = (resolve(&d.group), resolve(&d.artifact)) else { continue };
        let version = if d.version.is_empty() {
            managed.get(&(group.clone(), artifact.clone())).cloned()
        } else {
            resolve(&d.version)
        };
        let Some(version) = version else { continue };
        if let Some(v) = literal(&version)
            && !group.is_empty()
            && !artifact.is_empty()
        {
            out.push(Package::new("Maven", &format!("{group}:{artifact}"), v));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplying_properties_are_refused() {
        let mut props = BTreeMap::new();
        props.insert("p0".to_string(), "lol".to_string());
        for i in 1..=8 {
            props.insert(format!("p{i}"), format!("${{p{}}}", i - 1).repeat(100));
        }
        assert_eq!(interpolate("${p0}-${p0}", &props, 0).as_deref(), Some("lol-lol"));
        assert_eq!(interpolate("${p8}", &props, 0), None);
    }

    #[test]
    fn literal_property_and_managed_versions() {
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- <dependency> in a comment -->
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>3.0.0</version></parent>
  <artifactId>app</artifactId>
  <properties>
    <a.version>1.2.3</a.version>
    <b.version>${a.version}</b.version>
    <range>[1.0,2.0)</range>
    <loop>${loop}</loop>
  </properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.m</groupId><artifactId>managed</artifactId><version>4.5.6</version></dependency>
    <dependency><groupId>org.u</groupId><artifactId>unused</artifactId><version>9.9.9</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.a</groupId><artifactId>a</artifactId><version>${b.version}</version></dependency>
    <dependency><groupId>org.m</groupId><artifactId>managed</artifactId></dependency>
    <dependency><groupId>${project.groupId}</groupId><artifactId>sibling</artifactId><version>${project.version}</version></dependency>
    <dependency><groupId>org.r</groupId><artifactId>ranged</artifactId><version>${range}</version></dependency>
    <dependency><groupId>org.e</groupId><artifactId>exact</artifactId><version>[2.0.1]</version></dependency>
    <dependency><groupId>org.l</groupId><artifactId>looped</artifactId><version>${loop}</version></dependency>
    <dependency><groupId>org.x</groupId><artifactId>undefined</artifactId><version>${nope}</version></dependency>
    <dependency><groupId>org.s</groupId><artifactId>sys</artifactId><version>1.0</version><scope>system</scope></dependency>
    <dependency><groupId>org.amp</groupId><artifactId>a&amp;b</artifactId><version><![CDATA[5.0]]></version></dependency>
  </dependencies>
  <build><plugins><plugin><artifactId>p</artifactId><version>1.0</version>
    <dependencies><dependency><groupId>org.p</groupId><artifactId>plugin-dep</artifactId><version>1.0</version></dependency></dependencies>
  </plugin></plugins></build>
  <profiles><profile><dependencies>
    <dependency><groupId>org.q</groupId><artifactId>profile-dep</artifactId><version>1.0</version></dependency>
  </dependencies></profile></profiles>
</project>
"#;
        let got: Vec<String> = parse(pom).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
        assert_eq!(
            got,
            [
                "org.a:a 1.2.3",
                "org.m:managed 4.5.6",
                "org.example:sibling 3.0.0",
                "org.e:exact 2.0.1",
                "org.amp:a&b 5.0"
            ]
        );
        assert!(parse("<project><dependencies></project>").is_err());
        assert!(parse("<project>").is_err());
    }
}
