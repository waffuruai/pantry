//! .NET projects without a lock → `NuGet`: `*.csproj`, `*.fsproj` and
//! `*.vbproj` `PackageReference` items, and `packages.config`. Lock files
//! are opt-in in .NET, so most projects have none; a sibling
//! `packages.lock.json` wins and the project is skipped (the lock is read
//! on its own).
//!
//! Nothing is evaluated or restored. A project's versions come from the
//! item itself (`Version`/`VersionOverride`, attribute or child element)
//! or, with central package management, from a `PackageVersion` in the
//! nearest `Directory.Packages.props`. The nearest `Directory.Build.props`
//! adds its properties and `PackageReference` items, and the nearest
//! `Directory.Packages.props` its `GlobalPackageReference` items, as
//! MSBuild imports them; both are looked for from the project's directory
//! up to the repository root and no further, and their own imports are
//! not followed.
//!
//! Only exact versions are reported: a bare version (NuGet restores the
//! lowest it allows, which is that one) or `[1.2.3]`. A range, a floating
//! `*`, a property function or a `$(Name)` defined in none of those three
//! files (or only under a `Condition`) is returned as not checked, never
//! dropped: reading it as clean would hide the package.
//!
//! Example: `<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />`
//! reads as `NuGet Newtonsoft.Json 12.0.1`; `Version="$(JsonVersion)"`
//! with `<JsonVersion>12.0.1</JsonVersion>` in a `Directory.Build.props`
//! above reads the same; `Version="[12.0,13.0)"` is not checked.

use super::{MAX_FILE, Package, Scope, plausible};
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

const MAX_DEPTH: usize = 256;
/// The longest a property may expand to: a version, not a document.
const MAX_EXPANSION: usize = 4096;
const BUILD_PROPS: &str = "Directory.Build.props";
const PACKAGES_PROPS: &str = "Directory.Packages.props";

/// What a project file pins, and the references it names without an
/// exact version (`Name (why)`), which the scan reports as not checked.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Read {
    pub packages: Vec<Package>,
    pub unchecked: Vec<String>,
}

/// A project file or `packages.config`, the files this module reads.
pub fn is_project_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    name == "packages.config"
        || [".csproj", ".fsproj", ".vbproj"].iter().any(|s| lower.ends_with(s) && lower.len() > s.len())
}

/// The files a project's versions can come from besides itself.
pub fn is_context_file(name: &str) -> bool {
    name == BUILD_PROPS || name == PACKAGES_PROPS
}

// XML -------------------------------------------------------------------------

/// One element: its local name (a namespace prefix dropped), attributes,
/// direct text and child elements.
#[derive(Debug, Default)]
struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    text: String,
    children: Vec<Element>,
}

impl Element {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// An attribute, else the text of a child element of that name.
    fn field(&self, name: &str) -> Option<String> {
        self.attr(name).map(str::to_string).or_else(|| {
            self.children.iter().rev().find(|c| c.name.eq_ignore_ascii_case(name)).map(|c| c.text.trim().to_string())
        })
    }

    fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// `name="value"` pairs of a start tag (after its name), decoded.
fn attributes(mut s: &str, bad: &dyn Fn(&str) -> Error) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    loop {
        s = s.trim_start();
        if s.is_empty() {
            return Ok(out);
        }
        let eq = s.find('=').ok_or_else(|| bad("an attribute without a value"))?;
        let name = s[..eq].trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(bad("an attribute without a value"));
        }
        let rest = s[eq + 1..].trim_start();
        let q = rest.chars().next().filter(|c| *c == '"' || *c == '\'').ok_or_else(|| bad("an unquoted attribute"))?;
        let end = rest[1..].find(q).ok_or_else(|| bad("an attribute never closes"))? + 1;
        out.push((local(name).to_string(), super::maven::decode(&rest[1..end])));
        s = &rest[end + 1..];
    }
}

/// Where a start tag ends: the first `>` outside a quoted attribute value.
fn tag_end(s: &str) -> Option<usize> {
    let mut quote = None;
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '>') => return Some(i),
            _ => {}
        }
    }
    None
}

/// The document's root element.
fn document(xml: &str, what: &str) -> Result<Element> {
    let bad = |m: &str| Error::Invalid(format!("{what}: {m}"));
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        let top = stack.last_mut().expect("the document stays on the stack");
        top.text.push_str(&super::maven::decode(&rest[..lt]));
        rest = &rest[lt..];
        if let Some(r) = rest.strip_prefix("<!--") {
            rest = &r[r.find("-->").ok_or_else(|| bad("a comment never closes"))? + 3..];
        } else if let Some(r) = rest.strip_prefix("<![CDATA[") {
            let end = r.find("]]>").ok_or_else(|| bad("a CDATA section never closes"))?;
            top.text.push_str(&r[..end]);
            rest = &r[end + 3..];
        } else if rest.starts_with("<?") || rest.starts_with("<!") {
            rest = &rest[rest.find('>').ok_or_else(|| bad("a declaration never closes"))? + 1..];
        } else if let Some(r) = rest.strip_prefix("</") {
            let end = r.find('>').ok_or_else(|| bad("a tag never closes"))?;
            let name = local(r[..end].trim());
            if stack.len() < 2 {
                return Err(bad("a closing tag without an opening one"));
            }
            let done = stack.pop().expect("checked above");
            if done.name != name {
                return Err(bad(&format!("</{name}> closes <{}>", done.name)));
            }
            stack.last_mut().expect("checked above").children.push(done);
            rest = &r[end + 1..];
        } else {
            let end = tag_end(rest).ok_or_else(|| bad("a tag never closes"))?;
            let tag = &rest[1..end];
            let self_closing = tag.ends_with('/');
            let tag = tag.trim_end_matches('/');
            let split = tag.find(char::is_whitespace).unwrap_or(tag.len());
            let el = Element {
                name: local(&tag[..split]).to_string(),
                attrs: attributes(&tag[split..], &bad)?,
                ..Default::default()
            };
            if el.name.is_empty() {
                return Err(bad("a tag without a name"));
            }
            if self_closing {
                top.children.push(el);
            } else {
                if stack.len() > MAX_DEPTH {
                    return Err(bad("nested too deeply"));
                }
                stack.push(el);
            }
            rest = &rest[end + 1..];
        }
    }
    let doc = stack.pop().expect("the document stays on the stack");
    if !stack.is_empty() {
        return Err(bad("an element never closes"));
    }
    let mut roots = doc.children.into_iter();
    match (roots.next(), roots.next()) {
        (Some(root), None) => Ok(root),
        _ => Err(bad("not one root element")),
    }
}

// MSBuild ---------------------------------------------------------------------

/// A value as one file sets it, and whether a `Condition` guards it.
#[derive(Clone, Debug)]
struct Def {
    value: String,
    conditional: bool,
}

/// An item operation, in document order.
#[derive(Clone, Debug)]
enum Op {
    Include(Item),
    Update(Item),
    Remove(String),
}

#[derive(Clone, Debug, Default)]
struct Item {
    name: String,
    version: Option<String>,
    version_override: Option<String>,
}

/// What one MSBuild file defines.
#[derive(Debug, Default)]
struct Defs {
    /// Property name (lowercased) → its definitions, in order.
    props: Vec<(String, Def)>,
    /// `PackageReference` operations.
    refs: Vec<Op>,
    /// `PackageVersion` Include (lowercased) → version.
    versions: Vec<(String, Def)>,
    /// `GlobalPackageReference` items.
    globals: Vec<Item>,
}

fn item(e: &Element, name: &str) -> Item {
    Item { name: name.trim().to_string(), version: e.field("Version"), version_override: e.field("VersionOverride") }
}

/// The names an `Include`/`Update`/`Remove` lists (`A;B`).
fn names(s: &str) -> impl Iterator<Item = &str> {
    s.split(';').map(str::trim).filter(|n| !n.is_empty())
}

fn collect(e: &Element, conditional: bool, out: &mut Defs) {
    let conditional = conditional || e.attr("Condition").is_some() || e.is("When") || e.is("Otherwise");
    if e.is("Target") {
        return; // runs at build time, not when the project is evaluated
    }
    if e.is("PropertyGroup") {
        for p in &e.children {
            let conditional = conditional || p.attr("Condition").is_some();
            out.props.push((p.name.to_ascii_lowercase(), Def { value: p.text.trim().to_string(), conditional }));
        }
        return;
    }
    if e.is("ItemGroup") {
        for i in &e.children {
            let conditional = conditional || i.attr("Condition").is_some();
            if i.is("PackageReference") {
                if let Some(inc) = i.attr("Include") {
                    out.refs.extend(names(inc).map(|n| Op::Include(item(i, n))));
                } else if let Some(upd) = i.attr("Update") {
                    out.refs.extend(names(upd).map(|n| Op::Update(item(i, n))));
                } else if let Some(rem) = i.attr("Remove") {
                    out.refs.extend(names(rem).map(|n| Op::Remove(n.to_string())));
                }
            } else if i.is("PackageVersion") {
                let (Some(inc), Some(v)) = (i.attr("Include").or(i.attr("Update")), i.field("Version")) else {
                    continue;
                };
                for n in names(inc) {
                    out.versions.push((n.to_ascii_lowercase(), Def { value: v.clone(), conditional }));
                }
            } else if i.is("GlobalPackageReference")
                && let Some(inc) = i.attr("Include")
            {
                out.globals.extend(names(inc).map(|n| item(i, n)));
            }
        }
        return;
    }
    for c in &e.children {
        collect(c, conditional, out);
    }
}

/// Why a value isn't one exact version.
#[derive(Debug, PartialEq, Eq)]
enum Why {
    Undefined(String),
    Conditional(String),
    CentralConditional,
    Function,
    Loop,
    Range,
    Floating,
    NoVersion,
    NotAVersion,
}

impl Why {
    fn note(&self, name: &str, raw: &str) -> String {
        let why = match self {
            Why::Undefined(p) => format!("$({p}) is not defined in the project, {BUILD_PROPS} or {PACKAGES_PROPS}"),
            Why::Conditional(p) => format!("$({p}) is set under a Condition"),
            Why::CentralConditional => "its PackageVersion is set under a Condition".into(),
            Why::Function => "a property function or item reference".into(),
            Why::Loop => "properties that loop or grow too long".into(),
            Why::Range => "a version range".into(),
            Why::Floating => "a floating version".into(),
            Why::NoVersion => "no version".into(),
            Why::NotAVersion => "not a version".into(),
        };
        if raw.is_empty() { format!("{name} ({why})") } else { format!("{name} {raw} ({why})") }
    }
}

/// The one value `defs` (in evaluation order) leave for `key`: the last
/// unconditional one, unless a conditional one after it could change it.
fn settled<'a>(defs: &'a [(String, Def)], key: &str) -> std::result::Result<&'a str, bool> {
    let all: Vec<&Def> = defs.iter().filter(|(k, _)| k == key).map(|(_, d)| d).collect();
    let from = all.iter().rposition(|d| !d.conditional);
    let tail = &all[from.unwrap_or(0)..];
    match tail.first() {
        None => Err(false),
        Some(first) if from.is_some() && tail.iter().all(|d| d.value == first.value) => Ok(&first.value),
        Some(_) => Err(true),
    }
}

/// `$(Name)` references expanded from `props`, recursively.
fn expand(s: &str, props: &[(String, Def)], depth: usize) -> std::result::Result<String, Why> {
    if s.contains("@(") || s.contains("%(") || s.contains("$([") {
        return Err(Why::Function);
    }
    if !s.contains("$(") {
        return Ok(s.to_string());
    }
    if depth > 8 {
        return Err(Why::Loop);
    }
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("$(") {
        out.push_str(&rest[..i]);
        let end = rest[i..].find(')').ok_or(Why::Function)? + i;
        let name = &rest[i + 2..end];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(Why::Function);
        }
        let value = match settled(props, &name.to_ascii_lowercase()) {
            Ok(v) => v,
            Err(false) => return Err(Why::Undefined(name.to_string())),
            Err(true) => return Err(Why::Conditional(name.to_string())),
        };
        out.push_str(&expand(value, props, depth + 1)?);
        if out.len() > MAX_EXPANSION {
            return Err(Why::Loop);
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The exact version a NuGet version string pins.
fn exact(v: &str) -> std::result::Result<&str, Why> {
    let v = v.trim();
    let v = match v.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        Some(one) if !one.contains(',') => one.trim(),
        Some(_) => return Err(Why::Range),
        None => v,
    };
    if v.contains('*') {
        return Err(Why::Floating);
    }
    if v.contains(['[', ']', '(', ')', ',']) {
        return Err(Why::Range);
    }
    if !plausible(v) || v.contains(char::is_whitespace) {
        return Err(Why::NotAVersion);
    }
    Ok(v)
}

/// The nearest `name` from `dir` up to `root`, inside `root`.
fn nearest(dir: &Path, root: &Path, name: &str) -> Option<PathBuf> {
    dir.ancestors().take_while(|d| d.starts_with(root)).map(|d| d.join(name)).find(|f| f.is_file())
}

fn read(path: &Path, what: &str) -> Result<Element> {
    document(&crate::utils::files::read_capped(path, MAX_FILE)?, what)
}

/// What a `Directory.*.props` above the project defines; a note instead
/// when it can't be read (its properties then count as undefined).
fn context(dir: &Path, root: &Path, name: &str, notes: &mut Vec<String>) -> Defs {
    let mut defs = Defs::default();
    let Some(f) = nearest(dir, root, name) else { return defs };
    match f.canonicalize().map_err(Error::from).and_then(|real| {
        if real.starts_with(root) {
            read(&real, name)
        } else {
            Err(Error::Invalid(format!("{name} links outside the repository; not read")))
        }
    }) {
        Ok(e) => collect(&e, false, &mut defs),
        Err(e) => notes.push(e.to_string()),
    }
    defs
}

fn package(name: &str, raw: &str, props: &[(String, Def)], out: &mut Read) {
    let resolved = expand(name, props, 0).and_then(|n| expand(raw, props, 0).map(|v| (n, v)));
    match resolved.and_then(|(n, v)| exact(&v).map(|e| (n.clone(), e.to_string()))) {
        Ok((n, v)) => out.packages.push(Package::new("NuGet", &n, &v).direct(true)),
        Err(why) => out.unchecked.push(why.note(name, raw)),
    }
}

fn project(text: &str, dir: &Path, root: &Path, what: &str) -> Result<Read> {
    let doc = document(text, what)?;
    if !doc.is("Project") {
        return Err(Error::Invalid(format!("{what} isn't an MSBuild project")));
    }
    let mut out = Read::default();
    let build = context(dir, root, BUILD_PROPS, &mut out.unchecked);
    let central = context(dir, root, PACKAGES_PROPS, &mut out.unchecked);
    let mut own = Defs::default();
    collect(&doc, false, &mut own);
    // MSBuild's order: Directory.Build.props, Directory.Packages.props, then
    // the project. Properties are all set before any item reads them.
    let props: Vec<(String, Def)> = [&build, &central, &own].iter().flat_map(|d| d.props.iter().cloned()).collect();
    let versions: Vec<(String, Def)> =
        [&build, &central, &own].iter().flat_map(|d| d.versions.iter().cloned()).collect();
    let mut items: Vec<Item> = Vec::new();
    for op in build.refs.iter().chain(&own.refs) {
        match op {
            Op::Include(i) => items.push(i.clone()),
            Op::Update(u) => {
                for i in items.iter_mut().filter(|i| i.name.eq_ignore_ascii_case(&u.name)) {
                    i.version = u.version.clone().or(i.version.take());
                    i.version_override = u.version_override.clone().or(i.version_override.take());
                }
            }
            Op::Remove(n) => items.retain(|i| !i.name.eq_ignore_ascii_case(n)),
        }
    }
    for i in &items {
        let raw = match i.version_override.as_ref().or(i.version.as_ref()) {
            Some(v) => Ok(v.as_str()),
            None => settled(&versions, &i.name.to_ascii_lowercase()),
        };
        match raw {
            Ok(v) => package(&i.name, v, &props, &mut out),
            Err(false) => out.unchecked.push(Why::NoVersion.note(&i.name, "")),
            Err(true) => out.unchecked.push(Why::CentralConditional.note(&i.name, "")),
        }
    }
    for g in &central.globals {
        match &g.version {
            Some(v) => package(&g.name, v, &props, &mut out),
            None => out.unchecked.push(Why::NoVersion.note(&g.name, "")),
        }
    }
    Ok(out)
}

/// `packages.config`: every `<package id version>`, all exact; a
/// `developmentDependency` is dev scope. It lists transitive packages too,
/// so directness is unknown.
fn packages_config(text: &str) -> Result<Read> {
    let doc = document(text, "packages.config")?;
    if !doc.is("packages") {
        return Err(Error::Invalid("packages.config has no <packages> root".into()));
    }
    let mut out = Read::default();
    for p in doc.children.iter().filter(|c| c.is("package")) {
        let (id, v) = (p.attr("id").unwrap_or("").trim(), p.attr("version").unwrap_or("").trim());
        match exact(v) {
            Ok(v) if !id.is_empty() => {
                let dev = p.attr("developmentDependency").is_some_and(|d| d.eq_ignore_ascii_case("true"));
                let pkg = Package::new("NuGet", id, v);
                out.packages.push(if dev { pkg.scoped(Scope::Dev) } else { pkg });
            }
            Ok(_) => {}
            Err(why) => out.unchecked.push(why.note(id, v)),
        }
    }
    Ok(out)
}

/// A project file (or `packages.config`) at `path` in the repository at
/// `root`. An empty read when a `packages.lock.json` sits beside it.
pub fn parse_file(path: &Path, root: &Path) -> Result<Read> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let text = crate::utils::files::read_capped(path, MAX_FILE)?;
    let (real, base) = (path.canonicalize()?, root.canonicalize()?);
    let dir = real.parent().unwrap_or(&base);
    let found = if name == "packages.config" { packages_config(&text)? } else { project(&text, dir, &base, name)? };
    if dir.join("packages.lock.json").is_file() {
        return Ok(Read::default());
    }
    Ok(found)
}

#[cfg(test)]
#[path = "csproj_tests.rs"]
mod tests;
