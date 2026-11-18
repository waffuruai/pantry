use super::*;
use crate::utils::temp::TempDir;

fn write(root: &Path, rel: &str, text: &str) -> PathBuf {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, text).unwrap();
    p
}

/// `name version` of each package, and the not-checked notes.
fn got(read: &Read) -> (Vec<String>, Vec<String>) {
    (read.packages.iter().map(|p| format!("{} {}", p.name, p.version)).collect(), read.unchecked.clone())
}

fn one(d: &TempDir, rel: &str, text: &str) -> (Vec<String>, Vec<String>) {
    let f = write(d.path(), rel, text);
    got(&parse_file(&f, d.path()).unwrap())
}

fn project(items: &str) -> String {
    format!("<Project Sdk=\"Microsoft.NET.Sdk\">\n{items}\n</Project>\n")
}

#[test]
fn the_files_it_reads() {
    for name in ["App.csproj", "Lib.fsproj", "Old.vbproj", "LOUD.CSPROJ", "packages.config"] {
        assert!(is_project_file(name), "{name}");
    }
    for name in [".csproj", "App.csproj.user", "App.sln", "Packages.config", "Directory.Build.props"] {
        assert!(!is_project_file(name), "{name}");
    }
    assert!(is_context_file("Directory.Build.props") && is_context_file("Directory.Packages.props"));
    assert!(!is_context_file("Directory.Build.targets"));
}

/// The three .NET layouts without a lock: a version on the reference, a
/// version from central package management, and packages.config.
#[test]
fn reference_central_and_packages_config_versions() {
    let d = TempDir::new("csproj-shapes").unwrap();
    let csproj = r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
  </ItemGroup>
</Project>
"#;
    let pkg = one(&d, "app/App.csproj", csproj);
    assert_eq!(pkg, (vec!["Newtonsoft.Json 12.0.1".to_string()], vec![]));
    let read = parse_file(&d.path().join("app/App.csproj"), d.path()).unwrap();
    assert_eq!((read.packages[0].ecosystem.as_str(), read.packages[0].direct), ("NuGet", Some(true)));

    write(
        d.path(),
        "cpm/Directory.Packages.props",
        r#"<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="System.Text.Json" Version="8.0.0" />
  </ItemGroup>
</Project>
"#,
    );
    let cpm = one(
        &d,
        "cpm/Svc.csproj",
        &project(r#"<ItemGroup><PackageReference Include="System.Text.Json" /></ItemGroup>"#),
    );
    assert_eq!(cpm, (vec!["System.Text.Json 8.0.0".to_string()], vec![]));

    let config = r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="log4net" version="2.0.8" targetFramework="net48" />
  <package id="StyleCop.Analyzers" version="1.1.118" developmentDependency="true" />
</packages>
"#;
    let f = write(d.path(), "legacy/packages.config", config);
    let read = parse_file(&f, d.path()).unwrap();
    assert_eq!(got(&read), (vec!["log4net 2.0.8".to_string(), "StyleCop.Analyzers 1.1.118".to_string()], vec![]));
    assert_eq!((read.packages[0].scope, read.packages[0].direct), (Scope::Unknown, None));
    assert_eq!(read.packages[1].scope, Scope::Dev);
}

/// Known-bad oracle: a version through a property nobody defines is not
/// checked, never a clean project with no packages.
#[test]
fn an_undefined_property_is_not_checked_not_clean() {
    let d = TempDir::new("csproj-undefined").unwrap();
    let (pkgs, notes) = one(
        &d,
        "App.csproj",
        &project(r#"<ItemGroup><PackageReference Include="Foo" Version="$(Undefined)" /></ItemGroup>"#),
    );
    assert!(pkgs.is_empty());
    assert_eq!(
        notes,
        [
            "Foo $(Undefined) ($(Undefined) is not defined in the project, Directory.Build.props or Directory.Packages.props)"
        ]
    );
}

/// Properties resolve from the project, the nearest Directory.Build.props
/// and the nearest Directory.Packages.props inside the repository; the
/// project's own definition wins; one above the repository isn't read.
#[test]
fn properties_from_the_project_and_the_props_above_it() {
    let d = TempDir::new("csproj-props").unwrap();
    let repo = d.path().join("repo");
    write(
        d.path(),
        "Directory.Build.props",
        "<Project><PropertyGroup><Outside>6.6.6</Outside></PropertyGroup></Project>",
    );
    write(&repo, "Directory.Build.props", "<Project><PropertyGroup><Far>9.9.9</Far></PropertyGroup></Project>");
    write(
        &repo,
        "src/Directory.Build.props",
        r#"<Project>
  <PropertyGroup>
    <SerilogVersion>3.1.1</SerilogVersion>
    <Shared>1.0.0</Shared>
    <Major>2</Major>
    <Full>$(Major).5.0</Full>
  </PropertyGroup>
  <ItemGroup><PackageReference Include="Analyzer" Version="4.0.0" PrivateAssets="all" /></ItemGroup>
</Project>"#,
    );
    write(
        &repo,
        "src/Directory.Packages.props",
        "<Project><PropertyGroup><Central>7.0.0</Central></PropertyGroup></Project>",
    );
    let f = write(
        &repo,
        "src/app/App.csproj",
        &project(
            r#"<PropertyGroup><Shared>1.2.0</Shared></PropertyGroup>
<ItemGroup>
  <PackageReference Include="Serilog" Version="$(SerilogVersion)" />
  <PackageReference Include="Shared" Version="$(Shared)" />
  <PackageReference Include="Built" Version="$(Full)" />
  <PackageReference Include="Central" Version="$(Central)" />
  <PackageReference Include="Far" Version="$(Far)" />
  <PackageReference Include="Outside" Version="$(Outside)" />
</ItemGroup>"#,
        ),
    );
    let (pkgs, notes) = got(&parse_file(&f, &repo).unwrap());
    assert_eq!(pkgs, ["Analyzer 4.0.0", "Serilog 3.1.1", "Shared 1.2.0", "Built 2.5.0", "Central 7.0.0"]);
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(notes[0].starts_with("Far $(Far) ($(Far) is not defined"), "only the nearest props: {notes:?}");
    assert!(notes[1].starts_with("Outside $(Outside) ($(Outside) is not defined"), "not above the repo: {notes:?}");
}

/// Only exact versions count: a bare version, `[x]`, a child element, a
/// VersionOverride over central; ranges, floating versions, functions and
/// missing versions are notes.
#[test]
fn only_exact_versions_are_read() {
    let d = TempDir::new("csproj-exact").unwrap();
    write(
        d.path(),
        "Directory.Packages.props",
        r#"<Project><ItemGroup>
  <PackageVersion Include="Over" Version="1.0.0" />
  <PackageVersion Include="Twice" Version="1.0.0" />
  <PackageVersion Include="Twice" Version="1.1.0" />
  <PackageVersion Include="Maybe" Version="1.0.0" />
  <PackageVersion Include="Maybe" Version="2.0.0" Condition="'$(X)' == 'y'" />
  <GlobalPackageReference Include="Global.Analyzer" Version="3.0.0" />
  <GlobalPackageReference Include="Global.Bare" />
</ItemGroup></Project>"#,
    );
    let (pkgs, notes) = one(
        &d,
        "App.csproj",
        &project(
            r#"<ItemGroup>
  <PackageReference Include="Bare" Version=" 1.2.3 " />
  <PackageReference Include="Bracket" Version="[2.0.1]" />
  <PackageReference Include="Child"><Version>3.0.0-beta.1</Version></PackageReference>
  <PackageReference Include="Over" VersionOverride="1.5.0" />
  <PackageReference Include="Twice" />
  <PackageReference Include="Maybe" />
  <PackageReference Include="Ranged" Version="[1.0,2.0)" />
  <PackageReference Include="Open" Version="(1.0,)" />
  <PackageReference Include="Float" Version="1.*" />
  <PackageReference Include="Func" Version="$([MSBuild]::Add(1, 2))" />
  <PackageReference Include="Item" Version="@(Versions)" />
  <PackageReference Include="Unclosed" Version="$(Nope" />
  <PackageReference Include="Odd" Version="$(a.b)" />
  <PackageReference Include="Word" Version="latest" />
  <PackageReference Include="None" />
</ItemGroup>"#,
        ),
    );
    assert_eq!(
        pkgs,
        ["Bare 1.2.3", "Bracket 2.0.1", "Child 3.0.0-beta.1", "Over 1.5.0", "Twice 1.1.0", "Global.Analyzer 3.0.0"]
    );
    assert_eq!(
        notes,
        [
            "Maybe (its PackageVersion is set under a Condition)",
            "Ranged [1.0,2.0) (a version range)",
            "Open (1.0,) (a version range)",
            "Float 1.* (a floating version)",
            "Func $([MSBuild]::Add(1, 2)) (a property function or item reference)",
            "Item @(Versions) (a property function or item reference)",
            "Unclosed $(Nope (a property function or item reference)",
            "Odd $(a.b) (a property function or item reference)",
            "Word latest (not a version)",
            "None (no version)",
            "Global.Bare (no version)",
        ]
    );
}

/// What MSBuild evaluates: Update and Remove items, `A;B` lists,
/// conditions on properties, nothing inside a Target.
#[test]
fn item_operations_and_conditions() {
    let d = TempDir::new("csproj-ops").unwrap();
    write(
        d.path(),
        "Directory.Build.props",
        r#"<Project><ItemGroup>
  <PackageReference Include="FromProps" Version="1.0.0" />
  <PackageReference Include="Dropped" Version="1.0.0" />
</ItemGroup></Project>"#,
    );
    let (pkgs, notes) = one(
        &d,
        "App.csproj",
        &project(
            r#"<PropertyGroup>
  <Same>5.0.0</Same>
  <Same Condition="'$(Configuration)' == 'Release'">5.0.0</Same>
  <Varies>1.0.0</Varies>
  <Varies Condition="'$(Configuration)' == 'Release'">2.0.0</Varies>
  <Settled Condition="'$(Configuration)' == 'Release'">2.0.0</Settled>
  <Settled>3.0.0</Settled>
  <Loop>$(Loop)</Loop>
</PropertyGroup>
<PropertyGroup Condition="'$(OS)' == 'Windows_NT'"><OnlyWindows>4.0.0</OnlyWindows></PropertyGroup>
<Choose><When Condition="true"><PropertyGroup><Chosen>1.0.0</Chosen></PropertyGroup></When></Choose>
<ItemGroup>
  <PackageReference Include="A;B" Version="1.0.0" />
  <PackageReference Update="FromProps" Version="1.1.0" />
  <PackageReference Remove="Dropped" />
  <PackageReference Include="Same" Version="$(Same)" />
  <PackageReference Include="Varies" Version="$(Varies)" />
  <PackageReference Include="Settled" Version="$(Settled)" />
  <PackageReference Include="Windows" Version="$(OnlyWindows)" />
  <PackageReference Include="Chosen" Version="$(Chosen)" />
  <PackageReference Include="Looped" Version="$(Loop)" />
  <PackageReference Include="$(PkgName)" Version="1.0.0" />
</ItemGroup>
<ItemGroup Condition="'$(TargetFramework)' == 'net48'">
  <PackageReference Include="Conditional.Ref" Version="2.2.2" />
</ItemGroup>
<Target Name="Build"><ItemGroup><PackageReference Include="InTarget" Version="1.0.0" /></ItemGroup></Target>"#,
        ),
    );
    assert_eq!(pkgs, ["FromProps 1.1.0", "A 1.0.0", "B 1.0.0", "Same 5.0.0", "Settled 3.0.0", "Conditional.Ref 2.2.2"]);
    assert_eq!(
        notes,
        [
            "Varies $(Varies) ($(Varies) is set under a Condition)",
            "Windows $(OnlyWindows) ($(OnlyWindows) is set under a Condition)",
            "Chosen $(Chosen) ($(Chosen) is set under a Condition)",
            "Looped $(Loop) (properties that loop or grow too long)",
            "$(PkgName) 1.0.0 ($(PkgName) is not defined in the project, Directory.Build.props or Directory.Packages.props)",
        ]
    );
}

#[test]
fn multiplying_properties_are_refused() {
    let mut props: Vec<(String, Def)> = vec![("p0".into(), Def { value: "1".into(), conditional: false })];
    for i in 1..=8 {
        props.push((format!("p{i}"), Def { value: format!("$(p{})", i - 1).repeat(100), conditional: false }));
    }
    assert_eq!(expand("$(p0).$(p0)", &props, 0), Ok("1.1".to_string()));
    assert_eq!(expand("$(p8)", &props, 0), Err(Why::Loop));
}

/// A packages.lock.json beside the project wins: the project is skipped.
#[test]
fn a_sibling_lock_wins() {
    let d = TempDir::new("csproj-lock").unwrap();
    write(d.path(), "packages.lock.json", r#"{"version": 1, "dependencies": {}}"#);
    let (pkgs, notes) = one(
        &d,
        "App.csproj",
        &project(r#"<ItemGroup><PackageReference Include="Foo" Version="$(Undefined)" /></ItemGroup>"#),
    );
    assert!(pkgs.is_empty() && notes.is_empty());
    assert_eq!(
        one(&d, "packages.config", r#"<packages><package id="a" version="1.0.0" /></packages>"#),
        (vec![], vec![])
    );
}

/// XML details: entities and single quotes in attributes, `>` inside a
/// value, namespaces, comments and CDATA.
#[test]
fn xml_details() {
    let d = TempDir::new("csproj-xml").unwrap();
    let text = r#"<?xml version="1.0" encoding="utf-8"?>
<!-- <PackageReference Include="Commented" Version="1.0.0" /> -->
<msb:Project xmlns:msb="http://schemas.microsoft.com/developer/msbuild/2003">
  <msb:PropertyGroup><V><![CDATA[1.0.0]]></V></msb:PropertyGroup>
  <msb:ItemGroup>
    <msb:PackageReference Include='A&amp;B' Version='2.0.0' Condition="'$(X)' > '1'" />
    <msb:PackageReference Include="Cdata" Version="$(V)" />
  </msb:ItemGroup>
</msb:Project>"#;
    assert_eq!(one(&d, "App.csproj", text), (vec!["A&B 2.0.0".to_string(), "Cdata 1.0.0".to_string()], vec![]));
}

#[test]
fn malformed_files_are_errors() {
    let d = TempDir::new("csproj-bad").unwrap();
    let bad = [
        ("App.csproj", "not xml at all"),
        ("App.csproj", ""),
        ("App.csproj", "<Project>"),
        ("App.csproj", "<Project></Other>"),
        ("App.csproj", "</Project>"),
        ("App.csproj", "<Project><!-- open </Project>"),
        ("App.csproj", "<Project><![CDATA[ x </Project>"),
        ("App.csproj", "<?xml version='1.0'"),
        ("App.csproj", "<Project"),
        ("App.csproj", "<Project a></Project>"),
        ("App.csproj", "<Project a=b></Project>"),
        ("App.csproj", "<Project a=\"b></Project>"),
        ("App.csproj", "<Project = \"b\"></Project>"),
        ("App.csproj", "<></>"),
        ("App.csproj", "</a>"),
        ("App.csproj", "<Project/><Project/>"),
        ("App.csproj", "<packages />"),
        ("packages.config", "<Project />"),
        ("packages.config", "{}"),
    ];
    for (i, (name, text)) in bad.iter().enumerate() {
        let f = write(d.path(), &format!("{i}/{name}"), text);
        assert!(matches!(parse_file(&f, d.path()), Err(Error::Invalid(_))), "{name} accepted {text:?}");
    }
    let deep = format!("<Project>{}{}</Project>", "<a>".repeat(MAX_DEPTH + 1), "</a>".repeat(MAX_DEPTH + 1));
    let f = write(d.path(), "deep/App.csproj", &deep);
    assert!(matches!(parse_file(&f, d.path()), Err(Error::Invalid(m)) if m.contains("deeply")));
}

/// A Directory.*.props that can't be read is a note, and the properties
/// it would have set count as undefined.
#[test]
fn an_unreadable_props_file_is_a_note() {
    let d = TempDir::new("csproj-badprops").unwrap();
    write(d.path(), "Directory.Build.props", "<Project><PropertyGroup>");
    let (pkgs, notes) = one(
        &d,
        "App.csproj",
        &project(r#"<ItemGroup><PackageReference Include="Foo" Version="$(FooVersion)" /></ItemGroup>"#),
    );
    assert!(pkgs.is_empty());
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(notes[0].contains("Directory.Build.props: an element never closes"), "{notes:?}");
    assert!(notes[1].starts_with("Foo $(FooVersion) ($(FooVersion) is not defined"), "{notes:?}");
}

#[cfg(unix)]
#[test]
fn a_props_file_linking_outside_the_repo_is_not_read() {
    let d = TempDir::new("csproj-linkprops").unwrap();
    let (repo, outside) = (d.path().join("repo"), d.path().join("outside"));
    write(&outside, "Directory.Build.props", "<Project><PropertyGroup><V>1.0.0</V></PropertyGroup></Project>");
    std::fs::create_dir_all(&repo).unwrap();
    std::os::unix::fs::symlink(outside.join("Directory.Build.props"), repo.join("Directory.Build.props")).unwrap();
    let f = write(
        &repo,
        "App.csproj",
        &project(r#"<ItemGroup><PackageReference Include="Foo" Version="$(V)" /></ItemGroup>"#),
    );
    let read = parse_file(&f, &repo).unwrap();
    assert!(read.packages.is_empty());
    assert!(read.unchecked[0].contains("links outside the repository"), "{:?}", read.unchecked);
}

#[test]
fn packages_config_entries_without_an_exact_version() {
    let d = TempDir::new("pkgconfig-notes").unwrap();
    let text = r#"<packages>
  <package id="ok" version="1.0.0" />
  <package id="ranged" version="[1.0,2.0)" />
  <package id="" version="1.0.0" />
  <package id="nover" />
  <other id="x" version="1.0.0" />
</packages>"#;
    assert_eq!(
        one(&d, "packages.config", text),
        (
            vec!["ok 1.0.0".to_string()],
            vec!["ranged [1.0,2.0) (a version range)".to_string(), "nover (not a version)".to_string()]
        )
    );
}

/// Every truncation of a project parses or errors; none panics.
#[test]
fn truncated_projects_never_panic() {
    let text = r#"<?xml version="1.0"?><!-- c --><Project><PropertyGroup><V>1.0.0</V></PropertyGroup>
<ItemGroup><PackageReference Include='A&amp;B' Version="$(V)" Condition="'x' > 'y'"><Version><![CDATA[2.0]]></Version></PackageReference></ItemGroup></Project>"#;
    for (i, _) in text.char_indices() {
        let _ = document(&text[..i], "App.csproj");
    }
    assert!(document(text, "App.csproj").is_ok());
}
