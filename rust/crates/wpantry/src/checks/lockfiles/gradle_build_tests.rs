use super::*;

fn maven(name: &str, version: &str) -> Package {
    Package::new("Maven", name, version).direct(true)
}

fn whys(d: &Declared) -> Vec<(&str, &str)> {
    d.unresolved.iter().map(|u| (u.what.as_str(), u.why)).collect()
}

/// The shape a Groovy build without a lockfile has: the literal is read,
/// the interpolated version is not checked (never dropped, never clean).
#[test]
fn a_literal_reads_and_a_variable_is_not_checked() {
    let text = "plugins { id 'java' }\ndependencies {\n    implementation 'org.apache.logging.log4j:log4j-core:2.14.1'\n    implementation \"org.x:y:$ver\"\n}\n";
    let d = script(text).unwrap();
    assert_eq!(d.packages, [maven("org.apache.logging.log4j:log4j-core", "2.14.1")]);
    assert_eq!(whys(&d), [("implementation \"org.x:y:$ver\"", "version from a variable")]);
    assert_eq!(parse_script(text).unwrap(), d.packages);
}

#[test]
fn groovy_declarations() {
    let text = r#"
buildscript {
    dependencies { classpath 'com.example:plugin-lib:1.0.0' }
}
plugins {
    id 'org.springframework.boot' version '3.1.0'
}
// implementation 'commented:out:1.0'
/* dependencies { implementation 'block:comment:1.0' }
   still a comment */
def depsVersion = '2.0.0'
println "dependencies { implementation 'in:a:string' }"
dependencies {
    implementation 'org.a:a:1.0', 'org.b:b:2.0'
    implementation('org.c:c:3.0') {
        exclude group: 'org.unwanted', module: 'x'
        because 'org.not:a-dep:1.0'
    }
    api "org.d:d:4.0:sources@jar"
    runtimeOnly 'org.e:e:5.0!!'
    testImplementation 'junit:junit:4.13.2'
    implementation project(':core')
    implementation files('libs/local.jar')
    implementation fileTree(dir: 'libs', include: ['*.jar'])
    implementation platform('org.springframework.boot:spring-boot-dependencies:3.1.0')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.f:f:1.+'
    implementation 'org.g:g:latest.release'
    implementation 'org.h:h:[1.0,2.0)'
    implementation group: 'org.i', name: 'i', version: '1.0'
    implementation libs.from.catalog
    implementation deps.from.ext
    implementation "org.j:j:${depsVersion}"
    implementation 'org.k:k:' + depsVersion
    constraints {
        implementation 'org.constrained:c:9.9'
    }
    if (System.getenv('CI')) {
        implementation 'org.ci:ci:1.0'
    } else {
        implementation 'org.local:local:1.0'
    }
}
"#;
    let d = script(text).unwrap();
    assert_eq!(
        d.packages,
        [
            maven("com.example:plugin-lib", "1.0.0"),
            maven("org.a:a", "1.0"),
            maven("org.b:b", "2.0"),
            maven("org.c:c", "3.0"),
            maven("org.d:d", "4.0"),
            maven("org.e:e", "5.0"),
            maven("junit:junit", "4.13.2").scoped(Scope::Dev),
            maven("org.springframework.boot:spring-boot-dependencies", "3.1.0"),
            maven("org.ci:ci", "1.0"),
            maven("org.local:local", "1.0"),
        ]
    );
    assert_eq!(
        whys(&d),
        [
            (
                "implementation 'org.springframework.boot:spring-boot-starter-web'",
                "no version (left to a platform, BOM or plugin)"
            ),
            ("implementation 'org.f:f:1.+'", "a dynamic version or a range"),
            ("implementation 'org.g:g:latest.release'", "a dynamic version or a range"),
            ("implementation 'org.h:h:[1.0,2.0)'", "a dynamic version or a range"),
            ("implementation group: 'org.i', name: 'i', version: '1.0'", "map or named-argument notation"),
            ("implementation deps.from.ext", "version from a variable"),
            ("implementation \"org.j:j:${depsVersion}\"", "version from a variable"),
            ("implementation 'org.k:k:' + depsVersion", "an expression"),
        ]
    );
}

#[test]
fn kotlin_declarations() {
    let text = r#"
plugins {
    java
    kotlin("jvm") version "2.0.0"
    id("com.example.plugin") version "1.0"
}
val jacksonVersion = "2.9.8"
dependencies {
    implementation("org.apache.logging.log4j:log4j-core:2.14.1")
    implementation(libs.jackson.databind); api(libs.bundles.web)
    implementation(platform(libs.spring.bom))
    implementation(
        "org.multi:line:1.0"
    )
    testImplementation(kotlin("test"))
    implementation("com.fasterxml.jackson.core:jackson-core:$jacksonVersion")
    implementation(group = "org.n", name = "n", version = "1.0")
    implementation(project(":shared"))
    implementation(enforcedPlatform("org.bom:bom:1.0"))
    testFixturesApi(testFixtures("org.tf:tf:2.0"))
    "ksp"("org.string:call:1.0")
}
kotlin {
    sourceSets {
        val commonMain by getting {
            dependencies { implementation("org.kmp:common:1.0") }
        }
    }
}
"#;
    let d = script(text).unwrap();
    assert_eq!(
        d.packages,
        [
            maven("org.apache.logging.log4j:log4j-core", "2.14.1"),
            maven("org.multi:line", "1.0"),
            maven("org.bom:bom", "1.0"),
            maven("org.tf:tf", "2.0").scoped(Scope::Dev),
            maven("org.string:call", "1.0"),
            maven("org.kmp:common", "1.0"),
        ]
    );
    assert_eq!(
        whys(&d),
        [
            ("testImplementation(kotlin(\"test\"))", "a helper call"),
            ("implementation(\"com.fasterxml.jackson.core:jackson-core:$jacksonVersion\")", "version from a variable"),
            ("implementation(group = \"org.n\", name = \"n\", version = \"1.0\")", "map or named-argument notation"),
        ]
    );
}

#[test]
fn a_script_that_cannot_be_tokenized_is_an_error() {
    for text in ["dependencies { implementation 'never:closes:1.0 }\n", "/* never closes\ndependencies {}\n"] {
        assert!(matches!(script(text), Err(Error::Invalid(_))), "{text:?}");
    }
    assert!(matches!(script(&"{".repeat(MAX_DEPTH + 1)), Err(Error::Invalid(_))));
    // Triple-quoted strings and escapes are strings, not code.
    let d = script("def s = \"\"\"dependencies { implementation 'a:b:1' }\"\"\"\ndependencies { implementation 'org.q:q:1.0' /* \\' */ }\n").unwrap();
    assert_eq!(d.packages, [maven("org.q:q", "1.0")]);
    assert_eq!(script("").unwrap(), Declared::default());
}

#[test]
fn coordinates() {
    assert_eq!(coordinate("g:a:1.0"), Ok(("g:a".into(), "1.0".into())));
    assert_eq!(coordinate("g:a:1.0:jdk15@jar"), Ok(("g:a".into(), "1.0".into())));
    assert_eq!(coordinate("g:a:1.0!!"), Ok(("g:a".into(), "1.0".into())));
    for (s, why) in [
        ("g:a:$v", "version from a variable"),
        ("g:a", "no version (left to a platform, BOM or plugin)"),
        ("plain", "not a group:artifact:version string"),
        ("g::1.0", "not a group:artifact:version string"),
        ("g:a:1:c:x", "not a group:artifact:version string"),
        ("g:a b:1.0", "not a group:artifact:version string"),
        ("g:a:1.0+", "a dynamic version or a range"),
        ("g:a:latest.integration", "a dynamic version or a range"),
        ("g:a:(,2.0]", "a dynamic version or a range"),
        ("g:a:SNAPSHOT", "not a version"),
    ] {
        assert_eq!(coordinate(s), Err(why), "{s}");
    }
    assert_eq!(shown(&"x".repeat(100)), format!("{}...", "x".repeat(SHOWN)));
    assert_eq!(shown(&"x".repeat(SHOWN)), "x".repeat(SHOWN));
    assert_eq!(shown(&format!("{} y", "x".repeat(SHOWN - 1))), format!("{} ...", "x".repeat(SHOWN - 1)));
    assert_eq!(shown("a \n   b"), "a b");
    assert_eq!(shown("  a  "), "a");
}

/// A long list of unresolved arguments is read in time linear in its
/// length: each is shown from its own tokens, not by flattening the whole
/// declaration again from its start (16K items took 32 s that way).
#[test]
fn a_long_unresolved_list_reads_in_linear_time() {
    const N: usize = 16_000;
    let text = format!("dependencies {{\n    implementation {}'g:last'\n}}\n", "'g:a',\n".repeat(N - 1));
    let started = std::time::Instant::now();
    let d = script(&text).unwrap();
    let took = started.elapsed();
    assert_eq!(d.unresolved.len(), N);
    assert!(took < std::time::Duration::from_secs(2), "{N} items took {took:?}");
    assert_eq!(d.unresolved[0].what, "implementation 'g:a'");
    assert_eq!(d.unresolved[N - 1].what, "implementation 'g:last'", "its own span, not the list so far");
    // Kotlin's parenthesized form keeps the parentheses on the later ones.
    let d = script("dependencies { implementation(\"a:b:$v\", \"c:d\") }\n").unwrap();
    assert_eq!(
        whys(&d),
        [
            ("implementation(\"a:b:$v\"", "version from a variable"),
            ("implementation(\"c:d\")", "no version (left to a platform, BOM or plugin)")
        ]
    );
}

#[test]
fn version_catalogs() {
    let text = r#"
[versions]
jackson = "2.9.8"
strict = { strictly = "1.5.0" }
ranged = { strictly = "[1.0,2.0)" }
preferred = { prefer = "1.0" }

[libraries]
jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
inline = { module = "org.inline:inline", version = "3.0" }
by-group = { group = "org.group", name = "named", version = "4.0" }
rich = { module = "org.rich:rich", version = { strictly = "5.0" } }
ref-table = { module = "org.ref:ref", version = { ref = "strict" } }
as-string = "org.string:string:6.0"
ranged = { module = "org.ranged:ranged", version.ref = "ranged" }
preferred = { module = "org.pref:pref", version.ref = "preferred" }
missing = { module = "org.missing:missing", version.ref = "nope" }
managed = { module = "org.managed:managed" }
dynamic = "org.dyn:dyn:1.+"
broken = { version = "1.0" }

[plugins]
spring = { id = "org.springframework.boot", version = "3.1.0" }
"#;
    let d = catalog(text).unwrap();
    assert_eq!(
        d.packages,
        [
            maven("com.fasterxml.jackson.core:jackson-databind", "2.9.8"),
            maven("org.inline:inline", "3.0"),
            maven("org.group:named", "4.0"),
            maven("org.rich:rich", "5.0"),
            maven("org.ref:ref", "1.5.0"),
            maven("org.string:string", "6.0"),
        ]
    );
    assert_eq!(
        whys(&d),
        [
            ("[libraries] ranged", "a dynamic version or a range"),
            ("[libraries] preferred", "a dynamic version or a range"),
            ("[libraries] missing", "version.ref names no [versions] entry"),
            ("[libraries] managed", "no version (left to a platform, BOM or plugin)"),
            ("[libraries] dynamic", "a dynamic version or a range"),
            ("[libraries] broken", "not a module or group and name"),
        ]
    );
    assert_eq!(parse_catalog(text).unwrap(), d.packages);
    for not in ["", "this is not a catalog\n", "[package]\nname = \"x\"\n"] {
        assert!(matches!(catalog(not), Err(Error::Invalid(_))), "{not:?}");
    }
    assert_eq!(catalog("[versions]\n").unwrap(), Declared::default());
}

#[test]
fn which_files_the_walk_reads() {
    let d = crate::utils::temp::TempDir::new("gradle-scanned").unwrap();
    let (locked, open, modular) = (d.path().join("locked"), d.path().join("open"), d.path().join("modular"));
    std::fs::create_dir_all(locked.join("gradle")).unwrap();
    std::fs::create_dir_all(open.join("gradle")).unwrap();
    std::fs::write(locked.join("gradle.lockfile"), "empty=\n").unwrap();
    let none: &[PathBuf] = &[];
    assert!(scanned(&open, "build.gradle", none) && scanned(&open, "build.gradle.kts", none));
    let beside = [locked.clone()];
    assert!(!scanned(&locked, "build.gradle", &beside) && !scanned(&locked, "build.gradle.kts", &beside));
    assert!(scanned(&open.join("gradle"), "libs.versions.toml", none));
    assert!(scanned(&open.join("gradle"), "tools.versions.toml", none));
    assert!(!scanned(&locked.join("gradle"), "libs.versions.toml", none), "the project is locked");
    // A multi-module build locks its modules, not its root: the catalog is
    // still covered, and so is the module's script, not the root's.
    let module = [modular.join("app")];
    assert!(!scanned(&modular.join("gradle"), "libs.versions.toml", &module), "a module is locked");
    assert!(!scanned(&modular.join("app"), "build.gradle", &module));
    assert!(scanned(&modular, "build.gradle", &module));
    assert!(scanned(&open.join("gradle"), "libs.versions.toml", &module), "another project's lockfile");
    assert!(!scanned(&open, "libs.versions.toml", none), "catalogs live under gradle/");
    assert!(!scanned(&open.join("gradle"), ".versions.toml", none));
    assert!(!scanned(&open, "settings.gradle", none) && !scanned(&open, "build.gradle.bak", none));
    assert!(super::super::supported("build.gradle") && super::super::supported("libs.versions.toml"));
    assert!(declared(&open.join("build.gradle")) && declared(&open.join("build.gradle.kts")));
    assert!(declared(&open.join("gradle/libs.versions.toml")));
    assert!(
        !declared(&locked.join("gradle.lockfile")) && !declared(&open.join("pom.xml")) && !declared(Path::new("/"))
    );
}

#[test]
fn the_not_checked_note() {
    let d = crate::utils::temp::TempDir::new("gradle-note").unwrap();
    let write = |name: &str, text: &str| {
        let p = d.path().join(name);
        std::fs::write(&p, text).unwrap();
        p
    };
    let one = write("build.gradle", "dependencies { implementation \"org.x:y:$ver\" }\n");
    assert_eq!(
        unresolved_note(&one).unwrap(),
        (
            1,
            "1 not checked, Gradle would have to run to know the version: implementation \"org.x:y:$ver\" (version from a variable)"
                .to_string()
        )
    );
    let two = write("build.gradle.kts", "dependencies {\n implementation(\"a:b:$v\")\n implementation(\"c:d\")\n}\n");
    let (n, note) = unresolved_note(&two).unwrap();
    assert!(n == 2 && note.ends_with("(version from a variable) and 1 more"), "{n} {note}");
    let cat = write("libs.versions.toml", "[libraries]\nx = { module = \"a:b\" }\n");
    assert!(unresolved_note(&cat).unwrap().1.contains("[libraries] x (no version"));
    let clean = write("other.versions.toml", "[libraries]\nx = \"a:b:1.0\"\n");
    assert_eq!(unresolved_note(&clean), None);
    assert_eq!(unresolved_note(&write("pom.xml", "<project/>")), None);
    assert_eq!(unresolved_note(&write("broken.versions.toml", "nope")), None, "the extractor reports it");
    assert_eq!(unresolved_note(&d.path().join("missing/build.gradle")), None);
}
