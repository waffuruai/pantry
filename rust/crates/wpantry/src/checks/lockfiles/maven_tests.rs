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
        ["org.a:a 1.2.3", "org.m:managed 4.5.6", "org.example:sibling 3.0.0", "org.e:exact 2.0.1", "org.amp:a&b 5.0"]
    );
    assert!(parse("<project><dependencies></project>").is_err());
    assert!(parse("<project>").is_err());
}
