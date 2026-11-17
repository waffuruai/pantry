use super::*;

#[test]
fn lines_of_coordinates() {
    let text = "# This is a Gradle generated file for dependency locking.\ncom.google.guava:guava:32.1.2-jre=compileClasspath,runtimeClasspath\njunit:junit:4.13.2=testCompileClasspath\nbad-line\nempty=annotationProcessor\n";
    assert_eq!(
        parse(text).unwrap(),
        [Package::new("Maven", "com.google.guava:guava", "32.1.2-jre"), Package::new("Maven", "junit:junit", "4.13.2")]
    );
}
