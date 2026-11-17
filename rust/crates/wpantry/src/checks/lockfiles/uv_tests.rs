use super::*;

#[test]
fn the_projects_metadata_says_what_is_direct() {
    let text = "version = 1\n\n[[package]]\nname = \"golden\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\ndependencies = [\n    { name = \"jinja2\" },\n]\n\n[package.dev-dependencies]\ndev = [\n    { name = \"pytest\" },\n]\n\n[package.metadata]\nrequires-dist = [\n    { name = \"Jinja2\", specifier = \"==3.1.2\" },\n]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"pytest\", specifier = \"==7.4.0\" }]\n\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.2\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"markupsafe\"\nversion = \"2.1.5\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"pytest\"\nversion = \"7.4.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
    let got = parse(text).unwrap();
    let names: Vec<&str> = got.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["jinja2", "markupsafe", "pytest"]);
    assert_eq!((got[0].scope, got[0].direct), (Scope::Runtime, Some(true)));
    assert_eq!((got[1].scope, got[1].direct), (Scope::Unknown, Some(false)));
    assert_eq!((got[2].scope, got[2].direct), (Scope::Dev, Some(true)));
    assert_eq!(names_in("[{ name = \"a\", specifier = \">=1\" }, { name = 'B_c' }]"), ["a", "b-c"]);
}
