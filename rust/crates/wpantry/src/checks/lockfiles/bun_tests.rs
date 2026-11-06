use super::*;

#[test]
fn jsonc_and_entries() {
    let text = r#"{
  // a comment, with a comma,
  "lockfileVersion": 1, /* and "a block" */
  "workspaces": { "": { "name": "app", "dependencies": { "x": "1", }, }, },
  "packages": {
    "@types/node": ["@types/node@20.11.0", "", { "dependencies": { "undici-types": "~5.26.4" } }, "sha512-x"],
    "my-ms": ["ms@2.1.3", "", {}, "sha512-y"],
    "debug/ms": ["ms@2.0.0", "", {}, "sha512-z"],
    "url": ["url@https://example.com/x.tgz", {}],
    "gh": ["gh@github:user/repo#abc", {}, "user-repo-abc"],
    "local": ["local@file:local", {}],
    "ws": ["ws@workspace:packages/ws"],
    "odd": ["odd@1.0.0 // not a comment, ]", "", {}],
  },
}
"#;
    let got: Vec<String> = parse(text).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
    assert_eq!(got, ["@types/node 20.11.0", "ms 2.0.0", "ms 2.1.3", "odd 1.0.0 // not a comment, ]"]);
    assert!(parse("{ \"packages\": ").is_err());
}
