use super::*;

fn got(text: &str) -> Vec<String> {
    parse(text).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect()
}

#[test]
fn classic_entries() {
    let text = r#"# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.22.5":
  version "7.22.5"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.22.5.tgz#234d98e1551960604f1246e6475891a570ad5658"
  dependencies:
    "@babel/highlight" "^7.22.5"

"alias@npm:left-pad@^1.3.0":
  version "1.3.0"

"local@file:../local":
  version "0.1.0"

"gitdep@git+https://github.com/x/gitdep.git#abc":
  version "2.0.0"
  resolved "git+https://github.com/x/gitdep.git#abc"

"short@user/repo":
  version "3.0.0"
  resolved "https://codeload.github.com/user/repo/tar.gz/abc"

"tar@https://example.com/tar-1.0.0.tgz":
  version "1.0.0"
"#;
    assert_eq!(got(text), ["@babel/code-frame 7.22.5", "left-pad 1.3.0"]);
}

#[test]
fn berry_entries() {
    let text = r#"__metadata:
  version: 8
  cacheKey: 10c0

"my-ms@npm:ms@2.1.3":
  version: 2.1.3
  resolution: "ms@npm:2.1.3"

"resolve@patch:resolve@npm%3A^1.22.0#optional!builtin<compat/resolve>":
  version: 1.22.8
  resolution: "resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=c3c19d"

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"dep@https://github.com/x/dep.git#commit=abc":
  version: 1.0.0
  resolution: "dep@https://github.com/x/dep.git#commit=abc"

"@scope/pkg@npm:^1.0.0":
  version: 1.0.1
  resolution: "@scope/pkg@npm:1.0.1"
  dependencies:
    version: "npm:9.9.9"
"#;
    assert_eq!(got(text), ["ms 2.1.3", "resolve 1.22.8", "@scope/pkg 1.0.1"]);
}
