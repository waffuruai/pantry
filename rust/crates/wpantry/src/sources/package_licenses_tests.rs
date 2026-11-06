use super::*;
use crate::sources::testing::ids;
use crate::utils::net::{Fake, Response};

#[test]
fn lookup_caches_and_encodes_names() {
    let d = crate::utils::temp::TempDir::new("lic").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let net = Fake::new(|r| {
        Ok(match r.url.as_str() {
            "https://api.deps.dev/v3/systems/npm/packages/%40types%2Fnode/versions/20.11.0" => {
                Response::ok(r#"{"licenses": ["MIT"]}"#)
            }
            _ => Response { status: 404, body: vec![], etag: None },
        })
    });
    let items = vec![
        ("npm".to_string(), "@types/node".to_string(), "20.11.0".to_string()),
        ("npm".into(), "gone".into(), "1.0.0".into()),
        ("Hex".into(), "x".into(), "1".into()),
    ];
    assert_eq!(lookup(&c, &net, &items, false, &|_| {}).unwrap(), vec![ids(&["MIT"]), vec![], vec![]]);
    let quiet = Fake::new(|_| panic!("cached"));
    assert_eq!(lookup(&c, &quiet, &items[..1], false, &|_| {}).unwrap(), vec![ids(&["MIT"])]);
    assert!(matches!(
        lookup(&c, &Fake::offline(), &[("npm".into(), "new".into(), "1".into())], false, &|_| {}),
        Err(Error::Offline(_))
    ));
}
