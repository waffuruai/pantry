use super::*;
use crate::error::Error;
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Response};

/// formulae.brew.sh's expat, trimmed to what is read (2026-11-22).
pub(crate) fn expat() -> Value {
    json!({
        "name": "expat",
        "homepage": "https://libexpat.github.io/",
        "versions": {"stable": "2.10.0", "head": "HEAD", "bottle": true},
        "urls": {
            "stable": {"url": "https://github.com/libexpat/libexpat/releases/download/R_2_10_0/expat-2.10.0.tar.xz", "using": null},
            "head": {"url": "https://github.com/libexpat/libexpat.git", "branch": "master"}
        },
        "revision": 0
    })
}

#[test]
fn a_repo_is_read_from_a_git_hosts_url() {
    let gh = "https://github.com/libexpat/libexpat";
    assert_eq!(
        repo_of("https://github.com/libexpat/libexpat/releases/download/R_2_10_0/expat-2.10.0.tar.xz").unwrap(),
        gh
    );
    assert_eq!(repo_of("https://github.com/libexpat/libexpat.git").unwrap(), gh);
    assert_eq!(repo_of("https://github.com/libexpat/libexpat/archive/refs/tags/R_2_10_0.tar.gz").unwrap(), gh);
    assert_eq!(repo_of("https://www.github.com/libexpat/libexpat/").unwrap(), gh);
    // The case is kept: OSV's GIT names are case-sensitive.
    assert_eq!(
        repo_of("https://github.com/OpenShot/openshot-qt/archive/refs/tags/v3.3.0.tar.gz").unwrap(),
        "https://github.com/OpenShot/openshot-qt"
    );
    assert_eq!(
        repo_of("https://codeberg.org/dnkl/foot/archive/1.20.0.tar.gz").unwrap(),
        "https://codeberg.org/dnkl/foot"
    );
    assert_eq!(
        repo_of("https://gitlab.com/group/sub/proj/-/archive/v1.0/proj-v1.0.tar.gz").unwrap(),
        "https://gitlab.com/group/sub/proj"
    );
    assert_eq!(repo_of("https://gitlab.com/group/proj.git").unwrap(), "https://gitlab.com/group/proj");
    for none in [
        "https://libexpat.github.io/",
        "https://ftp.gnu.org/gnu/readline/readline-8.2.tar.gz",
        "https://github.com/libexpat",
        "https://github.com/",
        "ftp://github.com/a/b",
        "https://github.com/a/b%20c",
    ] {
        assert_eq!(repo_of(none), None, "{none}");
    }
}

#[test]
fn a_formula_is_trimmed_to_its_urls_and_stable_version() {
    assert_eq!(
        trim(&expat()),
        json!({
            "urls": [
                "https://github.com/libexpat/libexpat/releases/download/R_2_10_0/expat-2.10.0.tar.xz",
                "https://github.com/libexpat/libexpat.git",
                "https://libexpat.github.io/"
            ],
            "stable": "2.10.0"
        })
    );
    // The homepage names the repo when the stable URL doesn't.
    let (_d, c) = cache();
    c.set(
        &key("x"),
        &json!({"urls": ["https://ftp.example.org/x.tar.gz", "https://github.com/o/x"], "stable": "1"}).to_string(),
    )
    .unwrap();
    assert_eq!(
        formula(&c, "x").unwrap().unwrap(),
        Formula { repo: "https://github.com/o/x".into(), stable: "1".into() }
    );
}

#[test]
fn formulae_are_fetched_by_name_once_and_kept() {
    let (_d, c) = cache();
    let net = Fake::new(|r| {
        match r.url.as_str() {
        "https://formulae.brew.sh/api/formula/expat.json" => Ok(Response::ok(expat().to_string())),
        "https://formulae.brew.sh/api/formula/openssl%403.json" => Ok(Response::ok(
            json!({"urls": {"stable": {"url": "https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz"}},
                   "versions": {"stable": "3.6.0"}})
            .to_string(),
        )),
        _ => Ok(Response::not_found()),
    }
    });
    let names = vec!["expat".to_string(), "openssl@3".to_string(), "tapped".to_string()];
    assert_eq!(formula(&c, "expat").unwrap(), None);
    prefetch(&c, &net, &names, false).unwrap();
    prefetch(&c, &net, &names, false).unwrap();
    assert_eq!(net.requests().len(), 3, "fresh copies aren't asked again");
    assert_eq!(
        formula(&c, "expat").unwrap().unwrap(),
        Formula { repo: "https://github.com/libexpat/libexpat".into(), stable: "2.10.0".into() }
    );
    assert_eq!(formula(&c, "openssl@3").unwrap().unwrap().repo, "https://github.com/openssl/openssl");
    // A formula the API doesn't know is kept with no repo.
    assert_eq!(formula(&c, "tapped").unwrap().unwrap(), Formula::default());
}

#[test]
fn an_unreachable_or_odd_answer_keeps_the_last_copy() {
    let (_d, c) = cache();
    prefetch(&c, &Fake::offline(), &["expat".into()], false).unwrap();
    assert_eq!(formula(&c, "expat").unwrap(), None, "nothing fetched is missing, not empty");
    let odd = Fake::new(|_| Ok(Response::ok("[1, 2]")));
    prefetch(&c, &odd, &["expat".into()], false).unwrap();
    assert_eq!(formula(&c, "expat").unwrap(), None);
    // Offline asks nothing.
    let net = Fake::new(|_| Ok(Response::ok(expat().to_string())));
    prefetch(&c, &net, &["expat".into()], true).unwrap();
    assert!(net.requests().is_empty());
    // An internal error passes through.
    let broken = Fake::new(|_| Err(Error::Io(std::io::Error::other("disk"))));
    assert!(prefetch(&c, &broken, &["expat".into()], false).is_err());
}
