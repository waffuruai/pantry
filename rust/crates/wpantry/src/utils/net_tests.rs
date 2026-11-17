use super::*;

#[test]
fn github_clone_urls() {
    assert_eq!(github("jdx/mise"), "https://github.com/jdx/mise.git");
}

#[test]
fn redirects_are_followed_only_to_listed_hosts() {
    let req = Request {
        method: "GET",
        url: "https://api.github.com/a".into(),
        headers: vec![("Authorization".into(), "Bearer t".into()), ("Accept".into(), "x".into())],
        body: None,
        limit: MAX_BODY,
    };
    let seen = Mutex::new(Vec::new());
    let send = |r: &Request| {
        allowed(&r.url)?;
        seen.lock().unwrap().push((r.url.clone(), r.header("authorization").is_some()));
        Ok(match r.url.as_str() {
            "https://api.github.com/a" => (Response { status: 302, body: vec![], etag: None }, Some("/b".to_string())),
            "https://api.github.com/b" => (
                Response { status: 302, body: vec![], etag: None },
                Some("https://release-assets.githubusercontent.com/c".to_string()),
            ),
            _ => (Response::ok("done"), None),
        })
    };
    assert_eq!(follow_redirects(&req, send).unwrap().body, b"done");
    assert_eq!(
        seen.into_inner().unwrap(),
        [
            ("https://api.github.com/a".to_string(), true),
            ("https://api.github.com/b".to_string(), true),
            ("https://release-assets.githubusercontent.com/c".to_string(), false),
        ],
        "the token stays with the first host"
    );
    let elsewhere = |r: &Request| {
        allowed(&r.url)?;
        Ok((Response { status: 301, body: vec![], etag: None }, Some("https://evil.example/".to_string())))
    };
    assert!(follow_redirects(&req, elsewhere).is_err(), "a hop to an unlisted host is refused");
    let looping = |_: &Request| Ok((Response { status: 302, body: vec![], etag: None }, Some("/a".to_string())));
    assert!(follow_redirects(&req, looping).unwrap_err().to_string().contains("redirects"));
    let not_a_redirect = |_: &Request| Ok((Response::ok("x"), Some("/ignored".to_string())));
    assert_eq!(follow_redirects(&req, not_a_redirect).unwrap().status, 200);
}

#[test]
fn a_users_host_is_allowed_only_once_allowed() {
    assert!(allowed("https://t-allow.example/x").is_err());
    allow("T-Allow.Example");
    assert!(allowed("https://t-allow.example/x").is_ok());
    assert!(allowed("https://other.t-allow.example/x").is_err(), "the host, not its subdomains");
}

#[test]
fn user_agent_names_the_project() {
    assert_eq!(USER_AGENT, format!("wpantry/{} (+https://github.com/waffuruai/pantry)", crate::VERSION));
}

#[test]
fn every_source_is_on_the_host_list_and_nothing_else_is_asked() {
    // Every bundled https source, and the hosts its downloads redirect to.
    let mut sources: Vec<String> = Vec::new();
    for s in crate::sources::file::bundled() {
        if s.transport == crate::sources::file::Transport::Https {
            sources.push(s.url.replace("{}", "x"));
            sources.extend(s.redirects.iter().map(|h| format!("https://{h}/x")));
        }
    }
    for url in &sources {
        assert!(allowed(url).is_ok(), "{url}");
    }
    assert_eq!(host_of("https://API.OSV.DEV:443/v1/querybatch?x#y").as_deref(), Some("api.osv.dev"));
    assert_eq!(host_of("http://api.osv.dev/v1"), None, "plain http is never used");
    assert_eq!(host_of("https://api.osv.dev@evil.example/"), None, "userinfo can't dress a host up");
    assert_eq!(host_of("https:///path"), None);
    // The real client refuses before any connection is made: no network here.
    let http = Http::new();
    for url in ["https://evil.example/", "https://api.osv.dev.evil.example/v1", "http://api.osv.dev/v1", "ftp://x/"] {
        let req = Request { method: "GET", url: url.into(), headers: Vec::new(), body: None, limit: MAX_BODY };
        assert!(matches!(http.send(&req), Err(Error::Invalid(_))), "{url}");
    }
}

#[test]
fn backoff_grows_and_jitters_within_bounds() {
    for attempt in 0..3u32 {
        let base = 250u64 << attempt;
        let b = backoff(attempt).as_millis() as u64;
        assert!((base..=base + base / 4).contains(&b), "attempt {attempt}: {b}");
    }
}

#[test]
fn request_semantics() {
    let net = Fake::new(|r| {
        Ok(match r.url.as_str() {
            "https://x/ok" => Response { status: 200, body: b"{\"a\": 1}".to_vec(), etag: Some("\"e1\"".into()) },
            "https://x/gone" => Response { status: 404, body: b"nope".to_vec(), etag: None },
            "https://x/same" => Response { status: 304, body: Vec::new(), etag: None },
            _ => Response { status: 503, body: Vec::new(), etag: None },
        })
    });
    assert_eq!(get_json(&net, "https://x/ok", &[]).unwrap().unwrap()["a"], 1);
    assert_eq!(get_json(&net, "https://x/gone", &[]).unwrap(), None);
    assert_eq!(request(&net, "https://x/same", None, &[], Some("\"e1\"")).unwrap().etag.as_deref(), Some("\"e1\""));
    assert!(matches!(get_json(&net, "https://x/down", &[]), Err(Error::Offline(_))));
    let sent = net.requests();
    assert_eq!(sent[0].header("user-agent"), Some(USER_AGENT));
    assert_eq!(sent[2].header("If-None-Match"), Some("\"e1\""));
    post_json(&net, "https://x/ok", &serde_json::json!({"q": 1})).unwrap();
    let post = net.requests().pop().unwrap();
    assert_eq!((post.method, post.header("content-type")), ("POST", Some("application/json")));
}

#[test]
fn github_headers_ask_for_the_api_json() {
    let h = github_headers();
    assert_eq!(h[0], ("Accept".to_string(), "application/vnd.github+json".to_string()));
    // A token, when the environment has one, is sent as a bearer.
    assert!(h.iter().skip(1).all(|(k, v)| k == "Authorization" && v.starts_with("Bearer ")));
    assert_eq!(h.len(), 1 + usize::from(std::env::var("GITHUB_TOKEN").is_ok_and(|t| !t.is_empty())));
}

#[test]
fn retries_stop_at_the_first_answer_or_hard_error() {
    let resp = |status: u16| Response { status, body: Vec::new(), etag: None };
    // Retryable statuses are tried again after Retry-After (0 s here), then
    // the last answer is returned as it is.
    let mut n = 0;
    let r = with_retries(|| {
        n += 1;
        Ok((resp(503), Some(Duration::ZERO)))
    });
    assert_eq!((r.unwrap().status, n), (503, TRIES));
    let mut n = 0;
    let r = with_retries(|| {
        n += 1;
        Ok((resp(if n == 1 { 429 } else { 200 }), Some(Duration::ZERO)))
    });
    assert_eq!((r.unwrap().status, n), (200, 2));
    // A dropped connection is tried again after the backoff; a refused
    // host or an oversized body is not.
    let mut n = 0;
    let r = with_retries(|| {
        n += 1;
        if n == 1 { Err(Error::Offline("reset".into())) } else { Ok((resp(404), None)) }
    });
    assert_eq!((r.unwrap().status, n), (404, 2));
    let mut n = 0;
    let r = with_retries(|| {
        n += 1;
        Err(Error::Invalid("too big".into()))
    });
    assert!(matches!(r, Err(Error::Invalid(_))) && n == 1);
    let mut n = 0;
    let r = with_retries(|| {
        n += 1;
        Err::<(Response, Option<Duration>), Error>(Error::Offline("down".into()))
    });
    assert!(matches!(r, Err(Error::Offline(_))) && n == TRIES);
}

#[test]
fn retry_after_and_body_errors_are_read_as_the_server_meant() {
    assert_eq!(retry_after(Some(" 3 ")), Some(Duration::from_secs(3)));
    assert_eq!(retry_after(Some("600")), Some(Duration::from_secs(10)), "capped");
    assert_eq!(retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")), None);
    assert_eq!(retry_after(None), None);
    let big = body_error("https://x/", MAX_BODY, ureq::Error::BodyExceedsLimit(MAX_BODY));
    assert!(matches!(big, Error::Invalid(m) if m == format!("https://x/: response over {MAX_BODY} bytes")));
    let cut = body_error("https://x/", MAX_BODY, ureq::Error::Io(std::io::Error::other("reset")));
    assert!(matches!(cut, Error::Offline(m) if m.starts_with("https://x/: ")));
}

/// Nothing listens on port 1 of the loopback: the connection is refused
/// before any byte leaves the machine, and comes back as `Offline`.
#[test]
fn a_refused_connection_is_offline() {
    let http = Http::default();
    for body in [None, Some(b"{}".to_vec())] {
        let req = Request {
            method: if body.is_some() { "POST" } else { "GET" },
            url: "https://127.0.0.1:1/".into(),
            headers: vec![("Accept".into(), "application/json".into())],
            body,
            limit: MAX_BODY,
        };
        assert!(matches!(http.send_once(&req), Err(Error::Offline(m)) if m.starts_with("https://127.0.0.1:1/")));
    }
}

#[test]
fn a_relative_redirect_resolves_against_the_url_it_answered() {
    let base = "https://epss.empiricalsecurity.com/dir/epss_scores-current.csv.gz?x=1";
    assert_eq!(
        resolve(base, "epss_scores-2026-11-05.csv.gz"),
        "https://epss.empiricalsecurity.com/dir/epss_scores-2026-11-05.csv.gz"
    );
    assert_eq!(resolve(base, "/other.gz"), "https://epss.empiricalsecurity.com/other.gz");
    assert_eq!(resolve(base, "https://elsewhere.example/a"), "https://elsewhere.example/a");
    assert_eq!(resolve("https://h.example", "a.gz"), "https://h.example/a.gz", "a URL with no path");
}
