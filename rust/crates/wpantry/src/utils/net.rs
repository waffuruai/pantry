//! HTTP behind a trait: one `ureq` + `rustls` implementation, and a fake for
//! tests that answers from a closure and records every request. Every
//! request names us and times out after 30 s; callers decide what an offline
//! machine means for their source. Only the hosts in [`HOSTS`] (the list in
//! `docs/public/checks-and-sources.md#sources`) are ever asked: [`Http`]
//! refuses any other URL before a connection is made. TLS is verified
//! against the platform's trust store, so a CA this machine distrusts is
//! distrusted here too.

use crate::error::{Error, Result};
use crate::utils::json;
use serde_json::Value;
use std::sync::Mutex;
use std::time::Duration;

pub const USER_AGENT: &str = concat!("wpantry/", env!("CARGO_PKG_VERSION"), " (+https://github.com/waffuruai/pantry)");
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// The largest response body read; a bigger one is `Invalid`.
pub const MAX_BODY: u64 = 128 << 20;

/// Every host wpantry asks, and the only ones [`Http`] will connect to. A
/// source that moves, or a new one, is added here and in
/// `docs/public/checks-and-sources.md`, in the same change.
pub const HOSTS: &[&str] = &[
    "api.osv.dev",
    "www.cisa.gov",
    "endoflife.date",
    "formulae.brew.sh",
    "security.archlinux.org",
    "versionhistory.googleapis.com",
    "product-details.mozilla.org",
    "www.postgresql.org",
    "main.vscode-cdn.net",
    "marketplace.visualstudio.com",
    "open-vsx.org",
    "api.github.com",
    "api.deps.dev",
    "haveibeenpwned.com",
    "api.xposedornot.com",
    // GitHub serves release assets (YARA rule bundles) from these, by redirect.
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    // The malware scan's indicator lists and, with consent, hash lookups.
    "feodotracker.abuse.ch",
    "yaraify-api.abuse.ch",
    "hashlookup.circl.lu",
    "mb-api.abuse.ch",
];

/// Redirects followed per request; every hop must be in [`HOSTS`] too.
const MAX_REDIRECTS: usize = 5;

/// The host of an `https://` URL, lowercased and without a port; `None` for
/// any other scheme, a missing host, or userinfo (`https://a@b/`).
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    if host.is_empty() { None } else { Some(host.to_ascii_lowercase()) }
}

/// `Ok` when `url` is https to a host in [`HOSTS`].
fn allowed(url: &str) -> Result<()> {
    match host_of(url) {
        Some(h) if HOSTS.contains(&h.as_str()) => Ok(()),
        _ => Err(Error::Invalid(format!("{url}: not a host wpantry asks (docs/public/checks-and-sources.md)"))),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub etag: Option<String>,
}

impl Response {
    pub fn ok(body: impl Into<Vec<u8>>) -> Response {
        Response { status: 200, body: body.into(), etag: None }
    }
}

/// Sends one request. Any HTTP status comes back as a `Response`; only a
/// transport failure (DNS, TLS, timeout, a body over the cap) is an error.
pub trait Net: Send + Sync {
    fn send(&self, req: &Request) -> Result<Response>;
}

/// `request` semantics shared by every caller (Python: `net.request`):
/// 2xx and 304 (when `etag` still matches) and 404 come back; anything else
/// is `Offline`.
pub fn request(
    net: &dyn Net,
    url: &str,
    data: Option<&Value>,
    headers: &[(&str, &str)],
    etag: Option<&str>,
) -> Result<Response> {
    let mut h: Vec<(String, String)> =
        vec![("User-Agent".into(), USER_AGENT.into()), ("Accept".into(), "application/json".into())];
    for (k, v) in headers {
        h.retain(|(name, _)| !name.eq_ignore_ascii_case(k));
        h.push((k.to_string(), v.to_string()));
    }
    let body = data.map(|d| serde_json::to_vec(d).expect("a Value always serialises"));
    if body.is_some() {
        h.push(("Content-Type".into(), "application/json".into()));
    }
    if let Some(e) = etag {
        h.push(("If-None-Match".into(), e.to_string()));
    }
    let req = Request { method: if body.is_some() { "POST" } else { "GET" }, url: url.to_string(), headers: h, body };
    let resp = net.send(&req)?;
    match resp.status {
        200..=299 | 404 => Ok(resp),
        304 => Ok(Response { status: 304, body: Vec::new(), etag: etag.map(str::to_string) }),
        s => Err(Error::Offline(format!("{url}: HTTP {s}"))),
    }
}

/// The JSON at `url`, or None on 404.
pub fn get_json(net: &dyn Net, url: &str, headers: &[(&str, &str)]) -> Result<Option<Value>> {
    let resp = request(net, url, None, headers, None)?;
    if resp.status == 404 {
        return Ok(None);
    }
    json::parse(&resp.body, json::MAX_DOCUMENT).map(Some)
}

pub fn post_json(net: &dyn Net, url: &str, data: &Value) -> Result<Value> {
    let resp = request(net, url, Some(data), &[], None)?;
    json::parse(&resp.body, json::MAX_DOCUMENT)
}

/// GitHub API headers; a GITHUB_TOKEN, when set, lifts the anonymous rate
/// limit (60 requests an hour).
pub fn github_headers() -> Vec<(String, String)> {
    let mut h = vec![("Accept".to_string(), "application/vnd.github+json".to_string())];
    if let Ok(t) = std::env::var("GITHUB_TOKEN")
        && !t.is_empty()
    {
        h.push(("Authorization".into(), format!("Bearer {t}")));
    }
    h
}

/// The real network: blocking `ureq` over `rustls`, server certificates
/// verified by the platform (the keychain on macOS, the system bundle on
/// Linux), proxy from the environment (`HTTPS_PROXY`, `ALL_PROXY`), and
/// only the hosts in [`HOSTS`].
pub struct Http {
    agent: ureq::Agent,
}

impl Default for Http {
    fn default() -> Self {
        Self::new()
    }
}

impl Http {
    pub fn new() -> Http {
        // Keep a connection for each parallel fetch (OSV records, deps.dev):
        // ureq keeps 3 per host by default, so the rest paid a TLS handshake
        // per request.
        let tls = ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build();
        let config = ureq::Agent::config_builder()
            .tls_config(tls)
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .https_only(true)
            .max_idle_connections(32)
            .max_idle_connections_per_host(16)
            // Redirects are followed here, not by ureq, so each hop is
            // checked against HOSTS before a connection is made.
            .max_redirects(0)
            .build();
        Http { agent: config.into() }
    }
}

/// Tries per request: a dropped connection or a 429/502/503/504 is tried
/// again after 250 ms, then 500 ms (plus jitter), honouring Retry-After up
/// to 10 s. Every request here is idempotent (GETs, and OSV's querybatch).
const TRIES: u32 = 3;

impl Net for Http {
    fn send(&self, req: &Request) -> Result<Response> {
        follow_redirects(req, |r| {
            allowed(&r.url)?;
            let mut location = None;
            let resp = with_retries(|| {
                let (resp, retry, loc) = self.send_once(r)?;
                location = loc;
                Ok((resp, retry))
            })?;
            Ok((resp, location))
        })
    }
}

/// Send `req`, then follow a 301/302/303/307/308 to its `Location` (a GET,
/// headers kept except `Authorization`, which never leaves the first host),
/// at most [`MAX_REDIRECTS`] times. `send` checks each URL against [`HOSTS`].
fn follow_redirects(req: &Request, send: impl Fn(&Request) -> Result<(Response, Option<String>)>) -> Result<Response> {
    let mut current = req.clone();
    for _ in 0..=MAX_REDIRECTS {
        let (resp, location) = send(&current)?;
        let Some(next) = location.filter(|_| matches!(resp.status, 301 | 302 | 303 | 307 | 308)) else {
            return Ok(resp);
        };
        let next = if next.starts_with('/') {
            let host = host_of(&current.url).unwrap_or_default();
            format!("https://{host}{next}")
        } else {
            next
        };
        let first_host = host_of(&req.url);
        current = Request {
            method: "GET",
            headers: current
                .headers
                .into_iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("authorization") || host_of(&next) == first_host)
                .collect(),
            url: next,
            body: None,
        };
    }
    Err(Error::Invalid(format!("{}: more than {MAX_REDIRECTS} redirects", req.url)))
}

/// `once` up to [`TRIES`] times: the response and the server's Retry-After.
fn with_retries(mut once: impl FnMut() -> Result<(Response, Option<Duration>)>) -> Result<Response> {
    let mut last = None;
    for attempt in 0..TRIES {
        match once() {
            Ok((resp, retry_after)) if attempt + 1 < TRIES && matches!(resp.status, 429 | 502 | 503 | 504) => {
                std::thread::sleep(retry_after.unwrap_or_else(|| backoff(attempt)));
                last = Some(Ok(resp));
            }
            Ok((resp, _)) => return Ok(resp),
            Err(e @ Error::Offline(_)) if attempt + 1 < TRIES => {
                std::thread::sleep(backoff(attempt));
                last = Some(Err(e));
            }
            Err(e) => return Err(e),
        }
    }
    last.expect("at least one try")
}

/// 250 ms, 500 ms, …, each with up to a quarter of jitter.
fn backoff(attempt: u32) -> std::time::Duration {
    let base = 250u64 << attempt;
    let jitter =
        (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0)
            as u64)
            % (base / 4 + 1);
    std::time::Duration::from_millis(base + jitter)
}

impl Http {
    /// One try: the response, the server's Retry-After (capped) and its
    /// redirect `Location`, if any.
    fn send_once(&self, req: &Request) -> Result<(Response, Option<std::time::Duration>, Option<String>)> {
        let offline = |e: ureq::Error| Error::Offline(format!("{}: {e}", req.url));
        let mut resp = match &req.body {
            Some(body) => {
                let mut r = self.agent.post(&req.url);
                for (k, v) in &req.headers {
                    r = r.header(k.as_str(), v.as_str());
                }
                r.send(&body[..]).map_err(offline)?
            }
            None => {
                let mut r = self.agent.get(&req.url);
                for (k, v) in &req.headers {
                    r = r.header(k.as_str(), v.as_str());
                }
                r.call().map_err(offline)?
            }
        };
        let status = resp.status().as_u16();
        let etag = resp.headers().get("etag").and_then(|v| v.to_str().ok()).map(str::to_string);
        let retry_after = retry_after(resp.headers().get("retry-after").and_then(|v| v.to_str().ok()));
        let location = resp.headers().get("location").and_then(|v| v.to_str().ok()).map(str::to_string);
        let body = resp.body_mut().with_config().limit(MAX_BODY).read_to_vec().map_err(|e| body_error(&req.url, e))?;
        Ok((Response { status, body, etag }, retry_after, location))
    }
}

/// A Retry-After header in seconds, capped at 10 s; a date form is ignored.
fn retry_after(header: Option<&str>) -> Option<std::time::Duration> {
    header.and_then(|s| s.trim().parse::<u64>().ok()).map(|s| std::time::Duration::from_secs(s.min(10)))
}

/// A body that couldn't be read: over the cap is `Invalid`, anything else
/// (a dropped connection) `Offline`.
fn body_error(url: &str, e: ureq::Error) -> Error {
    match e {
        ureq::Error::BodyExceedsLimit(_) => Error::Invalid(format!("{url}: response over {MAX_BODY} bytes")),
        e => Error::Offline(format!("{url}: {e}")),
    }
}

type Handler = Box<dyn Fn(&Request) -> Result<Response> + Send + Sync>;

/// A network for tests: answers from a closure and records every request.
pub struct Fake {
    handler: Handler,
    log: Mutex<Vec<Request>>,
}

impl Fake {
    pub fn new(handler: impl Fn(&Request) -> Result<Response> + Send + Sync + 'static) -> Fake {
        Fake { handler: Box::new(handler), log: Mutex::new(Vec::new()) }
    }

    /// A network where every host is unreachable.
    pub fn offline() -> Fake {
        Fake::new(|r| Err(Error::Offline(format!("{}: offline (fake)", r.url))))
    }

    pub fn requests(&self) -> Vec<Request> {
        self.log.lock().expect("fake net log").clone()
    }
}

impl Net for Fake {
    fn send(&self, req: &Request) -> Result<Response> {
        self.log.lock().expect("fake net log").push(req.clone());
        (self.handler)(req)
    }
}

/// A GitHub repository's clone URL.
pub fn github(repo: &str) -> String {
    format!("https://github.com/{repo}.git")
}

#[cfg(test)]
mod tests {
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
        };
        let seen = Mutex::new(Vec::new());
        let send = |r: &Request| {
            allowed(&r.url)?;
            seen.lock().unwrap().push((r.url.clone(), r.header("authorization").is_some()));
            Ok(match r.url.as_str() {
                "https://api.github.com/a" => {
                    (Response { status: 302, body: vec![], etag: None }, Some("/b".to_string()))
                }
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
    fn user_agent_names_the_project() {
        assert_eq!(USER_AGENT, format!("wpantry/{} (+https://github.com/waffuruai/pantry)", crate::VERSION));
    }

    #[test]
    fn every_source_is_on_the_host_list_and_nothing_else_is_asked() {
        use crate::sources::{deps_dev, distros, extensions, kev, osv, releases};
        let sources = [
            kev::KEV_URL,
            distros::ARCH_URL,
            releases::CASKS_URL,
            releases::CHROME_URL,
            releases::FIREFOX,
            releases::POSTGRES_URL,
            extensions::VSCODE_LISTS,
            extensions::MARKETPLACE,
            extensions::OPENVSX,
            releases::GITHUB_LATEST,
            deps_dev::API,
            osv::API,
            "https://haveibeenpwned.com/api/v3/breachedaccount/x",
            "https://api.xposedornot.com/v1/check-email/x",
            crate::checks::malware::FORGE_RELEASE,
            crate::sources::indicator_lists::SIGNATURE_BASE,
            crate::sources::indicator_lists::FEODO,
            crate::sources::hash_lookups::YARAIFY,
            crate::sources::hash_lookups::CIRCL,
            crate::sources::hash_lookups::MALWAREBAZAAR,
            "https://release-assets.githubusercontent.com/github-production-release-asset/x",
            "https://objects.githubusercontent.com/github-production-release-asset-2e65be/x",
        ];
        for url in sources {
            assert!(allowed(url).is_ok(), "{url}");
        }
        assert_eq!(host_of("https://API.OSV.DEV:443/v1/querybatch?x#y").as_deref(), Some("api.osv.dev"));
        assert_eq!(host_of("http://api.osv.dev/v1"), None, "plain http is never used");
        assert_eq!(host_of("https://api.osv.dev@evil.example/"), None, "userinfo can't dress a host up");
        assert_eq!(host_of("https:///path"), None);
        // The real client refuses before any connection is made: no network here.
        let http = Http::new();
        for url in ["https://evil.example/", "https://api.osv.dev.evil.example/v1", "http://api.osv.dev/v1", "ftp://x/"]
        {
            let req = Request { method: "GET", url: url.into(), headers: Vec::new(), body: None };
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
        let big = body_error("https://x/", ureq::Error::BodyExceedsLimit(MAX_BODY));
        assert!(matches!(big, Error::Invalid(m) if m == format!("https://x/: response over {MAX_BODY} bytes")));
        let cut = body_error("https://x/", ureq::Error::Io(std::io::Error::other("reset")));
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
            };
            assert!(matches!(http.send_once(&req), Err(Error::Offline(m)) if m.starts_with("https://127.0.0.1:1/")));
        }
    }
}
