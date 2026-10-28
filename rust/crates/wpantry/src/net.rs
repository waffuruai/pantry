//! HTTP behind a trait: one `ureq` + `rustls` implementation, and a fake for
//! tests that answers from a closure and records every request. Every
//! request names us and times out after 30 s; callers decide what an offline
//! machine means for their source. Only the hosts in
//! `specs/design/rust-port.md#network` are ever asked (S5).

use crate::error::{Error, Result};
use crate::json;
use serde_json::Value;
use std::sync::Mutex;
use std::time::Duration;

pub const USER_AGENT: &str = concat!("wpantry/", env!("CARGO_PKG_VERSION"), " (+https://github.com/waffuruai/pantry)");
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// The largest response body read (S7); a bigger one is `Invalid`.
pub const MAX_BODY: u64 = 128 << 20;

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

/// The real network: blocking `ureq` over `rustls`, proxy from the
/// environment (`HTTPS_PROXY`, `ALL_PROXY`).
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
        let config = ureq::Agent::config_builder().timeout_global(Some(TIMEOUT)).http_status_as_error(false).build();
        Http { agent: config.into() }
    }
}

impl Net for Http {
    fn send(&self, req: &Request) -> Result<Response> {
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
        let body = resp.body_mut().with_config().limit(MAX_BODY).read_to_vec().map_err(|e| match e {
            ureq::Error::BodyExceedsLimit(_) => Error::Invalid(format!("{}: response over {MAX_BODY} bytes", req.url)),
            e => offline(e),
        })?;
        Ok(Response { status, body, etag })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_names_the_project() {
        assert_eq!(USER_AGENT, format!("wpantry/{} (+https://github.com/waffuruai/pantry)", crate::VERSION));
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
}
