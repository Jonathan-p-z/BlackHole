//! The `HttpHandler` implementation hudsucker calls for every intercepted
//! request/response. This file is the complete list of everything this
//! module does with your decrypted traffic: check the destination
//! domain against the tracker list, and if it matches, replace cookie
//! *values* (nothing else) via `cookie_store::CookieStore`. Every other
//! domain, and every other part of a tracker domain's own traffic, is
//! untouched. See `THREAT_MODEL.md`'s "How the randomization works" and
//! "For everything else: pass through unchanged".

use std::sync::Arc;

use cookie::Cookie;
use hudsucker::hyper::header::{COOKIE, HOST, SET_COOKIE};
use hudsucker::hyper::{Request, Response};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::cookie_store::CookieStore;
use crate::tracker_list::TrackerList;

/// Cloned by hudsucker once per intercepted connection (see
/// `HttpHandler`'s own `Clone` bound). `tracker_list`/`cookie_store` are
/// `Arc`-shared across every clone (the tracker list and the
/// randomization table are process-wide state); `current_request_host`
/// is deliberately per-clone, per-connection state: hudsucker calls
/// `handle_request` then `handle_response` on the *same* handler
/// instance for a given exchange, so stashing the request's host here
/// and reading it back in `handle_response` (which otherwise has no way
/// to know which domain a response came from; see `HttpContext`'s own,
/// much narrower, fields) is safe and is the only reason this struct
/// needs a mutable field at all.
#[derive(Clone)]
pub struct CookieRandomizingHandler {
    tracker_list: Arc<TrackerList>,
    cookie_store: Arc<CookieStore>,
    current_request_host: Option<String>,
}

impl CookieRandomizingHandler {
    pub fn new(tracker_list: Arc<TrackerList>, cookie_store: Arc<CookieStore>) -> Self {
        Self {
            tracker_list,
            cookie_store,
            current_request_host: None,
        }
    }
}

impl HttpHandler for CookieRandomizingHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        let host = request_host(&req);
        self.current_request_host = host.clone();

        if let Some(host) = host.filter(|h| self.tracker_list.matches(h)) {
            rewrite_outgoing_cookie_header(&mut req, &host, &self.cookie_store);
        }

        req.into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        mut res: Response<Body>,
    ) -> Response<Body> {
        if let Some(host) = self
            .current_request_host
            .take()
            .filter(|h| self.tracker_list.matches(h))
        {
            rewrite_incoming_set_cookie_headers(&mut res, &host, &self.cookie_store);
        }
        res
    }
}

/// The destination host for `req`: the `Host` header if present (this is
/// what a request looks like once hudsucker has already terminated TLS
/// for it, since the request line itself then carries only a relative
/// path), falling back to the request URI's own authority (an absolute-
/// form URI, `http://host/path`, is what a plain, non-MITM'd proxied HTTP
/// request looks like). Either way, no port, no scheme; just the host.
fn request_host(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(str::to_string))
}

fn rewrite_outgoing_cookie_header(req: &mut Request<Body>, host: &str, store: &CookieStore) {
    let Some(header_value) = req.headers().get(COOKIE).and_then(|h| h.to_str().ok()) else {
        return;
    };

    let rewritten = Cookie::split_parse(header_value.to_string())
        .filter_map(Result::ok)
        .map(|cookie| {
            let randomized = store.randomized_value(host, cookie.name());
            format!("{}={}", cookie.name(), randomized)
        })
        .collect::<Vec<_>>()
        .join("; ");

    if let Ok(value) = rewritten.parse() {
        req.headers_mut().insert(COOKIE, value);
    }
}

fn rewrite_incoming_set_cookie_headers(res: &mut Response<Body>, host: &str, store: &CookieStore) {
    let originals: Vec<_> = res.headers().get_all(SET_COOKIE).iter().cloned().collect();
    if originals.is_empty() {
        return;
    }

    res.headers_mut().remove(SET_COOKIE);

    for original in originals {
        let Ok(text) = original.to_str() else {
            // Not valid UTF-8: pass through unmodified rather than drop
            // it, since we can't safely parse or rewrite it either way.
            res.headers_mut().append(SET_COOKIE, original);
            continue;
        };

        match Cookie::parse(text.to_string()) {
            Ok(mut cookie) => {
                let randomized = store.randomized_value(host, cookie.name());
                cookie.set_value(randomized);
                if let Ok(value) = cookie.to_string().parse() {
                    res.headers_mut().append(SET_COOKIE, value);
                } else {
                    res.headers_mut().append(SET_COOKIE, original);
                }
            }
            Err(_) => {
                // Unparseable Set-Cookie value: pass through unmodified
                // rather than silently drop the header (dropping it could
                // break a site relying on a cookie this parser doesn't
                // understand; leaving it as-is at worst means this one
                // cookie isn't randomized, never that it's lost).
                res.headers_mut().append(SET_COOKIE, original);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hudsucker::hyper::{Method, StatusCode, Uri};

    // `HttpContext` is `#[non_exhaustive]` with no public constructor
    // outside hudsucker's own connection handling, so these tests call
    // the module functions directly (the same functions `HttpHandler`'s
    // trait methods call) rather than the trait methods themselves; see
    // `tests/proxy_integration.rs` for a real end-to-end test that does
    // go through the actual `HttpHandler` trait methods via a live
    // connection.

    fn request_with_cookie(host: &str, cookie_header: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(Uri::from_static("/"))
            .header(HOST, host)
            .header(COOKIE, cookie_header)
            .body(Body::empty())
            .unwrap()
    }

    fn response_with_set_cookie(set_cookie: &str) -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(SET_COOKIE, set_cookie)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn request_host_prefers_the_host_header() {
        let req = request_with_cookie("faketracker.test", "a=1");
        assert_eq!(request_host(&req), Some("faketracker.test".to_string()));
    }

    #[test]
    fn request_host_strips_a_port_from_the_host_header() {
        let req = Request::builder()
            .uri(Uri::from_static("/"))
            .header(HOST, "faketracker.test:8443")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_host(&req), Some("faketracker.test".to_string()));
    }

    #[test]
    fn rewrite_outgoing_cookie_replaces_every_value_consistently() {
        let store = CookieStore::new();
        let mut req =
            request_with_cookie("faketracker.test", "trackid=REALVALUE; other=REALVALUE2");
        rewrite_outgoing_cookie_header(&mut req, "faketracker.test", &store);

        let rewritten = req
            .headers()
            .get(COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(!rewritten.contains("REALVALUE"));

        // Same store, same host, same cookie name: the value already
        // recorded above must come back unchanged on a second rewrite,
        // this is the actual "consistent within a session" property.
        let mut req2 =
            request_with_cookie("faketracker.test", "trackid=REALVALUE; other=REALVALUE2");
        rewrite_outgoing_cookie_header(&mut req2, "faketracker.test", &store);
        assert_eq!(
            req.headers().get(COOKIE).unwrap(),
            req2.headers().get(COOKIE).unwrap(),
        );
    }

    #[test]
    fn rewrite_incoming_set_cookie_replaces_value_but_keeps_attributes() {
        let store = CookieStore::new();
        let mut res =
            response_with_set_cookie("trackid=REALVALUE; Path=/; Secure; HttpOnly; SameSite=None");
        rewrite_incoming_set_cookie_headers(&mut res, "faketracker.test", &store);

        let rewritten = res
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(!rewritten.contains("REALVALUE"));
        assert!(rewritten.starts_with("trackid="));
        assert!(rewritten.contains("Path=/"));
        assert!(rewritten.contains("Secure"));
        assert!(rewritten.contains("HttpOnly"));
        assert!(rewritten.contains("SameSite=None"));
    }

    #[test]
    fn set_cookie_and_cookie_rewrites_share_the_same_randomized_value() {
        // The property that actually matters end to end: whether a given
        // (domain, cookie name) pair is first seen via an incoming
        // Set-Cookie or an outgoing Cookie header, both directions must
        // agree on the same randomized value for the rest of the
        // session, so the browser and the (fooled) tracker stay in sync.
        let store = CookieStore::new();

        let mut res = response_with_set_cookie("trackid=REALVALUE; Path=/");
        rewrite_incoming_set_cookie_headers(&mut res, "faketracker.test", &store);
        let set_cookie = res.headers().get(SET_COOKIE).unwrap().to_str().unwrap();
        let randomized_from_response = Cookie::parse(set_cookie.to_string())
            .unwrap()
            .value()
            .to_string();

        let mut req = request_with_cookie("faketracker.test", "trackid=REALVALUE");
        rewrite_outgoing_cookie_header(&mut req, "faketracker.test", &store);
        let cookie_header = req.headers().get(COOKIE).unwrap().to_str().unwrap();
        assert_eq!(cookie_header, format!("trackid={randomized_from_response}"));
    }

    #[test]
    fn multiple_set_cookie_headers_are_each_rewritten_independently() {
        let store = CookieStore::new();
        let mut res = Response::builder()
            .status(StatusCode::OK)
            .header(SET_COOKIE, "a=REAL1; Path=/")
            .header(SET_COOKIE, "b=REAL2; Path=/")
            .body(Body::empty())
            .unwrap();

        rewrite_incoming_set_cookie_headers(&mut res, "faketracker.test", &store);

        let values: Vec<String> = res
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(values.len(), 2);
        assert!(
            values
                .iter()
                .all(|v| !v.contains("REAL1") && !v.contains("REAL2"))
        );
    }

    #[test]
    fn no_cookie_header_is_a_harmless_no_op() {
        let store = CookieStore::new();
        let mut req = Request::builder()
            .uri(Uri::from_static("/"))
            .header(HOST, "faketracker.test")
            .body(Body::empty())
            .unwrap();
        rewrite_outgoing_cookie_header(&mut req, "faketracker.test", &store);
        assert!(req.headers().get(COOKIE).is_none());
    }

    #[test]
    fn no_set_cookie_header_is_a_harmless_no_op() {
        let store = CookieStore::new();
        let mut res = Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
        rewrite_incoming_set_cookie_headers(&mut res, "faketracker.test", &store);
        assert!(res.headers().get(SET_COOKIE).is_none());
    }
}
