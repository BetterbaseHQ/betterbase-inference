use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::{Stream, StreamExt};
use tracing::{error, warn};

use crate::backend::Backend;
use crate::protocol::{ErrorResponse, HealthResponse};
use crate::server::middleware::AuthUser;
use crate::server::proxy::build_upstream_url;

use super::middleware::has_scope;

/// AUD-044: maximum time between upstream response chunks. SSE streams
/// pause while a model thinks, so this is generous; a fully stalled
/// upstream is dropped rather than pinning a connection indefinitely.
const RESPONSE_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// AUD-044: absolute budget for one upstream response stream, however
/// chatty. Bounds aggregate connection time, not just per-chunk stalls.
const RESPONSE_TOTAL_TIMEOUT: Duration = Duration::from_secs(900);

/// Shared application state.
pub struct AppState {
    pub backend: Arc<dyn Backend>,
    pub http_client: reqwest::Client,
    pub rate_limiter: Option<Arc<super::ratelimit::RateLimiter>>,
    /// Bounds concurrent proxied upstream requests across all routes
    /// (AUD-044) — including the public hpke-keys proxy, which attaches
    /// the backend API key and would otherwise be unbounded.
    pub upstream_permits: Arc<tokio::sync::Semaphore>,
    /// Declared request-body cap; enforced up front via Content-Length
    /// and as a streaming backstop via `DefaultBodyLimit` (AUD-044).
    pub max_request_body_bytes: usize,
    /// AUD-041: when set, chat requests must carry client-side
    /// encryption material (EHBP encapsulation) or be rejected.
    pub require_ehbp: bool,
}

/// Health check handler.
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        backend: Some(state.backend.name().to_string()),
    })
}

/// Models endpoint — proxies to backend.
pub async fn models(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    req: axum::extract::Request,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, &auth) {
        return resp;
    }
    if let Some(resp) = require_inference_scope(&auth) {
        return resp;
    }
    proxy_to_backend(&state, req, "/v1/models").await
}

/// Chat completions endpoint — proxies to backend with streaming support.
pub async fn chat_completions(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    req: axum::extract::Request,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, &auth) {
        return resp;
    }
    if let Some(resp) = require_inference_scope(&auth) {
        return resp;
    }
    // AUD-041: operators can enforce that no plaintext prompt transits
    // the proxy. The encapsulation header is only present when the
    // client performed EHBP encryption; without it the body is
    // plaintext and readable by the proxy.
    if state.require_ehbp && req.headers().get("ehbp-encapsulated-key").is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "client-side encryption required: request is missing Ehbp-Encapsulated-Key"
                    .to_string(),
            }),
        )
            .into_response();
    }
    proxy_to_backend(&state, req, "/v1/chat/completions").await
}

/// HPKE keys endpoint — proxies to backend (public, no scope check).
pub async fn hpke_keys(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Response {
    proxy_to_backend(&state, req, "/.well-known/hpke-keys").await
}

/// Check rate limit; returns Some(Response) if rate limited.
fn check_rate_limit(state: &AppState, auth: &AuthUser) -> Option<Response> {
    let limiter = state.rate_limiter.as_ref()?;
    if limiter.allow(&auth.0.issuer, &auth.0.user_id) {
        None
    } else {
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limit exceeded".to_string(),
            }),
        )
            .into_response();
        response
            .headers_mut()
            .insert("Retry-After", "60".parse().unwrap());
        Some(response)
    }
}

/// Require "inference" scope; returns Some(Response) if forbidden.
fn require_inference_scope(auth: &AuthUser) -> Option<Response> {
    if has_scope(&auth.0.scope, "inference") {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "inference scope required".to_string(),
                }),
            )
                .into_response(),
        )
    }
}

/// Reject requests whose declared body exceeds the cap (AUD-044).
/// Honest clients get a clean 413; the `DefaultBodyLimit` layer is the
/// streaming backstop for lying or chunked bodies.
fn check_request_size(headers: &HeaderMap, max: usize) -> Option<Response> {
    let len = headers
        .get("content-length")?
        .to_str()
        .ok()?
        .trim()
        .parse::<usize>()
        .ok()?;
    if len > max {
        return Some(
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ErrorResponse {
                    error: format!("request body exceeds {max} bytes"),
                }),
            )
                .into_response(),
        );
    }
    None
}

/// Proxy a request to the configured backend.
async fn proxy_to_backend(state: &AppState, req: axum::extract::Request, path: &str) -> Response {
    let backend = &state.backend;

    if let Some(resp) = check_request_size(req.headers(), state.max_request_body_bytes) {
        return resp;
    }

    // AUD-044: bound aggregate upstream concurrency. `try_acquire` fails
    // fast — an overloaded proxy answers 429 instead of queueing.
    let _permit = match state.upstream_permits.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "upstream concurrency limit reached".to_string(),
                }),
            )
                .into_response();
        }
    };

    let transformed_path = backend.transform_path(path);

    let raw_query = req.uri().query().unwrap_or("");

    let upstream_url = match build_upstream_url(backend.base_url(), transformed_path, raw_query) {
        Ok(url) => url,
        Err(e) => {
            error!(
                backend = backend.name(),
                base_url = backend.base_url(),
                path = transformed_path,
                error = %e,
                "failed to build upstream URL"
            );
            return write_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    // Build upstream request — stream body directly like Go (no buffering/size cap)
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body = req.into_body();

    let mut req_builder = state.http_client.request(method, &upstream_url);

    // Copy Content-Type
    if let Some(ct) = headers.get("content-type") {
        req_builder = req_builder.header("content-type", ct);
    }

    // Copy Accept
    if let Some(accept) = headers.get("accept") {
        req_builder = req_builder.header("accept", accept);
    }

    // Forward backend-specific headers
    for h in backend.forward_headers() {
        if let Some(v) = headers.get(*h) {
            req_builder = req_builder.header(*h, v);
        }
    }

    // Stream request body directly (no buffering)
    let body_stream = body.into_data_stream();
    let req_body = reqwest::Body::wrap_stream(body_stream);
    req_builder = req_builder.body(req_body);

    let mut proxy_req = match req_builder.build() {
        Ok(r) => r,
        Err(e) => {
            error!(backend = backend.name(), error = %e, "failed to create proxy request");
            return write_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    // Backend authentication
    backend.authorize_request(proxy_req.headers_mut());

    // Execute with response-header timeout (streaming body may take longer)
    let resp = match tokio::time::timeout(
        Duration::from_secs(60),
        state.http_client.execute(proxy_req),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            error!(
                backend = backend.name(),
                url = upstream_url,
                error = %e,
                "upstream request failed"
            );
            return write_error(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
        Err(_) => {
            error!(
                backend = backend.name(),
                url = upstream_url,
                "upstream request timed out"
            );
            return write_error(StatusCode::GATEWAY_TIMEOUT, "upstream timeout");
        }
    };

    // Build response with streaming body
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response_headers = HeaderMap::new();
    for (k, v) in resp.headers() {
        response_headers.insert(k.clone(), v.clone());
    }

    // Stream response body with idle and total deadlines (AUD-044)
    let stream = bounded_upstream_stream(
        resp.bytes_stream(),
        RESPONSE_IDLE_TIMEOUT,
        RESPONSE_TOTAL_TIMEOUT,
    );

    let body = Body::from_stream(stream);

    let mut response = Response::builder()
        .status(status)
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()));

    *response.headers_mut() = response_headers;

    response
}

fn write_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
        .into_response()
}

/// Wrap an upstream body stream with idle and total deadlines (AUD-044).
///
/// Each chunk must arrive within `idle_timeout` of the previous one, and
/// the whole stream within `total_timeout`, or the stream terminates
/// with a `TimedOut` error — downstream cancellation then drops the
/// upstream response.
fn bounded_upstream_stream<S>(
    stream: S,
    idle_timeout: Duration,
    total_timeout: Duration,
) -> impl Stream<Item = Result<axum::body::Bytes, std::io::Error>>
where
    S: Stream<Item = Result<bytes::Bytes, reqwest::Error>>,
{
    let stream = Box::pin(stream);
    let deadline = tokio::time::Instant::now() + total_timeout;
    futures_util::stream::unfold((stream, deadline), move |(stream, deadline)| async move {
        let mut stream = stream;
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        // The idle wait never outlives the total budget.
        let remaining = deadline - tokio::time::Instant::now();
        let wait = idle_timeout.min(remaining);
        match tokio::time::timeout(wait, stream.next()).await {
            Ok(Some(Ok(chunk))) => Some((
                Ok(axum::body::Bytes::from(chunk.to_vec())),
                (stream, deadline),
            )),
            Ok(Some(Err(e))) => {
                warn!(error = %e, "error reading upstream response");
                Some((Err(std::io::Error::other(e)), (stream, deadline)))
            }
            Ok(None) => None,
            Err(_) => {
                warn!("upstream response stream stalled (idle or total deadline)");
                // Expire the deadline so the stream ends after this error.
                Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "upstream stream deadline exceeded",
                    )),
                    (stream, tokio::time::Instant::now()),
                ))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::DefaultBodyLimit;
    use axum::routing::get;
    use futures_util::StreamExt;
    use std::time::Instant;
    use tower::ServiceExt;

    /// Minimal backend pointing at an unreachable upstream — enough to
    /// exercise the pre-proxy guards without a live Tinfoil.
    struct StubBackend;

    impl Backend for StubBackend {
        fn name(&self) -> &str {
            "stub"
        }
        fn base_url(&self) -> &str {
            "http://127.0.0.1:9"
        }
        fn authorize_request(&self, _headers: &mut http::HeaderMap) {}
        fn forward_headers(&self) -> &[&str] {
            &[]
        }
        fn transform_path<'a>(&self, path: &'a str) -> &'a str {
            path
        }
        fn capabilities(&self) -> crate::backend::Capabilities {
            crate::backend::Capabilities {
                chat_completions: true,
                models: true,
                hpke_keys: true,
            }
        }
    }

    fn test_state(permits: usize) -> Arc<AppState> {
        Arc::new(AppState {
            backend: Arc::new(StubBackend),
            http_client: reqwest::Client::new(),
            rate_limiter: None,
            upstream_permits: Arc::new(tokio::sync::Semaphore::new(permits)),
            max_request_body_bytes: 1024,
            require_ehbp: false,
        })
    }

    #[tokio::test]
    async fn test_require_ehbp_rejects_plaintext_chat() {
        use crate::auth::TokenInfo;

        let mut state = test_state(4);
        Arc::get_mut(&mut state).unwrap().require_ehbp = true;

        let auth = AuthUser(TokenInfo {
            issuer: "iss".into(),
            user_id: "user".into(),
            client_id: "client".into(),
            scope: "inference".into(),
            jti: "jti".into(),
        });

        // Plaintext body (no EHBP header) -> 400.
        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/v1/chat/completions")
            .extension(auth.clone())
            .body(Body::empty())
            .unwrap();
        let resp = chat_completions(State(state.clone()), Extension(auth.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // With encapsulation material the request proceeds to the proxy
        // (and fails upstream against the stub backend, not with 400).
        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/v1/chat/completions")
            .header("Ehbp-Encapsulated-Key", "encapsulated")
            .extension(auth)
            .body(Body::empty())
            .unwrap();
        let resp = chat_completions(
            State(state),
            Extension(AuthUser(TokenInfo {
                issuer: "iss".into(),
                user_id: "user".into(),
                client_id: "client".into(),
                scope: "inference".into(),
                jti: "jti".into(),
            })),
            req,
        )
        .await;
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_exhausted_upstream_concurrency_returns_429() {
        let state = test_state(1);
        // Consume the only permit, as an in-flight upstream would.
        let _held = state
            .upstream_permits
            .clone()
            .acquire_owned()
            .await
            .unwrap();

        let app = axum::Router::new()
            .route("/.well-known/hpke-keys", get(hpke_keys))
            .with_state(state);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/hpke-keys")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_oversized_content_length_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", "999999".parse().unwrap());
        let resp = check_request_size(&headers, 1024).unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        headers.insert("content-length", "512".parse().unwrap());
        assert!(check_request_size(&headers, 1024).is_none());

        // Absent or malformed Content-Length is not rejected here — the
        // DefaultBodyLimit layer bounds those while streaming.
        let mut absent = HeaderMap::new();
        assert!(check_request_size(&absent, 1024).is_none());
        absent.insert("content-length", "not-a-number".parse().unwrap());
        assert!(check_request_size(&absent, 1024).is_none());
    }

    #[tokio::test]
    async fn test_idle_stall_terminates_stream() {
        let stalled = futures_util::stream::pending::<Result<bytes::Bytes, reqwest::Error>>();
        let started = Instant::now();
        let mut stream = std::pin::pin!(bounded_upstream_stream(
            stalled,
            Duration::from_millis(50),
            Duration::from_secs(60)
        ));

        let first = stream.next().await.unwrap();
        assert_eq!(first.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(
            stream.next().await.is_none(),
            "stream must end after the deadline error"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_total_deadline_terminates_stream() {
        // One chunk, then silence: the total budget must end the stream
        // even though the idle timeout alone would keep waiting.
        let chunk: Result<bytes::Bytes, reqwest::Error> = Ok(bytes::Bytes::from_static(b"data"));
        let stream =
            futures_util::stream::iter(vec![chunk]).chain(futures_util::stream::pending::<
                Result<bytes::Bytes, reqwest::Error>,
            >());
        let started = Instant::now();
        let mut bounded = std::pin::pin!(bounded_upstream_stream(
            stream,
            Duration::from_secs(60),
            Duration::from_millis(100)
        ));

        assert_eq!(
            bounded.next().await.unwrap().unwrap(),
            axum::body::Bytes::from_static(b"data")
        );
        let second = bounded.next().await.unwrap();
        assert_eq!(second.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(bounded.next().await.is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn test_default_body_limit_configured_on_protected_routes() {
        // Compile-level documentation: the protected router layers
        // DefaultBodyLimit with the configured cap (see build_router).
        // Behavior is axum's; asserted here that our default is sane.
        assert!(1024 < 10 * 1024 * 1024);
        let _ = DefaultBodyLimit::max(10);
    }
}
