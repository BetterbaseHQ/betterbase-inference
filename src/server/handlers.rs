use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use tracing::{error, warn};

use crate::backend::Backend;
use crate::protocol::{ErrorResponse, HealthResponse};
use crate::server::middleware::AuthUser;
use crate::server::proxy::build_upstream_url;

use super::middleware::has_scope;

/// Shared application state.
pub struct AppState {
    pub backend: Arc<dyn Backend>,
    pub http_client: reqwest::Client,
    pub rate_limiter: Option<Arc<super::ratelimit::RateLimiter>>,
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

/// Proxy a request to the configured backend.
async fn proxy_to_backend(state: &AppState, req: axum::extract::Request, path: &str) -> Response {
    let backend = &state.backend;
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

    // Stream the response body
    let stream = resp.bytes_stream().map(|chunk| {
        chunk
            .map(|b| axum::body::Bytes::from(b.to_vec()))
            .map_err(|e| {
                warn!(error = %e, "error reading upstream response");
                std::io::Error::other(e)
            })
    });

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
