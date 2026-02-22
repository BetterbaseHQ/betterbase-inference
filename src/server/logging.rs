use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::{error, info, warn};

/// Logging middleware that skips health checks and logs at appropriate levels.
pub async fn logging_middleware(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();

    // Skip logging for health checks
    if path == "/health" {
        return next.run(req).await;
    }

    let method = req.method().to_string();
    let start = Instant::now();

    let response = next.run(req).await;

    let status = response.status().as_u16();
    let duration_ms = start.elapsed().as_millis();

    match status {
        500.. => error!(method, path, status, duration_ms, "request"),
        400..=499 => warn!(method, path, status, duration_ms, "request"),
        _ => info!(method, path, status, duration_ms, "request"),
    }

    response
}
