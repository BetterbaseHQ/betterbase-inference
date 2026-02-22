pub mod handlers;
pub mod logging;
pub mod middleware;
pub mod proxy;
pub mod ratelimit;

use std::sync::Arc;

use axum::middleware as axum_middleware;
use axum::routing::{get, post};
use axum::Router;

use crate::auth::Validator;
use crate::backend::Backend;

use self::handlers::AppState;
use self::ratelimit::RateLimiter;

/// Build the axum router with public and protected route split.
pub fn build_router(
    backend: Arc<dyn Backend>,
    validator: Arc<Validator>,
    rate_limiter: Option<Arc<RateLimiter>>,
    http_client: reqwest::Client,
) -> Router {
    let state = Arc::new(AppState {
        backend: backend.clone(),
        http_client,
        rate_limiter,
    });

    let caps = backend.capabilities();

    // Public routes (no auth)
    let mut public_routes = Router::new().route("/health", get(handlers::health));

    if caps.hpke_keys {
        public_routes = public_routes.route("/.well-known/hpke-keys", get(handlers::hpke_keys));
    }

    // Protected routes (with auth middleware)
    let mut protected_routes = Router::new();

    if caps.models {
        protected_routes = protected_routes.route("/v1/models", get(handlers::models));
    }

    if caps.chat_completions {
        protected_routes =
            protected_routes.route("/v1/chat/completions", post(handlers::chat_completions));
    }

    let protected_routes = protected_routes.layer(axum_middleware::from_fn_with_state(
        validator.clone(),
        |state: axum::extract::State<Arc<Validator>>,
         req: axum::extract::Request,
         next: axum_middleware::Next| { middleware::auth_middleware(state.0, req, next) },
    ));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(axum_middleware::from_fn(
            middleware::protocol_version_middleware,
        ))
        .layer(axum_middleware::from_fn(logging::logging_middleware))
        .with_state(state)
}
