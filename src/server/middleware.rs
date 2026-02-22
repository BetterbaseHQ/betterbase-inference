use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth::{TokenInfo, Validator};
use crate::protocol::ErrorResponse;

/// Token info stored in request extensions.
#[derive(Debug, Clone)]
pub struct AuthUser(pub TokenInfo);

/// Auth middleware: extracts Bearer token, validates JWT, injects `AuthUser` into extensions.
pub async fn auth_middleware(
    validator: Arc<Validator>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let auth_header = req.headers().get("authorization");

    let token = match auth_header.and_then(|v| v.to_str().ok()) {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        Some(_) => {
            return auth_error("invalid authorization header format");
        }
        None => {
            return auth_error("missing authorization");
        }
    };

    match validator.validate_token(token).await {
        Ok(info) => {
            req.extensions_mut().insert(AuthUser(info));
            next.run(req).await
        }
        Err(crate::auth::AuthError::MissingToken) => auth_error("missing authorization token"),
        Err(crate::auth::AuthError::ExpiredToken) => auth_error("token has expired"),
        Err(crate::auth::AuthError::InvalidIssuer) => auth_error("invalid token issuer"),
        Err(_) => auth_error("invalid token"),
    }
}

/// X-Protocol-Version response header middleware.
pub async fn protocol_version_middleware(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert("X-Protocol-Version", "1".parse().unwrap());
    response
}

fn auth_error(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
        .into_response()
}

/// Check if a scope string contains the given capability.
pub fn has_scope(scope: &str, capability: &str) -> bool {
    scope.split_whitespace().any(|s| s == capability)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_scope() {
        assert!(has_scope("inference openai", "inference"));
        assert!(has_scope("inference   profile", "inference"));
        assert!(!has_scope("profile", "inference"));
        assert!(!has_scope("", "inference"));
    }
}
