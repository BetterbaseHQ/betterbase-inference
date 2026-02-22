use thiserror::Error;

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing authorization token")]
    MissingToken,

    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("token has expired")]
    ExpiredToken,

    #[error("invalid token issuer")]
    InvalidIssuer,

    #[error("failed to fetch JWKS: {0}")]
    JwksFetchError(String),

    #[error("key {0} not found in JWKS")]
    KeyNotFound(String),
}
