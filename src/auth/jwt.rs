use std::time::Duration;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tracing::warn;

use super::{AuthError, JwksClient};

/// JWT claims.
#[derive(Debug, Deserialize)]
struct Claims {
    sub: Option<String>,
    iss: Option<String>,
    aud: Option<Vec<String>>,
    scope: Option<String>,
    client_id: Option<String>,
    jti: Option<String>,
}

/// Validated token information.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TokenInfo {
    pub issuer: String,
    pub user_id: String,
    pub client_id: String,
    pub scope: String,
    pub jti: String,
}

/// JWT validator configuration.
pub struct ValidatorConfig {
    pub jwks_url: String,
    pub issuer: String,
    pub audiences: Vec<String>,
    pub refresh_ttl: Option<Duration>,
}

/// JWT validator using JWKS.
pub struct Validator {
    jwks: JwksClient,
    issuer: String,
    audiences: Vec<String>,
}

impl Validator {
    /// Create a new JWT validator.
    pub fn new(config: ValidatorConfig) -> Self {
        // Warn if JWKS URL is not HTTPS
        if !config.jwks_url.starts_with("https://")
            && !config.jwks_url.starts_with("http://localhost")
            && !config.jwks_url.starts_with("http://127.0.0.1")
        {
            warn!(url = %config.jwks_url, "JWKS URL is not HTTPS - this is insecure in production");
        }

        let refresh_ttl = config.refresh_ttl.unwrap_or(Duration::from_secs(3600));

        Self {
            jwks: JwksClient::new(config.jwks_url, refresh_ttl),
            issuer: config.issuer,
            audiences: config.audiences,
        }
    }

    /// Create a validator with an existing JWKS client (for testing).
    #[cfg(test)]
    pub fn with_jwks(jwks: JwksClient, issuer: String, audiences: Vec<String>) -> Self {
        Self {
            jwks,
            issuer,
            audiences,
        }
    }

    /// Validate a JWT and return token info.
    pub async fn validate_token(&self, token: &str) -> Result<TokenInfo, AuthError> {
        if token.is_empty() {
            return Err(AuthError::MissingToken);
        }

        // Decode header to get kid and verify algorithm
        let header = decode_header(token)
            .map_err(|e| AuthError::InvalidToken(format!("failed to decode header: {e}")))?;

        if header.alg != Algorithm::ES256 {
            return Err(AuthError::InvalidToken(format!(
                "unexpected signing method: {:?}",
                header.alg
            )));
        }

        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidToken("token missing kid header".into()))?;

        // Get key from JWKS
        let (x_bytes, y_bytes) = self.jwks.get_key_bytes(&kid).await?;

        // Build DecodingKey from EC coordinates
        // jsonwebtoken expects the SEC1 uncompressed point format
        let mut ec_point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
        ec_point.push(0x04); // uncompressed point prefix
        ec_point.extend_from_slice(&x_bytes);
        ec_point.extend_from_slice(&y_bytes);

        // jsonwebtoken's from_ec_der accepts SEC1 uncompressed points (0x04 || x || y)
        // for P-256 keys, despite the function name suggesting DER format.
        let decoding_key = DecodingKey::from_ec_der(&ec_point);

        // Configure validation — we validate issuer and audience manually for better error messages
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_aud = false;
        validation.set_required_spec_claims::<&str>(&["exp"]);

        // Decode and validate
        let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
            if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                AuthError::ExpiredToken
            } else {
                AuthError::InvalidToken(e.to_string())
            }
        })?;

        let claims = token_data.claims;

        // Validate issuer
        if !self.issuer.is_empty() && claims.iss.as_deref() != Some(&self.issuer) {
            return Err(AuthError::InvalidIssuer);
        }

        // Validate audience if configured
        if !self.audiences.is_empty() {
            let token_auds = claims.aud.as_deref().unwrap_or(&[]);
            let found = self.audiences.iter().any(|a| token_auds.contains(a));
            if !found {
                return Err(AuthError::InvalidToken("invalid audience".into()));
            }
        }

        // Extract subject
        let user_id = claims
            .sub
            .ok_or_else(|| AuthError::InvalidToken("missing subject claim".into()))?;

        // Extract client_id
        let client_id = claims
            .client_id
            .ok_or_else(|| AuthError::InvalidToken("missing client_id claim".into()))?;

        Ok(TokenInfo {
            issuer: claims.iss.unwrap_or_default(),
            user_id,
            client_id,
            scope: claims.scope.unwrap_or_default(),
            jti: claims.jti.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;
    use serde::Serialize;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: Vec<String>,
        scope: String,
        client_id: String,
        jti: String,
        exp: u64,
        iat: u64,
    }

    fn make_test_key() -> (p256::SecretKey, EncodingKey) {
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let der = secret.to_pkcs8_der().unwrap();
        let encoding_key = EncodingKey::from_ec_der(der.as_bytes());
        (secret, encoding_key)
    }

    async fn make_test_validator(secret: &p256::SecretKey, kid: &str) -> Validator {
        let public = secret.public_key();
        let point = public.to_encoded_point(false);

        let jwks = JwksClient::new("http://unused".into(), Duration::from_secs(3600));
        jwks.insert_key(
            kid.to_string(),
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        )
        .await;

        Validator::with_jwks(jwks, "less-accounts".into(), vec!["less-inference".into()])
    }

    fn build_token(encoding_key: &EncodingKey, kid: &str, claims: TestClaims) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        encode(&header, &claims, encoding_key).unwrap()
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn test_valid_token() {
        let (secret, encoding_key) = make_test_key();
        let validator = make_test_validator(&secret, "test-key").await;

        let token = build_token(
            &encoding_key,
            "test-key",
            TestClaims {
                sub: "user-123".into(),
                iss: "less-accounts".into(),
                aud: vec!["less-inference".into()],
                scope: "inference profile".into(),
                client_id: "client-abc".into(),
                jti: "token-id".into(),
                exp: now_secs() + 86400,
                iat: now_secs(),
            },
        );

        let info = validator.validate_token(&token).await.unwrap();
        assert_eq!(info.user_id, "user-123");
        assert_eq!(info.client_id, "client-abc");
        assert_eq!(info.scope, "inference profile");
    }

    #[tokio::test]
    async fn test_expired_token() {
        let (secret, encoding_key) = make_test_key();
        let validator = make_test_validator(&secret, "test-key").await;

        let token = build_token(
            &encoding_key,
            "test-key",
            TestClaims {
                sub: "user-123".into(),
                iss: "less-accounts".into(),
                aud: vec!["less-inference".into()],
                scope: "inference".into(),
                client_id: "client-abc".into(),
                jti: "token-id".into(),
                exp: now_secs() - 120,
                iat: now_secs() - 240,
            },
        );

        let err = validator.validate_token(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::ExpiredToken));
    }

    #[tokio::test]
    async fn test_invalid_audience() {
        let (secret, encoding_key) = make_test_key();
        let validator = make_test_validator(&secret, "test-key").await;

        let token = build_token(
            &encoding_key,
            "test-key",
            TestClaims {
                sub: "user-123".into(),
                iss: "less-accounts".into(),
                aud: vec!["other-audience".into()],
                scope: "inference".into(),
                client_id: "client-abc".into(),
                jti: "token-id".into(),
                exp: now_secs() + 86400,
                iat: now_secs(),
            },
        );

        let err = validator.validate_token(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn test_invalid_issuer() {
        let (secret, encoding_key) = make_test_key();
        let validator = make_test_validator(&secret, "test-key").await;

        let token = build_token(
            &encoding_key,
            "test-key",
            TestClaims {
                sub: "user-123".into(),
                iss: "other-issuer".into(),
                aud: vec!["less-inference".into()],
                scope: "inference".into(),
                client_id: "client-abc".into(),
                jti: "token-id".into(),
                exp: now_secs() + 86400,
                iat: now_secs(),
            },
        );

        let err = validator.validate_token(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidIssuer));
    }

    #[tokio::test]
    async fn test_wrong_algorithm_hs256() {
        let (secret, _) = make_test_key();
        let validator = make_test_validator(&secret, "test-key").await;

        // Sign with HS256 instead of ES256
        let shared_secret = b"test-secret-key-for-hmac-256-sig";
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".to_string());

        let claims = TestClaims {
            sub: "user-123".into(),
            iss: "less-accounts".into(),
            aud: vec!["less-inference".into()],
            scope: "inference".into(),
            client_id: "client-abc".into(),
            jti: "token-id".into(),
            exp: now_secs() + 86400,
            iat: now_secs(),
        };

        let token = encode(&header, &claims, &EncodingKey::from_secret(shared_secret)).unwrap();

        let err = validator.validate_token(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }
}
