use std::sync::Arc;

use axum::routing::get;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use serde::Serialize;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

/// Dev mode helper: ephemeral key, local JWKS server, test token generation.
pub struct DevMode {
    encoding_key: EncodingKey,
    jwks_json: Value,
    key_id: String,
}

#[derive(Serialize)]
struct DevClaims {
    sub: String,
    client_id: String,
    scope: String,
    iss: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
}

impl DevMode {
    /// Create a new dev mode with an ephemeral P-256 key.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let public = secret.public_key();
        let point = public.to_encoded_point(false);

        let der = secret.to_pkcs8_der()?;
        let encoding_key = EncodingKey::from_ec_der(der.as_bytes());

        let key_id = "test-key".to_string();

        let jwks_json = json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                "kid": key_id,
                "alg": "ES256",
                "use": "sig",
            }]
        });

        Ok(Self {
            encoding_key,
            jwks_json,
            key_id,
        })
    }

    /// Generate a test JWT.
    pub fn generate_token(
        &self,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = DevClaims {
            sub: user_id.into(),
            client_id: client_id.into(),
            scope: scope.into(),
            iss: "less-accounts".into(),
            aud: vec!["betterbase-inference".into()],
            exp: now + 86400,
            iat: now,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        encode(&header, &claims, &self.encoding_key)
    }

    /// Start a local JWKS server on a random port. Returns the JWKS URL.
    pub async fn start_jwks_server(self: Arc<Self>) -> Result<String, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let jwks_url = format!("http://{}/.well-known/jwks.json", addr);

        let dev_mode = self.clone();
        let app = axum::Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let json = dev_mode.jwks_json.clone();
                async move { Json(json) }
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        Ok(jwks_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Validator, ValidatorConfig};
    use std::time::Duration;

    #[tokio::test]
    async fn test_devmode_roundtrip() {
        let dev = Arc::new(DevMode::new().unwrap());

        let jwks_url = dev.clone().start_jwks_server().await.unwrap();

        let token = dev
            .generate_token("test-user", "test-client", "inference")
            .unwrap();

        let validator = Validator::new(ValidatorConfig {
            jwks_url,
            issuer: "less-accounts".into(),
            audiences: vec!["betterbase-inference".into()],
            refresh_ttl: Some(Duration::from_secs(3600)),
        });

        let info = validator.validate_token(&token).await.unwrap();
        assert_eq!(info.user_id, "test-user");
        assert_eq!(info.client_id, "test-client");
        assert_eq!(info.scope, "inference");
        assert_eq!(info.issuer, "less-accounts");
    }
}
