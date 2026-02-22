use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::PublicKey;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use super::AuthError;

/// Maximum allowed JWKS response size (1MB).
const MAX_JWKS_SIZE: usize = 1 << 20;

/// Raw JWK coordinate bytes for a P-256 key.
/// We store raw bytes instead of `DecodingKey` because `DecodingKey` doesn't implement `Clone`.
#[derive(Clone)]
struct KeyBytes {
    x: Vec<u8>,
    y: Vec<u8>,
}

/// JWKS client that fetches and caches keys from a remote endpoint.
pub struct JwksClient {
    url: String,
    http_client: reqwest::Client,
    cache: RwLock<KeyCache>,
    refresh_mutex: Mutex<()>,
    refresh_ttl: Duration,
}

struct KeyCache {
    keys: HashMap<String, KeyBytes>,
    last_fetch: Option<Instant>,
}

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkEntry>,
}

#[derive(Deserialize)]
struct JwkEntry {
    kty: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    kid: Option<String>,
    #[allow(dead_code)]
    alg: Option<String>,
    #[allow(dead_code)]
    r#use: Option<String>,
}

impl JwksClient {
    /// Create a new JWKS client.
    pub fn new(url: String, refresh_ttl: Duration) -> Self {
        Self {
            url,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
            cache: RwLock::new(KeyCache {
                keys: HashMap::new(),
                last_fetch: None,
            }),
            refresh_mutex: Mutex::new(()),
            refresh_ttl,
        }
    }

    /// Get the decoding key bytes for the given key ID.
    /// Fetches from remote if cache is stale or key is not found.
    pub async fn get_key_bytes(&self, kid: &str) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
        // Try cache first
        {
            let cache = self.cache.read().await;
            if let Some(key) = cache.keys.get(kid) {
                if !self.needs_refresh(&cache) {
                    return Ok((key.x.clone(), key.y.clone()));
                }
            }
        }

        // Single-flight refresh
        let _guard = self.refresh_mutex.lock().await;

        // Double-check after acquiring lock
        {
            let cache = self.cache.read().await;
            if let Some(key) = cache.keys.get(kid) {
                if !self.needs_refresh(&cache) {
                    return Ok((key.x.clone(), key.y.clone()));
                }
            }
        }

        // Perform refresh
        let refresh_result = self.refresh().await;

        if let Err(e) = refresh_result {
            // If refresh fails, try returning cached key
            let cache = self.cache.read().await;
            if let Some(key) = cache.keys.get(kid) {
                return Ok((key.x.clone(), key.y.clone()));
            }
            return Err(AuthError::JwksFetchError(e.to_string()));
        }

        // Try cache again after refresh
        let cache = self.cache.read().await;
        match cache.keys.get(kid) {
            Some(key) => Ok((key.x.clone(), key.y.clone())),
            None => Err(AuthError::KeyNotFound(kid.to_string())),
        }
    }

    /// Insert a key directly into the cache (for testing).
    #[cfg(test)]
    pub async fn insert_key(&self, kid: String, x: Vec<u8>, y: Vec<u8>) {
        let mut cache = self.cache.write().await;
        cache.keys.insert(kid, KeyBytes { x, y });
        cache.last_fetch = Some(Instant::now());
    }

    fn needs_refresh(&self, cache: &KeyCache) -> bool {
        match cache.last_fetch {
            Some(last) => last.elapsed() > self.refresh_ttl,
            None => true,
        }
    }

    async fn refresh(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.http_client.get(&self.url).send().await?;

        if !resp.status().is_success() {
            return Err(format!("JWKS endpoint returned status {}", resp.status()).into());
        }

        let body = resp.bytes().await?;
        if body.len() > MAX_JWKS_SIZE {
            return Err("JWKS response exceeds size limit".into());
        }

        let jwks: JwksResponse = serde_json::from_slice(&body)?;

        let mut keys = HashMap::new();
        for entry in jwks.keys {
            if let Some(key_bytes) = parse_jwk_entry(&entry) {
                if let Some(kid) = &entry.kid {
                    keys.insert(kid.clone(), key_bytes);
                }
            }
        }

        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.last_fetch = Some(Instant::now());

        Ok(())
    }
}

/// Parse a JWK entry into raw coordinate bytes.
/// Returns None for unsupported key types or invalid coordinates.
fn parse_jwk_entry(entry: &JwkEntry) -> Option<KeyBytes> {
    // Only support EC keys on P-256
    if entry.kty.as_deref() != Some("EC") {
        return None;
    }
    if entry.crv.as_deref() != Some("P-256") {
        return None;
    }

    let x_b64 = entry.x.as_deref()?;
    let y_b64 = entry.y.as_deref()?;

    let x_bytes = URL_SAFE_NO_PAD.decode(x_b64).ok()?;
    let y_bytes = URL_SAFE_NO_PAD.decode(y_b64).ok()?;

    // Validate point is on the P-256 curve by trying to construct a PublicKey.
    // This is safer than Go's explicit IsOnCurve check.
    validate_p256_point(&x_bytes, &y_bytes)?;

    Some(KeyBytes {
        x: x_bytes,
        y: y_bytes,
    })
}

/// Validate that (x, y) is a valid point on P-256.
fn validate_p256_point(x: &[u8], y: &[u8]) -> Option<()> {
    // Build uncompressed point: 0x04 || x || y
    let mut uncompressed = Vec::with_capacity(1 + x.len() + y.len());
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(x);
    uncompressed.extend_from_slice(y);

    // p256::PublicKey::from_sec1_bytes rejects invalid curve points
    PublicKey::from_sec1_bytes(&uncompressed).ok()?;
    Some(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn test_parse_valid_jwk() {
        // Generate a real P-256 key and extract coordinates
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let public = secret.public_key();
        let point = public.to_encoded_point(false);

        let x_b64 = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y_b64 = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let entry = JwkEntry {
            kty: Some("EC".into()),
            crv: Some("P-256".into()),
            x: Some(x_b64),
            y: Some(y_b64),
            kid: Some("test-key".into()),
            alg: Some("ES256".into()),
            r#use: Some("sig".into()),
        };

        let result = parse_jwk_entry(&entry);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_invalid_curve_point() {
        // Use obviously invalid coordinates
        let x_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let y_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);

        let entry = JwkEntry {
            kty: Some("EC".into()),
            crv: Some("P-256".into()),
            x: Some(x_b64),
            y: Some(y_b64),
            kid: Some("bad-key".into()),
            alg: Some("ES256".into()),
            r#use: Some("sig".into()),
        };

        let result = parse_jwk_entry(&entry);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_unsupported_key_type() {
        let entry = JwkEntry {
            kty: Some("RSA".into()),
            crv: None,
            x: None,
            y: None,
            kid: Some("rsa-key".into()),
            alg: Some("RS256".into()),
            r#use: Some("sig".into()),
        };

        let result = parse_jwk_entry(&entry);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let client = JwksClient::new("http://unused".into(), Duration::from_secs(3600));

        // Manually populate cache
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let public = secret.public_key();
        let point = public.to_encoded_point(false);

        let key_bytes = KeyBytes {
            x: point.x().unwrap().to_vec(),
            y: point.y().unwrap().to_vec(),
        };

        {
            let mut cache = client.cache.write().await;
            cache.keys.insert("cached-key".into(), key_bytes.clone());
            cache.last_fetch = Some(Instant::now());
        }

        let result = client.get_key_bytes("cached-key").await;
        assert!(result.is_ok());
        let (x, y) = result.unwrap();
        assert_eq!(x, key_bytes.x);
        assert_eq!(y, key_bytes.y);
    }
}
