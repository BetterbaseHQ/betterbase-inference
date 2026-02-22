use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Rate limiter configuration.
pub struct RateLimiterConfig {
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub hash_key: Option<Vec<u8>>,
}

/// Per-user token bucket rate limiter.
pub struct RateLimiter {
    requests_per_minute: u32,
    burst_size: u32,
    hash_key: Option<Vec<u8>>,
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            requests_per_minute: config.requests_per_minute,
            burst_size: config.burst_size,
            hash_key: config.hash_key,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request from the given issuer+user should be allowed.
    pub fn allow(&self, issuer: &str, user_id: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let key = rate_limit_key(self.hash_key.as_deref(), issuer, user_id);
        let now = Instant::now();

        let bucket = buckets.entry(key).or_insert(TokenBucket {
            tokens: self.burst_size as f64,
            last_update: now,
        });

        // Refill tokens based on time elapsed
        let elapsed_minutes = bucket.last_update.elapsed().as_secs_f64() / 60.0;
        bucket.tokens += elapsed_minutes * self.requests_per_minute as f64;
        if bucket.tokens > self.burst_size as f64 {
            bucket.tokens = self.burst_size as f64;
        }
        bucket.last_update = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remove stale buckets to prevent memory leaks.
    pub fn cleanup(&self, max_age: Duration) {
        let mut buckets = self.buckets.lock().unwrap();
        buckets.retain(|_, bucket| bucket.last_update.elapsed() <= max_age);
    }
}

/// Compute the bucket key for rate limiting.
/// When hash_key is set, returns HMAC-SHA256(key, issuer + "\0" + userID) as hex.
/// When hash_key is None, falls back to plaintext "issuer:userID".
pub fn rate_limit_key(hash_key: Option<&[u8]>, issuer: &str, user_id: &str) -> String {
    match hash_key {
        Some(key) => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC can accept any key size");
            mac.update(issuer.as_bytes());
            mac.update(&[0x00]);
            mac.update(user_id.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
        None => format!("{issuer}:{user_id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_key_with_hash_key() {
        let hash_key = b"01234567890123456789012345678901"; // 32 bytes
        let key = rate_limit_key(Some(hash_key), "https://accounts.less.so", "user-123");

        // HMAC-SHA256 output is 64 hex chars
        assert_eq!(key.len(), 64);

        // Deterministic
        let key2 = rate_limit_key(Some(hash_key), "https://accounts.less.so", "user-123");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_rate_limit_key_different_inputs() {
        let hash_key = b"01234567890123456789012345678901";
        let k1 = rate_limit_key(Some(hash_key), "https://accounts.less.so", "user1");
        let k2 = rate_limit_key(Some(hash_key), "https://accounts.less.so", "user2");
        let k3 = rate_limit_key(Some(hash_key), "https://other.example.com", "user1");

        assert_ne!(k1, k2, "different users should produce different keys");
        assert_ne!(k1, k3, "different issuers should produce different keys");
    }

    #[test]
    fn test_rate_limit_key_null_separator() {
        let hash_key = b"01234567890123456789012345678901";
        let k1 = rate_limit_key(Some(hash_key), "ab", "c");
        let k2 = rate_limit_key(Some(hash_key), "a", "bc");
        assert_ne!(
            k1, k2,
            "null separator should prevent issuer/userID boundary collision"
        );
    }

    #[test]
    fn test_rate_limit_key_no_hash_key() {
        let key = rate_limit_key(None, "issuer", "user");
        assert_eq!(key, "issuer:user");
    }

    #[test]
    fn test_rate_limit_key_different_keys() {
        let key1 = b"01234567890123456789012345678901";
        let key2 = b"abcdefghijklmnopqrstuvwxyz012345";
        let h1 = rate_limit_key(Some(key1), "issuer", "user");
        let h2 = rate_limit_key(Some(key2), "issuer", "user");
        assert_ne!(h1, h2, "different keys should produce different hashes");
    }

    #[test]
    fn test_allow_consumes_and_exhausts() {
        let rl = RateLimiter::new(RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 2,
            hash_key: None,
        });

        assert!(
            rl.allow("issuer", "user"),
            "first request should be allowed"
        );
        assert!(
            rl.allow("issuer", "user"),
            "second request should be allowed"
        );
        assert!(
            !rl.allow("issuer", "user"),
            "bucket should be exhausted after burst"
        );
    }

    #[test]
    fn test_cleanup_removes_stale_buckets() {
        let rl = RateLimiter::new(RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 10,
            hash_key: None,
        });

        // Create a fresh bucket
        rl.allow("issuer", "fresh-user");

        // Manually insert a stale bucket
        {
            let mut buckets = rl.buckets.lock().unwrap();
            buckets.insert(
                "stale".into(),
                TokenBucket {
                    tokens: 1.0,
                    last_update: Instant::now() - Duration::from_secs(3600),
                },
            );
        }

        rl.cleanup(Duration::from_secs(1800)); // 30 minutes

        let buckets = rl.buckets.lock().unwrap();
        assert!(
            !buckets.contains_key("stale"),
            "stale bucket should be removed"
        );
        assert_eq!(buckets.len(), 1, "fresh bucket should remain");
    }
}
