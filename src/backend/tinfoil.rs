use super::{Backend, Capabilities};

/// Tinfoil backend configuration.
pub struct TinfoilConfig {
    pub base_url: Option<String>,
    pub api_key: String,
}

/// Tinfoil backend: OpenAI-compatible endpoints with TEE-based EHBP encryption.
pub struct Tinfoil {
    base_url: String,
    api_key: String,
}

const FORWARD_HEADERS: &[&str] = &["Ehbp-Encapsulated-Key", "Ehbp-Response-Nonce"];

impl Tinfoil {
    pub fn new(config: TinfoilConfig) -> Self {
        Self {
            base_url: config
                .base_url
                .unwrap_or_else(|| "https://inference.tinfoil.sh".into()),
            api_key: config.api_key,
        }
    }
}

impl Backend for Tinfoil {
    fn name(&self) -> &str {
        "tinfoil"
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn authorize_request(&self, headers: &mut http::HeaderMap) {
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {}", self.api_key)
                .parse()
                .expect("valid header value"),
        );
    }

    fn forward_headers(&self) -> &[&str] {
        FORWARD_HEADERS
    }

    fn transform_path<'a>(&self, path: &'a str) -> &'a str {
        path
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            chat_completions: true,
            models: true,
            hpke_keys: true,
        }
    }
}
