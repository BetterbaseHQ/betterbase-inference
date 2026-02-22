pub mod tinfoil;

pub use tinfoil::{Tinfoil, TinfoilConfig};

/// Backend trait for LLM inference backends.
pub trait Backend: Send + Sync {
    /// Human-readable name for this backend.
    fn name(&self) -> &str;

    /// Base URL for API requests.
    fn base_url(&self) -> &str;

    /// Add authentication to an outgoing request.
    fn authorize_request(&self, headers: &mut http::HeaderMap);

    /// Headers that should be forwarded from client to backend.
    fn forward_headers(&self) -> &[&str];

    /// Optionally transform the request path.
    fn transform_path<'a>(&self, path: &'a str) -> &'a str;

    /// What features this backend supports.
    fn capabilities(&self) -> Capabilities;
}

/// Capabilities describes what features a backend supports.
#[derive(Debug, Clone)]
pub struct Capabilities {
    pub chat_completions: bool,
    pub models: bool,
    pub hpke_keys: bool,
}
