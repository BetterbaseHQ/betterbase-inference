use clap::Parser;

/// Less Inference — authenticated E2EE inference proxy.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Config {
    /// Listen address (e.g. ":5381" or "0.0.0.0:5381")
    #[arg(long, default_value = ":5381", env = "ADDR")]
    pub addr: String,

    /// Log format: "text" or "json"
    #[arg(long, default_value = "text", env = "LOG_FORMAT")]
    pub log_format: String,

    /// Enable dev mode with ephemeral test JWT key
    #[arg(long, default_value_t = false, env = "DEV_MODE")]
    pub dev_mode: bool,

    /// JWKS URL for JWT validation
    #[arg(long, env = "JWKS_URL")]
    pub jwks_url: Option<String>,

    /// Expected JWT issuer (iss claim)
    #[arg(long, env = "ISSUER")]
    pub issuer: Option<String>,

    /// Comma-separated list of valid JWT audiences
    #[arg(long, env = "AUDIENCES")]
    pub audiences: Option<String>,

    /// Tinfoil API base URL
    #[arg(
        long,
        default_value = "https://inference.tinfoil.sh",
        env = "TINFOIL_BASE_URL"
    )]
    pub tinfoil_base_url: String,

    /// Tinfoil API key
    #[arg(long, env = "TINFOIL_API_KEY")]
    pub tinfoil_api_key: Option<String>,

    /// Requests per minute per user (0 to disable rate limiting)
    #[arg(long, default_value_t = 60, env = "RATE_LIMIT_RPM")]
    pub rate_limit_rpm: u32,

    /// Rate limit burst size
    #[arg(long, default_value_t = 10, env = "RATE_LIMIT_BURST")]
    pub rate_limit_burst: u32,

    /// Maximum in-flight proxied upstream requests (AUD-044). Further
    /// requests fail with 429 until a slot frees.
    #[arg(long, default_value_t = 64, env = "MAX_UPSTREAM_CONCURRENCY")]
    pub max_upstream_concurrency: u32,

    /// Maximum proxied request body size in bytes (AUD-044). Oversized
    /// bodies fail with 413.
    #[arg(long, default_value_t = 10 * 1024 * 1024, env = "MAX_REQUEST_BODY_BYTES")]
    pub max_request_body_bytes: usize,

    /// AUD-041: reject chat requests that are not client-side encrypted.
    /// When enabled, `/v1/chat/completions` requires the
    /// `Ehbp-Encapsulated-Key` header (present only when the client
    /// performed EHBP encapsulation), so no plaintext prompt can transit
    /// the proxy. Requires clients to implement Tinfoil's client-side
    /// encryption; the documented quick-start sends plaintext and will
    /// be rejected with 400 while this is enabled.
    #[arg(long, default_value_t = false, env = "REQUIRE_EHBP")]
    pub require_ehbp: bool,
}

/// Parse comma-separated audience list, trimming whitespace and filtering empties.
pub fn parse_audience_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// AUD-042: token acceptance must be bound to an expected issuer and
/// audience set. Outside dev mode, missing either restriction fails
/// closed — a proxy that accepts tokens from any issuer/audience is a
/// token-confusion hazard whenever the signing authority issues
/// inference-scoped tokens for other services.
pub fn validate_auth_binding(
    dev_mode: bool,
    issuer: &str,
    audiences: &[String],
) -> Result<(), String> {
    if dev_mode {
        return Ok(());
    }
    if issuer.is_empty() {
        return Err("ISSUER is required (expected JWT issuer claim; dev mode defaults it)".into());
    }
    if audiences.is_empty() {
        return Err(
            "AUDIENCES is required (comma-separated valid JWT audiences; dev mode defaults it)"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_audience_list_trims_whitespace() {
        assert_eq!(
            parse_audience_list("foo, bar ,baz"),
            vec!["foo", "bar", "baz"]
        );
    }

    #[test]
    fn test_parse_audience_list_filters_empties() {
        assert_eq!(parse_audience_list("foo,, ,bar,"), vec!["foo", "bar"]);
    }

    #[test]
    fn test_parse_audience_list_all_empty() {
        let result = parse_audience_list(", ,");
        assert!(result.is_empty());
    }

    #[test]
    fn test_auth_binding_fails_closed_without_issuer() {
        let err = validate_auth_binding(false, "", &["betterbase-inference".into()]).unwrap_err();
        assert!(
            err.contains("ISSUER"),
            "error should name the missing variable: {err}"
        );
    }

    #[test]
    fn test_auth_binding_fails_closed_without_audiences() {
        let err = validate_auth_binding(false, "https://accounts.example.com", &[]).unwrap_err();
        assert!(
            err.contains("AUDIENCES"),
            "error should name the missing variable: {err}"
        );
    }

    #[test]
    fn test_auth_binding_accepts_full_configuration() {
        assert!(validate_auth_binding(
            false,
            "https://accounts.example.com",
            &["betterbase-inference".into()]
        )
        .is_ok());
    }

    #[test]
    fn test_auth_binding_dev_mode_exempt() {
        assert!(validate_auth_binding(true, "", &[]).is_ok());
    }
}
