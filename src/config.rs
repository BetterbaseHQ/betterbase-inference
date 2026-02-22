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
}

/// Parse comma-separated audience list, trimming whitespace and filtering empties.
pub fn parse_audience_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
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
}
