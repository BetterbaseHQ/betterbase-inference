use url::Url;

/// Build the upstream URL from base URL, path, and query string.
pub fn build_upstream_url(base_url: &str, path: &str, raw_query: &str) -> Result<String, String> {
    let mut parsed = Url::parse(base_url).map_err(|e| e.to_string())?;

    let normalized_base = parsed.path().trim_end_matches('/');
    let trimmed_path = path.trim_start_matches('/');

    let full_path = if normalized_base.is_empty() || normalized_base == "/" {
        if trimmed_path.is_empty() {
            "/".to_string()
        } else {
            format!("/{trimmed_path}")
        }
    } else if trimmed_path.is_empty() {
        normalized_base.to_string()
    } else {
        format!("{normalized_base}/{trimmed_path}")
    };

    parsed.set_path(&full_path);
    if !raw_query.is_empty() {
        parsed.set_query(Some(raw_query));
    } else {
        parsed.set_query(None);
    }

    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preserves_query() {
        let got = build_upstream_url("https://inference.example.com", "/v1/models", "foo=bar&x=1")
            .unwrap();
        assert_eq!(got, "https://inference.example.com/v1/models?foo=bar&x=1");
    }

    #[test]
    fn test_trims_base_path() {
        let got =
            build_upstream_url("https://inference.example.com/api/", "/v1/models", "").unwrap();
        assert_eq!(got, "https://inference.example.com/api/v1/models");
    }

    #[test]
    fn test_invalid_base_url() {
        let result = build_upstream_url("://bad", "/v1/models", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_raw_query() {
        let got = build_upstream_url("https://inference.example.com", "/v1/models", "").unwrap();
        assert_eq!(got, "https://inference.example.com/v1/models");
    }
}
