mod auth;
mod backend;
mod config;
mod protocol;
mod server;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};

use backend::Backend;

use auth::devmode::DevMode;
use backend::{Tinfoil, TinfoilConfig};
use config::{parse_audience_list, Config};
use server::ratelimit::{RateLimiter, RateLimiterConfig};

#[tokio::main]
async fn main() {
    let config = Config::parse();

    // Configure logging
    match config.log_format.as_str() {
        "json" => {
            tracing_subscriber::fmt().json().init();
        }
        _ => {
            tracing_subscriber::fmt().init();
        }
    }

    let mut jwks_url = config.jwks_url.clone();
    let mut issuer = config.issuer.clone().unwrap_or_default();
    let mut audiences_raw = config.audiences.clone().unwrap_or_default();

    // Dev mode
    let _dev_mode_holder;
    if config.dev_mode {
        warn!("DEV MODE ENABLED - do not use in production");

        let dev = match DevMode::new() {
            Ok(d) => Arc::new(d),
            Err(e) => {
                error!(error = %e, "failed to initialize dev mode");
                std::process::exit(1);
            }
        };

        let dev_jwks_url = match dev.clone().start_jwks_server().await {
            Ok(url) => url,
            Err(e) => {
                error!(error = %e, "failed to start JWKS server");
                std::process::exit(1);
            }
        };

        jwks_url = Some(dev_jwks_url);

        let test_token = match dev.generate_token("test-user", "test-client", "inference") {
            Ok(t) => t,
            Err(e) => {
                error!(error = %e, "failed to generate test token");
                std::process::exit(1);
            }
        };

        if issuer.is_empty() {
            issuer = "betterbase-accounts".into();
        }
        if audiences_raw.is_empty() {
            audiences_raw = "betterbase-inference".into();
        }

        let addr = normalize_addr(&config.addr);
        println!();
        println!("========================================");
        println!("DEV MODE - Test Token:");
        println!("========================================");
        println!("{test_token}");
        println!("========================================");
        println!();
        println!("Example usage:");
        println!(
            "  curl -H \"Authorization: Bearer {test_token}\" http://localhost:{}/v1/models",
            addr.split(':').next_back().unwrap_or("5381")
        );
        println!();

        _dev_mode_holder = dev;
    }

    // Validate required config
    let jwks_url = match jwks_url {
        Some(url) => url,
        None => {
            error!("JWKS_URL is required for JWT authentication (or use --dev-mode)");
            std::process::exit(1);
        }
    };

    let audiences = if audiences_raw.is_empty() {
        vec![]
    } else {
        parse_audience_list(&audiences_raw)
    };

    if issuer.is_empty() && audiences.is_empty() {
        warn!("ISSUER and AUDIENCES are both unconfigured — tokens from any issuer/audience will be accepted");
    }

    // Configure Tinfoil backend
    let api_key = match &config.tinfoil_api_key {
        Some(key) => {
            if std::env::var("TINFOIL_API_KEY").is_err() {
                warn!("Tinfoil API key provided via command-line flag - use TINFOIL_API_KEY env var in production");
            }
            key.clone()
        }
        None => {
            if !config.dev_mode {
                error!("TINFOIL_API_KEY is required");
                std::process::exit(1);
            }
            "dev-mode-placeholder".into()
        }
    };

    let backend = Arc::new(Tinfoil::new(TinfoilConfig {
        base_url: Some(config.tinfoil_base_url.clone()),
        api_key,
    }));

    info!(
        backend = backend.name(),
        base_url = backend.base_url(),
        "using backend"
    );

    // Validator
    let validator = Arc::new(auth::Validator::new(auth::ValidatorConfig {
        jwks_url,
        issuer,
        audiences,
        refresh_ttl: None,
    }));

    // Rate limiter
    let rate_limiter = if config.rate_limit_rpm > 0 {
        let hash_key = match std::env::var("IDENTITY_HASH_KEY") {
            Ok(hex_str) => {
                let bytes = hex::decode(&hex_str).unwrap_or_else(|_| {
                    error!("IDENTITY_HASH_KEY must be hex-encoded");
                    std::process::exit(1);
                });
                if bytes.len() != 32 {
                    error!("IDENTITY_HASH_KEY must be 32 bytes (64 hex chars)");
                    std::process::exit(1);
                }
                Some(bytes)
            }
            Err(_) => {
                warn!("IDENTITY_HASH_KEY not set — rate limit keys will use plaintext identity");
                None
            }
        };

        let limiter = Arc::new(RateLimiter::new(RateLimiterConfig {
            requests_per_minute: config.rate_limit_rpm,
            burst_size: config.rate_limit_burst,
            hash_key,
        }));

        info!(
            requests_per_minute = config.rate_limit_rpm,
            burst_size = config.rate_limit_burst,
            "rate limiting enabled"
        );

        // Cleanup task — dropped automatically when the Tokio runtime shuts down
        let cleanup_limiter = limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(600));
            loop {
                interval.tick().await;
                cleanup_limiter.cleanup(Duration::from_secs(1800));
            }
        });

        Some(limiter)
    } else {
        None
    };

    // HTTP client for proxying
    // Match Go's transport config: connection pool limits, TLS timeout
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .build()
        .expect("failed to build HTTP client");

    let app = server::build_router(backend, validator, rate_limiter, http_client);

    let addr = normalize_addr(&config.addr);
    let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        error!(addr = addr, error = %e, "failed to bind");
        std::process::exit(1);
    });

    info!(addr = addr, "server starting");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| {
            error!(error = %e, "server error");
            std::process::exit(1);
        });

    info!("server stopped");
}

/// Convert Go-style ":5381" to "0.0.0.0:5381".
fn normalize_addr(addr: &str) -> String {
    if addr.starts_with(':') {
        format!("0.0.0.0{addr}")
    } else {
        addr.to_string()
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for ctrl+c");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received SIGINT, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}
