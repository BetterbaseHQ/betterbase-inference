# CLAUDE.md

## What this is

Rust port of the Go `less-inference` microservice — an authenticated HTTP reverse proxy for Tinfoil E2EE inference. Validates JWTs via JWKS, enforces per-user rate limiting, and streams proxied responses (SSE).

**Go source:** `/Users/nchapman/Code/lessisbetter/less-platform/less-inference/`

## Commands

```bash
just check         # fmt + clippy + test
just test          # cargo test
just lint          # cargo clippy -D warnings
just fmt           # cargo fmt
just dev           # Run in dev mode (ephemeral key, test token)
just run           # Run with custom args
```

## Architecture

```
src/
├── main.rs              # clap CLI, tracing init, graceful shutdown
├── config.rs            # Config struct (clap derive + env vars)
├── protocol.rs          # ErrorResponse, HealthResponse
├── auth/
│   ├── errors.rs        # AuthError enum (thiserror)
│   ├── jwks.rs          # JWKS client: P-256 key cache, single-flight refresh
│   ├── jwt.rs           # JWT validator: ES256-only, custom claims
│   └── devmode.rs       # Ephemeral keypair, local JWKS server, test tokens
├── backend/
│   ├── mod.rs           # Backend trait + Capabilities
│   └── tinfoil.rs       # Tinfoil implementation (EHBP headers)
└── server/
    ├── mod.rs           # axum Router: public vs protected route split
    ├── middleware.rs     # Auth layer, X-Protocol-Version, scope checking
    ├── ratelimit.rs     # Token bucket per-user, HMAC key hashing
    ├── proxy.rs         # Reverse proxy with streaming (Body::from_stream)
    ├── handlers.rs      # health, models, chat_completions, hpke_keys
    └── logging.rs       # Status-based log levels, health skip
```

### Route split

- **Public** (no auth): `/health`, `/.well-known/hpke-keys`
- **Protected** (auth + rate limit): `/v1/models`, `/v1/chat/completions`

### Key design decisions

- **Store raw JWK coordinates** (not `DecodingKey`): avoids `Clone` issues, construction from bytes is cheap
- **`std::sync::Mutex` for rate limiter**: `allow()` is pure computation, no async needed
- **No `reqwest` read timeout**: streaming responses can take minutes; only connect + response-header timeout
- **Implicit P-256 validation**: `p256::PublicKey::from_sec1_bytes()` rejects invalid curve points

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWKS_URL` | Yes (unless `--dev-mode`) | JWKS endpoint for JWT validation |
| `ISSUER` | No | Expected JWT issuer |
| `AUDIENCES` | No | Comma-separated valid audiences |
| `TINFOIL_API_KEY` | Yes | Tinfoil API key |
| `TINFOIL_BASE_URL` | No | Tinfoil base URL (default: `https://inference.tinfoil.sh`) |
| `RATE_LIMIT_RPM` | No | Requests per minute (default: 60, 0 to disable) |
| `RATE_LIMIT_BURST` | No | Burst size (default: 10) |
| `IDENTITY_HASH_KEY` | No | 32 bytes hex for privacy-preserving rate limit keys |
| `LOG_FORMAT` | No | `text` (default) or `json` |
