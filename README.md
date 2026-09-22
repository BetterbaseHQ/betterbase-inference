# betterbase-inference

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/BetterbaseHQ/betterbase-inference/blob/main/LICENSE)

Authenticated proxy for private LLM inference via a [Tinfoil](https://tinfoil.sh) Trusted Execution Environment (TEE). The proxy authenticates and rate-limits requests and forwards them to the TEE backend.

> **Read this before relying on confidentiality.** End-to-end encryption is *the client's job* in this architecture: a client that implements Tinfoil's client-side EHBP encryption encrypts prompts so only the TEE can decrypt them, and the proxy relays the ciphertext (`Ehbp-Encapsulated-Key` / `Ehbp-Response-Nonce` headers are passed through). **A client that does not — including the quick-start below — sends plaintext that this proxy can read.** No reference EHBP client is checked in yet (tracked as a v1.x work item); until one exists, treat the proxy as a trusted hop. Operators who must not accept plaintext can set `REQUIRE_EHBP=true`, which rejects any chat request lacking encryption material.

> **Note:** This service runs standalone and is not part of the `docker-compose` stack. See the [betterbase-dev](https://github.com/BetterbaseHQ/betterbase-dev) repo for the full platform setup.

## How It Works

```
Client (authenticated)
  |
  |  POST /v1/chat/completions  (Bearer JWT)
  v
betterbase-inference
  |  1. Validate JWT via JWKS
  |  2. Check rate limit (token bucket per user)
  |  3. Proxy request to Tinfoil TEE
  v
Tinfoil (enclave)
  |  Process in trusted execution environment
  |  Stream SSE response back
  v
Client receives streamed response
```

The proxy passes Tinfoil's EHBP (Encrypted HTTP Bearer Protocol) headers through, which lets an encrypting client receive responses only it can decrypt and verify attestation. Whether the request is actually encrypted is decided client-side; see the confidentiality note above.

## Prerequisites

- **Rust** (stable toolchain) -- [install via rustup](https://rustup.rs/)
- **just** -- command runner ([install](https://github.com/casey/just#installation))
- **Tinfoil API key** -- sign up at [tinfoil.sh](https://tinfoil.sh)

## Quick Start

### Development Mode

Dev mode generates an ephemeral signing key, serves a local JWKS endpoint, and prints a test JWT you can use immediately:

```bash
TINFOIL_API_KEY=your-key just dev
```

Once the server is running, copy the test JWT from the output and make a request:

```bash
# NOTE: this sends a PLAINTEXT prompt — fine for dev mode, but it means
# the proxy can read it. Real confidentiality requires a client that
# implements Tinfoil's EHBP encryption (see the note at the top).
curl http://localhost:5381/v1/chat/completions \
  -H "Authorization: Bearer <test-jwt-from-output>" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

### Production

`ISSUER` and `AUDIENCES` are **required** — the server refuses to start without them, because an unbound validator would accept inference-scoped tokens issued for any service.

```bash
JWKS_URL=https://accounts.example.com/.well-known/jwks.json \
ISSUER=https://accounts.example.com \
AUDIENCES=betterbase-inference \
TINFOIL_API_KEY=your-key \
cargo run
```

## API

### Public Endpoints (no auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/.well-known/hpke-keys` | HPKE public keys for E2EE (proxied from Tinfoil). HPKE (Hybrid Public Key Encryption) keys let clients encrypt requests so only the TEE can decrypt them. |

### Protected Endpoints (JWT + rate limit)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/models` | List available models (proxied from Tinfoil) |
| POST | `/v1/chat/completions` | Chat completions with streaming SSE (proxied from Tinfoil) |

All protected endpoints require a valid JWT with the `inference` scope.

## Commands

```bash
just check    # Format, lint, test
just test     # cargo test
just lint     # cargo clippy -D warnings
just fmt      # cargo fmt
just dev      # Run in dev mode (ephemeral key, test token)
just run      # Run with custom args
```

## Configuration

All configuration via environment variables or CLI flags:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TINFOIL_API_KEY` | Yes | -- | API key for Tinfoil backend |
| `JWKS_URL` | Yes* | -- | JWKS endpoint for JWT validation (*not needed in `--dev-mode`) |
| `ISSUER` | **Yes** | -- | Expected JWT issuer claim (dev mode defaults it) |
| `AUDIENCES` | **Yes** | -- | Comma-separated valid JWT audiences (dev mode defaults it) |
| `TINFOIL_BASE_URL` | No | `https://inference.tinfoil.sh` | Tinfoil API base URL |
| `RATE_LIMIT_RPM` | No | 60 | Requests per minute per user (0 to disable) |
| `RATE_LIMIT_BURST` | No | 10 | Burst size for rate limiter |
| `REQUIRE_EHBP` | No | `false` | Reject chat requests without client-side encryption (see confidentiality note) |
| `MAX_UPSTREAM_CONCURRENCY` | No | 256 | Max concurrent upstream connections, permits held for the response-stream lifetime (429 beyond) |
| `MAX_REQUEST_BODY_BYTES` | No | 10485760 | Max proxied request body size, enforced on the wire (413/teardown beyond) |
| `IDENTITY_HASH_KEY` | No | -- | 32-byte hex key for privacy-preserving rate limit keys |
| `LOG_FORMAT` | No | `text` | Log format: `text` or `json` |
| `PORT` | No | 5381 | Listen port |

## Architecture

Single-crate Rust binary using Axum:

```
src/
├── main.rs              # CLI (clap), tracing, graceful shutdown
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
    ├── mod.rs           # Axum Router: public vs protected route split
    ├── middleware.rs     # Auth layer, X-Protocol-Version, scope checking
    ├── ratelimit.rs     # Token bucket per-user, HMAC key hashing
    ├── proxy.rs         # Reverse proxy with streaming (Body::from_stream)
    ├── handlers.rs      # health, models, chat_completions, hpke_keys
    └── logging.rs       # Status-based log levels, health skip
```

## Related

- [betterbase-dev](https://github.com/BetterbaseHQ/betterbase-dev) -- Platform orchestration
- [betterbase-accounts](../betterbase-accounts/) -- OPAQUE auth + OAuth 2.0 server
- [betterbase-sync](../betterbase-sync/) -- Encrypted blob sync service
- [betterbase](../betterbase/) -- Client SDK (auth, crypto, sync, db)

## License

Apache-2.0
