# Build stage
FROM rust:1.84-alpine AS builder

WORKDIR /app

RUN apk --no-cache add musl-dev ca-certificates

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Build the actual binary
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM alpine:3.21
RUN apk add --no-cache ca-certificates && \
    addgroup -g 65532 -S nonroot && adduser -u 65532 -S -G nonroot nonroot
COPY --from=builder /app/target/release/less-inference /server
USER nonroot
EXPOSE 5381
ENTRYPOINT ["/server"]
