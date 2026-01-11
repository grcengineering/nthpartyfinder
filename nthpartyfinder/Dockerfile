# =============================================================================
# nthpartyfinder Docker Build - Production (Distroless)
# Uses Docker Hardened Images (dhi.io) for build, scratch for runtime
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build stage using DHI Rust with musl for static binary
# -----------------------------------------------------------------------------
FROM dhi.io/rust:1.83-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

# Set up cargo for static linking
ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV PKG_CONFIG_ALLOW_CROSS=1
ENV OPENSSL_STATIC=1
ENV OPENSSL_DIR=/usr

WORKDIR /build

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true

# Copy actual source
COPY src/ src/
COPY config/ config/
COPY templates/ templates/

# Copy model files for embedded NER
COPY models/ models/

# Build the real binary with embedded NER
RUN touch src/main.rs && \
    cargo build --release --target x86_64-unknown-linux-musl --features embedded-ner

# Strip the binary for minimal size
RUN strip /build/target/x86_64-unknown-linux-musl/release/nthpartyfinder

# -----------------------------------------------------------------------------
# Stage 2: Runtime stage using scratch (true distroless - 0 bytes overhead)
# -----------------------------------------------------------------------------
FROM scratch

# Copy the static binary
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/nthpartyfinder /nthpartyfinder

# Copy config files
COPY --from=builder /build/config/ /etc/nthpartyfinder/

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Set environment
ENV NTHPARTYFINDER_CONFIG_DIR=/etc/nthpartyfinder

ENTRYPOINT ["/nthpartyfinder"]
CMD ["--help"]
