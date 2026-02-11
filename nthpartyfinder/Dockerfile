# =============================================================================
# nthpartyfinder Docker Build - Production
# Full feature parity: NER/GLiNER, headless Chrome, subfinder, all discovery
#
# Build stage uses official Rust slim-bookworm (glibc matches runtime)
# Download stages use Chainguard hardened images (free, zero-CVE, SLSA provenance)
# Runtime uses Debian slim because no hardened image supports Chromium installation
# (hardened images are distroless with no package manager — Chromium needs 30+ libs)
# Runtime is manually hardened: non-root, cap-drop ALL, post-install cleanup
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build (Debian bookworm-based Rust — glibc matches runtime)
# -----------------------------------------------------------------------------
FROM rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release 2>/dev/null || true

# Copy actual source and assets
COPY src/ src/
COPY config/ config/
COPY templates/ templates/
COPY static/ static/
COPY models/ models/

# Build with default features (includes embedded-ner)
RUN touch src/main.rs && cargo build --release
RUN strip target/release/nthpartyfinder

# -----------------------------------------------------------------------------
# Stage 2: Download ONNX Runtime (Chainguard hardened base)
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS onnx-dl
USER root
RUN apk add curl && \
    curl -fsSL -o /tmp/onnxruntime.tgz \
      "https://github.com/microsoft/onnxruntime/releases/download/v1.20.1/onnxruntime-linux-x64-1.20.1.tgz" && \
    tar -xzf /tmp/onnxruntime.tgz -C /tmp/

# -----------------------------------------------------------------------------
# Stage 3: Download subfinder (Chainguard hardened base)
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS subfinder-dl
USER root
RUN apk add curl unzip && \
    curl -fsSL -o /tmp/subfinder.zip \
      "https://github.com/projectdiscovery/subfinder/releases/download/v2.11.0/subfinder_2.11.0_linux_amd64.zip" && \
    unzip /tmp/subfinder.zip -d /tmp/subfinder && \
    chmod +x /tmp/subfinder/subfinder

# -----------------------------------------------------------------------------
# Stage 4: Runtime (Debian slim — required for Chromium, manually hardened)
# No free hardened image supports Chromium: Chainguard/Wolfi has no Chromium
# package (request closed as "not planned"), Distroless has no package manager.
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

# Install runtime dependencies, then harden by removing package manager cache
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    whois \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/share/doc /usr/share/man /usr/share/info \
    && groupadd -g 10001 nthparty \
    && useradd -u 10001 -g nthparty -d /home/nthparty -m -s /usr/sbin/nologin nthparty

# Copy binaries
COPY --from=builder /build/target/release/nthpartyfinder /usr/local/bin/nthpartyfinder
COPY --from=subfinder-dl /tmp/subfinder/subfinder /usr/local/bin/subfinder

# Copy ONNX Runtime shared library
COPY --from=onnx-dl /tmp/onnxruntime-linux-x64-1.20.1/lib/libonnxruntime.so.1.20.1 /usr/local/lib/
COPY --from=onnx-dl /tmp/onnxruntime-linux-x64-1.20.1/lib/libonnxruntime_providers_shared.so /usr/local/lib/
RUN ln -s /usr/local/lib/libonnxruntime.so.1.20.1 /usr/local/lib/libonnxruntime.so && ldconfig

# Copy config files
COPY --from=builder /build/config/ /app/config/

# Create output and cache directories
RUN mkdir -p /output /cache && \
    chown -R nthparty:nthparty /app /output /cache

# Environment
ENV ORT_DYLIB_PATH=/usr/local/lib/libonnxruntime.so.1.20.1
ENV CHROME_PATH=/usr/bin/chromium
ENV NTHPARTYFINDER_CONTAINER=1

USER 10001:10001
WORKDIR /app

ENTRYPOINT ["nthpartyfinder"]
CMD ["--help"]
