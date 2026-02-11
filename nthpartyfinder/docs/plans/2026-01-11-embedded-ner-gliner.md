# Embedded NER with GLiNER Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the Ollama-dependent SLM with an embedded GLiNER NER model using `include_bytes!` for true single-binary deployment, and add Docker Hardened Image containerization.

**Architecture:** Replace `slm_org.rs` (Ollama-based) with `ner_org.rs` (embedded GLiNER via gline-rs). The GLiNER ONNX model will be compiled into the binary using Rust's `include_bytes!` macro. For Docker, we use Alpine-based Docker Hardened Images from dhi.io for minimal attack surface.

**Tech Stack:** gline-rs (GLiNER Rust inference), ort (ONNX Runtime bindings), Docker Hardened Images (dhi.io/rust, dhi.io/alpine)

---

## Phase 1: Replace Ollama SLM with Embedded GLiNER

### Task 1: Add gline-rs and ort dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add the required dependencies to Cargo.toml**

Add these dependencies after the existing ones:

```toml
# Embedded NER for organization extraction (replaces Ollama SLM)
gline-rs = { version = "0.9", optional = true }
ort = { version = "2.0", optional = true, features = ["load-dynamic"] }

[features]
default = []
embedded-ner = ["gline-rs", "ort"]
```

**Step 2: Verify cargo check passes**

Run: `cargo check --features embedded-ner`
Expected: Dependencies resolve (may take a while to download)

**Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "feat: add gline-rs and ort dependencies for embedded NER"
```

---

### Task 2: Download and prepare GLiNER ONNX model

**Files:**
- Create: `models/.gitkeep`
- Create: `scripts/download-model.ps1`
- Create: `scripts/download-model.sh`

**Step 1: Create models directory**

```bash
mkdir -p models
```

**Step 2: Create download script for Windows (PowerShell)**

Create `scripts/download-model.ps1`:

```powershell
# Download GLiNER small model (INT8 quantized for smaller size)
$ModelUrl = "https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/main/onnx/model_int8.onnx"
$TokenizerUrl = "https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/main/tokenizer.json"
$ConfigUrl = "https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/main/config.json"

$ModelsDir = Join-Path $PSScriptRoot "..\models"
New-Item -ItemType Directory -Force -Path $ModelsDir | Out-Null

Write-Host "Downloading GLiNER small model (INT8 quantized)..."
Invoke-WebRequest -Uri $ModelUrl -OutFile (Join-Path $ModelsDir "gliner_small.onnx")

Write-Host "Downloading tokenizer..."
Invoke-WebRequest -Uri $TokenizerUrl -OutFile (Join-Path $ModelsDir "tokenizer.json")

Write-Host "Downloading config..."
Invoke-WebRequest -Uri $ConfigUrl -OutFile (Join-Path $ModelsDir "config.json")

Write-Host "Done! Model files saved to $ModelsDir"
Get-ChildItem $ModelsDir | Format-Table Name, Length
```

**Step 3: Create download script for Linux/macOS**

Create `scripts/download-model.sh`:

```bash
#!/bin/bash
set -e

MODEL_URL="https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/main/onnx/model_int8.onnx"
TOKENIZER_URL="https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/main/tokenizer.json"
CONFIG_URL="https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/main/config.json"

MODELS_DIR="$(dirname "$0")/../models"
mkdir -p "$MODELS_DIR"

echo "Downloading GLiNER small model (INT8 quantized)..."
curl -L "$MODEL_URL" -o "$MODELS_DIR/gliner_small.onnx"

echo "Downloading tokenizer..."
curl -L "$TOKENIZER_URL" -o "$MODELS_DIR/tokenizer.json"

echo "Downloading config..."
curl -L "$CONFIG_URL" -o "$MODELS_DIR/config.json"

echo "Done! Model files:"
ls -lh "$MODELS_DIR"
```

**Step 4: Create .gitkeep for models directory**

Create `models/.gitkeep` (empty file)

**Step 5: Add models to .gitignore (except .gitkeep)**

Add to `.gitignore`:
```
# Model files (too large for git, download via scripts)
models/*.onnx
models/*.json
!models/.gitkeep
```

**Step 6: Download the model**

Run: `powershell -ExecutionPolicy Bypass -File scripts/download-model.ps1`
Expected: Model files downloaded to `models/` directory

**Step 7: Commit**

```bash
git add scripts/ models/.gitkeep .gitignore
git commit -m "feat: add model download scripts for GLiNER"
```

---

### Task 3: Create embedded NER module

**Files:**
- Create: `src/ner_org.rs`
- Modify: `src/lib.rs`

**Step 1: Create the NER organization extraction module**

Create `src/ner_org.rs`:

```rust
//! Embedded NER-based organization extraction
//!
//! This module uses GLiNER (via gline-rs) to extract organization names
//! from web page content. The model is embedded in the binary at compile time.

#[cfg(feature = "embedded-ner")]
use anyhow::{Result, anyhow};
#[cfg(feature = "embedded-ner")]
use tracing::{debug, info, warn};

/// Model bytes embedded at compile time
#[cfg(feature = "embedded-ner")]
static MODEL_BYTES: &[u8] = include_bytes!("../models/gliner_small.onnx");

#[cfg(feature = "embedded-ner")]
static TOKENIZER_BYTES: &[u8] = include_bytes!("../models/tokenizer.json");

#[cfg(feature = "embedded-ner")]
static CONFIG_BYTES: &[u8] = include_bytes!("../models/config.json");

/// Result of NER organization extraction
#[derive(Debug, Clone)]
pub struct NerOrgResult {
    /// The extracted organization name
    pub organization: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

/// NER-based organization extractor using embedded GLiNER model
#[cfg(feature = "embedded-ner")]
pub struct NerOrganizationExtractor {
    pipeline: gline_rs::NerPipeline,
    min_confidence: f32,
}

#[cfg(feature = "embedded-ner")]
impl NerOrganizationExtractor {
    /// Create a new NER extractor with the embedded model
    pub fn new(min_confidence: f32) -> Result<Self> {
        debug!("Initializing embedded GLiNER NER model...");

        // Write model files to temp directory for gline-rs to load
        let temp_dir = std::env::temp_dir().join("nthpartyfinder_ner");
        std::fs::create_dir_all(&temp_dir)?;

        let model_path = temp_dir.join("model.onnx");
        let tokenizer_path = temp_dir.join("tokenizer.json");
        let config_path = temp_dir.join("config.json");

        // Only write if not already present (caching)
        if !model_path.exists() {
            std::fs::write(&model_path, MODEL_BYTES)?;
            std::fs::write(&tokenizer_path, TOKENIZER_BYTES)?;
            std::fs::write(&config_path, CONFIG_BYTES)?;
            debug!("Wrote model files to {:?}", temp_dir);
        }

        // Initialize gline-rs pipeline
        let pipeline = gline_rs::NerPipeline::from_pretrained(&temp_dir)?;

        info!("GLiNER NER model initialized successfully");

        Ok(Self {
            pipeline,
            min_confidence,
        })
    }

    /// Extract organization name from text content
    pub fn extract_organization(&self, text: &str) -> Result<Option<NerOrgResult>> {
        if text.is_empty() {
            return Ok(None);
        }

        // Truncate to first 2000 chars to limit processing time
        let text_truncated = if text.len() > 2000 {
            &text[..2000]
        } else {
            text
        };

        // Run NER with "organization" entity type
        let entities = self.pipeline.predict(text_truncated, &["organization"])?;

        // Find the highest confidence organization entity
        let best_org = entities
            .iter()
            .filter(|e| e.label.to_lowercase() == "organization")
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));

        match best_org {
            Some(entity) if entity.score >= self.min_confidence => {
                debug!("NER found organization: {} (confidence: {:.2})",
                       entity.text, entity.score);
                Ok(Some(NerOrgResult {
                    organization: clean_org_name(&entity.text),
                    confidence: entity.score,
                }))
            }
            Some(entity) => {
                debug!("NER found organization with low confidence: {} ({:.2} < {:.2})",
                       entity.text, entity.score, self.min_confidence);
                Ok(None)
            }
            None => {
                debug!("NER found no organization entities in text");
                Ok(None)
            }
        }
    }

    /// Extract organization from domain by analyzing web content
    pub async fn extract_from_domain(&self, domain: &str, page_content: Option<&str>) -> Result<Option<NerOrgResult>> {
        // If we have page content, use it directly
        if let Some(content) = page_content {
            return self.extract_organization(content);
        }

        // Otherwise, try to fetch the page
        match crate::web_org::fetch_page_content(domain).await {
            Ok(content) => self.extract_organization(&content),
            Err(e) => {
                debug!("Failed to fetch page for NER: {}", e);
                Ok(None)
            }
        }
    }
}

/// Clean up organization name
fn clean_org_name(name: &str) -> String {
    name.trim()
        .replace('\n', " ")
        .replace('\r', " ")
        .replace('\t', " ")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

// Stub implementation when feature is disabled
#[cfg(not(feature = "embedded-ner"))]
pub struct NerOrganizationExtractor;

#[cfg(not(feature = "embedded-ner"))]
impl NerOrganizationExtractor {
    pub fn new(_min_confidence: f32) -> Result<Self, anyhow::Error> {
        Err(anyhow::anyhow!("embedded-ner feature not enabled"))
    }
}

/// Global NER extractor instance
#[cfg(feature = "embedded-ner")]
static NER_EXTRACTOR: std::sync::OnceLock<NerOrganizationExtractor> = std::sync::OnceLock::new();

/// Initialize the global NER extractor
#[cfg(feature = "embedded-ner")]
pub fn init(min_confidence: f32) -> Result<()> {
    let extractor = NerOrganizationExtractor::new(min_confidence)?;
    NER_EXTRACTOR.set(extractor)
        .map_err(|_| anyhow!("NER extractor already initialized"))?;
    Ok(())
}

#[cfg(not(feature = "embedded-ner"))]
pub fn init(_min_confidence: f32) -> Result<(), anyhow::Error> {
    Ok(()) // No-op when feature disabled
}

/// Check if NER is available
pub fn is_available() -> bool {
    #[cfg(feature = "embedded-ner")]
    {
        NER_EXTRACTOR.get().is_some()
    }
    #[cfg(not(feature = "embedded-ner"))]
    {
        false
    }
}

/// Get the global NER extractor
#[cfg(feature = "embedded-ner")]
pub fn get() -> Option<&'static NerOrganizationExtractor> {
    NER_EXTRACTOR.get()
}

/// Extract organization using the global NER extractor
#[cfg(feature = "embedded-ner")]
pub async fn extract_organization(domain: &str, page_content: Option<&str>) -> Result<Option<NerOrgResult>> {
    match NER_EXTRACTOR.get() {
        Some(extractor) => extractor.extract_from_domain(domain, page_content).await,
        None => Ok(None),
    }
}

#[cfg(not(feature = "embedded-ner"))]
pub async fn extract_organization(_domain: &str, _page_content: Option<&str>) -> Result<Option<NerOrgResult>, anyhow::Error> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_org_name() {
        assert_eq!(clean_org_name("  Stripe, Inc.  "), "Stripe, Inc.");
        assert_eq!(clean_org_name("Company\n\tName"), "Company Name");
    }
}
```

**Step 2: Add module to lib.rs**

Add to `src/lib.rs` after other module declarations:

```rust
pub mod ner_org;
```

**Step 3: Run cargo check**

Run: `cargo check --features embedded-ner`
Expected: Compiles successfully (ignore warnings for now)

**Step 4: Commit**

```bash
git add src/ner_org.rs src/lib.rs
git commit -m "feat: add embedded NER module using GLiNER"
```

---

### Task 4: Integrate NER into organization lookup chain

**Files:**
- Modify: `src/whois.rs`
- Modify: `src/main.rs`
- Modify: `src/cli.rs`

**Step 1: Update whois.rs to use NER instead of SLM**

In `src/whois.rs`, replace the SLM import and usage:

Replace:
```rust
use crate::slm_org;
```

With:
```rust
use crate::ner_org;
```

Replace the SLM fallback section (around line 98-113):
```rust
    // Priority 5: SLM-based extraction (if available)
    if slm_org::is_available().await {
        // First try to get web content for the SLM to analyze
        let page_content = web_org::fetch_page_content(domain).await.ok();
        let content_ref = page_content.as_deref();

        if let Ok(Some(slm_result)) = slm_org::extract_organization(domain, content_ref).await {
            debug!("Found organization via SLM for {}: {} (model: {}, confidence: {:.2})",
                   domain, slm_result.organization, slm_result.model, slm_result.confidence);
            return Ok(OrganizationResult::verified(
                slm_result.organization,
                &format!("slm_{}", slm_result.model),
            ));
        }
        debug!("SLM could not determine organization for {}, using domain fallback", domain);
    }
```

With:
```rust
    // Priority 5: NER-based extraction (if embedded-ner feature enabled)
    if ner_org::is_available() {
        // First try to get web content for NER to analyze
        let page_content = web_org::fetch_page_content(domain).await.ok();
        let content_ref = page_content.as_deref();

        if let Ok(Some(ner_result)) = ner_org::extract_organization(domain, content_ref).await {
            debug!("Found organization via NER for {}: {} (confidence: {:.2})",
                   domain, ner_result.organization, ner_result.confidence);
            return Ok(OrganizationResult::verified(
                ner_result.organization,
                "ner_gliner",
            ));
        }
        debug!("NER could not determine organization for {}, using domain fallback", domain);
    }
```

**Step 2: Update main.rs initialization**

Replace the SLM initialization section (around lines 95-129) with NER initialization:

```rust
    // Initialize embedded NER for organization extraction (if feature enabled)
    #[cfg(feature = "embedded-ner")]
    {
        if !args.disable_slm {  // Reuse the disable flag for backward compatibility
            match ner_org::init(0.6) {
                Ok(()) => {
                    eprintln!("NER organization extraction initialized (embedded GLiNER model)");
                }
                Err(e) => {
                    if args.enable_slm {
                        eprintln!("NER init failed: {}", e);
                    }
                    // Not critical - continue without NER
                }
            }
        }
    }

    #[cfg(not(feature = "embedded-ner"))]
    {
        if args.enable_slm {
            eprintln!("Embedded NER not available (compile with --features embedded-ner)");
        }
    }
```

**Step 3: Update cli.rs help text**

Update the SLM-related args (lines 81-95) to reflect NER:

```rust
    /// Enable embedded NER for organization name extraction
    /// (requires --features embedded-ner at compile time)
    #[arg(long)]
    pub enable_slm: bool,

    /// Disable NER organization extraction
    #[arg(long)]
    pub disable_slm: bool,
```

Remove the `slm_model` and `slm_url` args since they're no longer needed.

**Step 4: Run cargo check**

Run: `cargo check --features embedded-ner`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add src/whois.rs src/main.rs src/cli.rs
git commit -m "feat: integrate embedded NER into org lookup chain"
```

---

### Task 5: Update configuration

**Files:**
- Modify: `config/nthpartyfinder.toml`
- Modify: `src/config.rs`

**Step 1: Update config.rs**

Remove SLM-specific config fields and add NER config. In `src/config.rs`, in `DiscoveryConfig`:

Remove these fields:
```rust
    pub slm_enabled: bool,
    pub slm_url: String,
    pub slm_model: String,
    pub slm_timeout_secs: u64,
    pub slm_min_confidence: f32,
```

Add these fields:
```rust
    /// Enable embedded NER for organization extraction
    /// Only works when compiled with --features embedded-ner
    #[serde(default = "default_ner_enabled")]
    pub ner_enabled: bool,
    /// Minimum confidence (0.0-1.0) for NER extraction
    #[serde(default = "default_ner_min_confidence")]
    pub ner_min_confidence: f32,
```

Add default functions:
```rust
fn default_ner_enabled() -> bool {
    true // Enabled by default when feature is compiled in
}

fn default_ner_min_confidence() -> f32 {
    0.6
}
```

**Step 2: Update nthpartyfinder.toml**

Replace the SLM section (lines 352-384) with:

```toml
# =============================================================================
# Embedded NER Organization Extraction
# =============================================================================
# Uses GLiNER (embedded at compile time) for organization name extraction.
# Requires the binary to be compiled with --features embedded-ner
# No external service required - model is embedded in the binary.

# Enable NER-based organization extraction
# Only works when binary is compiled with --features embedded-ner
# Default: true (enabled when available)
ner_enabled = true

# Minimum confidence level (0.0-1.0) for NER extraction
# Higher values = more reliable but fewer matches
# Default: 0.6
ner_min_confidence = 0.6
```

**Step 3: Commit**

```bash
git add config/nthpartyfinder.toml src/config.rs
git commit -m "feat: update config for embedded NER (remove Ollama SLM)"
```

---

### Task 6: Remove old SLM module

**Files:**
- Delete: `src/slm_org.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs`

**Step 1: Remove slm_org from lib.rs**

Remove this line from `src/lib.rs`:
```rust
pub mod slm_org;
```

**Step 2: Remove slm_org import from main.rs**

Remove this line from `src/main.rs`:
```rust
mod slm_org;
```

**Step 3: Delete slm_org.rs**

```bash
git rm src/slm_org.rs
```

**Step 4: Run cargo check**

Run: `cargo check`
Expected: Compiles without embedded-ner feature

Run: `cargo check --features embedded-ner`
Expected: Compiles with embedded-ner feature

**Step 5: Commit**

```bash
git add src/lib.rs src/main.rs
git commit -m "refactor: remove Ollama-based SLM module (replaced by embedded NER)"
```

---

## Phase 2: Docker Hardened Image Containerization

### Task 7: Create Dockerfile using Docker Hardened Images

**Files:**
- Create: `Dockerfile`
- Create: `Dockerfile.debug`
- Create: `.dockerignore`

**Step 1: Create .dockerignore**

Create `.dockerignore`:

```
target/
.git/
.github/
.claude/
backup/
*.md
!README.md
*.code-workspace
reports/
cache/
```

**Step 2: Create production Dockerfile (true distroless with scratch)**

Create `Dockerfile`:

```dockerfile
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
```

**Step 3: Create debug Dockerfile (with shell for troubleshooting)**

Create `Dockerfile.debug`:

```dockerfile
# =============================================================================
# nthpartyfinder Docker Build - Debug (with shell)
# Uses Docker Hardened Images (dhi.io) for both build and runtime
# =============================================================================

FROM dhi.io/rust:1.83-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV OPENSSL_STATIC=1
ENV OPENSSL_DIR=/usr

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY config/ config/
COPY templates/ templates/
COPY models/ models/

RUN cargo build --release --target x86_64-unknown-linux-musl --features embedded-ner
RUN strip /build/target/x86_64-unknown-linux-musl/release/nthpartyfinder

# Runtime with busybox for debugging capability
FROM dhi.io/busybox:latest

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/nthpartyfinder /usr/local/bin/
COPY --from=builder /build/config/ /etc/nthpartyfinder/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENV NTHPARTYFINDER_CONFIG_DIR=/etc/nthpartyfinder

ENTRYPOINT ["nthpartyfinder"]
CMD ["--help"]
```

**Step 4: Commit**

```bash
git add Dockerfile Dockerfile.debug .dockerignore
git commit -m "feat: add Dockerfiles using DHI (scratch for prod, busybox for debug)"
```

---

### Task 8: Create Docker Compose for development

**Files:**
- Create: `docker-compose.yml`

**Step 1: Create docker-compose.yml**

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  nthpartyfinder:
    build:
      context: .
      dockerfile: Dockerfile
    image: nthpartyfinder:latest
    container_name: nthpartyfinder
    # Mount output directory
    volumes:
      - ./output:/output
    # Example: analyze a domain
    # command: ["-d", "example.com", "-r", "2", "-f", "json", "-o", "/output/results"]

    # Security settings
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL

  # Development build without embedded NER (faster iteration)
  nthpartyfinder-dev:
    build:
      context: .
      dockerfile: Dockerfile.dev
    image: nthpartyfinder:dev
    volumes:
      - ./output:/output
```

**Step 2: Create development Dockerfile (without embedded NER)**

Create `Dockerfile.dev`:

```dockerfile
# Development build without embedded NER (faster, smaller)
FROM docker.io/library/rust:1.83-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV OPENSSL_STATIC=1
ENV OPENSSL_DIR=/usr

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY config/ config/
COPY templates/ templates/

RUN cargo build --release --target x86_64-unknown-linux-musl
RUN strip /build/target/x86_64-unknown-linux-musl/release/nthpartyfinder

FROM dhi.io/alpine:3.22
RUN addgroup -S nthparty && adduser -S -G nthparty nthparty
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/nthpartyfinder /usr/local/bin/
COPY --from=builder /build/config/ /etc/nthpartyfinder/
RUN chown -R nthparty:nthparty /etc/nthpartyfinder
RUN mkdir -p /output && chown nthparty:nthparty /output
USER nthparty
ENV NTHPARTYFINDER_CONFIG_DIR=/etc/nthpartyfinder
WORKDIR /output
ENTRYPOINT ["nthpartyfinder"]
CMD ["--help"]
```

**Step 3: Commit**

```bash
git add docker-compose.yml Dockerfile.dev
git commit -m "feat: add Docker Compose and development Dockerfile"
```

---

### Task 9: Add CI/CD workflow for Docker builds

**Files:**
- Create: `.github/workflows/docker.yml`

**Step 1: Create GitHub Actions workflow**

Create `.github/workflows/docker.yml`:

```yaml
name: Docker Build

on:
  push:
    branches: [main, master]
    tags: ['v*']
  pull_request:
    branches: [main, master]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        if: github.event_name != 'pull_request'
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Download model files
        run: |
          mkdir -p models
          curl -L "https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/main/onnx/model_int8.onnx" -o models/gliner_small.onnx
          curl -L "https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/main/tokenizer.json" -o models/tokenizer.json
          curl -L "https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/main/config.json" -o models/config.json

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}

      - name: Build and push (with embedded NER)
        uses: docker/build-push-action@v5
        with:
          context: .
          push: ${{ github.event_name != 'pull_request' }}
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Build and push (without embedded NER - slim)
        uses: docker/build-push-action@v5
        with:
          context: .
          file: Dockerfile.dev
          push: ${{ github.event_name != 'pull_request' }}
          tags: |
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:slim
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

**Step 2: Commit**

```bash
git add .github/workflows/docker.yml
git commit -m "ci: add GitHub Actions workflow for Docker builds"
```

---

### Task 10: Update README with new build instructions

**Files:**
- Modify: `README.md`

**Step 1: Add Docker and NER sections to README**

Add the following sections to `README.md`:

```markdown
## Installation

### Option 1: Docker (Recommended)

Pull the pre-built image with embedded NER:

```bash
docker pull ghcr.io/your-org/nthpartyfinder:latest
```

Or build locally:

```bash
docker build -t nthpartyfinder .
```

Run analysis:

```bash
docker run -v $(pwd)/output:/output nthpartyfinder -d example.com -r 2 -f json -o /output/results
```

### Option 2: Pre-built Binary

Download from [Releases](https://github.com/your-org/nthpartyfinder/releases).

- **Full version** (`nthpartyfinder-full`): Includes embedded NER (~150MB)
- **Slim version** (`nthpartyfinder`): No NER, smaller size (~15MB)

### Option 3: Build from Source

```bash
# Clone the repository
git clone https://github.com/your-org/nthpartyfinder.git
cd nthpartyfinder

# Build without embedded NER (faster, smaller)
cargo build --release

# Build with embedded NER (requires model files)
./scripts/download-model.sh  # or .ps1 on Windows
cargo build --release --features embedded-ner
```

## Features

### Embedded NER Organization Extraction

When compiled with `--features embedded-ner`, the tool includes a GLiNER model
for intelligent organization name extraction. This requires no external services
and works completely offline.

The NER model is approximately 130MB and is embedded directly in the binary.
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README with Docker and NER build instructions"
```

---

## Phase 3: Testing and Validation

### Task 11: Add integration tests for NER

**Files:**
- Create: `tests/ner_org_tests.rs`

**Step 1: Create NER integration tests**

Create `tests/ner_org_tests.rs`:

```rust
//! Integration tests for embedded NER organization extraction

#[cfg(feature = "embedded-ner")]
mod ner_tests {
    use nthpartyfinder::ner_org;

    #[test]
    fn test_ner_initialization() {
        // Test that NER can be initialized
        let result = ner_org::init(0.6);
        assert!(result.is_ok(), "NER initialization failed: {:?}", result.err());
        assert!(ner_org::is_available(), "NER should be available after init");
    }

    #[test]
    fn test_ner_extracts_organization() {
        // Initialize NER
        let _ = ner_org::init(0.6);

        if let Some(extractor) = ner_org::get() {
            let test_text = "Stripe, Inc. is a financial services company headquartered in San Francisco.";
            let result = extractor.extract_organization(test_text);

            assert!(result.is_ok(), "NER extraction failed: {:?}", result.err());

            if let Ok(Some(org_result)) = result {
                assert!(!org_result.organization.is_empty(), "Organization should not be empty");
                assert!(org_result.confidence > 0.0, "Confidence should be positive");
                println!("Extracted: {} (confidence: {:.2})", org_result.organization, org_result.confidence);
            }
        }
    }
}

#[cfg(not(feature = "embedded-ner"))]
mod ner_disabled_tests {
    use nthpartyfinder::ner_org;

    #[test]
    fn test_ner_not_available_without_feature() {
        assert!(!ner_org::is_available(), "NER should not be available without feature");
    }
}
```

**Step 2: Run tests**

Run: `cargo test --features embedded-ner -- --test-threads=1`
Expected: All tests pass

**Step 3: Commit**

```bash
git add tests/ner_org_tests.rs
git commit -m "test: add integration tests for embedded NER"
```

---

### Task 12: Final verification and cleanup

**Step 1: Run full test suite**

```bash
cargo test
cargo test --features embedded-ner
```

**Step 2: Build release binaries**

```bash
# Slim version
cargo build --release

# Full version with NER
cargo build --release --features embedded-ner
```

**Step 3: Test Docker build**

```bash
docker build -t nthpartyfinder:test .
docker run nthpartyfinder:test --version
```

**Step 4: Test Docker with a domain**

```bash
docker run -v $(pwd)/output:/output nthpartyfinder:test -d google.com -r 1 -f json
```

**Step 5: Final commit**

```bash
git add -A
git commit -m "chore: final cleanup for embedded NER release"
```

---

## Summary

This plan implements:

1. **Embedded GLiNER NER** via gline-rs with `include_bytes!` for true single-binary deployment
2. **Feature flag** (`embedded-ner`) for optional NER inclusion
3. **Docker Hardened Images** using dhi.io Alpine base for minimal attack surface
4. **Multi-stage Docker build** with static musl linking
5. **CI/CD** for automated Docker image builds
6. **Tests** for NER functionality

Binary size expectations:
- Slim (no NER): ~15-20MB
- Full (with NER): ~150-180MB

Docker image size:
- Slim: ~25-30MB
- Full: ~160-190MB
