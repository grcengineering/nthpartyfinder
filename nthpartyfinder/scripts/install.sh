#!/usr/bin/env bash
#
# nthpartyfinder — install helper
# Detects platform, downloads ONNX Runtime, checks optional dependencies,
# and downloads GLiNER model files.
#
set -e

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

ok()   { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()  { printf "${RED}[ERR]${NC}   %s\n" "$*"; }
info() { printf "${BOLD}[INFO]${NC}  %s\n" "$*"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo ""
printf "${BOLD}════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}  nthpartyfinder — install helper${NC}\n"
printf "${BOLD}════════════════════════════════════════════════════${NC}\n"
echo ""

SUMMARY_OK=()
SUMMARY_WARN=()
SUMMARY_ERR=()

# ── 1. Detect OS and architecture ───────────────────────────────────────────
info "Detecting platform..."

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin) OS_LABEL="macOS (darwin)" ;;
  Linux)  OS_LABEL="Linux" ;;
  *)      err "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64)       ARCH_LABEL="x86_64" ;;
  aarch64|arm64) ARCH_LABEL="arm64 (aarch64)" ;;
  *)            err "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ok "Detected platform: $OS_LABEL / $ARCH_LABEL"

# ── 2. Download ONNX Runtime 1.20.1 ─────────────────────────────────────────
ONNX_VERSION="1.20.1"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64|aarch64) ORT_SLUG="osx-arm64" ;;
      x86_64)        ORT_SLUG="osx-x86_64" ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      aarch64|arm64) ORT_SLUG="linux-aarch64" ;;
      x86_64)        ORT_SLUG="linux-x64" ;;
    esac
    ;;
esac

ORT_TARBALL="onnxruntime-${ORT_SLUG}-${ONNX_VERSION}.tgz"
ORT_URL="https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/${ORT_TARBALL}"
ORT_DEST="${PROJECT_DIR}/onnxruntime"

info "ONNX Runtime v${ONNX_VERSION} (${ORT_SLUG})"

if [ -d "$ORT_DEST" ] && [ -n "$(ls -A "$ORT_DEST" 2>/dev/null)" ]; then
  ok "ONNX Runtime already present at ${ORT_DEST}"
  SUMMARY_OK+=("ONNX Runtime")
else
  info "Downloading from ${ORT_URL} ..."
  TMPDIR_ORT="$(mktemp -d)"
  if curl -fSL --progress-bar -o "${TMPDIR_ORT}/${ORT_TARBALL}" "$ORT_URL"; then
    mkdir -p "$ORT_DEST"
    tar xzf "${TMPDIR_ORT}/${ORT_TARBALL}" -C "$ORT_DEST" --strip-components=1
    rm -rf "$TMPDIR_ORT"
    ok "ONNX Runtime extracted to ${ORT_DEST}"
    SUMMARY_OK+=("ONNX Runtime")
  else
    rm -rf "$TMPDIR_ORT"
    err "Failed to download ONNX Runtime"
    SUMMARY_ERR+=("ONNX Runtime download failed")
  fi
fi

case "$OS" in
  Darwin) ORT_LIB_FILE="${ORT_DEST}/lib/libonnxruntime.dylib" ;;
  Linux)  ORT_LIB_FILE="${ORT_DEST}/lib/libonnxruntime.so" ;;
esac

echo ""
info "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
printf "  ${GREEN}export ORT_DYLIB_PATH=\"%s\"${NC}\n" "$ORT_LIB_FILE"
echo ""

# ── 3. Check for whois ──────────────────────────────────────────────────────
info "Checking for whois..."

if which whois >/dev/null 2>&1; then
  ok "whois found: $(which whois)"
  SUMMARY_OK+=("whois")
else
  warn "whois not found"
  case "$OS" in
    Darwin) warn "whois is usually pre-installed. If missing: brew install whois" ;;
    Linux)  warn "Install with: sudo apt-get install whois  (or)  sudo yum install whois" ;;
  esac
  SUMMARY_WARN+=("whois not found")
fi

# ── 4. Check for Chrome / Chromium ──────────────────────────────────────────
info "Checking for Chrome/Chromium..."

CHROME_FOUND=false
for chrome_path in \
  "/Applications/Google Chrome.app" \
  "/usr/bin/chromium" \
  "/usr/bin/google-chrome" \
  "/usr/bin/chromium-browser"; do
  if [ -e "$chrome_path" ]; then
    ok "Chrome/Chromium found: $chrome_path"
    CHROME_FOUND=true
    break
  fi
done

if [ "$CHROME_FOUND" = true ]; then
  SUMMARY_OK+=("Chrome/Chromium")
else
  warn "Chrome/Chromium not found. Optional - needed for --enable-web-org and --enable-web-traffic-discovery"
  case "$OS" in
    Darwin) warn "Install with: brew install --cask google-chrome" ;;
    Linux)  warn "Install with: sudo apt-get install chromium-browser  (or download from https://www.google.com/chrome/)" ;;
  esac
  SUMMARY_WARN+=("Chrome/Chromium not found (optional)")
fi

# ── 5. Check for subfinder ──────────────────────────────────────────────────
info "Checking for subfinder..."

if which subfinder >/dev/null 2>&1; then
  ok "subfinder found: $(which subfinder)"
  SUMMARY_OK+=("subfinder")
else
  warn "subfinder not found. Optional - needed for --enable-subdomain-discovery"
  warn "Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  SUMMARY_WARN+=("subfinder not found (optional)")
fi

# ── 6. Download GLiNER model files ──────────────────────────────────────────
info "Checking for GLiNER model files..."

if [ -f "${PROJECT_DIR}/models/gliner_small.onnx" ]; then
  ok "Model files already present"
  SUMMARY_OK+=("GLiNER model")
else
  info "Downloading GLiNER model files..."
  if [ -x "${SCRIPT_DIR}/download-model.sh" ]; then
    if (cd "$PROJECT_DIR" && bash "${SCRIPT_DIR}/download-model.sh"); then
      ok "Model files downloaded"
      SUMMARY_OK+=("GLiNER model")
    else
      err "Model download failed — check download-model.sh output"
      SUMMARY_ERR+=("GLiNER model download failed")
    fi
  else
    err "download-model.sh not found or not executable at ${SCRIPT_DIR}/download-model.sh"
    SUMMARY_ERR+=("download-model.sh missing")
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
printf "${BOLD}════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}  Summary${NC}\n"
printf "${BOLD}════════════════════════════════════════════════════${NC}\n"

for item in "${SUMMARY_OK[@]}"; do
  printf "  ${GREEN}✓${NC}  %s\n" "$item"
done
for item in "${SUMMARY_WARN[@]}"; do
  printf "  ${YELLOW}!${NC}  %s\n" "$item"
done
for item in "${SUMMARY_ERR[@]}"; do
  printf "  ${RED}✗${NC}  %s\n" "$item"
done

echo ""
if [ ${#SUMMARY_ERR[@]} -gt 0 ]; then
  err "Some required components failed to install. See above for details."
  exit 1
else
  ok "Setup complete. Happy scanning!"
fi
