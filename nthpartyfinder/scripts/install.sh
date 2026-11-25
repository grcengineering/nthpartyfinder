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
# The GitHub release tarballs for 1.20.1 now return 404, so we use Microsoft's
# official Microsoft.ML.OnnxRuntime NuGet package. It is a ZIP holding every
# platform's native library under runtimes/<rid>/native/, and its digest is
# fixed, so we pin it. Keep 1.20.x: the ort crate is built against that API.
ONNX_VERSION="1.20.1"
ORT_NUPKG_SHA256="9c32108e9a1c78b090a95c2a219f244dd5f067d4caf68fb0f967103f3f20839c"
ORT_URL="https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/${ONNX_VERSION}/microsoft.ml.onnxruntime.${ONNX_VERSION}.nupkg"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64|aarch64) ORT_RID="osx-arm64" ;;
      x86_64)        ORT_RID="osx-x64" ;;
    esac
    ORT_FILES="libonnxruntime.dylib"
    ;;
  Linux)
    case "$ARCH" in
      aarch64|arm64) ORT_RID="linux-arm64" ;;
      x86_64)        ORT_RID="linux-x64" ;;
    esac
    ORT_FILES="libonnxruntime.so libonnxruntime_providers_shared.so"
    ;;
esac

ORT_DEST="${PROJECT_DIR}/onnxruntime"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    return 1
  fi
}

install_ort() {
  local tmp="$1"
  local pkg="${tmp}/onnxruntime.nupkg"
  if ! command -v unzip >/dev/null 2>&1; then
    err "unzip is needed to unpack ONNX Runtime (e.g. sudo apt-get install unzip)"
    return 1
  fi
  curl -fSL --progress-bar -o "$pkg" "$ORT_URL" || { err "Download failed"; return 1; }
  local actual
  actual="$(sha256_of "$pkg")" || { err "No sha256sum or shasum found to verify the download"; return 1; }
  if [ "$actual" != "$ORT_NUPKG_SHA256" ]; then
    err "Checksum mismatch (expected ${ORT_NUPKG_SHA256}, got ${actual}); not installing"
    return 1
  fi
  local entries=()
  for f in $ORT_FILES; do entries+=("runtimes/${ORT_RID}/native/${f}"); done
  mkdir -p "${tmp}/x"
  unzip -q -j "$pkg" "${entries[@]}" -d "${tmp}/x" || { err "Could not unpack ${ORT_RID} libraries"; return 1; }
  mkdir -p "${ORT_DEST}/lib"
  for f in $ORT_FILES; do mv "${tmp}/x/${f}" "${ORT_DEST}/lib/${f}"; done
}

info "ONNX Runtime v${ONNX_VERSION} (${ORT_RID})"

if [ -d "$ORT_DEST" ] && [ -n "$(ls -A "$ORT_DEST" 2>/dev/null)" ]; then
  ok "ONNX Runtime already present at ${ORT_DEST}"
  SUMMARY_OK+=("ONNX Runtime")
else
  info "Downloading from ${ORT_URL} ..."
  TMPDIR_ORT="$(mktemp -d)"
  if install_ort "$TMPDIR_ORT"; then
    rm -rf "$TMPDIR_ORT"
    ok "ONNX Runtime verified and extracted to ${ORT_DEST}"
    SUMMARY_OK+=("ONNX Runtime")
  else
    rm -rf "$TMPDIR_ORT"
    err "Failed to install ONNX Runtime"
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
