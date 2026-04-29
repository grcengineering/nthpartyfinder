#!/bin/bash
set -e

COMMIT="8142fb00740ccea973e64b1272949ff48653df5e"
BASE_URL="https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/${COMMIT}"

MODEL_URL="${BASE_URL}/onnx/model_int8.onnx"
TOKENIZER_URL="${BASE_URL}/tokenizer.json"
CONFIG_URL="${BASE_URL}/config.json"

MODEL_SHA256="c76c90920547fd937aaf505e7f2de5ec73168bf1c25abbb55a298104cb061400"
TOKENIZER_SHA256="677203884d026e721115cf0daccf70ec4239545a13d6619e3e66d7151e0c9ce3"
CONFIG_SHA256="8aece71b73ca0fbd6dd121ad755deb736e7757d053ced523c2e4959ff446d3f5"

MODELS_DIR="$(dirname "$0")/../models"
mkdir -p "$MODELS_DIR"

verify_checksum() {
  local file="$1" expected="$2" name="$3"
  actual=$(shasum -a 256 "$file" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "FATAL: SHA-256 mismatch for ${name}" >&2
    echo "  expected: ${expected}" >&2
    echo "  actual:   ${actual}" >&2
    rm -f "$file"
    exit 1
  fi
  echo "  checksum verified: ${name}"
}

echo "Downloading GLiNER small model (INT8 quantized)..."
curl -fSL "$MODEL_URL" -o "$MODELS_DIR/gliner_small.onnx"
verify_checksum "$MODELS_DIR/gliner_small.onnx" "$MODEL_SHA256" "model_int8.onnx"

echo "Downloading tokenizer..."
curl -fSL "$TOKENIZER_URL" -o "$MODELS_DIR/tokenizer.json"
verify_checksum "$MODELS_DIR/tokenizer.json" "$TOKENIZER_SHA256" "tokenizer.json"

echo "Downloading config..."
curl -fSL "$CONFIG_URL" -o "$MODELS_DIR/config.json"
verify_checksum "$MODELS_DIR/config.json" "$CONFIG_SHA256" "config.json"

echo "Done! Model files:"
ls -lh "$MODELS_DIR"
