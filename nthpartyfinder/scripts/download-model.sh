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
