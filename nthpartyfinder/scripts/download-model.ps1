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
