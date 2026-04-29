$ErrorActionPreference = "Stop"

$Commit = "8142fb00740ccea973e64b1272949ff48653df5e"
$BaseUrl = "https://huggingface.co/onnx-community/gliner_small-v2.1/resolve/$Commit"

$ModelUrl = "$BaseUrl/onnx/model_int8.onnx"
$TokenizerUrl = "$BaseUrl/tokenizer.json"
$ConfigUrl = "$BaseUrl/config.json"

$ModelSha256 = "c76c90920547fd937aaf505e7f2de5ec73168bf1c25abbb55a298104cb061400"
$TokenizerSha256 = "677203884d026e721115cf0daccf70ec4239545a13d6619e3e66d7151e0c9ce3"
$ConfigSha256 = "8aece71b73ca0fbd6dd121ad755deb736e7757d053ced523c2e4959ff446d3f5"

$ModelsDir = Join-Path $PSScriptRoot "..\models"
New-Item -ItemType Directory -Force -Path $ModelsDir | Out-Null

function Test-FileChecksum {
    param([string]$FilePath, [string]$Expected, [string]$Name)
    $actual = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $Expected) {
        Remove-Item -Path $FilePath -Force
        throw "FATAL: SHA-256 mismatch for ${Name}`n  expected: ${Expected}`n  actual:   ${actual}"
    }
    Write-Host "  checksum verified: $Name"
}

Write-Host "Downloading GLiNER small model (INT8 quantized)..."
$modelPath = Join-Path $ModelsDir "gliner_small.onnx"
Invoke-WebRequest -Uri $ModelUrl -OutFile $modelPath
Test-FileChecksum -FilePath $modelPath -Expected $ModelSha256 -Name "model_int8.onnx"

Write-Host "Downloading tokenizer..."
$tokenizerPath = Join-Path $ModelsDir "tokenizer.json"
Invoke-WebRequest -Uri $TokenizerUrl -OutFile $tokenizerPath
Test-FileChecksum -FilePath $tokenizerPath -Expected $TokenizerSha256 -Name "tokenizer.json"

Write-Host "Downloading config..."
$configPath = Join-Path $ModelsDir "config.json"
Invoke-WebRequest -Uri $ConfigUrl -OutFile $configPath
Test-FileChecksum -FilePath $configPath -Expected $ConfigSha256 -Name "config.json"

Write-Host "Done! Model files saved to $ModelsDir"
Get-ChildItem $ModelsDir | Format-Table Name, Length
