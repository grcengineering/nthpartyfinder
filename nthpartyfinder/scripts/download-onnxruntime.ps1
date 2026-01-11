# Download ONNX Runtime for Windows
# This is required when building with the embedded-ner feature on Windows
# The load-dynamic feature loads the DLL at runtime via ORT_DYLIB_PATH

$OrtVersion = "1.19.2"
$OrtUrl = "https://github.com/microsoft/onnxruntime/releases/download/v$OrtVersion/onnxruntime-win-x64-$OrtVersion.zip"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$OrtDir = Join-Path $ProjectDir "onnxruntime"

Write-Host "Downloading ONNX Runtime v$OrtVersion for Windows..."

# Create directory
New-Item -ItemType Directory -Force -Path $OrtDir | Out-Null

# Download
$ZipPath = Join-Path $OrtDir "onnxruntime.zip"
Invoke-WebRequest -Uri $OrtUrl -OutFile $ZipPath

# Extract
Write-Host "Extracting..."
Expand-Archive -Path $ZipPath -DestinationPath $OrtDir -Force

# Find the extracted directory and move DLL to project root
$ExtractedDir = Get-ChildItem -Path $OrtDir -Directory | Where-Object { $_.Name -like "onnxruntime-win-*" } | Select-Object -First 1
if ($ExtractedDir) {
    $DllPath = Join-Path $ExtractedDir.FullName "lib\onnxruntime.dll"
    if (Test-Path $DllPath) {
        Copy-Item $DllPath -Destination $ProjectDir
        Write-Host "Copied onnxruntime.dll to project root"
    }
}

# Clean up
Remove-Item $ZipPath -Force

Write-Host ""
Write-Host "ONNX Runtime installed successfully!"
Write-Host ""
Write-Host "To run nthpartyfinder with NER on Windows, either:"
Write-Host "  1. Set ORT_DYLIB_PATH environment variable:"
Write-Host "     `$env:ORT_DYLIB_PATH = '$ProjectDir\onnxruntime.dll'"
Write-Host ""
Write-Host "  2. Or copy onnxruntime.dll to the same directory as the executable"
Write-Host ""
