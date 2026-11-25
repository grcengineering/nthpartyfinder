# Download ONNX Runtime for Windows
# This is required when building with the embedded-ner feature on Windows
# The load-dynamic feature loads the DLL at runtime via ORT_DYLIB_PATH
#
# The GitHub release zips for 1.20.1 now return 404, so this uses Microsoft's
# official Microsoft.ML.OnnxRuntime NuGet package. It is a ZIP holding every
# platform's native library under runtimes/<rid>/native/, and its digest is
# fixed, so we pin it. Keep 1.20.x: the ort crate is built against that API.

$ErrorActionPreference = "Stop"

$OrtVersion = "1.20.1"
$OrtSha256 = "9c32108e9a1c78b090a95c2a219f244dd5f067d4caf68fb0f967103f3f20839c"
$OrtUrl = "https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/$OrtVersion/microsoft.ml.onnxruntime.$OrtVersion.nupkg"
$OrtRid = "win-x64"
$OrtFiles = @("onnxruntime.dll", "onnxruntime_providers_shared.dll")

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$OrtDir = Join-Path $ProjectDir "onnxruntime"
$LibDir = Join-Path $OrtDir "onnxruntime-win-x64-$OrtVersion\lib"

Write-Host "Downloading ONNX Runtime v$OrtVersion for Windows..."

New-Item -ItemType Directory -Force -Path $LibDir | Out-Null

$PkgPath = Join-Path $OrtDir "onnxruntime.nupkg"
Invoke-WebRequest -Uri $OrtUrl -OutFile $PkgPath -UseBasicParsing

try {
    Write-Host "Verifying checksum..."
    $Actual = (Get-FileHash -Path $PkgPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $OrtSha256) {
        throw "Checksum mismatch (expected $OrtSha256, got $Actual); not installing"
    }

    Write-Host "Extracting..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Zip = [System.IO.Compression.ZipFile]::OpenRead($PkgPath)
    try {
        foreach ($File in $OrtFiles) {
            $EntryName = "runtimes/$OrtRid/native/$File"
            $Entry = $Zip.GetEntry($EntryName)
            if ($null -eq $Entry) {
                throw "Package is missing $EntryName"
            }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($Entry, (Join-Path $LibDir $File), $true)
        }
    }
    finally {
        $Zip.Dispose()
    }
}
finally {
    Remove-Item $PkgPath -Force -ErrorAction SilentlyContinue
}

# Also copy the DLLs to the project root, next to where the binary usually runs
foreach ($File in $OrtFiles) {
    Copy-Item (Join-Path $LibDir $File) -Destination $ProjectDir -Force
}
Write-Host "Copied onnxruntime.dll to project root"

Write-Host ""
Write-Host "ONNX Runtime installed successfully!"
Write-Host ""
Write-Host "To run nthpartyfinder with NER on Windows, either:"
Write-Host "  1. Set ORT_DYLIB_PATH environment variable:"
Write-Host "     `$env:ORT_DYLIB_PATH = '$ProjectDir\onnxruntime.dll'"
Write-Host ""
Write-Host "  2. Or copy onnxruntime.dll to the same directory as the executable"
Write-Host ""
