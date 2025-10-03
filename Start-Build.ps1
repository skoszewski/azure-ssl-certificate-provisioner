[CmdletBinding()]
param ()

Write-Host "Starting build process..."

if (-not (Test-Path -Path "$PSScriptRoot\build")) {
    New-Item -ItemType Directory -Path "$PSScriptRoot\build" | Out-Null
}

$env:GOOS="windows"
$env:GOARCH="amd64"

go build -o "$PSScriptRoot\build\azure-ssl-certificate-provisioner.exe" .

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed."
    exit $LASTEXITCODE
}

Write-Host "Build completed successfully. Output located at '$PSScriptRoot\build\azure-ssl-certificate-provisioner.exe'"
