[CmdletBinding()]
param (
    [switch]$Push = $false
)

# Check, if build_env.ps1 exists
if (-not (Test-Path -Path "$PSScriptRoot\build_env.ps1")) {
    Write-Error "build_env.ps1 file not found!"
    exit 1
}

Write-Verbose "Loading build environment from `"$PSScriptRoot\build_env.ps1`""

# Include build time environment variables
. "$PSScriptRoot\build_env.ps1"

if ( "$env:REPOSITORY" -eq "" || "$env:IMAGE_NAME" -eq "" ) {
    Write-Error "REPOSITORY or IMAGE_NAME not set in build_env.ps1!"
    exit 1
}

# Determine architecture-specific tag
if ( "$env:PROCESSOR_ARCHITECTURE" -eq "AMD64" ) {
    $tag = "latest"
} elseif ( "$env:PROCESSOR_ARCHITECTURE" -eq "ARM64" ) {
    $tag = "arm64"
} else {
    Write-Error "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
    exit 1
}

# Check if Podman or Docker is installed
if (Get-Command podman -ErrorAction SilentlyContinue) {
    $containerTool = "podman"
} elseif (Get-Command docker -ErrorAction SilentlyContinue) {
    $containerTool = "docker"
} else {
    Write-Error "Neither Podman nor Docker is installed!"
    exit 1
}

$imageName = "${env:REPOSITORY}/${env:IMAGE_NAME}:$tag"
Write-Verbose "Building container image: $imageName"

& $containerTool build --build-arg REPOSITORY=$env:REPOSITORY --build-arg TAG=$tag -t "$imageName" .
if ($?) {
    Write-Host "Container image built successfully."
} else {
    Write-Error "Failed to build the container image."
    exit 1
}

if ($Push) {
    Write-Verbose "Pushing container image: $imageName"
    & $containerTool push "$imageName"
    if ($?) {
        Write-Host "Container image pushed successfully."
    } else {
        Write-Error "Failed to push the container image."
        exit 1
    }
}
