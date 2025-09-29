[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$args
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
Write-Verbose "Running container image: $imageName"

$ENVIRONMENT_VARIABLES = @(
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_RESOURCE_GROUP",
    "LEGO_EMAIL",
    "DNS_RESOLVERS"
)

$ENV_PARAMS = $ENVIRONMENT_VARIABLES | ForEach-Object { 
    $varName = $_
    $varValue = [Environment]::GetEnvironmentVariable($varName)
    "-e"
    "$varName=$varValue"
}

& $containerTool run --rm -it -v ./root:/root:rw @ENV_PARAMS "$imageName" $args
if ($?) {
    Write-Host "Container image ran successfully."
} else {
    Write-Error "Failed to run the container image."
    exit 1
}
