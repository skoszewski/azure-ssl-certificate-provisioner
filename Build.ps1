[CmdletBinding()]
param (
    [switch]$Push = $false,
    [ValidateSet("amd64", "arm64")]
    [string]$Architecture = "amd64"
)

function Import-EnvFile {
    [CmdletBinding()]
    param (
        [string]$EnvFilePath    
    )
    
    Get-Content -Path $EnvFilePath | ForEach-Object {
        if ($_ -match '^\s*#') {
            # Skip comment lines
            return
        }

        if ($_ -match '^\s*$') {
            # Skip empty lines
            return
        }

        $parts = $_ -split '=', 2
    
        if ($parts.Length -eq 2) {
            $key = $parts[0].Trim()
            $value = $parts[1].Trim()
            [System.Environment]::SetEnvironmentVariable($key, $value)
            Write-Verbose "Set environment variable: $key"
        }
        else {
            Write-Warning "Ignoring invalid line in env file: $_"
        }
    }
}

# Check, if build.env exists
if (-not (Test-Path -Path "$PSScriptRoot\build.env")) {
    Write-Error "build.env file not found!"
    exit 1
}

Write-Verbose "Loading build environment from `"$PSScriptRoot\build.env`""

# Include build time environment variables
Import-EnvFile -EnvFilePath "$PSScriptRoot\build.env"

if ( "$env:REPOSITORY" -eq "" || "$env:IMAGE_NAME" -eq "" ) {
    Write-Error "REPOSITORY or IMAGE_NAME not set in build.env!"
    exit 1
}

# Determine architecture-specific tag
if ( "$Architecture" -eq "amd64" ) {
    $Tag = "latest"
} elseif ( "$Architecture" -eq "arm64" ) {
    $Tag = "arm64"
} else {
    Write-Error "Unsupported architecture: $Architecture"
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

Write-Verbose "Building for Linux/$Architecture"
$env:GOOS = "linux"
$env:GOARCH = $Architecture
go build -o ./build/azure-ssl-certificate-provisioner-linux .

$imageName = "${env:REPOSITORY}/${env:IMAGE_NAME}:$Tag"
Write-Verbose "Building container image: $imageName"

& $containerTool build --platform linux/$Architecture -t "$imageName" .
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
