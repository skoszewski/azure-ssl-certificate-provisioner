[CmdletBinding(PositionalBinding = $false)]
param (
    [ValidateSet("amd64", "arm64")]
    [string]$Architecture = "amd64",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$args
)

function Import-EnvFile {
    [CmdletBinding()]
    param (
        [string]$EnvFilePath    
    )
    
    Get-Content -Path $EnvFilePath | ForEach-Object {
        if ($_ -match '^#') {
            # Skip comment lines
            return
        }
        if ($_ -match '^$') {
            # Skip empty lines
            return
        }
        if ($_ -match '^[A-Za-z_][A-Za-z0-9_]*=.*$') {
            $parts = $_ -split '=', 2
            $key = $parts[0]
            $value = $parts[1]
            
            # Remove surrounding quotes if present (Docker-style env files)
            if ($value -match '^".*"$') {
                $value = $value.Trim('"')
            } elseif ($value -match "^'.*'$") {
                $value = $value.Trim("'")
            }
            
            [System.Environment]::SetEnvironmentVariable($key, $value)
            Write-Verbose "Set environment variable: $key = $value"
        }
        else {
            Write-Warning "Ignoring invalid or non-Docker env line: $_"
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

$imageName = "${env:REPOSITORY}/${env:IMAGE_NAME}:$Tag"
Write-Verbose "Running container image: $imageName"

& $containerTool run `
  -e AZURE_TENANT_ID `
  -e AZURE_CLIENT_ID `
  -e AZURE_CLIENT_SECRET `
  -e AZURE_SUBSCRIPTION_ID `
  -e AZURE_RESOURCE_GROUP `
  -e AZURE_KEY_VAULT_URL `
  -e LEGO_EMAIL `
  -v ./config.yaml:/root/config.yaml:ro `
  -v ./.lego:/root/.lego `
  --entrypoint "/bin/sh" `
  --rm -it "$imageName" $args
if ($?) {
    Write-Host "Container image ran successfully."
} else {
    Write-Error "Failed to run the container image."
    exit 1
}