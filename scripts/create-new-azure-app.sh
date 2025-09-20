#!/usr/bin/env bash
set -euo pipefail

# Default values
AZURE_APP_NAME="$1"

if [ -z "$AZURE_APP_NAME" ]; then
    echo "Usage: $0 azure_app_name" >&2
    exit 1
fi

# Create an Azure AD application
read AZURE_APP_ID AZURE_CLIENT_ID < <(az ad app create --display-name "$AZURE_APP_NAME" --query '{id:id,appid:appId}' -o tsv)
# Create a service principal for the application
read SPN_ID < <(az ad sp create --id "$AZURE_APP_ID" --query id -o tsv)
# Create a client secret for the application
read AZURE_CLIENT_SECRET < <(az ad app credential reset --id "$AZURE_APP_ID" --query password -o tsv)
# define tenant ID
AZURE_TENANT_ID=$(az account show --query tenantId -o tsv)

# print values required to authenticate SPN to the console
cat <<EOF
# Environment variables to use the \"$AZURE_APP_NAME\" service principal
export AZURE_TENANT_ID="$AZURE_TENANT_ID"
export AZURE_CLIENT_ID="$AZURE_CLIENT_ID"
export AZURE_CLIENT_SECRET="$AZURE_CLIENT_SECRET"
EOF
