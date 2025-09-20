#!/usr/bin/env bash
set -eo pipefail

# Defaults
SPN_ID="${SPN_ID:-}"

# Parse command line arguments
while getopts "hg:s:p:" opt; do
    case $opt in
        g)
            AZURE_RESOURCE_GROUP="$OPTARG"
            ;;
        s)
            AZURE_SUBSCRIPTION_ID="$OPTARG"
            ;;
        p)
            SPN_ID="$OPTARG"
            ;;
        *|h)
            echo "Usage: $0 [ -s subscription_id ] -g resource_group -p service_principal_id" >&2
            echo "       Alternatively, set AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, and SPN_ID environment variables." >&2
            exit 1
            ;;
    esac
done

# Set subscription ID from az CLI if not provided nor set in environment
AZURE_SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}"

# Check required environment variables
REQUIRED_VARS=(
    AZURE_RESOURCE_GROUP
    AZURE_SUBSCRIPTION_ID
)

for VAR in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!VAR:-}" ]; then
        echo "Error: Environment variable $VAR is not set." >&2
        exit 1
    fi
done

# Assign RBAC role to the defined Service Principal, if AZURE_* variables are set
if [ -n "$SPN_ID"] || [ -n "$AZURE_CLIENT_ID" ]; then
    if [ -z "$SPN_ID" ]; then
        SPN_ID="$AZURE_CLIENT_ID"
    fi

    echo "Assigning 'Key Vault Certificates Officer' role to Service Principal '$SPN_ID' in resource group '$AZURE_RESOURCE_GROUP'..."
    ASSIGNMENT_ID=$(az role assignment create \
        --subscription $AZURE_SUBSCRIPTION_ID \
        --assignee "$SPN_ID" \
        --role "Key Vault Certificates Officer" \
        --scope "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$AZURE_RESOURCE_GROUP" \
        --query id -o tsv
    )
    echo "Role assignment completed."
    echo "Role Assignment ID: $ASSIGNMENT_ID"
else
    echo "Service Principal ID not provided. Skipping RBAC role assignment." >&2
fi
