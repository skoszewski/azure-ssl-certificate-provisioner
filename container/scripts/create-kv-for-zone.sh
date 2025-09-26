#!/usr/bin/env bash
set -eo pipefail

# Defaults
LOCATION=""

# Parse command line arguments
while getopts "hg:z:s:l:" opt; do
    case $opt in
        g)
            AZURE_RESOURCE_GROUP="$OPTARG"
            ;;
        z)
            AZURE_DNS_ZONE="$OPTARG"
            ;;
        s)
            AZURE_SUBSCRIPTION_ID="$OPTARG"
            ;;
        l)
            LOCATION="$OPTARG"
            ;;
        *|h)
            echo "Usage: $0 -s subscription_id -g resource_group -z dns_zone -l location" >&2
            echo "       Alternatively, set AZURE_RESOURCE_GROUP, AZURE_DNS_ZONE, and AZURE_SUBSCRIPTION_ID environment variables." >&2
            exit 1
            ;;
    esac
done

# Set subscription ID from Azure CLI if not provided nor set in environment
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

LOCATION="${LOCATION:-$(az group show --subscription $AZURE_SUBSCRIPTION_ID --name "$AZURE_RESOURCE_GROUP" --query "location" -o tsv)}"

# Check if the resource group exists
if ! az group show --subscription $AZURE_SUBSCRIPTION_ID --name "$AZURE_RESOURCE_GROUP" &> /dev/null; then
    echo "Error: Resource group '$AZURE_RESOURCE_GROUP' does not exist." >&2
    exit 1
fi

KEY_VAULT_NAME="kv-${AZURE_RESOURCE_GROUP}"

if ! az keyvault show --subscription $AZURE_SUBSCRIPTION_ID --name "$KEY_VAULT_NAME" --resource-group "$AZURE_RESOURCE_GROUP" &> /dev/null; then
    echo "Creating Key Vault '$KEY_VAULT_NAME' in resource group '$AZURE_RESOURCE_GROUP'..."
    KV_URI=$(az keyvault create \
        --subscription $AZURE_SUBSCRIPTION_ID \
        --name "$KEY_VAULT_NAME" \
        --resource-group "$AZURE_RESOURCE_GROUP" \
        --location "$LOCATION" \
        --query "properties.vaultUri" -o tsv)
    echo "Created Key Vault at URI: $KV_URI"
else
    echo "Key Vault '$KEY_VAULT_NAME' already exists in resource group '$AZURE_RESOURCE_GROUP'." >&2
fi
