#!/usr/bin/env bash
set -eo pipefail

# Defaults
MULTIPLE_KV=""
LOCATION="$(az group show --name "$AZURE_RESOURCE_GROUP" --query location -o tsv)"

while getopts "g:z:s:mp:l:" opt; do
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
        m)
            MULTIPLE_KV=1 # Enable creation of a Key Vault for each DNS zone
            ;;
        p)
            AZURE_KEY_VAULT_POLICY="$OPTARG"
            ;;
        l)
            LOCATION="$OPTARG"
            ;;
        *)
            echo "Usage: $0 -g resource_group -z dns_zone -s subscription_id" >&2
            echo "       Alternatively, set AZURE_RESOURCE_GROUP, AZURE_DNS_ZONE, and AZURE_SUBSCRIPTION_ID environment variables." >&2
            exit 1
            ;;
    esac
done

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

# Check if the resource group exists
if ! az group show --subscription $AZURE_SUBSCRIPTION_ID --name "$AZURE_RESOURCE_GROUP" &> /dev/null; then
    echo "Error: Resource group '$AZURE_RESOURCE_GROUP' does not exist." >&2
    exit 1
fi

if [ -z "$MULTIPLE_KV" ]; then
    # Multiple Key Vaults not enabled, create a single Key Vault for all zones in the resource group 
    KEY_VAULT_NAME="kv-${AZURE_RESOURCE_GROUP}"
    if ! az keyvault show --subscription $AZURE_SUBSCRIPTION_ID --name "$KEY_VAULT_NAME" --resource-group "$AZURE_RESOURCE_GROUP" &> /dev/null; then
        echo "Creating Key Vault '$KEY_VAULT_NAME' in resource group '$AZURE_RESOURCE_GROUP'..."
        KV_URI=$(az keyvault create --subscription $AZURE_SUBSCRIPTION_ID --name "$KEY_VAULT_NAME" --resource-group "$AZURE_RESOURCE_GROUP" --location "$LOCATION" --query "properties.vaultUri" -o tsv)
        echo "Created Key Vault at URI: $KV_URI"
    else
        echo "Key Vault '$KEY_VAULT_NAME' already exists in resource group '$AZURE_RESOURCE_GROUP'." >&2
    fi
else
    DNS_ZONES=""
    if [ -z "$AZURE_DNS_ZONE" ]; then
        # No DNS zone privided, enumerate all zones in the resource group
        echo "No DNS zone provided. Enumerating all DNS zones in resource group '$AZURE_RESOURCE_GROUP'..."
        DNS_ZONES=$(az network dns zone list --subscription $AZURE_SUBSCRIPTION_ID --resource-group "$AZURE_RESOURCE_GROUP" --query "[].name" -o tsv)
        if [ -z "$DNS_ZONES" ]; then
            echo "Error: No DNS zones found in resource group '$AZURE_RESOURCE_GROUP'." >&2
            exit 1
        fi
    else
        DNS_ZONES="$AZURE_DNS_ZONE"
    fi

    for ZONE in $DNS_ZONES; do
        KEY_VAULT_NAME="kv-${ZONE//./-}"
        if ! az keyvault show --subscription $AZURE_SUBSCRIPTION_ID --name "$KEY_VAULT_NAME" --resource-group "$AZURE_RESOURCE_GROUP" &> /dev/null; then
            echo "Creating Key Vault '$KEY_VAULT_NAME' for DNS zone '$ZONE' in resource group '$AZURE_RESOURCE_GROUP'..."
            KV_URI=$(az keyvault create --subscription $AZURE_SUBSCRIPTION_ID --name "$KEY_VAULT_NAME" --resource-group "$AZURE_RESOURCE_GROUP" --location "$LOCATION" --query "properties.vaultUri" -o tsv)
            echo "Created Key Vault at URI: $KV_URI"
        else
            echo "Key Vault '$KEY_VAULT_NAME' already exists in resource group '$AZURE_RESOURCE_GROUP'." >&2
        fi
    done
fi

# Assign RBAC role to the defined Service Principal, if AZURE_* variables are set