#!/usr/bin/env bash
set -euo pipefail

AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-}"
AZURE_DNS_ZONE="${AZURE_DNS_ZONE:-}"
DAYS_REMAINING_THRESHOLD=${DAYS_REMAINING_THRESHOLD:-7}
LEGO_PATH="$(pwd)/.lego"

# Parse command line arguments
while getopts "hs:g:z:" opt; do
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
        *|h)
            echo "Usage: $0 [ -s subscription_id ] -g resource_group [ -z dns_zone ]" >&2
            echo "       Alternatively, set AZURE_RESOURCE_GROUP, AZURE_DNS_ZONE, and AZURE_SUBSCRIPTION_ID environment variables." >&2
            echo "       AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET environment variables must be set for lego DNS plugin authentication." >&2
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
    AZURE_TENANT_ID
    AZURE_CLIENT_ID
    AZURE_CLIENT_SECRET
    LEGO_EMAIL
)

for VAR in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!VAR:-}" ]; then
        echo "Error: Environment variable $VAR is not set." >&2
        exit 1
    fi
done

# Enumerate zones in the resource group if AZURE_DNS_ZONE is not provided
if [ -z "$AZURE_DNS_ZONE" ]; then
    echo "Fetching DNS zones in resource group '$AZURE_RESOURCE_GROUP'..."
    ZONES=$(az network dns zone list \
        --subscription "$AZURE_SUBSCRIPTION_ID" \
        --resource-group "$AZURE_RESOURCE_GROUP" \
        --query "[].name" -o tsv
    )
    if [ -z "$ZONES" ]; then
        echo "No DNS zones found in resource group '$AZURE_RESOURCE_GROUP'." >&2
        exit 1
    fi
else
    ZONES="$AZURE_DNS_ZONE"
fi

# Enumerate zones
for ZONE in $ZONES; do
    echo "Processing DNS zone '$ZONE'..."
    RECORDS=$(az network dns record-set list \
        --subscription "$AZURE_SUBSCRIPTION_ID" \
        --resource-group "$AZURE_RESOURCE_GROUP" \
        --zone-name "$ZONE" \
        --query "[?metadata.acme=='true' && (ends_with(type, '/A') || ends_with(type, '/CNAME'))].name" -o tsv
    )

    VAULT_NAME="kv-${AZURE_RESOURCE_GROUP}"

    # Enumerate records
    for RECORD in $RECORDS; do
        echo "Processing: $RECORD.$ZONE..."
        NEED_UPLOAD=""
        CERT_NAME="cert-${RECORD//./-}-${ZONE//./-}"
        LEGO_PFX_PATH="$LEGO_PATH/certificates/${RECORD}.$ZONE.pfx"
        LEGO_CRT_PATH="$LEGO_PATH/certificates/${RECORD}.$ZONE.crt"

        # Check if the certificate already exists in Key Vault
        if [ -f "$LEGO_PFX_PATH" ]; then
            # Try to renew the certificate if it exists
            echo "Certificate found, renewing (if needed)..."

            # Request the certificate using lego
            if ! lego \
                --accept-tos \
                --server https://acme-staging-v02.api.letsencrypt.org/directory \
                --email "$LEGO_EMAIL" \
                --path "$LEGO_PATH" \
                --dns azuredns \
                --domains "$RECORD.$ZONE" \
                renew --days "$DAYS_REMAINING_THRESHOLD"
            then
                echo "Error: Failed to renew certificate for $RECORD.$ZONE" >&2
                continue
            fi
        else
            # Certificate does not exist, will request a new one
            echo "Certificate not found, will request new certificate."

            # Request the certificate using lego
            if ! lego \
                --accept-tos \
                --server https://acme-staging-v02.api.letsencrypt.org/directory \
                --email "$LEGO_EMAIL" \
                --path "$LEGO_PATH" \
                --dns azuredns \
                --domains "$RECORD.$ZONE" \
                --pfx \
                --pfx.format "SHA256" \
                run
            then
                echo "Error: Failed to request certificate for $RECORD.$ZONE" >&2
                continue
            fi
        fi

        # Check, if the certificate in $LEGO_PFX_PATH exists and has a different thumbprint than the one in Key Vault
        if [ -f "$LEGO_PFX_PATH" ]; then
            # Get thumbprint of the certificate in Key Vault
            EXISTING_THUMBPRINT=$(az keyvault certificate show \
                --vault-name "kv-${AZURE_RESOURCE_GROUP}" \
                --name "$CERT_NAME" \
                --query "x509ThumbprintHex" -o tsv 2>/dev/null || echo "")

            # Get thumbprint of the newly obtained certificate
            NEW_THUMBPRINT=$(openssl x509 -noout -fingerprint -in "$LEGO_CRT_PATH" | cut -d= -f2 | tr -d ':')

            if [ "$EXISTING_THUMBPRINT" != "$NEW_THUMBPRINT" ]; then
                az keyvault certificate import \
                    --vault-name "kv-${AZURE_RESOURCE_GROUP}" \
                    --name "cert-${RECORD//./-}-${ZONE//./-}" \
                    --file "$LEGO_PFX_PATH" \
                    --password "changeit"
            else
                echo "No upload needed for $RECORD.$ZONE."
            fi
        fi
    done
done

# az keyvault certificate show --vault-name "$VAULT_NAME" --name "$CERT_NAME" &> /dev/null