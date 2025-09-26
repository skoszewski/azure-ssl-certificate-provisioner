##!/usr/bin/env bash

set -euo pipefail

# Default values
VAULT_NAME="Private"
ITEM_NAME=""
ZONE_INFO=""

# Parse options
while getopts "v:n:z" opt; do
    case $opt in
        v)
            VAULT_NAME="$OPTARG"
            ;;
        n)
            ITEM_NAME="$OPTARG"
            ;;
        z)
            ZONE_INFO=1
            ;;
        *)
            echo "Usage: $0 [-v vault_name] -n item_name" >&2
            exit 1
            ;;
    esac
done

if [ -z "$ITEM_NAME" ]; then
    echo "Error: -n (item name) is required." >&2
    echo "Usage: $0 [-v vault_name] -n item_name" >&2
    exit 1
fi

TEMPLATE=$(cat <<EOF
export AZURE_TENANT_ID="{{ op://$VAULT_NAME/$ITEM_NAME/tenant id }}"
export AZURE_CLIENT_ID="{{ op://$VAULT_NAME/$ITEM_NAME/client id }}"
export AZURE_CLIENT_SECRET="{{ op://$VAULT_NAME/$ITEM_NAME/client secret }}"
EOF
)

if [ ! -z "$ZONE_INFO" ]; then
    TEMPLATE="$TEMPLATE
$(cat <<EOF
export AZURE_SUBSCRIPTION_ID="{{ op://$VAULT_NAME/$ITEM_NAME/subscription id }}"
export AZURE_RESOURCE_GROUP="{{ op://$VAULT_NAME/$ITEM_NAME/resource group }}"
export AZURE_DNS_ZONE="{{ op://$VAULT_NAME/$ITEM_NAME/dns zone }}"
EOF
)"
fi

echo "$TEMPLATE" | op inject
