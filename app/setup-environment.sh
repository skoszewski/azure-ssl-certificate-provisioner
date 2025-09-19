##!/usr/bin/env bash

set -euo pipefail

# Default values
VAULT_NAME="Private"
ITEM_NAME=""

# Parse options
while getopts "v:n:" opt; do
    case $opt in
        v)
            VAULT_NAME="$OPTARG"
            ;;
        n)
            ITEM_NAME="$OPTARG"
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

cat <<EOF | op inject
export AZURE_TENANT_ID={{ op://$VAULT_NAME/$ITEM_NAME/tenant id }}
export AZURE_CLIENT_ID={{ op://$VAULT_NAME/$ITEM_NAME/client id }}
export AZURE_CLIENT_SECRET={{ op://$VAULT_NAME/$ITEM_NAME/client secret }}
export AZURE_SUBSCRIPTION_ID={{ op://$VAULT_NAME/$ITEM_NAME/subscription id }}
EOF
