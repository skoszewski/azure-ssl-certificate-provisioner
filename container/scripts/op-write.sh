##!/usr/bin/env bash

set -euo pipefail

if [ -z "$AZURE_TENANT_ID" ] || [ -z "$AZURE_CLIENT_ID" ] || [ -z "$AZURE_CLIENT_SECRET" ]; then
    echo "Error: One or more of AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are not set." >&2
    exit 1
fi

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

VAULT_ID=$(op vault get "$VAULT_NAME" --format=json | jq -r .id)

# Store the values in 1Password vault using the op CLI
JSON=$(cat <<EOF
{
    "title": "PLACEHOLDER",
    "category": "API_CREDENTIAL",
    "vault": {
        "id": "PLACEHOLDER"
    },
    "fields": [
        {
            "id": "username",
            "type": "STRING",
            "label": "client id",
            "value": ""
        },
        {
            "id": "credential",
            "type": "CONCEALED",
            "label": "client secret",
            "value": ""
        },
        {
            "id": "tenant-id",
            "type": "STRING",
            "label": "tenant id",
            "value": "PLACEHOLDER"
        }
    ]
}
EOF
)

echo "$JSON" | jq \
    --arg vault_id "$VAULT_ID" \
    --arg item_name "$ITEM_NAME" \
    --arg client_id "$AZURE_CLIENT_ID" \
    --arg client_secret "$AZURE_CLIENT_SECRET" \
    --arg tenant_id "$AZURE_TENANT_ID" \
    '.title = $item_name
    | .vault.id = $vault_id
    | .fields[0].value = $client_id
    | .fields[1].value = $client_secret
    | .fields[2].value = $tenant_id' | op item create -
