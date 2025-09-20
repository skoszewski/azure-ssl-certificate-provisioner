#!/usr/bin/env bash
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

# Create an Azure AD application
read AZURE_APP_ID AZURE_CLIENT_ID < <(az ad app create --display-name "$ITEM_NAME" --query '{id:id,appid:appId}' -o tsv)
# Create a service principal for the application
read SPN_ID < <(az ad sp create --id "$AZURE_APP_ID" --query id -o tsv)
# Create a client secret for the application
read AZURE_CLIENT_SECRET < <(az ad app credential reset --id "$AZURE_APP_ID" --query password -o tsv)
# define subscription ID and tenant ID
read AZURE_SUBSCRIPTION_ID AZURE_TENANT_ID < <(az account show --query '{a:id,b:tenantId}' -o tsv)

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
            "id": "applicationid",
            "type": "STRING",
            "label": "application id",
            "value": "PLACEHOLDER"
        },
        {
            "id": "spn-id",
            "type": "STRING",
            "label": "spn id",
            "value": "PLACEHOLDER"
        },
        {
            "id": "subscription-id",
            "type": "STRING",
            "label": "subscription id",
            "value": "PLACEHOLDER"
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
    --arg vault_id "$(op vault get Private --format=json | jq -r .id)" \
    --arg app_id "$AZURE_APP_ID" \
    --arg client_id "$AZURE_CLIENT_ID" \
    --arg client_secret "$AZURE_CLIENT_SECRET" \
    --arg subscription_id "$AZURE_SUBSCRIPTION_ID" \
    --arg tenant_id "$AZURE_TENANT_ID" \
    --arg spn_id "$SPN_ID" \
    '.title = "Azure SSL Certificate Provisioner"
    | .vault.id = $vault_id
    | .fields[0].value = $client_id
    | .fields[1].value = $client_secret
    | .fields[2].value = $app_id
    | .fields[3].value = $spn_id
    | .fields[4].value = $subscription_id
    | .fields[5].value = $tenant_id' | op item create -
