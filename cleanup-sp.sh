#!/bin/bash

# Script to delete Azure AD Application and Service Principal by display name
# Usage: ./cleanup-sp.sh "app-display-name"

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <app-display-name>"
    echo "Example: $0 'letsencrypt-certificate-provisioner'"
    exit 1
fi

APP_DISPLAY_NAME="$1"

echo "Looking for Azure AD Application with display name: '$APP_DISPLAY_NAME'"

# Find the application by display name
APP_ID=$(az ad app list --display-name "$APP_DISPLAY_NAME" --query "[0].appId" -o tsv)

if [ -z "$APP_ID" ] || [ "$APP_ID" = "null" ]; then
    echo "No application found with display name: '$APP_DISPLAY_NAME'"
    exit 1
fi

echo "Found application: $APP_ID"

# Find the service principal associated with the application
SP_ID=$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0].id" -o tsv)

if [ -n "$SP_ID" ] && [ "$SP_ID" != "null" ]; then
    echo "Found service principal: $SP_ID"
    echo "Deleting service principal..."
    az ad sp delete --id "$SP_ID"
    echo "Service principal deleted successfully"
else
    echo "No service principal found for application: $APP_ID"
fi

# Delete the application
echo "Deleting Azure AD application..."
az ad app delete --id "$APP_ID"
echo "Azure AD application deleted successfully"

# Clean up any certificate files that might exist locally
# Extract potential client ID from the app (though we can't know for sure)
echo "Cleaning up any local certificate files..."
find . -name "*.key" -o -name "*.crt" | while read -r file; do
    if [ -f "$file" ]; then
        echo "Removing local certificate file: $file"
        rm -f "$file"
    fi
done

echo "Cleanup completed for application: '$APP_DISPLAY_NAME'"