#!/usr/bin/env bash

set -euo pipefail

# Environment variables to pass into the container
ENVIRONMENT_VARIABLES=(
    AZURE_TENANT_ID
    AZURE_CLIENT_ID
    AZURE_CLIENT_SECRET
    AZURE_RESOURCE_GROUP
    LEGO_EMAIL
    DNS_RESOLVERS
)

# Chceck, if the environment variables are set
for VAR in "${ENVIRONMENT_VARIABLES[@]}"; do
    if [ -z "${!VAR:-}" ]; then
        echo "Error: Environment variable $VAR is not set."
        exit 1
    fi
done

ENV_PARAMS=$(printf -- '-e %q ' "${ENVIRONMENT_VARIABLES[@]}")

docker run \
    $ENV_PARAMS \
    -v ./.lego:/root/.lego \
    -v ./.azure:/root/.azure \
    -v ./scripts:/root/scripts:ro \
    --pull never \
    --rm -it "azure-certificate-provisioner:latest" $@
