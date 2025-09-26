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

docker run \
    $(printf -- '-e %q ' "${ENVIRONMENT_VARIABLES[@]}") \
    -v ./.lego:/root/.lego \
    -v ./.azure:/root/.azure \
    -v ./lego.env.sh:/root/lego.env.sh:ro \
    -v ./request-or-renew.sh:/root/request-or-renew.sh:ro \
    -v ./az-login.sh:/root/az-login.sh:ro \
    -v ./scripts:/root/scripts:rw \
    --arch arm64 \
    --rm -it sktest $@
