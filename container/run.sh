#!/usr/bin/env bash

set -euo pipefail

if [ ! -f build.env ]; then
    echo "Error: build.env file not found!"
    exit 1
fi

# Load environment variables from build.env
. build.env

# Set the image name to the current directory name if not provided
if [ -z "$IMAGE_NAME" ] || [ -z "$REPOSITORY" ]; then
    echo "Error: IMAGE_NAME or REPOSITORY is not set in build.env!"
    exit 1
fi

ARCH=${ARCH:-$(uname -m)}
TAG=""

case $ARCH in
    amd64 | x86_64) TAG="latest" ;;
    aarch64 | arm64) TAG="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Environment variables to pass into the container
ENVIRONMENT_VARIABLES=(
    AZURE_TENANT_ID
    AZURE_CLIENT_ID
    AZURE_CLIENT_SECRET
    AZURE_RESOURCE_GROUP
    LEGO_EMAIL
    DNS_RESOLVERS
)

# Check, if the environment variables are set
for VAR in "${ENVIRONMENT_VARIABLES[@]}"; do
    if [ -z "${!VAR:-}" ]; then
        echo "Error: Environment variable $VAR is not set."
        exit 1
    fi
done

ENV_PARAMS=$(printf -- '-e %q ' "${ENVIRONMENT_VARIABLES[@]}")

docker run \
    $ENV_PARAMS \
    -v ./root:/root:rw \
    --rm -it "$REPOSITORY/$IMAGE_NAME:$TAG" $@
