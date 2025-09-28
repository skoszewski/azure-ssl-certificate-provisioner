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

echo "Building container image: $REPOSITORY/$IMAGE_NAME:$TAG."

if docker build \
    --build-arg REPOSITORY="$REPOSITORY" \
    --build-arg TAG="$TAG" \
    -t "$REPOSITORY/$IMAGE_NAME:$TAG" \
    .
then
    echo "Container image built successfully."
else
    echo "Failed to build the container image."
    exit 1
fi

if grep -qE -- '(\b-p\b|\b--push\b)' <<< "$@"; then
    echo "Pushing container image to repository..."
    docker push "$REPOSITORY/$IMAGE_NAME:$TAG"
fi
