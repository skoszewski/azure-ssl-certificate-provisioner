#!/usr/bin/env bash

set -euo pipefail

# Default values
PUSH=false
ARCHITECTURE="amd64"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --push)
            PUSH=true
            shift
            ;;
        --architecture)
            ARCHITECTURE="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# Check if build.env exists
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$SCRIPT_DIR/build.env" ]]; then
    echo "build.env file not found!" >&2
    exit 1
fi

echo "Loading build environment from '$SCRIPT_DIR/build.env'"
set -a
. "$SCRIPT_DIR/build.env"
set +a

if [[ -z "${REPOSITORY:-}" || -z "${IMAGE_NAME:-}" ]]; then
    echo "REPOSITORY or IMAGE_NAME not set in build.env!" >&2
    exit 1
fi

# Determine architecture-specific tag
if [[ "$ARCHITECTURE" == "amd64" ]]; then
    TAG="latest"
elif [[ "$ARCHITECTURE" == "arm64" ]]; then
    TAG="arm64"
else
    echo "Unsupported architecture: $ARCHITECTURE" >&2
    exit 1
fi

# Check if Podman or Docker is installed
if command -v podman &>/dev/null; then
    CONTAINER_TOOL="podman"
elif command -v docker &>/dev/null; then
    CONTAINER_TOOL="docker"
else
    echo "Neither Podman nor Docker is installed!" >&2
    exit 1
fi

echo "Building for Linux/$ARCHITECTURE"
export GOOS=linux
export GOARCH="$ARCHITECTURE"
go build -o ./build/azure-ssl-certificate-provisioner-linux .

IMAGE_NAME_FULL="${REPOSITORY}/${IMAGE_NAME}:${TAG}"
echo "Building container image: $IMAGE_NAME_FULL"

"$CONTAINER_TOOL" build --platform "linux/$ARCHITECTURE" -t "$IMAGE_NAME_FULL" .
if [[ $? -eq 0 ]]; then
    echo "Container image built successfully."
else
    echo "Failed to build the container image." >&2
    exit 1
fi

if [[ "$PUSH" == true ]]; then
    echo "Pushing container image: $IMAGE_NAME_FULL"
    "$CONTAINER_TOOL" push "$IMAGE_NAME_FULL"
    if [[ $? -eq 0 ]]; then
        echo "Container image pushed successfully."
    else
        echo "Failed to push the container image." >&2
        exit 1
    fi
fi
