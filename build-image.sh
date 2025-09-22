#!/usr/bin/env bash

BINARY_NAME="azure-ssl-certificate-provisioner"

if [ ! -z "$GOARCH" ]; then
    echo "Using GOARCH from environment: $GOARCH"
else
    echo "Detecting architecture..."
    case $(uname -m) in
        x86_64)
            GOARCH="amd64"
            ;;
        aarch64 | arm64)
            GOARCH="arm64"
            ;;
        *)
            echo "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
    echo "Detected architecture: $GOARCH"
fi

echo "Building for architecture: $GOARCH"
# Build the Go app for Linux ARM64
GOOS=linux go build -o build/${BINARY_NAME}-linux-$GOARCH .

CONTAINER_COMMAND=""

# Detect container runtime
if command -v podman &> /dev/null; then
    echo "Using Podman as the container runtime."
    CONTAINER_COMMAND="podman"
elif command -v docker &> /dev/null; then
    echo "Using Docker as the container runtime."
    CONTAINER_COMMAND="docker"
else
    echo "Neither Podman nor Docker is installed. Please install one of them to proceed."
    exit 1
fi

# Build the container image using the detected container runtime
$CONTAINER_COMMAND build --build-arg ARCH=$GOARCH -t skdomlab.azurecr.io/${BINARY_NAME}:latest .
