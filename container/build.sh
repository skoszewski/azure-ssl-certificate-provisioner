#!/usr/bin/env bash

ARCH="${1:-amd64}"
IMAGE_NAME="skdomlab.azurecr.io/azure-certificate-provisioner:latest"
echo "Building Docker image: $IMAGE_NAME"
docker build --arch $ARCH -t $IMAGE_NAME .
