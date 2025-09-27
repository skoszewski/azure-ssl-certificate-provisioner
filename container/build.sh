#!/usr/bin/env bash

if [ ! -f serial.txt ]; then
    echo "0" > serial.txt
fi
SERIAL=$(cat serial.txt)
IMAGE_NAME="azure-certificate-provisioner:latest"
echo "Building container image: $IMAGE_NAME"
if docker build --build-arg SERIAL=$SERIAL -t $IMAGE_NAME .; then
    echo "Container image built successfully."
    echo $((SERIAL + 1)) > serial.txt
else
    echo "Failed to build the container image."
    exit 1
fi
