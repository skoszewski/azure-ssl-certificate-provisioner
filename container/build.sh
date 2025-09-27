#!/usr/bin/env bash

if [ -f serial.txt ]; then
    SERIAL=$(cat serial.txt)
    SERIAL=$((SERIAL + 1))
else
    SERIAL=1
fi
echo $SERIAL > serial.txt
IMAGE_NAME="azure-certificate-provisioner:latest"
echo "Building container image: $IMAGE_NAME ($SERIAL)"
if docker build --build-arg SERIAL=$SERIAL -t $IMAGE_NAME .; then
    echo "Container image built successfully."
else
    echo "Failed to build the container image."
    exit 1
fi
