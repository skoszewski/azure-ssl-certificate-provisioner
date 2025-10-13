#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="azure-ssl-certificate-provisioner:latest"

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "Building image $IMAGE_NAME ..."
  docker build -t "$IMAGE_NAME" .
fi

. ./.env

docker run --rm \
  -e ACME_EMAIL \
  -e AZURE_SUBSCRIPTION_ID \
  -e AZURE_RESOURCE_GROUP \
  -e AZURE_KEY_VAULT_URL \
  -e ACME_DIRECTORY_URL \
  -e AZURE_TENANT_ID \
  -e AZURE_CLIENT_ID \
  -e AZURE_CLIENT_SECRET \
  "$IMAGE_NAME" "$@"
