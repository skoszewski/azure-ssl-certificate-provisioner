#!/usr/bin/env bash

# Run the container and pass environment variables
podman run --rm -it --name azure-ssl-certificate-provisioner \
  -e AZURE_TENANT_ID \
  -e AZURE_CLIENT_ID \
  -e AZURE_CLIENT_SECRET \
  -e AZURE_SUBSCRIPTION_ID \
  -e AZURE_RESOURCE_GROUP \
  -e AZURE_KEY_VAULT_URL \
  -e LEGO_EMAIL \
  -v $HOME/.lego:/root/.lego \
  skdomlab.azurecr.io/azure-ssl-certificate-provisioner:latest $@
