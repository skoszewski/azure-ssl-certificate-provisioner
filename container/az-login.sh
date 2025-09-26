#!/usr/bin/env bash

az login --service-principal \
    -u "$AZURE_CLIENT_ID" \
    -p "$AZURE_CLIENT_SECRET" \
    --tenant "$AZURE_TENANT_ID"
