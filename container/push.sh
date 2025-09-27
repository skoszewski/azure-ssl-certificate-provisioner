#!/usr/bin/env bash

docker tag "azure-certificate-provisioner" "skdomlab.azurecr.io/azure-certificate-provisioner:latest"
docker push "skdomlab.azurecr.io/azure-certificate-provisioner:latest"
