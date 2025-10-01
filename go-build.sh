#!/usr/bin/env bash

case "$(uname -o)" in
  "GNU/Linux") export GOOS=linux ;;
  "Darwin") export GOOS=darwin ;;
  *) echo "Unsupported OS"; exit 1 ;;
esac

case "$(uname -m)" in
  "x86_64") export GOARCH=amd64 ;;
  "arm64") export GOARCH=arm64 ;;
  *) echo "Unsupported architecture"; exit 1 ;;
esac

echo "Building for $GOOS/$GOARCH..."
mkdir -p build
go build -o build/azure-ssl-certificate-provisioner .
