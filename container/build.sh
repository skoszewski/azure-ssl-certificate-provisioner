#!/usr/bin/env bash

docker build --build-arg ARCH=arm64 -t sktest .
