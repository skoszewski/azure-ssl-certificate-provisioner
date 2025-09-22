ARG ARCH=arm64

FROM --platform=$ARCH alpine:latest

ARG ARCH=arm64

# Install curl for health checks
#RUN apk --no-cache add curl
# Clean up package manager cache
#RUN rm -rf /var/cache/apk/*

# Copy the binary to the container
COPY ./build/azure-ssl-certificate-provisioner-linux-$ARCH /usr/local/bin/azure-ssl-certificate-provisioner

ENTRYPOINT ["/usr/local/bin/azure-ssl-certificate-provisioner"]
