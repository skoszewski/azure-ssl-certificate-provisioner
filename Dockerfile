FROM alpine:latest

# Install curl for health checks
#RUN apk --no-cache add curl
# Clean up package manager cache
#RUN rm -rf /var/cache/apk/*

# Copy the binary to the container
COPY ./build/azure-ssl-certificate-provisioner-linux /
RUN chmod +x /azure-ssl-certificate-provisioner-linux
WORKDIR /root

ENTRYPOINT ["/azure-ssl-certificate-provisioner-linux"]
