FROM alpine:latest

# Install curl for health checks
#RUN apk --no-cache add curl
# Clean up package manager cache
#RUN rm -rf /var/cache/apk/*

# Copy the binary to the container
COPY ./build/azure-ssl-certificate-provisioner-linux /certificate-provisioner
RUN chmod +x /certificate-provisioner
WORKDIR /root

ENTRYPOINT ["/certificate-provisioner"]
