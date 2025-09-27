ARG REPOSITORY=docker.io/skoszewski
FROM ${REPOSITORY}/azure-tools-base-container:latest

# Install Go ACME client (LEGO)
RUN LEGO_URL=$(curl -s https://api.github.com/repos/go-acme/lego/releases/latest | jq -r --arg arch $(dpkg --print-architecture) '.assets[] | select(.name | test("^lego_v[0-9.]+_linux_\($arch)\\.tar\\.gz$")) | .browser_download_url') && \
    curl -sL $LEGO_URL -o /tmp/lego.tar.gz && \
    tar -x -C /usr/local/bin -z -f /tmp/lego.tar.gz lego && \
    rm /tmp/lego.tar.gz && \
    chmod +x /usr/local/bin/lego

WORKDIR /root

COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/request-or-renew.sh /

# Burn the serial number into the image for tracking purposes
ARG SERIAL="0"
ENV SERIAL=${SERIAL}
RUN echo $SERIAL > /build_number.txt

ENTRYPOINT ["/entrypoint.sh"]
