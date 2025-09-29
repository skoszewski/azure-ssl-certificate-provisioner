ARG REPOSITORY
ARG TAG
FROM ${REPOSITORY}/base:${TAG}

# Install Go ACME client (LEGO)
RUN LEGO_URL=$(curl -s https://api.github.com/repos/go-acme/lego/releases/latest | jq -r --arg arch $(dpkg --print-architecture) '.assets[] | select(.name | test("^lego_v[0-9.]+_linux_\($arch)\\.tar\\.gz$")) | .browser_download_url') && \
    curl -sL $LEGO_URL -o /tmp/lego.tar.gz && \
    tar -x -C /usr/local/bin -z -f /tmp/lego.tar.gz lego && \
    rm /tmp/lego.tar.gz && \
    chmod +x /usr/local/bin/lego

WORKDIR /root

COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/request-or-renew.sh /
# Required to make the entrypoint script executable if building on Windows host
RUN chmod +x /entrypoint.sh
RUN chmod +x /request-or-renew.sh
ENTRYPOINT ["/entrypoint.sh"]
