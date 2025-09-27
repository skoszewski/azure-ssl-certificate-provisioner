FROM ubuntu:latest

# Install prerequisites
RUN apt-get update && \
    apt-get install -y \
        curl \
        jq \
        apt-transport-https \
        ca-certificates \
        gnupg \
        python3 \
        python3-venv \
        python3-pip \
        libicu74 && \
    rm -rf /var/lib/apt/lists/*

# Install Microsoft GnuPG key
RUN mkdir -p /etc/apt/keyrings && \
    curl -sL https://packages.microsoft.com/keys/microsoft.asc | \
        gpg --dearmor | tee /etc/apt/keyrings/microsoft.gpg > /dev/null

# Configure Microsoft apt repository
RUN SUITE=$(. /etc/os-release && echo $VERSION_CODENAME) && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $SUITE main" > /etc/apt/sources.list.d/microsoft.list

# Pin Azure CLI package, so it won't be overwritten by an Ubuntu native package
RUN cat <<EOF > /etc/apt/preferences.d/99-microsoft
Package: *
Pin: origin https://packages.microsoft.com/repos/azure-cli
Pin-Priority: 1

Package: azure-cli
Pin: origin https://packages.microsoft.com/repos/azure-cli
Pin-Priority: 500
EOF

# Install Azure CLI
RUN apt-get update && \
    apt-get install -y azure-cli && \
    rm -rf /var/lib/apt/lists/*

# Install PowerShell using direct download
# Microsoft does not provide a debian package for ARM64 architecture, therefore we download and install it manually
RUN ARCH=$(dpkg --print-architecture | sed 's/aarch/arm/; s/amd64/x64/') && \
    POWERSHELL_URL=$(curl -s https://api.github.com/repos/PowerShell/PowerShell/releases/latest | jq -r --arg arch $ARCH '.assets[] | select(.name | test("^powershell-[0-9.]+-linux-\($arch)\\.tar\\.gz$")) | .browser_download_url') && \
    curl -sL $POWERSHELL_URL -o /tmp/powershell.tar.gz && \
    mkdir -p /opt/microsoft/powershell/7 && \
    tar -x -C /opt/microsoft/powershell/7 -z -f /tmp/powershell.tar.gz && \
    rm /tmp/powershell.tar.gz && \
    chmod +x /opt/microsoft/powershell/7/pwsh && \
    ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh

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
