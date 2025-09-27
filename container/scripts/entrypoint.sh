#!/usr/bin/env bash

set -euo pipefail

cd /root || exit 1

# Check if the first argument is 'shell'
if [[ "${1:-}" == "shell" ]]; then
    echo "Starting an interactive bash shell..."
    exec /bin/bash
fi

echo "Starting the certificate request or renewal process..."
echo "Build Number: $(printf '%06d' $(cat /build_number.txt))"

if [ ! -f /request-or-renew.sh ]; then
    echo "No request-or-renew.sh script found. Exiting."
    echo "Diagnostics information:"
    echo
    echo "Root's home directory contents:"
    ls -la /root
    echo
    echo "/ directory contents:"
    ls -la /
    exit 1
fi

exec /request-or-renew.sh "$@"