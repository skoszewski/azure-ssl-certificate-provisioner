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
test -f /root/request-or-renew.sh && exec /root/request-or-renew.sh "$@"
echo "No request-or-renew.sh script found. Exiting."
exit 1
