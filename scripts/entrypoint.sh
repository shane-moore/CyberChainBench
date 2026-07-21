#!/bin/bash
# Container entrypoint: start whitelist proxy then exec command as current user.
set -euo pipefail

# Start the whitelist proxy in background (binds localhost, no root needed)
python3 /usr/local/bin/whitelist_proxy.py &

sleep 0.3

# Execute the actual command
exec "$@"
