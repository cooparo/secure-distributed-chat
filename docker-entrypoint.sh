#!/bin/sh
set -e

KEY_FILE="/data/private.key"
LISTEN_PORT="${LISTEN_PORT:-1337}"

# Ensure runtime directory exists
mkdir -p "$XDG_RUNTIME_DIR"

# Generate identity if key doesn't exist
if [ ! -f "$KEY_FILE" ]; then
    echo "Generating new identity..."
    gratcli identity -g -k "$KEY_FILE"
fi

# Symlink to default path so gratcli works without -k
ln -sf "$KEY_FILE" /root/private.key

# Print our address
gratcli identity

# Resolve EXTERNAL_IP hostname to an IP address.
# gratserver's -e flag expects an IP (net.ParseIP), not a hostname.
RESOLVED_IP=""
if [ -n "$EXTERNAL_IP" ]; then
    RESOLVED_IP=$(getent hosts "$EXTERNAL_IP" | awk '{print $1; exit}')
fi
if [ -z "$RESOLVED_IP" ]; then
    RESOLVED_IP="::1"
fi

echo "Resolved external IP: $RESOLVED_IP"

# Start gratserver
exec gratserver -k /root/private.key -e "$RESOLVED_IP" -p "$LISTEN_PORT" -v
