#!/bin/bash
set -e

SOCKET_PATH="${FAIL2BAN_SOCKET:-/var/run/fail2ban/fail2ban.sock}"

if [ -S "$SOCKET_PATH" ]; then
    chmod 666 "$SOCKET_PATH" && echo "Socket permissions set: $SOCKET_PATH" \
        || echo "Warning: could not chmod socket $SOCKET_PATH (non-fatal)"
else
    echo "Warning: fail2ban socket not found at $SOCKET_PATH – continuing anyway"
fi

# Ensure log directory ownership (crucial if mounted as a volume)
LOG_DIR="${LOG_DIR:-/var/log/fail2ban-unban}"
if [ -d "$LOG_DIR" ]; then
    chown -R unbanuser:unbanuser "$LOG_DIR"
fi

# Drop to unprivileged user and exec the application
exec su-exec unbanuser "$@"
