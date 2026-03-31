#!/bin/bash
set -e

# Check if fail2ban socket exists and has correct permissions
if [ -S /var/run/fail2ban/fail2ban.sock ]; then
    echo "Fail2ban socket found"
    # Try to get the group of the socket from the host
    SOCKET_GID=$(stat -c '%g' /var/run/fail2ban/fail2ban.sock 2>/dev/null || echo "")
    
    if [ -n "$SOCKET_GID" ] && [ "$SOCKET_GID" != "0" ]; then
        # Create group with the same GID as the socket
        if ! getent group $SOCKET_GID > /dev/null; then
            groupadd -g $SOCKET_GID fail2ban_host
        fi
        # Add unbanuser to that group
        usermod -a -G $SOCKET_GID unbanuser
        echo "Added unbanuser to group with GID $SOCKET_GID"
    fi
else
    echo "Warning: Fail2ban socket not found at /var/run/fail2ban/fail2ban.sock"
fi

# Switch to unbanuser and run the application
exec gosu unbanuser "$@"