#!/bin/bash
set -e

# Check if fail2ban socket exists and has correct permissions
if [ -S /var/run/fail2ban/fail2ban.sock ]; then
    echo "Fail2ban socket found"
    # Try to get the group of the socket from the host
    SOCKET_GID=$(stat -c '%g' /var/run/fail2ban/fail2ban.sock 2>/dev/null || echo "")
    
    if [ -n "$SOCKET_GID" ] && [ "$SOCKET_GID" != "0" ]; then
        # Create group with the same GID as the socket if it doesn't exist
        if ! getent group $SOCKET_GID > /dev/null; then
            groupadd -g $SOCKET_GID fail2ban_host
        fi
        # Add unbanuser to that group
        usermod -a -G $SOCKET_GID unbanuser
        echo "Added unbanuser to group with GID $SOCKET_GID"
        
        # Ensure the group has write access to the socket
        chmod g+rw /var/run/fail2ban/fail2ban.sock
        echo "Ensured group write access to socket"
    else
        # If GID is 0 or unknown, ensure everyone can at least talk to it if we are root
        chmod 666 /var/run/fail2ban/fail2ban.sock
        echo "Socket owned by root or unknown, set 666 permissions"
    fi
else
    echo "Warning: Fail2ban socket not found at /var/run/fail2ban/fail2ban.sock"
fi

# Ensure log directory ownership (crucial if mounted as a volume)
LOG_DIR="${LOG_DIR:-/var/log/fail2ban-unban}"
if [ -d "$LOG_DIR" ]; then
    chown -R unbanuser:unbanuser "$LOG_DIR"
fi

# Switch to unbanuser and run the application
exec su-exec unbanuser "$@"