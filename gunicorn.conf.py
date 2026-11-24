# Loaded by gunicorn (-c). Hooks run in the master process.


def when_ready(server):
    """Start the single fail2ban socket watchdog once the master is up."""
    from socket_watchdog import start_from_env

    start_from_env()
