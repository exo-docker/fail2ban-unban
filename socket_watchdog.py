"""Fail2ban socket watchdog.

Runs as a background thread inside the gunicorn *master* process (started from
``gunicorn.conf.py``), so there is exactly one instance regardless of the
number of workers.

Why it exists: when fail2ban restarts on the host it recreates its socket
(new inode, root-owned, mode 0755).  The bind-mounted directory stays valid,
but the container can no longer use the socket, because ``entrypoint.sh``
only chmods it at start-up.  The only fix is to restart the container so the
entrypoint runs again, which is what this watchdog triggers (SIGTERM to
gunicorn, then Docker's restart policy brings it back).

A probe fails when the socket is missing, not readable/writable by the app
user, or ``fail2ban-client ping`` does not answer ``pong``.  The container is
only restarted after several *consecutive* failures, so a short fail2ban
reload does not cause a restart.
"""
import logging
import os
import signal
import subprocess
import sys
import threading

DEFAULT_SOCKET = "/var/run/fail2ban/fail2ban.sock"

logger = logging.getLogger("fail2ban_unban.watchdog")


def probe(socket_path: str, ping_timeout: float = 5.0):
    """Return ``(ok, reason)`` for one health probe of the fail2ban socket."""
    if not os.path.exists(socket_path):
        return False, "socket missing"
    if not os.access(socket_path, os.R_OK | os.W_OK):
        return False, "socket not readable/writable (permissions reset by a fail2ban restart?)"
    try:
        result = subprocess.run(
            ["fail2ban-client", "-s", socket_path, "ping"],
            capture_output=True, text=True, timeout=ping_timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"ping timed out after {ping_timeout:g}s"
    except FileNotFoundError:
        return False, "fail2ban-client not found"
    except OSError as exc:
        return False, f"ping could not run: {exc}"
    if result.returncode == 0 and "pong" in result.stdout.lower():
        return True, ""
    detail = (result.stderr or result.stdout).strip().splitlines()
    return False, "ping failed: " + (detail[-1] if detail else f"rc={result.returncode}")


class Watchdog:
    """Count consecutive probe failures and call ``on_fatal`` at the limit."""

    def __init__(self, socket_path, interval=30.0, max_failures=3,
                 ping_timeout=5.0, on_fatal=None, probe_fn=probe):
        if interval <= 0 or max_failures < 1:
            raise ValueError("interval must be > 0 and max_failures >= 1")
        self.socket_path = socket_path
        self.interval = interval
        self.max_failures = max_failures
        self.ping_timeout = ping_timeout
        self.on_fatal = on_fatal or _terminate_self
        self._probe = probe_fn
        self._stop = threading.Event()
        self.failures = 0

    def stop(self):
        self._stop.set()

    def tick(self):
        """Run one probe; return True when the fatal action was triggered."""
        ok, reason = self._probe(self.socket_path, self.ping_timeout)
        if ok:
            if self.failures:
                logger.info("Watchdog: fail2ban recovered after %d failed probe(s)", self.failures)
            self.failures = 0
            logger.debug("Watchdog: %s OK", self.socket_path)
            return False
        self.failures += 1
        if self.failures < self.max_failures:
            logger.warning("Watchdog: probe failed (%d/%d): %s",
                           self.failures, self.max_failures, reason)
            return False
        logger.critical(
            "Watchdog: %d consecutive probe failures (%s) - stopping so Docker "
            "restarts the container and entrypoint.sh re-applies the socket permissions",
            self.failures, reason,
        )
        self.on_fatal()
        return True

    def run(self):
        logger.info("Watchdog started | socket=%s | interval=%gs | max_failures=%d",
                    self.socket_path, self.interval, self.max_failures)
        # wait() returns True once stop() is called; it is also the sleep.
        while not self._stop.wait(self.interval):
            try:
                if self.tick():
                    return
            except Exception:  # never let the thread die silently
                logger.exception("Watchdog: unexpected error")


def _terminate_self():
    # Called from the gunicorn master: SIGTERM = graceful shutdown.  os._exit()
    # would be wrong here, gunicorn would respawn killed workers.
    os.kill(os.getpid(), signal.SIGTERM)


def _env_number(name, default, cast):
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        value = cast(raw)
    except ValueError:
        logger.error("Ignoring invalid %s=%r, using %s", name, raw, default)
        return default
    if value <= 0:
        logger.error("Ignoring non-positive %s=%r, using %s", name, raw, default)
        return default
    return value


def start_from_env():
    """Start the watchdog thread from env settings; return it (or None if disabled).

    WATCHDOG_ENABLED   true|false          (default true)
    WATCHDOG_INTERVAL  seconds between probes (default 30)
    WATCHDOG_FAILURES  consecutive failures before restart (default 3)
    """
    if os.getenv("WATCHDOG_ENABLED", "true").strip().lower() in ("0", "false", "no", "off"):
        print("Watchdog disabled (WATCHDOG_ENABLED=false)", file=sys.stderr)
        return None
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z"))
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO))
    dog = Watchdog(
        os.getenv("FAIL2BAN_SOCKET", DEFAULT_SOCKET),
        interval=_env_number("WATCHDOG_INTERVAL", 30.0, float),
        max_failures=_env_number("WATCHDOG_FAILURES", 3, int),
    )
    threading.Thread(target=dog.run, daemon=True, name="socket-watchdog").start()
    return dog
