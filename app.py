import os
import re
import subprocess
import logging
import logging.handlers
import time
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, g
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
LOG_DIR  = os.getenv("LOG_DIR", "/var/log/fail2ban-unban")
LOG_FILE = os.path.join(LOG_DIR, "app.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

os.makedirs(LOG_DIR, exist_ok=True)

_fmt = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)

# Stdout handler (container logs: docker logs / kubectl logs)
_stdout_handler = logging.StreamHandler()
_stdout_handler.setFormatter(_fmt)

# Rotating file handler – 10 MB × 5 files
_file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
_file_handler.setFormatter(_fmt)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    handlers=[_stdout_handler, _file_handler],
)

# Suppress noisy werkzeug access lines – we log our own request summary
logging.getLogger("werkzeug").setLevel(logging.WARNING)

logger = logging.getLogger("fail2ban_unban")

# ---------------------------------------------------------------------------
# Application config
# ---------------------------------------------------------------------------
ALLOWED_JAILS = [j.strip() for j in os.getenv("ALLOWED_JAILS", "sshd").split(",") if j.strip()]
UNBAN_TIMEOUT = int(os.getenv("UNBAN_TIMEOUT", "10"))
FAIL2BAN_SOCKET = os.getenv("FAIL2BAN_SOCKET", "/var/run/fail2ban/fail2ban.sock")

# Compiled regex for fast IPv4 + basic IPv6 validation
_IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,39}$")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


# ---------------------------------------------------------------------------
# Socket watchdog
# ---------------------------------------------------------------------------
import threading
import signal

def _socket_watchdog(interval: int = 300):
    """Background thread: periodically check the fail2ban socket still exists.

    If the socket disappears (e.g. fail2ban restarted and recreated its
    runtime directory, replacing the inode that Docker bind-mounted), sends
    SIGTERM to PID 1 (gunicorn master) to trigger a clean container shutdown.
    Docker restart: always will bring it back with a fresh bind-mount pointing
    at the new socket inode, and entrypoint.sh will re-apply chmod 666 before
    dropping to unbanuser.

    os._exit() is intentionally avoided: gunicorn catches worker exits and
    respawns them, so only killing PID 1 actually stops the container.
    """
    logger.info("Socket watchdog started | socket=%s | interval=%ds", FAIL2BAN_SOCKET, interval)
    while True:
        time.sleep(interval)
        if not os.path.exists(FAIL2BAN_SOCKET):
            logger.critical(
                "Socket watchdog: %s has disappeared – sending SIGTERM to PID 1 to restart container",
                FAIL2BAN_SOCKET,
            )
            os.kill(1, signal.SIGTERM)
            return  # thread exits; container shutdown is in progress
        logger.debug("Socket watchdog: %s OK", FAIL2BAN_SOCKET)

_watchdog = threading.Thread(target=_socket_watchdog, daemon=True, name="socket-watchdog")
_watchdog.start()


def _validate_ip(ip: str) -> tuple:
    """Return (is_valid, reason). Accepts IPv4 and abbreviated IPv6."""
    if not ip:
        return False, "IP address is required"
    if len(ip) > 45:
        return False, "IP address too long"
    if _IPV4_RE.match(ip):
        return True, ""
    if _IPV6_RE.match(ip) and ":" in ip:
        return True, ""
    return False, f"Invalid IP address format: {ip!r}"


def _socket_accessible() -> bool:
    """Return True if the fail2ban Unix socket exists and is accessible.

    Called before every fail2ban-client invocation so that a missing or
    inaccessible socket (e.g. after a fail2ban restart on the host) is
    caught early and reported clearly instead of producing a cryptic
    'Failed to access socket path' error buried in stderr.
    """
    return os.path.exists(FAIL2BAN_SOCKET) and os.access(FAIL2BAN_SOCKET, os.R_OK | os.W_OK)


def unban_ip_from_all_jails(ip_address):
    """Unban ip_address from every jail in ALLOWED_JAILS.

    Returns (any_success, per-jail result lines).
    """
    results = []
    success_count = 0

    logger.info("Unban requested | ip=%s | jails=%s", ip_address, ALLOWED_JAILS)

    # Fast pre-flight: check socket once before iterating jails.
    # The socket can disappear after a fail2ban restart on the host even
    # while the directory bind-mount keeps the container path intact.
    if not _socket_accessible():
        logger.error(
            "Socket not accessible | path=%s | exists=%s",
            FAIL2BAN_SOCKET,
            os.path.exists(FAIL2BAN_SOCKET),
        )
        msg = f"fail2ban socket unavailable ({FAIL2BAN_SOCKET}). Is fail2ban running on the host?"
        return False, [f"✗ {jail}: {msg}" for jail in ALLOWED_JAILS]

    for jail in ALLOWED_JAILS:
        cmd = ["fail2ban-client", "set", jail, "unbanip", ip_address]
        logger.debug("Executing | cmd=%s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=UNBAN_TIMEOUT
            )

            if result.returncode == 0:
                logger.info("Unban success | ip=%s | jail=%s", ip_address, jail)
                results.append(f"✓ {jail}: unbanned")
                success_count += 1
            else:
                stderr_lower = result.stderr.lower()
                if "not found" in stderr_lower or "does not exist" in stderr_lower:
                    logger.info("IP not present | ip=%s | jail=%s", ip_address, jail)
                    results.append(f"○ {jail}: not banned")
                elif "socket path" in stderr_lower or "fail2ban running" in stderr_lower:
                    # Socket gone mid-operation (fail2ban restarted between jails)
                    logger.error(
                        "Socket lost mid-unban | ip=%s | jail=%s | stderr=%s",
                        ip_address, jail, result.stderr.strip(),
                    )
                    results.append(f"✗ {jail}: fail2ban socket lost – is fail2ban running?")
                else:
                    logger.error(
                        "Unban failed | ip=%s | jail=%s | stderr=%s",
                        ip_address, jail, result.stderr.strip(),
                    )
                    results.append(f"✗ {jail}: failed – {result.stderr.strip()}")

        except subprocess.TimeoutExpired:
            logger.error(
                "Unban timeout | ip=%s | jail=%s | timeout=%ds",
                ip_address, jail, UNBAN_TIMEOUT,
            )
            results.append(f"✗ {jail}: timeout after {UNBAN_TIMEOUT}s")

        except FileNotFoundError:
            logger.critical("fail2ban-client not found in PATH")
            results.append(f"✗ {jail}: fail2ban-client missing")

        except Exception as exc:
            logger.exception("Unexpected error | ip=%s | jail=%s | error=%s", ip_address, jail, exc)
            results.append(f"✗ {jail}: error – {exc}")

    logger.info(
        "Unban complete | ip=%s | success=%d | total=%d",
        ip_address, success_count, len(ALLOWED_JAILS),
    )
    return success_count > 0, results


# ---------------------------------------------------------------------------
# Request lifecycle hooks
# ---------------------------------------------------------------------------
@app.before_request
def _before():
    if request.path == "/health":
        return
    g.start_ts = datetime.now(timezone.utc)
    real_ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
    logger.info(
        "Request start | method=%s | path=%s | remote=%s",
        request.method, request.path, real_ip,
    )


@app.after_request
def _after(response):
    if request.path == "/health":
        return response

    elapsed_ms = (
        (datetime.now(timezone.utc) - g.start_ts).total_seconds() * 1000
        if hasattr(g, "start_ts")
        else -1
    )
    logger.info(
        "Request end | method=%s | path=%s | status=%d | elapsed_ms=%.1f",
        request.method, request.path, response.status_code, elapsed_ms,
    )
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", allowed_jails_count=len(ALLOWED_JAILS))


@app.route("/unban", methods=["POST"])
def handle_unban():
    try:
        data = request.get_json(silent=True) or {}
        ip_address = data.get("ip", "").strip()

        valid, reason = _validate_ip(ip_address)
        if not valid:
            logger.warning("Invalid unban request | ip=%r | reason=%s", ip_address, reason)
            return jsonify({"success": False, "message": reason}), 400

        success, results = unban_ip_from_all_jails(ip_address)

        if success:
            return jsonify({
                "success": True,
                "message": f"IP {ip_address} processed successfully",
                "details": results,
            })

        return jsonify({
            "success": False,
            "message": f"Failed to unban IP {ip_address}",
            "details": results,
        }), 500

    except Exception as exc:
        logger.exception("Unhandled error in /unban | error=%s", exc)
        return jsonify({"success": False, "message": "Internal server error"}), 500


@app.route("/jails", methods=["GET"])
def get_jails():
    return jsonify({"jails": ALLOWED_JAILS, "count": len(ALLOWED_JAILS)})


def _check_fail2ban(retries: int = 2, retry_delay: float = 1.0) -> str:
    """Ping the fail2ban daemon and return a status string.

    Checks socket accessibility first (covers the fail2ban-restart-on-host
    scenario where the socket file is recreated but the container still holds
    the old bind-mount directory).  Retries once on transient errors before
    reporting degraded.
    """
    # Distinguish "socket gone" from "daemon slow" for a clear health message
    if not _socket_accessible():
        logger.warning(
            "Health check: socket not accessible | path=%s | exists=%s",
            FAIL2BAN_SOCKET,
            os.path.exists(FAIL2BAN_SOCKET),
        )
        return "unhealthy: socket not accessible – is fail2ban running on the host?"

    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(
                ["fail2ban-client", "ping"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "pong" in result.stdout.lower():
                return "healthy"
            # Daemon responded but did not pong – genuine degraded state, no retry
            logger.warning(
                "fail2ban ping unexpected response | rc=%d | stdout=%r | stderr=%r",
                result.returncode, result.stdout.strip(), result.stderr.strip(),
            )
            return "degraded"
        except FileNotFoundError:
            logger.critical("fail2ban-client not found in PATH")
            return "unhealthy: fail2ban-client not found"
        except subprocess.TimeoutExpired:
            logger.warning("fail2ban ping timed out (attempt %d/%d)", attempt, retries)
        except Exception as exc:
            logger.warning("fail2ban ping error (attempt %d/%d): %s", attempt, retries, exc)

        if attempt < retries:
            time.sleep(retry_delay)

    return "degraded"


@app.route("/health")
def health():
    fail2ban_status = _check_fail2ban()
    status_code = 200 if fail2ban_status == "healthy" else 503
    return jsonify({
        "status": fail2ban_status,
        "fail2ban": fail2ban_status,
        "jails_configured": len(ALLOWED_JAILS),
        "log_file": LOG_FILE,
    }), status_code


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("fail2ban-unban starting")
    logger.info("Jails    : %s", ALLOWED_JAILS)
    logger.info("Log file : %s", LOG_FILE)
    logger.info("Log level: %s", LOG_LEVEL)
    logger.info("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
