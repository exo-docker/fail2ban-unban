import os
import re
import subprocess
import logging
import logging.handlers
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

# Compiled regex for fast IPv4 + basic IPv6 validation
_IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,39}$")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


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


def unban_ip_from_all_jails(ip_address):
    """Unban ip_address from every jail in ALLOWED_JAILS.

    Returns (any_success, per-jail result lines).
    """
    results = []
    success_count = 0

    logger.info("Unban requested | ip=%s | jails=%s", ip_address, ALLOWED_JAILS)

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
    g.start_ts = datetime.now(timezone.utc)
    logger.info(
        "Request start | method=%s | path=%s | remote=%s",
        request.method, request.path, request.remote_addr,
    )


@app.after_request
def _after(response):
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


@app.route("/health")
def health():
    try:
        result = subprocess.run(
            ["fail2ban-client", "status"],
            capture_output=True, text=True, timeout=5,
        )
        fail2ban_status = "healthy" if result.returncode == 0 else "degraded"
    except FileNotFoundError:
        fail2ban_status = "unhealthy: fail2ban-client not found"
    except Exception as exc:
        fail2ban_status = f"unhealthy: {exc}"

    status_code = 200 if fail2ban_status == "healthy" else 503
    return jsonify({
        "status": "healthy",
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
