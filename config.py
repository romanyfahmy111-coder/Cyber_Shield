"""PhishLens configuration.

Every secret and tunable value is read from environment variables
(optionally loaded from the ``.env`` file).  Nothing in here is ever sent
to the browser.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _env_str(name, default=""):
    return (os.getenv(name) or default).strip()


def _env_int(name, default, minimum=None, maximum=None):
    raw = os.getenv(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _env_bool(name, default):
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _thresholds():
    medium = _env_int("RISK_MEDIUM_THRESHOLD", 30, 1, 100)
    high = _env_int("RISK_HIGH_THRESHOLD", 60, 1, 100)
    critical = _env_int("RISK_CRITICAL_THRESHOLD", 80, 1, 100)
    if not (medium < high < critical):
        # Invalid combination: fall back to the documented defaults.
        return 30, 60, 80
    return medium, high, critical


class Config:
    # --- storage -------------------------------------------------------
    # On Vercel the project directory is read-only; only /tmp is writable
    # (and it is wiped between cold starts, so history is not permanent).
    ON_VERCEL = bool(os.getenv("VERCEL"))
    DATABASE = _env_str("DATABASE_PATH") or (
        "/tmp/phishlens.db" if ON_VERCEL else str(BASE_DIR / "instance" / "phishlens.db")
    )
    MAX_HISTORY = _env_int("MAX_HISTORY", 500, 10, 10000)

    # --- threat intelligence (keys stay on the server) -------------------
    VIRUSTOTAL_API_KEY = _env_str("VIRUSTOTAL_API_KEY")
    GOOGLE_SAFE_BROWSING_API_KEY = _env_str("GOOGLE_SAFE_BROWSING_API_KEY")
    VT_SUBMIT_UNKNOWN_URLS = _env_bool("VT_SUBMIT_UNKNOWN_URLS", True)
    VT_MALICIOUS_THRESHOLD = _env_int("VT_MALICIOUS_THRESHOLD", 3, 1, 50)
    VT_POLL_ATTEMPTS = _env_int("VT_POLL_ATTEMPTS", 5, 1, 20)
    VT_POLL_INTERVAL = _env_int("VT_POLL_INTERVAL", 3, 1, 15)

    # --- risk model --------------------------------------------------------
    RISK_THRESHOLDS = _thresholds()  # (medium, high, critical)

    # --- timeouts (seconds) --------------------------------------------------
    HTTP_TIMEOUT = _env_int("HTTP_TIMEOUT", 10, 2, 60)
    DNS_TIMEOUT = _env_int("DNS_TIMEOUT", 5, 1, 30)
    TLS_TIMEOUT = _env_int("TLS_TIMEOUT", 5, 1, 30)

    # --- optional active checks ---------------------------------------------
    ENABLE_TLS_INSPECTION = _env_bool("ENABLE_TLS_INSPECTION", True)
    ENABLE_DOMAIN_AGE = _env_bool("ENABLE_DOMAIN_AGE", True)

    # --- input limits / abuse protection -------------------------------------
    MAX_URL_LENGTH = 2048
    MAX_CONTENT_LENGTH = 16 * 1024  # request bodies are tiny JSON documents
    RATE_LIMIT_SCAN = _env_int("RATE_LIMIT_SCAN", 10, 1, 1000)  # per minute / IP
    RATE_LIMIT_API = _env_int("RATE_LIMIT_API", 120, 1, 10000)  # per minute / IP
    RATE_LIMIT_WINDOW = 60
    MAX_CONCURRENT_SCANS = _env_int("MAX_CONCURRENT_SCANS", 4, 1, 50)

    # --- server ----------------------------------------------------------------
    HOST = _env_str("HOST", "127.0.0.1")
    PORT = _env_int("PORT", 5000, 1, 65535)
    DEBUG = _env_bool("FLASK_DEBUG", False)
    JSON_SORT_KEYS = False
