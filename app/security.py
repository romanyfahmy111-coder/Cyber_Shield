"""Application-level security controls: security headers, rate limiting,
same-origin enforcement for state-changing requests and safe error output."""
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

from flask import jsonify, request

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def json_error(code, message, status, **extra):
    body = {"error": {"code": code, "message": message}}
    resp = jsonify(body)
    resp.status_code = status
    for key, value in extra.items():
        resp.headers[key] = str(value)
    return resp


class RateLimiter:
    """Small thread-safe sliding-window limiter (per process, in memory)."""

    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key, limit, window):
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] >= window:
                hits.popleft()
            if len(hits) >= limit:
                retry_after = max(1, int(window - (now - hits[0])) + 1)
                return False, retry_after
            hits.append(now)
            if len(self._hits) > 5000:  # keep memory bounded
                stale = [k for k, q in self._hits.items() if not q or now - q[-1] > 3600]
                for k in stale:
                    del self._hits[k]
            return True, 0


def _same_origin():
    origin = request.headers.get("Origin")
    if not origin:
        return True
    try:
        netloc = urlsplit(origin).netloc
    except ValueError:
        return False
    return netloc.lower() == request.host.lower()


def init_security(app):
    limiter = RateLimiter()
    app.extensions["limiter"] = limiter

    @app.before_request
    def _guard():
        if request.method in UNSAFE_METHODS and not _same_origin():
            return json_error("forbidden_origin", "Cross-origin requests are not allowed.", 403)

        path = request.path
        if not path.startswith("/api/"):
            return None
        cfg = app.config
        window = cfg["RATE_LIMIT_WINDOW"]
        client = request.remote_addr or "unknown"
        if request.method == "POST" and path in ("/api/scan", "/api/scan/stream"):
            ok, retry = limiter.check(("scan", client), cfg["RATE_LIMIT_SCAN"], window)
            msg = "Too many scans. Please wait a moment before scanning again."
        else:
            ok, retry = limiter.check(("api", client), cfg["RATE_LIMIT_API"], window)
            msg = "Too many requests. Please slow down."
        if not ok:
            return json_error("rate_limited", msg, 429, **{"Retry-After": retry})
        return None

    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def _api_or_page(status, code, message):
        if request.path.startswith("/api/"):
            return json_error(code, message, status)
        from flask import render_template

        return (
            render_template("error.html", status=status, message=message),
            status,
        )

    @app.errorhandler(404)
    def _404(_e):
        return _api_or_page(404, "not_found", "The requested resource was not found.")

    @app.errorhandler(405)
    def _405(_e):
        return _api_or_page(405, "method_not_allowed", "This method is not allowed here.")

    @app.errorhandler(413)
    def _413(_e):
        return _api_or_page(413, "payload_too_large", "The request body is too large.")

    @app.errorhandler(Exception)
    def _500(exc):
        from werkzeug.exceptions import HTTPException

        if isinstance(exc, HTTPException):
            return _api_or_page(exc.code or 500, "http_error", exc.description or "Request failed.")
        app.logger.exception("Unhandled error")  # details stay in the server log only
        return _api_or_page(500, "internal_error", "Something went wrong on the server.")
