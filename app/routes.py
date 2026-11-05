"""HTTP routes: pages, REST API and the Server-Sent-Events scan stream."""
import json
import logging
import threading

from flask import Blueprint, Response, current_app, jsonify, render_template, request

from .database import models
from .scanner import run_scan
from .security import json_error

log = logging.getLogger(__name__)
bp = Blueprint("main", __name__)


@bp.record_once
def _setup(state):
    app = state.app
    app.extensions["scan_slots"] = threading.BoundedSemaphore(app.config["MAX_CONCURRENT_SCANS"])


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@bp.get("/")
def index():
    return render_template("index.html")


@bp.get("/history")
def history_page():
    return render_template("history.html")


@bp.get("/report/<int:scan_id>")
def report_page(scan_id):
    if models.get_scan(current_app.config["DATABASE"], scan_id) is None:
        return render_template("error.html", status=404, message="That scan report was not found."), 404
    return render_template("results.html", scan_id=scan_id)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _read_url():
    if not request.is_json:
        return None, json_error("unsupported_media_type",
                                "Send a JSON body with Content-Type: application/json.", 415)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("url"), str):
        return None, json_error("invalid_request",
                                "The request body must be a JSON object with a string field 'url'.", 400)
    return data["url"], None


def _sse(event):
    return "data: " + json.dumps(event) + "\n\n"


def _status_for(code):
    return 500 if code == "internal_error" else 400


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

@bp.get("/api/health")
def api_health():
    return jsonify({"status": "ok"})


@bp.get("/api/status")
def api_status():
    """Which checks are available on this server.  Never includes secrets."""
    cfg = current_app.config
    medium, high, critical = cfg["RISK_THRESHOLDS"]
    return jsonify({
        "providers": {
            "virustotal": {
                "configured": bool(cfg["VIRUSTOTAL_API_KEY"]),
                "submits_unknown_urls": bool(cfg["VT_SUBMIT_UNKNOWN_URLS"]),
            },
            "safe_browsing": {"configured": bool(cfg["GOOGLE_SAFE_BROWSING_API_KEY"])},
        },
        "checks": {
            "tls_inspection": bool(cfg["ENABLE_TLS_INSPECTION"]),
            "domain_age": bool(cfg["ENABLE_DOMAIN_AGE"]),
        },
        "thresholds": {"medium": medium, "high": high, "critical": critical},
        "max_url_length": cfg["MAX_URL_LENGTH"],
    })


@bp.post("/api/scan")
def api_scan():
    url, err = _read_url()
    if err:
        return err
    slots = current_app.extensions["scan_slots"]
    if not slots.acquire(blocking=False):
        return json_error("busy", "The server is busy with other scans. Please try again shortly.", 503,
                          **{"Retry-After": 5})
    try:
        cfg = dict(current_app.config)
        report = None
        for event in run_scan(url, cfg):
            if event["type"] == "error":
                return json_error(event["error"]["code"], event["error"]["message"],
                                  _status_for(event["error"]["code"]))
            if event["type"] == "result":
                report = event["report"]
        if report is None:
            return json_error("scan_failed", "The scan did not finish.", 500)
        scan_id = models.save_scan(cfg["DATABASE"], report, cfg["MAX_HISTORY"])
        return jsonify({"id": scan_id, "report": report})
    finally:
        slots.release()


@bp.post("/api/scan/stream")
def api_scan_stream():
    """Runs the scan and streams real progress as Server-Sent Events."""
    url, err = _read_url()
    if err:
        return err
    slots = current_app.extensions["scan_slots"]
    if not slots.acquire(blocking=False):
        return json_error("busy", "The server is busy with other scans. Please try again shortly.", 503,
                          **{"Retry-After": 5})
    cfg = dict(current_app.config)
    released = {"done": False}

    def release_once():
        if not released["done"]:
            released["done"] = True
            slots.release()

    def generate():
        try:
            for event in run_scan(url, cfg):
                if event["type"] == "result":
                    scan_id = models.save_scan(cfg["DATABASE"], event["report"], cfg["MAX_HISTORY"])
                    event = {"type": "result", "id": scan_id, "report": event["report"]}
                yield _sse(event)
        except Exception:
            log.exception("Scan stream failed")
            yield _sse({"type": "error", "error": {"code": "internal_error",
                                                   "message": "Something went wrong on the server."}})
        finally:
            release_once()

    resp = Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
    resp.call_on_close(release_once)
    return resp


@bp.get("/api/scans")
def api_list_scans():
    try:
        limit = int(request.args.get("limit", 20))
    except ValueError:
        return json_error("invalid_request", "'limit' must be an integer.", 400)
    scans = models.list_scans(current_app.config["DATABASE"], limit)
    return jsonify({"scans": scans})


@bp.get("/api/scans/<int:scan_id>")
def api_get_scan(scan_id):
    scan = models.get_scan(current_app.config["DATABASE"], scan_id)
    if scan is None:
        return json_error("not_found", "Scan not found.", 404)
    return jsonify(scan)


@bp.delete("/api/scans/<int:scan_id>")
def api_delete_scan(scan_id):
    if not models.delete_scan(current_app.config["DATABASE"], scan_id):
        return json_error("not_found", "Scan not found.", 404)
    return jsonify({"deleted": scan_id})


@bp.delete("/api/scans")
def api_clear_scans():
    count = models.clear_scans(current_app.config["DATABASE"])
    return jsonify({"deleted": count})


@bp.get("/api/stats")
def api_stats():
    return jsonify(models.get_stats(current_app.config["DATABASE"]))
