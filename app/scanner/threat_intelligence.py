"""Stage 5: threat-intelligence integrations (VirusTotal, Google Safe Browsing).

Honesty rules:
* A provider that was not configured, failed, timed out or was rate limited is
  reported as "Not Available" - never as clean.
* "No match" from a provider only means "no known threat in that database".
* API keys are read from the server config and never returned to the browser.
"""
import base64
import hashlib
import time
from datetime import datetime, timezone

from . import netsafe
from .findings import make_finding

VT_BASE = "https://www.virustotal.com/api/v3"
GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

GSB_THREAT_LABELS = {
    "SOCIAL_ENGINEERING": "Phishing / social engineering",
    "MALWARE": "Malware",
    "UNWANTED_SOFTWARE": "Unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "Potentially harmful application",
}


def _result(provider, status, detail, **extra):
    base = {"provider": provider, "status": status, "detail": detail, "url_sent": False}
    base.update(extra)
    return base


def _vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _vt_summary(attrs, url_id=None):
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    counts = {k: int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")}
    total = sum(counts.values())
    flagged = []
    results = attrs.get("last_analysis_results") or attrs.get("results") or {}
    for engine, info in results.items():
        if isinstance(info, dict) and info.get("category") in ("malicious", "suspicious"):
            flagged.append({"engine": engine, "category": info["category"], "result": info.get("result") or ""})
    flagged.sort(key=lambda f: (f["category"] != "malicious", f["engine"].lower()))
    date = attrs.get("last_analysis_date") or attrs.get("date")
    analysed = None
    if isinstance(date, (int, float)):
        analysed = datetime.fromtimestamp(date, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return counts, total, flagged[:12], analysed


def check_virustotal(url, cfg):
    """Look the URL up on VirusTotal (submitting it if unknown and allowed)."""
    key = cfg.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return _result("virustotal", "not_configured", "No VirusTotal API key is configured on the server.")
    timeout = cfg.get("HTTP_TIMEOUT", 10)
    headers = {"x-apikey": key, "accept": "application/json"}
    url_id = _vt_url_id(url)

    def call(method, path, **kw):
        return netsafe.api_request(method, VT_BASE + path, headers=headers, timeout=timeout,
                                   max_bytes=3_000_000, **kw)

    def map_http_error(resp):
        if resp.status in (401, 403):
            return _result("virustotal", "error", "VirusTotal rejected the API key (HTTP %d)." % resp.status, url_sent=True)
        if resp.status == 429:
            return _result("virustotal", "rate_limited", "VirusTotal rate limit or quota reached. Try again later.", url_sent=True)
        return _result("virustotal", "error", f"VirusTotal answered with HTTP {resp.status}.", url_sent=True)

    try:
        resp = call("GET", f"/urls/{url_id}")
        if resp.status == 200:
            data = resp.json().get("data", {})
            counts, total, flagged, analysed = _vt_summary(data.get("attributes", {}))
            if total == 0:
                return _result("virustotal", "pending", "VirusTotal knows the URL but has no analysis results yet.", url_sent=True)
            vt_id = data.get("id") or hashlib.sha256(url.encode()).hexdigest()
            return _result("virustotal", "ok", "Existing VirusTotal report retrieved.", url_sent=True,
                           counts=counts, total=total, flagged=flagged, analysed_at=analysed, source="lookup",
                           permalink=f"https://www.virustotal.com/gui/url/{vt_id}")
        if resp.status != 404:
            return map_http_error(resp)

        # Not known to VirusTotal yet.
        if not cfg.get("VT_SUBMIT_UNKNOWN_URLS", True):
            return _result("virustotal", "not_found",
                           "VirusTotal has no report for this URL and submissions are disabled in the configuration.",
                           url_sent=True)
        sub = call("POST", "/urls", data={"url": url})
        if sub.status != 200:
            return map_http_error(sub)
        analysis_id = sub.json().get("data", {}).get("id")
        if not analysis_id:
            return _result("virustotal", "error", "VirusTotal did not return an analysis id.", url_sent=True)
        attempts = int(cfg.get("VT_POLL_ATTEMPTS", 5))
        interval = float(cfg.get("VT_POLL_INTERVAL", 3))
        for i in range(attempts):
            if i:
                time.sleep(interval)
            poll = call("GET", f"/analyses/{analysis_id}")
            if poll.status != 200:
                return map_http_error(poll)
            attrs = poll.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                counts, total, flagged, analysed = _vt_summary(attrs)
                return _result("virustotal", "ok", "URL was submitted to VirusTotal and analysed.", url_sent=True,
                               counts=counts, total=total, flagged=flagged, analysed_at=analysed, source="submission",
                               permalink=f"https://www.virustotal.com/gui/url/{hashlib.sha256(url.encode()).hexdigest()}")
        return _result("virustotal", "pending",
                       "The URL was submitted but VirusTotal had not finished analysing it in time.", url_sent=True)
    except netsafe.RequestFailed as exc:
        kind = "timeout" if exc.kind == "timeout" else "error"
        return _result("virustotal", kind, f"VirusTotal check failed: {exc.message}", url_sent=True)


def check_safe_browsing(url, cfg):
    """Query Google Safe Browsing v4 (threatMatches:find)."""
    key = cfg.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not key:
        return _result("safe_browsing", "not_configured", "No Google Safe Browsing API key is configured on the server.")
    body = {
        "client": {"clientId": "phishlens", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(GSB_THREAT_LABELS),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = netsafe.api_request("POST", GSB_ENDPOINT, params={"key": key}, json_body=body,
                                   timeout=cfg.get("HTTP_TIMEOUT", 10), max_bytes=500_000)
    except netsafe.RequestFailed as exc:
        kind = "timeout" if exc.kind == "timeout" else "error"
        return _result("safe_browsing", kind, f"Safe Browsing check failed: {exc.message}", url_sent=True)
    if resp.status in (400, 401, 403):
        return _result("safe_browsing", "error",
                       f"Google rejected the request or API key (HTTP {resp.status}). Check the key and that the Safe Browsing API is enabled.",
                       url_sent=True)
    if resp.status == 429:
        return _result("safe_browsing", "rate_limited", "Safe Browsing quota exceeded. Try again later.", url_sent=True)
    if resp.status != 200:
        return _result("safe_browsing", "error", f"Safe Browsing answered with HTTP {resp.status}.", url_sent=True)
    try:
        data = resp.json()
    except netsafe.RequestFailed as exc:
        return _result("safe_browsing", "error", exc.message, url_sent=True)
    matches = data.get("matches", []) if isinstance(data, dict) else []
    if not matches:
        return _result("safe_browsing", "ok", "No match in Google's Safe Browsing lists.", url_sent=True, threats=[])
    threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
    return _result("safe_browsing", "ok", "The URL matches Google's list of unsafe resources.", url_sent=True,
                   threats=threats, threat_labels=[GSB_THREAT_LABELS.get(t, t) for t in threats])


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

def _unavailable(fid, name, res, source):
    label = {
        "not_configured": "Not Available (not configured)",
        "timeout": "Not Available (timed out)",
        "rate_limited": "Not Available (rate limited)",
        "pending": "Not Available (analysis pending)",
        "not_found": "Not Available (no report)",
    }.get(res["status"], "Not Available (service error)")
    rec = "Add the API key to the server's .env file." if res["status"] == "not_configured" else "Try the scan again later."
    return make_finding(
        fid, name, label, status="not_available",
        explanation="This threat-intelligence source could not be consulted, so it contributes nothing to the verdict. "
                    "This is NOT a clean result.",
        evidence=res["detail"], recommendation=rec, source=source,
    )


def virustotal_finding(res, cfg):
    name, source = "VirusTotal", "VirusTotal API v3"
    if res["status"] != "ok":
        return _unavailable("virustotal", name, res, source)
    c, total = res["counts"], res["total"]
    ev = (f"malicious {c['malicious']}, suspicious {c['suspicious']}, harmless {c['harmless']}, "
          f"undetected {c['undetected']} (of {total} engines)")
    if res.get("flagged"):
        ev += "; flagged by: " + ", ".join(f["engine"] for f in res["flagged"][:6])
    threshold = int(cfg.get("VT_MALICIOUS_THRESHOLD", 3))
    if c["malicious"] >= threshold:
        return make_finding(
            "virustotal", name, f"{c['malicious']} engines report it malicious", status="flag", severity="critical",
            points=85, group="threat_intel", confirmed=True, floor=85, source=source,
            explanation="Multiple independent security engines on VirusTotal classify this URL as malicious.",
            evidence=ev, recommendation="Do not open this link or enter any information. Report it if you received it by email or message.",
        )
    if c["malicious"] >= 1:
        return make_finding(
            "virustotal", name, f"{c['malicious']} engine(s) report it malicious", status="flag", severity="high",
            points=40, group="threat_intel", source=source,
            explanation=f"Fewer than {threshold} engines flagged the URL. This may be a real threat or a false positive, "
                        "so it is treated as suspicious rather than confirmed.",
            evidence=ev, recommendation="Treat the link as dangerous until you can verify it independently.",
        )
    if c["suspicious"] >= 1:
        return make_finding(
            "virustotal", name, f"{c['suspicious']} engine(s) report it suspicious", status="flag", severity="medium",
            points=20, group="threat_intel", source=source,
            explanation="One or more engines consider the URL suspicious.",
            evidence=ev, recommendation="Be cautious and verify the destination.",
        )
    return make_finding(
        "virustotal", name, "No detections", status="pass", source=source,
        explanation="None of the engines flagged this URL. This only means no known threat was detected - "
                    "new or targeted phishing pages are often missed.",
        evidence=ev,
    )


def safe_browsing_finding(res, cfg):
    name, source = "Google Safe Browsing", "Google Safe Browsing API v4"
    if res["status"] != "ok":
        return _unavailable("safe_browsing", name, res, source)
    if res.get("threats"):
        labels = ", ".join(res["threat_labels"])
        return make_finding(
            "safe_browsing", name, f"Listed as unsafe: {labels}", status="flag", severity="critical",
            points=90, group="threat_intel", confirmed=True, floor=90, source=source,
            explanation="Google Safe Browsing lists this URL as an unsafe resource. This is a confirmed detection from a threat database.",
            evidence="Threat types: " + ", ".join(res["threats"]),
            recommendation="Do not open this link. Browsers that use Safe Browsing will show a warning page.",
        )
    return make_finding(
        "safe_browsing", name, "No match in Safe Browsing lists", status="pass", source=source,
        explanation="The URL is not currently in Google's lists of unsafe resources. This does not guarantee that it is safe.",
        evidence="threatMatches:find returned no matches",
    )
