"""Runs the seven scan stages and yields *real* progress events.

Each event is emitted when the corresponding backend step actually starts or
finishes, so the browser animation reflects genuine work (no fake timers).
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import (
    dns_analyzer,
    domain_analyzer,
    risk_engine,
    threat_intelligence,
    url_analyzer,
)
from .findings import make_finding
from .url_analyzer import URLValidationError

log = logging.getLogger(__name__)

STAGES = [
    ("validate", "Validating URL..."),
    ("structure", "Analyzing URL structure..."),
    ("domain", "Checking domain information..."),
    ("dns", "Checking DNS records..."),
    ("threat", "Consulting threat intelligence..."),
    ("risk", "Calculating risk score..."),
    ("report", "Generating security report..."),
]

DISCLAIMER = (
    "PhishLens combines heuristic indicators with third-party threat-intelligence lookups. Heuristic warnings are "
    "not proof of malicious intent, and 'no known threats' is not a guarantee of safety. The URL itself is never "
    "opened or fetched by this server."
)


def _safe_provider(fn, name, url, cfg):
    try:
        return fn(url, cfg)
    except Exception:  # pragma: no cover - defensive
        log.exception("Unexpected error in %s check", name)
        return {"provider": name, "status": "error", "url_sent": False,
                "detail": "An unexpected internal error occurred during this check."}


def _flag_count(findings):
    return sum(1 for f in findings if f["status"] == "flag")


def run_scan(raw_url, cfg):
    started = time.monotonic()
    ctx = {"findings": [], "parsed": None, "dns": None, "https": None,
           "domain_info": None, "vt": None, "gsb": None, "risk": None}
    stage_log = []

    def begin(i):
        return {"type": "stage", "index": i, "id": STAGES[i][0], "label": STAGES[i][1], "state": "running"}

    def finish(i, t0, state, detail):
        ev = {"type": "stage", "index": i, "id": STAGES[i][0], "label": STAGES[i][1], "state": state,
              "detail": detail, "elapsed_ms": int((time.monotonic() - t0) * 1000)}
        stage_log.append({k: ev[k] for k in ("id", "label", "state", "detail", "elapsed_ms")})
        return ev

    # ---------------- Stage 1: validation ----------------
    yield begin(0)
    t0 = time.monotonic()
    try:
        parsed = url_analyzer.validate_and_normalize(raw_url, cfg.get("MAX_URL_LENGTH", 2048))
    except URLValidationError as exc:
        yield finish(0, t0, "failed", exc.message)
        yield {"type": "error", "error": {"code": exc.code, "message": exc.message}}
        return
    ctx["parsed"] = parsed
    yield finish(0, t0, "done", f"Host: {parsed.hostname}" + (" (IP address)" if parsed.is_ip else ""))

    findings = ctx["findings"]

    # ---------------- Stage 2: URL structure ----------------
    def s_structure():
        found = url_analyzer.analyze_url(parsed)
        findings.extend(found)
        n = _flag_count(found)
        return ("warning" if n else "done",
                f"{n} indicator(s) flagged out of {len(found)} checks" if n else f"{len(found)} checks, no indicators")

    # ---------------- Stage 3: domain ----------------
    def s_domain():
        findings.append(domain_analyzer.analyze_tld(parsed))
        if parsed.is_ip:
            age = {"status": "not_applicable"}
        elif cfg.get("ENABLE_DOMAIN_AGE", True):
            age = domain_analyzer.lookup_domain_age(parsed, cfg.get("HTTP_TIMEOUT", 10))
        else:
            age = {"status": "disabled"}
        findings.append(domain_analyzer.analyze_domain_age(age))
        ctx["domain_info"] = {
            "registered_domain": parsed.registered_domain, "suffix": parsed.suffix, "tld": parsed.tld,
            "subdomains": parsed.subdomain_labels, "age": age,
        }
        if parsed.is_ip:
            return "skipped", "The URL uses an IP address, so there is no domain to look up"
        if age["status"] == "ok":
            return "done", f"{parsed.registered_domain} registered {age['created']} ({age['age_days']} days ago)"
        return "warning", f"{parsed.registered_domain}: domain age not available"

    # ---------------- Stage 4: DNS (+ HTTPS inspection) ----------------
    def s_dns():
        if parsed.is_ip:
            dns_res = {"status": "not_applicable", "ips": [parsed.ip]}
        else:
            dns_res = dns_analyzer.resolve_host(parsed.hostname, parsed.registered_domain, cfg.get("DNS_TIMEOUT", 5))
        ctx["dns"] = dns_res
        findings.extend(dns_analyzer.analyze_dns(dns_res, parsed))

        enabled = cfg.get("ENABLE_TLS_INSPECTION", True)
        if dns_res["status"] in ("nxdomain", "no_data"):
            https = {"status": "not_applicable", "detail": "The host has no address records."}
            findings.append(make_finding(
                "https_inspection", "HTTPS / certificate", "Not applicable", status="info",
                explanation="There is no server to inspect because the host does not resolve.",
                source="TLS handshake (port 443)"))
        else:
            if not enabled or dns_res["status"] == "error":
                https = {"status": "skipped",
                         "detail": "DNS lookup failed." if enabled else "TLS inspection is disabled."}
            else:
                https = domain_analyzer.inspect_https(parsed.hostname, dns_res["ips"], cfg.get("TLS_TIMEOUT", 5))
            findings.append(domain_analyzer.analyze_https(https, parsed, enabled))
        ctx["https"] = https

        bad = [f["check"] for f in findings[-4:] if f["status"] == "not_available"]
        if parsed.is_ip:
            return ("warning" if bad else "done"), "DNS lookup skipped (IP address); HTTPS " + (
                "could not be inspected" if bad else "inspected")
        if dns_res["status"] == "error":
            return "warning", "DNS lookup failed or timed out"
        if dns_res["status"] == "nxdomain":
            return "warning", "Domain does not exist (NXDOMAIN)"
        n_ips = len(dns_res["ips"])
        return ("warning" if bad else "done"), f"{n_ips} address(es); HTTPS " + (
            "not available" if bad else https["status"].replace("_", " "))

    # ---------------- Stage 5: threat intelligence ----------------
    def s_threat():
        url = parsed.normalized
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_vt = pool.submit(_safe_provider, threat_intelligence.check_virustotal, "virustotal", url, cfg)
            f_gsb = pool.submit(_safe_provider, threat_intelligence.check_safe_browsing, "safe_browsing", url, cfg)
            vt, gsb = f_vt.result(), f_gsb.result()
        ctx["vt"], ctx["gsb"] = vt, gsb
        new = [threat_intelligence.virustotal_finding(vt, cfg), threat_intelligence.safe_browsing_finding(gsb, cfg)]
        findings.extend(new)
        ok = [f for f in new if f["status"] != "not_available"]
        detail = f"VirusTotal: {vt['status'].replace('_', ' ')}; Safe Browsing: {gsb['status'].replace('_', ' ')}"
        return ("done" if len(ok) == 2 else "warning"), detail

    # ---------------- Stage 6: risk ----------------
    def s_risk():
        risk = risk_engine.assess(findings, cfg)
        ctx["risk"] = risk
        return "done", f"Score {risk['score']}/100 - {risk['classification']} ({risk['verdict_label']})"

    for idx, fn in ((1, s_structure), (2, s_domain), (3, s_dns), (4, s_threat), (5, s_risk)):
        yield begin(idx)
        t0 = time.monotonic()
        try:
            state, detail = fn()
        except Exception:
            log.exception("Stage %s failed", STAGES[idx][0])
            state, detail = "failed", "This stage hit an internal error."
            if idx != 5:
                findings.append(make_finding(
                    f"internal_{STAGES[idx][0]}", STAGES[idx][1].rstrip("."), "Not Available",
                    status="not_available",
                    explanation="An internal error prevented this check from running. This is NOT a clean result."))
        yield finish(idx, t0, state, detail)

    if ctx["risk"] is None:
        yield {"type": "error", "error": {"code": "internal_error", "message": "The risk score could not be calculated."}}
        return

    # ---------------- Stage 7: report ----------------
    yield begin(6)
    t0 = time.monotonic()
    risk = ctx["risk"]
    vt, gsb = ctx["vt"] or {}, ctx["gsb"] or {}
    shared = [name for name, res in (("VirusTotal", vt), ("Google Safe Browsing", gsb)) if res.get("url_sent")]
    report = {
        "version": 1,
        "input_url": parsed.original,
        "normalized_url": parsed.normalized,
        "hostname": parsed.hostname,
        "domain": parsed.display_domain,
        "is_ip": parsed.is_ip,
        "notes": parsed.notes,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "risk": risk,
        "findings": findings,
        "unavailable": [f["check"] for f in findings if f["status"] == "not_available"],
        "threat_intel": {"virustotal": vt, "safe_browsing": gsb},
        "dns": ctx["dns"],
        "https": ctx["https"],
        "domain_info": ctx["domain_info"],
        "url_shared_with": shared,
        "stages": stage_log,
        "disclaimer": DISCLAIMER,
    }
    ev = finish(6, t0, "done", f"{len(findings)} findings, {len(report['unavailable'])} unavailable")
    report["duration_ms"] = int((time.monotonic() - started) * 1000)
    yield ev
    yield {"type": "result", "report": report}
