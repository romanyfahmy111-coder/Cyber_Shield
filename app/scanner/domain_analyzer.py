"""Stage 3 (and the HTTPS part of stage 4): domain analysis.

* TLD reputation heuristic
* Domain age via RDAP (IANA bootstrap -> the TLD registry's own RDAP server)
* HTTPS inspection: a TLS handshake (no HTTP request) against a PUBLIC IP
  address that DNS returned for the host.  Private addresses are never contacted.
"""
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import netsafe
from .findings import make_finding
from .url_analyzer import SUSPICIOUS_TLDS

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_bootstrap_cache = {"fetched": 0.0, "data": None}
_bootstrap_lock = threading.Lock()

AGE_VERY_NEW_DAYS = 30
AGE_NEW_DAYS = 90
AGE_RECENT_DAYS = 365


# --------------------------------------------------------------------------
# TLD
# --------------------------------------------------------------------------

def analyze_tld(parsed):
    if parsed.is_ip:
        return make_finding(
            "tld", "Top-level domain (TLD)", "Not applicable", status="info",
            explanation="The URL uses an IP address, so there is no TLD.",
        )
    tld = parsed.tld
    if tld in ("zip", "mov"):
        return make_finding(
            "tld", "Top-level domain (TLD)", f".{tld} (file-name look-alike TLD)", status="flag",
            severity="medium", points=10, group="host_form",
            explanation=f".{tld} looks like a file extension, which makes links such as 'report.{tld}' easy to "
                        "mistake for files. It is frequently abused.",
            evidence=f"Registered domain: {parsed.registered_domain}",
            recommendation="Be careful with links that end in .zip or .mov.",
        )
    if tld in SUSPICIOUS_TLDS:
        return make_finding(
            "tld", "Top-level domain (TLD)", f".{tld} (often abused)", status="flag", severity="low",
            points=6, group="host_form",
            explanation=f"The .{tld} TLD is cheap or free and appears disproportionately in abuse reports. "
                        "Many legitimate sites also use it, so this is only a weak signal.",
            evidence=f"TLD: .{tld}  |  registered domain: {parsed.registered_domain}",
            recommendation="Look closely at the rest of the domain before trusting the page.",
        )
    return make_finding(
        "tld", "Top-level domain (TLD)", f".{tld}", status="pass",
        explanation="The TLD is not in the built-in list of frequently abused TLDs.",
        evidence=f"Registered domain: {parsed.registered_domain}",
    )


# --------------------------------------------------------------------------
# Domain age (RDAP)
# --------------------------------------------------------------------------

def _load_bootstrap(timeout):
    with _bootstrap_lock:
        if _bootstrap_cache["data"] is not None and time.time() - _bootstrap_cache["fetched"] < 86400:
            return _bootstrap_cache["data"]
    resp = netsafe.api_request("GET", RDAP_BOOTSTRAP_URL, timeout=timeout, max_bytes=1_000_000)
    if resp.status != 200:
        raise netsafe.RequestFailed("http", "The RDAP bootstrap service is unavailable.", resp.status)
    data = resp.json()
    with _bootstrap_lock:
        _bootstrap_cache["data"] = data
        _bootstrap_cache["fetched"] = time.time()
    return data


def _rdap_base_for(tld, bootstrap):
    for entry in bootstrap.get("services", []):
        tlds, urls = entry[0], entry[1]
        if tld in tlds:
            https = [u for u in urls if u.startswith("https://")]
            if https:
                return https[0] if https[0].endswith("/") else https[0] + "/"
    return None


def _parse_date(value):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def lookup_domain_age(parsed, timeout=10):
    """Returns a dict: status ok|not_available|disabled, plus created/age_days/detail."""
    if parsed.is_ip:
        return {"status": "not_applicable", "detail": "IP address"}
    try:
        bootstrap = _load_bootstrap(timeout)
        base = _rdap_base_for(parsed.tld, bootstrap)
        if base is None:
            return {"status": "not_available",
                    "detail": f"The .{parsed.tld} registry does not publish an RDAP service."}
        resp = netsafe.api_request(
            "GET", base + "domain/" + parsed.registered_domain,
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=timeout, max_bytes=1_500_000, max_redirects=3, verify_hosts=True,
        )
    except netsafe.RequestFailed as exc:
        return {"status": "not_available", "detail": exc.message}
    if resp.status == 404:
        return {"status": "not_available", "detail": "The registry has no RDAP record for this domain."}
    if resp.status == 429:
        return {"status": "not_available", "detail": "The registry rate-limited the lookup."}
    if resp.status != 200:
        return {"status": "not_available", "detail": f"The registry answered with HTTP {resp.status}."}
    try:
        data = resp.json()
    except netsafe.RequestFailed as exc:
        return {"status": "not_available", "detail": exc.message}
    created = None
    for event in data.get("events", []) if isinstance(data, dict) else []:
        if event.get("eventAction") == "registration":
            created = _parse_date(event.get("eventDate", ""))
            break
    if created is None:
        return {"status": "not_available", "detail": "The registry record has no registration date."}
    age_days = (datetime.now(timezone.utc) - created).days
    return {
        "status": "ok", "created": created.date().isoformat(), "age_days": max(age_days, 0),
        "source": urlsplit(base).hostname or "",
    }


def analyze_domain_age(info):
    src = "RDAP (IANA bootstrap)"
    if info["status"] == "not_applicable":
        return make_finding("domain_age", "Domain age", "Not applicable", status="info",
                            explanation="The URL uses an IP address, so there is no domain registration.")
    if info["status"] == "disabled":
        return make_finding("domain_age", "Domain age", "Not Available", status="not_available",
                            explanation="Domain-age lookup is disabled in the server configuration.", source=src)
    if info["status"] != "ok":
        return make_finding(
            "domain_age", "Domain age", "Not Available", status="not_available",
            explanation="The domain registration date could not be retrieved, so this check was not performed. "
                        "This is NOT a clean result.",
            evidence=info.get("detail", ""), source=src,
        )
    days = info["age_days"]
    ev = f"Registered {info['created']} ({days} days ago)"
    if days < AGE_VERY_NEW_DAYS:
        pts, sev, res = 25, "high", "Registered less than 30 days ago"
    elif days < AGE_NEW_DAYS:
        pts, sev, res = 12, "medium", "Registered less than 90 days ago"
    elif days < AGE_RECENT_DAYS:
        pts, sev, res = 4, "low", "Registered less than a year ago"
    else:
        return make_finding(
            "domain_age", "Domain age", f"{days // 365} year(s) old", status="pass",
            explanation="The domain has been registered for a long time. Age alone does not prove a site is trustworthy "
                        "(old domains can be hijacked).",
            evidence=ev, source=src,
        )
    return make_finding(
        "domain_age", "Domain age", res, status="flag", severity=sev, points=pts, group="domain_age",
        explanation="Most phishing domains are used within days or weeks of registration, so very new domains deserve extra caution.",
        evidence=ev, source=src,
        recommendation="Be especially careful if this site asks for credentials or payments.",
    )


# --------------------------------------------------------------------------
# HTTPS inspection (TLS handshake only)
# --------------------------------------------------------------------------

def _flatten_name(rdns):
    out = {}
    for rdn in rdns or ():
        for key, value in rdn:
            out[key] = value
    return out


def inspect_https(hostname, ips, timeout=5, port=443):
    """TLS handshake against public IPs only.  Never raises."""
    public_ips = [ip for ip in ips if netsafe.is_public_ip(ip)]
    if not public_ips:
        return {"status": "skipped", "detail": "No public IP address available to inspect."}
    context = ssl.create_default_context()
    last_error = None
    for ip in public_ips[:2]:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls:
                    cert = tls.getpeercert()
                    not_after = ssl.cert_time_to_seconds(cert["notAfter"]) if cert.get("notAfter") else None
                    days_left = int((not_after - time.time()) // 86400) if not_after else None
                    issuer = _flatten_name(cert.get("issuer"))
                    subject = _flatten_name(cert.get("subject"))
                    return {
                        "status": "ok", "ip": ip, "tls_version": tls.version(),
                        "issuer": issuer.get("organizationName") or issuer.get("commonName") or "unknown",
                        "subject": subject.get("commonName", ""),
                        "san_count": len(cert.get("subjectAltName", ())),
                        "not_after": datetime.fromtimestamp(not_after, timezone.utc).date().isoformat() if not_after else None,
                        "days_remaining": days_left,
                    }
        except ssl.SSLCertVerificationError as exc:
            return {"status": "invalid_certificate", "ip": ip,
                    "detail": exc.verify_message or "certificate verification failed"}
        except ssl.SSLError as exc:
            return {"status": "tls_error", "ip": ip, "detail": (exc.reason or "TLS handshake failed")}
        except ConnectionRefusedError:
            return {"status": "refused", "ip": ip, "detail": "Port 443 refused the connection."}
        except (socket.timeout, TimeoutError):
            last_error = "Connection to port 443 timed out."
        except OSError as exc:
            last_error = f"Could not connect to port 443 ({exc.__class__.__name__})."
    return {"status": "unreachable", "detail": last_error or "Could not connect to port 443."}


def analyze_https(result, parsed, enabled=True):
    src = "TLS handshake (port 443)"
    if not enabled:
        return make_finding("https_inspection", "HTTPS / certificate", "Not Available", status="not_available",
                            explanation="TLS inspection is disabled in the server configuration.", source=src)
    status = result["status"]
    if status == "skipped":
        return make_finding(
            "https_inspection", "HTTPS / certificate", "Not Available", status="not_available",
            explanation="The HTTPS check was skipped because there was no safe, public address to connect to. "
                        "This is NOT a clean result.",
            evidence=result["detail"], source=src,
        )
    if status == "ok":
        days = result["days_remaining"]
        ev = (f"{result['tls_version']}; issuer: {result['issuer']}; subject: {result['subject'] or 'n/a'}; "
              f"expires {result['not_after']} ({days} days left)")
        note = ""
        if parsed.scheme == "http":
            note = " The URL itself uses plain HTTP, although the server also supports HTTPS."
        return make_finding(
            "https_inspection", "HTTPS / certificate", "Valid certificate", status="pass",
            explanation="The server presented a certificate that is trusted and matches the hostname. "
                        "A valid certificate does not prove the site is legitimate - phishing sites obtain them too." + note,
            evidence=ev, source=src,
        )
    if status == "invalid_certificate":
        return make_finding(
            "https_inspection", "HTTPS / certificate", "Invalid certificate", status="flag", severity="high",
            points=18, group="transport",
            explanation="The server's certificate failed verification (expired, self-signed, wrong hostname or untrusted issuer). "
                        "Browsers will warn about this site.",
            evidence=result["detail"], source=src,
            recommendation="Do not bypass the browser warning or enter any information.",
        )
    if status == "refused":
        pts, sev = (12, "medium") if parsed.scheme == "https" else (5, "low")
        return make_finding(
            "https_inspection", "HTTPS / certificate", "HTTPS not offered", status="flag", severity=sev,
            points=pts, group="transport",
            explanation="The server does not accept HTTPS connections on port 443, so traffic cannot be encrypted.",
            evidence=result["detail"], source=src,
            recommendation="Avoid entering personal data on a site without HTTPS.",
        )
    if status == "tls_error":
        return make_finding(
            "https_inspection", "HTTPS / certificate", "TLS handshake failed", status="flag", severity="medium",
            points=10, group="transport",
            explanation="The server answered on port 443 but could not complete a secure TLS handshake.",
            evidence=result["detail"], source=src,
            recommendation="Treat the connection as insecure.",
        )
    return make_finding(
        "https_inspection", "HTTPS / certificate", "Not Available", status="not_available",
        explanation="PhishLens could not reach port 443 from this server, so HTTPS could not be inspected. "
                    "This may be a network restriction rather than a property of the site. This is NOT a clean result.",
        evidence=result.get("detail", ""), source=src,
    )
