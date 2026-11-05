"""Stage 4: DNS analysis (A, AAAA, NS, MX and SPF presence) using dnspython."""
import dns.exception
import dns.resolver

from . import netsafe
from .findings import make_finding


def _query(resolver, name, rtype):
    """Return (status, answers).  status: ok | no_data | nxdomain | error."""
    try:
        answer = resolver.resolve(name, rtype, raise_on_no_answer=True)
        return "ok", answer
    except dns.resolver.NXDOMAIN:
        return "nxdomain", None
    except dns.resolver.NoAnswer:
        return "no_data", None
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return "error", None
    except dns.exception.DNSException:
        return "error", None


def resolve_host(hostname, registered_domain, timeout=5):
    """Look up DNS records.  Never raises; failures are reported in the result."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = float(timeout)
    resolver.timeout = float(timeout)

    result = {
        "status": "ok",            # ok | no_data | nxdomain | error
        "A": [], "AAAA": [], "NS": [], "MX": [],
        "cname": None, "spf": None, "errors": {}, "ips": [],
    }

    st, ans = _query(resolver, hostname, "A")
    if st == "ok":
        result["A"] = sorted({r.address for r in ans})
        canonical = str(ans.canonical_name).rstrip(".").lower()
        if canonical != hostname.lower():
            result["cname"] = canonical
    elif st in ("nxdomain", "error"):
        result["status"] = st
        if st == "error":
            result["errors"]["A"] = "lookup failed or timed out"
        return result
    st6, ans6 = _query(resolver, hostname, "AAAA")
    if st6 == "ok":
        result["AAAA"] = sorted({r.address for r in ans6})
    elif st6 == "error":
        result["errors"]["AAAA"] = "lookup failed or timed out"

    result["ips"] = result["A"] + result["AAAA"]
    if not result["ips"]:
        result["status"] = "no_data"

    stn, ansn = _query(resolver, registered_domain, "NS")
    if stn == "ok":
        result["NS"] = sorted(str(r.target).rstrip(".").lower() for r in ansn)
    elif stn == "error":
        result["errors"]["NS"] = "lookup failed or timed out"
    stm, ansm = _query(resolver, registered_domain, "MX")
    if stm == "ok":
        result["MX"] = sorted(str(r.exchange).rstrip(".").lower() for r in ansm)
    elif stm == "error":
        result["errors"]["MX"] = "lookup failed or timed out"
    stt, anst = _query(resolver, registered_domain, "TXT")
    if stt == "ok":
        result["spf"] = any(
            b"v=spf1" in b"".join(r.strings).lower() for r in anst
        )
    elif stt == "error":
        result["errors"]["TXT"] = "lookup failed or timed out"
    return result


def analyze_dns(dns_result, parsed):
    """Convert raw DNS results into findings."""
    findings = []
    if parsed.is_ip:
        findings.append(make_finding(
            "dns_resolution", "DNS resolution", "Not applicable", status="info",
            explanation="The URL uses an IP address directly, so no DNS lookup is needed.",
            evidence=f"Host: {parsed.hostname}", source="DNS",
        ))
        return findings

    status = dns_result["status"]
    if status == "nxdomain":
        findings.append(make_finding(
            "dns_resolution", "DNS resolution", "Domain does not exist (NXDOMAIN)", status="flag",
            severity="medium", points=10, group="dns", source="DNS",
            explanation="The domain has no DNS records. The site cannot be reached - it may be mistyped, expired "
                        "or a phishing site that has already been taken down.",
            evidence=f"NXDOMAIN for {parsed.hostname}",
            recommendation="Do not rely on this URL. Check where you got the link from.",
        ))
    elif status == "error":
        findings.append(make_finding(
            "dns_resolution", "DNS resolution", "Not Available", status="not_available",
            explanation="The DNS lookup failed or timed out, so DNS-based checks could not be completed. "
                        "This is NOT a clean result.",
            evidence=dns_result["errors"].get("A", "resolver error"), source="DNS",
            recommendation="Try the scan again later.",
        ))
    elif status == "no_data":
        findings.append(make_finding(
            "dns_resolution", "DNS resolution", "No address records", status="flag", severity="low",
            points=5, group="dns", source="DNS",
            explanation="The name exists but has no A/AAAA records, so it does not point to a web server.",
            evidence=f"No A or AAAA records for {parsed.hostname}",
        ))
    else:
        ips = dns_result["ips"]
        shown = ", ".join(ips[:6]) + (f" (+{len(ips) - 6} more)" if len(ips) > 6 else "")
        findings.append(make_finding(
            "dns_resolution", "DNS resolution", f"Resolves to {len(ips)} address(es)", status="pass",
            explanation="The domain has valid address records.",
            evidence=shown + (f"; CNAME -> {dns_result['cname']}" if dns_result["cname"] else ""),
            source="DNS",
        ))
        private = [ip for ip in ips if not netsafe.is_public_ip(ip)]
        if private:
            findings.append(make_finding(
                "dns_ip_scope", "Resolved IP scope", "Points to a non-public address", status="flag",
                severity="high", points=25, group="dns", source="DNS",
                explanation="A public domain resolving to a private/loopback address is a sign of DNS rebinding "
                            "or a misconfigured/hijacked record. PhishLens refuses to connect to it.",
                evidence="Non-public addresses: " + ", ".join(private[:5]),
                recommendation="Do not open this link.",
            ))
        else:
            findings.append(make_finding(
                "dns_ip_scope", "Resolved IP scope", "All addresses are public", status="pass",
                explanation="Every resolved address is a public Internet address.",
                evidence=shown, source="DNS",
            ))

    if status in ("ok", "no_data"):
        bits = []
        bits.append(f"NS: {', '.join(dns_result['NS'][:4]) if dns_result['NS'] else 'none found'}")
        bits.append(f"MX: {', '.join(dns_result['MX'][:3]) if dns_result['MX'] else 'none found'}")
        if dns_result["spf"] is not None:
            bits.append("SPF: " + ("present" if dns_result["spf"] else "absent"))
        findings.append(make_finding(
            "dns_records", "Name servers & mail records", "Collected", status="info",
            explanation="Informational DNS data. Missing mail records are normal for many web-only domains "
                        "and are not scored.",
            evidence="; ".join(bits), source="DNS",
        ))
    return findings
