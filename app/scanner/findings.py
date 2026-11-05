"""Shared structure for individual findings (one card in the report)."""

SEVERITIES = ("info", "low", "medium", "high", "critical")

# pass          - the check ran and found nothing notable
# flag          - the check ran and found an indicator
# info          - informational only (or not applicable for this URL)
# not_available - the check could NOT be completed (never shown as clean)
STATUSES = ("pass", "flag", "info", "not_available")


def make_finding(
    fid,
    check,
    result,
    *,
    status,
    explanation,
    severity="info",
    evidence="",
    recommendation="",
    source="PhishLens heuristic",
    points=0,
    group=None,
    confirmed=False,
    floor=0,
):
    if severity not in SEVERITIES:
        raise ValueError(f"bad severity {severity!r}")
    if status not in STATUSES:
        raise ValueError(f"bad status {status!r}")
    return {
        "id": fid,
        "check": check,
        "result": result,
        "status": status,
        "severity": severity,
        "explanation": explanation,
        "evidence": evidence,
        "recommendation": recommendation,
        "source": source,
        "points": points,
        "group": group,
        "confirmed": confirmed,
        "floor": floor,
    }
