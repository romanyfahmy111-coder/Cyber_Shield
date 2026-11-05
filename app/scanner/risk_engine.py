"""Stage 6: risk scoring and verdict.

Scoring model (kept deliberately explainable):

1. Every finding carries ``points`` and a ``group`` (host form, lexical clues,
   transport/HTTPS, domain age, DNS, threat intelligence).
2. Correlated indicators are not double counted: inside a group the strongest
   indicator counts fully, the second counts 50 %, the rest 25 %.  Threat
   intelligence counts only its strongest source (VirusTotal and Safe Browsing
   often flag the very same URL).
3. Each group is capped, so no single family of clues can reach 100 alone.
4. A *confirmed* detection from a threat-intelligence source sets a floor on
   the score (so it can never read as low risk).
"""

GROUP_CAPS = {
    "host_form": 40,
    "lexical": 40,
    "transport": 20,
    "domain_age": 25,
    "dns": 25,
    "threat_intel": 100,
}
GROUP_LABELS = {
    "host_form": "Host & domain form",
    "lexical": "URL wording & structure",
    "transport": "HTTPS / transport",
    "domain_age": "Domain age",
    "dns": "DNS",
    "threat_intel": "Threat intelligence",
}
GROUP_WEIGHTS = {"threat_intel": [1.0, 0.0]}
DEFAULT_WEIGHTS = [1.0, 0.5, 0.25]

LEVELS = ("low", "medium", "high", "critical")
LEVEL_LABELS = {"low": "Low Risk", "medium": "Medium Risk", "high": "High Risk", "critical": "Critical Risk"}

VERDICT_LABELS = {
    "confirmed_malicious": "Confirmed malicious",
    "suspicious": "Suspicious",
    "no_known_threats": "No known threats detected",
    "inconclusive": "Inconclusive - scan incomplete",
}

# Checks whose absence makes the overall scan "partial"/"incomplete".
TI_IDS = ("virustotal", "safe_browsing")
PARTIAL_IDS = ("virustotal", "safe_browsing", "https_inspection")


def classify(score, thresholds):
    medium, high, critical = thresholds
    if score >= critical:
        level = "critical"
    elif score >= high:
        level = "high"
    elif score >= medium:
        level = "medium"
    else:
        level = "low"
    return level, LEVEL_LABELS[level]


def _group_score(points, group):
    weights = GROUP_WEIGHTS.get(group, DEFAULT_WEIGHTS)
    ordered = sorted(points, reverse=True)
    total = 0.0
    for i, p in enumerate(ordered):
        total += p * weights[min(i, len(weights) - 1)]
    return total


def assess(findings, cfg):
    thresholds = tuple(cfg.get("RISK_THRESHOLDS", (30, 60, 80)))

    by_group = {}
    for f in findings:
        if f["status"] == "flag" and f["points"] > 0 and f["group"] in GROUP_CAPS:
            by_group.setdefault(f["group"], []).append(f["points"])

    breakdown, total = [], 0.0
    for group, cap in GROUP_CAPS.items():
        if group not in by_group:
            continue
        raw = sum(by_group[group])
        effective = min(cap, _group_score(by_group[group], group))
        total += effective
        breakdown.append({
            "group": group, "label": GROUP_LABELS[group], "raw": round(raw, 1),
            "effective": round(effective, 1), "cap": cap, "indicators": len(by_group[group]),
        })

    score = min(100, int(round(total)))
    floor = max([f.get("floor", 0) for f in findings if f.get("confirmed")] or [0])
    floor_applied = floor > score
    score = max(score, floor)
    level, classification = classify(score, thresholds)

    ids_not_available = {f["id"] for f in findings if f["status"] == "not_available"}
    confirmed = any(f.get("confirmed") for f in findings)
    ti_answered = sum(
        1 for f in findings if f["id"] in TI_IDS and f["status"] in ("pass", "flag")
    )
    dns_failed = "dns_resolution" in ids_not_available

    if ti_answered == 0 or dns_failed:
        status = "incomplete"
    elif ids_not_available & set(PARTIAL_IDS):
        status = "partial"
    else:
        status = "complete"

    ti_suspicious = any(
        f["id"] in TI_IDS and f["status"] == "flag" and not f.get("confirmed") for f in findings
    )
    if confirmed:
        verdict = "confirmed_malicious"
    elif score >= thresholds[0] or ti_suspicious:
        verdict = "suspicious"
    elif status == "incomplete":
        verdict = "inconclusive"
    else:
        verdict = "no_known_threats"

    flagged_n = sum(1 for f in findings if f["status"] == "flag")
    summary = {
        "confirmed_malicious": "A threat-intelligence source reports this URL as malicious. Do not open it.",
        "suspicious": f"{flagged_n} indicator(s) were flagged. These are heuristic warnings, not proof of malicious "
                      "intent - verify the destination before entering any information.",
        "no_known_threats": "No threat-intelligence source flagged this URL and no strong heuristic indicators were found. "
                            "This is not a guarantee that the site is safe.",
        "inconclusive": "Some key checks could not be completed (see 'Not Available' items), so PhishLens cannot say "
                        "whether this URL is safe. The score reflects only the checks that ran.",
    }[verdict]

    return {
        "score": score,
        "level": level,
        "classification": classification,
        "verdict": verdict,
        "verdict_label": VERDICT_LABELS[verdict],
        "status": status,
        "summary": summary,
        "breakdown": breakdown,
        "floor_applied": floor if floor_applied else None,
        "thresholds": {"medium": thresholds[0], "high": thresholds[1], "critical": thresholds[2]},
    }
