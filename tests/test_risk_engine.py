from app.scanner.findings import make_finding
from app.scanner.risk_engine import assess, classify

CFG = {"RISK_THRESHOLDS": (30, 60, 80)}


def flag(fid, pts, group, **kw):
    return make_finding(fid, fid, "x", status="flag", explanation="e", points=pts, group=group, severity="medium", **kw)


def ok(fid):
    return make_finding(fid, fid, "ok", status="pass", explanation="e")


def na(fid):
    return make_finding(fid, fid, "Not Available", status="not_available", explanation="e")


def test_classification_boundaries_and_configurable():
    t = (30, 60, 80)
    assert [classify(s, t)[0] for s in (0, 29, 30, 59, 60, 79, 80, 100)] == \
        ["low", "low", "medium", "medium", "high", "high", "critical", "critical"]
    assert classify(25, (20, 40, 60))[0] == "medium"


def test_correlated_indicators_not_double_counted():
    f = [flag("a", 20, "lexical"), flag("b", 20, "lexical"), flag("c", 20, "lexical")]
    r = assess(f, CFG)
    assert r["score"] == 35  # 20 + 10 + 5, not 60


def test_group_cap():
    f = [flag(str(i), 40, "lexical") for i in range(5)]
    assert assess(f, CFG)["score"] <= 40


def test_clean_but_unchecked_is_inconclusive_not_safe():
    r = assess([ok("a"), na("virustotal"), na("safe_browsing")], CFG)
    assert r["verdict"] == "inconclusive" and r["status"] == "incomplete"


def test_clean_with_threat_intel_is_no_known_threats():
    r = assess([ok("virustotal"), ok("safe_browsing"), ok("https_inspection")], CFG)
    assert r["verdict"] == "no_known_threats" and r["status"] == "complete" and r["score"] == 0


def test_confirmed_detection_sets_floor():
    vt = flag("virustotal", 85, "threat_intel", confirmed=True, floor=85)
    r = assess([vt], CFG)
    assert r["verdict"] == "confirmed_malicious" and r["score"] >= 85 and r["level"] == "critical"


def test_heuristics_alone_never_confirm():
    f = [flag("a", 40, "host_form"), flag("b", 40, "lexical"), flag("c", 20, "transport"),
         flag("d", 25, "domain_age"), flag("e", 25, "dns")]
    r = assess(f, CFG)
    assert r["verdict"] == "suspicious" and r["score"] <= 100
