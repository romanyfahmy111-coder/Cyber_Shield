from app.scanner import netsafe, threat_intelligence as ti

CFG = {"VIRUSTOTAL_API_KEY": "k", "GOOGLE_SAFE_BROWSING_API_KEY": "k", "HTTP_TIMEOUT": 2,
       "VT_SUBMIT_UNKNOWN_URLS": True, "VT_MALICIOUS_THRESHOLD": 3, "VT_POLL_ATTEMPTS": 2, "VT_POLL_INTERVAL": 1}


def resp(status, body=b"{}"):
    return netsafe.ApiResponse(status, {}, body)


def vt_body(mal=0, sus=0, har=60, und=10):
    import json
    return json.dumps({"data": {"id": "abc", "attributes": {
        "last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": har, "undetected": und, "timeout": 0},
        "last_analysis_results": {"EngineA": {"category": "malicious", "result": "phishing"}} if mal else {},
        "last_analysis_date": 1700000000}}}).encode()


def test_not_configured_is_not_available():
    res = ti.check_virustotal("https://x.com/", {"VIRUSTOTAL_API_KEY": ""})
    f = ti.virustotal_finding(res, CFG)
    assert res["status"] == "not_configured" and f["status"] == "not_available" and f["points"] == 0
    res = ti.check_safe_browsing("https://x.com/", {})
    assert ti.safe_browsing_finding(res, CFG)["status"] == "not_available"


def test_vt_confirmed_malicious(monkeypatch):
    monkeypatch.setattr(netsafe, "api_request", lambda *a, **k: resp(200, vt_body(mal=8)))
    f = ti.virustotal_finding(ti.check_virustotal("https://x.com/", CFG), CFG)
    assert f["confirmed"] and f["severity"] == "critical" and "8" in f["result"]


def test_vt_low_detection_is_suspicious_not_confirmed(monkeypatch):
    monkeypatch.setattr(netsafe, "api_request", lambda *a, **k: resp(200, vt_body(mal=1)))
    f = ti.virustotal_finding(ti.check_virustotal("https://x.com/", CFG), CFG)
    assert f["status"] == "flag" and not f["confirmed"]


def test_vt_clean(monkeypatch):
    monkeypatch.setattr(netsafe, "api_request", lambda *a, **k: resp(200, vt_body()))
    f = ti.virustotal_finding(ti.check_virustotal("https://x.com/", CFG), CFG)
    assert f["status"] == "pass" and "only means" in f["explanation"]


def test_vt_rate_limit_timeout_and_bad_key(monkeypatch):
    monkeypatch.setattr(netsafe, "api_request", lambda *a, **k: resp(429))
    assert ti.check_virustotal("https://x.com/", CFG)["status"] == "rate_limited"
    monkeypatch.setattr(netsafe, "api_request", lambda *a, **k: resp(401))
    assert ti.check_virustotal("https://x.com/", CFG)["status"] == "error"

    def boom(*a, **k):
        raise netsafe.RequestFailed("timeout", "The service timed out.")
    monkeypatch.setattr(netsafe, "api_request", boom)
    res = ti.check_virustotal("https://x.com/", CFG)
    assert res["status"] == "timeout"
    assert ti.virustotal_finding(res, CFG)["status"] == "not_available"


def test_vt_unknown_url_submission_and_polling(monkeypatch):
    import json
    calls = []

    def fake(method, url, **k):
        calls.append((method, url.split("/api/v3")[1]))
        if method == "GET" and "/urls/" in url:
            return resp(404)
        if method == "POST":
            return resp(200, json.dumps({"data": {"id": "an-1"}}).encode())
        return resp(200, json.dumps({"data": {"attributes": {"status": "completed", "stats": {
            "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5}, "results": {}}}}).encode())
    monkeypatch.setattr(netsafe, "api_request", fake)
    res = ti.check_virustotal("https://x.com/", CFG)
    assert res["status"] == "ok" and res["source"] == "submission"
    assert [c[0] for c in calls] == ["GET", "POST", "GET"]


def test_vt_no_submit_when_disabled(monkeypatch):
    monkeypatch.setattr(netsafe, "api_request", lambda *a, **k: resp(404))
    res = ti.check_virustotal("https://x.com/", dict(CFG, VT_SUBMIT_UNKNOWN_URLS=False))
    assert res["status"] == "not_found"


def test_safe_browsing_match_and_clean(monkeypatch):
    import json
    body = json.dumps({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}).encode()
    monkeypatch.setattr(netsafe, "api_request", lambda *a, **k: resp(200, body))
    f = ti.safe_browsing_finding(ti.check_safe_browsing("https://x.com/", CFG), CFG)
    assert f["confirmed"] and "Phishing" in f["result"]
    monkeypatch.setattr(netsafe, "api_request", lambda *a, **k: resp(200, b"{}"))
    f = ti.safe_browsing_finding(ti.check_safe_browsing("https://x.com/", CFG), CFG)
    assert f["status"] == "pass"


def test_safe_browsing_errors_never_leak_key(monkeypatch):
    monkeypatch.setattr(netsafe, "api_request", lambda *a, **k: resp(403))
    res = ti.check_safe_browsing("https://x.com/", dict(CFG, GOOGLE_SAFE_BROWSING_API_KEY="SECRETKEY123"))
    assert res["status"] == "error" and "SECRETKEY123" not in str(res)


def test_api_request_refuses_http_and_private_hosts():
    import pytest
    with pytest.raises(netsafe.RequestFailed):
        netsafe.api_request("GET", "http://example.com/")
    with pytest.raises(netsafe.RequestFailed):
        netsafe.api_request("GET", "https://127.0.0.1/", verify_hosts=True)
