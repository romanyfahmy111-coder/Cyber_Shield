import json

import pytest


def post(client, url, path="/api/scan", **kw):
    return client.post(path, json={"url": url}, **kw)


def test_pages_render(client):
    for path in ("/", "/history"):
        r = client.get(path)
        assert r.status_code == 200 and b"PhishLens" in r.data
    assert client.get("/report/999").status_code == 404
    assert client.get("/nope").status_code == 404


def test_status_never_exposes_keys(app):
    app.config["VIRUSTOTAL_API_KEY"] = "SUPERSECRET"
    r = app.test_client().get("/api/status")
    assert r.status_code == 200 and b"SUPERSECRET" not in r.data
    assert r.get_json()["providers"]["virustotal"]["configured"] is True


def test_scan_and_history_roundtrip(client):
    r = post(client, "https://example.com")
    assert r.status_code == 200
    data = r.get_json()
    report = data["report"]
    assert report["domain"] == "example.com"
    # threat intel is not configured -> must be Not Available, scan incomplete
    assert set(report["unavailable"]) == {"VirusTotal", "Google Safe Browsing"}
    assert report["risk"]["verdict"] == "inconclusive" and report["risk"]["status"] == "incomplete"

    listing = client.get("/api/scans").get_json()["scans"]
    assert len(listing) == 1 and listing[0]["id"] == data["id"]
    assert client.get(f"/api/scans/{data['id']}").get_json()["report"]["input_url"] == "https://example.com"
    assert client.get(f"/report/{data['id']}").status_code == 200
    stats = client.get("/api/stats").get_json()
    assert stats["total"] == 1 and stats["inconclusive"] == 1

    assert client.delete(f"/api/scans/{data['id']}").status_code == 200
    assert client.delete(f"/api/scans/{data['id']}").status_code == 404
    post(client, "https://example.com")
    assert client.delete("/api/scans").get_json()["deleted"] == 1
    assert client.get("/api/scans").get_json()["scans"] == []


@pytest.mark.parametrize("body,code", [
    ({}, "invalid_request"), ({"url": 5}, "invalid_request"), ([1], "invalid_request"),
    ({"url": ""}, "empty"), ({"url": "javascript:alert(1)"}, "unsupported_scheme"),
    ({"url": "http://127.0.0.1/"}, "non_public_address"),
    ({"url": "http://169.254.169.254/latest/meta-data"}, "non_public_address"),
    ({"url": "http://localhost/"}, "non_public_host"),
])
def test_invalid_inputs(client, body, code):
    r = client.post("/api/scan", json=body)
    assert r.status_code == 400 and r.get_json()["error"]["code"] == code
    assert client.get("/api/scans").get_json()["scans"] == []  # failed scans are not stored


def test_content_type_and_size_limits(client):
    assert client.post("/api/scan", data='{"url":"x.com"}').status_code == 415
    assert client.post("/api/scan", json={"url": "a" * 20000}).status_code == 413
    assert client.post("/api/scan", data="not json", content_type="application/json").status_code == 400


def test_stream_emits_real_stages_then_result(client):
    r = post(client, "https://example.com", "/api/scan/stream")
    assert r.status_code == 200 and r.mimetype == "text/event-stream"
    events = [json.loads(l[6:]) for l in r.get_data(as_text=True).split("\n") if l.startswith("data: ")]
    stages = [e for e in events if e["type"] == "stage"]
    assert [s["id"] for s in stages if s["state"] == "running"] == \
        ["validate", "structure", "domain", "dns", "threat", "risk", "report"]
    assert events[-1]["type"] == "result" and "id" in events[-1]
    assert client.get("/api/scans").get_json()["scans"][0]["id"] == events[-1]["id"]


def test_stream_reports_validation_error(client):
    r = post(client, "ftp://x.com", "/api/scan/stream")
    events = [json.loads(l[6:]) for l in r.get_data(as_text=True).split("\n") if l.startswith("data: ")]
    assert events[-1]["type"] == "error" and events[-1]["error"]["code"] == "unsupported_scheme"


def test_heuristics_flag_phishing_like_url(client):
    r = post(client, "http://paypa1-secure-login.verify-account.tk/signin?update=1")
    risk = r.get_json()["report"]["risk"]
    assert risk["verdict"] == "suspicious" and risk["score"] >= 30


def test_security_headers_and_cross_origin(client):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    r = client.post("/api/scan", json={"url": "https://example.com"}, headers={"Origin": "http://evil.com"})
    assert r.status_code == 403
    assert client.get("/api/scan").status_code == 405


def test_rate_limit(cfg, offline):
    from app import create_app
    app = create_app(dict(cfg, RATE_LIMIT_SCAN=2))
    c = app.test_client()
    codes = [c.post("/api/scan", json={"url": "https://example.com"}).status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]
    assert c.post("/api/scan", json={"url": "https://example.com"}).headers["Retry-After"]


def test_unexpected_error_hides_details(app, monkeypatch):
    from app import routes
    monkeypatch.setattr(routes.models, "list_scans", lambda *a, **k: 1 / 0)
    app.config["PROPAGATE_EXCEPTIONS"] = False
    r = app.test_client().get("/api/scans")
    assert r.status_code == 500
    assert "ZeroDivision" not in r.get_data(as_text=True) and "Traceback" not in r.get_data(as_text=True)


def test_sql_injection_is_inert(client):
    r = post(client, "https://example.com/?q=';DROP/**/TABLE/**/scans;--")
    assert r.status_code == 200
    assert len(client.get("/api/scans").get_json()["scans"]) == 1
    assert client.get("/api/stats").get_json()["total"] == 1  # table still exists
