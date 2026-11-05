import pytest

from app import create_app
from app.scanner import dns_analyzer, domain_analyzer


@pytest.fixture
def cfg(tmp_path):
    return {
        "DATABASE": str(tmp_path / "test.db"),
        "TESTING": True,
        "VIRUSTOTAL_API_KEY": "",
        "GOOGLE_SAFE_BROWSING_API_KEY": "",
        "RATE_LIMIT_SCAN": 1000,
        "RATE_LIMIT_API": 10000,
    }


@pytest.fixture
def offline(monkeypatch):
    """Replace every network-touching step with deterministic fakes."""
    def fake_resolve(hostname, registered, timeout=5):
        return {"status": "ok", "A": ["93.184.216.34"], "AAAA": [], "NS": ["ns1.example.net"],
                "MX": [], "cname": None, "spf": False, "errors": {}, "ips": ["93.184.216.34"]}

    monkeypatch.setattr(dns_analyzer, "resolve_host", fake_resolve)
    monkeypatch.setattr(domain_analyzer, "lookup_domain_age",
                        lambda parsed, timeout=10: {"status": "ok", "created": "2010-01-01", "age_days": 5000})
    monkeypatch.setattr(domain_analyzer, "inspect_https", lambda *a, **k: {
        "status": "ok", "ip": "93.184.216.34", "tls_version": "TLSv1.3", "issuer": "Test CA",
        "subject": "example.com", "san_count": 1, "not_after": "2030-01-01", "days_remaining": 1000})


@pytest.fixture
def app(cfg, offline):
    return create_app(cfg)


@pytest.fixture
def client(app):
    return app.test_client()
