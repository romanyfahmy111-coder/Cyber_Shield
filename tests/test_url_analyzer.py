import pytest

from app.scanner.url_analyzer import URLValidationError, analyze_url, validate_and_normalize


def flags(url):
    return {f["id"] for f in analyze_url(validate_and_normalize(url)) if f["status"] == "flag"}


@pytest.mark.parametrize("raw,code", [
    ("", "empty"), ("   ", "empty"),
    ("javascript:alert(1)", "unsupported_scheme"), ("ftp://example.com", "unsupported_scheme"),
    ("file:///etc/passwd", "unsupported_scheme"),
    ("http://a b.com", "invalid_characters"),
    ("http://127.0.0.1/", "non_public_address"), ("http://10.1.2.3/", "non_public_address"),
    ("http://169.254.169.254/", "non_public_address"), ("http://[::1]/", "non_public_address"),
    ("http://2130706433/", "non_public_address"), ("http://0x7f.0.0.1/", "non_public_address"),
    ("http://localhost:5000", "non_public_host"), ("http://intranet/", "non_public_host"),
    ("http://-bad.com", "malformed"), ("http://x..com", "malformed"), ("http:/example.com", "malformed"),
])
def test_rejected_inputs(raw, code):
    with pytest.raises(URLValidationError) as exc:
        validate_and_normalize(raw)
    assert exc.value.code == code


def test_too_long():
    with pytest.raises(URLValidationError) as exc:
        validate_and_normalize("http://example.com/" + "a" * 2100)
    assert exc.value.code == "too_long"


def test_normalization():
    p = validate_and_normalize("  GitHub.com/Path?x=1 ")
    assert p.normalized == "https://github.com/Path?x=1"
    assert p.assumed_scheme and p.registered_domain == "github.com"
    assert validate_and_normalize("https://Example.COM:443").normalized == "https://example.com/"
    assert validate_and_normalize("http://shop.example.co.uk/").registered_domain == "example.co.uk"


def test_obfuscated_public_ip_is_decoded_and_flagged():
    p = validate_and_normalize("http://0x5db8d822/")
    assert p.hostname == "93.184.216.34" and p.ip_obfuscated
    assert "ip_host" in flags("http://0x5db8d822/")


def test_clean_urls_have_no_flags():
    assert flags("https://github.com") == set()
    assert flags("https://www.google.com/search?q=cats") == set()


def test_at_symbol_hides_real_host():
    p = validate_and_normalize("http://paypal.com@evil.example.tk/x")
    assert p.hostname == "evil.example.tk"
    assert "at_symbol" in flags("http://paypal.com@evil.example.tk/x")


def test_phishing_indicators():
    f = flags("http://paypa1-secure-login.verify-account.tk/signin?update=1")
    assert {"keywords", "brand_impersonation", "url_scheme"} <= f


def test_legit_brand_domains_not_flagged():
    for url in ("https://login.microsoftonline.com/", "https://accounts.google.com/signin", "https://www.amazon.de/"):
        assert "brand_impersonation" not in flags(url)


def test_homograph_detected():
    assert "idn" in flags("https://аpple.com/")  # Cyrillic a


def test_shortener_and_subdomains_and_long_url():
    assert "shortener" in flags("https://bit.ly/abc")
    assert "subdomains" in flags("https://a.b.c.d.e.example.com/")
    assert "url_length" in flags("https://example.com/" + "a" * 300)
