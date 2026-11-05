"""Stage 1 and 2: URL validation / normalization and URL-structure analysis.

Everything here works on the URL *string only* - nothing is fetched.
"""
import ipaddress
import math
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import netsafe
from .findings import make_finding

# --------------------------------------------------------------------------
# Data tables (edit these to tune detection)
# --------------------------------------------------------------------------

# Public-suffix list is intentionally not bundled; this covers the common
# multi-part suffixes so "bank.co.uk" is split correctly.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au",
    "edu.au", "gov.au", "co.nz", "org.nz", "co.jp", "or.jp", "ne.jp", "co.in",
    "net.in", "org.in", "com.br", "net.br", "org.br", "com.eg", "edu.eg",
    "gov.eg", "org.eg", "net.eg", "com.sa", "com.tr", "org.tr", "co.za",
    "org.za", "com.mx", "com.cn", "net.cn", "org.cn", "com.hk", "com.sg",
    "com.my", "co.il", "com.ar", "com.co", "co.kr", "or.kr", "com.ng", "co.ke",
    "com.pk", "com.ph", "com.vn", "com.ua", "co.id", "com.tw", "com.pe",
    "com.ve", "com.ec", "com.uy", "co.th", "com.bd", "com.ae", "com.qa",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "zip", "mov", "work",
    "support", "rest", "country", "kim", "loan", "men", "party", "review",
    "stream", "download", "science", "racing", "win", "bid", "icu", "cyou",
    "cfd", "sbs", "buzz", "monster", "quest",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "bit.do", "lnkd.in",
    "t.ly", "rb.gy", "s.id", "v.gd", "shorte.st", "adf.ly", "bl.ink", "soo.gd",
    "clck.ru", "qr.ae", "trib.al", "amzn.to", "fb.me", "wp.me", "lnk.to",
    "urlz.fr", "tr.im", "cli.re", "short.io", "shrtco.de", "ouo.io", "gg.gg",
}

KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "validate",
    "secure", "security", "account", "update", "confirm", "password", "passwd",
    "credential", "banking", "wallet", "billing", "invoice", "payment",
    "suspend", "locked", "unlock", "recover", "restore", "authenticate",
    "webscr", "ebayisapi", "helpdesk", "alert", "reactivate", "urgent",
    "claim", "prize", "giftcard", "bonus", "2fa", "otp",
)

# brand -> legitimate registered domains.  Brands of 6+ letters are matched as
# substrings ("paypalsecure"); shorter ones only as whole tokens ("apple-id").
BRANDS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "google": {"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
               "googlevideo.com", "ggpht.com", "googleadservices.com",
               "googlesyndication.com", "youtube.com", "withgoogle.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com",
                  "office365.com", "outlook.com", "windows.com", "azure.com",
                  "msn.com", "bing.com", "sharepoint.com", "skype.com", "xbox.com"},
    "apple": {"apple.com", "icloud.com", "cdn-apple.com", "mzstatic.com"},
    "amazon": {"amazon.com", "amazonaws.com", "media-amazon.com",
               "ssl-images-amazon.com", "amazon.jobs"},
    "facebook": {"facebook.com", "fb.com", "fbcdn.net", "facebook.net", "messenger.com", "meta.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com", "nflxso.net", "nflximg.net", "nflxext.com", "nflxvideo.net"},
    "linkedin": {"linkedin.com", "licdn.com"},
    "dropbox": {"dropbox.com", "dropboxapi.com", "dropboxstatic.com", "dropboxusercontent.com"},
    "ebay": {"ebay.com", "ebaystatic.com", "ebayimg.com"},
    "github": {"github.com", "github.io", "githubusercontent.com", "githubassets.com", "githubstatus.com"},
    "adobe": {"adobe.com", "adobelogin.com", "adobe.io", "typekit.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "hsbc": {"hsbc.com"},
    "binance": {"binance.com", "binance.us"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "spotify": {"spotify.com", "scdn.co", "spotifycdn.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "zoom": {"zoom.us", "zoom.com"},
    "telegram": {"telegram.org", "t.me", "telegram.me"},
    "tiktok": {"tiktok.com", "tiktokcdn.com", "tiktokv.com"},
    "yahoo": {"yahoo.com", "yimg.com"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "twitter": {"twitter.com", "x.com", "twimg.com", "t.co"},
}

_HOST_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_UNSAFE_CHARS = re.compile(
    "[\x00-\x20\x7f-\x9f   -‏ -  ⁠　﻿]"
)
_SCHEME_START = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\d+(?:[/?#]|$))")
_EMBEDDED_URL = re.compile(r"https?(?::|%3a)(?:/|%2f){2}", re.I)

LEET = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"}


# --------------------------------------------------------------------------
# Parsing / validation
# --------------------------------------------------------------------------

class URLValidationError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    hostname: str  # ASCII (punycode) host, or canonical IP
    unicode_host: str
    port: int | None
    path: str
    query: str
    userinfo: str | None
    is_ip: bool
    ip: str | None
    ip_obfuscated: bool
    registered_domain: str
    suffix: str
    tld: str
    subdomain_labels: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    assumed_scheme: bool = False
    had_backslash: bool = False

    @property
    def display_domain(self):
        return self.registered_domain or self.hostname


def split_domain(host):
    """Heuristic registered-domain split (no public-suffix list)."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        suffix_len = 2
    else:
        suffix_len = 1
    if len(labels) <= suffix_len:
        return host, ".".join(labels[-suffix_len:]), labels[-1], []
    registered = ".".join(labels[-(suffix_len + 1):])
    suffix = ".".join(labels[-suffix_len:])
    return registered, suffix, labels[-1], labels[: -(suffix_len + 1)]


def _to_ascii_host(host):
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        raise URLValidationError("malformed", "The hostname contains invalid international characters.") from None


def validate_and_normalize(raw, max_length=2048):
    """Stage 1.  Returns a ParsedURL or raises URLValidationError."""
    if not isinstance(raw, str):
        raise URLValidationError("empty", "Please enter a URL.")
    text = raw.strip()
    if not text:
        raise URLValidationError("empty", "Please enter a URL.")
    if len(text) > max_length:
        raise URLValidationError("too_long", f"The URL is longer than {max_length} characters.")
    if _UNSAFE_CHARS.search(text):
        raise URLValidationError("invalid_characters", "The URL contains spaces or control characters.")

    notes = []
    had_backslash = "\\" in text
    if had_backslash:
        text = text.replace("\\", "/")
        notes.append("Backslashes were converted to forward slashes, as browsers do.")

    assumed = False
    if text.startswith("//"):
        text = "https:" + text
        assumed = True
        notes.append("A protocol-relative URL was entered, so https:// was assumed.")
    elif "://" in text:
        scheme = text.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise URLValidationError("unsupported_scheme", "Only http:// and https:// URLs can be analyzed.")
    elif re.match(r"^https?:", text, re.I):
        raise URLValidationError("malformed", "The URL scheme is malformed (expected http:// or https://).")
    elif _SCHEME_START.match(text):
        raise URLValidationError("unsupported_scheme", "Only http:// and https:// URLs can be analyzed.")
    else:
        text = "https://" + text
        assumed = True
        notes.append("No scheme was entered, so https:// was assumed.")

    try:
        parts = urlsplit(text)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise URLValidationError("malformed", "The URL is malformed (invalid host or port).") from None
    if not host:
        raise URLValidationError("no_host", "The URL does not contain a hostname.")
    if port is not None and port == 0:
        raise URLValidationError("malformed", "The URL port is invalid.")

    scheme = parts.scheme.lower()
    userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else None
    host = host.rstrip(".")
    if not host:
        raise URLValidationError("no_host", "The URL does not contain a hostname.")

    ip, obfuscated = None, False
    if ":" in host:  # IPv6 literal
        ip = netsafe.strict_ip(host)
        if ip is None:
            raise URLValidationError("malformed", "The IPv6 address in the URL is invalid.")
        ascii_host = str(ip)
    else:
        ascii_host = _to_ascii_host(host).lower()
        if len(ascii_host) > 253:
            raise URLValidationError("malformed", "The hostname is too long.")
        for label in ascii_host.split("."):
            if not _HOST_LABEL.match(label):
                raise URLValidationError("malformed", "The hostname contains invalid characters or labels.")
        try:
            ip, obfuscated = netsafe.parse_ip_host(ascii_host)
        except ValueError:
            raise URLValidationError("malformed", "The numeric hostname is not a valid IP address.") from None
        if ip is not None:
            ascii_host = str(ip)

    if ip is not None:
        if not netsafe.is_public_ip(ip):
            raise URLValidationError(
                "non_public_address",
                "This URL points to a private, loopback or reserved IP address. "
                "PhishLens only analyzes public URLs.",
            )
    elif netsafe.is_internal_hostname(ascii_host):
        raise URLValidationError(
            "non_public_host",
            "This looks like an internal or non-public hostname. PhishLens only analyzes public URLs.",
        )

    default_port = 443 if scheme == "https" else 80
    host_for_url = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    netloc = host_for_url if port in (None, default_port) else f"{host_for_url}:{port}"
    path = parts.path or "/"
    normalized = f"{scheme}://{netloc}{path}" + (f"?{parts.query}" if parts.query else "")

    try:
        unicode_host = ascii_host.encode("ascii").decode("idna") if "xn--" in ascii_host else ascii_host
    except UnicodeError:
        unicode_host = ascii_host

    if ip is not None:
        registered, suffix, tld, subs = str(ip), "", "", []
    else:
        registered, suffix, tld, subs = split_domain(ascii_host)

    return ParsedURL(
        original=raw.strip(), normalized=normalized, scheme=scheme, hostname=ascii_host,
        unicode_host=unicode_host, port=port, path=path, query=parts.query, userinfo=userinfo,
        is_ip=ip is not None, ip=str(ip) if ip is not None else None, ip_obfuscated=obfuscated,
        registered_domain=registered, suffix=suffix, tld=tld, subdomain_labels=subs,
        notes=notes, assumed_scheme=assumed, had_backslash=had_backslash,
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def shannon_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _deleet_variants(token):
    base = "".join(LEET.get(c, c) for c in token).replace("vv", "w").replace("rn", "m")
    variants = {base}
    if "1" in base:
        variants.add(base.replace("1", "l"))
        variants.add(base.replace("1", "i"))
    return variants


def _is_legit_brand_domain(registered, brand_domains, tld):
    if registered in brand_domains:
        return True
    # e.g. google.de, amazon.co.uk: same brand label under a country TLD
    label = registered.split(".")[0]
    return (
        any(d.split(".")[0] == label for d in brand_domains)
        and len(tld) == 2
        and tld not in SUSPICIOUS_TLDS
    )


def _script_of(ch):
    name = unicodedata.name(ch, "")
    first = name.split(" ")[0] if name else ""
    return first if first in {"LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "ARMENIAN"} else "OTHER"


# --------------------------------------------------------------------------
# Individual checks (each returns one finding)
# --------------------------------------------------------------------------

def _check_length(p):
    n = len(p.normalized)
    if n >= 500:
        pts, sev, res = 14, "high", "Extremely long URL"
    elif n >= 200:
        pts, sev, res = 8, "medium", "Very long URL"
    elif n >= 100:
        pts, sev, res = 4, "low", "Long URL"
    else:
        return make_finding(
            "url_length", "URL length", "Normal length", status="pass",
            explanation="The URL length is within the range of ordinary links.",
            evidence=f"{n} characters",
        )
    return make_finding(
        "url_length", "URL length", res, status="flag", severity=sev, points=pts, group="lexical",
        explanation="Very long URLs are often used to hide the real destination or to embed tracking and redirect data.",
        evidence=f"{n} characters (normalized form)",
        recommendation="Check the domain at the start of the URL, not the long tail of parameters.",
    )


def _check_scheme(p):
    note = " (no scheme was entered, so https:// was assumed)" if p.assumed_scheme else ""
    if p.scheme == "http":
        return make_finding(
            "url_scheme", "Connection scheme", "Unencrypted HTTP", status="flag", severity="low",
            points=5, group="transport",
            explanation="The URL uses plain HTTP. Anything typed on the page can be read or altered in transit. "
                        "Many phishing pages still use HTTP, although HTTPS alone does not make a site trustworthy.",
            evidence=f"Scheme: http{note}",
            recommendation="Do not enter credentials or payment details on an HTTP page.",
        )
    return make_finding(
        "url_scheme", "Connection scheme", "HTTPS", status="pass",
        explanation="The URL uses HTTPS. This only means traffic is encrypted - phishing sites also use HTTPS.",
        evidence=f"Scheme: https{note}",
    )


def _check_ip_host(p):
    if not p.is_ip:
        return make_finding(
            "ip_host", "IP address instead of domain", "Domain name used", status="pass",
            explanation="The URL uses a domain name rather than a raw IP address.",
            evidence=f"Host: {p.hostname}",
        )
    extra = ""
    pts = 25
    if p.ip_obfuscated:
        extra = " The address was written in an obfuscated numeric form (decimal/hex/octal), which is a common evasion trick."
        pts = 32
    return make_finding(
        "ip_host", "IP address instead of domain", "Host is a raw IP address", status="flag",
        severity="high", points=pts, group="host_form",
        explanation="Legitimate services rarely ask users to log in at a bare IP address. Phishing and malware "
                        "kits are often hosted that way." + extra,
        evidence=f"Host: {p.hostname}" + (" (written differently in the input)" if p.ip_obfuscated else ""),
        recommendation="Do not trust login pages served from a raw IP address. Use the service's official domain.",
    )


def _check_userinfo(p):
    in_path = "@" in p.path or "@" in p.query
    if p.userinfo is not None:
        shown = p.userinfo if len(p.userinfo) <= 60 else p.userinfo[:57] + "..."
        return make_finding(
            "at_symbol", "Misleading '@' in URL", "Text before '@' hides the real host", status="flag",
            severity="high", points=30, group="host_form",
            explanation="Everything before an '@' in the address is treated as a username, so a URL can start "
                        "with a trusted-looking name while actually pointing somewhere else.",
            evidence=f"Ignored username part: '{shown}'  ->  real host: {p.hostname}",
            recommendation="Read the address after the '@' sign: that is where the link really goes.",
        )
    if in_path:
        return make_finding(
            "at_symbol", "Misleading '@' in URL", "'@' found in path or query", status="flag",
            severity="low", points=3, group="lexical",
            explanation="An '@' inside the path or parameters is unusual and can be used to confuse readers.",
            evidence="The URL path or query string contains '@'.",
            recommendation="Verify the domain before continuing.",
        )
    return make_finding(
        "at_symbol", "Misleading '@' in URL", "No '@' symbol", status="pass",
        explanation="The URL does not use an '@' symbol to disguise its destination.",
    )


def _check_subdomains(p):
    subs = [s for s in p.subdomain_labels if s != "www"]
    n = len(subs)
    if p.is_ip:
        return make_finding("subdomains", "Subdomain depth", "Not applicable", status="info",
                            explanation="The host is an IP address, so it has no subdomains.")
    if n >= 4:
        sev, pts, res = "medium", 10, "Excessive subdomains"
    elif n == 3:
        sev, pts, res = "low", 5, "Many subdomains"
    else:
        return make_finding(
            "subdomains", "Subdomain depth", "Normal", status="pass",
            explanation="The number of subdomains is within the normal range.",
            evidence=f"{n} subdomain label(s) before {p.registered_domain}",
        )
    return make_finding(
        "subdomains", "Subdomain depth", res, status="flag", severity=sev, points=pts, group="lexical",
        explanation="Long chains of subdomains can push a trusted-looking name to the front of the address "
                    "while the real domain sits at the end.",
        evidence=f"{n} subdomain labels: {'.'.join(subs)}  (registered domain: {p.registered_domain})",
        recommendation=f"The site actually belongs to '{p.registered_domain}'. Decide whether you trust that domain.",
    )


def _check_shortener(p):
    if p.hostname in URL_SHORTENERS or p.registered_domain in URL_SHORTENERS:
        return make_finding(
            "shortener", "URL shortener", "Known URL shortening service", status="flag", severity="medium",
            points=12, group="lexical",
            explanation="Shortened links hide their destination. PhishLens does not follow redirects (to stay safe "
                        "from SSRF), so the real target is unknown to this scan.",
            evidence=f"Shortener domain: {p.registered_domain}",
            recommendation="Expand the link with a trusted preview tool, or ask the sender for the full address.",
        )
    return make_finding(
        "shortener", "URL shortener", "Not a known shortener", status="pass",
        explanation="The domain is not in the built-in list of URL shortening services.",
        evidence=f"Checked against {len(URL_SHORTENERS)} known shortener domains",
    )


def _check_keywords(p):
    host = p.hostname
    tail = (p.path + "?" + p.query).lower()
    host_hits = sorted({k for k in KEYWORDS if k in host})
    path_hits = sorted({k for k in KEYWORDS if k in tail})
    if not host_hits and not path_hits:
        return make_finding(
            "keywords", "Suspicious keywords", "None found", status="pass",
            explanation="No common phishing keywords (login, verify, secure, ...) were found.",
            evidence=f"Checked {len(KEYWORDS)} keywords in the hostname and path",
        )
    pts = min(15, 5 * len(host_hits)) + min(6, 2 * len(path_hits))
    sev = "medium" if pts >= 10 else "low"
    ev = []
    if host_hits:
        ev.append("In hostname: " + ", ".join(host_hits))
    if path_hits:
        ev.append("In path/query: " + ", ".join(path_hits))
    return make_finding(
        "keywords", "Suspicious keywords", f"{len(host_hits) + len(path_hits)} keyword(s) found", status="flag",
        severity=sev, points=pts, group="lexical",
        explanation="Words like 'login', 'verify' or 'secure' are common in phishing links, but also appear on "
                    "many legitimate sites - this is a weak, heuristic indicator on its own.",
        evidence="; ".join(ev),
        recommendation="Make sure the domain itself belongs to the organization you expect.",
    )


def _check_brand(p):
    if p.is_ip:
        return make_finding("brand_impersonation", "Brand impersonation", "Not applicable", status="info",
                            explanation="The host is an IP address, so no brand name can be compared.")
    labels = [l for l in p.hostname.split(".")[: -(p.suffix.count(".") + 1)]]
    tokens = {tok for lab in labels for tok in lab.split("-") if tok}
    hits = []
    for brand, legit in BRANDS.items():
        if _is_legit_brand_domain(p.registered_domain, legit, p.tld):
            continue
        if brand in tokens or (len(brand) >= 6 and any(brand in lab for lab in labels)):
            hits.append(("contains", brand, brand))
            continue
        for tok in tokens:
            if tok == brand or len(tok) < 4:
                continue
            if brand in _deleet_variants(tok):
                hits.append(("lookalike", brand, tok))
                break
            if len(brand) >= 6 and abs(len(tok) - len(brand)) <= 1 and levenshtein(tok, brand) == 1:
                hits.append(("typosquat", brand, tok))
                break
    if not hits:
        return make_finding(
            "brand_impersonation", "Brand impersonation", "No lookalike found", status="pass",
            explanation="The hostname does not embed or imitate any of the well-known brand names in the built-in list.",
            evidence=f"Compared against {len(BRANDS)} popular brands",
        )
    kind, brand, tok = hits[0]
    pts = {"contains": 25, "lookalike": 28, "typosquat": 22}[kind]
    descr = {
        "contains": f"The name '{brand}' appears in the hostname, but the registered domain is '{p.registered_domain}', "
                    f"which is not an official {brand} domain.",
        "lookalike": f"'{tok}' imitates '{brand}' using look-alike characters (such as 0 for o or 1 for l).",
        "typosquat": f"'{tok}' is one character away from '{brand}', a typical typosquatting pattern.",
    }[kind]
    more = f" (+{len(hits) - 1} more brand match(es))" if len(hits) > 1 else ""
    return make_finding(
        "brand_impersonation", "Brand impersonation", "Possible brand impersonation", status="flag",
        severity="high", points=pts, group="lexical",
        explanation="Attackers often put a trusted brand name inside their own domain. " + descr,
        evidence=f"Registered domain: {p.registered_domain}; matched brand: {brand}{more}",
        recommendation=f"Only log in to {brand} through its official website or app, not via this link.",
    )


def _check_special_chars(p):
    issues, pts = [], 0
    tail = p.path + ("?" + p.query if p.query else "")
    pct = len(re.findall(r"%[0-9a-fA-F]{2}", p.normalized))
    if pct >= 6:
        issues.append(f"{pct} percent-encoded characters")
        pts += 4
    if "%25" in p.normalized:
        issues.append("double-encoded characters (%25)")
        pts += 5
    if re.search(r"[<>\"'`{}|^]", tail):
        issues.append("raw markup/script characters in the path or query")
        pts += 8
    if _EMBEDDED_URL.search(tail):
        issues.append("another URL embedded in the path or query (possible redirect)")
        pts += 6
    if re.search(r"(?:^|[.-])https?(?:[.-]|$)", p.hostname.rsplit(".", 1)[0]) and not p.is_ip:
        issues.append("the word 'http'/'https' inside the hostname")
        pts += 10
    if "//" in p.path.lstrip("/"):
        issues.append("repeated slashes in the path")
        pts += 2
    if p.had_backslash:
        issues.append("backslashes (browsers and servers may interpret them differently)")
        pts += 8
    if "_" in p.hostname:
        issues.append("underscore in the hostname")
        pts += 3
    if not issues:
        return make_finding(
            "special_chars", "Special characters & obfuscation", "None found", status="pass",
            explanation="No unusual encoding, embedded URLs or misleading characters were found.",
        )
    sev = "medium" if pts >= 8 else "low"
    return make_finding(
        "special_chars", "Special characters & obfuscation", f"{len(issues)} issue(s) found", status="flag",
        severity=sev, points=min(pts, 20), group="lexical",
        explanation="Unusual encoding and embedded URLs are used to hide the destination or bypass filters.",
        evidence="; ".join(issues),
        recommendation="Treat links with heavy encoding or embedded addresses with caution.",
    )


def _check_idn(p):
    if p.is_ip or "xn--" not in p.hostname:
        return make_finding(
            "idn", "International (IDN) characters", "None", status="pass",
            explanation="The hostname uses plain ASCII characters only.",
        )
    mixed = False
    for label in p.unicode_host.split("."):
        scripts = {_script_of(c) for c in label if c.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            mixed = True
    if mixed:
        return make_finding(
            "idn", "International (IDN) characters", "Mixed scripts (homograph risk)", status="flag",
            severity="high", points=28, group="host_form",
            explanation="The hostname mixes Latin letters with look-alike Cyrillic or Greek letters. "
                        "This is the classic homograph attack: the name looks identical to a trusted site.",
            evidence=f"Displayed as: {p.unicode_host}  |  real (punycode) host: {p.hostname}",
            recommendation="Do not trust this link. Type the website's address manually.",
        )
    return make_finding(
        "idn", "International (IDN) characters", "Internationalized domain name", status="flag",
        severity="low", points=8, group="host_form",
        explanation="The domain uses non-ASCII characters. Many are legitimate, but IDNs are also used for look-alike domains.",
        evidence=f"Displayed as: {p.unicode_host}  |  punycode: {p.hostname}",
        recommendation="Verify that the characters really match the site you expect.",
    )


def _check_host_pattern(p):
    if p.is_ip:
        return make_finding("host_pattern", "Domain name pattern", "Not applicable", status="info",
                            explanation="The host is an IP address.")
    label = p.registered_domain.split(".")[0]
    issues, pts = [], 0
    if not label.startswith("xn--") and len(label) >= 10 and shannon_entropy(label) >= 3.6:
        issues.append(f"random-looking name (entropy {shannon_entropy(label):.2f} bits/char)")
        pts += 8
    digits = sum(c.isdigit() for c in label)
    if len(label) >= 8 and digits / len(label) >= 0.4:
        issues.append(f"{digits} of {len(label)} characters are digits")
        pts += 6
    if p.hostname.count("-") >= 3:
        issues.append(f"{p.hostname.count('-')} hyphens in the hostname")
        pts += 6
    if len(p.hostname) >= 50:
        issues.append(f"very long hostname ({len(p.hostname)} characters)")
        pts += 5
    if p.port not in (None, 80, 443):
        issues.append(f"non-standard port {p.port}")
        pts += 4
    if not issues:
        return make_finding(
            "host_pattern", "Domain name pattern", "Looks ordinary", status="pass",
            explanation="The domain name does not show machine-generated or otherwise unusual patterns.",
            evidence=f"Domain label: {label}",
        )
    return make_finding(
        "host_pattern", "Domain name pattern", "Unusual domain pattern", status="flag",
        severity="medium" if pts >= 10 else "low", points=min(pts, 16), group="host_form",
        explanation="Algorithmically generated or heavily hyphenated/numeric names are common in disposable phishing domains. "
                    "This is a weak heuristic: some legitimate names look the same.",
        evidence="; ".join(issues),
        recommendation="Check whether you recognise this domain from a trusted source.",
    )


CHECKS = (
    _check_length, _check_scheme, _check_ip_host, _check_userinfo, _check_subdomains,
    _check_shortener, _check_keywords, _check_brand, _check_special_chars, _check_idn,
    _check_host_pattern,
)


def analyze_url(p):
    """Stage 2.  Returns a list of findings for the URL structure."""
    return [check(p) for check in CHECKS]
