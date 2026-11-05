"""Network-safety helpers: SSRF protection and bounded outbound requests.

PhishLens never fetches the URL a user submits.  The only outbound traffic is:
  * fixed third-party API hosts (VirusTotal, Google Safe Browsing, IANA/RDAP),
  * DNS queries,
  * a TLS handshake (no HTTP request) to a *public* IP address that DNS returned.
"""
import ipaddress
import json
import re
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests

_LEGACY_LAST_LABEL = re.compile(r"^(?:\d+|0x[0-9a-f]*)$", re.I)

# Names that can never be public Internet hosts.
NON_PUBLIC_SUFFIXES = (
    "localhost", "local", "internal", "lan", "home", "home.arpa", "corp",
    "intranet", "private", "test", "example", "invalid", "onion",
)


def strict_ip(host):
    """Return an ipaddress object for a literal IP, else None."""
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def parse_ip_host(host):
    """Detect IP-address hosts, including obfuscated IPv4 forms.

    Returns ``(ip_or_None, obfuscated)``.  Raises ValueError when the host looks
    numeric (browsers would treat it as an IPv4 address) but is not valid.
    """
    ip = strict_ip(host)
    if ip is not None:
        return ip, False
    last_label = host.rsplit(".", 1)[-1]
    if _LEGACY_LAST_LABEL.match(last_label):
        try:
            packed = socket.inet_aton(host)
        except OSError:
            raise ValueError("invalid numeric host") from None
        return ipaddress.IPv4Address(packed), True
    return None, False


def is_public_ip(ip):
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not ip.is_multicast


def is_internal_hostname(host):
    host = host.lower().rstrip(".")
    if "." not in host:
        return True  # single-label names are intranet hosts
    return any(host == s or host.endswith("." + s) for s in NON_PUBLIC_SUFFIXES)


def host_resolves_public(host):
    """True only if the host is not an IP/internal name and every address is public."""
    if strict_ip(host) is not None or is_internal_hostname(host):
        return False
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    addrs = {info[4][0] for info in infos}
    return bool(addrs) and all(is_public_ip(a) for a in addrs)


class RequestFailed(Exception):
    """Outbound request problem.  The message is safe to show to users
    (it never contains URLs, so API keys in query strings cannot leak)."""

    def __init__(self, kind, message, status=None):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.status = status


@dataclass
class ApiResponse:
    status: int
    headers: dict
    body: bytes

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise RequestFailed("bad_response", "The service returned an unreadable response.") from None


_REDIRECT_CODES = {301, 302, 303, 307, 308}


def _read_limited(resp, max_bytes):
    chunks, total = [], 0
    try:
        for chunk in resp.iter_content(8192):
            total += len(chunk)
            if total > max_bytes:
                raise RequestFailed("too_large", "The service response was too large.")
            chunks.append(chunk)
    except requests.Timeout:
        raise RequestFailed("timeout", "The service timed out.") from None
    except requests.RequestException:
        raise RequestFailed("connection", "The connection to the service was interrupted.") from None
    return b"".join(chunks)


def api_request(
    method,
    url,
    *,
    headers=None,
    params=None,
    json_body=None,
    data=None,
    timeout=10,
    max_bytes=2_000_000,
    max_redirects=0,
    verify_hosts=False,
):
    """Bounded HTTPS request.

    * HTTPS only (also for redirect targets).
    * Redirects are followed manually, at most ``max_redirects`` times.
    * With ``verify_hosts`` every hop must be a public, non-internal hostname.
    * Response size is capped and exceptions never expose the request URL.
    """
    current = url
    for hop in range(max_redirects + 1):
        parts = urlsplit(current)
        if parts.scheme != "https" or not parts.hostname:
            raise RequestFailed("insecure_url", "Refused to contact a non-HTTPS address.")
        if verify_hosts and not host_resolves_public(parts.hostname):
            raise RequestFailed("unsafe_host", "Refused to contact a non-public address.")
        try:
            resp = requests.request(
                method,
                current,
                headers=headers,
                params=params if hop == 0 else None,
                json=json_body if hop == 0 else None,
                data=data if hop == 0 else None,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
        except requests.Timeout:
            raise RequestFailed("timeout", "The service timed out.") from None
        except requests.RequestException:
            raise RequestFailed("connection", "Could not connect to the service.") from None
        try:
            if resp.status_code in _REDIRECT_CODES:
                if hop >= max_redirects:
                    raise RequestFailed("redirect", "The service sent an unexpected redirect.", resp.status_code)
                location = resp.headers.get("Location", "")
                current = urljoin(current, location)
                continue
            body = _read_limited(resp, max_bytes)
            return ApiResponse(resp.status_code, dict(resp.headers), body)
        finally:
            resp.close()
    raise RequestFailed("redirect", "Too many redirects.")
