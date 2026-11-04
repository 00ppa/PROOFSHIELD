"""Shared credential-safe HTTP transport primitives for read-only SIEM clients."""

import ipaddress
import ssl
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, build_opener


def validate_source_url(value: str) -> str:
    """Require HTTPS except explicit literal loopback HTTP used by local mocks."""
    parts = urlsplit(value.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("SIEM URL must use HTTP(S) with a hostname")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("SIEM URL must not contain credentials, query, or fragment")
    if parts.path not in {"", "/"}:
        raise ValueError("SIEM URL must identify an origin, without a path")
    try:
        _ = parts.port
        loopback = ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        loopback = parts.hostname == "localhost"
    if parts.scheme == "http" and not loopback:
        raise ValueError("Non-loopback SIEM connections require verified HTTPS")
    return value.strip().rstrip("/")


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # urllib raises HTTPError rather than forwarding the Authorization header.
        return None


def verified_opener(ca_file=None):
    context = ssl.create_default_context(cafile=ca_file)
    return build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirects())


def public_source_url(value):
    if not value:
        return ""
    try:
        return validate_source_url(value)
    except ValueError:
        return "[invalid configuration]"
