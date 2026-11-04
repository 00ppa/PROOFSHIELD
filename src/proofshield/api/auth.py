"""Deployment-wide bearer authentication for the single-tenant API."""

import ipaddress
import os
import secrets
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


_API_TOKEN_ENV = "PROOFSHIELD_API_TOKEN"
_LOCAL_BYPASS_ENV = "PROOFSHIELD_ALLOW_LOCAL_UNAUTHENTICATED"
_PUBLIC_PATHS = {
    "/health",
    "/api/v1/health",
    "/docs",
    "/redoc",
    "/openapi.json",
}
_EXECUTION_PREFIX = "/api/v1/execution/"


def _is_loopback_client(request: Request) -> bool:
    """Return whether the request is directly local, without proxy forwarding headers."""
    client = request.client
    if client is None:
        return False
    if any(request.headers.get(header) for header in ("forwarded", "x-forwarded-for", "x-real-ip")):
        return False
    host = client.host.strip().lower()
    if host == "testclient":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def _bearer_matches(request: Request, configured: str) -> bool:
    """Validate exactly one bearer token without exposing the configured value."""
    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not supplied.strip():
        return False
    return secrets.compare_digest(supplied.strip().encode(), configured.encode())


class APITokenMiddleware(BaseHTTPMiddleware):
    """Protect every non-public, non-execution API route with one bearer token.

    The service is single-tenant, so one deployment token is sufficient. A
    missing token configuration fails closed with 503. The only unauthenticated
    exception is an explicit local-development opt-in, restricted to direct
    loopback/TestClient requests and disabled whenever proxy-forwarding headers
    are present. Execution routes remain protected by their dedicated
    ``PROOFSHIELD_EXEC_TOKEN`` dependency and cannot be bypassed with the API
    token.
    """

    @staticmethod
    def _is_public(path: str) -> bool:
        return path.rstrip("/") in _PUBLIC_PATHS or path.startswith("/ui")

    @staticmethod
    def _is_execution_route(path: str) -> bool:
        return path == "/api/v1/execution" or path.startswith(_EXECUTION_PREFIX)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/v1/") or self._is_public(path):
            return await call_next(request)

        # Execution routes have a separate server-side token policy.
        if self._is_execution_route(path):
            return await call_next(request)

        configured = os.environ.get(_API_TOKEN_ENV, "").strip()
        if not configured:
            local_opt_in = os.environ.get(_LOCAL_BYPASS_ENV, "").strip().lower()
            if local_opt_in in {"1", "true", "yes", "on"} and _is_loopback_client(request):
                return await call_next(request)
            return JSONResponse(
                status_code=503,
                content={"detail": "API authentication is not configured."},
            )

        if not _bearer_matches(request, configured):
            return JSONResponse(
                status_code=401,
                content={"detail": "API bearer authentication required."},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)


# Backwards-compatible import name for integrations that imported the old class.
OptionalAPITokenMiddleware = APITokenMiddleware
