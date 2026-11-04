"""Safe environment construction and secret redaction for child processes."""

from __future__ import annotations

import os
from typing import Dict, Mapping, Optional


SERVER_EXECUTION_SECRET_ENV = "PROOFSHIELD_EXEC_TOKEN"
EXECUTION_TOKEN_ENV = "PROOFSHIELD_EXECUTION_TOKEN"
REDACTED_SECRET = "[REDACTED_SECRET]"
SAFE_ENV_KEYS = {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "TZ"}


def build_child_environment(
    execution_token: Optional[str] = None,
    base_environment: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Build a subprocess environment without the server authentication secret.

    The execution token is deliberately a separate value from the server bearer
    secret.  The server secret is removed even when a caller supplies a custom
    base environment, which keeps this boundary effective for every subprocess
    creation path.
    """
    source = os.environ if base_environment is None else base_environment
    environment = {key: value for key, value in source.items() if key.upper() in SAFE_ENV_KEYS}
    if execution_token is None:
        execution_token = source.get(EXECUTION_TOKEN_ENV)
    if execution_token is not None:
        environment[EXECUTION_TOKEN_ENV] = execution_token
    return environment


def redact_server_secret(value: Optional[str]) -> str:
    """Redact the configured server secret from text before persistence or logging."""
    text = value or ""
    for name, secret in os.environ.items():
        if name.upper().startswith("PROOFSHIELD_") and any(part in name.upper() for part in ("TOKEN", "KEY", "PASSWORD", "SECRET")):
            if secret and secret.strip():
                text = text.replace(secret, REDACTED_SECRET)
    return text
