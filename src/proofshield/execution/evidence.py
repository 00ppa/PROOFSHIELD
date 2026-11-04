"""Security boundary for data copied into persisted execution evidence.

Actions may need caller-supplied content or sensitive values while executing,
but execution evidence must retain only useful operational metadata. This
module recursively preserves ordinary values and replaces content/credential
fields with deterministic markers before hashing or persistence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from proofshield.execution.environment import redact_server_secret


REDACTED_CONTENT = "[REDACTED_CONTENT]"
REDACTED_SENSITIVE = "[REDACTED_SENSITIVE_VALUE]"
REDACTED_NESTED = "[REDACTED_NESTED]"

_PRESERVED_TOKEN_KEYS = {
    "execution_token",
    "environment_token",
    "run_token",
    "test_token",
    "proofshield_token",
    "token_verified",
}

_CONTENT_KEYS = {
    "content",
    "contents",
    "content_prefix",
    "file_content",
    "raw_content",
    "plaintext",
    "payload",
    "body",
    "raw",
    "raw_payload",
}

_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "passphrase",
    "secret",
    "credential",
    "credentials",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth_token",
    "bearer_token",
    "client_secret",
    "private_key",
    "authorization",
    "cookie",
}

_SENSITIVE_SUFFIXES = (
    "_password",
    "_passwd",
    "_passphrase",
    "_secret",
    "_credential",
    "_credentials",
    "_api_key",
    "_apikey",
    "_access_token",
    "_refresh_token",
    "_auth_token",
    "_private_key",
    "_client_secret",
)

_INLINE_SECRET = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|auth(?:orization)?|bearer)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)


def _key_name(key: Any) -> str:
    return str(key).strip().lower().replace("-", "_").replace(".", "_")


def _is_sensitive_key(key: str) -> bool:
    return key in _SENSITIVE_KEYS or any(key.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES)


def _sanitize_scalar(value: Any) -> Any:
    if isinstance(value, bytes):
        return REDACTED_CONTENT
    if isinstance(value, str):
        return _INLINE_SECRET.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED_SENSITIVE}", redact_server_secret(value))
    return value


def sanitize_evidence_value(
    value: Any,
    *,
    max_depth: int = 16,
    _depth: int = 0,
) -> Any:
    """Return a deterministic, recursively sanitized evidence-safe value.

    Preserved values include filenames, numeric results, status flags, action
    identifiers, execution tokens, and ordinary analyst metadata. Values under
    credential keys or content-bearing keys are replaced; unknown non-sensitive
    fields are retained and recursively inspected.
    """
    if _depth >= max_depth:
        return REDACTED_NESTED
    if isinstance(value, dict):
        sanitized: Dict[Any, Any] = {}
        for key, item in value.items():
            normalized = _key_name(key)
            if normalized in _CONTENT_KEYS:
                sanitized[key] = REDACTED_CONTENT
            elif normalized not in _PRESERVED_TOKEN_KEYS and _is_sensitive_key(normalized):
                sanitized[key] = REDACTED_SENSITIVE
            else:
                sanitized[key] = sanitize_evidence_value(item, max_depth=max_depth, _depth=_depth + 1)
        return sanitized
    if isinstance(value, list):
        return [sanitize_evidence_value(item, max_depth=max_depth, _depth=_depth + 1) for item in value]
    if isinstance(value, tuple):
        return [sanitize_evidence_value(item, max_depth=max_depth, _depth=_depth + 1) for item in value]
    return _sanitize_scalar(value)


def sanitize_execution_evidence_fields(
    *,
    parameters: Optional[Dict[str, Any]],
    action_result: Optional[Dict[str, Any]],
    metadata: Optional[Dict[str, Any]],
    evidence_references: Optional[list[str]],
    error_message: Optional[str],
    cleanup_error: Optional[str],
) -> Dict[str, Any]:
    """Sanitize every caller/action-controlled field persisted in evidence."""
    return {
        "parameters": sanitize_evidence_value(parameters or {}),
        "action_result": sanitize_evidence_value(action_result or {}),
        "metadata": sanitize_evidence_value(metadata or {}),
        "evidence_references": sanitize_evidence_value(evidence_references or []),
        "error_message": sanitize_evidence_value(error_message),
        "cleanup_error": sanitize_evidence_value(cleanup_error),
    }
