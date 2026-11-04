"""Elastic Security Alert Ingestion Connector for PROOFSHIELD.

Provides:
1. Pure, offline-testable mapping of Elastic Security alert documents (ECS,
   Kibana Alerting, legacy Signal formats) into canonical AlertV1 models.
2. Safe, read-only Elasticsearch client using standard-library urllib with
   deterministic queries, mandatory TLS verification, bounded time ranges,
   and secret redaction.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import math
import os
from pathlib import Path
import re
import ssl
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
import urllib.error
import urllib.request

import dateutil.parser

from proofshield.normalisation.engine import extract_execution_token
from proofshield.schemas.alert import AlertV1
from proofshield.schemas.telemetry import RawTelemetryEventV1
from proofshield.connectors.transport import validate_source_url
from proofshield.services.base_store import StoreProtocol


class ElasticAlertMappingError(ValueError):
    """Raised when an Elastic alert document cannot be mapped into AlertV1."""


class ElasticClientError(RuntimeError):
    """Raised on connection, query, timeout, or authentication failures with Elastic."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class TelemetryRetrievalStatus(str, Enum):
    """Status classification for telemetry queries against Elasticsearch."""
    COMPLETE = "COMPLETE"
    TRUNCATED = "TRUNCATED"
    EMPTY = "EMPTY"
    FAILED = "FAILED"


@dataclass
class ElasticTelemetryHit:
    """Strongly typed representation of an individual telemetry document hit."""
    hit_id: str
    index: str
    source: Dict[str, Any]
    timestamp: Optional[datetime] = None
    sort_token: Optional[List[Any]] = None


@dataclass
class ElasticTelemetryBatch:
    """Strongly typed batch response for telemetry retrieval queries."""
    hits: List[Dict[str, Any]]
    total_matched: Optional[int]
    relation: str
    is_truncated: bool
    status: TelemetryRetrievalStatus
    query_window: Tuple[Optional[datetime], Optional[datetime]] = (None, None)


# Conservative Credential Redaction Policy:
# 1. Exact secret keys (case-insensitive, normalized): 'password', 'api_key', 'private_key', etc.
# 2. Secret suffix keys: ending with '_password', '_api_key', '_private_key', etc.
# 3. Sensitive headers: 'authorization', 'proxy-authorization', 'cookie', etc.
# 4. Bearer/ApiKey authorization value strings.
# 5. Legitimate forensic metadata keys (ending with '_id', '_hash', '_reset', '_scope', etc.)
#    and primitive boolean/numeric values are explicitly preserved for investigation integrity.

_EXACT_SECRET_KEYS = {
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "secret",
    "private_key",
    "auth_token",
    "access_token",
    "refresh_token",
    "bearer_token",
    "client_secret",
    "secret_key",
}

_EXACT_SECRET_SUFFIXES = (
    "_password",
    "_passwd",
    "_api_key",
    "_apikey",
    "_private_key",
    "_secret_key",
    "_client_secret",
)

_FORENSIC_NON_SECRET_SUFFIXES = (
    "_id",
    "_uuid",
    "_hash",
    "_type",
    "_count",
    "_scope",
    "_action",
    "_event",
    "_name",
    "_status",
    "_result",
    "_reset",
    "_at",
    "_time",
    "_date",
    "_changed",
    "_length",
    "_algorithm",
)

_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
}

_AUTH_VALUE_PATTERN = re.compile(r"^(?:Bearer|ApiKey|Basic)\s+[A-Za-z0-9_\-\.\+/=]+", re.IGNORECASE)


DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ALLOWED_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_ALLOWED_RETRIES = 10


def _first_present(data: Dict[str, Any], paths: Sequence[str]) -> Any:
    """Return the first present value without treating valid zero values as absent."""
    for path in paths:
        value = _get_nested(data, path)
        if value is not None:
            return value
    return None


def _hit_source(hit: Dict[str, Any]) -> Dict[str, Any]:
    source = hit.get("_source", hit)
    if not isinstance(source, dict):
        raise ElasticClientError(
            f"Elasticsearch search hit has invalid '_source' type '{type(source).__name__}'"
        )
    return source


def _hit_identifier(hit: Dict[str, Any], source: Optional[Dict[str, Any]] = None) -> Optional[str]:
    source = source if source is not None else _hit_source(hit)
    raw_id = _first_present(
        hit,
        ("_id",),
    )
    if raw_id is None:
        raw_id = _first_present(
            source,
            (
                "_id",
                "event.id",
                "kibana.alert.uuid",
                "kibana.alert.id",
                "signal.id",
                "signal.parent.id",
                "alert_id",
            ),
        )
    if not isinstance(raw_id, str) or not raw_id.strip():
        return None
    return raw_id.strip()


def _validate_search_page(
    body: Any,
    *,
    require_timestamps: bool = False,
) -> Tuple[List[Dict[str, Any]], Optional[int], str]:
    """Validate one Elasticsearch search response before pagination uses it."""
    if not isinstance(body, dict):
        raise ElasticClientError(
            f"Malformed Elasticsearch response: expected object, received {type(body).__name__}"
        )
    hits_container = body.get("hits")
    if not isinstance(hits_container, dict):
        raise ElasticClientError("Malformed Elasticsearch response: 'hits' must be an object")
    page_hits = hits_container.get("hits")
    if not isinstance(page_hits, list):
        raise ElasticClientError("Malformed Elasticsearch response: 'hits.hits' must be an array")

    for position, hit in enumerate(page_hits):
        if not isinstance(hit, dict):
            raise ElasticClientError(
                f"Malformed Elasticsearch response: hit {position} must be an object"
            )
        if "_source" not in hit:
            raise ElasticClientError(
                f"Malformed Elasticsearch response: hit {position} lacks '_source'"
            )
        source = _hit_source(hit)
        if _hit_identifier(hit, source) is None:
            raise ElasticClientError(
                f"Malformed Elasticsearch response: hit {position} lacks a valid identifier"
            )
        if require_timestamps:
            raw_timestamp = _first_present(source, ("@timestamp", "event.created"))
            if raw_timestamp is None:
                raise ElasticClientError(
                    f"Malformed Elasticsearch response: hit {position} lacks a telemetry timestamp"
                )
            try:
                if _parse_timestamp(raw_timestamp) is None:
                    raise ElasticClientError(
                        f"Malformed Elasticsearch response: hit {position} has an empty telemetry timestamp"
                    )
            except ElasticAlertMappingError as exc:
                raise ElasticClientError(
                    f"Malformed Elasticsearch response: hit {position} has an invalid telemetry timestamp"
                ) from exc

    total_raw = hits_container.get("total")
    if total_raw is None:
        total = None
        relation = "eq"
    elif isinstance(total_raw, dict):
        value = total_raw.get("value")
        relation_raw = total_raw.get("relation", "eq")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ElasticClientError("Malformed Elasticsearch response: 'hits.total.value' must be a non-negative integer")
        if relation_raw not in ("eq", "gte"):
            raise ElasticClientError("Malformed Elasticsearch response: 'hits.total.relation' must be 'eq' or 'gte'")
        total = value
        relation = relation_raw
    elif isinstance(total_raw, int) and not isinstance(total_raw, bool) and total_raw >= 0:
        total = total_raw
        relation = "eq"
    else:
        raise ElasticClientError("Malformed Elasticsearch response: 'hits.total' has an invalid type")
    return page_hits, total, relation


def _sanitize_metadata(
    val: Any,
    max_depth: int = 32,
    _current_depth: int = 0,
    _seen_ids: Optional[set] = None,
) -> Any:
    """Recursively scrub credentials from metadata dicts while preserving forensic fields.

    Preserves legitimate investigation attributes like 'password_reset', 'secret_scope',
    'auth_token_id', and 'password_hash' unless they hold cleartext credentials.
    Protects against infinite recursion from cyclic structures and deeply nested payloads.
    """
    if _current_depth >= max_depth:
        return "[REDACTED_NESTED]"

    if _seen_ids is None:
        _seen_ids = set()

    if isinstance(val, (dict, list)):
        val_id = id(val)
        if val_id in _seen_ids:
            return "[REDACTED_CYCLE]"
        _seen_ids.add(val_id)

    try:
        if isinstance(val, dict):
            sanitized = {}
            for k, v in val.items():
                k_clean = str(k).strip().lower().replace("-", "_").replace(".", "_")

                # Check if this is an explicitly preserved forensic attribute
                is_forensic_attribute = any(
                    k_clean.endswith(suf) for suf in _FORENSIC_NON_SECRET_SUFFIXES
                )

                if is_forensic_attribute:
                    sanitized[k] = _sanitize_metadata(
                        v,
                        max_depth=max_depth,
                        _current_depth=_current_depth + 1,
                        _seen_ids=_seen_ids,
                    )
                elif k_clean in _SENSITIVE_HEADER_KEYS:
                    sanitized[k] = "[REDACTED]"
                elif k_clean in _EXACT_SECRET_KEYS or any(k_clean.endswith(suf) for suf in _EXACT_SECRET_SUFFIXES):
                    if isinstance(v, (bool, int, float)) or v is None:
                        sanitized[k] = v
                    else:
                        sanitized[k] = "[REDACTED]"
                elif isinstance(v, str) and _AUTH_VALUE_PATTERN.match(v.strip()):
                    sanitized[k] = "[REDACTED]"
                else:
                    sanitized[k] = _sanitize_metadata(
                        v,
                        max_depth=max_depth,
                        _current_depth=_current_depth + 1,
                        _seen_ids=_seen_ids,
                    )
            return sanitized
        if isinstance(val, list):
            return [
                _sanitize_metadata(
                    item,
                    max_depth=max_depth,
                    _current_depth=_current_depth + 1,
                    _seen_ids=_seen_ids,
                )
                for item in val
            ]
        return val
    finally:
        if isinstance(val, (dict, list)):
            _seen_ids.remove(id(val))


def _get_nested(data: Dict[str, Any], path: str) -> Any:
    """Retrieve a value by dotted path from either nested dicts or dotted literal keys.

    Handles mixed formats seamlessly, e.g.:
    - doc["kibana.alert.rule.name"]
    - doc["kibana"]["alert"]["rule"]["name"]
    - doc["kibana.alert"]["rule"]["name"]
    """
    if not isinstance(data, dict):
        return None

    # 1. Exact dotted key match at current level
    if path in data and data[path] is not None:
        return data[path]

    # 2. Step-by-step traversal along dot boundaries
    parts = path.split(".")
    curr: Any = data
    for i, part in enumerate(parts):
        if not isinstance(curr, dict):
            break
        if part in curr:
            curr = curr[part]
            if i == len(parts) - 1:
                return curr
        else:
            # Check remaining joined path (e.g. curr["rule.name"])
            remaining = ".".join(parts[i:])
            if remaining in curr and curr[remaining] is not None:
                return curr[remaining]
            break

    return None


def _parse_timestamp(raw_val: Any) -> Optional[datetime]:
    """Parse raw timestamp into a UTC-aware datetime.

    Supports ISO-8601 strings and numeric timestamps (epoch seconds or milliseconds).
    Raises ElasticAlertMappingError on malformed strings.
    """
    if raw_val is None:
        return None

    if isinstance(raw_val, datetime):
        if raw_val.tzinfo is None:
            return raw_val.replace(tzinfo=timezone.utc)
        return raw_val.astimezone(timezone.utc)

    if isinstance(raw_val, bool):
        raise ElasticAlertMappingError(
            f"Unsupported timestamp type 'bool' for value '{raw_val}'"
        )

    if isinstance(raw_val, (int, float)):
        if math.isnan(raw_val) or math.isinf(raw_val):
            raise ElasticAlertMappingError(
                f"Malformed numeric timestamp '{raw_val}': value cannot be NaN or Infinite"
            )
        try:
            # If value is in milliseconds (greater than year 2286 in seconds, ~1e11)
            if raw_val > 1e11:
                return datetime.fromtimestamp(raw_val / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(raw_val, tz=timezone.utc)
        except (OverflowError, ValueError, OSError) as exc:
            raise ElasticAlertMappingError(
                f"Malformed or out-of-range numeric timestamp '{raw_val}': {exc}"
            ) from exc

    if isinstance(raw_val, str):
        cleaned = raw_val.strip()
        if not cleaned:
            return None
        try:
            dt = dateutil.parser.isoparse(cleaned)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception as exc:
            raise ElasticAlertMappingError(
                f"Malformed alert timestamp '{raw_val}': {exc}"
            ) from exc

    raise ElasticAlertMappingError(
        f"Unsupported timestamp type '{type(raw_val).__name__}' for value '{raw_val}'"
    )


def map_elastic_alert(doc: Dict[str, Any]) -> AlertV1:
    """Map a raw Elastic Security alert hit or document into a canonical AlertV1 record.

    Supports:
    - Standard ECS Kibana alert format (`kibana.alert.*`)
    - Legacy 7.x SIEM signals (`signal.*`)
    - Standard ECS host and process attributes
    - Structured and unstructured execution token extraction
    - Strict UTC timestamp conversion
    - Robust credential scrubbing

    Raises:
        ElasticAlertMappingError: If required fields (identifier, host) are missing
        or if timestamp data is invalid.
    """
    if not isinstance(doc, dict):
        raise ElasticAlertMappingError(
            f"Expected alert document as dict, received {type(doc).__name__}"
        )

    # Elastic hits typically wrap payload inside '_source'; support both hit and raw source
    source: Dict[str, Any] = doc.get("_source", doc)
    if not isinstance(source, dict):
        raise ElasticAlertMappingError(
            f"Expected '_source' as dict, received {type(source).__name__}"
        )

    # 1. Identifier resolution
    raw_id = _hit_identifier(doc, source)
    if raw_id is None:
        raise ElasticAlertMappingError(
            "Elastic alert document lacks a valid identifier ('_id', 'kibana.alert.uuid', etc.)"
        )
    source_alert_id = raw_id

    # Prefix with 'elastic:' for internal uniqueness in ProofShield if not already prefixed
    alert_id = source_alert_id if source_alert_id.startswith("elastic:") else f"elastic:{source_alert_id}"

    # 2. Host resolution
    host_val = (
        _get_nested(source, "host.hostname")
        or _get_nested(source, "host.name")
        or _get_nested(source, "host.id")
        or _get_nested(source, "agent.hostname")
        or _get_nested(source, "agent.name")
        or _get_nested(source, "host_name")
    )
    if host_val is None:
        # Fallback to host.ip
        ip_val = _get_nested(source, "host.ip")
        if isinstance(ip_val, list) and ip_val:
            host_val = ip_val[0]
        elif isinstance(ip_val, str) and ip_val.strip():
            host_val = ip_val.strip()

    if host_val is None or not str(host_val).strip():
        raise ElasticAlertMappingError(
            "Elastic alert document lacks host identity ('host.hostname', 'host.name', 'host.id', etc.)"
        )
    host_id = str(host_val).strip()

    # 3. Timestamp resolution
    raw_ts = _first_present(
        source,
        ("@timestamp", "kibana.alert.start", "signal.original_time", "timestamp", "event.created"),
    )
    alert_timestamp = _parse_timestamp(raw_ts)

    # 4. Rule reference resolution
    rule_ref = (
        _get_nested(source, "kibana.alert.rule.rule_id")
        or _get_nested(source, "signal.rule.rule_id")
        or _get_nested(source, "kibana.alert.rule.uuid")
        or _get_nested(source, "signal.rule.id")
        or _get_nested(source, "rule.id")
        or _get_nested(source, "rule.rule_id")
        or _get_nested(source, "kibana.alert.rule.name")
        or _get_nested(source, "signal.rule.name")
        or _get_nested(source, "rule.name")
    )
    rule_reference = str(rule_ref).strip() if rule_ref is not None and str(rule_ref).strip() else None

    # 5. Alert title resolution
    title_val = (
        _get_nested(source, "kibana.alert.rule.name")
        or _get_nested(source, "signal.rule.name")
        or _get_nested(source, "rule.name")
        or _get_nested(source, "message")
    )
    alert_title = str(title_val).strip() if title_val is not None and str(title_val).strip() else None

    # 6. Severity resolution
    sev_val = (
        _get_nested(source, "kibana.alert.rule.severity")
        or _get_nested(source, "signal.rule.severity")
        or _get_nested(source, "rule.severity")
        or _get_nested(source, "event.severity")
    )
    severity = str(sev_val).strip().lower() if sev_val is not None and str(sev_val).strip() else None

    # 7. Raw record reference (bounded)
    index_name = doc.get("_index") or _get_nested(source, "_index") or ".alerts-security.alerts-default"
    raw_ref = f"{index_name}/{source_alert_id}"[:256]

    # 8. Execution token extraction
    # Aggregate potential text fields where tokens may reside
    cmd_line = _get_nested(source, "process.command_line")
    args = _get_nested(source, "process.args")
    args_str = " ".join(str(a) for a in args) if isinstance(args, list) else None
    proc_name = _get_nested(source, "process.name") or _get_nested(source, "process.executable")
    proc_title = _get_nested(source, "process.title")
    message = _get_nested(source, "message")
    event_orig = _get_nested(source, "event.original")

    text_fields = [
        cmd_line,
        args_str,
        proc_name,
        proc_title,
        message,
        event_orig,
        alert_title,
    ]

    # Include tag strings in text fields for token scanning
    tags = _get_nested(source, "tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str):
                text_fields.append(tag)

    # Structured payload candidate fields
    structured_payload: Dict[str, Any] = {}
    labels = _get_nested(source, "labels")
    if isinstance(labels, dict):
        structured_payload.update(labels)
    custom = _get_nested(source, "custom")
    if isinstance(custom, dict):
        structured_payload.update(custom)

    # Check top-level source keys
    for k, v in source.items():
        if isinstance(v, (str, int, float)) and "." not in k:
            structured_payload[k] = v

    explicit_tok = _get_nested(source, "execution_token") or _get_nested(source, "proofshield_token")
    if explicit_tok is not None:
        explicit_tok = str(explicit_tok).strip()

    token = extract_execution_token(
        payload=structured_payload,
        explicit_token=explicit_tok,
        text_fields=text_fields,
    )

    # 9. Sanitized metadata
    meta = deepcopy(source)
    sanitized_meta = _sanitize_metadata(meta)

    return AlertV1(
        schema_version="v1",
        alert_id=alert_id,
        source_alert_id=source_alert_id,
        source_type="elastic",
        alert_timestamp=alert_timestamp,
        ingested_at=datetime.now(timezone.utc),
        host_id=host_id,
        rule_reference=rule_reference,
        alert_title=alert_title,
        severity=severity,
        raw_record_reference=raw_ref,
        execution_token=token,
        metadata=sanitized_meta,
    )


def map_elastic_alerts_batch(
    docs: Iterable[Dict[str, Any]],
    deduplicate: bool = True,
) -> List[AlertV1]:
    """Map a sequence of Elastic alert documents into AlertV1 objects.

    Args:
        docs: Iterable of Elastic search hit dictionaries.
        deduplicate: If True, drops duplicate alert_id occurrences within the batch.

    Returns:
        List of successfully parsed AlertV1 models.
    """
    alerts: List[AlertV1] = []
    seen_ids = set()

    for doc in docs:
        alert = map_elastic_alert(doc)
        if deduplicate:
            if alert.alert_id in seen_ids:
                continue
            seen_ids.add(alert.alert_id)
        alerts.append(alert)

    return alerts


class ElasticConnectorSettings:
    """Configuration settings for the Elastic Security connector."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        ca_cert_path: Optional[Union[str, Path]] = None,
        index_pattern: str = ".alerts-security.alerts-*",
        telemetry_index_pattern: str = "logs-*",
        request_timeout: float = 10.0,
        max_results: int = 100,
        enabled: bool = False,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        url_clean = str(base_url).strip()
        if not url_clean:
            raise ValueError("Elastic base URL cannot be empty.")
        if not (url_clean.startswith("http://") or url_clean.startswith("https://")):
            raise ValueError(
                f"Elastic base URL must start with 'http://' or 'https://': '{base_url}'"
            )
        self.base_url = validate_source_url(url_clean)

        api_key_clean = str(api_key).strip()
        if not api_key_clean:
            raise ValueError("Elastic API key cannot be empty.")
        self.api_key = api_key_clean

        if ca_cert_path is not None:
            ca_p = Path(ca_cert_path).resolve()
            if not ca_p.exists() or not ca_p.is_file():
                raise ValueError(
                    f"Specified Elastic CA certificate file does not exist: {ca_cert_path}"
                )
            self.ca_cert_path: Optional[str] = str(ca_p)
        else:
            self.ca_cert_path = None

        idx_clean = str(index_pattern).strip()
        if not idx_clean:
            raise ValueError("Elastic index pattern cannot be empty.")
        self.index_pattern = idx_clean

        tel_idx_clean = str(telemetry_index_pattern).strip()
        if not tel_idx_clean:
            raise ValueError("Elastic telemetry index pattern cannot be empty.")
        self.telemetry_index_pattern = tel_idx_clean

        try:
            t_val = float(request_timeout)
            if not math.isfinite(t_val) or t_val <= 0:
                raise ValueError()
            self.request_timeout = t_val
        except (ValueError, TypeError):
            raise ValueError(
                f"Elastic request timeout must be a positive float: '{request_timeout}'"
            )

        try:
            if isinstance(max_results, bool):
                raise ValueError()
            m_val = int(max_results)
            if isinstance(max_results, float) and not max_results.is_integer():
                raise ValueError()
            if m_val < 1 or m_val > 10000:
                raise ValueError()
            self.max_results = m_val
        except (ValueError, TypeError):
            raise ValueError(
                f"Elastic max_results must be an integer between 1 and 10000: '{max_results}'"
            )

        try:
            if isinstance(max_response_bytes, bool):
                raise ValueError()
            response_limit = int(max_response_bytes)
            if isinstance(max_response_bytes, float) and not max_response_bytes.is_integer():
                raise ValueError()
            if response_limit < 1 or response_limit > MAX_ALLOWED_RESPONSE_BYTES:
                raise ValueError()
            self.max_response_bytes = response_limit
        except (ValueError, TypeError):
            raise ValueError(
                "Elastic max_response_bytes must be an integer between 1 and "
                f"{MAX_ALLOWED_RESPONSE_BYTES}: '{max_response_bytes}'"
            )

        self.enabled = bool(enabled)

    @classmethod
    def from_env(cls) -> "ElasticConnectorSettings":
        """Load Elastic connector settings from PROOFSHIELD_ELASTIC_* environment variables."""
        url = os.environ.get("PROOFSHIELD_ELASTIC_URL", "")
        api_key = os.environ.get("PROOFSHIELD_ELASTIC_API_KEY", "")
        ca_cert = os.environ.get("PROOFSHIELD_ELASTIC_CA_CERT")
        index = os.environ.get("PROOFSHIELD_ELASTIC_INDEX", ".alerts-security.alerts-*")
        telemetry_index = os.environ.get("PROOFSHIELD_ELASTIC_TELEMETRY_INDEX", "logs-*")
        timeout_env = os.environ.get("PROOFSHIELD_ELASTIC_TIMEOUT", "10.0")
        max_env = os.environ.get("PROOFSHIELD_ELASTIC_MAX_RESULTS", "100")
        response_max_env = os.environ.get(
            "PROOFSHIELD_ELASTIC_MAX_RESPONSE_BYTES", str(DEFAULT_MAX_RESPONSE_BYTES)
        )
        enabled_env = os.environ.get("PROOFSHIELD_ELASTIC_ENABLED", "false").strip().lower()

        enabled = enabled_env in ("true", "1", "yes", "on")

        return cls(
            base_url=url,
            api_key=api_key,
            ca_cert_path=ca_cert,
            index_pattern=index,
            telemetry_index_pattern=telemetry_index,
            request_timeout=float(timeout_env),
            max_results=int(max_env),
            enabled=enabled,
            max_response_bytes=int(response_max_env),
        )

    def __repr__(self) -> str:
        # Redact the api_key to ensure credentials are never exposed in logs or representations
        return (
            f"ElasticConnectorSettings(base_url={self.base_url!r}, "
            f"api_key='***REDACTED***', "
            f"index_pattern={self.index_pattern!r}, "
            f"telemetry_index_pattern={self.telemetry_index_pattern!r}, "
            f"request_timeout={self.request_timeout}, "
            f"max_results={self.max_results}, "
            f"max_response_bytes={self.max_response_bytes}, "
            f"enabled={self.enabled})"
        )


def _extract_http_diagnostic(exc: urllib.error.HTTPError, redacted_secret: Optional[str] = None) -> str:
    """Safely extract and sanitize diagnostic details from an HTTP error response.

    Bounds payload reading, parses JSON error structures if present, and ensures
    any credentials or API keys are strictly redacted.
    """
    try:
        raw_bytes = exc.read(4096)
        if not raw_bytes:
            return ""
        raw_text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""

    diag = ""
    try:
        err_json = json.loads(raw_text)
        if isinstance(err_json, dict):
            err_obj = err_json.get("error", {})
            if isinstance(err_obj, dict):
                err_type = err_obj.get("type", "")
                reason = err_obj.get("reason", "")
                root_causes = err_obj.get("root_cause", [])
                if root_causes and isinstance(root_causes, list) and isinstance(root_causes[0], dict):
                    root_reason = root_causes[0].get("reason", "")
                    diag = f"[{err_type}] {reason or root_reason}" if err_type else (reason or root_reason)
                else:
                    diag = f"[{err_type}] {reason}" if err_type and reason else (reason or err_type)
            elif isinstance(err_obj, str):
                diag = err_obj
            elif "message" in err_json:
                diag = str(err_json["message"])
    except Exception:
        # Fallback to bounded raw text with stripped whitespace and tags
        cleaned = re.sub(r"<[^>]+>", " ", raw_text)
        diag = " ".join(cleaned.split())[:200]

    if not diag:
        diag = " ".join(raw_text.split())[:200]

    # Scrub specific secret and general authorization headers
    if redacted_secret and redacted_secret in diag:
        diag = diag.replace(redacted_secret, "[REDACTED]")

    diag = _AUTH_VALUE_PATTERN.sub("[REDACTED]", diag)
    return diag[:300].strip()


class ElasticAlertClient:
    """Read-only polling client for querying Elasticsearch Security Alerts.

    Endpoints & Permission Assumptions:
    - Queries standard Elasticsearch search endpoint: `POST {base_url}/{index_pattern}/_search`
    - Target index pattern is typically `.alerts-security.alerts-*` (Elastic 7.13+, 8.x, serverless).
    - Required Elasticsearch Permissions:
        In Elasticsearch 8.x+, security alert indices are restricted/system indices.
        The API key or role MUST possess 'read' privileges on `.alerts-security.alerts-*`
        with 'allow_restricted_indices: true' explicitly enabled on the role descriptor.
        Without 'allow_restricted_indices: true', direct searches will fail with HTTP 403.
    - Distinction from Kibana API:
        Kibana Detection Alerts API (`/api/detection_engine/signals/search`) operates
        at the UI/space application tier requiring Kibana session cookies/space tokens.
        ProofShield intentionally queries Elasticsearch directly to maintain version
        stability, minimal attack surface, and deterministic JSON query DSL.
    - TLS & Safety: Strictly enforces TLS certificate validation (custom CA supported).
    - Network calls are strictly opt-in and execute only when methods are explicitly invoked.
    """

    def __init__(self, settings: Optional[ElasticConnectorSettings] = None) -> None:
        if settings is None:
            settings = ElasticConnectorSettings.from_env()
        self.settings = settings
        self.last_search_total: Optional[int] = None
        self.last_search_relation: str = "eq"
        self.last_search_truncated: bool = False
        self.last_ingest_duplicates: List[str] = []

        # Prepare SSL context: enforce hostname verification and valid certificate trust chain
        if self.settings.base_url.startswith("https://"):
            if self.settings.ca_cert_path:
                ctx = ssl.create_default_context(cafile=self.settings.ca_cert_path)
            else:
                ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            self._ssl_context: Optional[ssl.SSLContext] = ctx
        else:
            self._ssl_context = None

    def _validate_search_parameters(
        self,
        *,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        limit: Optional[int],
        batch_size: Optional[int],
        max_retries: int = 2,
        rule_ids: Optional[Sequence[str]] = None,
        host: Optional[str] = None,
        process_name: Optional[str] = None,
        query_string: Optional[str] = None,
    ) -> None:
        """Reject ambiguous request parameters before constructing a query."""
        for name, value in (("start_time", start_time), ("end_time", end_time)):
            if value is not None and not isinstance(value, datetime):
                raise ElasticClientError(f"Invalid {name}; expected a datetime")
        if start_time is not None and end_time is not None:
            start_utc = start_time.astimezone(timezone.utc) if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)
            end_utc = end_time.astimezone(timezone.utc) if end_time.tzinfo else end_time.replace(tzinfo=timezone.utc)
            if start_utc > end_utc:
                raise ElasticClientError("Invalid Elasticsearch time window: start_time must not exceed end_time")

        for name, value in (("limit", limit), ("batch_size", batch_size)):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 1
            ):
                raise ElasticClientError(f"Invalid {name} '{value}'; expected a positive integer")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or not 0 <= max_retries <= MAX_ALLOWED_RETRIES:
            raise ElasticClientError(
                f"Invalid max_retries '{max_retries}'; expected an integer from 0 to {MAX_ALLOWED_RETRIES}"
            )

        if rule_ids is not None:
            if isinstance(rule_ids, (str, bytes)):
                raise ElasticClientError("Invalid rule_ids; expected a sequence of non-empty strings")
            try:
                for rule_id in rule_ids:
                    if not isinstance(rule_id, str) or not rule_id.strip():
                        raise ElasticClientError("Invalid rule_ids; expected a sequence of non-empty strings")
            except TypeError as exc:
                raise ElasticClientError("Invalid rule_ids; expected a sequence of non-empty strings") from exc
        for name, value in (("host", host), ("process_name", process_name), ("query_string", query_string)):
            if value is not None and not isinstance(value, str):
                raise ElasticClientError(f"Invalid {name}; expected a string")

    def _post_search(
        self,
        endpoint_url: str,
        query_dsl: Dict[str, Any],
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """Execute POST search against Elasticsearch with retry on transient status codes."""
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or not 0 <= max_retries <= MAX_ALLOWED_RETRIES:
            raise ElasticClientError(
                f"Invalid max_retries '{max_retries}'; expected an integer from 0 to {MAX_ALLOWED_RETRIES}"
            )
        payload_bytes = json.dumps(query_dsl).encode("utf-8")
        req = urllib.request.Request(
            url=endpoint_url,
            data=payload_bytes,
            headers={
                "Authorization": f"ApiKey {self.settings.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "ProofShield-Elastic-Connector/0.1.0",
            },
            method="POST",
        )

        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(
                    req,
                    timeout=self.settings.request_timeout,
                    context=self._ssl_context,
                ) as resp:
                    content_length = None
                    headers = getattr(resp, "headers", None)
                    if headers is not None:
                        raw_length = headers.get("Content-Length")
                        if raw_length is not None:
                            try:
                                content_length = int(raw_length)
                            except (TypeError, ValueError) as exc:
                                raise ElasticClientError(
                                    "Malformed Elasticsearch response: invalid Content-Length"
                                ) from exc
                            if content_length < 0:
                                raise ElasticClientError(
                                    "Malformed Elasticsearch response: negative Content-Length"
                                )
                            if content_length > self.settings.max_response_bytes:
                                raise ElasticClientError(
                                    "Elasticsearch response exceeds the configured byte limit"
                                )

                    try:
                        raw_bytes = resp.read(self.settings.max_response_bytes + 1)
                    except TypeError:
                        # Compatibility with minimal test doubles that expose read()
                        # without urllib's optional size argument. Real HTTPResponse
                        # objects always take the bounded read argument above.
                        raw_bytes = resp.read()
                    if not isinstance(raw_bytes, (bytes, bytearray)):
                        raise ElasticClientError(
                            "Malformed Elasticsearch response: response body is not bytes"
                        )
                    if len(raw_bytes) > self.settings.max_response_bytes:
                        raise ElasticClientError(
                            "Elasticsearch response exceeds the configured byte limit"
                        )
                    try:
                        resp_data = bytes(raw_bytes).decode("utf-8")
                        body = json.loads(resp_data)
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise ElasticClientError(
                            "Malformed Elasticsearch response: invalid JSON body"
                        ) from exc
                    if not isinstance(body, dict):
                        raise ElasticClientError(
                            "Malformed Elasticsearch response: top-level JSON value must be an object"
                        )
                    return body
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 502, 503, 504) and attempt < max_retries:
                    attempt += 1
                    time.sleep(0.05 * (2 ** (attempt - 1)))
                    continue
                diag = _extract_http_diagnostic(exc, redacted_secret=self.settings.api_key)
                err_detail = f"HTTP {exc.code} ({exc.reason})"
                if diag:
                    err_detail += f": {diag}"
                raise ElasticClientError(
                    f"Elasticsearch search failed with {err_detail}",
                    status_code=exc.code,
                ) from exc
            except (TimeoutError, urllib.error.URLError) as exc:
                is_timeout = isinstance(exc, TimeoutError) or "timed out" in str(getattr(exc, "reason", "")).lower()
                if is_timeout and attempt < max_retries:
                    attempt += 1
                    time.sleep(0.05 * (2 ** (attempt - 1)))
                    continue
                if isinstance(exc, TimeoutError):
                    raise ElasticClientError(
                        f"Elasticsearch request timed out after {self.settings.request_timeout}s"
                    ) from exc
                raise ElasticClientError(
                    f"Elasticsearch connection failed: {exc.reason}"
                ) from exc
            except ElasticClientError:
                raise
            except Exception as exc:
                raise ElasticClientError(
                    f"Unexpected error querying Elasticsearch: {exc}"
                ) from exc

    def search_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        rule_ids: Optional[Sequence[str]] = None,
        host: Optional[str] = None,
        limit: Optional[int] = None,
        raise_on_truncation: bool = False,
        batch_size: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Query Elasticsearch for alert documents within a bounded window.

        Supports pagination with 'search_after' up to the effective limit.
        Inspects hits.total and hits.total.relation to detect and expose truncation.

        Args:
            start_time: Earliest alert timestamp to include.
            end_time: Latest alert timestamp to include.
            rule_ids: Optional list of rule identifiers to filter by.
            host: Optional host identifier to filter by.
            limit: Maximum alerts to return (capped by settings.max_results).
            raise_on_truncation: If True, raises ElasticClientError when matching
                alerts exceed limit or relation is 'gte' instead of returning truncated results.
            batch_size: Number of hits to request per page query (default 100).

        Returns:
            List of Elasticsearch search hit dicts (`_id`, `_index`, `_source`).

        Raises:
            ElasticClientError: On network, HTTP, TLS, timeout, or authentication errors.
        """
        self._validate_search_parameters(
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            batch_size=batch_size,
            rule_ids=rule_ids,
            host=host,
        )
        filters: List[Dict[str, Any]] = []

        # Time range filter on ECS @timestamp
        range_filter: Dict[str, Any] = {}
        if start_time is not None:
            st = start_time.astimezone(timezone.utc) if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)
            range_filter["gte"] = st.isoformat()
        if end_time is not None:
            et = end_time.astimezone(timezone.utc) if end_time.tzinfo else end_time.replace(tzinfo=timezone.utc)
            range_filter["lte"] = et.isoformat()

        if range_filter:
            filters.append({"range": {"@timestamp": range_filter}})

        # Optional rule_ids filter
        if rule_ids:
            clean_rules = [r.strip() for r in rule_ids if r and r.strip()]
            if clean_rules:
                filters.append(
                    {
                        "bool": {
                            "should": [
                                {"terms": {"kibana.alert.rule.rule_id": clean_rules}},
                                {"terms": {"kibana.alert.rule.uuid": clean_rules}},
                                {"terms": {"signal.rule.rule_id": clean_rules}},
                                {"terms": {"signal.rule.id": clean_rules}},
                                {"terms": {"rule.id": clean_rules}},
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                )

        # Optional host filter
        if host and host.strip():
            h = host.strip()
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"term": {"host.hostname": h}},
                            {"term": {"host.name": h}},
                            {"term": {"host.id": h}},
                            {"term": {"agent.hostname": h}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )

        effective_limit = min(limit if limit is not None else self.settings.max_results, self.settings.max_results)
        endpoint_url = f"{self.settings.base_url}/{self.settings.index_pattern}/_search"

        all_hits: List[Dict[str, Any]] = []
        search_after: Optional[List[Any]] = None
        self.last_search_total = None
        self.last_search_relation = "eq"
        self.last_search_truncated = False
        page_chunk = min(batch_size if batch_size is not None else 100, self.settings.max_results)
        page_hits: List[Dict[str, Any]] = []
        page_size = page_chunk

        while len(all_hits) < effective_limit:
            page_size = min(effective_limit - len(all_hits), page_chunk)
            query_dsl: Dict[str, Any] = {
                "query": {"bool": {"filter": filters} if filters else {"match_all": {}}},
                "sort": [
                    {"@timestamp": {"order": "asc"}},
                    {"_id": {"order": "asc"}},
                ],
                "size": page_size,
            }
            if search_after:
                query_dsl["search_after"] = search_after

            body = self._post_search(endpoint_url, query_dsl, max_retries=2)
            page_hits, response_total, response_relation = _validate_search_page(body)

            # Parse hits.total (supports integer or {value: int, relation: str})
            if self.last_search_total is None:
                self.last_search_total = response_total if response_total is not None else len(page_hits)
                self.last_search_relation = response_relation

            if not page_hits:
                break

            all_hits.extend(page_hits)

            if len(all_hits) >= effective_limit or len(page_hits) < page_size:
                break

            # Prepare search_after token from the last hit in the current page
            last_hit = page_hits[-1]
            sort_val = last_hit.get("sort")
            if isinstance(sort_val, (list, tuple)) and len(sort_val) >= 1:
                search_after = list(sort_val)
            else:
                # Missing sort token prevents reliable continuation
                self.last_search_truncated = True
                if raise_on_truncation:
                    raise ElasticClientError(
                        "Elasticsearch search hit missing valid 'sort' values required for search_after pagination"
                    )
                break

        # Conservative truncation detection:
        # 1. Total count exceeds the number of retrieved hits
        if self.last_search_total is not None and self.last_search_total > len(all_hits):
            self.last_search_truncated = True
        # 2. Total relation is "gte" (lower bound) and retrieval was bounded or ended on page boundary
        elif self.last_search_relation == "gte" and (len(all_hits) >= effective_limit or (page_hits and len(page_hits) == page_size)):
            self.last_search_truncated = True

        if self.last_search_truncated and raise_on_truncation:
            rel_str = f" (relation '{self.last_search_relation}')" if self.last_search_relation != "eq" else ""
            raise ElasticClientError(
                f"Elasticsearch search results truncated: matched {self.last_search_total}{rel_str} alerts "
                f"but query limit bounded to {len(all_hits)}"
            )

        return all_hits

    def fetch_and_map_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        rule_ids: Optional[Sequence[str]] = None,
        host: Optional[str] = None,
        limit: Optional[int] = None,
        deduplicate: bool = True,
        raise_on_truncation: bool = False,
        batch_size: Optional[int] = None,
    ) -> List[AlertV1]:
        """Fetch alert documents from Elastic and map them into AlertV1 records."""
        hits = self.search_alerts(
            start_time=start_time,
            end_time=end_time,
            rule_ids=rule_ids,
            host=host,
            limit=limit,
            raise_on_truncation=raise_on_truncation,
            batch_size=batch_size,
        )
        try:
            return map_elastic_alerts_batch(hits, deduplicate=deduplicate)
        except ElasticAlertMappingError as exc:
            raise ElasticClientError(f"Malformed Elasticsearch alert hit: {exc}") from exc

    def poll_and_ingest(
        self,
        store: StoreProtocol,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        rule_ids: Optional[Sequence[str]] = None,
        host: Optional[str] = None,
        limit: Optional[int] = None,
        skip_duplicates: bool = True,
        raise_on_truncation: bool = False,
        batch_size: Optional[int] = None,
        atomic: bool = False,
    ) -> List[AlertV1]:
        """Fetch alerts and ingest them into a ProofShield store idempotently.

        Guarantees:
        - When atomic=True: the entire ingestion sequence is executed inside store.transaction().
          If a duplicate is encountered (with skip_duplicates=False) or an exception occurs,
          all newly ingested records in the batch are rolled back.
        - When atomic=False (default): partial success is preserved. Novel alerts added
          before an exception remain committed in the store.
        - When skip_duplicates=True: existing alerts are skipped idempotently; novel
          alerts are ingested and returned without raising ValueError.
        - When skip_duplicates=False: existing alerts are skipped from ingestion and
          recorded, subsequent novel alerts in the batch are still ingested, and
          ValueError is raised at the end listing all duplicates.

        Args:
            store: StoreProtocol implementation (InMemoryStore or SQLiteStore).
            start_time: Earliest timestamp filter.
            end_time: Latest timestamp filter.
            rule_ids: Optional rule filter.
            host: Optional host filter.
            limit: Maximum alerts to fetch.
            skip_duplicates: If True, skips duplicate alerts idempotently. If False,
                ingests novel alerts and raises ValueError listing duplicates.
            raise_on_truncation: If True, raises ElasticClientError on truncated results.
            batch_size: Page size chunk for pagination queries.
            atomic: If True, executes ingestion inside a transaction, rolling back on error.

        Returns:
            List of newly ingested AlertV1 instances.
        """
        # Decouple network retrieval from store transactions
        alerts = self.fetch_and_map_alerts(
            start_time=start_time,
            end_time=end_time,
            rule_ids=rule_ids,
            host=host,
            limit=limit,
            deduplicate=True,
            raise_on_truncation=raise_on_truncation,
            batch_size=batch_size,
        )

        def _execute_ingestion() -> List[AlertV1]:
            ingested: List[AlertV1] = []
            duplicate_ids: List[str] = []

            for alert in alerts:
                existing = store.get_alert(alert.alert_id)
                if existing is not None:
                    duplicate_ids.append(alert.alert_id)
                    continue

                try:
                    store.add_alert(alert)
                    ingested.append(alert)
                except ValueError as exc:
                    if "already exists" in str(exc).lower():
                        duplicate_ids.append(alert.alert_id)
                    else:
                        raise

            self.last_ingest_duplicates = duplicate_ids

            if not skip_duplicates and duplicate_ids:
                raise ValueError(
                    f"Duplicate alert(s) already exist in store: {', '.join(duplicate_ids)}"
                )

            return ingested

        if atomic:
            with store.transaction():
                return _execute_ingestion()
        return _execute_ingestion()

    def search_telemetry(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        host: Optional[str] = None,
        process_name: Optional[str] = None,
        query_string: Optional[str] = None,
        limit: Optional[int] = None,
        raise_on_truncation: bool = False,
        batch_size: Optional[int] = None,
        max_retries: int = 2,
    ) -> ElasticTelemetryBatch:
        """Query Elasticsearch for raw telemetry documents within a bounded window.

        Queries the configured telemetry index pattern (e.g. 'logs-*').
        Supports search_after pagination, host/process/query filters,
        and strict truncation detection.

        Args:
            start_time: Earliest event timestamp (inclusive).
            end_time: Latest event timestamp (inclusive).
            host: Optional host/endpoint identifier filter.
            process_name: Optional process name/executable filter.
            query_string: Optional Lucene query string.
            limit: Maximum events to return (capped by settings.max_results).
            raise_on_truncation: If True, raises ElasticClientError on truncated results.
            batch_size: Page size chunk for pagination queries.
            max_retries: Number of retries on transient errors (429, 502, 503, 504, timeout).

        Returns:
            ElasticTelemetryBatch with hits, count, and truncation status.
        """
        self._validate_search_parameters(
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            batch_size=batch_size,
            max_retries=max_retries,
            host=host,
            process_name=process_name,
            query_string=query_string,
        )
        filters: List[Dict[str, Any]] = []

        range_filter: Dict[str, Any] = {}
        if start_time is not None:
            st = start_time.astimezone(timezone.utc) if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)
            range_filter["gte"] = st.isoformat()
        if end_time is not None:
            et = end_time.astimezone(timezone.utc) if end_time.tzinfo else end_time.replace(tzinfo=timezone.utc)
            range_filter["lte"] = et.isoformat()

        if range_filter:
            filters.append({"range": {"@timestamp": range_filter}})

        if host and host.strip():
            h = host.strip()
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"term": {"host.hostname": h}},
                            {"term": {"host.name": h}},
                            {"term": {"host.id": h}},
                            {"term": {"agent.hostname": h}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )

        if process_name and process_name.strip():
            p = process_name.strip()
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"term": {"process.name": p}},
                            {"term": {"process.executable": p}},
                            {"wildcard": {"process.command_line": f"*{p}*"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )

        if query_string and query_string.strip():
            filters.append({"query_string": {"query": query_string.strip()}})

        effective_limit = min(limit if limit is not None else self.settings.max_results, self.settings.max_results)
        endpoint_url = f"{self.settings.base_url}/{self.settings.telemetry_index_pattern}/_search"

        all_hits: List[Dict[str, Any]] = []
        search_after: Optional[List[Any]] = None
        total_matched: Optional[int] = None
        relation: str = "eq"
        is_truncated: bool = False
        page_chunk = min(batch_size if batch_size is not None else 100, self.settings.max_results)
        page_hits: List[Dict[str, Any]] = []
        page_size = page_chunk

        while len(all_hits) < effective_limit:
            page_size = min(effective_limit - len(all_hits), page_chunk)
            query_dsl: Dict[str, Any] = {
                "query": {"bool": {"filter": filters} if filters else {"match_all": {}}},
                "sort": [
                    {"@timestamp": {"order": "asc"}},
                    {"_id": {"order": "asc"}},
                ],
                "size": page_size,
            }
            if search_after:
                query_dsl["search_after"] = search_after

            body = self._post_search(endpoint_url, query_dsl, max_retries=max_retries)
            page_hits, response_total, response_relation = _validate_search_page(
                body,
                require_timestamps=True,
            )

            if total_matched is None:
                total_matched = response_total if response_total is not None else len(page_hits)
                relation = response_relation

            if not page_hits:
                break

            all_hits.extend(page_hits)

            if len(all_hits) >= effective_limit or len(page_hits) < page_size:
                break

            last_hit = page_hits[-1]
            sort_val = last_hit.get("sort")
            if isinstance(sort_val, (list, tuple)) and len(sort_val) >= 1:
                search_after = list(sort_val)
            else:
                is_truncated = True
                if raise_on_truncation:
                    raise ElasticClientError(
                        "Elasticsearch search hit missing valid 'sort' values required for search_after pagination"
                    )
                break

        # Check truncation
        if total_matched is not None and total_matched > len(all_hits):
            is_truncated = True
        elif relation == "gte" and (len(all_hits) >= effective_limit or (page_hits and len(page_hits) == page_size)):
            is_truncated = True

        if is_truncated and raise_on_truncation:
            rel_str = f" (relation '{relation}')" if relation != "eq" else ""
            raise ElasticClientError(
                f"Elasticsearch telemetry search results truncated: matched {total_matched}{rel_str} events "
                f"but query limit bounded to {len(all_hits)}"
            )

        if not all_hits:
            status = TelemetryRetrievalStatus.EMPTY
        elif is_truncated:
            status = TelemetryRetrievalStatus.TRUNCATED
        else:
            status = TelemetryRetrievalStatus.COMPLETE

        return ElasticTelemetryBatch(
            hits=all_hits,
            total_matched=total_matched,
            relation=relation,
            is_truncated=is_truncated,
            status=status,
            query_window=(start_time, end_time),
        )

    @staticmethod
    def map_hits_to_raw_telemetry(hits: Iterable[Dict[str, Any]]) -> List[RawTelemetryEventV1]:
        """Convert raw Elastic hits to canonical RawTelemetryEventV1 models."""
        raw_events: List[RawTelemetryEventV1] = []
        for position, hit in enumerate(hits):
            if not isinstance(hit, dict):
                raise ElasticAlertMappingError(
                    f"Elastic telemetry hit {position} must be an object"
                )
            try:
                source = hit.get("_source", hit)
                if not isinstance(source, dict):
                    raise ElasticAlertMappingError(
                        f"Elastic telemetry hit {position} has an invalid '_source'"
                    )
                hit_id = _hit_identifier(hit, source)
                if hit_id is None:
                    raise ElasticAlertMappingError(
                        f"Elastic telemetry hit {position} lacks a valid identifier"
                    )
            except ElasticClientError as exc:
                raise ElasticAlertMappingError(str(exc)) from exc
            raw_event_id = f"elastic:raw:{hit_id}" if not hit_id.startswith("elastic:") else hit_id

            ts_raw = _first_present(source, ("@timestamp", "event.created"))
            if ts_raw is None:
                raise ElasticAlertMappingError(
                    f"Elastic telemetry hit {position} lacks a source timestamp"
                )
            source_ts = _parse_timestamp(ts_raw)
            if source_ts is None:
                raise ElasticAlertMappingError(
                    f"Elastic telemetry hit {position} has an empty source timestamp"
                )

            sanitized_payload = _sanitize_metadata(deepcopy(source))

            raw_events.append(
                RawTelemetryEventV1(
                    schema_version="v1",
                    raw_event_id=raw_event_id,
                    source_event_id=hit_id,
                    source_format="elastic_ecs",
                    source_timestamp=source_ts,
                    ingested_at=datetime.now(timezone.utc),
                    raw_payload=sanitized_payload,
                )
            )
        return raw_events

    def fetch_raw_telemetry(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        host: Optional[str] = None,
        process_name: Optional[str] = None,
        query_string: Optional[str] = None,
        limit: Optional[int] = None,
        raise_on_truncation: bool = False,
        batch_size: Optional[int] = None,
        max_retries: int = 2,
    ) -> List[RawTelemetryEventV1]:
        """Fetch telemetry documents from Elastic and map them into RawTelemetryEventV1 models."""
        batch = self.search_telemetry(
            start_time=start_time,
            end_time=end_time,
            host=host,
            process_name=process_name,
            query_string=query_string,
            limit=limit,
            raise_on_truncation=raise_on_truncation,
            batch_size=batch_size,
            max_retries=max_retries,
        )
        try:
            return self.map_hits_to_raw_telemetry(batch.hits)
        except ElasticAlertMappingError as exc:
            raise ElasticClientError(f"Malformed Elasticsearch telemetry hit: {exc}") from exc

    def poll_and_ingest_telemetry(
        self,
        store: StoreProtocol,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        host: Optional[str] = None,
        process_name: Optional[str] = None,
        query_string: Optional[str] = None,
        limit: Optional[int] = None,
        skip_duplicates: bool = True,
        raise_on_truncation: bool = False,
        batch_size: Optional[int] = None,
        atomic: bool = False,
        max_retries: int = 2,
    ) -> List[RawTelemetryEventV1]:
        """Fetch telemetry and ingest raw events into a ProofShield store idempotently.

        Guarantees:
        - When atomic=True: the ingestion sequence is executed inside store.transaction().
        - When skip_duplicates=True: existing raw events are skipped idempotently.
        - When skip_duplicates=False: raises ValueError listing duplicate IDs.
        """
        # Decouple network retrieval from store transactions
        raw_events = self.fetch_raw_telemetry(
            start_time=start_time,
            end_time=end_time,
            host=host,
            process_name=process_name,
            query_string=query_string,
            limit=limit,
            raise_on_truncation=raise_on_truncation,
            batch_size=batch_size,
            max_retries=max_retries,
        )

        def _execute_ingestion() -> List[RawTelemetryEventV1]:
            ingested: List[RawTelemetryEventV1] = []
            duplicate_ids: List[str] = []

            for rev in raw_events:
                existing = store.get_raw_event(rev.raw_event_id)
                if existing is not None:
                    duplicate_ids.append(rev.raw_event_id)
                    continue

                try:
                    store.add_raw_event(rev)
                    ingested.append(rev)
                except ValueError as exc:
                    if "already exists" in str(exc).lower():
                        duplicate_ids.append(rev.raw_event_id)
                    else:
                        raise

            if not skip_duplicates and duplicate_ids:
                raise ValueError(
                    f"Duplicate raw event(s) already exist in store: {', '.join(duplicate_ids)}"
                )

            return ingested

        if atomic:
            with store.transaction():
                return _execute_ingestion()
        return _execute_ingestion()


# Backwards compatibility alias
ElasticClient = ElasticAlertClient
