"""Elastic Security Alert Ingestion Connector for PROOFSHIELD.

Provides:
1. Pure, offline-testable mapping of Elastic Security alert documents (ECS,
   Kibana Alerting, legacy Signal formats) into canonical AlertV1 models.
2. Safe, read-only Elasticsearch client using standard-library urllib with
   deterministic queries, mandatory TLS verification, bounded time ranges,
   and secret redaction.
"""

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union
import urllib.error
import urllib.request

import dateutil.parser

from proofshield.normalisation.engine import extract_execution_token
from proofshield.schemas.alert import AlertV1
from proofshield.services.base_store import StoreProtocol


class ElasticAlertMappingError(ValueError):
    """Raised when an Elastic alert document cannot be mapped into AlertV1."""


class ElasticClientError(RuntimeError):
    """Raised on connection, query, timeout, or authentication failures with Elastic."""


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

import re
_AUTH_VALUE_PATTERN = re.compile(r"^(?:Bearer|ApiKey|Basic)\s+[A-Za-z0-9_\-\.\+/=]+", re.IGNORECASE)


def _sanitize_metadata(val: Any) -> Any:
    """Recursively scrub credentials from metadata dicts while preserving forensic fields.

    Preserves legitimate investigation attributes like 'password_reset', 'secret_scope',
    'auth_token_id', and 'password_hash' unless they hold cleartext credentials.
    """
    if isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            k_clean = str(k).strip().lower().replace("-", "_").replace(".", "_")

            # Check if this is an explicitly preserved forensic attribute
            is_forensic_attribute = any(
                k_clean.endswith(suf) for suf in _FORENSIC_NON_SECRET_SUFFIXES
            )

            if is_forensic_attribute:
                sanitized[k] = _sanitize_metadata(v)
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
                sanitized[k] = _sanitize_metadata(v)
        return sanitized
    if isinstance(val, list):
        return [_sanitize_metadata(item) for item in val]
    return val


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

    if isinstance(raw_val, (int, float)):
        # If value is in milliseconds (greater than year 2286 in seconds, ~1e11)
        if raw_val > 1e11:
            return datetime.fromtimestamp(raw_val / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(raw_val, tz=timezone.utc)

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
    raw_id = (
        doc.get("_id")
        or _get_nested(source, "_id")
        or _get_nested(source, "kibana.alert.uuid")
        or _get_nested(source, "kibana.alert.id")
        or _get_nested(source, "signal.id")
        or _get_nested(source, "signal.parent.id")
        or _get_nested(source, "alert_id")
    )
    if raw_id is None or not str(raw_id).strip():
        raise ElasticAlertMappingError(
            "Elastic alert document lacks a valid identifier ('_id', 'kibana.alert.uuid', etc.)"
        )
    source_alert_id = str(raw_id).strip()

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
    raw_ts = (
        _get_nested(source, "@timestamp")
        or _get_nested(source, "kibana.alert.start")
        or _get_nested(source, "signal.original_time")
        or _get_nested(source, "timestamp")
        or _get_nested(source, "event.created")
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
        request_timeout: float = 10.0,
        max_results: int = 100,
        enabled: bool = False,
    ) -> None:
        url_clean = str(base_url).strip()
        if not url_clean:
            raise ValueError("Elastic base URL cannot be empty.")
        if not (url_clean.startswith("http://") or url_clean.startswith("https://")):
            raise ValueError(
                f"Elastic base URL must start with 'http://' or 'https://': '{base_url}'"
            )
        self.base_url = url_clean.rstrip("/")

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

        try:
            t_val = float(request_timeout)
            if t_val <= 0:
                raise ValueError()
            self.request_timeout = t_val
        except (ValueError, TypeError):
            raise ValueError(
                f"Elastic request timeout must be a positive float: '{request_timeout}'"
            )

        try:
            m_val = int(max_results)
            if m_val < 1 or m_val > 10000:
                raise ValueError()
            self.max_results = m_val
        except (ValueError, TypeError):
            raise ValueError(
                f"Elastic max_results must be an integer between 1 and 10000: '{max_results}'"
            )

        self.enabled = bool(enabled)

    @classmethod
    def from_env(cls) -> "ElasticConnectorSettings":
        """Load Elastic connector settings from PROOFSHIELD_ELASTIC_* environment variables."""
        url = os.environ.get("PROOFSHIELD_ELASTIC_URL", "")
        api_key = os.environ.get("PROOFSHIELD_ELASTIC_API_KEY", "")
        ca_cert = os.environ.get("PROOFSHIELD_ELASTIC_CA_CERT")
        index = os.environ.get("PROOFSHIELD_ELASTIC_INDEX", ".alerts-security.alerts-*")
        timeout_env = os.environ.get("PROOFSHIELD_ELASTIC_TIMEOUT", "10.0")
        max_env = os.environ.get("PROOFSHIELD_ELASTIC_MAX_RESULTS", "100")
        enabled_env = os.environ.get("PROOFSHIELD_ELASTIC_ENABLED", "false").strip().lower()

        enabled = enabled_env in ("true", "1", "yes", "on")

        return cls(
            base_url=url,
            api_key=api_key,
            ca_cert_path=ca_cert,
            index_pattern=index,
            request_timeout=float(timeout_env),
            max_results=int(max_env),
            enabled=enabled,
        )

    def __repr__(self) -> str:
        # Redact the api_key to ensure credentials are never exposed in logs or representations
        return (
            f"ElasticConnectorSettings(base_url={self.base_url!r}, "
            f"api_key='***REDACTED***', "
            f"index_pattern={self.index_pattern!r}, "
            f"request_timeout={self.request_timeout}, "
            f"max_results={self.max_results}, "
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

        effective_limit = min(limit or self.settings.max_results, self.settings.max_results)
        endpoint_url = f"{self.settings.base_url}/{self.settings.index_pattern}/_search"

        all_hits: List[Dict[str, Any]] = []
        search_after: Optional[List[Any]] = None
        self.last_search_total = None
        self.last_search_relation = "eq"
        self.last_search_truncated = False
        page_chunk = batch_size if (batch_size is not None and batch_size > 0) else 100
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

            try:
                with urllib.request.urlopen(
                    req,
                    timeout=self.settings.request_timeout,
                    context=self._ssl_context,
                ) as resp:
                    resp_data = resp.read().decode("utf-8")
                    body = json.loads(resp_data)
                    hits_container = body.get("hits", {})
                    page_hits = hits_container.get("hits", [])

                    # Parse hits.total (supports integer or {value: int, relation: str})
                    if self.last_search_total is None:
                        total_raw = hits_container.get("total")
                        if isinstance(total_raw, dict):
                            self.last_search_total = int(total_raw.get("value", 0))
                            self.last_search_relation = str(total_raw.get("relation", "eq")).strip().lower()
                        elif isinstance(total_raw, (int, float)):
                            self.last_search_total = int(total_raw)
                            self.last_search_relation = "eq"
                        else:
                            self.last_search_total = len(page_hits)
                            self.last_search_relation = "eq"

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

            except urllib.error.HTTPError as exc:
                diag = _extract_http_diagnostic(exc, redacted_secret=self.settings.api_key)
                err_detail = f"HTTP {exc.code} ({exc.reason})"
                if diag:
                    err_detail += f": {diag}"
                raise ElasticClientError(
                    f"Elasticsearch search failed with {err_detail}"
                ) from exc
            except urllib.error.URLError as exc:
                raise ElasticClientError(
                    f"Elasticsearch connection failed: {exc.reason}"
                ) from exc
            except TimeoutError as exc:
                raise ElasticClientError(
                    f"Elasticsearch request timed out after {self.settings.request_timeout}s"
                ) from exc
            except ElasticClientError:
                raise
            except Exception as exc:
                raise ElasticClientError(
                    f"Unexpected error querying Elasticsearch: {exc}"
                ) from exc

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
        return map_elastic_alerts_batch(hits, deduplicate=deduplicate)

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
        def _execute_ingestion() -> List[AlertV1]:
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

