"""Read-only Splunk REST connector for ProofShield telemetry assurance.

The connector consumes Splunk search results, preserves each source result as a
``RawTelemetryEventV1``, and maps alert results to ``AlertV1``.  It deliberately
does not evaluate SPL or implement a second assurance engine; the canonical
normalisation and ``AssuranceEngine`` remain the authority.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import ssl
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request
import uuid

import dateutil.parser

from proofshield.normalisation.engine import extract_execution_token, TOKEN_STRUCTURED_KEYS
from proofshield.schemas.alert import AlertV1
from proofshield.schemas.telemetry import RawTelemetryEventV1
from proofshield.connectors.transport import validate_source_url, verified_opener
import math


class SplunkClientError(RuntimeError):
    """Raised when Splunk retrieval, authentication, or result parsing fails."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class SplunkMappingError(ValueError):
    """Raised when a Splunk result cannot be mapped to a canonical record."""


class SplunkRetrievalStatus(str):
    COMPLETE = "COMPLETE"
    TRUNCATED = "TRUNCATED"
    EMPTY = "EMPTY"
    FAILED = "FAILED"


@dataclass
class SplunkTelemetryBatch:
    results: List[Dict[str, Any]]
    total_matched: Optional[int]
    is_truncated: bool
    status: str
    query_window: Tuple[Optional[datetime], Optional[datetime]] = (None, None)


@dataclass
class SplunkConnectorSettings:
    """Configuration for the Splunk management/search API."""

    base_url: str
    token: str
    telemetry_index: str = "main"
    alert_index: str = "notable"
    telemetry_sourcetype: Optional[str] = None
    request_timeout: float = 10.0
    max_results: int = 1000
    verify_tls: bool = True
    enabled: bool = False

    def __post_init__(self) -> None:
        self.base_url = validate_source_url(str(self.base_url))
        self.token = str(self.token).strip()
        if not self.base_url:
            raise ValueError("Splunk base_url cannot be empty")
        if not self.token:
            raise ValueError("Splunk token cannot be empty")
        for value in (self.telemetry_index, self.alert_index, self.telemetry_sourcetype):
            if value is not None and not re.fullmatch(r"[A-Za-z0-9_.*:-]{1,128}", value):
                raise ValueError("Invalid Splunk index or sourcetype identifier")
        if not math.isfinite(float(self.request_timeout)) or not 0 < float(self.request_timeout) <= 120:
            raise ValueError("Splunk request_timeout must be positive")
        if not 1 <= int(self.max_results) <= 10000:
            raise ValueError("Splunk max_results must be between 1 and 10000")
        if self.base_url.startswith("https://") and not self.verify_tls:
            raise ValueError("Splunk HTTPS requires certificate verification")

    @classmethod
    def from_env(cls) -> "SplunkConnectorSettings":
        enabled = os.environ.get("PROOFSHIELD_SPLUNK_ENABLED", "false").lower() in {
            "1", "true", "yes", "on"
        }
        return cls(
            base_url=os.environ.get("PROOFSHIELD_SPLUNK_URL", ""),
            token=os.environ.get("PROOFSHIELD_SPLUNK_TOKEN", ""),
            telemetry_index=os.environ.get("PROOFSHIELD_SPLUNK_TELEMETRY_INDEX", "main"),
            alert_index=os.environ.get("PROOFSHIELD_SPLUNK_ALERT_INDEX", "notable"),
            telemetry_sourcetype=os.environ.get("PROOFSHIELD_SPLUNK_TELEMETRY_SOURCETYPE") or None,
            request_timeout=float(os.environ.get("PROOFSHIELD_SPLUNK_TIMEOUT", "10")),
            max_results=int(os.environ.get("PROOFSHIELD_SPLUNK_MAX_RESULTS", "1000")),
            verify_tls=os.environ.get("PROOFSHIELD_SPLUNK_VERIFY_TLS", "true").lower()
            not in {"0", "false", "no", "off"},
            enabled=enabled,
        )

    def __repr__(self) -> str:
        return (
            f"SplunkConnectorSettings(base_url={self.base_url!r}, token='***REDACTED***', "
            f"telemetry_index={self.telemetry_index!r}, alert_index={self.alert_index!r}, "
            f"request_timeout={self.request_timeout}, max_results={self.max_results}, "
            f"verify_tls={self.verify_tls}, enabled={self.enabled})"
        )


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    if text.replace(".", "", 1).isdigit():
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    parsed = dateutil.parser.isoparse(text)
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _nested(record: Dict[str, Any], *paths: str) -> Any:
    for path in paths:
        if path in record and record[path] is not None:
            return record[path]
        current: Any = record
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current is not None:
            return current
    return None


_SECRET_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "cookie"}


def _sanitize(value: Any, depth: int = 0) -> Any:
    if depth > 32:
        return "[REDACTED_NESTED]"
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key, item in value.items():
            name = str(key).lower().replace("-", "_")
            if name in _SECRET_KEYS or name.endswith(("_password", "_secret", "_api_key")):
                result[key] = "[REDACTED]"
            else:
                result[key] = _sanitize(item, depth + 1)
        return result
    if isinstance(value, list):
        return [_sanitize(item, depth + 1) for item in value[:1000]]
    return value


def _attribution_tokens(value, depth=0):
    if depth > 32:
        raise SplunkMappingError("Splunk attribution nesting exceeds limit")
    tokens = set()
    if isinstance(value, dict):
        for key, item in value.items():
            tail = str(key).rsplit(".", 1)[-1].lower()
            if tail in TOKEN_STRUCTURED_KEYS or tail == "proofshield_execution_token":
                token = extract_execution_token(payload={"execution_token": item})
                if token:
                    tokens.add(token)
            tokens |= _attribution_tokens(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            tokens |= _attribution_tokens(item, depth + 1)
    elif isinstance(value, str):
        token = extract_execution_token(text_fields=[value])
        if token:
            tokens.add(token)
    return tokens


def _result_source(result: Dict[str, Any]) -> Dict[str, Any]:
    event = result.get("_raw")
    if isinstance(event, str) and event.lstrip().startswith("{"):
        try:
            event = json.loads(event)
        except ValueError as exc:
            raise SplunkMappingError("Malformed JSON in Splunk _raw") from exc
    if isinstance(event, dict):
        for key in event.keys() & result.keys():
            if key not in {"_raw", "_cd", "index", "sourcetype", "source", "_indextime", "_serial"} and event[key] != result[key]:
                raise SplunkMappingError("Conflicting raw and extracted Splunk fields")
        merged = dict(event)
        merged.update({k: v for k, v in result.items() if k != "_raw"})
        tokens = _attribution_tokens(event) | _attribution_tokens(result)
    else:
        merged = dict(result)
        tokens = _attribution_tokens(result)
    if len(tokens) > 1 or "CONFLICT" in tokens:
        merged["execution_token"] = "CONFLICT"
    elif tokens:
        merged["execution_token"] = next(iter(tokens))
    return merged


def _stable_result_id(result: Dict[str, Any], source: Dict[str, Any]) -> str:
    candidate = (
        result.get("_cd")
        or result.get("event_id")
        or result.get("event.id")
        or result.get("id")
    )
    if candidate:
        index = str(result.get("index", ""))
        return f"{index}:{candidate}" if index else str(candidate)
    encoded = json.dumps(source, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:32]


def map_splunk_result_to_raw(result: Dict[str, Any]) -> RawTelemetryEventV1:
    """Map one Splunk search result to preserved raw canonical telemetry."""
    if not isinstance(result, dict):
        raise SplunkMappingError("Splunk result must be an object")
    source = _result_source(result)
    source_id = _stable_result_id(result, source)
    timestamp = _parse_timestamp(_nested(source, "@timestamp", "_time", "event.created", "timestamp"))
    if timestamp is None:
        raise SplunkMappingError("Splunk telemetry requires an observed source timestamp")
    return RawTelemetryEventV1(
        schema_version="v1",
        raw_event_id=f"splunk:raw:{source_id}",
        source_event_id=source_id,
        source_format="splunk",
        source_timestamp=timestamp,
        ingested_at=datetime.now(timezone.utc),
        raw_payload=deepcopy(result),
    )


def map_splunk_alert(result: Dict[str, Any]) -> AlertV1:
    """Map a Splunk alert/result record to the shared ``AlertV1`` schema."""
    if not isinstance(result, dict):
        raise SplunkMappingError("Splunk alert result must be an object")
    source = _result_source(result)
    source_id = _stable_result_id(result, source)
    host = _nested(source, "host.name", "host.hostname", "host", "dest", "ComputerName")
    if not isinstance(host, str) or not host.strip():
        raise SplunkMappingError("Splunk alert requires an observed host")
    host = host.strip()
    rule = _nested(source, "rule_id", "rule.id", "detection_rule_id", "savedsearch_name", "search_name")
    timestamp = _parse_timestamp(_nested(source, "@timestamp", "_time", "event.created", "timestamp"))
    token = extract_execution_token(payload=source, text_fields=[str(source.get("_raw", "")), str(_nested(source, "process.command_line", "CommandLine", "process") or "")])
    return AlertV1(
        schema_version="v1",
        alert_id=f"splunk:alert:{source_id}",
        source_alert_id=source_id,
        source_type="splunk",
        alert_timestamp=timestamp,
        ingested_at=datetime.now(timezone.utc),
        host_id=host,
        rule_reference=str(rule).strip() if rule else None,
        alert_title=str(_nested(source, "alert_title", "title", "name") or "Splunk detection alert"),
        severity=str(_nested(source, "severity", "priority") or "unknown"),
        raw_record_reference=f"splunk:raw:{source_id}",
        execution_token=token,
        metadata=_sanitize(source),
    )


class SplunkClient:
    """Bounded, read-only client for Splunk's export search endpoint."""

    def __init__(self, settings: Optional[SplunkConnectorSettings] = None) -> None:
        self.settings = settings or SplunkConnectorSettings.from_env()
        self.last_search_total: Optional[int] = None
        self.last_search_truncated = False
        self.last_ingest_duplicates: List[str] = []
        self._opener = verified_opener()

    def _search(self, query: str, earliest: Optional[datetime], latest: Optional[datetime], limit: int) -> List[Dict[str, Any]]:
        params = {
            "search": query,
            "output_mode": "json",
            "count": str(limit),
            "exec_mode": "blocking",
        }
        if earliest is not None:
            params["earliest_time"] = earliest.astimezone(timezone.utc).isoformat()
        if latest is not None:
            params["latest_time"] = latest.astimezone(timezone.utc).isoformat()
        body = urllib.parse.urlencode(params).encode("utf-8")
        request = urllib.request.Request(
            f"{self.settings.base_url}/services/search/jobs/export",
            data=body,
            headers={
                "Authorization": f"Bearer {self.settings.token}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": "ProofShield-Splunk-Connector/1.0",
            },
            method="POST",
        )
        for attempt in range(3):
            try:
                with self._opener.open(request, timeout=self.settings.request_timeout) as response:
                    payload = response.read(8 * 1024 * 1024 + 1)
                    expected_length = getattr(response, "headers", {}).get("Content-Length")
                if len(payload) > 8 * 1024 * 1024:
                    raise SplunkClientError("Splunk response exceeds byte limit; evidence is incomplete")
                if expected_length is not None and len(payload) != int(expected_length):
                    raise SplunkClientError("Premature end of Splunk HTTP response")
                raw = payload.decode("utf-8", errors="strict")
                return self._decode_results(raw)
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 502, 503, 504) and attempt < 2:
                    time.sleep(0.05 * (2**attempt))
                    continue
                raise SplunkClientError(f"Splunk search failed with HTTP {exc.code}", status_code=exc.code) from exc
            except (TimeoutError, urllib.error.URLError) as exc:
                if attempt < 2:
                    time.sleep(0.05 * (2**attempt))
                    continue
                raise SplunkClientError("Splunk connection failed after bounded retries") from exc
            except SplunkClientError:
                raise
            except Exception as exc:
                raise SplunkClientError("Invalid Splunk response or transport failure") from exc
        raise SplunkClientError("Splunk search failed after retries")

    @staticmethod
    def _decode_results(raw: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        finished = False
        saw_frame = False
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            saw_frame = True
            if finished:
                raise SplunkClientError("Splunk data received after final export row")
            try:
                decoded = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SplunkClientError("Malformed Splunk export JSON; evidence is incomplete") from exc
            if not isinstance(decoded, dict):
                raise SplunkClientError("Invalid Splunk export envelope")
            messages = decoded.get("messages", [])
            if not isinstance(messages, list):
                raise SplunkClientError("Invalid Splunk export messages envelope")
            if messages:
                raise SplunkClientError("Splunk export reported server messages; completeness unknown")
            if decoded.get("preview") not in (None, False):
                raise SplunkClientError("Splunk preview evidence cannot establish completeness")
            if "lastrow" in decoded and not isinstance(decoded["lastrow"], bool):
                raise SplunkClientError("Invalid Splunk export completion marker")
            finished = decoded.get("lastrow") is True
            if "result" in decoded and isinstance(decoded["result"], dict):
                results.append(decoded["result"])
            elif set(decoded) - {"messages", "preview", "lastrow", "offset", "init_offset"}:
                raise SplunkClientError("Unexpected Splunk export envelope")
        if not saw_frame or not finished:
            raise SplunkClientError("Splunk export ended without a final row marker")
        return results

    @staticmethod
    def _time_bounds(start_time: Optional[datetime], end_time: Optional[datetime]) -> Tuple[Optional[datetime], Optional[datetime]]:
        end = end_time or datetime.now(timezone.utc)
        from datetime import timedelta
        start = start_time or end - timedelta(minutes=5)
        if start.tzinfo is None or end.tzinfo is None or end < start or end - start > timedelta(days=7):
            raise ValueError("Splunk search requires timezone-aware ordered bounds of at most seven days")
        return start, end

    @staticmethod
    def _literal(value):
        if not isinstance(value, str) or len(value) > 256 or any(ord(c) < 32 or c in '*?|`' for c in value):
            raise ValueError("Invalid Splunk search literal")
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'

    def search_telemetry(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        host: Optional[str] = None,
        process_name: Optional[str] = None,
        query_string: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> SplunkTelemetryBatch:
        if query_string is not None:
            raise ValueError("Freeform SPL is not supported")
        start_time, end_time = self._time_bounds(start_time, end_time)
        if limit is not None and (not isinstance(limit, int) or limit < 1):
            raise ValueError("Result limit must be a positive integer")
        effective_limit = min(limit or self.settings.max_results, self.settings.max_results)
        clauses = [f"index={self.settings.telemetry_index}"]
        if self.settings.telemetry_sourcetype:
            clauses.append(f"sourcetype={self.settings.telemetry_sourcetype}")
        if host:
            literal = self._literal(host)
            clauses.append('(' + ' OR '.join(f'{field}={literal}' for field in ('host', 'host.name', 'dest', 'ComputerName')) + ')')
        if process_name:
            literal = self._literal(process_name)
            clauses.append(f'(process_name={literal} OR process.name={literal})')
        query = "search " + " ".join(clauses) + " | head " + str(effective_limit + 1)
        results = self._search(query, start_time, end_time, effective_limit + 1)
        truncated = len(results) > effective_limit
        status = SplunkRetrievalStatus.TRUNCATED if truncated else (
            SplunkRetrievalStatus.COMPLETE if results else SplunkRetrievalStatus.EMPTY
        )
        self.last_search_total = len(results)
        self.last_search_truncated = truncated
        return SplunkTelemetryBatch(results[:effective_limit], len(results), truncated, status, (start_time, end_time))

    def search_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        rule_ids: Optional[Sequence[str]] = None,
        host: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        start_time, end_time = self._time_bounds(start_time, end_time)
        if limit is not None and (not isinstance(limit, int) or limit < 1):
            raise ValueError("Result limit must be a positive integer")
        effective_limit = min(limit or self.settings.max_results, self.settings.max_results)
        clauses = [f"index={self.settings.alert_index}"]
        if host:
            literal = self._literal(host)
            clauses.append('(' + ' OR '.join(f'{field}={literal}' for field in ('host', 'host.name', 'dest', 'ComputerName')) + ')')
        if rule_ids:
            safe_rules = [r.strip() for r in rule_ids if r and r.strip()]
            if safe_rules:
                clauses.append("(" + " OR ".join(f'{field}={self._literal(r)}' for r in safe_rules
                    for field in ('rule_id', 'rule.id', 'detection_rule_id', 'savedsearch_name', 'search_name')) + ")")
        results = self._search("search " + " ".join(clauses) + " | head " + str(effective_limit + 1), start_time, end_time, effective_limit + 1)
        self.last_search_total = len(results)
        self.last_search_truncated = len(results) > effective_limit
        return results[:effective_limit]

    def fetch_raw_telemetry(self, **kwargs: Any) -> List[RawTelemetryEventV1]:
        return [map_splunk_result_to_raw(result) for result in self.search_telemetry(**kwargs).results]

    def fetch_and_map_alerts(self, **kwargs: Any) -> List[AlertV1]:
        return [map_splunk_alert(result) for result in self.search_alerts(**kwargs)]
