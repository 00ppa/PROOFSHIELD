"""Elastic Common Schema (ECS) telemetry event normaliser for PROOFSHIELD.

Provides deterministic mapping of ECS documents (e.g. from Elastic Agent, Beats,
Sysmon-on-ECS, Auditbeat, Endpoint Security) into canonical NormalizedTelemetryEventV1
records while strictly preserving immutable provenance, execution tokens, and evidence separation.
"""

from copy import deepcopy
from datetime import datetime, timezone
import math
import re
from typing import Any, Dict, List, Optional, Sequence, Union
import hashlib

import dateutil.parser

from proofshield.normalisation.base import BaseNormaliser
from proofshield.normalisation.engine import (
    _clean_path,
    _clean_str,
    _ensure_utc,
    _extract_basename,
    _parse_hashes,
    _parse_port,
    extract_execution_token,
)
from proofshield.schemas.common import EventCategory
from proofshield.schemas.telemetry import (
    NormalizedTelemetryEventV1,
    RawTelemetryEventV1,
)


def _get_nested(data: Dict[str, Any], path: str) -> Any:
    """Retrieve a value by dotted path from either nested dicts or dotted literal keys."""
    if not isinstance(data, dict):
        return None

    if path in data and data[path] is not None:
        return data[path]

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
            remaining = ".".join(parts[i:])
            if remaining in curr and curr[remaining] is not None:
                return curr[remaining]
            break

    return None


def _parse_timestamp(raw_val: Any) -> Optional[datetime]:
    """Parse raw timestamp into a UTC-aware datetime."""
    if raw_val is None:
        return None

    if isinstance(raw_val, datetime):
        if raw_val.tzinfo is None:
            return raw_val.replace(tzinfo=timezone.utc)
        return raw_val.astimezone(timezone.utc)

    if isinstance(raw_val, (int, float)):
        if math.isnan(raw_val) or math.isinf(raw_val):
            return None
        try:
            if raw_val > 1e11:
                return datetime.fromtimestamp(raw_val / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(raw_val, tz=timezone.utc)
        except Exception:
            return None

    if isinstance(raw_val, str):
        cleaned = raw_val.strip()
        if not cleaned:
            return None
        try:
            dt = dateutil.parser.isoparse(cleaned)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None

    return None


class ECSNormaliser(BaseNormaliser):
    """Normalises Elastic Common Schema (ECS) telemetry into canonical events.

    Guarantees:
    - Pure offline operation with no external dependencies or side effects.
    - Preserves source_event_id and source_timestamp with microsecond precision.
    - Maps ECS event categories (process, network, file, authentication, registry)
      into canonical EventCategory enums.
    - Deterministically extracts execution tokens from structured (labels, tags, custom)
      and unstructured (command lines, messages) ECS fields.
    - Credential-scrubs non-canonical extra_attributes.
    """

    ECS_FORMATS = {
        "elastic_ecs",
        "ecs",
        "elastic",
        "elastic-ecs",
        "beats",
        "elastic_agent",
        "endpoint_security",
    }

    def can_handle(self, raw_event: RawTelemetryEventV1) -> bool:
        """Determine if this normaliser can process the raw event."""
        fmt = (raw_event.source_format or "").strip().lower()
        if fmt in self.ECS_FORMATS:
            return True

        p = raw_event.raw_payload
        if not isinstance(p, dict):
            return False

        # Heuristic 1: Explicit ECS indicator fields
        if "ecs" in p or "ecs.version" in p:
            return True

        # Heuristic 2: Presence of event.category or event.dataset
        if _get_nested(p, "event.category") is not None or _get_nested(p, "event.dataset") is not None:
            return True

        # Heuristic 3: Common ECS top-level keys (@timestamp + host / process / network)
        has_ts = "@timestamp" in p or "event.created" in p
        has_ecs_entity = any(
            _get_nested(p, k) is not None
            for k in ("host.hostname", "host.name", "process.name", "process.executable", "destination.ip")
        )
        return bool(has_ts and has_ecs_entity)

    def normalize(self, raw_event: RawTelemetryEventV1) -> NormalizedTelemetryEventV1:
        """Transform raw ECS telemetry into canonical NormalizedTelemetryEventV1."""
        p = raw_event.raw_payload or {}

        # 1. Source event ID resolution
        raw_src_id = (
            _get_nested(p, "event.id")
            or _get_nested(p, "_id")
            or raw_event.source_event_id
            or "unknown_event"
        )
        src_id = str(raw_src_id).strip()

        # 2. Timestamp resolution (preserving UTC)
        ts_val = _get_nested(p, "@timestamp") or _get_nested(p, "event.created")
        if ts_val is not None:
            try:
                src_ts = _parse_timestamp(ts_val)
            except Exception:
                src_ts = None
        else:
            src_ts = None

        if src_ts is None:
            src_ts = _ensure_utc(raw_event.source_timestamp)
        else:
            src_ts = _ensure_utc(src_ts)

        norm_ts = src_ts

        # 3. Host resolution
        host_val = (
            _get_nested(p, "host.hostname")
            or _get_nested(p, "host.name")
            or _get_nested(p, "host.id")
            or _get_nested(p, "agent.hostname")
            or _get_nested(p, "agent.name")
            or _clean_str(p.get("host"))
            or "unknown_host"
        )
        host = str(host_val).strip()

        # 4. User resolution
        user_name = _clean_str(_get_nested(p, "user.name"))
        user_domain = _clean_str(_get_nested(p, "user.domain"))
        if user_name and user_domain:
            user = f"{user_domain}\\{user_name}"
        elif user_name:
            user = user_name
        else:
            user = _clean_str(_get_nested(p, "user.id"))

        # 5. Process details
        proc_path = _clean_path(
            _get_nested(p, "process.executable")
            or _get_nested(p, "process.binary_path")
            or _get_nested(p, "process.path")
        )
        proc_name = _clean_str(_get_nested(p, "process.name"))
        if not proc_name and proc_path:
            proc_name = _extract_basename(proc_path)

        cmd_line = _clean_str(
            _get_nested(p, "process.command_line") or _get_nested(p, "process.command")
        )
        if not cmd_line:
            args = _get_nested(p, "process.args")
            if isinstance(args, list) and args:
                cmd_line = " ".join(str(a) for a in args)

        parent_path = _clean_path(
            _get_nested(p, "process.parent.executable") or _get_nested(p, "process.parent.path")
        )
        parent_name = _clean_str(_get_nested(p, "process.parent.name"))
        if not parent_name and parent_path:
            parent_name = _extract_basename(parent_path)

        parent_cmd = _clean_str(_get_nested(p, "process.parent.command_line"))
        if not parent_cmd:
            p_args = _get_nested(p, "process.parent.args")
            if isinstance(p_args, list) and p_args:
                parent_cmd = " ".join(str(a) for a in p_args)

        # 6. Hashes
        hashes: Dict[str, str] = {}
        for hash_source in ("process.hash", "file.hash", "hashes"):
            raw_hash_container = _get_nested(p, hash_source)
            if raw_hash_container:
                hashes.update(_parse_hashes(raw_hash_container))

        for hash_field in ("sha256", "md5", "sha1", "imphash"):
            if hash_field not in hashes:
                h_val = _clean_str(
                    _get_nested(p, f"process.hash.{hash_field}")
                    or _get_nested(p, f"file.hash.{hash_field}")
                    or _get_nested(p, hash_field)
                )
                if h_val:
                    hashes[hash_field] = h_val.lower()

        # 7. Network attributes
        dest_ip = _clean_str(_get_nested(p, "destination.ip") or _get_nested(p, "server.ip"))
        dest_port = _parse_port(
            _get_nested(p, "destination.port") or _get_nested(p, "server.port")
        )

        # 8. Category resolution
        category = self._resolve_category(
            p=p,
            proc_name=proc_name,
            proc_path=proc_path,
            cmd_line=cmd_line,
            dest_ip=dest_ip,
            dest_port=dest_port,
        )

        # Strict gating: network fields only valid on NETWORK_CONNECTION
        if category != EventCategory.NETWORK_CONNECTION:
            dest_ip = None
            dest_port = None

        # 9. Execution token extraction
        text_fields: List[Optional[str]] = [
            cmd_line,
            parent_cmd,
            proc_name,
            proc_path,
            _clean_str(_get_nested(p, "message")),
            _clean_str(_get_nested(p, "event.original")),
            _clean_str(_get_nested(p, "process.title")),
        ]

        tags = _get_nested(p, "tags")
        if isinstance(tags, list):
            for t in tags:
                if isinstance(t, str):
                    text_fields.append(t)

        structured_payload: Dict[str, Any] = {}
        labels = _get_nested(p, "labels")
        if isinstance(labels, dict):
            structured_payload.update(labels)
        custom = _get_nested(p, "custom")
        if isinstance(custom, dict):
            structured_payload.update(custom)

        for k, v in p.items():
            if isinstance(v, (str, int, float)) and "." not in k:
                structured_payload[k] = v

        explicit_tok = _clean_str(
            _get_nested(p, "execution_token") or _get_nested(p, "proofshield_token")
        )

        token = extract_execution_token(
            payload=structured_payload,
            explicit_token=explicit_tok,
            text_fields=text_fields,
        )

        # 10. Sanitized extra attributes
        from proofshield.connectors.elastic import _sanitize_metadata
        raw_copy = deepcopy(p)
        sanitized_payload = _sanitize_metadata(raw_copy)

        known_top_keys = {
            "@timestamp", "ecs", "event", "host", "agent", "process", "user",
            "destination", "source", "server", "client", "file", "network",
            "labels", "tags", "message", "custom", "execution_token", "proofshield_token",
        }
        extra_attrs: Dict[str, Any] = {}
        for k, v in sanitized_payload.items():
            if k not in known_top_keys:
                extra_attrs[k] = v
        if labels and isinstance(sanitized_payload.get("labels"), dict):
            extra_attrs["labels"] = sanitized_payload["labels"]

        return NormalizedTelemetryEventV1(
            schema_version="v1",
            normalized_event_id="NORM-ECS-" + hashlib.sha256(raw_event.raw_event_id.encode()).hexdigest()[:24].upper(),
            raw_event_id=raw_event.raw_event_id,
            source_event_id=src_id,
            source_timestamp=src_ts,
            normalized_timestamp=norm_ts,
            event_category=category,
            host=host,
            user=user,
            process_name=proc_name,
            process_path=proc_path,
            command_line=cmd_line,
            parent_process_name=parent_name,
            parent_command_line=parent_cmd,
            hashes=hashes,
            network_destination_ip=dest_ip,
            network_destination_port=dest_port,
            execution_token=token,
            extra_attributes=extra_attrs,
        )

    def _resolve_category(
        self,
        p: Dict[str, Any],
        proc_name: Optional[str],
        proc_path: Optional[str],
        cmd_line: Optional[str],
        dest_ip: Optional[str],
        dest_port: Optional[int],
    ) -> EventCategory:
        """Resolve canonical EventCategory from ECS event fields."""
        categories: List[str] = []
        raw_cat = _get_nested(p, "event.category")
        if isinstance(raw_cat, list):
            categories.extend(str(c).lower().strip() for c in raw_cat)
        elif isinstance(raw_cat, str):
            categories.append(raw_cat.lower().strip())

        dataset = str(_get_nested(p, "event.dataset") or "").lower().strip()
        action = str(_get_nested(p, "event.action") or "").lower().strip()
        type_field = _get_nested(p, "event.type")
        types: List[str] = []
        if isinstance(type_field, list):
            types.extend(str(t).lower().strip() for t in type_field)
        elif isinstance(type_field, str):
            types.append(type_field.lower().strip())

        # Check explicit category declarations
        if any("process" in c for c in categories) or "process_start" in action or "start" in types:
            return EventCategory.PROCESS_CREATION
        if any("file" in c for c in categories) or "file" in dataset:
            return EventCategory.FILE_EVENT
        if any("registry" in c for c in categories) or "registry" in dataset:
            return EventCategory.REGISTRY_EVENT
        if any("authentication" in c for c in categories) or "iam" in categories or "user_login" in action:
            return EventCategory.AUTHENTICATION
        if any("network" in c for c in categories) or "network" in dataset:
            return EventCategory.NETWORK_CONNECTION

        # Fallback heuristics when event.category is missing or vague
        if dest_ip is not None and dest_port is not None:
            return EventCategory.NETWORK_CONNECTION
        if (proc_name or proc_path or cmd_line):
            return EventCategory.PROCESS_CREATION

        return EventCategory.OTHER
